"""Generic ASUS firmware discovery, matching and transport orchestration.

The engine deliberately knows about ASUS *capabilities*, not about one server
model.  Exact model/board/BMC evidence is required before a package can be
selected.  Redfish and local utility transports are discovered independently
for each component; a missing BMC path therefore does not block BIOS or local
inventory work.
"""

from __future__ import annotations

import hashlib
import html as html_lib
import json
import os
import re
import ssl
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .firmware import FirmwarePackageMetadata, FirmwareRepository, FirmwareRepositoryError, PackageDownloader


class AsusFirmwareError(RuntimeError):
    """A sanitized generic ASUS firmware failure."""


ASUS_VALIDATED_PACKAGE_STATUSES = frozenset(
    {
        "CHECKSUM_VERIFIED",
        "VENDOR_SIGNED",
        "LAB_VALIDATED",
        "PROVENANCE_VERIFIED",
        "CHECKSUM_VERIFIED_WITHOUT_VENDOR_HASH",
        "OFFICIAL_SOURCE_VERIFIED",
    }
)

ASUS_OFFICIAL_HOSTS = frozenset({"servers.asus.com", "www.asus.com", "dlcdnets.asus.com"})


def _is_official_asus_url(value: str) -> bool:
    parsed = urlparse(str(value or ""))
    return parsed.scheme.lower() == "https" and (parsed.hostname or "").casefold() in ASUS_OFFICIAL_HOSTS and not parsed.username and not parsed.password


def _clean(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def _exact_key(value: Any) -> str:
    """Case-insensitive exact comparison key; never folds model suffixes."""
    return _clean(value).casefold()


def _board_key(value: Any) -> str:
    """Canonicalize harmless board-label decorations, never model variants."""
    text = _exact_key(value)
    text = re.sub(r"\s+series$", "", text)
    text = re.sub(r"[-_ ]asus$", "", text)
    return text


def _first(mapping: Mapping[str, Any] | None, *keys: str) -> str:
    payload = mapping or {}
    for key in keys:
        value = payload.get(key)
        if isinstance(value, Mapping):
            value = value.get("value") or value.get("Value")
        if _clean(value):
            return _clean(value)
    return ""


def _version_key(value: str) -> tuple[Any, ...]:
    """Sort vendor versions without assuming a single ASUS numbering scheme."""
    text = _clean(value).casefold()
    tokens = re.findall(r"\d+|[a-z]+", text)
    result: list[Any] = []
    for token in tokens:
        result.append((0, int(token)) if token.isdigit() else (1, token))
    # Firmware catalogs often spell the same release as ``1.32`` and
    # ``1.32.00``.  Trailing numeric zero components do not constitute a
    # newer target and must not trigger a needless BMC mutation.
    while result and result[-1] == (0, 0):
        result.pop()
    return tuple(result) or ((1, text),)


@dataclass(frozen=True)
class AsusPlatformFingerprint:
    vendor: str = "ASUS"
    model: str = ""
    board: str = ""
    bmc_model: str = ""
    bmc_generation: str = ""
    platform_id: str = ""
    system_serial: str = ""
    board_serial: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_sources(
        cls,
        *,
        local: Mapping[str, Any] | None = None,
        redfish: Mapping[str, Any] | None = None,
        fru: Mapping[str, Any] | None = None,
        bmc: Mapping[str, Any] | None = None,
    ) -> "AsusPlatformFingerprint":
        local = local or {}
        redfish = redfish or {}
        fru = fru or {}
        bmc = bmc or {}
        # Redfish discovery normally nests these under normalized.system,
        # normalized.manager and normalized.fru.  Accept flat evidence too.
        system = redfish.get("system") if isinstance(redfish.get("system"), Mapping) else redfish
        manager = redfish.get("manager") if isinstance(redfish.get("manager"), Mapping) else redfish
        redfish_fru = redfish.get("fru") if isinstance(redfish.get("fru"), Mapping) else redfish
        model = _first(local, "product_name", "model", "product") or _first(system, "Model", "Name", "PartNumber") or _first(redfish_fru, "ProductName", "Model", "Name")
        board = _first(local, "board_name", "baseboard_product", "board") or _first(system, "BaseboardProduct", "BoardProduct") or _first(redfish_fru, "BoardProduct", "BoardName", "ProductName")
        bmc_model = _first(bmc, "model", "Model", "device_model") or _first(manager, "Model", "Name", "PartNumber", "Description")
        if not bmc_model:
            bmc_model = _first(redfish.get("update_service") if isinstance(redfish.get("update_service"), Mapping) else {}, "Oem")
        generation_match = re.search(r"(?i)\b(ASMB\s*\d+)\b", bmc_model)
        bmc_generation = generation_match.group(1).replace(" ", "").upper() if generation_match else ""
        vendor = _first(local, "manufacturer", "sys_vendor", "vendor") or _first(system, "Manufacturer", "Vendor") or "ASUS"
        system_serial = _first(local, "system_serial", "product_serial", "serial") or _first(system, "SerialNumber") or _first(redfish_fru, "ProductSerial", "SerialNumber", "ChassisSerial")
        board_serial = _first(local, "board_serial") or _first(redfish_fru, "BoardSerial", "SerialNumber")
        platform_id = _first(local, "platform_id") or ":".join(item for item in (model, board, bmc_generation) if item)
        evidence = {
            "model": {"value": model, "source": "DMI_SMBIOS" if _first(local, "product_name", "model", "product") else "REDFISH"},
            "board": {"value": board, "source": "DMI_SMBIOS" if _first(local, "board_name", "baseboard_product", "board") else "REDFISH_FRU"},
            "bmc_model": {"value": bmc_model, "source": "LOCAL_BMC" if bmc else "REDFISH_MANAGER"},
            "bmc_generation": {"value": bmc_generation, "source": "PARSED_BMC_MODEL"},
            "system_serial": {"value": system_serial, "source": "LOCAL_OR_REDFISH"},
            "board_serial": {"value": board_serial, "source": "LOCAL_OR_REDFISH_FRU"},
        }
        return cls(
            vendor=vendor,
            model=model,
            board=board,
            bmc_model=bmc_model,
            bmc_generation=bmc_generation,
            platform_id=platform_id,
            system_serial=system_serial,
            board_serial=board_serial,
            evidence=evidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AsusApplicabilityDecision:
    status: str
    reason_codes: tuple[str, ...]
    evidence: tuple[str, ...] = ()

    @property
    def exact_match(self) -> bool:
        return self.status == "EXACT_MATCH"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"exact_match": self.exact_match}


def match_asus_package(
    metadata: FirmwarePackageMetadata,
    fingerprint: AsusPlatformFingerprint,
) -> AsusApplicabilityDecision:
    """Require exact ASUS platform evidence; family names never substitute."""
    reasons: list[str] = []
    evidence: list[str] = []
    vendor_match = _exact_key(metadata.vendor) == _exact_key(fingerprint.vendor)
    if _exact_key(metadata.vendor) == "asus" and "asus" in _exact_key(fingerprint.vendor):
        vendor_match = True
    if not vendor_match:
        reasons.append("VENDOR_MISMATCH")
    if not (metadata.compatible_models or metadata.compatible_boards or getattr(metadata, "compatible_platform_ids", ())):
        reasons.append("EXACT_PLATFORM_APPLICABILITY_MISSING")
    model_list = {_exact_key(item) for item in metadata.compatible_models if _clean(item)}
    board_list = {_board_key(item) for item in metadata.compatible_boards if _clean(item)}
    platform_list = {_exact_key(item) for item in getattr(metadata, "compatible_platform_ids", ()) if _clean(item)}
    if model_list:
        if _exact_key(fingerprint.model) not in model_list:
            reasons.append("EXACT_MODEL_MISMATCH")
        else:
            evidence.append("EXACT_MODEL_MATCH")
    if board_list:
        if _board_key(fingerprint.board) not in board_list:
            reasons.append("EXACT_BOARD_MISMATCH")
        else:
            evidence.append("EXACT_BOARD_MATCH")
    if platform_list:
        if _exact_key(fingerprint.platform_id) not in platform_list:
            reasons.append("EXACT_PLATFORM_ID_MISMATCH")
        else:
            evidence.append("EXACT_PLATFORM_ID_MATCH")
    bmc_generations = {_exact_key(item) for item in getattr(metadata, "compatible_bmc_generations", ()) if _clean(item)}
    if bmc_generations:
        if _exact_key(fingerprint.bmc_generation) not in bmc_generations:
            reasons.append("BMC_GENERATION_MISMATCH")
        else:
            evidence.append("EXACT_BMC_GENERATION_MATCH")
    if metadata.validation_status not in ASUS_VALIDATED_PACKAGE_STATUSES:
        reasons.append("PACKAGE_NOT_PROVENANCE_VALIDATED")
    status = "EXACT_MATCH" if not reasons else "REJECTED"
    return AsusApplicabilityDecision(status, tuple(dict.fromkeys(reasons)), tuple(evidence))


@dataclass(frozen=True)
class AsusTransportDescriptor:
    name: str
    source: str
    target: str = ""
    components: tuple[str, ...] = ("BIOS", "BMC")
    rank: int = 0
    requires_authenticated_bmc: bool = True
    task_tracking: bool = False
    package_delivery: str = "UNKNOWN"
    reboot_behavior: str = "UNKNOWN"
    # Payload semantics are part of the discovered capability, not a model
    # hard-code.  ASUS ASMB UpdateService documents BIOS CAP and BMC HPM
    # multipart images; future generations can override these maps when their
    # live OEM metadata advertises different formats.
    component_payload_preferences: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    component_image_types: Mapping[str, str] = field(default_factory=dict)
    component_image_type_candidates: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    # Optional ASUS ASMB web-HPM capability metadata.  These fields are
    # populated only from a live, authenticated capability probe; the generic
    # planner never guesses an endpoint or a component id from a model name.
    web_update_method: str = ""
    web_component_ids: Mapping[str, int] = field(default_factory=dict)
    web_component_image_types: Mapping[str, int] = field(default_factory=dict)
    web_section_flash: Mapping[str, int] = field(default_factory=dict)
    web_endpoint_prefix: str = ""
    # A local utility is selectable only when these fields come from an
    # explicit, immutable operator configuration.  Discovery never infers a
    # command from a filename and never executes a candidate automatically.
    local_command: tuple[str, ...] = ()
    local_tool_sha256: str = ""
    local_timeout_seconds: int = 7200
    selectable: bool = False
    reason: str = ""

    def supports(self, component: str) -> bool:
        return component.upper() in {item.upper() for item in self.components}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def discover_asus_transports(
    *,
    redfish_discovery: Mapping[str, Any] | None = None,
    local_tools: Mapping[str, Any] | None = None,
    fingerprint: AsusPlatformFingerprint | None = None,
) -> dict[str, Any]:
    """Build a capability list from what the server actually advertises."""
    discovery = redfish_discovery or {}
    normalized = discovery.get("normalized") if isinstance(discovery.get("normalized"), Mapping) else discovery
    normalized = normalized if isinstance(normalized, Mapping) else {}
    auth = discovery.get("authentication") if isinstance(discovery.get("authentication"), Mapping) else {}
    auth_available = bool(auth.get("available", discovery.get("bmc_auth_available", False)))
    mechanisms = normalized.get("update_mechanisms") or discovery.get("update_mechanisms") or []
    if not isinstance(mechanisms, list):
        mechanisms = []
    task = normalized.get("task_service") if isinstance(normalized.get("task_service"), Mapping) else {}
    endpoint_catalog = discovery.get("endpoint_catalog") if isinstance(discovery.get("endpoint_catalog"), list) else []
    task_available = bool(task) or any(
        isinstance(item, Mapping) and str(item.get("label") or "") == "task_service" and int(item.get("status") or 0) == 200
        for item in endpoint_catalog
    )
    tools = local_tools or {}
    local_kcs = tools.get("kcs") if isinstance(tools.get("kcs"), Mapping) else {}
    # ``ipmitool mc info`` is collected locally during normal inventory.  It
    # is the read-only, current-boot proof that the host can reach the BMC via
    # KCS.  The adapter performs an additional package-owned Yafuflash
    # ``-kcs ... -info`` probe before it can flash anything, so this flag only
    # makes a safe candidate selectable; it never by itself authorizes a
    # mutation.
    kcs_status = str(local_kcs.get("status") or "").upper()
    local_kcs_available = bool(local_kcs.get("available")) and kcs_status in {"", "PASS", "AVAILABLE", "VERIFIED"}
    descriptors: list[AsusTransportDescriptor] = []
    # ASUS publishes a supported Linux updater inside the exact ASMB11/12
    # BMC package.  It is a real, package-bound transport rather than a
    # discovered arbitrary executable: the adapter extracts and hashes the
    # Yafuflash binary from the verified official ZIP at execution time.  Keep
    # this descriptor selectable even before authentication so the shared
    # planner can invoke the bounded KCS recovery path instead of incorrectly
    # reporting that no transport exists.
    generation = str(getattr(fingerprint, "bmc_generation", "") or "").replace(" ", "").upper()
    if generation == "ASMB11":
        descriptors.append(
            AsusTransportDescriptor(
                name="ASUS_ASMB11_KCS_YAFUFLASH",
                source="ASUS_OFFICIAL_ASMB_PACKAGE_YAFU_KCS",
                target="builtin://asus-asmb11-yafuflash-kcs",
                components=("BMC",),
                # The exact ASUS package's own Yafuflash binary documents
                # ``-kcs``.  It has no BMC username/password arguments and
                # therefore avoids exposing an operational BMC secret in a
                # child-process command line.  Do not generalize this to
                # other ASMB generations until their package capability is
                # independently verified.
                rank=130,
                requires_authenticated_bmc=False,
                task_tracking=False,
                package_delivery="ASUS_ASMB_LINUX_ZIP",
                reboot_behavior="BMC_RESTART_REQUIRED",
                local_command=("-kcs", "{image}", "-preserve-config", "-ignore-same-image"),
                selectable=local_kcs_available,
                reason=(
                    "Exact ASMB11 package exposes a password-free local KCS Yafuflash transport; "
                    "a current local KCS probe and a package-owned non-mutating -info preflight are required."
                    if local_kcs_available
                    else "Exact ASMB11 package exposes a password-free local KCS Yafuflash transport, but current local KCS evidence is unavailable."
                ),
            )
        )
        # Retain the historical ASUS USB-LAN wrapper as evidence only.  Its
        # documented invocation requires ``-U``/``-P`` arguments, which puts
        # the BMC password into a process command line.  It must not become an
        # automatic fallback for ASMB11 while the credential-free KCS mode is
        # available or unknown.  Authenticated Redfish remains an independent
        # selectable fallback when live UpdateService capability is advertised.
        descriptors.append(
            AsusTransportDescriptor(
                name="ASUS_ASMB_LINUX_OFFICIAL",
                source="ASUS_OFFICIAL_ASMB_PACKAGE_LINUX_UPDATER",
                target="builtin://asus-asmb-linux-yafuflash",
                components=("BMC",),
                rank=65,
                requires_authenticated_bmc=True,
                task_tracking=False,
                package_delivery="ASUS_ASMB_LINUX_ZIP",
                reboot_behavior="BMC_RESTART_REQUIRED",
                local_command=("-local", "{username}", "{password}", "-preserve-config"),
                selectable=False,
                reason="Legacy ASUS USB-LAN Yafuflash wrapper is retained for audit evidence but disabled because it requires credentials in process arguments.",
            )
        )
    elif generation == "ASMB12":
        descriptors.append(
            AsusTransportDescriptor(
                name="ASUS_ASMB_LINUX_OFFICIAL",
                source="ASUS_OFFICIAL_ASMB_PACKAGE_LINUX_UPDATER",
                target="builtin://asus-asmb-linux-yafuflash",
                components=("BMC",),
                # ASMB12 has a physically proven multipart task lifecycle,
                # so prefer that live-advertised, task-trackable Redfish path
                # when available and retain its package-bound Linux updater
                # as an exact-package fallback.  ASMB11 is intentionally
                # handled above by the credential-free KCS adapter.
                rank=95,
                requires_authenticated_bmc=True,
                task_tracking=False,
                package_delivery="ASUS_ASMB_LINUX_ZIP",
                reboot_behavior="BMC_RESTART_REQUIRED",
                local_command=("-local", "{username}", "{password}", "-preserve-config"),
                # Authentication is checked independently by the workflow.
                # Keep the candidate visible for capability evidence, but do
                # not mark it selectable until the approved credential probe
                # succeeds; this prevents an unauthenticated plan from being
                # mistaken for an immediately executable mutation path.
                selectable=auth_available,
                reason="Exact ASMB generation supports the official Linux Yafuflash updater embedded in the verified ASUS BMC package.",
            )
        )
    # The ASMB web HPM path is intentionally considered before generic
    # Redfish multipart.  It is selected only when the live web probe has
    # positively confirmed the exact endpoint/component contract.
    web_hpm = discovery.get("web_hpm") if isinstance(discovery.get("web_hpm"), Mapping) else {}
    if bool(web_hpm.get("supported")) and auth_available:
        components = tuple(str(item).upper() for item in (web_hpm.get("components") or ("BIOS",)))
        descriptors.append(
            AsusTransportDescriptor(
                name="ASUS_ASMB_WEB_HPM",
                source="AUTHENTICATED_ASUS_ASMB_WEB_CAPABILITY",
                target=str(web_hpm.get("endpoint_prefix") or "/api/maintenance/hpm"),
                components=components,
                rank=125,
                requires_authenticated_bmc=True,
                task_tracking=bool(web_hpm.get("task_tracking", False)),
                package_delivery="ASUS_HPM_WRAPPED_IMAGE",
                reboot_behavior=str(web_hpm.get("reboot_behavior") or "HOST_REBOOT_REQUIRED"),
                web_update_method=str(web_hpm.get("update_method") or "STAGED"),
                web_component_ids={str(k).upper(): int(v) for k, v in (web_hpm.get("component_ids") or {}).items()},
                web_component_image_types={str(k).upper(): int(v) for k, v in (web_hpm.get("image_types") or {}).items()},
                web_section_flash={str(k).upper(): int(v) for k, v in (web_hpm.get("section_flash") or {}).items()},
                web_endpoint_prefix=str(web_hpm.get("endpoint_prefix") or "/api/maintenance/hpm"),
                selectable=True,
                reason="Authenticated ASUS ASMB web-HPM lifecycle was positively discovered from live capability endpoints.",
            )
        )
    for item in mechanisms:
        if not isinstance(item, Mapping) or not item.get("target"):
            continue
        kind = str(item.get("kind") or "").strip()
        lowered = kind.casefold()
        if "biosfwupdate" in lowered:
            # AMI/ASUS ASMB exposes a concrete OEM BIOS action with an
            # ActionInfo contract (ImageURI + TransferProtocol + optional
            # BIOSOOBEnable). This stages the exact BIOS image for the next
            # host boot instead of requiring the live chassis to be powered
            # off while CNServerOps is running.
            name, rank, delivery = "ASUS_REDFISH_BIOS_OOB", 120, "REDFISH_BIOS_OOB"
        elif "multiparthttppushuri" in lowered:
            name, rank, delivery = "REDFISH_MULTIPART_PUSH", 100, "MULTIPART_FILE"
        elif "httppushuri" in lowered:
            name, rank, delivery = "REDFISH_HTTP_PUSH", 90, "MULTIPART_FILE"
        elif "simpleupdate" in lowered:
            name, rank, delivery = "REDFISH_SIMPLE_UPDATE", 80, "REMOTE_URI"
        elif "asus" in lowered or "ami" in lowered or "oem" in lowered:
            name, rank, delivery = "REDFISH_OEM_ACTION", 85, "VENDOR_DEFINED"
        else:
            name, rank, delivery = f"REDFISH_{re.sub(r'[^A-Z0-9]+', '_', kind.upper()).strip('_') or 'ACTION'}", 70, "VENDOR_DEFINED"
        descriptors.append(
            AsusTransportDescriptor(
                name=name,
                source="AUTHENTICATED_REDFISH_DISCOVERY",
                target=str(item.get("target")),
                rank=rank,
                requires_authenticated_bmc=True,
                task_tracking=task_available or "biosfwupdate" in lowered,
                package_delivery=delivery,
                reboot_behavior=("HOST_REBOOT_REQUIRED" if "biosfwupdate" in lowered else "BMC_RESTART_OR_HOST_REBOOT_UNKNOWN"),
                components=("BIOS",) if "biosfwupdate" in lowered else ("BIOS", "BMC"),
                component_payload_preferences={
                    "BIOS": ("cap", "bin", "ima"),
                    "BMC": ("hpm", "bin", "ima"),
                },
                component_image_types={"BIOS": "BIOS", "BMC": "BMC"},
                component_image_type_candidates={"BIOS": ("BIOS", "HPM"), "BMC": ("BMC", "HPM")},
                selectable=auth_available and (task_available or "biosfwupdate" in lowered),
                reason="Advertised by live UpdateService; package/component semantics still come from the official package manifest.",
            )
        )
    for candidate in tools.get("candidates", []) if isinstance(tools.get("candidates"), list) else []:
        if not isinstance(candidate, Mapping):
            continue
        if str(candidate.get("status") or "") not in {"APPROVED", "VERIFIED"}:
            continue
        command = tuple(str(item) for item in (candidate.get("command") or ()) if str(item).strip())
        tool_sha = str(candidate.get("sha256") or "").strip().lower()
        # A status label alone is not an authorization.  The immutable
        # executable hash and an explicit package placeholder are required so
        # a discovered script cannot become a mutation path by accident.
        if (
            not command
            or "{package}" not in command
            or not re.fullmatch(r"[0-9a-f]{64}", tool_sha)
            or not bool(candidate.get("official_source_verified"))
            or not bool(candidate.get("exact_platform_verified"))
            or bool(candidate.get("task_tracking"))
        ):
            continue
        descriptors.append(
            AsusTransportDescriptor(
                name="ASUS_LOCAL_OFFICIAL_UTILITY",
                source="LOCAL_ASUS_TOOL_DISCOVERY",
                target=str(candidate.get("path") or ""),
                components=tuple(str(item).upper() for item in candidate.get("components", ("BIOS", "BMC"))),
                rank=60,
                requires_authenticated_bmc=False,
                task_tracking=bool(candidate.get("task_tracking")),
                package_delivery="LOCAL_PATH",
                reboot_behavior=str(candidate.get("reboot_behavior") or "UNKNOWN"),
                local_command=command,
                local_tool_sha256=tool_sha,
                local_timeout_seconds=max(60, min(7200, int(candidate.get("timeout_seconds") or 7200))),
                selectable=True,
                reason="Explicitly approved local ASUS utility with pinned executable hash; arbitrary candidates remain non-selectable.",
            )
        )
    descriptors.sort(key=lambda item: (-item.rank, item.name, item.target))
    return {
        "schema_version": 1,
        "authentication_available": auth_available,
        "task_service_available": task_available,
        "descriptors": [item.to_dict() for item in descriptors],
        "components": {
            component: {
                "selected": next((item.to_dict() for item in descriptors if item.selectable and item.supports(component)), None),
                "candidates": [item.to_dict() for item in descriptors if item.supports(component)],
            }
            for component in ("BIOS", "BMC")
        },
    }


def _package_payload_capabilities(
    package: Path,
    *,
    metadata: FirmwarePackageMetadata,
    component: str,
) -> frozenset[str]:
    """Return bounded, non-executing payload capabilities for one package.

    Transport discovery happens before ASUS package bytes are necessarily in
    the local cache.  Once the exact, hash-verified package is available, the
    executor must not keep a higher-ranked transport whose required container
    is absent.  In particular, the ASMB web-HPM endpoint consumes a real
    ``PICMGFWU`` wrapper; a raw UEFI ``.CAP`` inside an ASUS ZIP is not an HPM
    image merely because the live BMC also advertises the HPM endpoint.

    This is only a compatibility classifier.  The selected adapter still
    performs its complete strict package/parser validation before mutation.
    """
    normalized_component = str(component or metadata.component).upper()
    expected_hpm_component = {"BIOS": 4, "BMC": 1}.get(normalized_component)
    capabilities: set[str] = set()

    def inspect_member(*, suffix: str, header: bytes, size: int) -> None:
        normalized_suffix = str(suffix or "").casefold().lstrip(".")
        if normalized_suffix in {"cap", "bin", "ima"}:
            capabilities.add(normalized_suffix)
        # Mirror the bounded structural gates in parse_asus_hpm_image without
        # weakening that authoritative parser or importing the transport
        # module back into this discovery module (which would be circular).
        if len(header) < 165 or header[:8] != b"PICMGFWU":
            return
        try:
            component_hpm_id = int(f"{header[36]:02x}", 10) if header[36] < 100 else -1
        except ValueError:
            return
        parsed_component = {1: 1, 4: 2, 10: 4}.get(component_hpm_id)
        data_length = int.from_bytes(header[65:69], "little")
        if (
            parsed_component is None
            or (expected_hpm_component is not None and parsed_component != expected_hpm_component)
            or data_length <= 0
            or 69 + data_length > int(size)
        ):
            return
        capabilities.add("hpm")
        capabilities.add("hpm_wrapped")

    if package.is_symlink() or not package.is_file():
        return frozenset()
    try:
        if zipfile.is_zipfile(package):
            capabilities.add("zip")
            with zipfile.ZipFile(package) as archive:
                for item in archive.infolist():
                    if item.is_dir():
                        continue
                    member = Path(item.filename)
                    if member.is_absolute() or ".." in member.parts:
                        return frozenset()
                    suffix = member.suffix.casefold().lstrip(".")
                    if suffix not in {"hpm", "cap", "bin", "ima"}:
                        continue
                    with archive.open(item) as stream:
                        header = stream.read(165)
                    inspect_member(suffix=suffix, header=header, size=item.file_size)
        else:
            with package.open("rb") as stream:
                header = stream.read(165)
            original_suffix = Path(metadata.package_filename).suffix.casefold().lstrip(".")
            inspect_member(
                suffix=original_suffix or package.suffix,
                header=header,
                size=package.stat().st_size,
            )
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):
        return frozenset()
    return frozenset(capabilities)


def select_asus_transport_for_package(
    transports: Mapping[str, Any],
    *,
    component: str,
    package: Path,
    metadata: FirmwarePackageMetadata,
) -> dict[str, Any] | None:
    """Select the highest-ranked *package-compatible* live transport.

    ``discover_asus_transports`` ranks live capabilities without package
    bytes.  This second, mandatory selection step runs after exact package
    download/cache verification and prevents a CAP-only BIOS package from
    being sent to the stricter ASUS web-HPM lifecycle.  Candidate ordering is
    otherwise preserved, so a genuine HPM package continues to prefer the
    positively discovered HPM endpoint.
    """
    normalized_component = str(component or metadata.component).upper()
    component_catalog = (
        transports.get("components", {}).get(normalized_component, {})
        if isinstance(transports, Mapping)
        and isinstance(transports.get("components"), Mapping)
        else {}
    )
    candidates = list(component_catalog.get("candidates") or []) if isinstance(component_catalog, Mapping) else []
    selected = component_catalog.get("selected") if isinstance(component_catalog, Mapping) else None
    if isinstance(selected, Mapping) and not any(
        isinstance(item, Mapping)
        and str(item.get("name") or "") == str(selected.get("name") or "")
        and str(item.get("target") or "") == str(selected.get("target") or "")
        for item in candidates
    ):
        candidates.append(selected)
    payloads = _package_payload_capabilities(
        package,
        metadata=metadata,
        component=normalized_component,
    )

    def compatible(candidate: Mapping[str, Any]) -> bool:
        if not bool(candidate.get("selectable")):
            return False
        supported = {str(item).upper() for item in (candidate.get("components") or ())}
        if normalized_component not in supported:
            return False
        delivery = str(candidate.get("package_delivery") or "").upper()
        if delivery == "ASUS_HPM_WRAPPED_IMAGE":
            return "hpm_wrapped" in payloads
        if delivery == "REDFISH_BIOS_OOB":
            return normalized_component == "BIOS" and "cap" in payloads
        if delivery == "MULTIPART_FILE":
            preferences = candidate.get("component_payload_preferences")
            configured = (
                preferences.get(normalized_component, ())
                if isinstance(preferences, Mapping)
                else ()
            )
            allowed = {
                str(item).casefold().lstrip(".")
                for item in (configured or (("cap", "bin", "ima") if normalized_component == "BIOS" else ("hpm", "bin", "ima")))
                if str(item).strip()
            }
            return bool(payloads.intersection(allowed))
        # Package-bound local transports and remote-URI mechanisms retain
        # their adapter-specific preview gate.  This selector only resolves
        # container conflicts that can be proven from the immutable bytes.
        return True

    ordered = sorted(
        (item for item in candidates if isinstance(item, Mapping)),
        key=lambda item: (
            -int(item.get("rank") or 0),
            str(item.get("name") or ""),
            str(item.get("target") or ""),
        ),
    )
    for candidate in ordered:
        if compatible(candidate):
            return dict(candidate) | {
                "package_compatibility": "VERIFIED",
                "package_payload_capabilities": sorted(payloads),
            }
    return None


class AsusCatalogSource(Protocol):
    name: str

    def discover(self, fingerprint: AsusPlatformFingerprint) -> Mapping[str, Any]: ...


def _download_url(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    for part in value.split("|"):
        if "@" in part:
            _, link = part.split("@", 1)
        else:
            link = part
        parsed = urlparse(link.strip())
        if parsed.scheme.lower() == "https" and parsed.hostname:
            return link.strip()
    return ""


class AsusOfficialCatalogSource:
    """Reader for the public ASUS server firmware compatibility endpoint.

    The endpoint is treated as a discovery source only.  A returned filename
    or version is never enough to authorize a flash; a sidecar hash and exact
    package applicability are still required by :func:`match_asus_package`.
    """

    name = "ASUS_OFFICIAL_SERVER_FIRMWARE_CATALOG"

    def __init__(self, *, base_url: str = "https://servers.asus.com", locale: str = "global", timeout_seconds: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.locale = locale.strip("/") or "global"
        self.timeout_seconds = timeout_seconds
        parsed = urlparse(self.base_url)
        if parsed.scheme.lower() != "https" or parsed.hostname not in {"servers.asus.com", "www.asus.com", "dlcdnets.asus.com"}:
            raise ValueError("ASUS catalog source must use an approved HTTPS ASUS host")

    def _request(self, url: str, *, method: str = "GET", body: bytes | None = None, content_type: str = "") -> bytes:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https" or parsed.hostname not in {"servers.asus.com", "www.asus.com", "dlcdnets.asus.com"}:
            raise AsusFirmwareError("ASUS catalog redirected to a non-approved host")
        request = Request(url, data=body, method=method, headers={"Accept": "application/json, text/html"})
        if content_type:
            request.add_header("Content-Type", content_type)
        context = ssl.create_default_context()
        try:
            with urlopen(request, timeout=self.timeout_seconds, context=context) as response:
                final = urlparse(response.geturl())
                if final.hostname not in {"servers.asus.com", "www.asus.com", "dlcdnets.asus.com"}:
                    raise AsusFirmwareError("ASUS catalog redirected to a non-approved host")
                return response.read()
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise AsusFirmwareError(f"ASUS catalog request failed: {type(exc).__name__}") from exc

    @staticmethod
    def _component_for_link(link: str) -> str:
        lowered = link.casefold()
        if any(token in lowered for token in ("bmc", "asmb", "ipmi", "management")):
            return "BMC"
        if any(token in lowered for token in ("bios", "uefi", "efi", "cap")):
            return "BIOS"
        return "UNKNOWN"

    @staticmethod
    def _model_slug(model: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", model.casefold()).strip("-")

    @staticmethod
    def _version_from_filename(filename: str) -> str:
        """Infer a release label only when the official page omits one.

        This is a discovery hint, not applicability proof.  Exact model
        provenance is still required and the downloaded bytes are hashed and
        inspected before a package can be used.  Restricting the fallback to
        firmware markers or standalone three-plus digit tokens avoids treating
        model-family numbers such as ``E12`` or ``RS12U`` as releases.
        """
        stem = Path(filename).stem
        marked = re.findall(
            r"(?i)(?:fw|firmware|bios|bmc)[-_ ]*v?([0-9]+(?:[._][0-9]+){0,2})",
            stem,
        )
        standalone = re.findall(
            r"(?<![A-Za-z0-9])(\d{3,}(?:[._]\d+){0,2})(?![A-Za-z0-9])",
            stem,
        )
        values = marked or standalone
        return values[-1].strip("._-") if values else ""

    def _support_page_urls(self, fingerprint: AsusPlatformFingerprint) -> list[str]:
        slug = self._model_slug(fingerprint.model)
        if not slug:
            return []
        # ASUS has operated more than one support frontend.  These are all
        # official, read-only discovery paths; links are accepted only when
        # they point back to an approved ASUS download host.
        return [
            f"https://www.asus.com/supportonly/{slug}/helpdesk_bios/",
            f"https://www.asus.com/supportonly/{slug}/helpdesk_download/",
            f"https://www.asus.com/us/networking-iot-servers/servers/rack-servers/{slug}/helpdesk_bios/?model2Name={slug}",
            f"https://servers.asus.com/products/Servers/Rack-Servers/{fingerprint.model}?model2Name={fingerprint.model}",
        ]

    def _entries_from_support_page(self, url: str, body: bytes, fingerprint: AsusPlatformFingerprint, *, exact_page: bool | None = None) -> list[dict[str, Any]]:
        text = html_lib.unescape(body.decode("utf-8", errors="replace")).replace("\\/", "/")
        # Do not follow arbitrary HTML links.  Only HTTPS ASUS download hosts
        # and firmware-like package extensions are candidates.
        links = re.findall(r"https://(?:servers\.asus\.com|www\.asus\.com|dlcdnets\.asus\.com)[^\s\"'<>\\]+", text, flags=re.IGNORECASE)
        links = list(dict.fromkeys(link.rstrip(".,);]") for link in links))
        sha_match = re.search(r"(?i)(?:sha[-_ ]?256|checksum|hash)[^a-f0-9]{0,40}([a-f0-9]{64})", text)
        vendor_sha = sha_match.group(1).lower() if sha_match else ""
        exact_page = self._model_slug(fingerprint.model) in self._model_slug(url) if exact_page is None else exact_page
        board_match = re.search(re.escape(fingerprint.board), text, flags=re.IGNORECASE) if fingerprint.board else None
        bmc_match = re.search(r"(?i)\bASMB\s*\d+\b", text)
        entries: list[dict[str, Any]] = []
        for link in links:
            parsed = urlparse(link)
            filename = Path(parsed.path).name
            if not filename or not re.search(r"\.(?:zip|bin|cap|rom|ima|img|efi|exe|iso)(?:$|\?)", filename, flags=re.IGNORECASE):
                continue
            lowered = f"{filename} {link}".casefold()
            if not any(token in lowered for token in ("bios", "bmc", "asmb", "firmware", "ipmi", "uefi")):
                continue
            # The detail endpoint contains several packages in one document;
            # take the nearest version label before this specific link rather
            # than reusing the first version in the page.
            before_link = text[: text.find(link)]
            version_matches = re.findall(r"(?i)(?:version|ver|firmware)[^0-9]{0,12}([0-9][0-9a-z._-]{1,})", before_link[-2500:])
            version = version_matches[-1].strip("._-") if version_matches else self._version_from_filename(filename)
            version = version or "DISCOVERED"
            component = self._component_for_link(link)
            entry = {
                "vendor": "ASUS",
                "component": component,
                "version": version,
                "package_filename": filename,
                "source": self.name,
                "source_type": "ASUS_SUPPORT_PAGE",
                "source_url": link,
                "official_release_url": url,
                "compatible_models": [fingerprint.model] if exact_page else [],
                "compatible_boards": [fingerprint.board] if board_match else [],
                "compatible_bmc_generations": [bmc_match.group(0).replace(" ", "").upper()] if bmc_match else [],
                "vendor_sha256": vendor_sha,
                "official_source_verified": True,
                "provenance_level": "OFFICIAL_SOURCE_EXACT_PLATFORM" if exact_page else "OFFICIAL_SOURCE_DISCOVERED",
                # The official page proves source/applicability, but the
                # package bytes have not been fetched yet.  Mark this as
                # provenance-only so the generic planner can carry the exact
                # candidate into the download/own-hash phase without treating
                # it as checksum-validated.
                "validation_status": "PROVENANCE_VERIFIED" if exact_page else ("DISCOVERED_NO_VENDOR_HASH" if not vendor_sha else "DISCOVERED_VENDOR_HASH"),
                "applicability_evidence": [f"official ASUS support page: {url}"],
                "catalog_row": {"source_url": link, "support_page": url},
            }
            entries.append(entry)
        return entries

    def _discover_product_detail(self, fingerprint: AsusPlatformFingerprint) -> dict[str, Any] | None:
        product_url = f"{self.base_url}/products/Servers/Rack-Servers/{fingerprint.model}?model2Name={fingerprint.model}"
        try:
            product_body = self._request(product_url)
        except AsusFirmwareError as exc:
            return {"source": self.name, "source_type": "ASUS_PRODUCT_DETAIL_API", "product_url": product_url, "status": "SOURCE_UNAVAILABLE", "reason": str(exc), "entries": []}
        product_text = product_body.decode("utf-8", errors="replace")
        id_match = re.search(r"pageProduct\s*=\s*\{[^}]*?id:\s*[\"'](\d+)", product_text, flags=re.IGNORECASE | re.DOTALL)
        if not id_match:
            return {"source": self.name, "source_type": "ASUS_PRODUCT_DETAIL_API", "product_url": product_url, "status": "PRODUCT_ID_NOT_EXPOSED", "entries": []}
        product_id = id_match.group(1)
        detail_url = f"{self.base_url}/{self.locale}/products/detail/BiosFirmware/{product_id}"
        try:
            detail_body = self._request(detail_url)
            entries = self._entries_from_support_page(detail_url, detail_body, fingerprint, exact_page=True)
            return {"source": self.name, "source_type": "ASUS_PRODUCT_DETAIL_API", "product_url": product_url, "detail_url": detail_url, "product_id": product_id, "status": "EXACT_ENTRIES_FOUND" if entries else "NO_FIRMWARE_LINKS_FOUND", "entries": entries}
        except AsusFirmwareError as exc:
            return {"source": self.name, "source_type": "ASUS_PRODUCT_DETAIL_API", "product_url": product_url, "detail_url": detail_url, "product_id": product_id, "status": "SOURCE_UNAVAILABLE", "reason": str(exc), "entries": []}

    def _discover_api(self, fingerprint: AsusPlatformFingerprint) -> dict[str, Any]:
        support_url = f"{self.base_url}/support/firmware"
        try:
            page = self._request(support_url).decode("utf-8", errors="replace")
        except AsusFirmwareError as exc:
            return {"source": self.name, "source_type": "ASUS_SERVER_CATALOG", "status": "SOURCE_UNAVAILABLE", "reason": str(exc), "entries": []}
        web_match = re.search(r'webSiteCode\s*:\s*["\']([^"\']+)', page)
        web_code = web_match.group(1) if web_match else self.locale
        filters: dict[str, list[int]] = {}
        for field_name, value in re.findall(r'name="(FilterField\d+)"[^>]+value="(\d+)"', page):
            filters.setdefault(field_name, []).append(int(value))
        payload = json.dumps({"fields": filters, "keyword": None}).encode("utf-8")
        endpoint = f"{self.base_url}/{web_code}/support/firmware/list"
        try:
            response = self._request(endpoint, method="POST", body=b"json=" + payload, content_type="application/x-www-form-urlencoded")
            document = json.loads(response.decode("utf-8", errors="replace"))
        except (AsusFirmwareError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            return {"source": self.name, "source_type": "ASUS_SERVER_CATALOG", "status": "SOURCE_PARSE_FAILED", "reason": type(exc).__name__, "entries": []}
        rows = document.get("data", []) if isinstance(document, Mapping) else []
        entries: list[dict[str, Any]] = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, Mapping):
                continue
            model = _clean(row.get("field2") or row.get("model"))
            link = _download_url(row.get("downloadUrl") or row.get("download_url"))
            if not model or not link or not _is_official_asus_url(link):
                continue
            filename = Path(urlparse(link).path).name or f"{model}.firmware"
            component = self._component_for_link(f"{filename} {link}")
            vendor_sha = _clean(row.get("sha256") or row.get("sha256sum") or row.get("checksum"))
            if not re.fullmatch(r"[a-fA-F0-9]{64}", vendor_sha):
                vendor_sha = ""
            row_version = _clean(row.get("version")) or self._version_from_filename(filename) or "DISCOVERED"
            entries.append({
                "vendor": "ASUS", "component": component, "version": row_version,
                "package_filename": filename, "source": self.name, "source_type": "ASUS_SERVER_CATALOG",
                "source_url": link, "official_release_url": support_url,
                "compatible_models": [model], "compatible_boards": [], "vendor_sha256": vendor_sha,
                "official_source_verified": True, "provenance_level": "OFFICIAL_SOURCE_EXACT_PLATFORM" if _exact_key(model) == _exact_key(fingerprint.model) else "OFFICIAL_SOURCE_DISCOVERED",
                "validation_status": "PROVENANCE_VERIFIED" if _exact_key(model) == _exact_key(fingerprint.model) else ("DISCOVERED_VENDOR_HASH" if vendor_sha else "DISCOVERED_NO_VENDOR_HASH"),
                "applicability_evidence": [f"official ASUS server compatibility row: {model}"],
                "catalog_row": dict(row),
            })
        return {"source": self.name, "source_type": "ASUS_SERVER_CATALOG", "status": "DISCOVERY_COMPLETE", "support_url": support_url, "catalog_endpoint": endpoint, "filters_used": filters, "entries": entries, "model_queried": fingerprint.model}

    def _discover_product_firmware_api(self, fingerprint: AsusPlatformFingerprint) -> dict[str, Any]:
        """Query ASUS' current product firmware API for an exact model.

        The support-page HTML is now a shell around this API and often does
        not contain the download URLs at all.  Treat the API response as
        official applicability metadata, but retain the exact model returned
        by ASUS and never widen it to a family or similarly named SKU.
        """
        model = _clean(fingerprint.model)
        if not model:
            return {"source": self.name, "source_type": "ASUS_PRODUCT_FIRMWARE_API", "status": "MODEL_MISSING", "entries": []}
        slug = self._model_slug(model)
        website = "wa" if self.locale.casefold() == "global" else self.locale
        endpoint = (
            "https://www.asus.com/support/webapi/ProductV2/GetPDBIOS"
            f"?website={website}&model={slug}&pdhashedid=&pdid=99999&cpu=&siteID=www&sitelang="
        )
        try:
            payload = json.loads(self._request(endpoint).decode("utf-8", errors="replace"))
        except (AsusFirmwareError, json.JSONDecodeError, UnicodeDecodeError):
            return {"source": self.name, "source_type": "ASUS_PRODUCT_FIRMWARE_API", "status": "SOURCE_PARSE_FAILED", "endpoint": endpoint, "entries": []}
        result = payload.get("Result") if isinstance(payload, Mapping) else {}
        returned_model = _clean(result.get("Model") if isinstance(result, Mapping) else "")
        if not returned_model or _exact_key(returned_model) != _exact_key(model):
            return {
                "source": self.name,
                "source_type": "ASUS_PRODUCT_FIRMWARE_API",
                "status": "EXACT_MODEL_NOT_CONFIRMED",
                "endpoint": endpoint,
                "returned_model": returned_model,
                "entries": [],
            }
        entries: list[dict[str, Any]] = []
        groups = result.get("Obj", []) if isinstance(result, Mapping) else []
        for group in groups if isinstance(groups, list) else []:
            if not isinstance(group, Mapping):
                continue
            group_name = _clean(group.get("Name") or "").upper()
            files = group.get("Files", [])
            for item in files if isinstance(files, list) else []:
                if not isinstance(item, Mapping):
                    continue
                download = item.get("DownloadUrl") if isinstance(item.get("DownloadUrl"), Mapping) else {}
                relative = _clean(download.get("Global") or download.get("global") or "")
                if not relative.startswith("/"):
                    continue
                source_url = "https://dlcdnets.asus.com" + relative
                if not _is_official_asus_url(source_url):
                    continue
                filename = Path(urlparse(source_url).path).name
                if not filename:
                    continue
                component = "BMC" if group_name in {"FIRMWARE", "BMC"} or re.search(r"(?i)(?:ASMB|BMC|IPMI)", filename) else "BIOS"
                vendor_sha = _clean(item.get("sha256") or "").lower()
                if not re.fullmatch(r"[a-f0-9]{64}", vendor_sha):
                    vendor_sha = ""
                # The package naming convention uses an underscore directly
                # after the generation (``ASMB11_FW...``), so word-boundary
                # matching would miss it.
                bmc_match = re.search(r"(?i)(ASMB\d+)", filename)
                board = fingerprint.board if component == "BIOS" and fingerprint.board and _exact_key(fingerprint.board).split()[0] in _exact_key(filename) else ""
                entries.append(
                    {
                        "vendor": "ASUS",
                        "component": component,
                        "version": _clean(item.get("Version") or "") or self._version_from_filename(filename),
                        "package_filename": filename,
                        "source": self.name,
                        "source_type": "ASUS_PRODUCT_FIRMWARE_API",
                        "source_url": source_url,
                        "official_release_url": f"https://www.asus.com/supportonly/{slug}/helpdesk_bios/",
                        "compatible_models": [returned_model],
                        "compatible_boards": [fingerprint.board] if board else [],
                        "compatible_bmc_generations": [bmc_match.group(1).upper()] if bmc_match else [],
                        "vendor_sha256": vendor_sha,
                        "official_source_verified": True,
                        "provenance_level": "OFFICIAL_SOURCE_EXACT_PLATFORM",
                        "validation_status": "PROVENANCE_VERIFIED",
                        "applicability_evidence": [
                            f"ASUS ProductV2 firmware API exact model: {returned_model}",
                            f"ASUS firmware group: {group_name or 'UNKNOWN'}",
                        ],
                        "package_metadata_evidence": [
                            f"ASUS API file id: {_clean(item.get('Id') or '')}",
                            f"ASUS API release date: {_clean(item.get('ReleaseDate') or '')}",
                        ],
                        "catalog_row": dict(item),
                    }
                )
        return {
            "source": self.name,
            "source_type": "ASUS_PRODUCT_FIRMWARE_API",
            "status": "EXACT_ENTRIES_FOUND" if entries else "NO_FIRMWARE_ENTRIES",
            "endpoint": endpoint,
            "returned_model": returned_model,
            "entries": entries,
        }

    def discover(self, fingerprint: AsusPlatformFingerprint) -> Mapping[str, Any]:
        results: list[dict[str, Any]] = [self._discover_product_firmware_api(fingerprint), self._discover_api(fingerprint)]
        product_detail = self._discover_product_detail(fingerprint)
        if product_detail is not None:
            results.append(product_detail)
        for support_url in self._support_page_urls(fingerprint):
            try:
                body = self._request(support_url)
                entries = self._entries_from_support_page(support_url, body, fingerprint)
                results.append({"source": self.name, "source_type": "ASUS_SUPPORT_PAGE", "support_url": support_url, "status": "EXACT_ENTRIES_FOUND" if entries else "NO_FIRMWARE_LINKS_FOUND", "entries": entries})
            except AsusFirmwareError as exc:
                results.append({"source": self.name, "source_type": "ASUS_SUPPORT_PAGE", "support_url": support_url, "status": "SOURCE_UNAVAILABLE", "reason": str(exc), "entries": []})
        entries: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for result in results:
            for entry in result.get("entries", []):
                key = (_clean(entry.get("component")), _clean(entry.get("version")), _clean(entry.get("source_url")))
                if key not in seen:
                    entries.append(dict(entry)); seen.add(key)
        exact = [entry for entry in entries if any(_exact_key(fingerprint.model) == _exact_key(item) for item in entry.get("compatible_models", []))]
        return {
            "source": self.name,
            "status": "EXACT_ENTRIES_FOUND" if exact else "NO_EXACT_OFFICIAL_MATCH",
            "model_queried": fingerprint.model,
            "source_results": results,
            "entries": entries,
            "exact_entry_count": len(exact),
            "discovery_paths_attempted": len(results),
        }


@dataclass(frozen=True)
class AsusFirmwarePlan:
    platform: AsusPlatformFingerprint
    catalog: Mapping[str, Any]
    transports: Mapping[str, Any]
    components: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "platform": self.platform.to_dict(),
            "catalog": dict(self.catalog),
            "transports": dict(self.transports),
            "components": dict(self.components),
            "mutation_authorized": False,
        }


class AsusFirmwareEngine:
    """Plan and execute ASUS firmware work for any discovered platform."""

    def __init__(self, *, catalog_sources: Sequence[AsusCatalogSource] = ()) -> None:
        self.catalog_sources = tuple(catalog_sources)

    @staticmethod
    def fetch_verified_package(
        metadata: FirmwarePackageMetadata,
        *,
        repository: FirmwareRepository,
        downloader: PackageDownloader,
    ) -> tuple[Path, str]:
        """Download/reuse a package after own-hash and provenance checks.

        ``metadata.sha256`` is always our pinned digest.  A vendor digest is
        optional: when ASUS does not publish one, an official HTTPS source,
        exact applicability evidence and package metadata/signature evidence
        provide the second, independent provenance leg.
        """
        metadata.validate()
        if metadata.sha256.casefold() == "0" * 64:
            raise AsusFirmwareError("OWN_SHA256_REQUIRED_BEFORE_DOWNLOAD")
        # ``source_url`` is the immutable package download location.  The
        # separate ``official_release_url`` is normally the ASUS support page
        # that proves provenance; preferring it here would download HTML (or
        # a support shell) instead of the firmware bytes.  Keep the fallback
        # for older catalog records that stored only one URL.
        source_url = metadata.source_url or metadata.official_release_url
        if not _is_official_asus_url(source_url):
            raise AsusFirmwareError("OFFICIAL_ASUS_SOURCE_REQUIRED")
        if metadata.vendor_sha256 and metadata.vendor_sha256.casefold() != metadata.sha256.casefold():
            raise AsusFirmwareError("VENDOR_SHA256_DOES_NOT_MATCH_PACKAGE_METADATA")
        if not metadata.vendor_sha256:
            if not metadata.official_source_verified or metadata.provenance_level not in {"OFFICIAL_SOURCE_EXACT_PLATFORM", "PROVENANCE_VERIFIED"}:
                raise AsusFirmwareError("STRONG_OFFICIAL_PROVENANCE_REQUIRED_WITHOUT_VENDOR_HASH")
            if not metadata.applicability_evidence or not metadata.package_metadata_evidence:
                raise AsusFirmwareError("PACKAGE_METADATA_EVIDENCE_REQUIRED_WITHOUT_VENDOR_HASH")
            if metadata.validation_status not in {"PROVENANCE_VERIFIED", "CHECKSUM_VERIFIED_WITHOUT_VENDOR_HASH", "OFFICIAL_SOURCE_VERIFIED"}:
                raise AsusFirmwareError("PACKAGE_NOT_PROVENANCE_VALIDATED")
        try:
            return repository.fetch_if_missing(metadata, downloader=downloader)
        except FirmwareRepositoryError as exc:
            raise AsusFirmwareError("VERIFIED_PACKAGE_FETCH_FAILED") from exc

    @staticmethod
    def _inspect_package(path: Path, *, fingerprint: AsusPlatformFingerprint, component: str) -> tuple[str, tuple[str, ...], str]:
        """Collect bounded, non-executing package evidence."""
        suffix = path.suffix.casefold().lstrip(".") or "unknown"
        evidence: list[str] = [f"package_size_bytes={path.stat().st_size}"]
        signature = "NOT_PUBLISHED"
        if zipfile.is_zipfile(path):
            suffix = "zip"
            with zipfile.ZipFile(path) as archive:
                names = [item.filename for item in archive.infolist() if not item.is_dir()]
                evidence.append("archive_members=" + ",".join(names[:80]))
                for name in names[:80]:
                    if Path(name).suffix.casefold() not in {".txt", ".md", ".json", ".xml", ".ini", ".cfg"}:
                        continue
                    try:
                        raw = archive.read(name)
                    except (KeyError, RuntimeError, ValueError):
                        continue
                    sample = raw[:256 * 1024].decode("utf-8", errors="replace")
                    if fingerprint.model.casefold() in sample.casefold():
                        evidence.append(f"manifest_model_match={name}")
                    if fingerprint.board and fingerprint.board.casefold() in sample.casefold():
                        evidence.append(f"manifest_board_match={name}")
                    generation = fingerprint.bmc_generation
                    if generation and generation.casefold() in sample.casefold():
                        evidence.append(f"manifest_bmc_generation_match={name}")
                    if re.search(r"(?i)(sha[-_ ]?256|signature|signed|certificate)", sample):
                        signature = "PACKAGE_METADATA_DECLARED"
        evidence.append(f"package_suffix={suffix}")
        return suffix.upper(), tuple(evidence), signature

    @classmethod
    def resolve_and_cache_candidate(
        cls,
        entry: Mapping[str, Any],
        *,
        fingerprint: AsusPlatformFingerprint,
        repository: FirmwareRepository,
        downloader: PackageDownloader,
    ) -> tuple[FirmwarePackageMetadata, Path, str]:
        """Fetch one exact official entry, pin our hash, inspect and cache it."""
        source_url = _clean(entry.get("source_url") or entry.get("download_url"))
        if not _is_official_asus_url(source_url):
            raise AsusFirmwareError("OFFICIAL_ASUS_DOWNLOAD_URL_REQUIRED")
        provisional = FirmwarePackageMetadata.from_dict({
            **dict(entry),
            "sha256": "0" * 64,
            "validation_status": "DISCOVERED_NO_VENDOR_HASH",
            "compatible_models": tuple(entry.get("compatible_models") or ()),
            "compatible_boards": tuple(entry.get("compatible_boards") or ()),
            "applicability_evidence": tuple(entry.get("applicability_evidence") or ()),
        })
        # This pre-download check proves only official-source/exact-platform
        # applicability.  The all-zero digest is an explicit "bytes not yet
        # downloaded" sentinel; it is never used as package integrity proof.
        # The real SHA256 is calculated from the completed download below and
        # is the only digest passed to repository.ingest().
        preflight = FirmwarePackageMetadata.from_dict(
            provisional.to_dict()
            | {
                "sha256": "0" * 64,
                "validation_status": "PROVENANCE_VERIFIED",
                "package_metadata_evidence": ("exact-catalog-entry-preflight",),
                "official_source_verified": True,
                "provenance_level": "OFFICIAL_SOURCE_EXACT_PLATFORM",
            }
        )
        decision = match_asus_package(preflight, fingerprint)
        if not decision.exact_match:
            raise AsusFirmwareError("EXACT_ASUS_PLATFORM_MATCH_REQUIRED")
        repository.initialize()
        descriptor, temporary_name = tempfile.mkstemp(prefix="asus-firmware-resolve-", suffix=".partial", dir=repository.root)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            downloader.download(source_url, temporary)
            digest = package_sha256(temporary)
            package_format, package_evidence, signature_status = cls._inspect_package(temporary, fingerprint=fingerprint, component=_clean(entry.get("component")))
            vendor_sha = _clean(entry.get("vendor_sha256"))
            if vendor_sha and vendor_sha.casefold() != digest.casefold():
                raise AsusFirmwareError("PUBLISHED_VENDOR_SHA256_MISMATCH")
            metadata = FirmwarePackageMetadata.from_dict({
                **dict(entry),
                "sha256": digest,
                "vendor_sha256": vendor_sha,
                "package_format": package_format,
                "official_release_url": _clean(entry.get("official_release_url") or source_url),
                "official_source_verified": True,
                "provenance_level": "PROVENANCE_VERIFIED",
                "package_signature_status": signature_status,
                "package_metadata_evidence": package_evidence,
                "validation_status": "CHECKSUM_VERIFIED" if vendor_sha else "CHECKSUM_VERIFIED_WITHOUT_VENDOR_HASH",
                "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
                "size_bytes": temporary.stat().st_size,
            })
            final_path = repository.ingest(temporary, metadata)
            return metadata, final_path, "DOWNLOADED_AND_OWN_HASH_PINNED"
        finally:
            temporary.unlink(missing_ok=True)

    @classmethod
    def prepare_plan_packages(
        cls,
        plan: AsusFirmwarePlan,
        *,
        repository: FirmwareRepository,
        downloader: PackageDownloader,
        components: Sequence[str] = ("BIOS", "BMC"),
    ) -> dict[str, Any]:
        """Resolve the newest exact candidates in a plan into the cache.

        Discovery and package preparation are deliberately separate from
        mutation.  This method may download and hash an official package, but
        it never selects a transport, opens a mutation gate, reboots a host,
        or sends a Redfish write.  A published ASUS digest is checked when
        present; otherwise the resolver pins the local SHA-256 and requires
        strong official provenance and package evidence.
        """
        prepared: dict[str, Any] = {}
        for component_name in components:
            component = str(component_name).upper()
            component_plan = plan.components.get(component, {}) if isinstance(plan.components, Mapping) else {}
            candidates = [
                item for item in (component_plan.get("candidates") or [])
                if isinstance(item, Mapping) and bool((item.get("match") or {}).get("exact_match"))
            ]
            if not candidates:
                prepared[component] = {"status": "NO_EXACT_OFFICIAL_MATCH", "reason": "No exact candidate was discovered."}
                continue
            selected = max(candidates, key=lambda item: _version_key(str((item.get("metadata") or {}).get("version") or "")))
            entry = dict(selected.get("metadata") or {})
            try:
                candidate_sha = str(entry.get("sha256") or "").lower()
                if candidate_sha and candidate_sha != "0" * 64:
                    metadata = FirmwarePackageMetadata.from_dict(entry)
                    path, status = cls.fetch_verified_package(metadata, repository=repository, downloader=downloader)
                else:
                    # Live ASUS catalog responses deliberately carry an
                    # all-zero own digest until the bytes are downloaded.  A
                    # previous run may already have pinned those bytes in the
                    # content-addressed repository, however.  Reuse only an
                    # exact model/component/version/source match, with the
                    # vendor digest when ASUS publishes one, and re-verify
                    # the cached object before returning it.  This rejects
                    # stale/cross-model entries while avoiding needless repeat
                    # downloads on the same SSD.
                    cached_match: tuple[FirmwarePackageMetadata, Path] | None = None
                    expected_version = _clean(entry.get("version"))
                    expected_filename = _clean(entry.get("package_filename"))
                    expected_source = _clean(entry.get("source_url"))
                    expected_vendor_sha = _clean(entry.get("vendor_sha256")).lower()
                    for cached in repository.find_candidates(vendor="ASUS", component=component):
                        if cached.version != expected_version or cached.package_filename != expected_filename:
                            continue
                        if expected_source and cached.source_url != expected_source:
                            continue
                        if expected_vendor_sha and cached.vendor_sha256.casefold() != expected_vendor_sha:
                            continue
                        if not expected_vendor_sha and cached.validation_status not in ASUS_VALIDATED_PACKAGE_STATUSES:
                            continue
                        if not any(
                            _exact_key(plan.platform.model) == _exact_key(model)
                            for model in cached.compatible_models
                        ):
                            continue
                        try:
                            cached_path = repository.verify(cached.sha256)
                        except FirmwareRepositoryError:
                            continue
                        cached_match = (cached, cached_path)
                        break
                    if cached_match is not None:
                        metadata, path = cached_match
                        status = "CACHE_HIT_PROVENANCE_VERIFIED"
                    else:
                        metadata, path, status = cls.resolve_and_cache_candidate(
                            entry,
                            fingerprint=plan.platform,
                            repository=repository,
                            downloader=downloader,
                        )
                prepared[component] = {
                    "status": "PACKAGE_READY",
                    "resolution": status,
                    "path": str(path),
                    "sha256": metadata.sha256,
                    "vendor_sha256": metadata.vendor_sha256 or "NOT_PUBLISHED",
                    "version": metadata.version,
                    "package_filename": metadata.package_filename,
                    "validation_status": metadata.validation_status,
                    # Dynamic official-catalog candidates begin with a
                    # provenance-only record (SHA256 all zeroes).  Return the
                    # finalized metadata so the executor uses the downloaded
                    # bytes' pinned digest rather than the preflight record.
                    "metadata": metadata.to_dict(),
                }
            except (AsusFirmwareError, FirmwareRepositoryError, OSError, ValueError) as exc:
                prepared[component] = {
                    "status": "PACKAGE_RESOLUTION_FAILED",
                    "reason": str(exc) if isinstance(exc, AsusFirmwareError) else type(exc).__name__,
                    "package_filename": str(entry.get("package_filename") or ""),
                    "version": str(entry.get("version") or ""),
                }
        return prepared

    @staticmethod
    def execute_component(
        *,
        identity: Mapping[str, Any],
        metadata: FirmwarePackageMetadata,
        fingerprint: AsusPlatformFingerprint,
        repository: FirmwareRepository,
        adapter: Any,
        mutation_gate: Any,
        run_id: str,
        progress_callback: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Run the common immutable executor after exact ASUS matching."""
        decision = match_asus_package(metadata, fingerprint)
        if not decision.exact_match:
            raise AsusFirmwareError("EXACT_ASUS_PLATFORM_MATCH_REQUIRED")
        from .firmware import ApplicabilityDecision
        from .firmware_executor import FirmwareUpdateExecutor

        applicability = ApplicabilityDecision(
            status="APPLICABLE",
            reason_codes=decision.reason_codes,
            package_sha256=metadata.sha256,
            current_version=str(identity.get("current_version") or ""),
            target_version=metadata.version,
            catalog_id=str(identity.get("catalog_id") or "ASUS_OFFICIAL_CATALOG"),
            evidence=decision.evidence,
        )
        return FirmwareUpdateExecutor(repository).execute(
            identity=identity,
            metadata=metadata,
            applicability=applicability,
            adapter=adapter,
            mutation_gate=mutation_gate,
            run_id=run_id,
            progress_callback=progress_callback,
        )

    def plan(
        self,
        *,
        fingerprint: AsusPlatformFingerprint,
        current_versions: Mapping[str, str],
        redfish_discovery: Mapping[str, Any] | None = None,
        local_tools: Mapping[str, Any] | None = None,
        catalog_documents: Sequence[Mapping[str, Any]] = (),
    ) -> AsusFirmwarePlan:
        catalog_results: list[Mapping[str, Any]] = []
        for source in self.catalog_sources:
            try:
                catalog_results.append(dict(source.discover(fingerprint)))
            except Exception as exc:
                catalog_results.append({"source": getattr(source, "name", type(source).__name__), "status": "SOURCE_ERROR", "reason": type(exc).__name__, "entries": []})
        catalog_results.extend(dict(document) for document in catalog_documents)
        all_entries = [entry for result in catalog_results for entry in result.get("entries", []) if isinstance(entry, Mapping)]
        # Some ASMB generations do not expose their marketing name through
        # unauthenticated IPMI/Redfish.  When the exact ASUS catalog entry
        # names one generation for this exact model, promote that metadata to
        # the live planning fingerprint.  A missing or conflicting generation
        # remains unknown and therefore cannot authorize a cross-generation
        # update.
        effective_fingerprint = fingerprint
        if not fingerprint.bmc_generation:
            generations = {
                str(value).replace(" ", "").upper()
                for entry in all_entries
                if _exact_key(entry.get("vendor")) == _exact_key(fingerprint.vendor)
                and any(_exact_key(fingerprint.model) == _exact_key(item) for item in (entry.get("compatible_models") or ()))
                for value in (entry.get("compatible_bmc_generations") or ())
                if _clean(value)
            }
            if len(generations) == 1:
                generation = next(iter(generations))
                effective_fingerprint = replace(
                    fingerprint,
                    bmc_generation=generation,
                    bmc_model=fingerprint.bmc_model or f"{generation}-iKVM",
                    platform_id=":".join(item for item in (fingerprint.model, fingerprint.board, generation) if item),
                    evidence=dict(fingerprint.evidence)
                    | {
                        "bmc_generation": {
                            "value": generation,
                            "source": "ASUS_OFFICIAL_EXACT_MODEL_FIRMWARE_METADATA",
                        }
                    },
                )
        transports = discover_asus_transports(
            redfish_discovery=redfish_discovery,
            local_tools=local_tools,
            fingerprint=effective_fingerprint,
        )
        component_plans: dict[str, Any] = {}
        for component in ("BIOS", "BMC"):
            current = _clean(current_versions.get(component, ""))
            candidates: list[dict[str, Any]] = []
            for entry in all_entries:
                if _clean(entry.get("component")) not in {component, "UNKNOWN"}:
                    continue
                try:
                    metadata_payload = dict(entry)
                    metadata_payload.setdefault("sha256", str(entry.get("sha256") or "0" * 64))
                    metadata_payload.setdefault("compatible_families", ())
                    metadata_payload.setdefault("compatible_models", ())
                    metadata_payload.setdefault("compatible_boards", ())
                    metadata_payload.setdefault("applicability_evidence", ())
                    metadata = FirmwarePackageMetadata.from_dict(metadata_payload)
                except Exception as exc:
                    candidates.append({"status": "REJECTED", "reason_codes": ["MALFORMED_CATALOG_ENTRY", type(exc).__name__], "entry": dict(entry)})
                    continue
                decision = match_asus_package(metadata, effective_fingerprint)
                candidates.append({"metadata": metadata.to_dict(), "match": decision.to_dict()})
            applicable = [
                item for item in candidates
                if item.get("match", {}).get("exact_match")
                and item.get("metadata", {}).get("validation_status") in ASUS_VALIDATED_PACKAGE_STATUSES
                and str(item.get("metadata", {}).get("sha256")) != "0" * 64
            ]
            # A live ASUS catalog can prove exact platform applicability and
            # official provenance before the package bytes are downloaded.
            # Carry that candidate into prepare_plan_packages so the executor
            # can download it, pin our own SHA256, inspect it, and only then
            # authorize mutation.  It is never treated as checksum-verified
            # at this planning stage.
            provenance_only = [
                item for item in candidates
                if item.get("match", {}).get("exact_match")
                and item.get("metadata", {}).get("validation_status") == "PROVENANCE_VERIFIED"
                and str(item.get("metadata", {}).get("sha256")) == "0" * 64
                and str(item.get("metadata", {}).get("version") or "").upper() not in {"", "DISCOVERED", "UNKNOWN"}
            ]
            selected = max(applicable or provenance_only, key=lambda item: _version_key(str(item["metadata"].get("version")))) if (applicable or provenance_only) else None
            transport = transports.get("components", {}).get(component, {}) if isinstance(transports, Mapping) else {}
            selected_transport = transport.get("selected") if isinstance(transport, Mapping) else None
            status = "NO_EXACT_OFFICIAL_PACKAGE"
            reason = "No exact, provenance-verified ASUS package with a pinned local SHA256 is present in the discovered catalog."
            target = ""
            if selected:
                target = str(selected["metadata"].get("version") or "")
                if current and _version_key(target) <= _version_key(current):
                    if selected in provenance_only:
                        status, reason = "CURRENT", "Installed version matches exact official ASUS provenance metadata; no package mutation is required."
                    else:
                        status, reason = "CURRENT", "Installed version is not older than the selected exact package."
                elif selected_transport:
                    if selected in provenance_only:
                        status, reason = "READY_FOR_OPERATOR_CONFIRMATION", "Exact package applicability is proven; package download, own-SHA256 pinning and integrity inspection are required before mutation."
                    else:
                        status, reason = "READY_FOR_OPERATOR_CONFIRMATION", "Exact package, checksum status and a supported transport are available."
                else:
                    status, reason = "NO_SUPPORTED_TRANSPORT", "Exact package is known, but no selectable transport is advertised for this component."
            component_plans[component] = {
                "current_version": current,
                "target_version": target,
                "status": status,
                "reason": reason,
                "selected_package": selected,
                "selected_transport": selected_transport,
                "candidates": candidates,
            }
        catalog = {
            "sources": catalog_results,
            "entry_count": len(all_entries),
            "exact_platform_required": True,
            "family_only_substitution_allowed": False,
        }
        return AsusFirmwarePlan(effective_fingerprint, catalog, transports, component_plans)


def package_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
