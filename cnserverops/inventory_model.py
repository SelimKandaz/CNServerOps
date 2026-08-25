"""Normalized, provenance-aware inventory for operator and engineering outputs.

Raw command evidence remains authoritative.  This module derives a stable,
credential-free presentation model without hiding source conflicts.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .secrets import assert_no_sensitive_fields
from .bmc_version import parse_ipmi_mc_firmware_version


INVENTORY_CATEGORIES = frozenset(
    {
        "SYSTEM",
        "CHASSIS",
        "MOTHERBOARD",
        "MANAGEMENT_MODULE",
        "CPU",
        "MEMORY",
        "STORAGE",
        "RAID/HBA",
        "NIC/OCP",
        "PSU",
        "GPU/ACCELERATOR",
        "BMC",
        "FIRMWARE",
    }
)

_MISSING = {"", "none", "not specified", "not provided", "unknown", "to be filled by o.e.m.", "n/a"}
_VIRTUAL_INTERFACE = re.compile(
    r"^(lo|docker\d*|br-.+|virbr\d*|veth.+|cni\d*|flannel.+|tun\d*|tap\d*|wg\d*|dummy\d*|ifb\d*)$",
    re.IGNORECASE,
)
_MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", re.IGNORECASE)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean_value(value: Any) -> str:
    text = " ".join(str(value or "").replace("\x00", " ").split()).strip()
    return "" if text.lower() in _MISSING else text


def normalize_mac(value: Any) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(compact) != 12 or compact == "0" * 12:
        return ""
    normalized = ":".join(compact[index : index + 2] for index in range(0, 12, 2)).upper()
    if not _MAC.fullmatch(normalized) or int(compact[:2], 16) & 1:
        return ""
    return normalized


def safe_component_id(category: str, *parts: Any) -> str:
    suffix = "-".join(
        re.sub(r"[^A-Za-z0-9._-]+", "-", clean_value(part)).strip("-")
        for part in parts
        if clean_value(part)
    )
    return f"{category.replace('/', '-')}-{suffix or 'UNKNOWN'}".upper()[:128]


@dataclass(frozen=True)
class FieldEvidence:
    value: Any
    source: str
    freshness: str
    confidence: str
    conflict: str = ""
    raw_reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComponentRecord:
    category: str
    component_id: str
    slot: str = ""
    location: str = ""
    manufacturer: str = ""
    model: str = ""
    part_number: str = ""
    serial: str = ""
    firmware: str = ""
    health: str = "UNKNOWN"
    status: str = "PRESENT"
    interface: str = ""
    pci_address: str = ""
    physical_port: str = ""
    capacity_bytes: int | None = None
    identifiers: dict[str, str] = field(default_factory=dict)
    mac_addresses: list[str] = field(default_factory=list)
    field_evidence: dict[str, FieldEvidence] = field(default_factory=dict)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.category not in INVENTORY_CATEGORIES:
            raise ValueError(f"unsupported normalized inventory category: {self.category}")
        self.mac_addresses = sorted({item for item in (normalize_mac(value) for value in self.mac_addresses) if item})
        self.identifiers = {str(key): clean_value(value) for key, value in self.identifiers.items() if clean_value(value)}

    def add_evidence(
        self,
        name: str,
        value: Any,
        *,
        source: str,
        freshness: str,
        confidence: str,
        conflict: str = "",
        raw_reference: str = "",
    ) -> None:
        self.field_evidence[name] = FieldEvidence(
            value=value,
            source=source,
            freshness=freshness,
            confidence=confidence,
            conflict=conflict,
            raw_reference=raw_reference,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["field_evidence"] = {key: value.to_dict() for key, value in self.field_evidence.items()}
        return payload


@dataclass
class NormalizedInventory:
    server_id: str
    run_id: str
    runner_id: str
    boot_id: str
    vendor: str
    model: str
    system_serial: str
    components: list[ComponentRecord]
    primary_host_mac: str = ""
    bmc_auth_state: str = "BMC_AUTH_UNAVAILABLE"
    bmc_ip: str = ""
    bmc_mac: str = ""
    bmc_channel: str = ""
    # A physical NIC/card serial is a component identity, not a replacement
    # for the server's trusted DMI/FRU system serial.  These fields make that
    # distinction explicit for Central and operator reports.
    nic_identity_anchors: list[dict[str, Any]] = field(default_factory=list)
    identity_fallback: dict[str, Any] = field(default_factory=dict)
    collected_at_utc: str = field(default_factory=utc_now)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    schema_version: int = 2

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["components"] = [component.to_dict() for component in self.components]
        payload["component_counts"] = {
            category: sum(1 for component in self.components if component.category == category)
            for category in sorted(INVENTORY_CATEGORIES)
        }
        payload["sensitive_data_excluded"] = True
        assert_no_sensitive_fields(payload)
        return payload


def parse_dmidecode(text: str) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in str(text or "").splitlines():
        match = re.match(r"^Handle\s+\S+,\s+DMI type\s+(\d+)", raw_line)
        if match:
            if current:
                blocks.append(current)
            current = {"dmi_type": int(match.group(1)), "name": "", "fields": {}}
            continue
        if current is None:
            continue
        if raw_line and not raw_line[0].isspace() and not current["name"]:
            current["name"] = clean_value(raw_line)
            continue
        field_match = re.match(r"^\s+([^:\t]+):\s*(.*?)\s*$", raw_line)
        if field_match:
            key, value = clean_value(field_match.group(1)), clean_value(field_match.group(2))
            if key and value and key not in current["fields"]:
                current["fields"][key] = value
    if current:
        blocks.append(current)
    return blocks


def parse_ipmi_fru_sections(text: str) -> list[dict[str, str]]:
    sections: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in str(text or "").splitlines():
        match = re.match(r"^([^:]+?)\s*:\s*(.*?)\s*$", line)
        if not match:
            continue
        key, value = clean_value(match.group(1)), clean_value(match.group(2))
        if key.lower() == "fru device description" and current:
            sections.append(current)
            current = {}
        if key and value:
            current[key] = value
    if current:
        sections.append(current)
    return sections


def parse_key_value(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in str(text or "").splitlines():
        match = re.match(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$", line)
        if match:
            key, value = clean_value(match.group(1)), clean_value(match.group(2))
            if key and value:
                values.setdefault(key, value)
    return values


def parse_pci_vpd(value: Any) -> dict[str, str]:
    """Decode PCIe VPD keyword records from a sysfs ``device/vpd`` blob.

    Linux exposes VPD as binary data.  The collector stores it as hex so the
    evidence remains JSON-safe and reproducible.  We only promote explicit
    VPD keywords (SN, PN, V1, etc.); a MAC address is never used as a serial.
    """
    if isinstance(value, bytes):
        blob = value
    else:
        text = str(value or "").strip()
        try:
            blob = bytes.fromhex(text)
        except ValueError:
            blob = text.encode("latin-1", errors="ignore")
    fields: dict[str, str] = {}
    cursor = 0
    while cursor < len(blob):
        tag = blob[cursor]
        if tag & 0x80:
            if cursor + 3 > len(blob):
                break
            length = blob[cursor + 1] | (blob[cursor + 2] << 8)
            payload = blob[cursor + 3 : cursor + 3 + length]
            cursor += 3 + length
        else:
            length = tag & 0x07
            cursor += 1 + length
            continue
        index = 0
        while index + 3 <= len(payload):
            key_bytes = payload[index : index + 2]
            try:
                key = key_bytes.decode("ascii")
            except UnicodeDecodeError:
                index += 1
                continue
            length = payload[index + 2]
            end = index + 3 + length
            if not re.fullmatch(r"[A-Z0-9]{2}", key) or end > len(payload):
                index += 1
                continue
            raw = payload[index + 3 : end]
            text_value = clean_value(raw.decode("latin-1", errors="replace"))
            if text_value:
                fields.setdefault(key, text_value)
            index = end
    return fields


def _pci_manufacturer(description: str) -> str:
    text = clean_value(description)
    match = re.search(r"\]:\s*([^:]+?)(?:\s+(?:Ethernet|Network)\b|$)", text, re.IGNORECASE)
    if match:
        return clean_value(match.group(1))
    match = re.search(r":\s*([^:]+?)(?:\s+(?:Ethernet|Network)\b|$)", text, re.IGNORECASE)
    return clean_value(match.group(1)) if match else ""


def parse_lspci(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in str(text or "").splitlines():
        match = re.match(r"^(?P<pci>[0-9A-Fa-f:.]+)\s+(?P<description>.+)$", line.strip())
        if not match:
            continue
        description = clean_value(match.group("description"))
        rows.append({"pci_address": match.group("pci").lower(), "description": description})
    return rows


def _json(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value or ""))
    except (json.JSONDecodeError, TypeError, ValueError):
        return fallback


def _stdout(raw: Mapping[str, Any], name: str) -> str:
    value = raw.get(name, "")
    if isinstance(value, Mapping):
        return str(value.get("stdout") or "")
    return str(value or "")


def _field_value(fields: Mapping[str, Any], *names: str) -> str:
    lowered = {str(key).lower(): clean_value(value) for key, value in fields.items()}
    for name in names:
        if clean_value(lowered.get(name.lower(), "")):
            return lowered[name.lower()]
    return ""


def _flatten_block_devices(devices: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for device in devices:
        if not isinstance(device, Mapping):
            continue
        result.append(device)
        children = device.get("children")
        if isinstance(children, list):
            result.extend(_flatten_block_devices(children))
    return result


def _interface_is_physical(row: Mapping[str, Any], sysfs: Mapping[str, Any]) -> tuple[bool, str]:
    name = clean_value(row.get("ifname"))
    if not name or _VIRTUAL_INTERFACE.match(name):
        return False, "software/interface-name classification"
    linkinfo = row.get("linkinfo")
    info_kind = linkinfo.get("info_kind") if isinstance(linkinfo, Mapping) else ""
    link_type = clean_value(row.get("link_type") or info_kind)
    if link_type.lower() in {"loopback", "bridge", "veth", "tun", "tap", "bond", "team", "dummy", "wireguard"}:
        return False, f"software link type {link_type}"
    details = sysfs.get(name) if isinstance(sysfs.get(name), Mapping) else {}
    if clean_value(details.get("device_path") or details.get("pci_address")):
        return True, "Linux sysfs device binding"
    if re.match(r"^(eno|enp|ens|eth)\w*", name, re.IGNORECASE):
        return True, "predictable physical-interface naming fallback"
    return False, "no physical device binding"


def _component_from_dmi(
    category: str,
    fields: Mapping[str, Any],
    *,
    slot: str,
    serial_default: str = "",
    source_ref: str = "dmidecode.txt",
) -> ComponentRecord:
    serial = _field_value(fields, "Serial Number") or serial_default
    component = ComponentRecord(
        category=category,
        component_id=safe_component_id(category, slot, serial, _field_value(fields, "Product Name", "Version")),
        slot=slot,
        location=slot,
        manufacturer=_field_value(fields, "Manufacturer"),
        model=_field_value(fields, "Product Name", "Version"),
        part_number=_field_value(fields, "Part Number"),
        serial=serial,
        firmware=_field_value(fields, "Firmware Revision"),
        health="UNKNOWN",
    )
    for name, value in {
        "manufacturer": component.manufacturer,
        "model": component.model,
        "part_number": component.part_number,
        "serial": component.serial,
        "firmware": component.firmware,
    }.items():
        if value:
            component.add_evidence(
                name,
                value,
                source="DMI/SMBIOS",
                freshness="CURRENT_BOOT",
                confidence="HIGH",
                raw_reference=source_ref,
            )
    return component


def _apply_fused_identity_evidence(
    component: ComponentRecord,
    identity: Mapping[str, Any],
    identity_field: str,
    component_field: str = "serial",
) -> None:
    fused = (identity.get("field_evidence") or {}).get(identity_field)
    if not isinstance(fused, Mapping):
        return
    reason_codes = [clean_value(item) for item in fused.get("reason_codes", []) if clean_value(item)]
    conflict = "; ".join(reason_codes)
    component.add_evidence(
        component_field,
        fused.get("value") or getattr(component, component_field, ""),
        source=clean_value(fused.get("source")) or "DMI/SMBIOS",
        freshness=clean_value(fused.get("freshness")) or "CURRENT_BOOT",
        confidence=clean_value(fused.get("confidence")) or "UNKNOWN",
        conflict=conflict,
        raw_reference="identity.field_evidence",
    )
    component.metadata[f"{component_field}_observations"] = list(fused.get("observations") or [])
    if conflict:
        component.conflicts.append(
            {
                "field": component_field,
                "detail": conflict,
                "freshness": "CONFLICTING" if fused.get("local_conflict") else "STALE_SUSPECTED",
            }
        )


def build_normalized_inventory(
    *,
    identity: Mapping[str, Any],
    platform: Mapping[str, Any],
    probe: Mapping[str, Any],
    raw: Mapping[str, Any],
    run_id: str,
    runner_id: str,
    boot_id: str,
    bmc_auth_state: str,
    network_sysfs: Mapping[str, Any] | None = None,
) -> NormalizedInventory:
    """Fuse current local evidence into a report-safe normalized model."""
    sysfs = dict(network_sysfs or {})
    components: list[ComponentRecord] = []
    dmi_blocks = parse_dmidecode(_stdout(raw, "dmidecode"))
    by_type: dict[int, list[Mapping[str, Any]]] = {}
    for block in dmi_blocks:
        by_type.setdefault(int(block["dmi_type"]), []).append(block)

    anchors = dict(identity.get("anchors") or {})
    vendor = clean_value(platform.get("vendor") or probe.get("sys_vendor")) or "UNKNOWN"
    model = clean_value(identity.get("model") or probe.get("product_name"))
    system_serial = clean_value(identity.get("primary_serial") or probe.get("system_serial"))

    system_fields = dict((by_type.get(1) or [{"fields": {}}])[0].get("fields") or {})
    system = _component_from_dmi("SYSTEM", system_fields, slot="SYSTEM", serial_default=system_serial)
    system.manufacturer = system.manufacturer or vendor
    system.model = system.model or model
    system.serial = system.serial or system_serial
    system.component_id = safe_component_id("SYSTEM", system.serial, system.model)
    _apply_fused_identity_evidence(system, identity, "system_serial")
    components.append(system)

    chassis_fields = dict((by_type.get(3) or [{"fields": {}}])[0].get("fields") or {})
    chassis = _component_from_dmi(
        "CHASSIS",
        chassis_fields,
        slot="CHASSIS",
        serial_default=clean_value(anchors.get("dmi_chassis_serial") or anchors.get("fru_chassis_serial")),
    )
    _apply_fused_identity_evidence(chassis, identity, "chassis_serial")
    components.append(chassis)

    board_fields = dict((by_type.get(2) or [{"fields": {}}])[0].get("fields") or {})
    board = _component_from_dmi(
        "MOTHERBOARD",
        board_fields,
        slot="MOTHERBOARD",
        serial_default=clean_value(anchors.get("dmi_board_serial") or anchors.get("fru_board_serial")),
    )
    _apply_fused_identity_evidence(board, identity, "board_serial")
    components.append(board)

    management = dict((identity.get("component_identities") or {}).get("MANAGEMENT_MODULE") or {})
    management_serial = clean_value(management.get("serial"))
    management_model = clean_value(management.get("model"))
    if management_serial or management_model:
        module = ComponentRecord(
            category="MANAGEMENT_MODULE",
            component_id=safe_component_id("MANAGEMENT_MODULE", management_model, management_serial),
            slot="ASMB",
            location="Management module",
            manufacturer="ASUSTeK COMPUTER INC." if management_model else "",
            model=management_model,
            serial=management_serial,
            health="INFO",
            status="PRESENT",
            interface="LOCAL_KCS/IPMI",
        )
        module.add_evidence(
            "serial",
            management_serial or "NOT_EXPOSED",
            source=str(management.get("source") or "IPMI_FRU_LOCAL_KCS"),
            freshness=str(management.get("freshness") or "STATIC_FRU"),
            confidence=str(management.get("confidence") or "HIGH"),
            raw_reference="ipmi-fru.txt",
        )
        if management_model:
            module.add_evidence(
                "model",
                management_model,
                source="IPMI_FRU_LOCAL_KCS",
                freshness="STATIC_FRU",
                confidence="HIGH",
                raw_reference="ipmi-fru.txt",
            )
        components.append(module)

    for index, block in enumerate(by_type.get(4, []), start=1):
        fields = dict(block.get("fields") or {})
        status = _field_value(fields, "Status")
        if status and "unpopulated" in status.lower():
            continue
        slot = _field_value(fields, "Socket Designation") or f"CPU{index}"
        cpu = _component_from_dmi("CPU", fields, slot=slot)
        cpu.serial = cpu.serial or "NOT_EXPOSED"
        cpu.component_id = safe_component_id("CPU", slot, cpu.model)
        cpu.health = "PASS" if not status or "enabled" in status.lower() else "REVIEW"
        cpu.metadata.update(
            {
                "cores": _field_value(fields, "Core Count", "Core Enabled"),
                "threads": _field_value(fields, "Thread Count"),
                "family": _field_value(fields, "Family"),
            }
        )
        cpu.add_evidence(
            "serial",
            cpu.serial,
            source="DMI/SMBIOS",
            freshness="CURRENT_BOOT",
            confidence="HIGH" if cpu.serial != "NOT_EXPOSED" else "NOT_EXPOSED",
            raw_reference="dmidecode.txt",
        )
        components.append(cpu)

    lscpu_payload = _json(_stdout(raw, "lscpu"), {})
    lscpu_rows = lscpu_payload.get("lscpu") if isinstance(lscpu_payload, Mapping) else []
    lscpu_fields = {
        clean_value(row.get("field")).rstrip(":"): clean_value(row.get("data"))
        for row in lscpu_rows if isinstance(row, Mapping) and clean_value(row.get("field"))
    }
    cpu_topology = {
        "sockets": lscpu_fields.get("Socket(s)", ""),
        "cores_per_socket": lscpu_fields.get("Core(s) per socket", ""),
        "threads_per_core": lscpu_fields.get("Thread(s) per core", ""),
        "logical_cpus": lscpu_fields.get("CPU(s)", ""),
        "architecture": lscpu_fields.get("Architecture", ""),
    }
    cpu_components = [item for item in components if item.category == "CPU"]
    if not cpu_components and lscpu_fields:
        cpu_model = lscpu_fields.get("Model name", "")
        cpu = ComponentRecord(
            category="CPU",
            component_id=safe_component_id("CPU", "TOPOLOGY", cpu_model),
            slot="CPU TOPOLOGY",
            location="CPU subsystem",
            model=cpu_model,
            serial="NOT_EXPOSED",
            health="PASS" if cpu_model else "REVIEW",
            metadata=cpu_topology,
        )
        cpu.add_evidence(
            "model",
            cpu_model or "NOT_EXPOSED",
            source="Linux lscpu",
            freshness="CURRENT_BOOT",
            confidence="HIGH" if cpu_model else "UNKNOWN",
            raw_reference="lscpu.txt",
        )
        cpu.add_evidence(
            "serial",
            "NOT_EXPOSED",
            source="Linux lscpu/DMI",
            freshness="CURRENT_BOOT",
            confidence="NOT_EXPOSED",
            raw_reference="lscpu.txt",
        )
        components.append(cpu)
    else:
        for cpu in cpu_components:
            cpu.metadata.update({key: value for key, value in cpu_topology.items() if value})

    for index, block in enumerate(by_type.get(17, []), start=1):
        fields = dict(block.get("fields") or {})
        size = _field_value(fields, "Size")
        if not size or "no module installed" in size.lower():
            continue
        slot = _field_value(fields, "Locator", "Bank Locator") or f"DIMM{index}"
        memory = _component_from_dmi("MEMORY", fields, slot=slot)
        memory.model = memory.model or _field_value(fields, "Type", "Form Factor")
        memory.health = "PASS" if memory.serial else "REVIEW"
        memory.metadata.update(
            {
                "size": size,
                "speed": _field_value(fields, "Configured Memory Speed", "Speed"),
                "memory_type": _field_value(fields, "Type"),
                "rank": _field_value(fields, "Rank"),
            }
        )
        components.append(memory)

    lsblk = _json(_stdout(raw, "lsblk"), {})
    devices = lsblk.get("blockdevices") if isinstance(lsblk, Mapping) else []
    for row in _flatten_block_devices(devices if isinstance(devices, list) else []):
        if clean_value(row.get("type")).lower() not in {"disk", "mpath", "raid"}:
            continue
        path = clean_value(row.get("path")) or (f"/dev/{clean_value(row.get('name'))}" if clean_value(row.get("name")) else "")
        serial = clean_value(row.get("serial"))
        storage = ComponentRecord(
            category="STORAGE",
            component_id=safe_component_id("STORAGE", path, serial, row.get("wwn")),
            slot=clean_value(row.get("hctl") or row.get("name")),
            location=path,
            manufacturer=clean_value(row.get("vendor")),
            model=clean_value(row.get("model")),
            serial=serial,
            firmware=clean_value(row.get("rev")),
            health="UNKNOWN",
            interface=clean_value(row.get("tran")),
            capacity_bytes=int(row.get("size")) if str(row.get("size") or "").isdigit() else None,
            identifiers={"WWN": row.get("wwn"), "PATH": path},
            metadata={"removable": bool(row.get("rm")), "rotational": row.get("rota")},
        )
        for name, value in {
            "model": storage.model,
            "serial": storage.serial,
            "firmware": storage.firmware,
            "capacity_bytes": storage.capacity_bytes,
            "WWN": storage.identifiers.get("WWN", ""),
        }.items():
            if value not in {None, ""}:
                storage.add_evidence(
                    name,
                    value,
                    source="Linux lsblk/udev",
                    freshness="CURRENT_BOOT",
                    confidence="HIGH",
                    raw_reference="lsblk.txt",
                )
        components.append(storage)

    nvme_payload = _json(_stdout(raw, "nvme"), {})
    nvme_devices = nvme_payload.get("Devices") if isinstance(nvme_payload, Mapping) else []
    for row in nvme_devices if isinstance(nvme_devices, list) else []:
        if not isinstance(row, Mapping):
            continue
        path = clean_value(row.get("DevicePath") or row.get("NameSpace"))
        matching = next((item for item in components if item.category == "STORAGE" and item.location == path), None)
        if matching is None:
            matching = ComponentRecord(
                category="STORAGE",
                component_id=safe_component_id("STORAGE", path, row.get("SerialNumber")),
                slot=clean_value(row.get("NameSpace")) or path.rsplit("/", 1)[-1],
                location=path,
                model=clean_value(row.get("ModelNumber")),
                serial=clean_value(row.get("SerialNumber")),
                firmware=clean_value(row.get("Firmware")),
                interface="NVMe",
                capacity_bytes=int(row.get("PhysicalSize")) if str(row.get("PhysicalSize") or "").isdigit() else None,
            )
            components.append(matching)
        for key in ("WWN", "NGUID", "EUI64"):
            value = clean_value(row.get(key) or row.get(key.lower()))
            if value:
                matching.identifiers[key] = value
                matching.add_evidence(
                    key,
                    value,
                    source="NVMe Identify",
                    freshness="CURRENT_BOOT",
                    confidence="HIGH",
                    raw_reference="nvme-list.txt",
                )

    pci_rows = parse_lspci(_stdout(raw, "lspci"))
    for row in pci_rows:
        description = row["description"]
        if re.search(r"RAID|SAS|SCSI|Serial Attached", description, re.IGNORECASE):
            category = "RAID/HBA"
        elif re.search(r"VGA compatible|3D controller|Display controller", description, re.IGNORECASE):
            category = "GPU/ACCELERATOR"
        else:
            continue
        component = ComponentRecord(
            category=category,
            component_id=safe_component_id(category, row["pci_address"], description),
            slot=row["pci_address"],
            location=row["pci_address"],
            model=description,
            pci_address=row["pci_address"],
            health="UNKNOWN",
        )
        component.add_evidence(
            "model",
            description,
            source="Linux PCI enumeration",
            freshness="CURRENT_BOOT",
            confidence="HIGH",
            raw_reference="lspci.txt",
        )
        components.append(component)

    ip_links = _json(_stdout(raw, "ip_link"), [])
    ethtool = raw.get("ethtool") if isinstance(raw.get("ethtool"), Mapping) else {}
    physical_nics: list[ComponentRecord] = []
    for row in ip_links if isinstance(ip_links, list) else []:
        if not isinstance(row, Mapping):
            continue
        is_physical, classification = _interface_is_physical(row, sysfs)
        if not is_physical:
            continue
        name = clean_value(row.get("ifname"))
        mac = normalize_mac(row.get("address"))
        if not mac:
            continue
        details = dict(sysfs.get(name) or {}) if isinstance(sysfs.get(name), Mapping) else {}
        tool_text = _stdout(ethtool, name) if isinstance(ethtool, Mapping) else ""
        tool_values = parse_key_value(tool_text)
        pci_address = clean_value(details.get("pci_address") or tool_values.get("bus-info"))
        port = clean_value(details.get("phys_port_name") or row.get("phys_port_name"))
        pci_description = next(
            (
                item["description"]
                for item in pci_rows
                if pci_address and pci_address.lower().endswith(item["pci_address"])
            ),
            "",
        )
        vpd_fields = parse_pci_vpd(details.get("vpd_hex"))
        adapter_serial = clean_value(vpd_fields.get("SN")) or "NOT_EXPOSED"
        part_number = clean_value(vpd_fields.get("PN"))
        manufacturer = _pci_manufacturer(pci_description)
        adapter_model = pci_description or clean_value(vpd_fields.get("V1"))
        nic = ComponentRecord(
            category="NIC/OCP",
            component_id=safe_component_id("NIC/OCP", pci_address, port, name, mac),
            slot=port or pci_address or name,
            location=clean_value(details.get("device_path")) or pci_address,
            manufacturer=manufacturer,
            model=adapter_model,
            part_number=part_number,
            serial=adapter_serial,
            firmware=clean_value(tool_values.get("firmware-version")),
            health="PASS" if str(row.get("operstate") or "").upper() == "UP" else "INFO",
            interface=name,
            pci_address=pci_address,
            physical_port=port,
            mac_addresses=[mac],
            identifiers={"DRIVER": tool_values.get("driver"), "BUS_INFO": pci_address, "VPD_SN": vpd_fields.get("SN", "")},
            metadata={
                "link_state": clean_value(row.get("operstate")) or "UNKNOWN",
                "physical_classification": classification,
                "serial_discovery": "PCIe VPD (sysfs)" if vpd_fields.get("SN") else "NOT_EXPOSED",
                "vpd_present": bool(vpd_fields),
            },
        )
        nic.add_evidence(
            "mac",
            mac,
            source="Linux sysfs/ip link",
            freshness="CURRENT_BOOT",
            confidence="HIGH" if details else "MEDIUM",
            raw_reference="ip-link.txt",
        )
        nic.add_evidence(
            "serial",
            adapter_serial,
            source="PCIe VPD (Linux sysfs)" if vpd_fields.get("SN") else "PCIe VPD/sysfs",
            freshness="CURRENT_BOOT",
            confidence="HIGH" if vpd_fields.get("SN") else "NOT_EXPOSED",
            raw_reference=f"network-sysfs-{name}.json",
        )
        if manufacturer:
            nic.add_evidence(
                "manufacturer",
                manufacturer,
                source="Linux PCI enumeration",
                freshness="CURRENT_BOOT",
                confidence="HIGH",
                raw_reference="lspci.txt",
            )
        if adapter_model:
            nic.add_evidence(
                "model",
                adapter_model,
                source="Linux PCI enumeration",
                freshness="CURRENT_BOOT",
                confidence="HIGH",
                raw_reference="lspci.txt",
            )
        if part_number:
            nic.add_evidence(
                "part_number",
                part_number,
                source="PCIe VPD (Linux sysfs)",
                freshness="STATIC_FRU",
                confidence="HIGH",
                raw_reference=f"network-sysfs-{name}.json",
            )
        if nic.firmware:
            nic.add_evidence(
                "firmware",
                nic.firmware,
                source="ethtool",
                freshness="CURRENT_BOOT",
                confidence="HIGH",
                raw_reference=f"ethtool-{name}.txt",
            )
        physical_nics.append(nic)
        components.append(nic)

    default_routes = _json(_stdout(raw, "ip_route"), [])
    default_interface = ""
    for route in default_routes if isinstance(default_routes, list) else []:
        if isinstance(route, Mapping) and clean_value(route.get("dst")) in {"default", "0.0.0.0/0", "::/0"}:
            default_interface = clean_value(route.get("dev"))
            if default_interface:
                break
    primary_mac = ""
    if default_interface:
        primary_mac = next(
            (item.mac_addresses[0] for item in physical_nics if item.interface == default_interface and item.mac_addresses),
            "",
        )
    if not primary_mac:
        preferred = sorted(
            physical_nics,
            key=lambda item: (
                item.metadata.get("link_state") != "UP",
                bool(re.search(r"usb", item.location, re.IGNORECASE)),
                item.pci_address,
                item.interface,
            ),
        )
        primary_mac = preferred[0].mac_addresses[0] if preferred and preferred[0].mac_addresses else ""

    ipmi_mc = parse_key_value(_stdout(raw, "ipmi_mc"))
    lan_rows = raw.get("ipmi_lan") if isinstance(raw.get("ipmi_lan"), Mapping) else {}
    bmc_ip = bmc_mac = bmc_channel = ""
    for channel, value in sorted(lan_rows.items(), key=lambda item: str(item[0])):
        lan = parse_key_value(_stdout(lan_rows, str(channel)))
        candidate_mac = normalize_mac(lan.get("MAC Address"))
        candidate_ip = clean_value(lan.get("IP Address"))
        if candidate_mac or candidate_ip:
            bmc_ip, bmc_mac, bmc_channel = candidate_ip, candidate_mac, str(channel)
            break
    bmc_firmware = clean_value(parse_ipmi_mc_firmware_version(_stdout(raw, "ipmi_mc")))
    bmc = ComponentRecord(
        category="BMC",
        component_id=safe_component_id("BMC", bmc_mac, ipmi_mc.get("Device ID")),
        slot="BMC",
        location=f"IPMI channel {bmc_channel}" if bmc_channel else "BMC",
        manufacturer=clean_value(ipmi_mc.get("Manufacturer Name")),
        model=clean_value(ipmi_mc.get("Product Name")),
        firmware=bmc_firmware,
        health="PASS" if _stdout(raw, "ipmi_mc") else "REVIEW",
        interface="LOCAL_KCS/IPMI",
        mac_addresses=[bmc_mac] if bmc_mac else [],
        identifiers={"MANAGEMENT_IP": bmc_ip, "IPMI_CHANNEL": bmc_channel},
    )
    if bmc_firmware:
        bmc.add_evidence(
            "firmware",
            bmc_firmware,
            source="IPMI MC local KCS",
            freshness="LIVE_SENSOR",
            confidence="HIGH",
            raw_reference="ipmi-mc-info.txt",
        )
    components.append(bmc)

    for index, section in enumerate(parse_ipmi_fru_sections(_stdout(raw, "ipmi_fru")), start=1):
        description = clean_value(section.get("FRU Device Description"))
        if not re.search(r"PSU|Power Supply", description, re.IGNORECASE):
            continue
        serial = clean_value(section.get("Product Serial") or section.get("Board Serial"))
        psu = ComponentRecord(
            category="PSU",
            component_id=safe_component_id("PSU", description, serial),
            slot=description or f"PSU{index}",
            location=description,
            manufacturer=clean_value(section.get("Product Manufacturer") or section.get("Board Mfg")),
            model=clean_value(section.get("Product Name") or section.get("Board Product")),
            part_number=clean_value(section.get("Product Part Number") or section.get("Board Part Number")),
            serial=serial,
            health="UNKNOWN",
        )
        for name, value in {"serial": serial, "part_number": psu.part_number}.items():
            if value:
                psu.add_evidence(
                    name,
                    value,
                    source="IPMI FRU local KCS",
                    freshness="STATIC_FRU",
                    confidence="HIGH",
                    raw_reference="ipmi-fru.txt",
                )
        components.append(psu)

    bios = clean_value(probe.get("bios_version"))
    for slot, value, source, freshness in (
        ("BIOS", bios, "DMI/SMBIOS", "CURRENT_BOOT"),
        ("BMC", bmc_firmware, "IPMI MC local KCS", "LIVE_SENSOR"),
    ):
        firmware = ComponentRecord(
            category="FIRMWARE",
            component_id=safe_component_id("FIRMWARE", slot),
            slot=slot,
            location=slot,
            model=slot,
            firmware=value,
            health="INFO" if value else "REVIEW",
        )
        firmware.add_evidence(
            "firmware",
            value or "NOT_EXPOSED",
            source=source,
            freshness=freshness,
            confidence="HIGH" if value else "UNKNOWN",
            raw_reference="DMI sysfs" if slot == "BIOS" else "ipmi-mc-info.txt",
        )
        components.append(firmware)

    conflicts = [
        {"type": "IDENTITY_CONFLICT", "detail": clean_value(value)}
        for value in identity.get("conflicts", [])
        if clean_value(value)
    ]
    for item in identity.get("bmc_conflicts", []):
        conflicts.append({"type": "BMC_INVENTORY_CONFLICT", "detail": clean_value(item), "freshness": "STALE_SUSPECTED"})

    provisional = {"components": [component.to_dict() for component in components]}
    nic_anchors = nic_identity_anchors(provisional)
    if system_serial:
        identity_fallback = {
            "state": "NOT_USED_PRIMARY_SYSTEM_SERIAL_TRUSTED",
            "value": "",
            "source": "DMI_SMBIOS/IPMI_FRU_LOCAL_KCS",
            "freshness": "CURRENT_BOOT",
            "confidence": "HIGH" if identity.get("confidence") == "high" else "MEDIUM",
            "reason": "Trusted current/local system serial remains authoritative.",
        }
    elif len(nic_anchors) == 1:
        identity_fallback = {
            "state": "FALLBACK_CANDIDATE_ONLY",
            "value": nic_anchors[0]["adapter_serial"],
            "source": nic_anchors[0]["source"],
            "freshness": nic_anchors[0]["freshness"],
            "confidence": nic_anchors[0]["confidence"],
            "reason": "One distinct exposed physical NIC/card serial is available, but it does not replace SERVER_ID without an explicit identity re-enrollment decision.",
        }
    elif len(nic_anchors) > 1:
        identity_fallback = {
            "state": "AMBIGUOUS_MULTIPLE_NIC_SERIALS",
            "value": "",
            "source": "PCIe VPD (Linux sysfs)",
            "freshness": "CURRENT_BOOT",
            "confidence": "LOW",
            "reason": "Multiple distinct physical NIC/card serials were found; no arbitrary server identity was selected.",
        }
    else:
        identity_fallback = {
            "state": "NOT_EXPOSED",
            "value": "",
            "source": "PCIe VPD/sysfs",
            "freshness": "CURRENT_BOOT",
            "confidence": "NOT_EXPOSED",
            "reason": "No exposed physical NIC/card serial is available.",
        }

    result = NormalizedInventory(
        server_id=clean_value(identity.get("server_id")),
        run_id=clean_value(run_id),
        runner_id=clean_value(runner_id),
        boot_id=clean_value(boot_id),
        vendor=vendor,
        model=model,
        system_serial=system_serial,
        components=components,
        primary_host_mac=primary_mac,
        bmc_auth_state=clean_value(bmc_auth_state) or "BMC_AUTH_UNAVAILABLE",
        bmc_ip=bmc_ip,
        bmc_mac=bmc_mac,
        bmc_channel=bmc_channel,
        nic_identity_anchors=nic_anchors,
        identity_fallback=identity_fallback,
        conflicts=conflicts,
        warnings=[] if physical_nics else ["NO_PHYSICAL_NIC_MAC_DISCOVERED"],
    )
    result.to_dict()  # validates that no credential-like fields crossed the boundary
    return result


def serial_rows(inventory: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return one Operations row per normalized component."""
    rows: list[dict[str, Any]] = []
    for component in inventory.get("components", []):
        if not isinstance(component, Mapping):
            continue
        identifiers = dict(component.get("identifiers") or {})
        field_evidence = component.get("field_evidence") or {}
        serial_evidence = field_evidence.get("serial") if isinstance(field_evidence, Mapping) else None
        preferred_evidence = serial_evidence if isinstance(serial_evidence, Mapping) else next(
            (
                item
                for item in field_evidence.values()
                if isinstance(item, Mapping) and item.get("source")
            ),
            {},
        )
        rows.append(
            {
                "category": clean_value(component.get("category")),
                "slot_location": clean_value(component.get("slot") or component.get("location")),
                "manufacturer": clean_value(component.get("manufacturer")),
                "model": clean_value(component.get("model")),
                "part_number": clean_value(component.get("part_number")),
                "serial": clean_value(component.get("serial")),
                "firmware": clean_value(component.get("firmware")),
                "health_status": clean_value(component.get("health") or component.get("status")) or "UNKNOWN",
                "interface_identifier": clean_value(
                    component.get("interface")
                    or identifiers.get("WWN")
                    or identifiers.get("NGUID")
                    or identifiers.get("EUI64")
                    or component.get("pci_address")
                ),
                # A NIC's Operations row must describe the physical card
                # serial provenance, not whichever evidence field happened to
                # be inserted first (usually its MAC address).
                "source": clean_value(preferred_evidence.get("source")),
                "confidence": clean_value(preferred_evidence.get("confidence")) or "UNKNOWN",
                "conflict": "; ".join(
                    clean_value(item.get("detail") if isinstance(item, Mapping) else item)
                    for item in component.get("conflicts", [])
                    if clean_value(item.get("detail") if isinstance(item, Mapping) else item)
                ),
            }
        )
    return rows


def physical_nic_rows(inventory: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for component in inventory.get("components", []):
        if not isinstance(component, Mapping) or component.get("category") != "NIC/OCP":
            continue
        field_evidence = component.get("field_evidence") or {}
        serial_evidence = field_evidence.get("serial") or {}
        # The row's Source column describes the adapter serial, not the MAC.
        # MAC provenance is useful corroboration but must never be promoted to
        # the card serial source.  This preserves PCIe VPD precedence when a
        # Redfish adapter object has a blank SerialNumber.
        serial_source = clean_value(serial_evidence.get("source"))
        serial_freshness = clean_value(serial_evidence.get("freshness"))
        serial_confidence = clean_value(serial_evidence.get("confidence"))
        macs = [item for item in (normalize_mac(value) for value in component.get("mac_addresses", [])) if item]
        for mac in macs:
            rows.append(
                {
                    "port_label": clean_value(component.get("physical_port") or component.get("slot")),
                    "interface": clean_value(component.get("interface")),
                    "mac": mac,
                    "pci_address": clean_value(component.get("pci_address")),
                    "adapter_serial": clean_value(component.get("serial")) or "NOT_EXPOSED",
                    "manufacturer": clean_value(component.get("manufacturer")),
                    "adapter": clean_value(component.get("model")),
                    "part_number": clean_value(component.get("part_number")),
                    "link_state": clean_value((component.get("metadata") or {}).get("link_state")),
                    "firmware": clean_value(component.get("firmware")),
                    "source": serial_source or clean_value(((field_evidence.get("mac") or {}).get("source"))),
                    "serial_source": serial_source,
                    "serial_freshness": serial_freshness,
                    "serial_confidence": serial_confidence,
                }
            )
    return sorted(rows, key=lambda row: (row["pci_address"], row["port_label"], row["interface"], row["mac"]))


def nic_identity_anchors(inventory: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Group ports by exposed adapter/card serial for identity corroboration.

    A dual-port card intentionally produces one anchor for both ports.  MAC
    addresses are retained as supporting identifiers only and are never
    promoted to a hardware serial.  ``NOT_EXPOSED`` components are omitted.
    """
    grouped: dict[str, dict[str, Any]] = {}
    for row in physical_nic_rows(inventory):
        serial = clean_value(row.get("adapter_serial"))
        if not serial or serial.upper() == "NOT_EXPOSED":
            continue
        key = serial.upper()
        item = grouped.setdefault(
            key,
            {
                "adapter_serial": serial,
                "ports": [],
                "mac_addresses": [],
                "pci_addresses": [],
                "source": clean_value(row.get("serial_source") or row.get("source")) or "UNKNOWN",
                "freshness": clean_value(row.get("serial_freshness")) or "UNKNOWN",
                "confidence": clean_value(row.get("serial_confidence")) or "UNKNOWN",
                "role": "SECONDARY_IDENTITY_ANCHOR",
            },
        )
        for field, value in (
            ("ports", row.get("interface")),
            ("mac_addresses", row.get("mac")),
            ("pci_addresses", row.get("pci_address")),
        ):
            text = clean_value(value)
            if text and text not in item[field]:
                item[field].append(text)
    return [
        {**item, "ports": sorted(item["ports"]), "mac_addresses": sorted(item["mac_addresses"]), "pci_addresses": sorted(item["pci_addresses"])}
        for _, item in sorted(grouped.items())
    ]
