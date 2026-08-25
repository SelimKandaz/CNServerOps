"""Capability-gated local ASUS BMC recovery for an unknown used-server account.

ASUS documents the bounded ``ipmitool raw 0x32 0x66`` factory/default action
for ASMB server-management controllers.  The runtime still requires exact
generation evidence from the current platform/catalog before allowing it and
records pre-reset LAN, account-list and SEL evidence.  It never accepts
credentials and never emits secrets.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from ipaddress import ip_address
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol

from .safety import MutationGate
from .asus.profiles import infer_inventory_platform_bmc_generation
from .bmc_version import parse_ipmi_mc_firmware_version, versions_equivalent


class BmcRecoveryError(RuntimeError):
    """Sanitized recovery error."""


class RecoveryCommandExecutor(Protocol):
    def run(self, tool: str, arguments: tuple[str, ...], *, timeout_seconds: int) -> dict[str, Any]: ...


def restore_local_ipmi_kcs(
    executor: RecoveryCommandExecutor,
    *,
    timeout_seconds: int = 30,
    wait_seconds: int = 30,
    poll_seconds: float = 2.0,
    force_reprobe: bool = False,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Restore the standard Linux IPMI device after a vendor KCS updater.

    ASUS' package-owned Yafuflash KCS path can leave ``ipmi_si`` unloaded even
    though the firmware update succeeded.  The operation below is bounded to
    the three standard kernel modules and then performs a read-only MC probe.
    It never resets the BMC and never uses a credential.
    """

    initial = _mc_info(executor, timeout_seconds)
    if not force_reprobe and _command_passed(initial) and _firmware_revision(initial):
        return {
            "schema_version": 1,
            "status": "PASS",
            "action": "ALREADY_AVAILABLE",
            "firmware_version": _firmware_revision(initial),
            "sensitive_material_exposed": False,
        }

    module_status: list[dict[str, Any]] = []
    deadline = time.monotonic() + max(0, int(wait_seconds))
    attempts = 0
    verified: dict[str, Any] = {}
    while attempts == 0 or time.monotonic() < deadline:
        attempts += 1
        # The package-owned ASMB11 updater explicitly unloads ``ipmi_si`` and
        # can try to restore it before the restarting controller is ready.  A
        # plain second ``modprobe`` cannot re-probe a driver which remained
        # loaded without binding, so the post-updater path performs a bounded
        # unload/reload.  Inventory/recovery callers use the non-forced path
        # and only load missing standard modules.
        if force_reprobe:
            for module in ("ipmi_devintf", "ipmi_si"):
                result = executor.run("modprobe", ("-r", module), timeout_seconds=timeout_seconds)
                module_status.append(
                    {
                        "attempt": attempts,
                        "action": "UNLOAD",
                        "module": module,
                        "status": str(result.get("status") or "UNKNOWN"),
                        "exit_code": result.get("exit_code"),
                    }
                )
        for module in ("ipmi_msghandler", "ipmi_si", "ipmi_devintf"):
            result = executor.run("modprobe", (module,), timeout_seconds=timeout_seconds)
            module_status.append(
                {
                    "attempt": attempts,
                    "action": "LOAD",
                    "module": module,
                    "status": str(result.get("status") or "UNKNOWN"),
                    "exit_code": result.get("exit_code"),
                }
            )
        verified = _mc_info(executor, timeout_seconds)
        if _command_passed(verified) and _firmware_revision(verified):
            break
        if time.monotonic() < deadline:
            sleep_fn(max(0.1, float(poll_seconds)))
    passed = _command_passed(verified) and bool(_firmware_revision(verified))
    return {
        "schema_version": 1,
        "status": "PASS" if passed else "UNAVAILABLE",
        "action": "STANDARD_IPMI_MODULE_RESTORE",
        "attempts": attempts,
        "forced_reprobe": bool(force_reprobe),
        "modules": module_status,
        "firmware_version": _firmware_revision(verified),
        "reason": "LOCAL_KCS_RESTORED" if passed else "LOCAL_KCS_NOT_AVAILABLE_AFTER_MODULE_RESTORE",
        "sensitive_material_exposed": False,
    }


@dataclass(frozen=True)
class LocalBmcEndpoint:
    """A current, locally-proven BMC endpoint.

    A BMC configuration reset can change a static address to DHCP.  The
    historic inventory address is therefore never an endpoint fallback: it is
    evidence about a previous state, not proof of the controller's current
    network identity.  An IPMI LAN response is local KCS evidence; when it
    omits an address, the only fallback allowed here is an exact BMC-MAC match
    in the host's local neighbour table.  This intentionally never scans a
    subnet or guesses an address.
    """

    status: str
    ip: str = ""
    mac: str = ""
    channel: str = ""
    source: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "bmc_ip": self.ip,
            "bmc_mac": self.mac,
            "ipmi_channel": self.channel,
            "source": self.source,
            "reason": self.reason,
            "sensitive_material_exposed": False,
        }


@dataclass(frozen=True)
class BmcRecoveryResult:
    status: str
    supported: bool
    method: str
    reset_requested: bool
    bmc_ip_before: str = ""
    bmc_ip_after: str = ""
    firmware_before: str = ""
    firmware_after: str = ""
    kcs_before: str = "NOT_TESTED"
    kcs_after: str = "NOT_TESTED"
    bmc_endpoint_status: str = "NOT_TESTED"
    bmc_endpoint_source: str = ""
    bmc_mac: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "status": self.status,
            "supported": self.supported,
            "method": self.method,
            "reset_requested": self.reset_requested,
            "bmc_ip_before": self.bmc_ip_before,
            "bmc_ip_after": self.bmc_ip_after,
            "firmware_before": self.firmware_before,
            "firmware_after": self.firmware_after,
            "kcs_before": self.kcs_before,
            "kcs_after": self.kcs_after,
            "bmc_endpoint_status": self.bmc_endpoint_status,
            "bmc_endpoint_source": self.bmc_endpoint_source,
            "bmc_mac": self.bmc_mac,
            "reason": self.reason,
            "sensitive_material_exposed": False,
        }


def asus_bmc_recovery_capability(
    *,
    normalized_inventory: Mapping[str, Any],
    firmware_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Return an exact platform-gated recovery capability record."""
    generic = firmware_plan.get("generic_asus_firmware_engine") if isinstance(firmware_plan, Mapping) else {}
    platform = generic.get("platform") if isinstance(generic, Mapping) else {}
    generation = str(platform.get("bmc_generation") or "").replace(" ", "").upper() if isinstance(platform, Mapping) else ""
    generation_source = "FIRMWARE_PLAN" if generation else ""
    if not generation:
        components = normalized_inventory.get("components") if isinstance(normalized_inventory, Mapping) else []
        for item in components if isinstance(components, list) else []:
            if not isinstance(item, Mapping):
                continue
            text = " ".join(str(item.get(key) or "") for key in ("category", "model", "slot", "location"))
            matched = re.search(r"\bASMB\s*(\d+)\b", text, re.IGNORECASE)
            if matched:
                generation = f"ASMB{matched.group(1)}"
                generation_source = "EXPLICIT_NORMALIZED_COMPONENT"
                break
    if not generation:
        generation, generation_source = infer_inventory_platform_bmc_generation(normalized_inventory)
    # An exact model/board profile is useful only when current local KCS has
    # also exposed a present ASUS BMC.  This prevents a stale model name from
    # authorizing the raw factory action on a non-ASUS/absent controller.
    if generation and generation_source.startswith("EXACT_ASUS_MODEL_BOARD"):
        local_bmc = any(
            isinstance(item, Mapping)
            and str(item.get("category") or "").upper() == "BMC"
            and str(item.get("status") or "").upper() == "PRESENT"
            and "KCS" in str(item.get("interface") or "").upper()
            and "ASUS" in str(item.get("manufacturer") or "").upper()
            for item in (normalized_inventory.get("components") or ())
        )
        if not local_bmc:
            generation = ""
            generation_source = "EXACT_PROFILE_LOCAL_KCS_BMC_EVIDENCE_REQUIRED"
    # This is a *local KCS* recovery capability.  A current BMC IP is useful
    # after reset for authenticated continuation, but must not be a precondition
    # for the only supported recovery mechanism itself.
    bmc_ip = str(normalized_inventory.get("bmc_ip") or "")
    supported = generation in {"ASMB11", "ASMB12"}
    method = f"ASUS_{generation}_KCS_FACTORY_DEFAULT_RAW_32_66" if supported else "NONE"
    return {
        "schema_version": 1,
        "capability": "ASUS_LOCAL_BMC_FACTORY_RECOVERY",
        "supported": supported,
        "bmc_generation": generation or "UNKNOWN",
        "bmc_ip_present": bool(bmc_ip),
        "method": method,
        "reason": "EXACT_ASUS_ASMB_LOCAL_KCS_CAPABILITY" if supported else "NO_VALIDATED_LOCAL_RECOVERY_FOR_THIS_BMC_GENERATION",
        "generation_evidence": generation_source,
        "sensitive_material_exposed": False,
    }


def recover_asus_bmc(
    *,
    executor: RecoveryCommandExecutor,
    identity: Mapping[str, Any],
    normalized_inventory: Mapping[str, Any],
    firmware_plan: Mapping[str, Any],
    mutation_gate: MutationGate,
    run_id: str,
    evidence_dir: Path,
    timeout_seconds: int = 30,
    wait_seconds: int = 180,
    poll_seconds: float = 2.0,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> BmcRecoveryResult:
    """Perform the bounded, evidence-preserving ASMB local recovery path."""
    capability = asus_bmc_recovery_capability(
        normalized_inventory=normalized_inventory,
        firmware_plan=firmware_plan,
    )
    method = str(capability["method"])
    if not bool(capability["supported"]):
        return BmcRecoveryResult(
            "UNSUPPORTED", False, method, False,
            reason=str(capability["reason"]),
        )
    mutation_gate.require(
        "BMC_FACTORY_RECOVERY",
        identity,
        context={"run_id": run_id, "component": "BMC"},
    )
    kcs_restore = restore_local_ipmi_kcs(executor, timeout_seconds=timeout_seconds)
    _atomic_json(evidence_dir / "linux-ipmi-kcs-restore.json", kcs_restore)
    evidence = preserve_bmc_recovery_evidence(executor, evidence_dir, timeout_seconds=timeout_seconds)
    before = evidence["mc"]
    before_endpoint = discover_local_bmc_endpoint(
        executor,
        normalized_inventory=normalized_inventory,
        timeout_seconds=timeout_seconds,
    )
    _atomic_json(evidence_dir / "bmc-recovery-before-endpoint.json", before_endpoint.to_dict())
    before_ip = before_endpoint.ip
    firmware_before = _firmware_revision(before)
    if not _command_passed(before):
        return BmcRecoveryResult(
            "FAIL", True, method, False, bmc_ip_before=before_ip,
            kcs_before="FAIL", bmc_endpoint_status=before_endpoint.status,
            bmc_endpoint_source=before_endpoint.source, bmc_mac=before_endpoint.mac,
            reason="BMC_KCS_UNAVAILABLE_BEFORE_RECOVERY",
        )
    reset = executor.run("ipmitool", ("raw", "0x32", "0x66"), timeout_seconds=timeout_seconds)
    if not _command_passed(reset):
        return BmcRecoveryResult(
            "FAIL", True, method, True, bmc_ip_before=before_ip,
            firmware_before=firmware_before, kcs_before="PASS",
            bmc_endpoint_status=before_endpoint.status,
            bmc_endpoint_source=before_endpoint.source, bmc_mac=before_endpoint.mac,
            reason="ASUS_FACTORY_RECOVERY_ACTION_FAILED",
        )
    deadline = time.monotonic() + max(1, int(wait_seconds))
    after: dict[str, Any] = {}
    after_endpoint = LocalBmcEndpoint("NOT_TESTED")

    # A reset can briefly return a successful KCS response before the BMC
    # enters its actual controller-reset/update phase.  Accepting that first
    # response made recovery report RECOVERED while the controller was still
    # unavailable (observed on ASMB11).  Give the controller a bounded grace
    # period, then require several identical, endpoint-backed samples before
    # declaring it ready.  Short waits remain fast for unit tests.
    grace_seconds = 15.0 if int(wait_seconds) >= 20 else 0.0
    if grace_seconds:
        sleep_fn(grace_seconds)
    stable_required = 3
    stable_count = 0
    stable_key: tuple[str, str, str] | None = None
    while time.monotonic() < deadline:
        candidate = _mc_info(executor, timeout_seconds)
        candidate_firmware = _firmware_revision(candidate)
        candidate_endpoint = LocalBmcEndpoint("NOT_TESTED")
        if _command_passed(candidate) and candidate_firmware:
            candidate_endpoint = discover_local_bmc_endpoint(
                executor,
                normalized_inventory=normalized_inventory,
                timeout_seconds=timeout_seconds,
            )
        after = candidate
        after_endpoint = candidate_endpoint
        if _command_passed(candidate) and candidate_firmware and candidate_endpoint.status == "DISCOVERED":
            candidate_key = (
                candidate_firmware,
                candidate_endpoint.ip,
                candidate_endpoint.mac,
            )
            if candidate_key == stable_key:
                stable_count += 1
            else:
                stable_key = candidate_key
                stable_count = 1
            if stable_count >= stable_required:
                break
        else:
            stable_key = None
            stable_count = 0
        sleep_fn(max(0.1, float(poll_seconds)))
    firmware_after = _firmware_revision(after)
    after_ip = after_endpoint.ip
    if not _command_passed(after) or not firmware_after or stable_count < stable_required:
        return BmcRecoveryResult(
            "FAIL", True, method, True, bmc_ip_before=before_ip, bmc_ip_after=after_ip,
            firmware_before=firmware_before, kcs_before="PASS", kcs_after="FAIL",
            bmc_endpoint_status=after_endpoint.status, bmc_endpoint_source=after_endpoint.source,
            bmc_mac=after_endpoint.mac,
            reason="BMC_DID_NOT_RETURN_STABLE_AFTER_FACTORY_RECOVERY",
        )
    if firmware_before and firmware_after and not _versions_equal(firmware_before, firmware_after):
        return BmcRecoveryResult(
            "FAIL", True, method, True, bmc_ip_before=before_ip, bmc_ip_after=after_ip,
            firmware_before=firmware_before, firmware_after=firmware_after,
            kcs_before="PASS", kcs_after="PASS", bmc_endpoint_status=after_endpoint.status,
            bmc_endpoint_source=after_endpoint.source, bmc_mac=after_endpoint.mac,
            reason="BMC_FIRMWARE_CHANGED_DURING_FACTORY_RECOVERY",
        )
    reason = f"{capability.get('bmc_generation')}_FACTORY_DEFAULT_RECOVERY_COMPLETE_STABLE_KCS_SAMPLES_{stable_count}"
    if after_endpoint.status != "DISCOVERED":
        # Local recovery is complete and the controller is alive, but callers
        # must treat authenticated continuation as blocked until a *current*
        # endpoint is proven.  Do not substitute normalized_inventory.bmc_ip.
        reason += "_BMC_ENDPOINT_REDISCOVERY_REQUIRED"
    result = BmcRecoveryResult(
        "RECOVERED", True, method, True, bmc_ip_before=before_ip, bmc_ip_after=after_ip,
        firmware_before=firmware_before, firmware_after=firmware_after,
        kcs_before="PASS", kcs_after="PASS", bmc_endpoint_status=after_endpoint.status,
        bmc_endpoint_source=after_endpoint.source, bmc_mac=after_endpoint.mac, reason=reason,
    )
    _atomic_json(
        evidence_dir / "bmc-recovery-result.json",
        result.to_dict(),
    )
    return result


def asmb12_recovery_capability(
    *,
    normalized_inventory: Mapping[str, Any],
    firmware_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Backward-compatible ASMB12 capability view for older callers."""
    result = asus_bmc_recovery_capability(
        normalized_inventory=normalized_inventory,
        firmware_plan=firmware_plan,
    )
    if str(result.get("bmc_generation") or "").upper() != "ASMB12":
        result["supported"] = False
        result["method"] = "NONE"
        result["reason"] = "NO_VALIDATED_ASMB12_LOCAL_RECOVERY_FOR_THIS_BMC_GENERATION"
    return result


def recover_asmb12_bmc(**kwargs: Any) -> BmcRecoveryResult:
    """Backward-compatible ASMB12 recovery wrapper for existing integrations."""
    return recover_asus_bmc(**kwargs)


def preserve_bmc_recovery_evidence(
    executor: RecoveryCommandExecutor,
    output: Path,
    *,
    timeout_seconds: int,
) -> dict[str, Mapping[str, Any]]:
    """Preserve credential-free BMC state before factory recovery."""
    output.mkdir(parents=True, exist_ok=True)
    commands = {
        "mc": ("mc", "info"),
        "lan": ("lan", "print", "1"),
        # ASUS platforms can expose the dedicated management interface on a
        # non-primary IPMI channel.  Preserve both bounded local candidates;
        # endpoint selection itself remains MAC-bound and never trusts a
        # previously recorded address.
        "lan_8": ("lan", "print", "8"),
        "users": ("user", "list", "1"),
        "sel": ("sel", "elist"),
    }
    result: dict[str, Mapping[str, Any]] = {}
    for name, arguments in commands.items():
        captured = executor.run("ipmitool", arguments, timeout_seconds=timeout_seconds if name != "sel" else 180)
        result[name] = captured
        _atomic_text(output / f"bmc-recovery-before-{name}.txt", str(captured.get("stdout") or "") or "<no stdout>\n")
        public = {key: value for key, value in captured.items() if key not in {"stdout", "stderr"}}
        public["stderr_present"] = bool(str(captured.get("stderr") or ""))
        _atomic_json(output / f"bmc-recovery-before-{name}.json", public)
    return result


def discover_local_bmc_endpoint(
    executor: RecoveryCommandExecutor,
    *,
    normalized_inventory: Mapping[str, Any],
    timeout_seconds: int = 30,
    lan_channels: Iterable[int | str] = (1, 8),
) -> LocalBmcEndpoint:
    """Find the BMC's current endpoint without trusting a cached IP address.

    The local KCS ``lan print`` reply is preferred.  If a controller returns
    only its MAC address after a reset, this function may use the *local host*
    neighbour table, but only for an exact MAC match.  It performs no subnet
    scan, never probes credentials, and deliberately ignores the historical
    ``normalized_inventory.bmc_ip`` value as a fallback.
    """
    preferred_channel = str(normalized_inventory.get("bmc_channel") or "").strip()
    channels: list[str] = []
    for channel in (preferred_channel, *(str(item) for item in lan_channels)):
        if channel and channel not in channels and re.fullmatch(r"\d{1,3}", channel):
            channels.append(channel)
    if not channels:
        channels = ["1", "8"]

    inventory_mac = _normalize_mac(normalized_inventory.get("bmc_mac"))
    observed_macs: list[tuple[str, str]] = []
    lan_attempted = False
    mac_mismatch_seen = False
    for channel in channels:
        try:
            lan = executor.run("ipmitool", ("lan", "print", channel), timeout_seconds=timeout_seconds)
        except Exception:
            continue
        if not _command_passed(lan):
            continue
        lan_attempted = True
        lan_mac = _lan_mac(lan)
        lan_ip = _lan_ip(lan)
        if lan_mac:
            observed_macs.append((channel, lan_mac))
        if not _valid_endpoint_ip(lan_ip):
            continue
        if inventory_mac and lan_mac and lan_mac != inventory_mac:
            # A different local IPMI LAN channel can be exposed alongside the
            # management controller.  Never join its current IP with the
            # inventory BMC identity.
            mac_mismatch_seen = True
            continue
        return LocalBmcEndpoint(
            "DISCOVERED",
            ip=lan_ip,
            mac=lan_mac or inventory_mac,
            channel=channel,
            source="LOCAL_KCS_IPMI_LAN",
            reason="CURRENT_LOCAL_LAN_CONFIGURATION",
        )

    # Prefer the pre-reset/current-inventory BMC MAC when it is available;
    # otherwise a live local KCS LAN MAC is enough to bind the host's ARP/NDP
    # entry.  If several LAN MACs are exposed and none is known to be the BMC,
    # do not guess which one owns an address.
    candidate_macs: list[str] = [inventory_mac] if inventory_mac else []
    if not candidate_macs and len({mac for _channel, mac in observed_macs}) == 1:
        candidate_macs = [observed_macs[0][1]]
    if not candidate_macs:
        return LocalBmcEndpoint(
            "UNAVAILABLE",
            source="LOCAL_KCS_IPMI_LAN",
            reason=(
                "BMC_LAN_MAC_MISMATCH" if mac_mismatch_seen else
                ("BMC_LAN_MAC_UNAVAILABLE" if lan_attempted else "BMC_LAN_KCS_UNAVAILABLE")
            ),
        )

    try:
        neighbours = executor.run("ip", ("-json", "neighbour", "show"), timeout_seconds=timeout_seconds)
    except Exception:
        neighbours = {"status": "ERROR", "stdout": ""}
    if not _command_passed(neighbours):
        return LocalBmcEndpoint(
            "UNAVAILABLE",
            mac=candidate_macs[0],
            source="LOCAL_MAC_BOUND_NEIGHBOUR",
            reason="LOCAL_NEIGHBOUR_TABLE_UNAVAILABLE",
        )
    matched = _mac_bound_neighbour_ips(str(neighbours.get("stdout") or ""), set(candidate_macs))
    if len(matched) == 1:
        ip, mac = matched[0]
        return LocalBmcEndpoint(
            "DISCOVERED",
            ip=ip,
            mac=mac,
            source="LOCAL_MAC_BOUND_NEIGHBOUR",
            reason="CURRENT_HOST_NEIGHBOUR_MATCHED_BMC_MAC",
        )
    if len(matched) > 1:
        return LocalBmcEndpoint(
            "AMBIGUOUS",
            mac=candidate_macs[0],
            source="LOCAL_MAC_BOUND_NEIGHBOUR",
            reason="MULTIPLE_CURRENT_NEIGHBOURS_MATCH_BMC_MAC",
        )
    return LocalBmcEndpoint(
        "UNAVAILABLE",
        mac=candidate_macs[0],
        source="LOCAL_MAC_BOUND_NEIGHBOUR",
        reason="NO_CURRENT_NEIGHBOUR_MATCHED_BMC_MAC",
    )


def _mc_info(executor: RecoveryCommandExecutor, timeout_seconds: int) -> dict[str, Any]:
    return executor.run("ipmitool", ("mc", "info"), timeout_seconds=timeout_seconds)


def _command_passed(result: Mapping[str, Any]) -> bool:
    return str(result.get("status") or "").upper() in {"PASS", "OK", "COMPLETED"} or result.get("exit_code") == 0


def _firmware_revision(result: Mapping[str, Any]) -> str:
    return parse_ipmi_mc_firmware_version(str(result.get("stdout") or ""))


def _lan_ip(result: Mapping[str, Any]) -> str:
    match = re.search(r"(?im)^IP Address\s*:\s*([0-9a-f:.]+)", str(result.get("stdout") or ""))
    return match.group(1).strip() if match else ""


def _lan_mac(result: Mapping[str, Any]) -> str:
    match = re.search(r"(?im)^MAC Address\s*:\s*([^\r\n]+)", str(result.get("stdout") or ""))
    return _normalize_mac(match.group(1) if match else "")


def _normalize_mac(value: Any) -> str:
    compact = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if len(compact) != 12 or not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        return ""
    return ":".join(compact[index:index + 2].lower() for index in range(0, 12, 2))


def _valid_endpoint_ip(value: str) -> bool:
    try:
        parsed = ip_address(str(value or "").split("%", 1)[0])
    except ValueError:
        return False
    return not (parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast)


def _mac_bound_neighbour_ips(text: str, candidate_macs: set[str]) -> list[tuple[str, str]]:
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    rows = payload if isinstance(payload, list) else []
    found: set[tuple[str, str]] = set()
    rejected_states = {"FAILED", "INCOMPLETE", "NONE", "NOARP"}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        mac = _normalize_mac(row.get("lladdr"))
        address = str(row.get("dst") or "").strip()
        state_value = row.get("state")
        if isinstance(state_value, list):
            states = {str(item).upper() for item in state_value}
        else:
            states = {str(state_value or "").upper()}
        if mac not in candidate_macs or not _valid_endpoint_ip(address) or states & rejected_states:
            continue
        found.add((address, mac))
    return sorted(found)


def _versions_equal(left: str, right: str) -> bool:
    return versions_equivalent(left, right)


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    _atomic_text(path, json.dumps(dict(payload), indent=2, sort_keys=True) + "\n")


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
