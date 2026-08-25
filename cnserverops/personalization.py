"""One-time, marker-gated personalization for cloned CNServerOps boot SSDs."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Mapping

from .models import utc_now
from .runner import bootstrap_runner, load_runner


class ClonePersonalizationError(RuntimeError):
    pass


_MARKER_RELATIVE = Path("etc/cnserverops/clone-template.json")
_CONSUMED_RELATIVE = Path("etc/cnserverops/clone-template.consumed.json")
_RUNNER_RELATIVE = Path("etc/cnserverops/runner.json")
_CURRENT_POINTER_RELATIVE = Path("opt/cnserverops/current.json")
_TRANSACTION_RELATIVE = Path("var/lib/cnserverops/personalization-transaction.json")
_RECEIPT_RELATIVE = Path("var/lib/cnserverops/personalization-receipt.json")
_LOCK_RELATIVE = Path("var/lib/cnserverops/personalization.lock")
_SAFE_TEMPLATE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
_CN_STATIC_NETWORK_PATHS = (
    "etc/netplan/99-cnserverops-static.yaml",
    "etc/netplan/99-cnstress-static.yaml",
    "etc/netplan/99-cnstress-dhcp.yaml.disabled",
    # A previous runtime may have already generated the native networkd
    # profile.  It is CNServerOps-owned state and must not be copied into the
    # clone source with an interface-specific address or match rule.
    "etc/systemd/network/10-cnserverops-dhcp.network",
)
_CN_DHCP_NETWORK_PATH = Path("etc/netplan/99-cnserverops-dhcp.yaml")
_CN_NETWORKD_DHCP_PATH = Path("etc/systemd/network/10-cnserverops-dhcp.network")
_DEFAULT_STALE_STATE_PATHS = (
    # Authoritative run and firmware continuation state must never jump from
    # the source SSD to a different physical server after cloning.
    "CN_STRESS_RESULTS/runs",
    "CN_STRESS_RESULTS/firmware-runs",
    "CN_STRESS_RESULTS/firmware-pending.json",
    "CN_STRESS_RESULTS/firmware-inflight.json",
    "var/lib/cnserverops/production",
    "var/lib/cnserverops/firmware-pending.json",
    "var/lib/cnserverops/firmware-inflight.json",
    "var/lib/cnserverops/bmc-auth-change-state.json",
    "var/lib/cnserverops/upload-queue.sqlite3",
    "var/lib/cnserverops/upload-queue.sqlite3-wal",
    "var/lib/cnserverops/upload-queue.sqlite3-shm",
    "var/lib/cnserverops/artifact-queue.sqlite3",
    "var/lib/cnserverops/artifact-queue.sqlite3-wal",
    "var/lib/cnserverops/artifact-queue.sqlite3-shm",
    "etc/cnserverops/firmware-current-proof.json",
    "etc/cnserverops/secrets/asus-bmc-password",
    "etc/cnserverops/secrets/asus-bmc-password.binding.json",
    # These are current-server selectors/metadata, not portable historical
    # evidence.  A cloned SSD must never carry them into first boot.
    "CN_STRESS_RESULTS/enrollment/latest.json",
    "CN_STRESS_RESULTS/firmware-diagnostics/update-service-action-info.json",
    "CN_STRESS_RESULTS/central-sync.sqlite3",
    "opt/cnserverops/current.json",
)


def prepare_clone_template(
    root: Path,
    *,
    template_id: str,
    authorized: bool,
    stale_state_paths: tuple[str, ...] = _DEFAULT_STALE_STATE_PATHS,
) -> dict[str, Any]:
    """Prepare a reviewed golden image without deleting its previous identity/state."""
    if not authorized:
        raise ClonePersonalizationError("GOLDEN_IMAGE_PREPARATION_NOT_AUTHORIZED")
    if not _SAFE_TEMPLATE_ID.fullmatch(template_id):
        raise ClonePersonalizationError("CLONE_TEMPLATE_ID_INVALID")
    root = root.resolve(strict=True)
    marker = root / _MARKER_RELATIVE
    if marker.exists():
        existing = _read_marker(marker)
        if existing["template_id"] != template_id:
            raise ClonePersonalizationError("DIFFERENT_CLONE_TEMPLATE_ALREADY_EXISTS")
        # Preparation is idempotent but must also finish scrubbing a template
        # that was marked by an older runtime before stale-state quarantine was
        # moved into the preparation phase.  Keeping this here prevents an
        # interrupted/older preparation from leaving queues, run evidence or
        # a pending firmware instruction in a clone source.
        quarantine = root / "var/lib/cnserverops/template-quarantine" / template_id
        identity_quarantined = _quarantine_identity_paths(root, quarantine)
        effective_stale_paths = _merge_stale_state_paths(
            existing.get("stale_state_paths") or (), stale_state_paths
        )
        stale_quarantined = _quarantine_stale_state(
            root,
            quarantine,
            effective_stale_paths,
        )
        network_quarantined = _quarantine_specific_paths(
            root,
            quarantine,
            _CN_STATIC_NETWORK_PATHS + (str(_CN_DHCP_NETWORK_PATH),),
        )
        existing_policy = dict(existing.get("network_policy") or {})
        desired_policy = dict(existing_policy)
        if str(existing_policy.get("mode") or "") == "DHCP_GENERIC":
            desired_policy.update(
                {
                    "path": str(_CN_DHCP_NETWORK_PATH).replace("\\", "/"),
                    "networkd_path": str(_CN_NETWORKD_DHCP_PATH).replace("\\", "/"),
                    "match": "en* eth* eno*",
                    "static_development_address_removed": True,
                }
            )
        network_policy_changed = desired_policy != existing_policy
        if identity_quarantined or stale_quarantined or network_quarantined:
            existing = dict(existing)
            existing["displaced_identity_paths"] = sorted(
                set(existing.get("displaced_identity_paths") or ()) | set(identity_quarantined)
            )
            existing["quarantined_network_paths"] = sorted(
                set(existing.get("quarantined_network_paths") or ()) | set(network_quarantined)
            )
            existing["quarantined_stale_state_paths"] = sorted(
                set(existing.get("quarantined_stale_state_paths") or ()) | set(stale_quarantined)
            )
            existing["stale_state_paths"] = list(effective_stale_paths)
            if network_policy_changed:
                existing["network_policy"] = desired_policy
            _atomic_json(marker, existing, mode=0o600)
        elif tuple(existing.get("stale_state_paths") or ()) != effective_stale_paths or network_policy_changed:
            existing = dict(existing)
            existing["stale_state_paths"] = list(effective_stale_paths)
            if network_policy_changed:
                existing["network_policy"] = desired_policy
            _atomic_json(marker, existing, mode=0o600)
        return existing
    quarantine = root / "var/lib/cnserverops/template-quarantine" / template_id
    displaced = _quarantine_identity_paths(root, quarantine)
    # A technician clone must not inherit a development-only address or an
    # interface name that vanished after a firmware update.  Only explicitly
    # CNServerOps-owned netplan files are quarantined; unrelated customer
    # network configuration is intentionally outside this golden-image tool.
    network_quarantined = _quarantine_specific_paths(
        root,
        quarantine,
        _CN_STATIC_NETWORK_PATHS + (str(_CN_DHCP_NETWORK_PATH),),
    )
    effective_stale_paths = _merge_stale_state_paths(stale_state_paths)
    stale_quarantined = _quarantine_stale_state(root, quarantine, effective_stale_paths)
    payload = {
        "schema_version": 1,
        "state": "READY_FOR_CLONE",
        "template_id": template_id,
        "prepared_at_utc": utc_now(),
        "regenerate_machine_id": True,
        "regenerate_ssh_host_keys": True,
        "require_storage_fingerprint": True,
        "stale_state_paths": list(effective_stale_paths),
        "displaced_identity_paths": displaced,
        "quarantined_network_paths": network_quarantined,
        "quarantined_stale_state_paths": stale_quarantined,
        "network_policy": {
            "mode": "DHCP_GENERIC",
            "path": str(_CN_DHCP_NETWORK_PATH).replace("\\", "/"),
            "networkd_path": str(_CN_NETWORKD_DHCP_PATH).replace("\\", "/"),
            "match": "en* eth* eno*",
            "static_development_address_removed": True,
        },
        "hostname_is_not_runner_identity": True,
    }
    _atomic_json(marker, payload, mode=0o600)
    return payload


def personalize_clone(
    root: Path,
    *,
    runtime_version: str,
    storage_fingerprint: str = "",
) -> dict[str, Any]:
    """Personalize an explicitly marked clone and preserve all displaced state.

    This function intentionally refuses an unmarked filesystem. A consumed marker
    plus a valid runner receipt makes subsequent boots stable and idempotent.
    """

    root = root.resolve(strict=True)
    marker_path = root / _MARKER_RELATIVE
    consumed_path = root / _CONSUMED_RELATIVE
    runner_path = root / _RUNNER_RELATIVE
    receipt_path = root / _RECEIPT_RELATIVE
    if not marker_path.exists():
        if consumed_path.is_file() and runner_path.is_file() and receipt_path.is_file():
            runner = load_runner(runner_path)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            expected_storage = str(receipt.get("storage_fingerprint_sha256") or "")
            if storage_fingerprint and expected_storage and storage_fingerprint != expected_storage:
                raise ClonePersonalizationError("DUPLICATE_RUNNER_STORAGE_MISMATCH")
            return {
                "status": "ALREADY_PERSONALIZED",
                "runner_id": runner["runner_id"],
                "runtime_version": runner["runtime_version"],
                "receipt": str(receipt_path),
            }
        raise ClonePersonalizationError("CLONE_TEMPLATE_MARKER_MISSING")

    marker = _read_marker(marker_path)
    if marker.get("require_storage_fingerprint") and not re.fullmatch(r"[a-f0-9]{64}", storage_fingerprint):
        raise ClonePersonalizationError("RUNNER_STORAGE_FINGERPRINT_REQUIRED")
    lock_path = root / _LOCK_RELATIVE
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _ExclusiveFileLock(lock_path):
        transaction_path = root / _TRANSACTION_RELATIVE
        transaction = _load_or_create_transaction(transaction_path, marker, storage_fingerprint)
        quarantine_root = root / "var/lib/cnserverops/quarantine" / transaction["transaction_id"]
        quarantine_root.mkdir(parents=True, exist_ok=True)

        quarantined = _quarantine_stale_state(
            root,
            quarantine_root,
            _merge_stale_state_paths(marker.get("stale_state_paths") or ()),
        )
        machine_id_status = _personalize_machine_id(root, quarantine_root, transaction, marker)
        ssh_status = _personalize_ssh_host_keys(root, quarantine_root, transaction, marker)
        network_status = _personalize_generic_dhcp_network(root, marker)

        runner = bootstrap_runner(
            runner_path,
            runner_id=transaction["runner_id"],
            runtime_version=runtime_version,
            local_runner_uuid=transaction["local_runner_uuid"],
            storage_fingerprint_sha256=transaction.get("storage_fingerprint_sha256", ""),
        )
        runtime_pointer = _refresh_runtime_pointer(root, runtime_version, runner["runner_id"])
        receipt = {
            "schema_version": 1,
            "status": "PERSONALIZED",
            "template_id": marker["template_id"],
            "transaction_id": transaction["transaction_id"],
            "runner_id": runner["runner_id"],
            "local_runner_uuid": transaction["local_runner_uuid"],
            "storage_fingerprint_sha256": transaction.get("storage_fingerprint_sha256", ""),
            "completed_at_utc": utc_now(),
            "machine_id": machine_id_status,
            "ssh_host_keys": ssh_status,
            "network": network_status,
            "runtime_pointer": runtime_pointer,
            "quarantined_paths": quarantined,
            "server_identity_is_separate": True,
            "hostname_is_not_identity": True,
        }
        _atomic_json(receipt_path, receipt, mode=0o600)
        consumed = dict(marker)
        consumed["consumed_at_utc"] = receipt["completed_at_utc"]
        consumed["runner_id"] = runner["runner_id"]
        _atomic_json(consumed_path, consumed, mode=0o600)
        marker_path.unlink()
        return receipt


def _read_marker(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ClonePersonalizationError("CLONE_TEMPLATE_MARKER_INVALID")
    if payload.get("state") != "READY_FOR_CLONE":
        raise ClonePersonalizationError("CLONE_TEMPLATE_NOT_READY")
    template_id = str(payload.get("template_id") or "")
    if not _SAFE_TEMPLATE_ID.fullmatch(template_id):
        raise ClonePersonalizationError("CLONE_TEMPLATE_ID_INVALID")
    for key in ("regenerate_machine_id", "regenerate_ssh_host_keys"):
        if not isinstance(payload.get(key), bool):
            raise ClonePersonalizationError(f"CLONE_TEMPLATE_{key.upper()}_FLAG_REQUIRED")
    if "require_storage_fingerprint" in payload and not isinstance(payload["require_storage_fingerprint"], bool):
        raise ClonePersonalizationError("CLONE_TEMPLATE_STORAGE_FINGERPRINT_FLAG_INVALID")
    stale = payload.get("stale_state_paths") or []
    if not isinstance(stale, list) or not all(isinstance(item, str) for item in stale):
        raise ClonePersonalizationError("CLONE_TEMPLATE_STALE_PATHS_INVALID")
    return payload


def _merge_stale_state_paths(*groups: Any) -> tuple[str, ...]:
    """Return the mandatory clone scrub list plus caller-supplied paths."""
    values: set[str] = set()
    for group in groups:
        if group is None:
            continue
        for item in group:
            value = str(item).replace("\\", "/").lstrip("/")
            if value:
                values.add(value)
    values.update(str(item).replace("\\", "/") for item in _DEFAULT_STALE_STATE_PATHS)
    return tuple(sorted(values))


def _refresh_runtime_pointer(root: Path, runtime_version: str, runner_id: str) -> dict[str, Any]:
    """Bind the JSON runtime pointer to the personalized runner.

    The legacy ``current`` symlink remains the selector used by systemd.  The
    JSON pointer is descriptive/diagnostic metadata, but it must not retain the
    golden-image runner after first boot.  Test roots without a managed symlink
    are reported explicitly and are not made to fail personalization.
    """
    current_link = root / "opt/cnserverops/current"
    releases = root / "opt/cnserverops/releases"
    pointer = root / _CURRENT_POINTER_RELATIVE
    if not current_link.is_symlink():
        return {"status": "NOT_REFRESHED_NO_RUNTIME_SYMLINK"}
    try:
        target = current_link.resolve(strict=True)
        releases_root = releases.resolve(strict=True)
        target.relative_to(releases_root)
        if not target.is_dir():
            raise ValueError("runtime target is not a directory")
    except (OSError, ValueError) as exc:
        raise ClonePersonalizationError("CLONE_RUNTIME_POINTER_TARGET_INVALID") from exc
    previous_version = ""
    if pointer.is_file():
        try:
            prior = json.loads(pointer.read_text(encoding="utf-8"))
            if isinstance(prior, Mapping):
                previous_version = str(prior.get("version") or "")
        except (OSError, ValueError, json.JSONDecodeError):
            previous_version = ""
    payload = {
        "schema_version": 1,
        "version": str(runtime_version),
        "release_path": str(target),
        "config_root": str(root / "etc/cnserverops"),
        "runner_id": str(runner_id),
        "approval_id": "CLONE_FIRSTBOOT",
        "activated_at_utc": utc_now(),
        "previous_version": previous_version,
        "pointer_backend": "SYMLINK_AND_JSON",
        "clone_personalized": True,
    }
    _atomic_json(pointer, payload, mode=0o600)
    return {"status": "REFRESHED", "path": str(_CURRENT_POINTER_RELATIVE).replace("\\", "/"), "runner_id": str(runner_id)}


def _load_or_create_transaction(
    path: Path,
    marker: Mapping[str, Any],
    storage_fingerprint: str,
) -> dict[str, str]:
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("template_id") != marker["template_id"]:
            raise ClonePersonalizationError("PERSONALIZATION_TRANSACTION_TEMPLATE_MISMATCH")
        expected_storage = str(payload.get("storage_fingerprint_sha256") or "")
        if storage_fingerprint and expected_storage and storage_fingerprint != expected_storage:
            raise ClonePersonalizationError("PERSONALIZATION_TRANSACTION_STORAGE_MISMATCH")
        return {str(key): str(value) for key, value in payload.items()}
    local_uuid = str(uuid.uuid4())
    payload = {
        "schema_version": "1",
        "template_id": str(marker["template_id"]),
        "transaction_id": f"CLONE-{uuid.uuid4().hex.upper()}",
        "runner_id": f"CNSSD-{local_uuid.replace('-', '').upper()}",
        "local_runner_uuid": local_uuid,
        "machine_id": uuid.uuid4().hex,
        "storage_fingerprint_sha256": storage_fingerprint,
        "created_at_utc": utc_now(),
    }
    _atomic_json(path, payload, mode=0o600)
    return payload


def _quarantine_stale_state(root: Path, quarantine: Path, relative_paths: Any) -> list[str]:
    moved: list[str] = []
    protected = {_MARKER_RELATIVE, _CONSUMED_RELATIVE, _RUNNER_RELATIVE, _TRANSACTION_RELATIVE, _RECEIPT_RELATIVE}
    for item in relative_paths:
        relative = Path(str(item).lstrip("/\\"))
        if not relative.parts or ".." in relative.parts or relative in protected:
            raise ClonePersonalizationError("CLONE_TEMPLATE_STALE_PATH_OUTSIDE_POLICY")
        source = root / relative
        if not source.exists() and not source.is_symlink():
            continue
        destination = quarantine / "stale-state" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            # A release activation or a retry can recreate a stale selector
            # after its historical quarantine copy already exists.  Never
            # leave that reintroduced state on the golden image; preserve it
            # under a distinct reversible name instead of overwriting either
            # copy.
            candidate = destination.with_name(destination.name + ".reactivated")
            suffix = 2
            while candidate.exists() or candidate.is_symlink():
                candidate = destination.with_name(destination.name + f".reactivated-{suffix}")
                suffix += 1
            source.replace(candidate)
            moved.append(str(relative).replace("\\", "/"))
            continue
        source.replace(destination)
        moved.append(str(relative).replace("\\", "/"))
    return moved


def _quarantine_identity_paths(root: Path, quarantine: Path) -> list[str]:
    """Move clone-source identity artifacts into the reversible template quarantine."""
    moved: list[str] = []
    for relative in (_RUNNER_RELATIVE, _CONSUMED_RELATIVE, _RECEIPT_RELATIVE, _TRANSACTION_RELATIVE):
        source = root / relative
        if not source.exists() and not source.is_symlink():
            continue
        destination = quarantine / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            # A release activation may temporarily restore the runner so that
            # it can remain bound to the approval.  Preserve a semantically
            # matching updated runner beside the historical copy; do not let
            # a harmless runtime-version refresh make clone preparation fail.
            if source.is_file() and destination.is_file() and source.read_bytes() == destination.read_bytes():
                source.unlink()
                moved.append(str(relative).replace("\\", "/"))
                continue
            if relative == _RUNNER_RELATIVE and source.is_file() and destination.is_file():
                try:
                    source_payload = json.loads(source.read_text(encoding="utf-8"))
                    destination_payload = json.loads(destination.read_text(encoding="utf-8"))
                except (OSError, ValueError, json.JSONDecodeError):
                    source_payload = destination_payload = None
                if (
                    isinstance(source_payload, Mapping)
                    and isinstance(destination_payload, Mapping)
                    and str(source_payload.get("runner_id") or "")
                    and str(source_payload.get("runner_id")) == str(destination_payload.get("runner_id"))
                    and str(source_payload.get("local_runner_uuid") or "") == str(destination_payload.get("local_runner_uuid") or "")
                ):
                    refreshed = destination.with_name(destination.name + ".reactivated")
                    if refreshed.exists() or refreshed.is_symlink():
                        if refreshed.is_file() and refreshed.read_bytes() == source.read_bytes():
                            source.unlink()
                            moved.append(str(relative).replace("\\", "/"))
                            continue
                        raise ClonePersonalizationError("TEMPLATE_QUARANTINE_DESTINATION_ALREADY_EXISTS")
                    source.replace(refreshed)
                    moved.append(str(relative).replace("\\", "/"))
                    continue
            raise ClonePersonalizationError("TEMPLATE_QUARANTINE_DESTINATION_ALREADY_EXISTS")
        source.replace(destination)
        moved.append(str(relative).replace("\\", "/"))
    return moved


def _quarantine_specific_paths(root: Path, quarantine: Path, relative_paths: tuple[str, ...]) -> list[str]:
    """Quarantine only fixed CNServerOps-owned paths during golden prep."""
    moved: list[str] = []
    for item in relative_paths:
        relative = Path(str(item).lstrip("/\\"))
        if not relative.parts or ".." in relative.parts:
            raise ClonePersonalizationError("CLONE_TEMPLATE_NETWORK_PATH_OUTSIDE_POLICY")
        source = root / relative
        if not source.exists() and not source.is_symlink():
            continue
        destination = quarantine / "network" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise ClonePersonalizationError("CLONE_TEMPLATE_NETWORK_QUARANTINE_EXISTS")
        source.replace(destination)
        moved.append(str(relative).replace("\\", "/"))
    return moved


def _personalize_generic_dhcp_network(root: Path, marker: Mapping[str, Any]) -> dict[str, Any]:
    """Write one owned generic DHCP profile before networking starts.

    The profile intentionally matches Ethernet interface names instead of the
    development adapter/MAC.  It contains no server identity, IP address, or
    route from the source SSD and does not touch unrelated netplan files.
    """
    policy = marker.get("network_policy") if isinstance(marker.get("network_policy"), Mapping) else {}
    if str(policy.get("mode") or "") != "DHCP_GENERIC":
        return {"status": "PRESERVED_BY_TEMPLATE_POLICY"}
    relative = Path(str(policy.get("path") or _CN_DHCP_NETWORK_PATH).lstrip("/\\"))
    if relative != _CN_DHCP_NETWORK_PATH:
        raise ClonePersonalizationError("CLONE_TEMPLATE_NETWORK_PATH_INVALID")
    target = root / relative
    content = (
        "# Generated once by CNServerOps clone-firstboot.\n"
        "# This file intentionally contains no development/static address.\n"
        "network:\n"
        "  version: 2\n"
        "  ethernets:\n"
        "    cnserverops-dhcp:\n"
        "      match:\n"
        "        name: 'en*'\n"
        "      dhcp4: true\n"
        "      dhcp6: false\n"
        "      optional: true\n"
    )
    _atomic_text(target, content, mode=0o600)
    # Netplan is not guaranteed to be applied before this one-shot service
    # runs (and some supported images use native systemd-networkd without
    # netplan at all).  Publish an equivalent native profile atomically so
    # the first boot has a usable DHCP path regardless of the image's network
    # frontend.  The profile contains no MAC, hostname, static address, or
    # server-specific route.
    networkd_relative = Path(
        str(policy.get("networkd_path") or _CN_NETWORKD_DHCP_PATH).lstrip("/\\")
    )
    if networkd_relative != _CN_NETWORKD_DHCP_PATH:
        raise ClonePersonalizationError("CLONE_TEMPLATE_NETWORKD_PATH_INVALID")
    networkd_target = root / networkd_relative
    networkd_content = (
        "# Generated once by CNServerOps clone-firstboot.\n"
        "# Generic DHCP only; no development/static address is retained.\n"
        "[Match]\n"
        "Name=en* eth* eno*\n\n"
        "[Network]\n"
        "DHCP=ipv4\n"
        "IPv6AcceptRA=no\n"
        "RequiredForOnline=no\n"
    )
    _atomic_text(networkd_target, networkd_content, mode=0o600)
    return {
        "status": "DHCP_GENERIC_WRITTEN",
        "path": str(relative).replace("\\", "/"),
        "networkd_path": str(networkd_relative).replace("\\", "/"),
        "matched_interface_globs": ["en*", "eth*", "eno*"],
        "static_address_present": False,
    }


def _personalize_machine_id(
    root: Path,
    quarantine: Path,
    transaction: Mapping[str, str],
    marker: Mapping[str, Any],
) -> str:
    if not marker["regenerate_machine_id"]:
        return "PRESERVED_BY_TEMPLATE_POLICY"
    machine_id = transaction["machine_id"]
    if not re.fullmatch(r"[a-f0-9]{32}", machine_id):
        raise ClonePersonalizationError("PERSONALIZATION_MACHINE_ID_INVALID")
    etc_machine_id = root / "etc/machine-id"
    existing = etc_machine_id.read_text(encoding="ascii").strip() if etc_machine_id.is_file() else ""
    if existing == machine_id:
        return "REGENERATED"
    if etc_machine_id.exists() or etc_machine_id.is_symlink():
        destination = quarantine / "os-identity/etc-machine-id"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            etc_machine_id.replace(destination)
    _atomic_text(etc_machine_id, machine_id + "\n", mode=0o444)

    dbus_machine_id = root / "var/lib/dbus/machine-id"
    if dbus_machine_id.is_symlink():
        return "REGENERATED"
    if dbus_machine_id.exists():
        destination = quarantine / "os-identity/dbus-machine-id"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            dbus_machine_id.replace(destination)
    _atomic_text(dbus_machine_id, machine_id + "\n", mode=0o444)
    return "REGENERATED"


def _personalize_ssh_host_keys(
    root: Path,
    quarantine: Path,
    transaction: Mapping[str, str],
    marker: Mapping[str, Any],
) -> str:
    if not marker["regenerate_ssh_host_keys"]:
        return "PRESERVED_BY_TEMPLATE_POLICY"
    ssh_dir = root / "etc/ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    marker_file = ssh_dir / ".cnserverops-personalization"
    if marker_file.is_file() and marker_file.read_text(encoding="ascii").strip() == transaction["transaction_id"]:
        return "REGENERATED"

    temporary_root = Path(tempfile.mkdtemp(prefix="cnserverops-ssh-", dir=ssh_dir))
    try:
        generated: list[Path] = []
        for key_type, extra in (("ed25519", []), ("rsa", ["-b", "3072"])):
            private = temporary_root / f"ssh_host_{key_type}_key"
            command = ["ssh-keygen", "-q", "-t", key_type, *extra, "-N", "", "-f", str(private)]
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=60)
            if completed.returncode != 0:
                raise ClonePersonalizationError(f"SSH_HOST_KEY_GENERATION_FAILED_{key_type.upper()}")
            generated.extend((private, Path(str(private) + ".pub")))

        old_key_root = quarantine / "os-identity/ssh-host-keys"
        old_key_root.mkdir(parents=True, exist_ok=True)
        for old in ssh_dir.glob("ssh_host_*_key*"):
            if temporary_root in old.parents:
                continue
            destination = old_key_root / old.name
            if not destination.exists():
                old.replace(destination)
        for source in generated:
            destination = ssh_dir / source.name
            source.replace(destination)
            os.chmod(destination, 0o644 if destination.suffix == ".pub" else 0o600)
        _atomic_text(marker_file, transaction["transaction_id"] + "\n", mode=0o600)
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
    return "REGENERATED"


class _ExclusiveFileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.descriptor: int | None = None

    def __enter__(self) -> "_ExclusiveFileLock":
        try:
            self.descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ClonePersonalizationError("PERSONALIZATION_ALREADY_RUNNING_OR_INTERRUPTED") from exc
        os.write(self.descriptor, str(os.getpid()).encode("ascii"))
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def _atomic_json(path: Path, payload: Mapping[str, Any], *, mode: int) -> None:
    _atomic_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n", mode=mode)


def _atomic_text(path: Path, value: str, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, mode)
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
