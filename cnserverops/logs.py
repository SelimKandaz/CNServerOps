"""Two-phase event-log preservation and gated cleanup engine."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Protocol

from .models import utc_now
from .safety import MutationGate


class LogCleanupError(RuntimeError):
    pass


class LogCleanupAdapter(Protocol):
    name: str

    def clear(self) -> Mapping[str, Any]: ...

    def verify_empty(self) -> Mapping[str, Any]: ...


class DisabledLogCleanupAdapter:
    name = "log_cleanup_transport_not_validated"

    def clear(self) -> Mapping[str, Any]:
        raise LogCleanupError("No physical ASUS log-clear adapter is enabled before PASS 3")

    def verify_empty(self) -> Mapping[str, Any]:
        raise LogCleanupError("No physical ASUS log-clear verification adapter is enabled before PASS 3")


class LocalIpmiSelCleanupAdapter:
    """ASUS-capable local KCS SEL clear with fixed commands and post-clear polling."""

    name = "local_kcs_ipmitool_sel"

    def __init__(self, *, timeout_seconds: int = 30, verify_attempts: int = 10) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise ValueError("SEL command timeout must be between 1 and 120 seconds")
        if verify_attempts <= 0 or verify_attempts > 60:
            raise ValueError("SEL verification attempts must be between 1 and 60")
        self.timeout_seconds = timeout_seconds
        self.verify_attempts = verify_attempts

    def clear(self) -> Mapping[str, Any]:
        completed = self._run(["ipmitool", "sel", "clear"])
        if completed.returncode != 0:
            raise LogCleanupError(f"Local KCS SEL clear failed with exit code {completed.returncode}")
        return {
            "mechanism": self.name,
            "command": ["ipmitool", "sel", "clear"],
            "exit_code": completed.returncode,
            "response": completed.stdout.strip()[:500],
            "executed_at_utc": utc_now(),
        }

    def verify_empty(self) -> Mapping[str, Any]:
        observations: list[int] = []
        for attempt in range(1, self.verify_attempts + 1):
            completed = self._run(["ipmitool", "sel", "info"])
            if completed.returncode != 0:
                raise LogCleanupError(f"Local KCS SEL verification failed with exit code {completed.returncode}")
            match = re.search(r"^Entries\s*:\s*(\d+)\s*$", completed.stdout, re.MULTILINE)
            if not match:
                raise LogCleanupError("Local KCS SEL verification did not report an entry count")
            entries = int(match.group(1))
            observations.append(entries)
            if entries == 0:
                return {
                    "mechanism": self.name,
                    "empty": True,
                    "entry_count": 0,
                    "attempts": attempt,
                    "observed_counts": observations,
                    "verified_at_utc": utc_now(),
                }
            # Several ASUS/AMI BMCs append one informational record describing
            # the successful clear operation ("Log area reset/cleared").  It
            # is not a residual hardware event and should not make an
            # otherwise verified clean operation fail.  Confirm the sole
            # record through the read-only SEL listing before accepting it.
            if entries == 1:
                listing = self._run(["ipmitool", "sel", "elist"])
                if listing.returncode == 0 and _is_expected_clear_record(listing.stdout):
                    return {
                        "mechanism": self.name,
                        "empty": True,
                        "entry_count": 1,
                        "residual_entries": 0,
                        "expected_clear_record": True,
                        "attempts": attempt,
                        "observed_counts": observations,
                        "verified_at_utc": utc_now(),
                    }
            if attempt < self.verify_attempts:
                time.sleep(1)
        return {
            "mechanism": self.name,
            "empty": False,
            "entry_count": observations[-1],
            "attempts": self.verify_attempts,
            "observed_counts": observations,
            "verified_at_utc": utc_now(),
        }

    def _run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            raise LogCleanupError(f"Local KCS SEL command unavailable: {type(exc).__name__}") from exc


def _is_expected_clear_record(text: str) -> bool:
    """Return true only for the BMC's informational clear-marker record."""
    lines = [str(line or "").strip().lower() for line in str(text or "").splitlines() if str(line or "").strip()]
    if len(lines) != 1:
        return False
    line = lines[0]
    return "log area reset/cleared" in line or "log area reset / cleared" in line


def preserve_preclean_logs(output: Path, evidence: Mapping[str, Path]) -> dict[str, Any]:
    if not evidence:
        raise LogCleanupError("At least one pre-clean event-log artifact is required")
    records: list[dict[str, Any]] = []
    for category, path in sorted(evidence.items()):
        if path.is_symlink() or not path.resolve(strict=True).is_file() or path.stat().st_size <= 0:
            raise LogCleanupError(f"Unsafe or empty pre-clean evidence: {category}")
        records.append(
            {
                "category": category,
                "path": str(path.resolve()),
                "size_bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    manifest = {
        "schema_version": 1,
        "phase": "PRE_CLEAN_PRESERVED",
        "created_at_utc": utc_now(),
        "artifacts": records,
        "verified_saved": True,
    }
    _atomic_json(output, manifest)
    return manifest


def execute_log_cleanup(
    *,
    identity: Mapping[str, Any],
    preclean_manifest: Mapping[str, Any],
    diagnostic_artifact_hashes: set[str],
    adapter: LogCleanupAdapter,
    mutation_gate: MutationGate,
    run_id: str = "",
) -> dict[str, Any]:
    artifacts = list(preclean_manifest.get("artifacts") or [])
    if preclean_manifest.get("phase") != "PRE_CLEAN_PRESERVED" or not preclean_manifest.get("verified_saved") or not artifacts:
        raise LogCleanupError("Pre-clean evidence has not been safely preserved")
    for record in artifacts:
        path = Path(str(record.get("path") or ""))
        expected = str(record.get("sha256") or "")
        if not path.is_file() or _sha256(path) != expected:
            raise LogCleanupError("Pre-clean evidence changed or disappeared before log clear")
        if expected not in diagnostic_artifact_hashes:
            raise LogCleanupError("Diagnostic bundle does not attest every pre-clean log artifact")
    mutation_gate.require(
        "LOG_CLEAR",
        identity,
        context={"run_id": run_id, "component": "SEL"},
    )
    clear_result = dict(adapter.clear())
    verification = dict(adapter.verify_empty())
    if not verification.get("empty"):
        return {
            "schema_version": 1,
            "status": "FAILED",
            "reason_code": "LOG_CLEAR_FAILED",
            "clear_result": clear_result,
            "postclean_verification": verification,
        }
    return {
        "schema_version": 1,
        "status": "SUCCESS",
        "reason_code": "LOG_CLEAR_VERIFIED",
        "clear_result": clear_result,
        "postclean_verification": verification,
        "preclean_hashes": sorted(diagnostic_artifact_hashes),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
