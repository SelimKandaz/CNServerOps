"""Dell production regression manifest and comparison harness."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class DellRegressionCheck:
    check_id: str
    description: str
    requires_physical_dell: bool = True


DELL_REGRESSION_CHECKS = (
    DellRegressionCheck("option1.orchestration", "Countdown menu Option 1 enters the existing Dell wrapper and automation path"),
    DellRegressionCheck("platform.detection", "Dell PowerEdge R640 routes only to the existing Dell production adapter", False),
    DellRegressionCheck("idrac.racadm", "RACADM/iDRAC inventory, reachability, and boot sanity"),
    DellRegressionCheck("firmware.catalog_preview", "SUU/DSU/catalog applicability and preview"),
    DellRegressionCheck("firmware.apply", "Approved Dell firmware apply and task/error behavior"),
    DellRegressionCheck("reboot.resume", "Identity-bound resume across required reboot"),
    DellRegressionCheck("serial.inventory", "System/board/chassis serial capture"),
    DellRegressionCheck("hardware.tests", "CPU, memory, storage, NIC, PCIe, and optional GPU tests"),
    DellRegressionCheck("reports.portal", "Normalized reports, portal, and final board"),
    DellRegressionCheck("supportassist.tsr", "SupportAssist/TSR collection and bundle inclusion"),
    DellRegressionCheck("logs.preclean", "Pre-clean lifecycle/event evidence preserved"),
    DellRegressionCheck("logs.sel_clear", "Gated SEL clear and post-clear verification"),
    DellRegressionCheck("result_vault.archive", "Result-vault/archive retention and cleanup"),
    DellRegressionCheck("storage.export", "Ext4 authoritative result plus EFI/CN_EXPORT compatibility"),
)


def hash_reference_files(root: Path, relative_paths: Iterable[str]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    missing: list[str] = []
    for relative in relative_paths:
        path = root / relative
        if not path.is_file():
            missing.append(relative)
            continue
        records.append({"path": relative, "size_bytes": path.stat().st_size, "sha256": _sha256(path)})
    return {"root": str(root.resolve()), "files": records, "missing": missing}


def evaluate_dell_regression(results: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    physical_pending = False
    failed = False
    for check in DELL_REGRESSION_CHECKS:
        result = dict(results.get(check.check_id) or {})
        status = str(result.get("status") or ("NOT_RUN_PHYSICAL" if check.requires_physical_dell else "NOT_RUN"))
        if check.requires_physical_dell and status in {"NOT_RUN", "NOT_RUN_PHYSICAL", "SIMULATED"}:
            physical_pending = True
        if status == "FAIL":
            failed = True
        rows.append(asdict(check) | {"status": status, "evidence": result.get("evidence", "")})
    overall = "FAIL" if failed else "NOT_RUN_PHYSICAL" if physical_pending else "PASS"
    return {
        "schema_version": 1,
        "overall_status": overall,
        "production_regression_claimed": overall == "PASS",
        "checks": rows,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
