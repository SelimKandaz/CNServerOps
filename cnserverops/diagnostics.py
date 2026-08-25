"""Universal diagnostic artifact packaging with independent export state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .capabilities import CapabilityRecord, ValidationLevel
from .storage import ensure_free_space


_SENSITIVE_NAME = re.compile(
    r"(^|[._-])(password|passwd|credential|credentials|secret|token|authorization|cookie|private[-_]?key)([._-]|$)",
    re.IGNORECASE,
)


class UnsafeEvidenceError(ValueError):
    """An evidence input is unsafe or likely to contain credentials."""


@dataclass(frozen=True)
class ArtifactRecord:
    source: str
    path: str
    filename: str
    size_bytes: int
    sha256: str
    collected_at_utc: str
    mechanism: str
    validation_level: ValidationLevel

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["validation_level"] = self.validation_level.value
        return payload


def inspect_artifact(
    path: Path,
    *,
    source: str,
    mechanism: str,
    validation_level: ValidationLevel = ValidationLevel.DISCOVERED,
) -> ArtifactRecord:
    if path.is_symlink():
        raise UnsafeEvidenceError(f"Artifact symlinks are not accepted: {path}")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise UnsafeEvidenceError(f"Artifact must be a regular file: {path}")
    if _SENSITIVE_NAME.search(resolved.name):
        raise UnsafeEvidenceError(f"Artifact name is credential-sensitive and cannot be bundled: {resolved.name}")
    size = resolved.stat().st_size
    if size <= 0:
        raise UnsafeEvidenceError(f"Artifact is empty: {resolved}")
    return ArtifactRecord(
        source=source,
        path=str(resolved),
        filename=resolved.name,
        size_bytes=size,
        sha256=_sha256(resolved),
        collected_at_utc=datetime.now(timezone.utc).isoformat(),
        mechanism=mechanism,
        validation_level=validation_level,
    )


def inspect_asmb12_system_diagnostics(
    path: Path,
    *,
    mechanism: str = "operator-provided ASMB12 System Diagnostics download",
    validation_level: ValidationLevel = ValidationLevel.DISCOVERED,
) -> ArtifactRecord:
    """Register an ASMB12 diagnostic file without executing or extracting it."""
    return inspect_artifact(
        path,
        source="ASUS ASMB12 System Diagnostics",
        mechanism=mechanism,
        validation_level=validation_level,
    )


def build_universal_bundle(
    primary_output_dir: Path,
    *,
    platform: Mapping[str, Any],
    identity: Mapping[str, Any],
    evidence_paths: Iterable[Path] = (),
    vendor_artifact: ArtifactRecord | None = None,
    capabilities: Iterable[CapabilityRecord] = (),
) -> tuple[Path, dict[str, Any]]:
    """Build on primary storage first. Export is always a separate operation."""
    primary_output_dir.mkdir(parents=True, exist_ok=True)
    approved_evidence = [_inspect_evidence(path) for path in evidence_paths]
    artifact_path = Path(vendor_artifact.path) if vendor_artifact else None
    if artifact_path is not None:
        current_hash = _sha256(artifact_path)
        if current_hash != vendor_artifact.sha256:
            raise UnsafeEvidenceError("Vendor diagnostic artifact changed after registration.")

    expected_bytes = sum(path.stat().st_size for path, _ in approved_evidence)
    if artifact_path is not None:
        expected_bytes += artifact_path.stat().st_size
    ensure_free_space(primary_output_dir, required_bytes=expected_bytes + 8 * 1024 * 1024)

    serial = _safe_name(str(identity.get("primary_serial") or "UNKNOWN_SERIAL"))
    model = _safe_name(str(identity.get("model") or platform.get("platform_id") or "UNKNOWN_MODEL"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle_name = f"Universal_DiagnosticBundle_{model}_{serial}_{stamp}.zip"
    bundle_path = primary_output_dir / bundle_name
    included: list[dict[str, Any]] = []

    collection_status = "SUCCESS" if vendor_artifact else "PARTIAL" if approved_evidence else "FAILED"
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "bundle_type": "UNIVERSAL_SERVER_DIAGNOSTIC_BUNDLE",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": dict(platform),
        "identity": dict(identity),
        "diagnostic_source": vendor_artifact.source if vendor_artifact else "OS/standard evidence only",
        "collection": {
            "status": collection_status,
            "vendor_artifact": vendor_artifact.to_dict() if vendor_artifact else None,
            "warnings": [] if vendor_artifact else ["No vendor diagnostic artifact was supplied."],
        },
        "export": {
            "status": "NOT_ATTEMPTED",
            "destination": "",
            "error": "",
        },
        "capabilities": [record.to_dict() for record in capabilities],
        "included": included,
        "credential_policy": "Explicit evidence allowlist; sensitive filenames rejected; credentials must never be supplied.",
    }

    descriptor, temporary_name = tempfile.mkstemp(prefix=bundle_name + ".", suffix=".tmp", dir=primary_output_dir)
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            if vendor_artifact and artifact_path is not None:
                arcname = f"vendor/{_safe_name(vendor_artifact.filename)}"
                archive.write(artifact_path, arcname=arcname)
                included.append(_included_record(arcname, artifact_path, vendor_artifact.sha256))
            for index, (path, digest) in enumerate(approved_evidence, start=1):
                arcname = f"evidence/{index:03d}_{_safe_name(path.name)}"
                archive.write(path, arcname=arcname)
                included.append(_included_record(arcname, path, digest))
            archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        temporary_path.replace(bundle_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return bundle_path, manifest


def export_bundle(bundle_path: Path, export_dir: Path, *, primary_receipt_dir: Path | None = None) -> dict[str, Any]:
    """Copy and hash-verify an existing primary bundle without changing collection status."""
    source = bundle_path.resolve(strict=True)
    result: dict[str, Any] = {
        "schema_version": 1,
        "collection_status": _collection_status_from_bundle(source),
        "export_status": "FAILED",
        "source": str(source),
        "destination": "",
        "sha256": _sha256(source),
        "error": "",
        "attempted_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    partial: Path | None = None
    try:
        ensure_free_space(export_dir, required_bytes=source.stat().st_size)
        export_dir.mkdir(parents=True, exist_ok=True)
        destination = export_dir / source.name
        if destination.exists():
            if not destination.is_file() or _sha256(destination) != result["sha256"]:
                raise FileExistsError(f"refusing to overwrite a different export artifact: {destination}")
            result["export_status"] = "SUCCESS"
            result["destination"] = str(destination.resolve())
            result["error"] = "already exported; checksum matched"
        else:
            descriptor, partial_name = tempfile.mkstemp(prefix=f".{source.name}.", suffix=".partial", dir=export_dir)
            os.close(descriptor)
            partial = Path(partial_name)
            shutil.copyfile(source, partial)
            if _sha256(partial) != result["sha256"]:
                raise OSError("exported copy checksum does not match primary artifact")
            partial.replace(destination)
            result["export_status"] = "SUCCESS"
            result["destination"] = str(destination.resolve())
    except (OSError, PermissionError) as exc:
        result["error"] = str(exc)
    finally:
        if partial is not None and partial.exists():
            partial.unlink()
    if primary_receipt_dir is not None:
        primary_receipt_dir.mkdir(parents=True, exist_ok=True)
        receipt = primary_receipt_dir / f"{source.name}.export.json"
        _atomic_json(receipt, result)
        result["receipt"] = str(receipt.resolve())
    return result


def _inspect_evidence(path: Path) -> tuple[Path, str]:
    if path.is_symlink():
        raise UnsafeEvidenceError(f"Evidence symlinks are not accepted: {path}")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise UnsafeEvidenceError(f"Evidence must be a regular file: {path}")
    if _SENSITIVE_NAME.search(resolved.name):
        raise UnsafeEvidenceError(f"Sensitive evidence filename rejected: {resolved.name}")
    return resolved, _sha256(resolved)


def _included_record(archive_path: str, source: Path, digest: str) -> dict[str, Any]:
    return {
        "archive_path": archive_path,
        "source_name": source.name,
        "size_bytes": source.stat().st_size,
        "sha256": digest,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _collection_status_from_bundle(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            manifest = json.loads(archive.read("manifest.json"))
        return str(manifest.get("collection", {}).get("status") or "UNKNOWN")
    except (KeyError, OSError, zipfile.BadZipFile, json.JSONDecodeError, AttributeError):
        return "UNKNOWN"


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-") or "unknown"


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
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
