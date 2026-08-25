"""Content-addressed firmware repository and evidence-based applicability decisions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import ssl
import tempfile
import time
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class FirmwareRepositoryError(RuntimeError):
    pass


class FirmwareApplicabilityStatus:
    APPLICABLE = "APPLICABLE"
    CURRENT = "CURRENT"
    REVIEW = "REVIEW"
    BLOCKED = "BLOCKED"


_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True)
class FirmwarePackageMetadata:
    vendor: str
    component: str
    version: str
    package_filename: str
    sha256: str
    source: str
    source_url: str = ""
    compatible_models: tuple[str, ...] = ()
    compatible_families: tuple[str, ...] = ()
    compatible_boards: tuple[str, ...] = ()
    # Optional ASUS-specific exact selectors.  Generic Dell metadata remains
    # valid; ASUS matching requires any selectors supplied by the vendor to
    # agree rather than treating a family name as a model substitute.
    compatible_platform_ids: tuple[str, ...] = ()
    compatible_bmc_generations: tuple[str, ...] = ()
    package_format: str = "UNKNOWN"
    official_release_url: str = ""
    vendor_sha256: str = ""
    # ASUS frequently publishes packages without a sidecar checksum. The
    # repository pins sha256 to the bytes received; these fields capture the
    # independent provenance for that case.
    official_source_verified: bool = False
    provenance_level: str = "UNVERIFIED"
    package_signature_status: str = "NOT_CHECKED"
    package_metadata_evidence: tuple[str, ...] = ()
    install_mechanism: str = "UNKNOWN"
    reboot_requirement: str = "UNKNOWN"
    validation_status: str = "UNVERIFIED"
    applicability_evidence: tuple[str, ...] = ()
    discovered_at_utc: str = ""
    downloaded_at_utc: str = ""
    size_bytes: int = 0

    def validate(self) -> None:
        if not self.vendor or not self.component or not self.version:
            raise FirmwareRepositoryError("Firmware metadata requires vendor, component, and version")
        if not _SHA256.fullmatch(self.sha256.lower()):
            raise FirmwareRepositoryError("Firmware metadata contains an invalid SHA256")
        if self.vendor_sha256 and not _SHA256.fullmatch(self.vendor_sha256.lower()):
            raise FirmwareRepositoryError("Firmware metadata contains an invalid vendor SHA256")
        if Path(self.package_filename).name != self.package_filename or not self.package_filename:
            raise FirmwareRepositoryError("Firmware package filename must be a plain filename")
        if not (self.compatible_models or self.compatible_families or self.compatible_boards or self.compatible_platform_ids):
            raise FirmwareRepositoryError("Firmware metadata requires explicit model, family, or board compatibility")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "FirmwarePackageMetadata":
        values = dict(payload)
        for field_name in (
            "compatible_models",
            "compatible_families",
            "compatible_boards",
            "compatible_platform_ids",
            "compatible_bmc_generations",
            "applicability_evidence",
            "package_metadata_evidence",
        ):
            values[field_name] = tuple(values.get(field_name) or ())
        # Catalog adapters may retain source-only fields in their evidence;
        # do not allow those to turn into constructor surprises.
        accepted = {item.name for item in fields(cls)}
        values = {key: value for key, value in values.items() if key in accepted}
        record = cls(**values)
        record.validate()
        return record


@dataclass(frozen=True)
class CatalogEvidence:
    catalog_id: str
    vendor: str
    checked_at_utc: str
    source: str
    status: str
    entries: tuple[Mapping[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ApplicabilityDecision:
    status: str
    reason_codes: tuple[str, ...]
    package_sha256: str
    current_version: str
    target_version: str
    catalog_id: str = ""
    evidence: tuple[str, ...] = ()

    @property
    def approved_for_executor(self) -> bool:
        return self.status == FirmwareApplicabilityStatus.APPLICABLE

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"approved_for_executor": self.approved_for_executor}


def evaluate_applicability(
    metadata: FirmwarePackageMetadata,
    *,
    identity: Mapping[str, Any],
    board_name: str = "",
    family: str = "",
    current_version: str,
    catalog_entry: Mapping[str, Any] | None,
) -> ApplicabilityDecision:
    """A cached binary is never sufficient evidence of freshness or applicability."""
    metadata.validate()
    reasons: list[str] = []
    vendor = str(identity.get("vendor") or "").upper()
    model = str(identity.get("model") or "").upper()
    if vendor != metadata.vendor.upper():
        reasons.append("VENDOR_MISMATCH")
    model_match = model in {item.upper() for item in metadata.compatible_models}
    family_match = bool(family) and family.upper() in {item.upper() for item in metadata.compatible_families}
    board_match = bool(board_name) and board_name.upper() in {item.upper() for item in metadata.compatible_boards}
    if not (model_match or family_match or board_match):
        reasons.append("PACKAGE_PLATFORM_MISMATCH")
    if metadata.validation_status not in {
        "CHECKSUM_VERIFIED",
        "VENDOR_SIGNED",
        "LAB_VALIDATED",
        "PROVENANCE_VERIFIED",
        "CHECKSUM_VERIFIED_WITHOUT_VENDOR_HASH",
        "OFFICIAL_SOURCE_VERIFIED",
    }:
        reasons.append("PACKAGE_NOT_VALIDATED")
    if not catalog_entry:
        reasons.append("CATALOG_APPLICABILITY_UNAVAILABLE")
        status = FirmwareApplicabilityStatus.BLOCKED
        target = metadata.version
        catalog_id = ""
    else:
        catalog_id = str(catalog_entry.get("catalog_id") or "")
        target = str(catalog_entry.get("version") or "")
        if str(catalog_entry.get("component") or "").upper() != metadata.component.upper():
            reasons.append("CATALOG_COMPONENT_MISMATCH")
        if target != metadata.version:
            reasons.append("CATALOG_PACKAGE_VERSION_MISMATCH")
        if str(catalog_entry.get("applicability") or "").upper() != "APPLICABLE":
            reasons.append("CATALOG_DID_NOT_CONFIRM_APPLICABILITY")
        if current_version and current_version == target and not reasons:
            status = FirmwareApplicabilityStatus.CURRENT
            reasons.append("ALREADY_CURRENT")
        elif reasons:
            status = FirmwareApplicabilityStatus.BLOCKED
        else:
            status = FirmwareApplicabilityStatus.APPLICABLE
    return ApplicabilityDecision(
        status=status,
        reason_codes=tuple(reasons),
        package_sha256=metadata.sha256.lower(),
        current_version=current_version,
        target_version=target,
        catalog_id=catalog_id,
        evidence=metadata.applicability_evidence,
    )


class PackageDownloader(Protocol):
    def download(self, source_url: str, destination: Path) -> None: ...


class HttpsPackageDownloader:
    """Bounded HTTPS downloader; repository ingest performs the authoritative checksum check."""

    def __init__(self, *, verify_tls: bool = True, timeout_seconds: int = 120, max_bytes: int = 4 * 1024**3) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.ssl_context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()

    def download(self, source_url: str, destination: Path) -> None:
        parsed = urlparse(source_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise FirmwareRepositoryError("Firmware source must be HTTPS without embedded credentials")
        request = Request(source_url, headers={"Accept": "application/octet-stream"}, method="GET")
        total = 0
        try:
            with urlopen(request, timeout=self.timeout_seconds, context=self.ssl_context) as response:
                final = urlparse(response.geturl())
                if final.scheme.lower() != "https":
                    raise FirmwareRepositoryError("Firmware download redirected away from HTTPS")
                declared = int(response.headers.get("Content-Length") or 0)
                if declared and declared > self.max_bytes:
                    raise FirmwareRepositoryError("Firmware package exceeds the configured size limit")
                with destination.open("wb") as stream:
                    while True:
                        block = response.read(1024 * 1024)
                        if not block:
                            break
                        total += len(block)
                        if total > self.max_bytes:
                            raise FirmwareRepositoryError("Firmware package exceeds the configured size limit")
                        stream.write(block)
                    stream.flush()
                    os.fsync(stream.fileno())
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise FirmwareRepositoryError(f"Firmware HTTPS download failed: {type(exc).__name__}") from exc


class FirmwareRepository:
    """Concurrent-safe local cache; catalog evidence is stored separately from binary objects."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.objects = root / "objects"
        self.metadata = root / "metadata"
        self.catalogs = root / "catalogs"
        self.locks = root / "locks"

    def initialize(self) -> None:
        for path in (self.objects, self.metadata, self.catalogs, self.locks):
            path.mkdir(parents=True, exist_ok=True)

    def object_path(self, digest: str) -> Path:
        normalized = digest.lower()
        if not _SHA256.fullmatch(normalized):
            raise FirmwareRepositoryError("Invalid firmware object SHA256")
        return self.objects / normalized[:2] / normalized

    def ingest(self, source: Path, metadata: FirmwarePackageMetadata) -> Path:
        metadata.validate()
        if source.is_symlink() or not source.resolve(strict=True).is_file():
            raise FirmwareRepositoryError("Firmware source must be a regular non-symlink file")
        actual = sha256_file(source)
        if actual != metadata.sha256.lower():
            raise FirmwareRepositoryError("Firmware package checksum does not match metadata")
        if metadata.size_bytes and source.stat().st_size != metadata.size_bytes:
            raise FirmwareRepositoryError("Firmware package size does not match metadata")
        self.initialize()
        with _RepositoryLock(self.root / ".repository.lock"):
            destination = self.object_path(actual)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                if sha256_file(destination) != actual:
                    raise FirmwareRepositoryError("Cached firmware object is corrupted")
            else:
                descriptor, temporary_name = tempfile.mkstemp(prefix=actual + ".", suffix=".partial", dir=destination.parent)
                os.close(descriptor)
                temporary = Path(temporary_name)
                try:
                    shutil.copyfile(source, temporary)
                    if sha256_file(temporary) != actual:
                        raise FirmwareRepositoryError("Copied firmware checksum verification failed")
                    temporary.replace(destination)
                finally:
                    if temporary.exists():
                        temporary.unlink()
            normalized_metadata = metadata.to_dict() | {
                "sha256": actual,
                "size_bytes": source.stat().st_size,
                "cached_at_utc": datetime.now(timezone.utc).isoformat(),
                "cache_object": str(destination.relative_to(self.root)),
                "cache_does_not_imply_current_or_applicable": True,
            }
            _atomic_json(self.metadata / f"{actual}.json", normalized_metadata)
        return destination

    def verify(self, digest: str) -> Path:
        path = self.object_path(digest)
        if not path.is_file() or sha256_file(path) != digest.lower():
            raise FirmwareRepositoryError("Firmware object is missing or checksum-invalid")
        return path

    def get_metadata(self, digest: str) -> FirmwarePackageMetadata:
        path = self.metadata / f"{digest.lower()}.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        accepted = {item.name for item in fields(FirmwarePackageMetadata)}
        return FirmwarePackageMetadata.from_dict({key: value for key, value in payload.items() if key in accepted})

    def find_candidates(self, *, vendor: str, component: str) -> list[FirmwarePackageMetadata]:
        if not self.metadata.exists():
            return []
        records: list[FirmwarePackageMetadata] = []
        for path in sorted(self.metadata.glob("*.json")):
            try:
                record = self.get_metadata(path.stem)
            except (OSError, ValueError, TypeError, json.JSONDecodeError, FirmwareRepositoryError):
                continue
            if record.vendor.upper() == vendor.upper() and record.component.upper() == component.upper():
                records.append(record)
        return records

    def record_catalog(self, evidence: CatalogEvidence) -> Path:
        self.initialize()
        safe_id = re.sub(r"[^A-Za-z0-9._-]+", "_", evidence.catalog_id).strip("._")
        if not safe_id:
            raise FirmwareRepositoryError("Catalog ID is invalid")
        destination = self.catalogs / f"{safe_id}.json"
        if destination.exists():
            existing = json.loads(destination.read_text(encoding="utf-8"))
            if existing != evidence.to_dict():
                raise FirmwareRepositoryError("Catalog ID already exists with different content")
            return destination
        _atomic_json(destination, evidence.to_dict())
        return destination

    def fetch_if_missing(
        self,
        metadata: FirmwarePackageMetadata,
        *,
        downloader: PackageDownloader,
    ) -> tuple[Path, str]:
        if not metadata.source_url.lower().startswith("https://"):
            raise FirmwareRepositoryError("Firmware download requires an explicit HTTPS source URL")
        self.initialize()
        # Lock by expected content digest and re-check inside the lock. This is a
        # single-flight download: concurrent runners wait and reuse the verified
        # object instead of each fetching the same package independently.
        with _RepositoryLock(
            self.locks / f"download-{metadata.sha256.lower()}.lock",
            timeout_seconds=600.0,
            stale_seconds=4 * 60 * 60,
        ):
            try:
                return self.verify(metadata.sha256), "CACHE_HIT_CHECKSUM_VERIFIED"
            except FirmwareRepositoryError:
                pass
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f"firmware-download-{metadata.sha256.lower()}.",
                suffix=".partial",
                dir=self.root,
            )
            os.close(descriptor)
            temporary = Path(temporary_name)
            try:
                downloader.download(metadata.source_url, temporary)
                return self.ingest(temporary, metadata), "DOWNLOADED_AND_CHECKSUM_VERIFIED"
            finally:
                if temporary.exists():
                    temporary.unlink()


@dataclass(frozen=True)
class RunFirmwareTarget:
    """Immutable firmware selection for one component in one production RUN."""

    component: str
    version: str
    package_sha256: str
    package_filename: str
    catalog_id: str
    source_url: str
    locked_at_utc: str = ""

    def validate(self) -> None:
        if not self.component or not self.version or not self.catalog_id:
            raise FirmwareRepositoryError("Run target requires component, version, and catalog evidence")
        if not _SHA256.fullmatch(self.package_sha256.lower()):
            raise FirmwareRepositoryError("Run target contains an invalid package SHA256")
        if Path(self.package_filename).name != self.package_filename or not self.package_filename:
            raise FirmwareRepositoryError("Run target package filename must be a plain filename")
        parsed = urlparse(self.source_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise FirmwareRepositoryError("Run target source must be credential-free HTTPS")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RunFirmwareTargetStore:
    """Persists a target once so a changing catalog cannot alter an active RUN."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def lock(self, run_id: str, target: RunFirmwareTarget) -> dict[str, Any]:
        target.validate()
        safe_run = re.sub(r"[^A-Za-z0-9._-]+", "_", str(run_id)).strip("._")
        safe_component = re.sub(r"[^A-Za-z0-9._-]+", "_", target.component).strip("._").upper()
        if not safe_run or not safe_component:
            raise FirmwareRepositoryError("RUN_ID or component cannot be represented safely")
        run_root = self.root / safe_run
        run_root.mkdir(parents=True, exist_ok=True)
        destination = run_root / f"{safe_component}.json"
        with _RepositoryLock(run_root / f".{safe_component}.lock"):
            if destination.exists():
                existing = json.loads(destination.read_text(encoding="utf-8"))
                proposed = target.to_dict()
                bookkeeping = {"locked_at_utc", "run_id", "immutable_for_run"}
                comparable_existing = {key: value for key, value in existing.items() if key not in bookkeeping}
                comparable_proposed = {key: value for key, value in proposed.items() if key not in bookkeeping}
                if comparable_existing != comparable_proposed:
                    raise FirmwareRepositoryError(
                        "Firmware target is already locked for this RUN_ID/component and cannot change"
                    )
                return existing
            payload = target.to_dict()
            payload["locked_at_utc"] = target.locked_at_utc or datetime.now(timezone.utc).isoformat()
            payload["run_id"] = str(run_id)
            payload["immutable_for_run"] = True
            _atomic_json(destination, payload)
            return payload


class _RepositoryLock:
    def __init__(self, path: Path, timeout_seconds: float = 10.0, stale_seconds: float = 300.0) -> None:
        self.path = path
        self.timeout_seconds = timeout_seconds
        self.stale_seconds = stale_seconds
        self.descriptor: int | None = None

    def __enter__(self) -> "_RepositoryLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                self.descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(self.descriptor, str(os.getpid()).encode("ascii"))
                return self
            except (FileExistsError, PermissionError):
                # Windows can report ERROR_ACCESS_DENIED instead of
                # FileExistsError when another thread owns the O_EXCL lock
                # inode.  Treat that equivalent race as lock contention, not
                # as a repository failure; a genuine timeout still produces
                # the deterministic lock error below.
                try:
                    if time.time() - self.path.stat().st_mtime > self.stale_seconds:
                        self.path.unlink()
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() >= deadline:
                    raise FirmwareRepositoryError("Timed out waiting for firmware repository lock")
                time.sleep(0.05)

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


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
