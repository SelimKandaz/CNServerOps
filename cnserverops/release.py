"""Versioned runtime release staging for existing CNServerOps SSDs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from .models import utc_now
from .runner import RunnerIdentityError, load_runner, update_runtime_version


class ReleaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReleaseApproval:
    authorized: bool
    approval_id: str
    runner_id: str

    def require(self) -> None:
        if not self.authorized or not self.approval_id or not self.runner_id:
            raise ReleaseError("Runtime release activation requires explicit runner-bound approval")


class RuntimeReleaseManager:
    """Stage immutable versions; activation changes only an atomic current pointer."""

    def __init__(self, root: Path, *, config_root: Path) -> None:
        self.root = root
        self.releases = root / "releases"
        self.backups = root / "pointer-backups"
        self.current_pointer = root / "current.json"
        # Field SSDs predating the JSON pointer use this symlink as the
        # authoritative runtime selector.  Keep supporting it explicitly: a
        # release must never be marked active in metadata while the console
        # still imports the previous target through ``/opt/cnserverops/current``.
        self.current_link = root / "current"
        self.config_root = config_root

    def stage(
        self,
        package: Path,
        *,
        expected_package_sha256: str,
        self_test: Callable[[Path], bool],
    ) -> dict[str, Any]:
        if package.is_symlink() or not package.resolve(strict=True).is_file():
            raise ReleaseError("Release package must be a regular non-symlink file")
        package_hash = _sha256(package)
        if package_hash != expected_package_sha256.lower():
            raise ReleaseError("Release package SHA256 mismatch")
        members = _read_release_members(package)
        try:
            manifest = json.loads(members.pop("release-manifest.json"))
        except (KeyError, json.JSONDecodeError) as exc:
            raise ReleaseError("Release manifest is missing or malformed") from exc
        if not isinstance(manifest, Mapping):
            raise ReleaseError("Release manifest is malformed")
        version = str(manifest.get("version") or "")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version):
            raise ReleaseError("Release version is invalid")
        files = manifest.get("files")
        if not isinstance(files, Mapping) or not files:
            raise ReleaseError("Release manifest has no files")
        expected_members = {str(_safe_archive_path(str(name))) for name in files}
        unexpected_members = sorted(set(members) - expected_members)
        if unexpected_members:
            raise ReleaseError(
                "Release archive contains members outside its manifest: "
                + ", ".join(unexpected_members[:5])
            )
        if "cnserverops/__init__.py" in members:
            init_member = members["cnserverops/__init__.py"]
            version_match = re.search(
                rb'^__version__\s*=\s*["\']([^"\']+)["\']',
                init_member,
                re.MULTILINE,
            )
            if not version_match or version_match.group(1).decode("utf-8", errors="replace") != version:
                raise ReleaseError("Release manifest version does not match cnserverops runtime version")
        stage_parent = self.root / ".staging"
        stage_parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=f"{version}.", dir=stage_parent))
        try:
            for name, expected in files.items():
                safe = _safe_archive_path(str(name))
                try:
                    data = members[str(safe)]
                except KeyError as exc:
                    raise ReleaseError(f"Release member is missing: {name}") from exc
                digest = hashlib.sha256(data).hexdigest()
                if digest != str(expected).lower():
                    raise ReleaseError(f"Release file checksum mismatch: {name}")
                destination = temporary.joinpath(*safe.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                # ``tarfile`` member metadata is intentionally not trusted
                # during staging.  Apply the small allowlist of runtime modes
                # ourselves so packaged launcher scripts remain directly
                # executable while units, JSON, and Python modules stay data.
                os.chmod(destination, _runtime_member_mode(safe))
            (temporary / "release-manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            if not self_test(temporary):
                raise ReleaseError("Staged runtime self-test failed")
            # A self-test must be observational.  Letting it leave bytecode,
            # logs, or generated configuration in the staged tree would mean
            # the activated release no longer matches the signed manifest.
            staged_files = {
                path.relative_to(temporary).as_posix()
                for path in temporary.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            allowed_staged_files = expected_members | {"release-manifest.json"}
            unexpected_staged = sorted(staged_files - allowed_staged_files)
            if unexpected_staged:
                raise ReleaseError(
                    "Staged runtime self-test wrote unexpected files: "
                    + ", ".join(unexpected_staged[:5])
                )
            destination = self.releases / version
            self.releases.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                if _tree_manifest(destination, files.keys()) != {str(key): str(value).lower() for key, value in files.items()}:
                    raise ReleaseError("Release version already exists with different content")
                shutil.rmtree(temporary)
            else:
                temporary.replace(destination)
            return {
                "status": "STAGED",
                "version": version,
                "package_sha256": package_hash,
                "release_path": str(destination.resolve()),
                "config_root_preserved": str(self.config_root.resolve()),
                "self_test": "PASS",
            }
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    def activate(self, staged: Mapping[str, Any], *, approval: ReleaseApproval) -> dict[str, Any]:
        approval.require()
        version = str(staged.get("version") or "")
        release_path = self.releases / version
        if staged.get("status") != "STAGED" or not release_path.is_dir():
            raise ReleaseError("Release must be successfully staged before activation")
        runner_path = self.config_root / "runner.json"
        runner_original: bytes | None = None
        if runner_path.exists():
            try:
                runner = load_runner(runner_path)
            except (OSError, ValueError, json.JSONDecodeError, RunnerIdentityError) as exc:
                raise ReleaseError("Runner configuration is invalid; refusing runtime activation") from exc
            if str(runner.get("runner_id") or "") != approval.runner_id:
                raise ReleaseError("Runtime activation approval is bound to a different runner")
            # Preserve a byte-for-byte rollback copy in case an unexpected
            # pointer write fails after this normal metadata refresh.
            runner_original = runner_path.read_bytes()
        previous: dict[str, Any] | None = None
        if self.current_pointer.exists():
            try:
                parsed = json.loads(self.current_pointer.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise ReleaseError("Existing runtime pointer is malformed") from exc
            if not isinstance(parsed, Mapping):
                raise ReleaseError("Existing runtime pointer is malformed")
            previous = dict(parsed)
            self.backups.mkdir(parents=True, exist_ok=True)
            backup = self.backups / f"current-{utc_now().replace(':', '').replace('+', '_')}.json"
            _atomic_json(backup, previous)
        previous_link = self._legacy_current_link_target()
        if previous_link is not None:
            self.backups.mkdir(parents=True, exist_ok=True)
            link_backup = self.backups / f"current-link-{utc_now().replace(':', '').replace('+', '_')}.json"
            _atomic_json(
                link_backup,
                {
                    "schema_version": 1,
                    "pointer_backend": "SYMLINK",
                    "release_path": str(previous_link),
                    "version": previous_link.name,
                    "captured_at_utc": utc_now(),
                },
            )
        previous_version = str((previous or {}).get("version") or (previous_link.name if previous_link else ""))
        pointer = {
            "schema_version": 1,
            "version": version,
            "release_path": str(release_path.resolve()),
            "config_root": str(self.config_root.resolve()),
            "runner_id": approval.runner_id,
            "approval_id": approval.approval_id,
            "activated_at_utc": utc_now(),
            "previous_version": previous_version,
            "pointer_backend": "SYMLINK_AND_JSON" if previous_link is not None else "JSON_ONLY",
        }
        try:
            if runner_path.exists():
                update_runtime_version(
                    runner_path,
                    runner_id=approval.runner_id,
                    runtime_version=version,
                )
            if previous_link is not None:
                self._replace_current_link(release_path)
            _atomic_json(self.current_pointer, pointer)
        except Exception:
            if runner_path.exists() and runner_original is not None:
                _atomic_bytes(runner_path, runner_original)
            raise
        return {
            "status": "READY",
            "pointer": pointer,
            "rollback_pointer_preserved": previous is not None or previous_link is not None,
            "runner_runtime_metadata": "UPDATED" if runner_path.exists() else "NOT_CONFIGURED",
        }

    def _legacy_current_link_target(self) -> Path | None:
        """Return the safe old-style symlink target, if this SSD uses one."""
        if self.current_link.is_symlink():
            try:
                target = self.current_link.resolve(strict=True)
            except OSError as exc:
                raise ReleaseError("Existing runtime symlink target is unavailable") from exc
            if not target.is_dir() or not _is_within(target, self.releases):
                raise ReleaseError("Existing runtime symlink target is outside managed releases")
            return target
        if self.current_link.exists():
            # A real directory at ``current`` cannot be atomically swapped
            # without deleting it.  Refuse rather than risking a live runtime.
            raise ReleaseError("Existing runtime selector is not an atomic symlink")
        return None

    def _replace_current_link(self, release_path: Path) -> None:
        """Atomically switch the legacy runtime symlink after staging passed."""
        if not self.current_link.is_symlink():
            raise ReleaseError("Legacy runtime symlink disappeared before activation")
        temporary = self.root / f".current-{release_path.name}-{os.getpid()}.tmp"
        try:
            if temporary.exists() or temporary.is_symlink():
                temporary.unlink()
            os.symlink(str(release_path.resolve()), temporary, target_is_directory=True)
            os.replace(temporary, self.current_link)
        finally:
            if temporary.exists() or temporary.is_symlink():
                temporary.unlink()


def _safe_archive_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.name == "release-manifest.json":
        raise ReleaseError(f"Unsafe release archive path: {value}")
    return path


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _runtime_member_mode(path: PurePosixPath) -> int:
    executable_names = {"cnserverops-console", "cnserverops-launcher-rollback"}
    return 0o755 if path.suffix == ".sh" or path.name in executable_names else 0o644


def _read_release_members(package: Path) -> dict[str, bytes]:
    """Read a credential-free release archive without unsafe extraction.

    Existing field packages are deterministic ``.tar.gz`` files while older
    developer tooling produced ZIPs.  Staging accepts both formats, validates
    every member name, and never follows archive links.
    """
    members: dict[str, bytes] = {}
    if zipfile.is_zipfile(package):
        with zipfile.ZipFile(package) as archive:
            for info in archive.infolist():
                name = info.filename
                if name == "release-manifest.json":
                    if info.is_dir():
                        raise ReleaseError("Release manifest is not a regular file")
                else:
                    _safe_archive_path(name)
                if info.is_dir():
                    continue
                if name in members:
                    raise ReleaseError("Release archive contains duplicate members")
                members[name] = archive.read(info)
        return members
    if not tarfile.is_tarfile(package):
        raise ReleaseError("Release package is neither a supported tar archive nor ZIP archive")
    with tarfile.open(package, mode="r:*") as archive:
        for info in archive.getmembers():
            name = info.name
            if name == "release-manifest.json":
                pass
            else:
                _safe_archive_path(name)
            if info.isdir():
                continue
            if not info.isfile():
                raise ReleaseError("Release archive contains non-regular member")
            if name in members:
                raise ReleaseError("Release archive contains duplicate members")
            stream = archive.extractfile(info)
            if stream is None:
                raise ReleaseError("Release archive member cannot be read")
            members[name] = stream.read()
    return members


def _tree_manifest(root: Path, names: Any) -> dict[str, str]:
    return {str(name): _sha256(root.joinpath(*PurePosixPath(str(name)).parts)) for name in names}


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


def _atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
