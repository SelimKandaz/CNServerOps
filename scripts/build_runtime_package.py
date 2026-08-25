#!/usr/bin/env python3
"""Build a deterministic, credential-free immutable CNServerOps runtime tarball."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path
from pathlib import PurePosixPath


ROOTS = ("cnserverops", "cndellops_asus", "config", "deployment")
FILES = ("README.md",)
REQUIRED_MEMBERS = frozenset(
    {
        "cnserverops/production.py",
        "cnserverops/firmware_lifecycle.py",
        "cnserverops/bmc_recovery.py",
        "cnserverops/bmc_handoff.py",
        "cnserverops/clone_firstboot.py",
        "cnserverops/operator_console.py",
        "cnserverops/runtime_preflight.py",
        "deployment/linux/cnserverops-firmware-resume.service",
        "deployment/linux/cnserverops-firmware-resume-retry.service",
        "deployment/linux/cnserverops-firmware-resume-retry.timer",
        "deployment/linux/cnserverops-clone-firstboot.service",
        "deployment/linux/cnserverops-sync-retry.service",
        "deployment/linux/cnserverops-sync-retry.timer",
        "deployment/linux/install-production-launcher.sh",
    }
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def runtime_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for name in ROOTS:
        base = root / name
        paths.extend(
            path
            for path in base.rglob("*")
            if path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        )
    paths.extend(root / name for name in FILES)
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix())


def normalized_info(path: Path, archive_name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(archive_name)
    info.size = path.stat().st_size
    info.mode = 0o755 if path.suffix in {".sh"} or path.name in {"cnserverops-console", "cnserverops-launcher-rollback"} else 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = 0
    return info


def verify_package(
    package: Path,
    *,
    expected_version: str,
    expected_files: dict[str, str] | None = None,
) -> dict[str, object]:
    """Re-open a finished tarball and verify its immutable contents.

    The package is treated as untrusted after writing: the manifest, member
    set, regular-file types, and every content hash are checked from the
    compressed archive itself.  This makes the receipt a proof of the bytes
    that will actually be deployed, rather than only of the source tree.
    """
    expected_files = dict(expected_files or {})
    with tarfile.open(package, mode="r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise RuntimeError("runtime package contains duplicate members")
        if "release-manifest.json" not in names:
            raise RuntimeError("runtime package is missing release-manifest.json")
        for member in members:
            parsed = PurePosixPath(member.name)
            if parsed.is_absolute() or ".." in parsed.parts:
                raise RuntimeError(f"runtime package contains unsafe member: {member.name}")
            if not member.isfile():
                raise RuntimeError(f"runtime package member is not a regular file: {member.name}")
        manifest_member = archive.getmember("release-manifest.json")
        raw_manifest = archive.extractfile(manifest_member)
        if raw_manifest is None:
            raise RuntimeError("runtime package manifest cannot be read")
        try:
            manifest = json.loads(raw_manifest.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("runtime package manifest is invalid JSON") from exc
        if not isinstance(manifest, dict) or str(manifest.get("version") or "") != expected_version:
            raise RuntimeError("runtime package manifest version mismatch")
        if manifest.get("schema_version") != 1 or manifest.get("immutable") is not True:
            raise RuntimeError("runtime package manifest is not immutable schema version 1")
        manifest_files = manifest.get("files")
        if not isinstance(manifest_files, dict) or not manifest_files:
            raise RuntimeError("runtime package manifest has no file hashes")
        archive_files = {name for name in names if name != "release-manifest.json"}
        manifest_names = {str(name) for name in manifest_files}
        if archive_files != manifest_names:
            raise RuntimeError("runtime package member set does not match release manifest")
        missing_required = sorted(REQUIRED_MEMBERS - archive_files)
        if missing_required:
            raise RuntimeError(
                "runtime package is missing required production members: " + ", ".join(missing_required)
            )
        if expected_files and manifest_files != expected_files:
            raise RuntimeError("runtime package manifest does not match source hashes")
        verified = 0
        for name in sorted(manifest_names):
            member = archive.getmember(name)
            stream = archive.extractfile(member)
            if stream is None:
                raise RuntimeError(f"runtime package member cannot be read: {name}")
            digest = sha256_bytes(stream.read())
            if digest != str(manifest_files[name]):
                raise RuntimeError(f"runtime package hash mismatch: {name}")
            verified += 1
        init_member = archive.getmember("cnserverops/__init__.py")
        init_stream = archive.extractfile(init_member)
        if init_stream is None:
            raise RuntimeError("runtime package runtime version module cannot be read")
        init_match = re.search(
            rb'^__version__\s*=\s*["\']([^"\']+)["\']',
            init_stream.read(),
            re.MULTILINE,
        )
        if not init_match or init_match.group(1).decode("utf-8", errors="replace") != expected_version:
            raise RuntimeError("runtime package manifest version does not match cnserverops runtime version")
    return {
        "status": "PASS",
        "version": expected_version,
        "members": verified,
        "manifest_sha256": sha256_file_bytes(package, member_name="release-manifest.json"),
    }


def sha256_file_bytes(package: Path, *, member_name: str) -> str:
    """Hash one archive member's finalized bytes for validation receipts."""
    with tarfile.open(package, mode="r:gz") as archive:
        member = archive.getmember(member_name)
        stream = archive.extractfile(member)
        if stream is None:
            raise RuntimeError(f"archive member cannot be read: {member_name}")
        return sha256_bytes(stream.read())


def build(root: Path, destination: Path, version: str) -> dict[str, object]:
    if destination.exists():
        raise FileExistsError(f"immutable package already exists: {destination}")
    files = runtime_files(root)
    if not files:
        raise RuntimeError("runtime package contains no files")
    member_names = {path.relative_to(root).as_posix() for path in files}
    missing = sorted(REQUIRED_MEMBERS - member_names)
    if missing:
        raise RuntimeError(f"runtime package is missing required production members: {', '.join(missing)}")
    member_hashes = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in files
    }
    manifest = {
        "schema_version": 1,
        "version": version,
        "immutable": True,
        "files": member_hashes,
        "excluded": ["tests", "outputs", "evidence", "dist", "credentials", "runtime state"],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for path in files:
                    name = path.relative_to(root).as_posix()
                    with path.open("rb") as stream:
                        archive.addfile(normalized_info(path, name), stream)
                info = tarfile.TarInfo("release-manifest.json")
                info.size = len(manifest_bytes)
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                archive.addfile(info, io.BytesIO(manifest_bytes))
    # Verify the compressed package after the writer has fully closed it and
    # before calculating the deploy receipt/hash.
    package_validation = verify_package(
        destination,
        expected_version=version,
        expected_files=member_hashes,
    )
    package_sha = sha256_file(destination)
    receipt = {
        "schema_version": 1,
        "version": version,
        "package": str(destination.resolve()),
        "package_sha256": package_sha,
        "size_bytes": destination.stat().st_size,
        "file_count": len(files),
        "release_manifest_sha256": sha256_bytes(manifest_bytes),
        "package_validation": package_validation,
    }
    receipt_path = destination.with_suffix(destination.suffix + ".json")
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    init_text = (root / "cnserverops" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', init_text, re.MULTILINE)
    if not match or match.group(1) != args.version:
        raise SystemExit("package version does not match cnserverops.__version__")
    print(json.dumps(build(root, args.output, args.version), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
