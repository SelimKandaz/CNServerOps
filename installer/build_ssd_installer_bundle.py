#!/usr/bin/env python3
"""Build a portable, offline-capable CNServerOps SSD installer bundle.

The bundle contains a verified immutable runtime and a clean Linux rootfs
archive.  It never reads or copies a live production SSD.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Any

try:
    from .cnserverops_ssd_installer import INSTALLER_VERSION, InstallerError, sha256_file, verify_runtime_package
except ImportError:  # direct execution: python3 installer/build_ssd_installer_bundle.py
    from cnserverops_ssd_installer import INSTALLER_VERSION, InstallerError, sha256_file, verify_runtime_package


def _sha256(path: Path) -> str:
    return sha256_file(path)


def _tar_info(source: Path, name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = source.stat().st_size
    info.mode = 0o755 if source.suffix == ".sh" else 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    return info


def _add_file(archive: tarfile.TarFile, source: Path, name: str) -> None:
    with source.open("rb") as stream:
        archive.addfile(_tar_info(source, name), stream)


def build_bundle(
    *,
    installer_dir: Path,
    runtime_package: Path,
    rootfs_tar: Path,
    output: Path,
    installer_version: str = INSTALLER_VERSION,
) -> dict[str, Any]:
    installer_dir = installer_dir.resolve(strict=True)
    runtime_package = runtime_package.resolve(strict=True)
    rootfs_tar = rootfs_tar.resolve(strict=True)
    output = output.resolve()
    receipt = verify_runtime_package(runtime_package)
    if not rootfs_tar.is_file():
        raise InstallerError("ROOTFS_ARCHIVE_NOT_FOUND")
    suffixes = rootfs_tar.suffixes
    if suffixes[-2:] in ([".tar", ".gz"], [".tar", ".xz"], [".tar", ".bz2"]):
        root_name = "payload/rootfs" + "".join(suffixes[-2:])
    elif suffixes[-1:] == [".tar"]:
        root_name = "payload/rootfs.tar"
    else:
        raise InstallerError("ROOTFS_ARCHIVE_MUST_BE_TAR_OR_COMPRESSED_TAR")
    required = {
        "installer/cnserverops-ssd-setup.sh": installer_dir / "cnserverops-ssd-setup.sh",
        "installer/cnserverops_ssd_installer.py": installer_dir / "cnserverops_ssd_installer.py",
        "installer/build_ssd_installer_bundle.py": installer_dir / "build_ssd_installer_bundle.py",
        "installer/README.md": installer_dir / "README.md",
        "payload/runtime.tar.gz": runtime_package,
        root_name: rootfs_tar,
    }
    for name, source in required.items():
        if not source.is_file():
            raise InstallerError(f"BUNDLE_MEMBER_MISSING:{name}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cnserverops-bundle-") as temp_dir:
        staging = Path(temp_dir)
        staged_runtime = staging / "runtime.tar.gz"
        shutil.copyfile(runtime_package, staged_runtime)
        staged_sidecar = runtime_package.with_suffix(runtime_package.suffix + ".json")
        if staged_sidecar.is_file():
            shutil.copyfile(staged_sidecar, staging / "runtime.tar.gz.json")
        elif not (staging / "runtime.tar.gz.json").exists():
            (staging / "runtime.tar.gz.json").write_text(
                json.dumps({"package_sha256": receipt["package_sha256"], "runtime_version": receipt["runtime_version"]}, indent=2) + "\n",
                encoding="utf-8",
            )
        members = {
            "installer/cnserverops-ssd-setup.sh": installer_dir / "cnserverops-ssd-setup.sh",
            "installer/cnserverops_ssd_installer.py": installer_dir / "cnserverops_ssd_installer.py",
            "installer/build_ssd_installer_bundle.py": installer_dir / "build_ssd_installer_bundle.py",
            "installer/README.md": installer_dir / "README.md",
            "payload/runtime.tar.gz": staged_runtime,
            "payload/runtime.tar.gz.json": staging / "runtime.tar.gz.json",
        }
        members[root_name] = rootfs_tar
        manifest: dict[str, Any] = {
            "schema_version": 1,
            "immutable": True,
            "bundle_type": "CNSERVEROPS_SSD_INSTALLER",
            "installer_version": installer_version,
            "runtime_version": receipt["runtime_version"],
            "runtime_package_sha256": receipt["package_sha256"],
            "rootfs_member": root_name,
            "created_at_utc": _datetime.datetime.now(_datetime.timezone.utc).isoformat(),
            "files": {},
        }
        for name, source in sorted(members.items()):
            manifest["files"][name] = _sha256(source)
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        temporary = output.with_suffix(output.suffix + ".tmp")
        with tarfile.open(temporary, "w:gz", compresslevel=9) as archive:
            for name, source in sorted(members.items()):
                _add_file(archive, source, name)
            info = tarfile.TarInfo("bundle-manifest.json")
            info.size = len(manifest_bytes)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            archive.addfile(info, __import__("io").BytesIO(manifest_bytes))
        os.replace(temporary, output)
    result = {
        "status": "PASS",
        "bundle": str(output),
        "bundle_sha256": _sha256(output),
        "installer_version": installer_version,
        "runtime_version": receipt["runtime_version"],
        "runtime_package_sha256": receipt["package_sha256"],
        "rootfs_member": root_name,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    output.with_suffix(output.suffix + ".json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-package", type=Path, required=True)
    parser.add_argument("--rootfs-tar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--installer-version", default=INSTALLER_VERSION)
    args = parser.parse_args()
    try:
        print(json.dumps(build_bundle(installer_dir=Path(__file__).parent, runtime_package=args.runtime_package, rootfs_tar=args.rootfs_tar, output=args.output, installer_version=args.installer_version), indent=2, sort_keys=True))
        return 0
    except InstallerError as exc:
        print(f"FAIL: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
