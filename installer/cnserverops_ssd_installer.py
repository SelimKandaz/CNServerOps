#!/usr/bin/env python3
"""Build and validate a clean CNServerOps boot SSD.

This module is intentionally independent of a live CNServerOps installation.
It consumes only a verified immutable runtime tarball and (for a physical
install) an explicit Linux rootfs archive.  Disk discovery and destructive
operations are kept here so the shell wrapper cannot accidentally select a
device by position or hostname.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


INSTALLER_VERSION = "1.0.0"
DEFAULT_CENTRAL_ENDPOINT = "https://10.1.10.51:8088"
DEFAULT_RUNTIME_PACKAGE = "payload/runtime.tar.gz"
DEFAULT_ROOTFS_GLOBS = ("payload/rootfs.tar", "payload/rootfs.tar.gz", "payload/rootfs.tar.xz")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$")
_STATIC_DEVELOPMENT_VALUES = (
    "10.1.10.155",
    "10.1.10.140",
    "10.1.10.145",
    "10.1.10.147",
    "10.1.10.192",
    "172.16.50.244",
    "172.16.50.243",
)
_FORBIDDEN_RELATIVE_FILES = (
    "etc/cnserverops/runner.json",
    "etc/cnserverops/clone-template.consumed.json",
    "etc/cnserverops/firmware-current-proof.json",
    "etc/cnserverops/secrets/asus-bmc-password",
    "etc/cnserverops/secrets/asus-bmc-password.binding.json",
    "var/lib/cnserverops/firmware-pending.json",
    "var/lib/cnserverops/firmware-inflight.json",
    "var/lib/cnserverops/bmc-auth-change-state.json",
    "var/lib/cnserverops/personalization-receipt.json",
    "var/lib/cnserverops/personalization-transaction.json",
    "var/lib/cnserverops/personalization.lock",
    "opt/cnserverops/current.json",
)
_FORBIDDEN_RELATIVE_DIRS = (
    "CN_STRESS_RESULTS/runs",
    "CN_STRESS_RESULTS/firmware-runs",
    "var/lib/cnserverops/quarantine",
    "var/lib/cnserverops/template-quarantine",
)
# Paths accepted by the existing marker-gated clone-firstboot scrubber.  Do
# not put marker/transaction/receipt paths here: personalization protects
# those paths while it is running and rejects them as unsafe input.
_CLONE_STALE_STATE_PATHS = (
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
    "CN_STRESS_RESULTS/enrollment/latest.json",
    "CN_STRESS_RESULTS/firmware-diagnostics/update-service-action-info.json",
    "CN_STRESS_RESULTS/central-sync.sqlite3",
    "opt/cnserverops/current.json",
)
_REQUIRED_UNITS = (
    "cnserverops-console.service",
    "cnserverops-firmware-resume.service",
    "cnserverops-firmware-resume-retry.service",
    "cnserverops-firmware-resume-retry.timer",
    "cnserverops-clone-firstboot.service",
    "cnserverops-sync-retry.service",
    "cnserverops-sync-retry.timer",
)


class InstallerError(RuntimeError):
    """A safe, actionable installer failure."""


def utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_write(path: Path, value: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
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


def atomic_json(path: Path, payload: Mapping[str, Any], *, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(dict(payload), indent=2, sort_keys=True) + "\n", mode=mode)


@dataclass(frozen=True)
class DiskInfo:
    path: str
    name: str
    type: str
    model: str = ""
    serial: str = ""
    size_bytes: int = 0
    removable: bool = False
    read_only: bool = False
    mountpoints: tuple[str, ...] = ()
    children: tuple["DiskInfo", ...] = field(default_factory=tuple)

    @property
    def mounted(self) -> bool:
        return bool(self.mountpoints) or any(child.mounted for child in self.children)

    def display(self) -> str:
        capacity = _human_size(self.size_bytes)
        mounts = ",".join(self.mountpoints) or "-"
        return (
            f"{self.path}  model={self.model or '-'}  serial={self.serial or '-'}  "
            f"size={capacity}  removable={'yes' if self.removable else 'no'}  "
            f"readonly={'yes' if self.read_only else 'no'}  mounts={mounts}"
        )


def _human_size(value: int) -> str:
    number = float(max(0, int(value)))
    for suffix in ("B", "GiB", "TiB", "PiB"):
        if number < 1024 or suffix == "PiB":
            return f"{number:.1f}{suffix}" if suffix != "B" else f"{int(number)}B"
        number /= 1024
    return "0B"


def _as_mountpoints(value: Any) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(item) for item in value if str(item or "").strip())
    if value:
        return (str(value),)
    return ()


def _parse_disk_node(node: Mapping[str, Any]) -> DiskInfo:
    children = tuple(_parse_disk_node(item) for item in (node.get("children") or []) if isinstance(item, Mapping))
    path = str(node.get("path") or ("/dev/" + str(node.get("name") or "")))
    return DiskInfo(
        path=path,
        name=str(node.get("name") or Path(path).name),
        type=str(node.get("type") or ""),
        model=str(node.get("model") or "").strip(),
        serial=str(node.get("serial") or "").strip(),
        size_bytes=int(node.get("size") or 0),
        removable=bool(int(node.get("rm") or 0)) if str(node.get("rm") or "").isdigit() else bool(node.get("rm")),
        read_only=bool(int(node.get("ro") or 0)) if str(node.get("ro") or "").isdigit() else bool(node.get("ro")),
        mountpoints=_as_mountpoints(node.get("mountpoints", node.get("mountpoint"))),
        children=children,
    )


def parse_lsblk(payload: Mapping[str, Any]) -> list[DiskInfo]:
    blockdevices = payload.get("blockdevices") if isinstance(payload, Mapping) else None
    if not isinstance(blockdevices, list):
        raise InstallerError("LSBLK_JSON_INVALID")
    disks = [_parse_disk_node(item) for item in blockdevices if isinstance(item, Mapping) and str(item.get("type")) == "disk"]
    return disks


def run_capture(command: Sequence[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallerError(f"COMMAND_FAILED_TO_START:{command[0]}") from exc


def host_lsblk() -> list[DiskInfo]:
    result = run_capture(
        ("lsblk", "-J", "-b", "-o", "PATH,NAME,TYPE,MODEL,SERIAL,SIZE,RM,RO,MOUNTPOINTS,PKNAME"),
    )
    if result.returncode != 0:
        raise InstallerError("LSBLK_DISCOVERY_FAILED")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise InstallerError("LSBLK_JSON_INVALID") from exc
    return parse_lsblk(payload)


def _find_disk_containing(device: str, disks: Sequence[DiskInfo]) -> str:
    candidate = str(device).strip()
    visited: set[str] = set()
    def walk(node: DiskInfo) -> str | None:
        if node.path == candidate:
            return node.path
        for child in node.children:
            found = walk(child)
            if found:
                return node.path if node.type == "disk" else found
        return None
    for disk in disks:
        found = walk(disk)
        if found:
            return found
    # Fallback to basename/parent discovery for mapper paths when lsblk
    # omitted the source node from JSON.
    while candidate not in visited:
        visited.add(candidate)
        result = run_capture(("lsblk", "-ndo", "PKNAME", candidate), timeout=15)
        parent = result.stdout.strip() if result.returncode == 0 else ""
        if not parent:
            break
        candidate = "/dev/" + parent
        for disk in disks:
            if disk.path == candidate:
                return disk.path
    return ""


def root_disk(disks: Sequence[DiskInfo]) -> str:
    result = run_capture(("findmnt", "-n", "-o", "SOURCE", "/"), timeout=15)
    if result.returncode != 0 or not result.stdout.strip():
        raise InstallerError("ROOT_SYSTEM_DISK_UNAVAILABLE")
    found = _find_disk_containing(result.stdout.strip(), disks)
    if not found:
        raise InstallerError("ROOT_SYSTEM_DISK_UNRESOLVED")
    return found


def path_disk(path: Path, disks: Sequence[DiskInfo]) -> str:
    result = run_capture(("findmnt", "-n", "-o", "SOURCE", "--target", str(path)), timeout=15)
    if result.returncode != 0:
        return ""
    return _find_disk_containing(result.stdout.strip(), disks)


def guard_target(
    target: str,
    disks: Sequence[DiskInfo],
    *,
    system_disk: str,
    source_disks: Iterable[str] = (),
) -> DiskInfo:
    normalized = str(target).strip()
    matches = [disk for disk in disks if disk.path == normalized]
    if len(matches) != 1:
        raise InstallerError("TARGET_MUST_BE_ONE_EXACT_WHOLE_DISK")
    disk = matches[0]
    if disk.type != "disk":
        raise InstallerError("TARGET_IS_NOT_A_WHOLE_DISK")
    if disk.path == system_disk:
        raise InstallerError("TARGET_IS_CURRENT_LINUX_SYSTEM_DISK")
    if disk.path in set(source_disks):
        raise InstallerError("TARGET_CONTAINS_INSTALLER_SOURCE_OR_REPOSITORY")
    if disk.read_only:
        raise InstallerError("TARGET_IS_READ_ONLY")
    if disk.mounted:
        raise InstallerError("TARGET_OR_PARTITION_IS_MOUNTED_OR_IN_USE")
    if not disk.size_bytes:
        raise InstallerError("TARGET_CAPACITY_UNAVAILABLE")
    return disk


def required_host_tools() -> tuple[str, ...]:
    return (
        "lsblk", "findmnt", "wipefs", "sgdisk", "partprobe", "mkfs.vfat", "mkfs.ext4",
        "mount", "umount", "blkid", "grub-install", "tar", "python3",
    )


def check_host_tools() -> dict[str, Any]:
    tools = {name: shutil.which(name) or "" for name in required_host_tools()}
    missing = sorted({name for name, path in tools.items() if not path})
    return {"status": "PASS" if not missing else "MISSING_DEPENDENCIES", "tools": tools, "missing": missing}


def bootstrap_dependencies(*, refresh: bool = False) -> dict[str, Any]:
    """Install builder prerequisites only when the operator explicitly asks.

    This is deliberately Debian/Ubuntu-only and never runs implicitly.  A
    failed apt transaction is surfaced without touching any target disk.
    """
    if os.geteuid() != 0:
        raise InstallerError("ROOT_REQUIRED_FOR_DEPENDENCY_BOOTSTRAP")
    apt = shutil.which("apt-get")
    if not apt:
        raise InstallerError("APT_GET_NOT_AVAILABLE_USE_MANUAL_DEPENDENCY_INSTALL")
    packages = ("gdisk", "dosfstools", "e2fsprogs", "grub-efi-amd64-bin", "util-linux", "tar", "python3")
    if refresh:
        _run_checked((apt, "update"), timeout=900)
    _run_checked((apt, "install", "-y", *packages), timeout=900)
    status = check_host_tools()
    if status["missing"]:
        raise InstallerError("DEPENDENCY_BOOTSTRAP_INCOMPLETE:" + ",".join(status["missing"]))
    return status


def _safe_member(name: str) -> PurePosixPath:
    parsed = PurePosixPath(name)
    if parsed.is_absolute() or ".." in parsed.parts or not parsed.parts:
        raise InstallerError(f"UNSAFE_ARCHIVE_MEMBER:{name}")
    return parsed


def _runtime_manifest_from_package(package: Path) -> tuple[dict[str, Any], list[tarfile.TarInfo]]:
    try:
        with tarfile.open(package, "r:*") as archive:
            members = archive.getmembers()
            names: set[str] = set()
            for member in members:
                parsed = _safe_member(member.name)
                if member.name in names:
                    raise InstallerError("RUNTIME_PACKAGE_DUPLICATE_MEMBER")
                names.add(member.name)
                if not member.isfile():
                    raise InstallerError(f"RUNTIME_PACKAGE_MEMBER_NOT_REGULAR:{member.name}")
            try:
                manifest_member = archive.getmember("release-manifest.json")
            except KeyError as exc:
                raise InstallerError("RUNTIME_PACKAGE_MANIFEST_MISSING") from exc
            stream = archive.extractfile(manifest_member)
            if stream is None:
                raise InstallerError("RUNTIME_PACKAGE_MANIFEST_UNREADABLE")
            manifest = json.loads(stream.read().decode("utf-8"))
            if not isinstance(manifest, dict) or manifest.get("schema_version") != 1 or manifest.get("immutable") is not True:
                raise InstallerError("RUNTIME_PACKAGE_MANIFEST_NOT_IMMUTABLE")
            version = str(manifest.get("version") or "")
            if not _VERSION_RE.fullmatch(version):
                raise InstallerError("RUNTIME_PACKAGE_VERSION_INVALID")
            files = manifest.get("files")
            if not isinstance(files, Mapping) or not files:
                raise InstallerError("RUNTIME_PACKAGE_MANIFEST_FILES_MISSING")
            archive_names = {member.name for member in members if member.name != "release-manifest.json"}
            if archive_names != {str(name) for name in files}:
                raise InstallerError("RUNTIME_PACKAGE_MEMBER_SET_MISMATCH")
            for name, expected in files.items():
                if not _SHA256_RE.fullmatch(str(expected).lower()):
                    raise InstallerError(f"RUNTIME_PACKAGE_HASH_INVALID:{name}")
                member_stream = archive.extractfile(str(name))
                if member_stream is None or sha256_bytes(member_stream.read()) != str(expected).lower():
                    raise InstallerError(f"RUNTIME_PACKAGE_HASH_MISMATCH:{name}")
            init_stream = archive.extractfile("cnserverops/__init__.py")
            init_bytes = init_stream.read() if init_stream is not None else b""
            init_match = re.search(
                rb'^__version__\s*=\s*["\']([^"\']+)["\']', init_bytes, re.MULTILINE
            )
            if init_match is None or init_match.group(1).decode() != version:
                raise InstallerError("RUNTIME_PACKAGE_VERSION_CONTENT_MISMATCH")
            return manifest, members
    except (OSError, tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
        if isinstance(exc, InstallerError):
            raise
        raise InstallerError("RUNTIME_PACKAGE_UNREADABLE") from exc


def verify_runtime_package(package: Path, *, expected_sha256: str = "") -> dict[str, Any]:
    package = package.resolve(strict=True)
    actual = sha256_file(package)
    expected = str(expected_sha256 or "").lower().strip()
    sidecar = package.with_suffix(package.suffix + ".json")
    if not expected and sidecar.is_file():
        try:
            receipt = json.loads(sidecar.read_text(encoding="utf-8"))
            expected = str(receipt.get("package_sha256") or "").lower()
        except (OSError, json.JSONDecodeError):
            expected = ""
    if not _SHA256_RE.fullmatch(expected) or expected != actual:
        raise InstallerError("RUNTIME_PACKAGE_SHA256_UNVERIFIED")
    manifest, members = _runtime_manifest_from_package(package)
    with tarfile.open(package, "r:*") as archive:
        manifest_member = archive.getmember("release-manifest.json")
        manifest_stream = archive.extractfile(manifest_member)
        if manifest_stream is None:
            raise InstallerError("RUNTIME_PACKAGE_MANIFEST_UNREADABLE")
        manifest_bytes = manifest_stream.read()
    return {
        "status": "PASS",
        "package": str(package),
        "package_sha256": actual,
        "runtime_version": str(manifest["version"]),
        "member_count": len(members) - 1,
        "release_manifest_sha256": sha256_bytes(manifest_bytes),
    }


def _safe_extract_archive(archive_path: Path, destination: Path, *, allow_symlinks: bool) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive.getmembers():
            # Common debootstrap archives contain a harmless top-level `.`
            # directory entry.  It does not create a path and is safe to
            # ignore; every other member still goes through strict checks.
            if member.name in {".", "./", ""}:
                continue
            relative = _safe_member(member.name)
            # Validate lexically (archive members already reject `..`) and
            # refuse writes through a pre-existing symlink parent.  Resolving
            # the final path would incorrectly treat normal rootfs links such
            # as /usr/bin/pager -> /bin/more as host paths.
            target = destination_root / Path(*relative.parts)
            parent = target.parent
            while parent != destination_root:
                if parent.is_symlink():
                    raise InstallerError(f"ARCHIVE_WRITE_THROUGH_SYMLINK:{member.name}")
                if destination_root not in parent.parents:
                    raise InstallerError(f"ARCHIVE_PATH_ESCAPES_ROOT:{member.name}")
                parent = parent.parent
            if member.issym() or member.islnk():
                if not allow_symlinks:
                    raise InstallerError(f"RUNTIME_PACKAGE_SYMLINK_REJECTED:{member.name}")
                link_target = str(member.linkname)
                # Normalize the link target relative to the member's parent.
                # Debian/Ubuntu rootfs archives commonly use safe links such
                # as `../bin/kill`; reject only links that actually climb
                # above the extraction root.
                stack = [] if link_target.startswith("/") else list(relative.parent.parts)
                for part in PurePosixPath(link_target).parts:
                    if part in {"", "."}:
                        continue
                    if part == "..":
                        if not stack:
                            raise InstallerError(f"ROOTFS_SYMLINK_ESCAPES_ROOT:{member.name}")
                        stack.pop()
                    else:
                        stack.append(part)
            if member.isdev() or member.isfifo():
                # Device nodes/FIFOs from a debootstrap archive are recreated
                # by udev/systemd on the installed host.  Never create them
                # from an untrusted runtime package; omit them only for the
                # explicitly supplied rootfs archive.
                if allow_symlinks:
                    continue
                raise InstallerError(f"ROOTFS_SPECIAL_FILE_REJECTED:{member.name}")
            archive.extract(member, destination_root, set_attrs=False)


def _remove_exact(root: Path, relative: str) -> None:
    target = root / Path(*PurePosixPath(relative).parts)
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.is_dir():
        shutil.rmtree(target)


def _write_dhcp(root: Path) -> None:
    netplan = root / "etc/netplan/99-cnserverops-dhcp.yaml"
    networkd = root / "etc/systemd/network/10-cnserverops-dhcp.network"
    atomic_write(
        netplan,
        "# CNServerOps generic production DHCP; no static development address.\n"
        "network:\n  version: 2\n  ethernets:\n    cnserverops-dhcp:\n"
        "      match:\n        name: 'en*'\n      dhcp4: true\n"
        "      dhcp6: false\n      optional: true\n",
    )
    atomic_write(
        networkd,
        "# CNServerOps generic production DHCP; no static development address.\n"
        "[Match]\nName=en* eth* eno*\n\n[Network]\nDHCP=ipv4\n"
        "IPv6AcceptRA=no\nRequiredForOnline=no\n",
    )


def _write_unit_enablement(root: Path) -> None:
    wants = root / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True, exist_ok=True)
    for unit in _REQUIRED_UNITS:
        installed_source = root / "opt/cnserverops/current/deployment/linux" / unit
        if not installed_source.is_file() or installed_source.is_symlink():
            raise InstallerError(f"RUNTIME_REQUIRED_UNIT_MISSING:{unit}")
        # Keep links valid after the temporary mount point is removed.  An
        # absolute link to the mounted path would become stale on reboot.
        source = Path("../../../../opt/cnserverops/current/deployment/linux") / unit
        target = wants / unit
        if target.exists() or target.is_symlink():
            target.unlink()
        target.symlink_to(source)
    for unit in ("getty@tty1.service", "cngpu-countdown-menu.service"):
        stale = wants / unit
        if stale.is_symlink():
            stale.unlink()


def _install_runtime_entrypoints(root: Path, release: Path) -> None:
    """Install the small immutable launcher shims expected by systemd.

    The runtime archive intentionally keeps deployment assets under its
    versioned release directory.  The systemd units use the stable
    ``/usr/local/sbin`` paths so an atomic runtime switch cannot leave a unit
    pointing into a temporary mount or an old release.  Copy only the two
    reviewed entrypoints; no executable is sourced from the builder host.
    """

    target_dir = root / "usr/local/sbin"
    target_dir.mkdir(parents=True, exist_ok=True)
    for name in ("cnserverops-console", "cnserverops-launcher-rollback"):
        source = release / "deployment/linux" / name
        if not source.is_file() or source.is_symlink():
            raise InstallerError(f"RUNTIME_ENTRYPOINT_MISSING:{name}")
        target = target_dir / name
        temporary = target.with_name(f".{name}.tmp")
        shutil.copyfile(source, temporary)
        os.chmod(temporary, 0o755)
        os.replace(temporary, target)


def _load_example_config(release: Path, relative: str, fallback: Mapping[str, Any]) -> dict[str, Any]:
    source = release / Path(*PurePosixPath(relative).parts)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = dict(fallback)
    return dict(payload) if isinstance(payload, Mapping) else dict(fallback)


def _clean_server_state(root: Path) -> None:
    for relative in _FORBIDDEN_RELATIVE_FILES:
        _remove_exact(root, relative)
    for relative in _FORBIDDEN_RELATIVE_DIRS:
        _remove_exact(root, relative)
    for relative in (
        "etc/machine-id",
        "var/lib/dbus/machine-id",
        "etc/cnserverops/clone-template.consumed.json",
        "etc/cnserverops/personalization-receipt.json",
        "etc/cnserverops/personalization-transaction.json",
        "etc/cnserverops/personalization.lock",
        "etc/netplan/99-cnserverops-static.yaml",
        "etc/netplan/99-cnstress-static.yaml",
        "etc/netplan/99-cnstress-dhcp.yaml.disabled",
    ):
        _remove_exact(root, relative)
    for key in ("ssh_host_*",):
        for path in (root / "etc/ssh").glob(key):
            if path.is_file() or path.is_symlink():
                path.unlink()


def populate_root(
    root: Path,
    *,
    runtime_package: Path,
    expected_package_sha256: str,
    installer_version: str = INSTALLER_VERSION,
    central_endpoint: str = DEFAULT_CENTRAL_ENDPOINT,
    install_timestamp_utc: str | None = None,
    rootfs_tar: Path | None = None,
) -> dict[str, Any]:
    """Populate a mounted root or test directory from immutable artifacts."""
    root = root.resolve()
    if not root.is_dir():
        raise InstallerError("ROOT_MOUNT_MISSING")
    package_receipt = verify_runtime_package(runtime_package, expected_sha256=expected_package_sha256)
    version = package_receipt["runtime_version"]
    release = root / "opt/cnserverops/releases" / str(version)
    if release.exists():
        raise InstallerError("RUNTIME_RELEASE_ALREADY_EXISTS")
    if rootfs_tar is not None:
        # mkfs.ext4 creates lost+found on a freshly formatted target.  It is
        # safe to remove that directory before extracting the supplied clean
        # OS archive; any other pre-existing entry indicates a contaminated
        # target and is rejected.
        entries = [entry for entry in root.iterdir() if entry.name != "lost+found"]
        if entries:
            raise InstallerError("ROOTFS_TARGET_NOT_EMPTY")
        _remove_exact(root, "lost+found")
        _safe_extract_archive(rootfs_tar.resolve(strict=True), root, allow_symlinks=True)
    release.parent.mkdir(parents=True, exist_ok=True)
    _safe_extract_archive(runtime_package, release, allow_symlinks=False)
    _install_runtime_entrypoints(root, release)
    current = root / "opt/cnserverops/current"
    if current.exists() or current.is_symlink():
        _remove_exact(root, "opt/cnserverops/current")
    current.symlink_to(Path("releases") / str(version))

    _clean_server_state(root)
    for directory in (
        "etc/cnserverops/secrets",
        "var/lib/cnserverops/production",
        "var/lib/cnserverops/firmware",
        "var/log/cnserverops",
        "CN_STRESS_RESULTS",
    ):
        (root / directory).mkdir(parents=True, exist_ok=True)
    os.chmod(root / "etc/cnserverops", 0o700)
    os.chmod(root / "etc/cnserverops/secrets", 0o700)

    production = _load_example_config(
        release,
        "deployment/linux/cnserverops-production.example.json",
        {"schema_version": 1},
    )
    production["runner_config"] = "/etc/cnserverops/runner.json"
    production["central_config"] = "/etc/cnserverops/central.json"
    production["primary_root"] = "/CN_STRESS_RESULTS"
    atomic_json(root / "etc/cnserverops/production.json", production)
    atomic_json(
        root / "etc/cnserverops/central.json",
        {
            "schema_version": 1,
            "endpoint": str(central_endpoint).rstrip("/"),
            "ca_file": "/etc/cnserverops/central-ca.pem",
            "access_file": "/etc/cnserverops/central-auth",
        },
    )
    atomic_write(root / "etc/hostname", "cnserverops\n", mode=0o644)
    _write_dhcp(root)
    _write_unit_enablement(root)
    marker = {
        "schema_version": 1,
        "state": "READY_FOR_CLONE",
        "template_id": f"CNSSD-BUILD-{uuid.uuid4().hex[:16].upper()}",
        "prepared_at_utc": install_timestamp_utc or utc_now(),
        "regenerate_machine_id": True,
        "regenerate_ssh_host_keys": True,
        "require_storage_fingerprint": True,
        "stale_state_paths": list(_CLONE_STALE_STATE_PATHS),
        "network_policy": {
            "mode": "DHCP_GENERIC",
            "path": "etc/netplan/99-cnserverops-dhcp.yaml",
            "networkd_path": "etc/systemd/network/10-cnserverops-dhcp.network",
            "match": "en* eth* eno*",
            "static_development_address_removed": True,
        },
        "hostname_is_not_runner_identity": True,
    }
    atomic_json(root / "etc/cnserverops/clone-template.json", marker)
    record = {
        "schema_version": 1,
        "status": "INSTALLED_TEMPLATE",
        "installer_version": installer_version,
        "installed_at_utc": install_timestamp_utc or utc_now(),
        "runtime_version": version,
        "runtime_package_sha256": package_receipt["package_sha256"],
        "release_manifest_sha256": package_receipt["release_manifest_sha256"],
        "source": "IMMUTABLE_RUNTIME_PACKAGE",
        "runner_identity": "GENERATED_ON_FIRST_BOOT_FROM_STORAGE_FINGERPRINT",
        "central_endpoint": str(central_endpoint).rstrip("/"),
    }
    atomic_json(root / "etc/cnserverops/installer-record.json", record)
    result = validate_tree(root, expected_runtime_version=version, expected_package_sha256=package_receipt["package_sha256"])
    result["installation_record"] = record
    return result


def _iter_text_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink() or "__pycache__" in path.parts:
            continue
        try:
            sample = path.read_bytes()[:4096]
        except OSError:
            continue
        if b"\x00" not in sample:
            yield path


def _validate_release_tree(release: Path, expected_version: str, expected_package_sha256: str) -> dict[str, Any]:
    manifest_path = release / "release-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise InstallerError("INSTALLED_RELEASE_MANIFEST_MISSING")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("version") != expected_version or manifest.get("immutable") is not True:
        raise InstallerError("INSTALLED_RELEASE_MANIFEST_INVALID")
    files = manifest.get("files")
    if not isinstance(files, Mapping):
        raise InstallerError("INSTALLED_RELEASE_MANIFEST_FILES_INVALID")
    for name, expected in files.items():
        target = release / Path(*PurePosixPath(str(name)).parts)
        if not target.is_file() or target.is_symlink() or sha256_file(target) != str(expected).lower():
            raise InstallerError(f"INSTALLED_RELEASE_HASH_MISMATCH:{name}")
    return {"status": "PASS", "version": expected_version, "file_count": len(files), "package_sha256": expected_package_sha256}


def validate_tree(
    root: Path,
    *,
    expected_runtime_version: str,
    expected_package_sha256: str,
    esp_root: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    checks: dict[str, str] = {}
    record_path = root / "etc/cnserverops/installer-record.json"
    if not record_path.is_file():
        raise InstallerError("INSTALLER_RECORD_MISSING")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if record.get("runtime_version") != expected_runtime_version or record.get("runtime_package_sha256") != expected_package_sha256:
        raise InstallerError("INSTALLER_RECORD_RUNTIME_MISMATCH")
    checks["installation_record"] = "PASS"
    release = root / "opt/cnserverops/releases" / expected_runtime_version
    checks["runtime_release"] = str(_validate_release_tree(release, expected_runtime_version, expected_package_sha256)["status"])
    current = root / "opt/cnserverops/current"
    if not current.is_symlink() or current.resolve() != release.resolve():
        raise InstallerError("CURRENT_RUNTIME_POINTER_INVALID")
    checks["runtime_pointer"] = "PASS"
    marker_path = root / "etc/cnserverops/clone-template.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8")) if marker_path.is_file() else {}
    if marker.get("state") != "READY_FOR_CLONE" or not marker.get("require_storage_fingerprint"):
        raise InstallerError("CLONE_FIRSTBOOT_MARKER_INVALID")
    checks["clone_firstboot_marker"] = "PASS"
    if (root / "etc/cnserverops/runner.json").exists():
        raise InstallerError("STALE_RUNNER_ID_PRESENT")
    checks["runner_identity"] = "CLEAN_FIRST_BOOT_REQUIRED"
    machine_id = root / "etc/machine-id"
    if machine_id.exists() and machine_id.read_text(encoding="utf-8", errors="ignore").strip():
        raise InstallerError("STALE_MACHINE_ID_PRESENT")
    ssh_keys = [path for path in (root / "etc/ssh").glob("ssh_host_*") if path.is_file() or path.is_symlink()]
    if ssh_keys:
        raise InstallerError("STALE_SSH_HOST_IDENTITY_PRESENT")
    checks["machine_and_ssh_identity"] = "CLEAN_FIRST_BOOT_REQUIRED"
    secret_files = [path for path in (root / "etc/cnserverops/secrets").glob("*") if path.is_file() or path.is_symlink()]
    if secret_files:
        raise InstallerError("OPERATIONAL_SECRET_PRESENT")
    checks["secrets"] = "CLEAN"
    for relative in _FORBIDDEN_RELATIVE_FILES:
        if (root / relative).exists() or (root / relative).is_symlink():
            raise InstallerError(f"STALE_STATE_PRESENT:{relative}")
    for relative in _FORBIDDEN_RELATIVE_DIRS:
        if (root / relative).exists():
            raise InstallerError(f"STALE_STATE_DIRECTORY_PRESENT:{relative}")
    checks["mutable_state"] = "CLEAN"
    production = json.loads((root / "etc/cnserverops/production.json").read_text(encoding="utf-8"))
    central = json.loads((root / "etc/cnserverops/central.json").read_text(encoding="utf-8"))
    if production.get("runner_config") != "/etc/cnserverops/runner.json" or not str(central.get("endpoint") or "").startswith(("http://", "https://")):
        raise InstallerError("CONFIGURATION_INVALID")
    checks["configuration"] = "PASS"
    netplan = (root / "etc/netplan/99-cnserverops-dhcp.yaml").read_text(encoding="utf-8")
    networkd = (root / "etc/systemd/network/10-cnserverops-dhcp.network").read_text(encoding="utf-8")
    netplan_has_static = bool(re.search(r"(?m)^\s*(?:addresses|gateway4|gateway6|routes):", netplan))
    networkd_has_static = bool(re.search(r"(?mi)^\s*(?:address|gateway|route)=", networkd))
    if "dhcp4: true" not in netplan or "DHCP=ipv4" not in networkd or netplan_has_static or networkd_has_static:
        raise InstallerError("GENERIC_DHCP_CONFIGURATION_INVALID")
    checks["networking"] = "DHCP_GENERIC"
    # Only mutable configuration/state is checked for development addresses.
    # Immutable runtime source may legitimately document historical examples;
    # those must not invalidate a clean installation.
    mutable_text_roots = [root / "etc", root / "var", root / "CN_STRESS_RESULTS"]
    for mutable_root in mutable_text_roots:
        if not mutable_root.exists():
            continue
        for path in _iter_text_files(mutable_root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for value in _STATIC_DEVELOPMENT_VALUES:
                if value in text:
                    raise InstallerError(f"STATIC_DEVELOPMENT_ADDRESS_PRESENT:{value}")
    checks["development_network_state"] = "ABSENT"
    wants = root / "etc/systemd/system/multi-user.target.wants"
    for unit in _REQUIRED_UNITS:
        target = wants / unit
        if not target.is_symlink() or target.resolve() != (root / "opt/cnserverops/current/deployment/linux" / unit).resolve():
            raise InstallerError(f"SYSTEMD_UNIT_NOT_ENABLED:{unit}")
    checks["systemd_units"] = "ENABLED"
    for name in ("cnserverops-console", "cnserverops-launcher-rollback"):
        entrypoint = root / "usr/local/sbin" / name
        if not entrypoint.is_file() or entrypoint.is_symlink() or not os.access(entrypoint, os.X_OK):
            raise InstallerError(f"RUNTIME_ENTRYPOINT_INVALID:{name}")
    checks["runtime_entrypoints"] = "PASS"
    if esp_root is not None:
        esp_root = esp_root.resolve()
        if not (esp_root / "EFI/BOOT/BOOTX64.EFI").exists() and not (esp_root / "EFI/CNServerOps").exists():
            raise InstallerError("EFI_BOOTLOADER_NOT_FOUND")
        checks["efi_boot"] = "PASS"
    return {"status": "PASS", "checks": checks, "runtime_version": expected_runtime_version}


def _partition_path(device: str, number: int) -> str:
    # NVMe, MMC and loop devices use the `pN` separator; SATA/SAS disks use
    # the traditional `/dev/sdX1` form.
    needs_separator = re.search(r"(?:nvme\d+n\d+|mmcblk\d+|loop\d+)$", device)
    return f"{device}p{number}" if needs_separator else f"{device}{number}"


def _run_checked(command: Sequence[str], *, timeout: int = 300) -> None:
    result = run_capture(command, timeout=timeout)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()[-1:]
        raise InstallerError(f"COMMAND_FAILED:{command[0]}:{detail[0] if detail else result.returncode}")


def _wait_for(path: str, *, timeout: int = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if Path(path).exists():
            return
        time.sleep(0.25)
    raise InstallerError(f"PARTITION_NODE_NOT_FOUND:{path}")


def install_physical(
    target: DiskInfo,
    *,
    runtime_package: Path,
    expected_package_sha256: str,
    rootfs_tar: Path,
    central_endpoint: str,
    installer_version: str,
) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise InstallerError("ROOT_REQUIRED_FOR_PHYSICAL_INSTALL")
    tools = check_host_tools()
    if tools["missing"]:
        raise InstallerError("MISSING_DEPENDENCIES:" + ",".join(tools["missing"]))
    target_path = target.path
    esp_device = _partition_path(target_path, 1)
    root_device = _partition_path(target_path, 2)
    _run_checked(("wipefs", "-a", target_path))
    _run_checked(("sgdisk", "--zap-all", target_path))
    _run_checked(("sgdisk", "-n", "1:1MiB:+512MiB", "-t", "1:EF00", "-c", "1:CN_ESP", "-n", "2:0:0", "-t", "2:8300", "-c", "2:CNSERVEROPS_ROOT", target_path))
    _run_checked(("partprobe", target_path), timeout=60)
    _wait_for(esp_device)
    _wait_for(root_device)
    _run_checked(("mkfs.vfat", "-F", "32", "-n", "CN_ESP", esp_device), timeout=120)
    _run_checked(("mkfs.ext4", "-F", "-L", "CNSERVEROPS_ROOT", root_device), timeout=300)
    with tempfile.TemporaryDirectory(prefix="cnserverops-ssd-") as folder:
        mount_root = Path(folder) / "root"
        mount_esp = mount_root / "boot/efi"
        mount_esp.mkdir(parents=True, exist_ok=True)
        _run_checked(("mount", root_device, str(mount_root)))
        try:
            _run_checked(("mount", esp_device, str(mount_esp)))
            result = populate_root(
                mount_root,
                runtime_package=runtime_package,
                expected_package_sha256=expected_package_sha256,
                installer_version=installer_version,
                central_endpoint=central_endpoint,
                rootfs_tar=rootfs_tar,
            )
            root_uuid = run_capture(("blkid", "-s", "UUID", "-o", "value", root_device), timeout=30).stdout.strip()
            esp_uuid = run_capture(("blkid", "-s", "UUID", "-o", "value", esp_device), timeout=30).stdout.strip()
            root_label = run_capture(("blkid", "-s", "LABEL", "-o", "value", root_device), timeout=30).stdout.strip()
            esp_label = run_capture(("blkid", "-s", "LABEL", "-o", "value", esp_device), timeout=30).stdout.strip()
            if not root_uuid or not esp_uuid:
                raise InstallerError("FILESYSTEM_UUID_UNAVAILABLE")
            if root_label != "CNSERVEROPS_ROOT" or esp_label != "CN_ESP":
                raise InstallerError("FILESYSTEM_LABEL_VERIFICATION_FAILED")
            atomic_write(
                mount_root / "etc/fstab",
                f"UUID={root_uuid} / ext4 defaults 0 1\nUUID={esp_uuid} /boot/efi vfat umask=0077 0 1\n",
                mode=0o644,
            )
            atomic_write(mount_root / "etc/default/grub", "GRUB_TIMEOUT=1\nGRUB_TIMEOUT_STYLE=hidden\n", mode=0o644)
            _run_checked(("grub-install", "--target=x86_64-efi", "--efi-directory", str(mount_esp), "--boot-directory", str(mount_root / "boot"), "--bootloader-id=CNServerOps", "--removable", "--no-nvram", "--recheck", target_path), timeout=300)
            result = validate_tree(mount_root, expected_runtime_version=result["runtime_version"], expected_package_sha256=expected_package_sha256, esp_root=mount_esp)
            result["filesystem_labels"] = {"root": root_label, "esp": esp_label}
            result["filesystem_uuids"] = {"root": root_uuid, "esp": esp_uuid}
            atomic_json(mount_root / "var/log/cnserverops/ssd-installer-final.json", result)
            return result
        finally:
            run_capture(("sync",), timeout=60)
            run_capture(("umount", "-R", str(mount_root)), timeout=120)


def _source_disks(package: Path, rootfs: Path | None, disks: Sequence[DiskInfo]) -> set[str]:
    values = {path_disk(package, disks)}
    if rootfs is not None:
        values.add(path_disk(rootfs, disks))
    return {item for item in values if item}


def _print_disks(disks: Sequence[DiskInfo], *, system_disk: str, source_disks: set[str]) -> None:
    print("Detected whole disks:")
    for disk in disks:
        labels: list[str] = []
        if disk.path == system_disk:
            labels.append("SYSTEM_DISK_BLOCKED")
        if disk.path in source_disks:
            labels.append("SOURCE_DISK_BLOCKED")
        if disk.mounted:
            labels.append("MOUNTED_OR_IN_USE")
        if disk.read_only:
            labels.append("READ_ONLY")
        suffix = f" [{', '.join(labels)}]" if labels else ""
        print(f"  {disk.display()}{suffix}")


def _interactive_target(disks: Sequence[DiskInfo], *, system_disk: str, source_disks: set[str]) -> str:
    candidates = [disk for disk in disks if disk.path != system_disk and disk.path not in source_disks and not disk.mounted and not disk.read_only]
    if not candidates:
        raise InstallerError("NO_SAFE_TARGET_DISK_CANDIDATE")
    print("\nSafe target candidates:")
    for index, disk in enumerate(candidates, start=1):
        print(f"  [{index}] {disk.display()}")
    answer = input("Select target SSD number (blank cancels): ").strip()
    if not answer.isdigit() or not 1 <= int(answer) <= len(candidates):
        raise InstallerError("TARGET_SELECTION_CANCELLED_OR_INVALID")
    return candidates[int(answer) - 1].path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CNServerOps reproducible SSD installer")
    parser.add_argument("--package", type=Path, help="verified immutable runtime package")
    parser.add_argument("--rootfs-tar", type=Path, help="Ubuntu/Debian root filesystem archive")
    parser.add_argument("--target", help="explicit whole-disk device; never inferred")
    parser.add_argument("--central-endpoint", default=DEFAULT_CENTRAL_ENDPOINT)
    parser.add_argument("--installer-version", default=INSTALLER_VERSION)
    parser.add_argument("--expected-package-sha256", default="")
    parser.add_argument("--check", action="store_true", help="non-destructive dependency/package/disk check")
    parser.add_argument("--dry-run", action="store_true", help="show the plan without changing disks")
    parser.add_argument("--bootstrap-deps", action="store_true", help="explicitly install Ubuntu/Debian builder prerequisites")
    parser.add_argument("--apt-update", action="store_true", help="with --bootstrap-deps, refresh apt metadata first")
    parser.add_argument("--populate-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--validate-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--image-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--yes-i-understand-wipe", action="store_true", help=argparse.SUPPRESS)
    return parser


def _default_package(script_path: Path) -> Path:
    roots = (script_path.parent, script_path.parent.parent)
    for root in roots:
        candidate = root / DEFAULT_RUNTIME_PACKAGE
        if candidate.is_file():
            return candidate
    candidates: list[Path] = []
    for root in roots:
        candidates.extend(root.glob("payload/runtime*.tar.gz"))
    if len(candidates) == 1:
        return candidates[0]
    raise InstallerError("RUNTIME_PACKAGE_NOT_FOUND_USE_PACKAGE_OPTION")


def _default_rootfs(script_path: Path) -> Path:
    for root in (script_path.parent, script_path.parent.parent):
        for relative in DEFAULT_ROOTFS_GLOBS:
            candidate = root / relative
            if candidate.is_file():
                return candidate
    raise InstallerError("ROOTFS_ARCHIVE_NOT_FOUND_BUNDLE_MUST_INCLUDE_ROOTFS_OR_USE_ROOTFS_TAR")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    script_path = Path(__file__).resolve()
    try:
        package = (args.package or _default_package(script_path)).resolve(strict=True)
        package_receipt = verify_runtime_package(package, expected_sha256=args.expected_package_sha256)
        rootfs = (args.rootfs_tar or _default_rootfs(script_path)).resolve(strict=True) if not args.populate_root and not args.validate_root else (args.rootfs_tar.resolve(strict=True) if args.rootfs_tar else None)
        if args.populate_root or args.image_root:
            root = (args.populate_root or args.image_root).resolve()
            result = populate_root(root, runtime_package=package, expected_package_sha256=package_receipt["package_sha256"], installer_version=args.installer_version, central_endpoint=args.central_endpoint, rootfs_tar=rootfs if args.populate_root else None)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.validate_root:
            result = validate_tree(args.validate_root, expected_runtime_version=package_receipt["runtime_version"], expected_package_sha256=package_receipt["package_sha256"])
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        disks = host_lsblk()
        system = root_disk(disks)
        sources = _source_disks(package, rootfs, disks)
        tool_status = bootstrap_dependencies(refresh=args.apt_update) if args.bootstrap_deps else check_host_tools()
        _print_disks(disks, system_disk=system, source_disks=sources)
        if args.check:
            result = {"status": "PASS" if tool_status["status"] == "PASS" else "CHECK_REQUIRED", "package": package_receipt, "host_tools": tool_status, "system_disk_blocked": system, "source_disks_blocked": sorted(sources)}
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "PASS" else 2
        target_path = args.target or _interactive_target(disks, system_disk=system, source_disks=sources)
        target = guard_target(target_path, disks, system_disk=system, source_disks=sources)
        print("\nDESTRUCTIVE OPERATION WARNING")
        print("The selected whole disk will be repartitioned and all existing data will be erased:")
        print("  " + target.display())
        if args.dry_run:
            print(json.dumps({"status": "DRY_RUN", "target": target.display(), "runtime": package_receipt, "rootfs": str(rootfs), "plan": ["GPT", "CN_ESP FAT32", "CNSERVEROPS_ROOT ext4", "UEFI bootloader", "clean runtime overlay", "first-boot runner personalization"]}, indent=2, sort_keys=True))
            return 0
        confirmation = input(f"Type exactly WIPE {target.path} to continue: ").strip()
        if confirmation != f"WIPE {target.path}":
            raise InstallerError("DESTRUCTIVE_CONFIRMATION_NOT_MATCHED")
        result = install_physical(target, runtime_package=package, expected_package_sha256=package_receipt["package_sha256"], rootfs_tar=rootfs, central_endpoint=args.central_endpoint, installer_version=args.installer_version)
        print(json.dumps({"status": "READY_FOR_SERVER", "target": target.display(), "runtime": package_receipt, "validation": result}, indent=2, sort_keys=True))
        return 0
    except InstallerError as exc:
        print(f"CNServerOps SSD installer: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
