"""Immutable runtime and deployment preflight checks.

The production SSD installs an immutable runtime under
``/opt/cnserverops/releases/<version>`` and points ``current`` at that
release.  These checks deliberately inspect metadata, unit files, and file
permissions only.  In particular, BMC password files are *never opened* by
this module; it only verifies that a configured factory-default secret is
present and private before a runtime which may need it is activated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


class RuntimePreflightError(RuntimeError):
    """A runtime package or its deployment prerequisites are unsafe."""


REQUIRED_RELEASE_MEMBERS = frozenset(
    {
        "cnserverops/__init__.py",
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

SYSTEMD_UNIT_NAMES = (
    "cnserverops-console.service",
    "cnserverops-firmware-resume.service",
    "cnserverops-firmware-resume-retry.service",
    "cnserverops-firmware-resume-retry.timer",
    "cnserverops-clone-firstboot.service",
    "cnserverops-sync-retry.service",
    "cnserverops-sync-retry.timer",
)

DEFAULT_BMC_SECRET_PATH = Path("/etc/cnserverops/secrets/asus-default-bmc-password")
_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_RUNTIME_VERSION_RE = re.compile(rb'^__version__\s*=\s*["\']([^"\']+)["\']', re.MULTILINE)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_member_path(value: object) -> PurePosixPath:
    path = PurePosixPath(str(value))
    if path.is_absolute() or ".." in path.parts or not path.parts or path.name == "release-manifest.json":
        raise RuntimePreflightError(f"unsafe release-manifest member: {value}")
    return path


def _regular_file(path: Path, *, description: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimePreflightError(f"{description} is missing") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimePreflightError(f"{description} must be a regular non-symlink file")


def _load_manifest(release_root: Path) -> tuple[dict[str, Any], Path]:
    manifest_path = release_root / "release-manifest.json"
    _regular_file(manifest_path, description="release manifest")
    try:
        parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimePreflightError("release manifest is malformed") from exc
    if not isinstance(parsed, dict):
        raise RuntimePreflightError("release manifest is malformed")
    return parsed, manifest_path


def verify_release_tree(release_root: Path, *, expected_version: str | None = None) -> dict[str, Any]:
    """Validate installed immutable release bytes against its manifest.

    Unlike a source-tree test, this re-hashes the files that the console will
    import.  It rejects extra files or symlinks because either makes the
    active release differ from its packaged proof.  Interpreter bytecode
    caches are generated runtime state and are ignored explicitly.
    """
    root = Path(release_root).resolve()
    if not root.is_dir():
        raise RuntimePreflightError("runtime release root is missing")
    manifest, manifest_path = _load_manifest(root)
    version = str(manifest.get("version") or "")
    if not _VERSION_RE.fullmatch(version):
        raise RuntimePreflightError("release manifest version is invalid")
    if expected_version is not None and version != expected_version:
        raise RuntimePreflightError("release manifest version does not match expected version")
    if manifest.get("schema_version") != 1 or manifest.get("immutable") is not True:
        raise RuntimePreflightError("release manifest does not declare immutable schema version 1")
    files = manifest.get("files")
    if not isinstance(files, Mapping) or not files:
        raise RuntimePreflightError("release manifest has no file hashes")

    expected: dict[str, str] = {}
    for raw_name, raw_hash in files.items():
        name = _safe_member_path(raw_name).as_posix()
        digest = str(raw_hash).lower()
        if not _SHA256_RE.fullmatch(digest):
            raise RuntimePreflightError(f"release manifest hash is invalid: {name}")
        if name in expected:
            raise RuntimePreflightError(f"release manifest contains duplicate member: {name}")
        expected[name] = digest
    missing_required = sorted(REQUIRED_RELEASE_MEMBERS - set(expected))
    if missing_required:
        raise RuntimePreflightError(
            "release manifest is missing required production members: " + ", ".join(missing_required)
        )

    actual: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path == manifest_path:
            continue
        # Python may create interpreter bytecode when an operator invokes a
        # module from the console shell (or when a one-time clone hook runs).
        # These files are generated cache, not runtime source, and must not
        # make a verified immutable release fail its own later preflight.
        # Everything else remains strictly hash-checked and unexpected files
        # still fail closed below.
        if "__pycache__" in path.parts and path.suffix == ".pyc":
            continue
        try:
            info = path.lstat()
        except OSError as exc:
            raise RuntimePreflightError(f"cannot inspect release member: {relative}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise RuntimePreflightError(f"release contains symlink: {relative}")
        if path.is_dir():
            continue
        if not stat.S_ISREG(info.st_mode):
            raise RuntimePreflightError(f"release contains non-regular member: {relative}")
        actual.add(relative)
    if actual != set(expected):
        missing = sorted(set(expected) - actual)
        unexpected = sorted(actual - set(expected))
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing[:5]))
        if unexpected:
            details.append("unexpected=" + ",".join(unexpected[:5]))
        raise RuntimePreflightError("release tree does not match manifest: " + "; ".join(details))

    for name, digest in expected.items():
        target = root.joinpath(*PurePosixPath(name).parts)
        _regular_file(target, description=f"release member {name}")
        if _sha256(target) != digest:
            raise RuntimePreflightError(f"release member checksum mismatch: {name}")

    init_path = root / "cnserverops" / "__init__.py"
    init_match = _RUNTIME_VERSION_RE.search(init_path.read_bytes())
    if not init_match or init_match.group(1).decode("utf-8", errors="replace") != version:
        raise RuntimePreflightError("release manifest version does not match cnserverops runtime version")
    return {
        "status": "PASS",
        "version": version,
        "release_root": str(root),
        "file_count": len(expected),
        "release_manifest_sha256": _sha256(manifest_path),
    }


def _configured_default_secret(config_path: Path) -> tuple[bool, Path]:
    _regular_file(config_path, description="production configuration")
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimePreflightError("production configuration is malformed") from exc
    if not isinstance(config, Mapping):
        raise RuntimePreflightError("production configuration is malformed")
    policy = config.get("bmc_auth_policy")
    if policy is None:
        policy = {}
    if not isinstance(policy, Mapping):
        raise RuntimePreflightError("BMC authentication policy is malformed")
    enabled = bool(policy.get("default_probe_enabled", True))
    configured_path = str(policy.get("default_password_file") or DEFAULT_BMC_SECRET_PATH)
    return enabled, Path(configured_path)


def _verify_default_secret_presence(config_path: Path) -> dict[str, str]:
    required, secret_path = _configured_default_secret(config_path)
    if not required:
        return {"status": "NOT_REQUIRED", "path": str(secret_path)}
    _regular_file(secret_path, description="configured ASUS default BMC secret")
    # Windows test fixtures do not reliably carry POSIX permission bits.  The
    # production runtime runs on Linux, where group/world-readable secrets are
    # an explicit deployment failure.  The value itself is never opened.
    if os.name != "nt" and stat.S_IMODE(secret_path.stat().st_mode) & 0o077:
        raise RuntimePreflightError("configured ASUS default BMC secret is not private")
    return {"status": "PRESENT_PRIVATE", "path": str(secret_path)}


def verify_deployment_preflight(
    *,
    release_root: Path,
    config_path: Path,
    systemd_root: Path | None = None,
    expected_version: str | None = None,
) -> dict[str, Any]:
    """Validate immutable bytes and non-secret deployment prerequisites.

    When ``systemd_root`` is supplied, every installed unit must be byte-for-
    byte identical to the unit inside the verified immutable release.  This
    prevents a source-only fix from being mistaken for a deployed one.
    """
    release = verify_release_tree(release_root, expected_version=expected_version)
    default_secret = _verify_default_secret_presence(Path(config_path))
    unit_status: dict[str, str] = {}
    if systemd_root is not None:
        unit_root = Path(systemd_root)
        for unit_name in SYSTEMD_UNIT_NAMES:
            source = Path(release_root) / "deployment" / "linux" / unit_name
            installed = unit_root / unit_name
            _regular_file(source, description=f"packaged systemd unit {unit_name}")
            _regular_file(installed, description=f"installed systemd unit {unit_name}")
            if source.read_bytes() != installed.read_bytes():
                raise RuntimePreflightError(f"installed systemd unit differs from immutable release: {unit_name}")
            unit_status[unit_name] = "MATCHES_RELEASE"
    return {
        "status": "PASS",
        "release": release,
        "default_bmc_secret": default_secret,
        "systemd_units": unit_status,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify CNServerOps immutable runtime deployment prerequisites")
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--systemd-root", type=Path)
    parser.add_argument("--expected-version")
    args = parser.parse_args(argv)
    try:
        result = verify_deployment_preflight(
            release_root=args.release_root,
            config_path=args.config,
            systemd_root=args.systemd_root,
            expected_version=args.expected_version,
        )
    except RuntimePreflightError as exc:
        print(f"CNServerOps deployment preflight failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
