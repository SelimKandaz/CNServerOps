from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from installer.cnserverops_ssd_installer import (
    DiskInfo,
    InstallerError,
    guard_target,
    _partition_path,
    populate_root,
    validate_tree,
    verify_runtime_package,
)


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _make_runtime_package(directory: Path, version: str = "9.9.9-pass3-test") -> tuple[Path, str]:
    files = {
        "cnserverops/__init__.py": f'__version__ = "{version}"\n'.encode(),
        "deployment/linux/cnserverops-console": b"#!/bin/sh\nexit 0\n",
        "deployment/linux/cnserverops-launcher-rollback": b"#!/bin/sh\nexit 0\n",
        "deployment/linux/cnserverops-console.service": b"[Unit]\nDescription=CNServerOps\n",
        "deployment/linux/cnserverops-firmware-resume.service": b"[Unit]\n",
        "deployment/linux/cnserverops-firmware-resume-retry.service": b"[Unit]\n",
        "deployment/linux/cnserverops-firmware-resume-retry.timer": b"[Timer]\n",
        "deployment/linux/cnserverops-clone-firstboot.service": b"[Unit]\n",
        "deployment/linux/cnserverops-sync-retry.service": b"[Unit]\n",
        "deployment/linux/cnserverops-sync-retry.timer": b"[Timer]\n",
        "deployment/linux/cnserverops-production.example.json": b'{"schema_version":1}\n',
    }
    manifest = {
        "schema_version": 1,
        "immutable": True,
        "version": version,
        "files": {name: _hash(value) for name, value in files.items()},
    }
    package = directory / "runtime.tar.gz"
    with tarfile.open(package, "w:gz", compresslevel=9) as archive:
        for name, value in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(value)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(value))
        manifest_value = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        info = tarfile.TarInfo("release-manifest.json")
        info.size = len(manifest_value)
        info.mode = 0o644
        info.mtime = 0
        archive.addfile(info, io.BytesIO(manifest_value))
    package_sha = _hash(package.read_bytes())
    (directory / "runtime.tar.gz.json").write_text(
        json.dumps({"package_sha256": package_sha, "runtime_version": version}), encoding="utf-8"
    )
    return package, package_sha


class SsdInstallerTests(unittest.TestCase):
    @staticmethod
    def _symlink_capable() -> bool:
        if os.name != "nt":
            return True
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            try:
                (path / "target").mkdir()
                (path / "link").symlink_to(path / "target", target_is_directory=True)
                return True
            except OSError:
                return False

    def test_target_guard_blocks_system_mounted_source_and_read_only(self) -> None:
        disks = [
            DiskInfo("/dev/sda", "sda", "disk", size_bytes=100),
            DiskInfo("/dev/sdb", "sdb", "disk", size_bytes=200, mountpoints=("/mnt/source",)),
            DiskInfo("/dev/sdc", "sdc", "disk", size_bytes=300, read_only=True),
        ]
        with self.assertRaisesRegex(InstallerError, "SYSTEM"):
            guard_target("/dev/sda", disks, system_disk="/dev/sda")
        with self.assertRaisesRegex(InstallerError, "MOUNTED"):
            guard_target("/dev/sdb", disks, system_disk="/dev/sda")
        with self.assertRaisesRegex(InstallerError, "SOURCE"):
            guard_target("/dev/sdb", disks, system_disk="/dev/sda", source_disks=("/dev/sdb",))
        with self.assertRaisesRegex(InstallerError, "READ_ONLY"):
            guard_target("/dev/sdc", disks, system_disk="/dev/sda")

    def test_partition_device_naming_is_correct_for_nvme_mmc_and_loop(self) -> None:
        self.assertEqual(_partition_path("/dev/nvme0n1", 2), "/dev/nvme0n1p2")
        self.assertEqual(_partition_path("/dev/mmcblk0", 1), "/dev/mmcblk0p1")
        self.assertEqual(_partition_path("/dev/loop0", 1), "/dev/loop0p1")
        self.assertEqual(_partition_path("/dev/sdb", 2), "/dev/sdb2")

    @unittest.skipUnless(_symlink_capable.__func__(), "Windows test host does not permit symlink creation; run image tests on Linux")
    def test_two_clean_roots_have_identical_runtime_and_distinct_first_boot_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            package, package_sha = _make_runtime_package(workspace)
            first, second = workspace / "first", workspace / "second"
            first.mkdir()
            second.mkdir()
            first_result = populate_root(first, runtime_package=package, expected_package_sha256=package_sha, central_endpoint="https://central.example:8088")
            second_result = populate_root(second, runtime_package=package, expected_package_sha256=package_sha, central_endpoint="https://central.example:8088")
            self.assertEqual(first_result["status"], "PASS")
            self.assertEqual(second_result["status"], "PASS")
            self.assertTrue((first / "usr/local/sbin/cnserverops-console").is_file())
            self.assertTrue((first / "usr/local/sbin/cnserverops-launcher-rollback").is_file())
            self.assertEqual(
                (first / "opt/cnserverops/releases/9.9.9-pass3-test/cnserverops/__init__.py").read_bytes(),
                (second / "opt/cnserverops/releases/9.9.9-pass3-test/cnserverops/__init__.py").read_bytes(),
            )
            # Clone-firstboot is the only place that creates runner identity.
            from cnserverops import personalization

            with mock.patch.object(personalization, "_personalize_ssh_host_keys", return_value={"status": "SKIPPED_TEST"}):
                one = personalization.personalize_clone(first, runtime_version="9.9.9-pass3-test", storage_fingerprint="a" * 64)
                two = personalization.personalize_clone(second, runtime_version="9.9.9-pass3-test", storage_fingerprint="b" * 64)
            self.assertNotEqual(one["runner_id"], two["runner_id"])
            self.assertTrue((first / "etc/cnserverops/runner.json").is_file())
            self.assertTrue((second / "etc/cnserverops/runner.json").is_file())
            self.assertNotEqual(
                json.loads((first / "etc/cnserverops/runner.json").read_text())["storage_fingerprint_sha256"],
                json.loads((second / "etc/cnserverops/runner.json").read_text())["storage_fingerprint_sha256"],
            )

    def test_package_hash_is_required_and_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            package, package_sha = _make_runtime_package(workspace)
            receipt = verify_runtime_package(package, expected_sha256=package_sha)
            self.assertEqual(receipt["status"], "PASS")
            package.write_bytes(package.read_bytes() + b"tamper")
            with self.assertRaisesRegex(InstallerError, "SHA256"):
                verify_runtime_package(package, expected_sha256=package_sha)

    @unittest.skipUnless(_symlink_capable.__func__(), "Windows test host does not permit symlink creation; run image tests on Linux")
    def test_validation_rejects_static_development_address_in_mutable_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            package, package_sha = _make_runtime_package(workspace)
            root = workspace / "root"
            root.mkdir()
            populate_root(root, runtime_package=package, expected_package_sha256=package_sha)
            (root / "etc/cnserverops/central.json").write_text('{"endpoint":"https://10.1.10.155:8088"}\n', encoding="utf-8")
            with self.assertRaisesRegex(InstallerError, "STATIC_DEVELOPMENT_ADDRESS_PRESENT"):
                validate_tree(root, expected_runtime_version="9.9.9-pass3-test", expected_package_sha256=package_sha)

    @unittest.skipUnless(_symlink_capable.__func__(), "Windows test host does not permit symlink creation; run image tests on Linux")
    def test_final_runtime_package_two_fresh_templates_have_distinct_runners(self) -> None:
        package = Path(__file__).parents[1] / "dist/cnserverops-runtime-3.8.120-pass3-stress-recovery.tar.gz"
        rootfs = Path(__file__).parents[1] / "dist/cnserverops-rootfs-ubuntu24.04.tar"
        if not package.is_file() or not rootfs.is_file():
            self.skipTest("built runtime/rootfs artifacts are not present")
        package_sha = verify_runtime_package(package)["package_sha256"]
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            first, second = workspace / "first", workspace / "second"
            first.mkdir(); second.mkdir()
            one = populate_root(first, runtime_package=package, expected_package_sha256=package_sha, rootfs_tar=rootfs)
            two = populate_root(second, runtime_package=package, expected_package_sha256=package_sha, rootfs_tar=rootfs)
            self.assertEqual(one["status"], "PASS")
            self.assertEqual(two["status"], "PASS")
            from cnserverops import personalization
            with mock.patch.object(personalization, "_personalize_ssh_host_keys", return_value={"status": "SKIPPED_TEST"}):
                runner_one = personalization.personalize_clone(first, runtime_version=one["runtime_version"], storage_fingerprint="c" * 64)
                runner_two = personalization.personalize_clone(second, runtime_version=two["runtime_version"], storage_fingerprint="d" * 64)
            self.assertNotEqual(runner_one["runner_id"], runner_two["runner_id"])


if __name__ == "__main__":
    unittest.main()
