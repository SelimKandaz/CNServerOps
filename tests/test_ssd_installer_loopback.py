"""Root-only Linux loopback smoke tests for the destructive installer path.

These tests are skipped on Windows and on Linux builders without the required
privileges/tools.  They use temporary sparse files and never select a real
block device.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from installer.cnserverops_ssd_installer import DiskInfo, InstallerError, install_physical
from tests.test_ssd_installer import _make_runtime_package


def _linux_loopback_ready() -> bool:
    if os.name == "nt" or os.geteuid() != 0:
        return False
    # WSL kernels expose loop devices but do not reliably surface newly
    # partitioned vfat loop nodes for mount; run this test on native Linux.
    try:
        if "microsoft" in Path("/proc/version").read_text(encoding="utf-8", errors="ignore").lower():
            return False
    except OSError:
        return False
    return all(shutil.which(tool) for tool in ("losetup", "sgdisk", "mkfs.vfat", "mkfs.ext4", "mount", "grub-install"))


@unittest.skipUnless(_linux_loopback_ready(), "Linux root loopback prerequisites are unavailable")
class LoopbackInstallerTests(unittest.TestCase):
    def test_two_sparse_loopback_images_install_cleanly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cnserverops-loopback-test-") as temp:
            root = Path(temp)
            runtime, runtime_sha = _make_runtime_package(root)
            rootfs = root / "rootfs.tar"
            with tarfile.open(rootfs, "w") as archive:
                info = tarfile.TarInfo("etc"); info.type = tarfile.DIRTYPE; archive.addfile(info)
                info = tarfile.TarInfo("etc/os-release"); value = b"ID=debian\n"; info.size = len(value); archive.addfile(info, io.BytesIO(value))
            outputs = []
            for index in (1, 2):
                image = root / f"disk{index}.img"
                with image.open("wb") as stream:
                    # 512 MiB ESP plus an ext4 root needs at least 1 GiB;
                    # use a sparse 2 GiB image so the test remains quick.
                    stream.truncate(2 * 1024 * 1024 * 1024)
                loop = subprocess.check_output(("losetup", "--find", "--show", "--partscan", str(image)), text=True).strip()
                try:
                    result = install_physical(
                        DiskInfo(loop, Path(loop).name, "disk", size_bytes=image.stat().st_size),
                        runtime_package=runtime,
                        expected_package_sha256=runtime_sha,
                        rootfs_tar=rootfs,
                        central_endpoint="https://central.example:8088",
                        installer_version="1.0.0",
                    )
                    self.assertEqual(result["status"], "PASS")
                    outputs.append(result)
                finally:
                    subprocess.run(("losetup", "-d", loop), check=False)
            self.assertEqual(len(outputs), 2)


if __name__ == "__main__":
    unittest.main()
