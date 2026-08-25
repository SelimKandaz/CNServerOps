from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from installer.build_ssd_installer_bundle import build_bundle
from tests.test_ssd_installer import _make_runtime_package


class SsdInstallerBundleTests(unittest.TestCase):
    def test_bundle_contains_hash_manifest_and_offline_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            runtime, _ = _make_runtime_package(workspace)
            rootfs = workspace / "rootfs.tar"
            with tarfile.open(rootfs, "w") as archive:
                info = tarfile.TarInfo(".")
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
                value = b"clean-rootfs-marker\n"
                info = tarfile.TarInfo("etc/cnserverops-rootfs-marker")
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
            output = workspace / "cnserverops-installer.tar.gz"
            result = build_bundle(
                installer_dir=Path(__file__).parents[1] / "installer",
                runtime_package=runtime,
                rootfs_tar=rootfs,
                output=output,
            )
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(output.is_file())
            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())
                self.assertIn("bundle-manifest.json", names)
                self.assertIn("payload/runtime.tar.gz", names)
                self.assertIn("payload/runtime.tar.gz.json", names)
                self.assertIn("payload/rootfs.tar", names)
                manifest = json.loads(archive.extractfile("bundle-manifest.json").read())
                self.assertTrue(manifest["immutable"])
                self.assertEqual(manifest["runtime_package_sha256"], result["runtime_package_sha256"])
                for name, expected in manifest["files"].items():
                    self.assertIn(name, names)
                    self.assertEqual(expected, __import__("hashlib").sha256(archive.extractfile(name).read()).hexdigest())


if __name__ == "__main__":
    unittest.main()
