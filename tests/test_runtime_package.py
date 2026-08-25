import importlib.util
import tempfile
import unittest
from pathlib import Path

from cnserverops import __version__


ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("cnserverops_runtime_package_builder", ROOT / "scripts" / "build_runtime_package.py")
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


class RuntimePackageTests(unittest.TestCase):
    def test_build_reopens_and_validates_finalized_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "runtime.tar.gz"
            receipt = _MODULE.build(ROOT, destination, __version__)
            self.assertEqual("PASS", receipt["package_validation"]["status"])
            self.assertEqual(__version__, receipt["package_validation"]["version"])
            self.assertEqual(receipt["file_count"], receipt["package_validation"]["members"])
            verified = _MODULE.verify_package(destination, expected_version=__version__)
            self.assertEqual("PASS", verified["status"])
            self.assertEqual(receipt["package_sha256"], _MODULE.sha256_file(destination))

    def test_package_verifier_rejects_manifest_runtime_version_disagreement(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "runtime.tar.gz"
            _MODULE.build(ROOT, destination, __version__)
            import tarfile

            tampered = Path(folder) / "tampered.tar.gz"
            with tarfile.open(destination, "r:gz") as source, tarfile.open(tampered, "w:gz") as target:
                for member in source.getmembers():
                    payload = source.extractfile(member).read() if member.isfile() else None
                    if member.name == "release-manifest.json":
                        import json

                        manifest = json.loads(payload.decode("utf-8"))
                        manifest["version"] = "0.0.1"
                        payload = (json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8")
                        member.size = len(payload)
                    target.addfile(member, __import__("io").BytesIO(payload) if payload is not None else None)
            with self.assertRaisesRegex(RuntimeError, "manifest version mismatch"):
                _MODULE.verify_package(tampered, expected_version=__version__)


if __name__ == "__main__":
    unittest.main()
