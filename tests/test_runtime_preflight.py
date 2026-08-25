import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

from cnserverops import __version__
from cnserverops.runtime_preflight import (
    REQUIRED_RELEASE_MEMBERS,
    RuntimePreflightError,
    SYSTEMD_UNIT_NAMES,
    verify_deployment_preflight,
)


ROOT = Path(__file__).resolve().parents[1]


def _stage_runtime(destination: Path) -> None:
    # Import the builder only in this helper so the test validates the same
    # archive format used for the immutable field-runtime artifact.
    import importlib.util

    spec = importlib.util.spec_from_file_location("cnserverops_runtime_package_builder_for_preflight", ROOT / "scripts" / "build_runtime_package.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    package = destination.parent / "runtime.tar.gz"
    module.build(ROOT, package, __version__)
    with tarfile.open(package, "r:gz") as archive:
        archive.extractall(destination, filter="data")


class RuntimePreflightTests(unittest.TestCase):
    def test_staged_immutable_runtime_and_installed_units_are_verified_without_reading_secret(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            release = root / "release"
            release.mkdir()
            _stage_runtime(release)
            config = root / "production.json"
            secret = root / "secrets" / "default-bmc-password"
            secret.parent.mkdir()
            # The sentinel proves preflight does not need to load the value.
            secret.write_text("private-test-sentinel", encoding="utf-8")
            if __import__("os").name != "nt":
                secret.chmod(0o600)
            config.write_text(
                json.dumps(
                    {
                        "bmc_auth_policy": {
                            "default_probe_enabled": True,
                            "default_password_file": str(secret),
                        }
                    }
                ),
                encoding="utf-8",
            )
            systemd = root / "systemd"
            systemd.mkdir()
            for name in SYSTEMD_UNIT_NAMES:
                shutil.copyfile(release / "deployment" / "linux" / name, systemd / name)

            result = verify_deployment_preflight(
                release_root=release,
                config_path=config,
                systemd_root=systemd,
                expected_version=__version__,
            )
            self.assertEqual("PASS", result["status"])
            self.assertEqual("PRESENT_PRIVATE", result["default_bmc_secret"]["status"])
            self.assertEqual(set(SYSTEMD_UNIT_NAMES), set(result["systemd_units"]))
            self.assertNotIn("private-test-sentinel", repr(result))
            self.assertTrue(
                REQUIRED_RELEASE_MEMBERS.issubset(
                    {path.relative_to(release).as_posix() for path in release.rglob("*") if path.is_file()}
                )
            )

    def test_preflight_rejects_missing_configured_default_secret_without_exposing_value(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            release = root / "release"
            release.mkdir()
            _stage_runtime(release)
            config = root / "production.json"
            missing = root / "secrets" / "absent-default-bmc-password"
            config.write_text(
                json.dumps(
                    {
                        "bmc_auth_policy": {
                            "default_probe_enabled": True,
                            "default_password_file": str(missing),
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimePreflightError, "default BMC secret") as captured:
                verify_deployment_preflight(release_root=release, config_path=config)
            self.assertNotIn("password", str(captured.exception).lower().replace("default bmc secret", ""))

    def test_preflight_rejects_installed_unit_that_differs_from_release(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            release = root / "release"
            release.mkdir()
            _stage_runtime(release)
            config = root / "production.json"
            config.write_text(
                json.dumps({"bmc_auth_policy": {"default_probe_enabled": False}}), encoding="utf-8"
            )
            systemd = root / "systemd"
            systemd.mkdir()
            for name in SYSTEMD_UNIT_NAMES:
                shutil.copyfile(release / "deployment" / "linux" / name, systemd / name)
            (systemd / "cnserverops-console.service").write_text("[Unit]\nDescription=tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimePreflightError, "differs from immutable release"):
                verify_deployment_preflight(release_root=release, config_path=config, systemd_root=systemd)

    def test_preflight_ignores_interpreter_bytecode_cache_but_rejects_other_extra_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            release = root / "release"
            release.mkdir()
            _stage_runtime(release)
            config = root / "production.json"
            config.write_text(json.dumps({"bmc_auth_policy": {"default_probe_enabled": False}}), encoding="utf-8")

            cache = release / "cnserverops" / "__pycache__"
            cache.mkdir()
            (cache / "runtime_preflight.cpython-312.pyc").write_bytes(b"generated-cache")
            result = verify_deployment_preflight(release_root=release, config_path=config)
            self.assertEqual("PASS", result["status"])

            (release / "unexpected-runtime-state.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(RuntimePreflightError, "unexpected=unexpected-runtime-state.json"):
                verify_deployment_preflight(release_root=release, config_path=config)


if __name__ == "__main__":
    unittest.main()
