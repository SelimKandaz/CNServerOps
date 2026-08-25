import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cnserverops.bmc_auth import BmcAuthPolicy, discover_bmc_auth
from cnserverops.bmc_provisioning import BmcProvisioningResult
from cndellops_asus.redfish import RedfishFailureKind, RedfishRequestError


class _Response:
    status = 200


class _ReadyClient:
    def get_json(self, _path):
        return _Response()


class _PasswordChangeClient:
    def get_json(self, path):
        if path == "/redfish/v1/Systems":
            raise RedfishRequestError(
                path,
                RedfishFailureKind.PASSWORD_CHANGE_REQUIRED,
                http_status=403,
            )
        return _Response()


class _FakeClock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.value += max(0.0, float(seconds))


class PostResetRedfishReadinessTests(unittest.TestCase):
    def _policy(self, root: Path, env_name: str) -> BmcAuthPolicy:
        return BmcAuthPolicy(
            default_password_env=env_name,
            default_password_file=root / "missing-default",
            first_login_password_env="CN_TEST_POST_RESET_MISSING_TARGET",
            first_login_password_file=root / "first-login-target",
            provisioned_password_file=root / "secrets" / "operational",
            collect_authenticated_get_only=False,
        )

    def test_transient_unavailable_then_password_change_provisions_exactly_once(self):
        """A persisted same-server reset marker can outlive Redfish startup."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            # Make the server historical to prove the recovery override, used
            # by both immediate recovery and durable marker continuation,
            # remains the sole authorization for the DEFAULT probe.
            run = root / "results" / "runs" / "RUN-OLD"
            run.mkdir(parents=True)
            (run / "run.json").write_text(
                json.dumps({"server": {"server_id": "SERVER-RESET"}}),
                encoding="utf-8",
            )
            target = root / "first-login-target"
            target.write_text("approved-temporary-target\n", encoding="utf-8")
            if os.name != "nt":
                os.chmod(target, 0o600)
            env_name = "CN_TEST_POST_RESET_DEFAULT"
            previous = os.environ.get(env_name)
            os.environ[env_name] = "factory-reference"
            clock = _FakeClock()
            calls = []

            def factory(_host, candidate, _policy):
                calls.append(candidate.kind)
                if calls == ["DEFAULT"]:
                    raise RedfishRequestError(
                        "/redfish/v1/",
                        RedfishFailureKind.TRANSPORT_ERROR,
                    )
                if candidate.kind == "DEFAULT":
                    return _PasswordChangeClient()
                return _ReadyClient()

            provisioned = BmcProvisioningResult(
                status="PROVISIONED",
                account_path="/redfish/v1/AccountService/Accounts/4",
                patch_http_status=204,
                mutation_performed=True,
                password_change_required_before=True,
            )
            try:
                with patch("cnserverops.bmc_auth.time.monotonic", side_effect=clock.monotonic), patch(
                    "cnserverops.bmc_auth.time.sleep", side_effect=clock.sleep
                ), patch(
                    "cnserverops.bmc_auth._provision_with_bounded_retry",
                    return_value=provisioned,
                ) as provision:
                    result = discover_bmc_auth(
                        "192.0.2.40",
                        policy=self._policy(root, env_name),
                        primary_root=root / "results",
                        server_id="SERVER-RESET",
                        allow_default_probe_after_recovery=True,
                        ignore_provisioned_candidates=True,
                        redfish_factory=factory,
                        post_recovery_readiness_timeout_seconds=20,
                        post_recovery_readiness_retry_delay_seconds=5,
                    )
            finally:
                if previous is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = previous

            self.assertEqual("BMC_AUTH_PROVISIONED", result["state"])
            self.assertEqual(["DEFAULT", "DEFAULT", "PROVISIONED"], calls)
            self.assertEqual(1, provision.call_count)
            receipt = result["post_recovery_redfish_readiness"]
            self.assertEqual("READY_FOR_FIRST_LOGIN", receipt["status"])
            self.assertEqual(
                "TRANSIENT_REDFISH_UNAVAILABLE_THEN_PASSWORD_CHANGE_REQUIRED",
                receipt["reason"],
            )
            self.assertEqual(2, receipt["attempt_count"])
            self.assertEqual(1, receipt["retry_count"])
            serialized = json.dumps(result)
            self.assertNotIn("factory-reference", serialized)
            self.assertNotIn("approved-temporary-target", serialized)

    def test_explicit_auth_rejection_is_terminal_without_retry(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env_name = "CN_TEST_POST_RESET_REJECTED_DEFAULT"
            previous = os.environ.get(env_name)
            os.environ[env_name] = "factory-reference"
            calls = []

            def factory(_host, candidate, _policy):
                calls.append(candidate.kind)
                raise RedfishRequestError(
                    "/redfish/v1/Systems",
                    RedfishFailureKind.BLOCKED_BY_AUTH,
                    http_status=401,
                )

            try:
                result = discover_bmc_auth(
                    "192.0.2.41",
                    policy=self._policy(root, env_name),
                    primary_root=root / "results",
                    server_id="SERVER-REJECTED",
                    allow_default_probe_after_recovery=True,
                    ignore_provisioned_candidates=True,
                    redfish_factory=factory,
                )
            finally:
                if previous is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = previous

            self.assertEqual(["DEFAULT"], calls)
            self.assertFalse(result["usable_for_authenticated_get"])
            receipt = result["post_recovery_redfish_readiness"]
            self.assertEqual("TERMINAL_RESPONSE", receipt["status"])
            self.assertEqual("EXPLICIT_AUTHENTICATION_REJECTION", receipt["reason"])
            self.assertEqual(0, receipt["retry_count"])
            self.assertEqual(401, receipt["terminal_http_status"])

    def test_transport_timeout_is_bounded_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env_name = "CN_TEST_POST_RESET_TIMEOUT_DEFAULT"
            previous = os.environ.get(env_name)
            os.environ[env_name] = "factory-reference"
            clock = _FakeClock()
            calls = []

            def factory(_host, candidate, _policy):
                calls.append(candidate.kind)
                raise RedfishRequestError(
                    "/redfish/v1/",
                    RedfishFailureKind.TRANSPORT_ERROR,
                )

            try:
                with patch("cnserverops.bmc_auth.time.monotonic", side_effect=clock.monotonic), patch(
                    "cnserverops.bmc_auth.time.sleep", side_effect=clock.sleep
                ):
                    result = discover_bmc_auth(
                        "192.0.2.42",
                        policy=self._policy(root, env_name),
                        primary_root=root / "results",
                        server_id="SERVER-TIMEOUT",
                        allow_default_probe_after_recovery=True,
                        ignore_provisioned_candidates=True,
                        redfish_factory=factory,
                        post_recovery_readiness_timeout_seconds=10,
                        post_recovery_readiness_retry_delay_seconds=5,
                    )
            finally:
                if previous is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = previous

            self.assertFalse(result["usable_for_authenticated_get"])
            self.assertEqual("APPROVED_AUTHENTICATION_UNAVAILABLE", result["reason"])
            self.assertEqual(["DEFAULT", "DEFAULT", "DEFAULT"], calls)
            receipt = result["post_recovery_redfish_readiness"]
            self.assertEqual("TIMEOUT", receipt["status"])
            self.assertEqual("BOUNDED_REDFISH_READINESS_TIMEOUT", receipt["reason"])
            self.assertEqual(3, receipt["attempt_count"])
            self.assertEqual(2, receipt["retry_count"])
            self.assertEqual(10.0, receipt["elapsed_seconds"])
            self.assertIsNone(receipt["terminal_http_status"])
            self.assertNotIn("provisioning", result)


if __name__ == "__main__":
    unittest.main()
