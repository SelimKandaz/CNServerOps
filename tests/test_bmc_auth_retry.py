import unittest
from unittest.mock import patch

from cnserverops.bmc_auth import _provision_with_bounded_retry
from cnserverops.bmc_provisioning import BmcProvisioningError, BmcProvisioningResult


class BmcAuthRetryTests(unittest.TestCase):
    def test_first_login_patch_retries_transient_redfish_403(self):
        success = BmcProvisioningResult(
            status="PROVISIONED",
            account_path="/redfish/v1/AccountService/Accounts/4",
            patch_http_status=204,
            mutation_performed=True,
        )
        transient = BmcProvisioningError("ACCOUNT_PATCH_IF_MATCH_ETAG", http_status=403)
        with patch(
            "cnserverops.bmc_auth.provision_bmc_password",
            side_effect=[transient, success],
        ) as provision:
            result = _provision_with_bounded_retry(
                "172.16.50.247",
                "admin",
                "factory-secret",
                "temporary-secret",
                verify_tls=False,
                account_path="/redfish/v1/AccountService/Accounts/4",
                attempts=2,
                retry_delay_seconds=0,
            )
        self.assertEqual("PROVISIONED", result.status)
        self.assertEqual(2, provision.call_count)


if __name__ == "__main__":
    unittest.main()
