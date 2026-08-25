import io
import os
import socket
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from cndellops_asus.redfish import (
    ReadOnlyRedfishClient,
    RedfishCredentials,
    RedfishFailureKind,
    RedfishRequestError,
    credentials_from_runtime,
)


class FakeResponse:
    status = 200

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.body


class RedfishSecurityTests(unittest.TestCase):
    def test_secret_is_not_in_repr_or_public_status(self):
        credential = RedfishCredentials(username="reader", password="fixture-secret", source="test")
        self.assertNotIn("fixture-secret", repr(credential))
        self.assertNotIn("fixture-secret", str(credential.public_status()))

    def test_environment_credential_is_resolved_but_not_exposed(self):
        with patch.dict(os.environ, {"TEST_BMC_PASSWORD": "fixture-secret"}, clear=False):
            credential = credentials_from_runtime(username="reader", password_env="TEST_BMC_PASSWORD")
        self.assertTrue(credential.available)
        self.assertEqual("USERNAME_PASSWORD", credential.public_status()["mode"])
        self.assertNotIn("fixture-secret", str(credential.public_status()))

    def test_credentials_in_bmc_url_are_rejected(self):
        with self.assertRaises(ValueError):
            ReadOnlyRedfishClient("https://reader:@bmc.example")

    def test_http_401_is_structured_and_sanitized(self):
        error = HTTPError("https://bmc/redfish/v1/Systems", 401, "Unauthorized", {}, io.BytesIO(b"secret body"))
        client = ReadOnlyRedfishClient("bmc.example", credentials=RedfishCredentials("reader", "fixture-secret"))
        with patch("cndellops_asus.redfish.urlopen", side_effect=error):
            with self.assertRaises(RedfishRequestError) as captured:
                client.get_json("/redfish/v1/Systems")
        self.assertEqual(RedfishFailureKind.BLOCKED_BY_AUTH, captured.exception.kind)
        self.assertNotIn("fixture-secret", str(captured.exception))
        self.assertNotIn("secret body", str(captured.exception))

    def test_malformed_payload_and_timeout_are_explicit(self):
        client = ReadOnlyRedfishClient("bmc.example")
        with patch("cndellops_asus.redfish.urlopen", return_value=FakeResponse(b"not-json")):
            with self.assertRaises(RedfishRequestError) as malformed:
                client.get_json("/redfish/v1/")
        self.assertEqual(RedfishFailureKind.MALFORMED_RESPONSE, malformed.exception.kind)
        with patch("cndellops_asus.redfish.urlopen", side_effect=socket.timeout()):
            with self.assertRaises(RedfishRequestError) as timeout:
                client.get_json("/redfish/v1/")
        self.assertEqual(RedfishFailureKind.TIMEOUT, timeout.exception.kind)


if __name__ == "__main__":
    unittest.main()
