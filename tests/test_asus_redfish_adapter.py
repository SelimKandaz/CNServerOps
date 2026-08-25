import unittest

from cndellops_asus.asus import AsusDiscoveryAdapter
from cndellops_asus.redfish import RedfishRequestError, RedfishResponse


class FakeReadOnlyClient:
    timeout_seconds = 2

    def __init__(self):
        self.calls = []
        self.payloads = {
            "/redfish/v1/": {
                "Systems": {"@odata.id": "/redfish/v1/Systems"},
                "Managers": {"@odata.id": "/redfish/v1/Managers"},
                "Chassis": {"@odata.id": "/redfish/v1/Chassis"},
            },
            "/redfish/v1/Systems": {"Members": [{"@odata.id": "/redfish/v1/Systems/Self"}]},
            "/redfish/v1/Managers": {"Members": [{"@odata.id": "/redfish/v1/Managers/Self"}]},
            "/redfish/v1/Chassis": {"Members": [{"@odata.id": "/redfish/v1/Chassis/Self"}]},
            "/redfish/v1/Systems/Self": {
                "Manufacturer": "ASUSTeK COMPUTER INC.",
                "Model": "RS700A-E13-RS12U",
                "SerialNumber": "ASUS123",
            },
            "/redfish/v1/Managers/Self": {"FirmwareVersion": "fixture"},
            "/redfish/v1/Chassis/Self": {},
        }

    def get_json(self, path):
        self.calls.append(("GET", path))
        if path not in self.payloads:
            raise RedfishRequestError(f"{path}: fixture endpoint unsupported")
        return RedfishResponse(path=path, status=200, payload=self.payloads[path])


class AsusRedfishAdapterTests(unittest.TestCase):
    def test_missing_optional_endpoints_do_not_abort_discovery(self):
        client = FakeReadOnlyClient()
        result = AsusDiscoveryAdapter(client).discover()
        self.assertEqual("asus_common_redfish_read_only", result["adapter"])
        self.assertEqual("ASUS123", result["identity"]["system_serial"])
        self.assertTrue(result["collection_errors"])
        self.assertTrue(result["capability_records"])
        self.assertEqual({"GET"}, {method for method, _ in client.calls})
        requested = {path for _, path in client.calls}
        self.assertIn("/redfish/v1/EventService", requested)
        self.assertIn("/redfish/v1/TelemetryService", requested)
        self.assertIn("/redfish/v1/UpdateService", requested)
        self.assertEqual(["GET"], result["safety"]["methods_issued"])
        self.assertEqual("not implemented", result["safety"]["firmware_actions"])
        self.assertTrue(all(not item["safe_for_production"] for item in result["capability_records"]))


if __name__ == "__main__":
    unittest.main()
