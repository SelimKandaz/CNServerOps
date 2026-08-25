import tempfile
import unittest
from pathlib import Path

from cndellops_asus.identity import derive_identity
from cndellops_asus.state import StateMismatchError, assert_resume_allowed, load_state, write_state


class IdentityAndStateTests(unittest.TestCase):
    def setUp(self):
        self.identity = derive_identity(
            {"Manufacturer": "ASUSTeK COMPUTER INC.", "Model": "RS700A-E13-RS12U", "SerialNumber": "SYS-1"},
            {"FruInfo": {"Board": {"BoardSerial": "BOARD-1"}, "Chassis": {"ChassisSerial": "CHASSIS-1"}}},
            {"SerialNumber": "BMC-1", "FirmwareVersion": "1.00"},
        )

    def test_identity_uses_multiple_anchors(self):
        self.assertEqual("high", self.identity["confidence"])
        self.assertEqual(4, self.identity["anchor_count"])
        self.assertEqual(64, len(self.identity["fingerprint_sha256"]))

    def test_state_blocks_a_different_server(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "state.json"
            write_state(path, self.identity["fingerprint_sha256"], "DISCOVERED")
            assert_resume_allowed(load_state(path), self.identity["fingerprint_sha256"])
            with self.assertRaises(StateMismatchError):
                assert_resume_allowed(load_state(path), "different-machine")


if __name__ == "__main__":
    unittest.main()
