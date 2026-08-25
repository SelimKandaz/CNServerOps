import unittest

from cnserverops.asus import AsusBmcFingerprint, infer_inventory_platform_bmc_generation, select_asus_profile


class AsusProfileTests(unittest.TestCase):
    def test_documented_hint_does_not_activate_generation_adapter(self):
        result = select_asus_profile(
            AsusBmcFingerprint(manufacturer_id="2623", product_id="4499", firmware_version="1.01"),
            documented_generation_hint="ASMB11",
        )
        self.assertEqual("asus_common", result["common_adapter"])
        self.assertEqual("UNKNOWN", result["generation"])
        self.assertEqual("DOCUMENTED_HINT_ONLY", result["generation_status"])
        self.assertEqual("none", result["generation_adapter"])

    def test_runtime_explicit_generation_can_select_small_overlay(self):
        result = select_asus_profile(
            AsusBmcFingerprint(),
            runtime_generation_evidence=["Board management controller: ASMB12-iKVM"],
        )
        self.assertEqual("ASMB12", result["generation"])
        self.assertEqual("asus_asmb12", result["generation_adapter"])
        self.assertFalse(result["mutating_operations_authorized"])

    def test_exact_rs500a_board_profile_infers_asmb11_without_management_fru(self):
        generation, evidence = infer_inventory_platform_bmc_generation(
            {
                "components": [
                    {"category": "SYSTEM", "model": "RS500A-E12-RS12U"},
                    {"category": "MOTHERBOARD", "model": "K14PA-U24 Series"},
                ]
            }
        )
        self.assertEqual("ASMB11", generation)
        self.assertTrue(evidence.startswith("EXACT_ASUS_MODEL_BOARD:"))
