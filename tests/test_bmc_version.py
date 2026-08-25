from __future__ import annotations

import unittest

from cnserverops.bmc_version import parse_ipmi_mc_firmware_version, versions_equivalent


class AsusBmcVersionTests(unittest.TestCase):
    def test_asmb11_aux_build_is_combined_with_ipmi_revision(self) -> None:
        output = """\
Firmware Revision         : 1.02
Manufacturer ID           : 2623
Manufacturer Name         : ASUSTek Computer Inc.
Aux Firmware Rev Info     :
    0x25
    0x00
    0x00
    0x00
"""
        self.assertEqual("1.02.37", parse_ipmi_mc_firmware_version(output))
        self.assertTrue(versions_equivalent("1.02.37", "1.2.37"))

    def test_asmb12_zero_aux_is_equivalent_to_catalog_spelling(self) -> None:
        output = """\
Firmware Revision         : 1.32
Manufacturer ID           : 2623
Aux Firmware Rev Info     :
    0x00
    0x00
    0x00
    0x00
"""
        self.assertEqual("1.32.0", parse_ipmi_mc_firmware_version(output))
        self.assertTrue(versions_equivalent("1.32.0", "1.32"))

    def test_non_asus_aux_is_not_interpreted(self) -> None:
        output = """\
Firmware Revision         : 3.40
Manufacturer ID           : 9999
Manufacturer Name         : Example Vendor
Aux Firmware Rev Info     :
    0x25
"""
        self.assertEqual("3.40", parse_ipmi_mc_firmware_version(output))


if __name__ == "__main__":
    unittest.main()
