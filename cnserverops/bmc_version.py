"""Parse current ASUS BMC firmware evidence from local IPMI MC output.

The standard IPMI ``Firmware Revision`` field exposes only two components.
ASUS ASMB11/ASMB12 stores the image build component in the first byte of
``Aux Firmware Rev Info``.  Keeping that byte separate previously made a live
``1.02`` controller look older than the exact official ``1.2.37`` package.
This parser combines the fields only for an ASUS controller and retains the
plain revision for all other vendors.
"""

from __future__ import annotations

import re


def parse_ipmi_mc_firmware_version(text: str) -> str:
    """Return the best current firmware version from ``ipmitool mc info``.

    Examples:
      * ASUS ``Firmware Revision: 1.02`` + aux ``0x25`` -> ``1.02.37``
      * ASUS ``1.32`` + aux ``0x00`` -> ``1.32.0``
      * non-ASUS output -> the standard revision unchanged
    """

    payload = str(text or "")
    match = re.search(r"(?im)^Firmware Revision\s*:\s*([^\r\n]+)", payload)
    revision = match.group(1).strip() if match else ""
    if not revision:
        return ""

    manufacturer_id = re.search(r"(?im)^Manufacturer ID\s*:\s*(\d+)", payload)
    manufacturer_name = re.search(r"(?im)^Manufacturer Name\s*:\s*([^\r\n]+)", payload)
    is_asus = bool(
        (manufacturer_id and manufacturer_id.group(1) == "2623")
        or (manufacturer_name and "ASUS" in manufacturer_name.group(1).upper())
    )
    if not is_asus:
        return revision

    # ipmitool prints the four vendor-defined auxiliary bytes on indented
    # lines immediately following this label.  Only the first byte is ASUS'
    # build/release component; the remaining bytes are reserved here.
    aux_block = re.search(
        r"(?ims)^Aux Firmware Rev Info\s*:\s*(.*?)(?=^[A-Za-z][^\r\n:]*\s*:|\Z)",
        payload,
    )
    if not aux_block:
        return revision
    aux_values = re.findall(r"(?i)0x([0-9a-f]{1,2})", aux_block.group(1))
    if not aux_values:
        return revision

    numbers = re.findall(r"\d+", revision)
    if len(numbers) != 2:
        return revision
    return f"{revision}.{int(aux_values[0], 16)}"


def versions_equivalent(left: str, right: str) -> bool:
    """Compare vendor versions while ignoring leading/trailing zero spelling."""

    def key(value: str) -> tuple[int, ...]:
        numbers = [int(item) for item in re.findall(r"\d+", str(value or ""))]
        while len(numbers) > 1 and numbers[-1] == 0:
            numbers.pop()
        return tuple(numbers)

    return bool(key(left)) and key(left) == key(right)
