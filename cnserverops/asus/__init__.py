"""ASUS common capability layer and optional generation overlays."""

from .profiles import (
    AsusBmcFingerprint,
    infer_exact_platform_bmc_generation,
    infer_inventory_platform_bmc_generation,
    select_asus_profile,
)

__all__ = [
    "AsusBmcFingerprint",
    "infer_exact_platform_bmc_generation",
    "infer_inventory_platform_bmc_generation",
    "select_asus_profile",
]
