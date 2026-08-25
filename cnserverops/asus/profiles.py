"""Select ASUS generation overlays only from explicit evidence.

Model documentation can provide a useful hint, but never activates a generation-specific
implementation by itself. The shared ASUS adapter remains the base for every generation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class AsusBmcFingerprint:
    manufacturer_id: str = ""
    product_id: str = ""
    firmware_version: str = ""
    redfish_version: str = ""
    redfish_vendor: str = ""
    redfish_product: str = ""
    redfish_oem_runtime: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


# Exact ASUS platform contracts for which the management generation is
# independently documented/physically validated.  This is intentionally an
# allow-list of complete model + board pairs: a family name, firmware version,
# or a partial model never selects a generation-specific mutator.
_EXACT_PLATFORM_BMC_GENERATIONS: tuple[tuple[str, str, str], ...] = (
    ("RS500A-E12-RS12U", "K14PA-U24", "ASMB11"),
    ("RS700-E12-RS12U", "Z14PP-D32", "ASMB12"),
)


def infer_exact_platform_bmc_generation(*, model: str = "", board: str = "") -> tuple[str, str]:
    """Return ``(generation, evidence)`` for an exact known ASUS contract.

    The returned generation is only authoritative when both model and board
    match one complete contract.  ``evidence`` is a stable, secret-free
    provenance label suitable for capability records.
    """
    clean_model = " ".join(str(model or "").replace("_", "-").split()).upper()
    clean_board = " ".join(str(board or "").replace("_", "-").split()).upper()
    clean_board = clean_board.removesuffix(" SERIES").strip()
    for known_model, known_board, generation in _EXACT_PLATFORM_BMC_GENERATIONS:
        if clean_model == known_model and clean_board == known_board:
            return generation, f"EXACT_ASUS_MODEL_BOARD:{known_model}+{known_board}"
    return "", ""


def infer_inventory_platform_bmc_generation(normalized_inventory: Mapping[str, Any]) -> tuple[str, str]:
    """Infer a generation from current normalized inventory only.

    Explicit runtime/component evidence is preferred.  If an older/blank FRU
    omits the management-module component, the exact model+motherboard
    contract is used as a bounded fallback, never a family or version guess.
    """
    direct = " ".join(
        str(normalized_inventory.get(key) or "")
        for key in ("bmc_generation", "management_model", "bmc_model")
    )
    import re
    match = re.search(r"\bASMB\s*(\d+)\b", direct, re.IGNORECASE)
    if match:
        return f"ASMB{match.group(1)}", "EXPLICIT_NORMALIZED_BMC_EVIDENCE"
    model = str(normalized_inventory.get("model") or normalized_inventory.get("product_name") or "")
    board = str(normalized_inventory.get("board") or normalized_inventory.get("board_name") or "")
    for item in normalized_inventory.get("components") or ():
        if not isinstance(item, Mapping):
            continue
        category = str(item.get("category") or "").upper()
        if category == "SYSTEM" and not model:
            model = str(item.get("model") or "")
        elif category == "MOTHERBOARD" and not board:
            board = str(item.get("model") or "")
        text = " ".join(str(item.get(key) or "") for key in ("model", "manufacturer", "slot", "location"))
        match = re.search(r"\bASMB\s*(\d+)\b", text, re.IGNORECASE)
        if match and category in {"MANAGEMENT_MODULE", "BMC"}:
            return f"ASMB{match.group(1)}", f"EXPLICIT_COMPONENT_BMC_EVIDENCE:{category}"
    return infer_exact_platform_bmc_generation(model=model, board=board)


def select_asus_profile(
    fingerprint: AsusBmcFingerprint,
    *,
    runtime_generation_evidence: Iterable[str] = (),
    documented_generation_hint: str = "",
) -> dict[str, Any]:
    evidence = " ".join(str(value) for value in runtime_generation_evidence).upper()
    explicit: list[str] = []
    if "ASMB11" in evidence:
        explicit.append("ASMB11")
    if "ASMB12" in evidence:
        explicit.append("ASMB12")

    if len(explicit) == 1:
        generation = explicit[0]
        generation_status = "RUNTIME_EXPLICIT"
        generation_adapter = f"asus_{generation.lower()}"
    elif len(explicit) > 1:
        generation = "CONFLICT"
        generation_status = "CONFLICT"
        generation_adapter = "none"
    else:
        generation = "UNKNOWN"
        generation_status = "DOCUMENTED_HINT_ONLY" if documented_generation_hint else "UNKNOWN"
        generation_adapter = "none"

    return {
        "schema_version": 1,
        "common_adapter": "asus_common",
        "generation": generation,
        "generation_status": generation_status,
        "generation_adapter": generation_adapter,
        "documented_generation_hint": documented_generation_hint.upper(),
        "documented_hint_activates_adapter": False,
        "fingerprint": fingerprint.to_dict(),
        "mutating_operations_authorized": False,
    }
