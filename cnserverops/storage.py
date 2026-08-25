"""Storage policy checks for primary results, CN_EXPORT, and boot-only EFI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import shutil
from typing import Any


class StoragePolicyError(ValueError):
    pass


class InsufficientDiskSpaceError(OSError):
    pass


@dataclass(frozen=True)
class StoragePolicy:
    primary_results_root: Path = Path("/CN_STRESS_RESULTS")
    export_root: Path = Path("/mnt/cn_export")
    efi_root: Path = Path("/boot/efi")

    def validate(self) -> None:
        primary = self.primary_results_root.resolve()
        export = self.export_root.resolve()
        efi = self.efi_root.resolve()
        if primary == export:
            raise StoragePolicyError("Primary results and CN_EXPORT must be separate roots.")
        if _inside(primary, efi):
            raise StoragePolicyError("Primary results must not live on EFI.")
        if _inside(export, efi):
            raise StoragePolicyError("CN_EXPORT must not live on EFI.")

    def to_dict(self) -> dict[str, Any]:
        return {key: str(value) for key, value in asdict(self).items()}


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def ensure_free_space(path: Path, *, required_bytes: int, reserve_bytes: int = 64 * 1024 * 1024) -> None:
    """Fail before collection/export when the target cannot hold the expected artifact."""
    if required_bytes < 0 or reserve_bytes < 0:
        raise ValueError("Disk-space requirements must be non-negative")
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    free = shutil.disk_usage(probe).free
    if free < required_bytes + reserve_bytes:
        raise InsufficientDiskSpaceError(
            f"Insufficient space at {path}: require {required_bytes + reserve_bytes} bytes including reserve; {free} available"
        )
