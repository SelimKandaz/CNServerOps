"""Identity-bound workflow state that cannot resume on a different server."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


class StateMismatchError(RuntimeError):
    """Persisted state belongs to another machine and must not be resumed."""


def load_state(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def assert_resume_allowed(existing: dict[str, Any] | None, current_fingerprint: str) -> None:
    if not existing:
        return
    recorded = str(existing.get("machine_fingerprint_sha256") or "")
    if not recorded or recorded != current_fingerprint:
        raise StateMismatchError(
            "Persisted workflow state does not belong to the currently discovered server; refusing resume."
        )


def write_state(path: Path, fingerprint: str, phase: str, details: dict[str, Any] | None = None) -> None:
    """Atomically persist state under an operator-chosen output directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "machine_fingerprint_sha256": fingerprint,
        "phase": phase,
        "details": details or {},
    }
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
