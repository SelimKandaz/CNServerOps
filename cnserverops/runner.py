"""Stable production SSD/runtime identity, separate from server and run identity."""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

from .models import utc_now, validate_runner_id


class RunnerIdentityError(RuntimeError):
    pass


def bootstrap_runner(
    path: Path,
    *,
    runner_id: str,
    runtime_version: str,
    local_runner_uuid: str = "",
    storage_fingerprint_sha256: str = "",
) -> dict[str, Any]:
    normalized = validate_runner_id(runner_id)
    if path.exists():
        existing = load_runner(path)
        if existing["runner_id"] != normalized:
            raise RunnerIdentityError("Runner identity already exists and cannot be silently changed")
        if storage_fingerprint_sha256 and existing.get("storage_fingerprint_sha256") not in {"", storage_fingerprint_sha256}:
            raise RunnerIdentityError("DUPLICATE_RUNNER_STORAGE_MISMATCH")
        return existing
    if storage_fingerprint_sha256 and (
        len(storage_fingerprint_sha256) != 64
        or any(character not in "0123456789abcdef" for character in storage_fingerprint_sha256.lower())
    ):
        raise RunnerIdentityError("Runner storage fingerprint must be a SHA256 value")
    if local_runner_uuid:
        try:
            parsed_uuid = str(uuid.UUID(local_runner_uuid))
        except ValueError as exc:
            raise RunnerIdentityError("Local runner UUID is invalid") from exc
    else:
        parsed_uuid = str(uuid.uuid4())
    payload = {
        "schema_version": 1,
        "runner_id": normalized,
        "local_runner_uuid": parsed_uuid,
        "storage_fingerprint_sha256": storage_fingerprint_sha256.lower(),
        "created_at_utc": utc_now(),
        "runtime_version": str(runtime_version),
    }
    _atomic_json(path, payload)
    return payload


def load_runner(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RunnerIdentityError("Runner identity must be a JSON object")
    payload["runner_id"] = validate_runner_id(str(payload.get("runner_id") or ""))
    if not payload.get("runtime_version"):
        raise RunnerIdentityError("Runner identity is missing runtime version")
    if payload.get("local_runner_uuid"):
        try:
            payload["local_runner_uuid"] = str(uuid.UUID(str(payload["local_runner_uuid"])))
        except ValueError as exc:
            raise RunnerIdentityError("Runner identity has an invalid local runner UUID") from exc
    storage = str(payload.get("storage_fingerprint_sha256") or "").lower()
    if storage and (len(storage) != 64 or any(character not in "0123456789abcdef" for character in storage)):
        raise RunnerIdentityError("Runner identity has an invalid storage fingerprint")
    payload["storage_fingerprint_sha256"] = storage
    return payload


def update_runtime_version(path: Path, *, runner_id: str, runtime_version: str) -> dict[str, Any]:
    payload = load_runner(path)
    if payload["runner_id"] != validate_runner_id(runner_id):
        raise RunnerIdentityError("Runtime update approval is bound to a different runner")
    payload["runtime_version"] = str(runtime_version)
    payload["updated_at_utc"] = utc_now()
    _atomic_json(path, payload)
    return payload


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path = Path(temporary_name)
        for attempt in range(10):
            try:
                temporary_path.replace(path)
                break
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
