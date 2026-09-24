"""Evidence-boundary helpers that prevent credential material from being persisted."""

from __future__ import annotations

import re
from typing import Any, Mapping


_SENSITIVE_KEY = re.compile(
    r"(^|[_ .-])(password|passwd|credential|secret|token|authorization|cookie|private[_ -]?key|api[_ -]?key|community[_ -]?string)($|[_ .-])",
    re.IGNORECASE,
)


class SensitiveEvidenceError(ValueError):
    """Raised when evidence still contains a credential-sensitive field."""


def sanitize_evidence(value: Any) -> Any:
    """Return a recursively sanitized copy suitable for evidence output."""

    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            sanitized[name] = "<REDACTED>" if _SENSITIVE_KEY.search(name) else sanitize_evidence(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_evidence(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_evidence(item) for item in value)
    return value


def assert_no_sensitive_fields(value: Any, *, path: str = "root") -> None:
    """Reject structures whose field names indicate reusable secret material."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key)
            if _SENSITIVE_KEY.search(name):
                raise SensitiveEvidenceError(f"Credential-sensitive field rejected at {path}.{name}")
            assert_no_sensitive_fields(item, path=f"{path}.{name}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            assert_no_sensitive_fields(item, path=f"{path}[{index}]")
