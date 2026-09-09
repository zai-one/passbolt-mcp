from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

REDACTED = "***redacted***"
TRUNCATED = "***truncated***"

_SENSITIVE_KEY_PARTS = frozenset(
    {
        "apikey",
        "authorization",
        "clientsecret",
        "cookie",
        "credential",
        "password",
        "passwd",
        "privatekey",
        "refreshtoken",
        "secret",
        "session",
        "setcookie",
        "token",
    }
)
# Contract fields that merely describe secret handling and never carry secret
# material themselves. Matched on the normalized key, exact form only.
_PRESERVED_EXACT_KEYS = frozenset(
    {
        "secretdisclosed",
    }
)
_BEARER_PATTERN = re.compile(r"(?i)(\bbearer\s+)[^\s,;]+")
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(\b(?:access[_-]?token|api[_-]?key|authorization|client[_-]?secret|password|passwd|private[_-]?key|refresh[_-]?token|secret|session|token)\s*[=:]\s*)([^\s&,;]+)"
)


@dataclass(frozen=True, slots=True)
class SanitizerLimits:
    """Bounds for pathological payloads only.

    Transport-level byte caps (JsonHttpClient/adapters) are the primary size
    boundary; these defaults must stay far above any legitimate provider
    response (crawl4ai HTML/markdown, base64 screenshots, Direct statistics
    rows) so sanitization never silently destroys real data.
    """

    max_depth: int = 24
    max_items: int = 500_000
    max_string_chars: int = 25_000_000
    max_key_chars: int = 256

    def __post_init__(self) -> None:
        if min(self.max_depth, self.max_items, self.max_string_chars, self.max_key_chars) < 1:
            raise ValueError("response sanitizer limits must be positive")


# Durable job results are paid and unrecoverable: redact but effectively never
# truncate (the HTTP transport cap already bounds what can get here).
DURABLE_SANITIZER_LIMITS = SanitizerLimits(
    max_depth=64,
    max_items=5_000_000,
    max_string_chars=30_000_000,
)


def _normalized_key(key: str) -> str:
    return "".join(character for character in key.lower() if character.isalnum())


def _is_sensitive_key(key: str) -> bool:
    normalized = _normalized_key(key)
    if normalized in _PRESERVED_EXACT_KEYS:
        return False
    return any(marker in normalized for marker in _SENSITIVE_KEY_PARTS)


def _sanitize_string(value: str, limit: int) -> str:
    sanitized = _BEARER_PATTERN.sub(r"\1***redacted***", value)
    sanitized = _ASSIGNMENT_PATTERN.sub(r"\1***redacted***", sanitized)
    if len(sanitized) > limit:
        return f"{sanitized[:limit]}{TRUNCATED}"
    return sanitized


def sanitize_provider_response(
    value: Any,
    *,
    limits: SanitizerLimits | None = None,
) -> Any:
    """Return a bounded, JSON-safe copy of an untrusted provider response.

    Secret-bearing fields and common inline credential forms are redacted. The
    traversal is depth/item bounded and handles cycles without returning object
    representations that could themselves contain credentials.
    """

    effective = limits or SanitizerLimits()
    remaining = effective.max_items
    active: set[int] = set()

    def visit(item: Any, depth: int) -> Any:
        nonlocal remaining
        if depth > effective.max_depth:
            return TRUNCATED
        if item is None or isinstance(item, bool | int | float):
            return item
        if isinstance(item, str):
            return _sanitize_string(item, effective.max_string_chars)
        if isinstance(item, bytes | bytearray | memoryview):
            return "***binary-redacted***"

        if isinstance(item, Mapping):
            identity = id(item)
            if identity in active:
                return "***cycle-redacted***"
            active.add(identity)
            sanitized_mapping: dict[str, Any] = {}
            try:
                for raw_key, child in item.items():
                    if remaining <= 0:
                        sanitized_mapping["__truncated__"] = TRUNCATED
                        break
                    remaining -= 1
                    full_key = str(raw_key)
                    key = _sanitize_string(full_key, effective.max_key_chars)
                    # Sensitivity is decided on the full key: truncation must
                    # not let an over-long key smuggle its marker past the cut.
                    if _is_sensitive_key(full_key) and not (child is None or isinstance(child, bool)):
                        # Booleans/None under a sensitive-looking key are flags
                        # about secrets, never secret material itself.
                        sanitized_mapping[key] = REDACTED
                    else:
                        sanitized_mapping[key] = visit(child, depth + 1)
            finally:
                active.remove(identity)
            return sanitized_mapping

        if isinstance(item, Sequence):
            identity = id(item)
            if identity in active:
                return "***cycle-redacted***"
            active.add(identity)
            sanitized_sequence: list[Any] = []
            try:
                for child in item:
                    if remaining <= 0:
                        sanitized_sequence.append(TRUNCATED)
                        break
                    remaining -= 1
                    sanitized_sequence.append(visit(child, depth + 1))
            finally:
                active.remove(identity)
            return sanitized_sequence

        return f"***unsupported:{type(item).__name__}***"

    return visit(value, 0)
