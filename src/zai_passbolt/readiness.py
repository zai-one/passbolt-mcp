"""Request-local, closed-vocabulary diagnostics. Never accept provider text."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

STAGES = frozenset(
    {
        "configuration",
        "resource_fetch",
        "resource_shape",
        "canary_select",
        "metadata_key_fetch",
        "metadata_key_envelope",
        "metadata_key_decrypt",
        "metadata_key_trust",
        "metadata_key_import",
        "metadata_key_select",
        "metadata_decrypt",
        "metadata_validate",
        "secret_fetch",
        "secret_decrypt",
        "secret_validate",
        "unknown",
    }
)
REASONS = frozenset(
    {
        "custody_not_configured",
        "provider_error",
        "invalid_response",
        "no_resources",
        "resource_id_missing",
        "invalid_envelope",
        "object_type_mismatch",
        "domain_mismatch",
        "fingerprint_mismatch",
        "fingerprint_not_pinned",
        "embedded_passphrase",
        "private_key_missing",
        "import_fingerprint_mismatch",
        "multiple_active_keys",
        "metadata_private_keys_unavailable",
        "requested_metadata_key_unavailable",
        "invalid_metadata",
        "secret_payload_missing",
        "empty_secret",
        "gpg_unavailable",
        "gpg_operation_failed",
        "gpg_signer_mismatch",
        "gpg_runtime_unavailable",
        "decrypted_payload_invalid",
        "unknown",
    }
)


@dataclass
class ReadinessTrace:
    stage: str = "configuration"
    reason: str = "custody_not_configured"


_TRACE: ContextVar[ReadinessTrace | None] = ContextVar("passbolt_readiness_trace", default=None)


@contextmanager
def readiness_trace() -> Iterator[ReadinessTrace]:
    trace = ReadinessTrace()
    token = _TRACE.set(trace)
    try:
        yield trace
    finally:
        _TRACE.reset(token)


def probe_step(stage: str, reason: str) -> None:
    trace = _TRACE.get()
    if trace is not None:
        trace.stage = stage if stage in STAGES else "unknown"
        trace.reason = reason if reason in REASONS else "unknown"


def probe_reason(reason: str) -> None:
    trace = _TRACE.get()
    if trace is not None:
        trace.reason = reason if reason in REASONS else "unknown"


def log_probe_failure(logger: logging.Logger, code: str, trace: ReadinessTrace) -> None:
    # Defense in depth: no exception object/type name, provider text or arbitrary extra.
    logger.warning(
        "Passbolt readiness probe failed",
        extra={
            "provider": "passbolt",
            "operation": "status",
            "error_code": code
            if code
            in {
                "custody_not_configured",
                "auth_probe_failed",
                "decrypt_canary_failed",
            }
            else "decrypt_canary_failed",
            "probe_stage": trace.stage if trace.stage in STAGES else "unknown",
            "probe_reason": trace.reason if trace.reason in REASONS else "unknown",
        },
    )
