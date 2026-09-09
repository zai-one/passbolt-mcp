from __future__ import annotations

import asyncio
import contextvars
import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, NoReturn

import httpx

from zai_passbolt.sanitizer import SanitizerLimits, sanitize_provider_response


class ProviderError(RuntimeError):
    pass


class ProviderRateLimited(ProviderError):
    def __init__(self, message: str, *, retry_after_seconds: int | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class ProviderAdmissionDenied(ProviderRateLimited):
    """The governor refused an additional network attempt; never retried locally."""


class LocalPreDispatchDenied(ProviderAdmissionDenied):
    """Standalone-only proof: this factory admitted no network request."""


# Set by the provider governor around each logical call so every real network
# retry consumes durable RPM admission instead of multiplying a single permit.
retry_attempt_admission: contextvars.ContextVar[Callable[[], Awaitable[bool]] | None] = (
    contextvars.ContextVar("retry_attempt_admission", default=None)
)


class ProviderHttpError(ProviderError):
    def __init__(self, status_code: int, *, body_preview: str | None = None) -> None:
        super().__init__(f"provider returned HTTP {status_code}")
        self.status_code = status_code
        self.body_preview = body_preview


class ProviderAuthenticationError(ProviderHttpError):
    pass


class ProviderNotFoundError(ProviderHttpError):
    pass


class ProviderTimeoutError(ProviderError):
    pass


class ProviderTransportError(ProviderError):
    pass


class ProviderTransientHttpError(ProviderHttpError):
    pass


class ProviderResponseError(ProviderError):
    pass


class ProviderRequestError(ProviderError):
    pass


class ProviderRequestTooLarge(ProviderRequestError):
    pass


class ProviderResponseTooLarge(ProviderResponseError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def request_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def redact(value: Any) -> Any:
    sensitive = {"authorization", "token", "password", "secret", "api_key", "session"}
    if isinstance(value, dict):
        return {
            key: "***redacted***" if any(marker in key.lower() for marker in sensitive) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    attempts: int = 3
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 10.0


@dataclass(frozen=True, slots=True)
class RawHttpResponse:
    status_code: int
    headers: dict[str, str]
    body: str


class JsonHttpClient:
    ERROR_PREVIEW_MAX_BYTES = 8 * 1024
    ERROR_SANITIZER_LIMITS = SanitizerLimits(
        max_depth=8,
        max_items=128,
        max_string_chars=2048,
        max_key_chars=128,
    )

    def __init__(
        self,
        *,
        timeout: float = 60.0,
        retry: RetryPolicy | None = None,
        max_request_bytes: int = 2 * 1024 * 1024,
        max_response_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        self.timeout = timeout
        self.retry = retry or RetryPolicy()
        if max_request_bytes <= 0 or max_response_bytes <= 0:
            raise ValueError("HTTP byte limits must be positive")
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes

    @staticmethod
    def _rate_limit_error(response: httpx.Response) -> ProviderRateLimited:
        value = response.headers.get("Retry-After", "").strip()
        retry_after = int(value) if value.isdigit() else None
        suffix = f" retry_after={retry_after}" if retry_after is not None else ""
        return ProviderRateLimited(f"provider returned HTTP 429{suffix}", retry_after_seconds=retry_after)

    def _retry_delay(self, attempt: int, exc: Exception) -> float | None:
        exponential: float = min(
            float(self.retry.max_delay_seconds),
            float(self.retry.base_delay_seconds * (2 ** (attempt - 1))),
        )
        if isinstance(exc, ProviderRateLimited) and exc.retry_after_seconds is not None:
            if exc.retry_after_seconds > self.retry.max_delay_seconds:
                return None
            retry_after = float(exc.retry_after_seconds)
            return exponential if exponential >= retry_after else retry_after
        return exponential

    @staticmethod
    def _raise_final(last_error: Exception | None) -> NoReturn:
        if isinstance(last_error, ProviderError):
            raise last_error
        if isinstance(last_error, httpx.TimeoutException):
            raise ProviderTimeoutError("provider request timed out") from last_error
        if isinstance(last_error, httpx.TransportError):
            raise ProviderTransportError("provider transport failed") from last_error
        raise ProviderError(str(last_error or "provider request failed"))

    @classmethod
    def _error_body_preview(cls, response: httpx.Response) -> str | None:
        if not response.content:
            return None
        try:
            value: Any = response.json()
        except ValueError:
            value = response.text
        sanitized = sanitize_provider_response(value, limits=cls.ERROR_SANITIZER_LIMITS)
        preview = canonical_json(sanitized)
        encoded = preview.encode("utf-8")
        if len(encoded) <= cls.ERROR_PREVIEW_MAX_BYTES:
            return preview
        marker = "***truncated***"
        available = cls.ERROR_PREVIEW_MAX_BYTES - len(marker.encode("utf-8"))
        prefix = encoded[:available].decode("utf-8", errors="ignore")
        return f"{prefix}{marker}"

    @classmethod
    def _http_error(cls, response: httpx.Response) -> ProviderHttpError:
        status_code = response.status_code
        body_preview = cls._error_body_preview(response)
        if status_code in {401, 403}:
            return ProviderAuthenticationError(status_code, body_preview=body_preview)
        if status_code == 404:
            return ProviderNotFoundError(status_code, body_preview=body_preview)
        if status_code >= 500:
            return ProviderTransientHttpError(status_code, body_preview=body_preview)
        return ProviderHttpError(status_code, body_preview=body_preview)

    @staticmethod
    def _method_is_retry_safe(method: str, *, idempotent: bool) -> bool:
        return idempotent or method.upper() in {"GET", "HEAD", "OPTIONS"}

    def _validate_request_size(self, payload: dict[str, Any] | None, params: dict[str, Any] | None) -> None:
        value = {"payload": payload, "params": params}
        try:
            size = len(canonical_json(value).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ProviderRequestError("provider request is not JSON serializable") from exc
        if size > self.max_request_bytes:
            raise ProviderRequestTooLarge("provider request exceeded the configured byte limit")

    def _validate_response_size(self, response: httpx.Response) -> None:
        length = response.headers.get("Content-Length", "").strip()
        if length.isdigit() and int(length) > self.max_response_bytes:
            raise ProviderResponseTooLarge("provider response exceeded the configured byte limit")
        if len(response.content) > self.max_response_bytes:
            raise ProviderResponseTooLarge("provider response exceeded the configured byte limit")

    @staticmethod
    def _retryable(exc: Exception, *, method: str, idempotent: bool) -> bool:
        if isinstance(exc, ProviderAdmissionDenied):
            return False
        if not JsonHttpClient._method_is_retry_safe(method, idempotent=idempotent):
            return False
        return isinstance(
            exc,
            (
                httpx.TransportError,
                ProviderRateLimited,
                ProviderTransientHttpError,
            ),
        )

    @staticmethod
    async def _admit_attempt(attempt: int) -> None:
        """Ask the governor for durable admission before every retry attempt.

        The first attempt is already covered by the provider permit; each
        additional network attempt must consume its own RPM slot so one logical
        permit can never multiply into unaccounted upstream traffic.
        """
        if attempt <= 1:
            return
        admission = retry_attempt_admission.get()
        if admission is None:
            return
        if not await admission():
            raise ProviderAdmissionDenied("provider governor denied a retry attempt", retry_after_seconds=60)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        idempotent: bool = False,
    ) -> dict[str, Any]:
        last_error: Exception | None = None
        self._validate_request_size(payload, params)
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            for attempt in range(1, self.retry.attempts + 1):
                try:
                    await self._admit_attempt(attempt)
                    response = await client.request(method, url, headers=headers, json=payload, params=params)
                    self._validate_response_size(response)
                    if response.status_code == 429:
                        raise self._rate_limit_error(response)
                    if response.status_code >= 500:
                        raise self._http_error(response)
                    if response.status_code >= 400:
                        raise self._http_error(response)
                    try:
                        value = response.json() if response.content else {}
                    except ValueError as exc:
                        raise ProviderResponseError("provider returned invalid JSON") from exc
                    if not isinstance(value, dict):
                        raise ProviderResponseError("provider returned non-object JSON")
                    return value
                except (httpx.TransportError, ProviderError) as exc:
                    last_error = exc
                    if attempt >= self.retry.attempts or not self._retryable(
                        exc, method=method, idempotent=idempotent
                    ):
                        break
                    delay = self._retry_delay(attempt, exc)
                    if delay is None:
                        break
                    await asyncio.sleep(delay)
        self._raise_final(last_error)

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        idempotent: bool = False,
    ) -> Any:
        """Request provider JSON without requiring an object-shaped response."""
        last_error: Exception | None = None
        self._validate_request_size(payload, params)
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            for attempt in range(1, self.retry.attempts + 1):
                try:
                    await self._admit_attempt(attempt)
                    response = await client.request(method, url, headers=headers, json=payload, params=params)
                    self._validate_response_size(response)
                    if response.status_code == 429:
                        raise self._rate_limit_error(response)
                    if response.status_code >= 500:
                        raise self._http_error(response)
                    if response.status_code >= 400:
                        raise self._http_error(response)
                    try:
                        return response.json() if response.content else {}
                    except ValueError as exc:
                        raise ProviderResponseError("provider returned invalid JSON") from exc
                except (httpx.TransportError, ProviderError) as exc:
                    last_error = exc
                    if attempt >= self.retry.attempts or not self._retryable(
                        exc, method=method, idempotent=idempotent
                    ):
                        break
                    delay = self._retry_delay(attempt, exc)
                    if delay is None:
                        break
                    await asyncio.sleep(delay)
        self._raise_final(last_error)

    async def request_raw(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        idempotent: bool = False,
    ) -> RawHttpResponse:
        last_error: Exception | None = None
        self._validate_request_size(payload, None)
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            for attempt in range(1, self.retry.attempts + 1):
                try:
                    await self._admit_attempt(attempt)
                    response = await client.request(method, url, headers=headers, json=payload)
                    self._validate_response_size(response)
                    if response.status_code == 429:
                        raise self._rate_limit_error(response)
                    if response.status_code >= 500:
                        raise self._http_error(response)
                    if response.status_code >= 400:
                        raise self._http_error(response)
                    return RawHttpResponse(
                        response.status_code,
                        {key.lower(): value for key, value in response.headers.items()},
                        response.text,
                    )
                except (httpx.TransportError, ProviderError) as exc:
                    last_error = exc
                    if attempt >= self.retry.attempts or not self._retryable(
                        exc, method=method, idempotent=idempotent
                    ):
                        break
                    delay = self._retry_delay(attempt, exc)
                    if delay is None:
                        break
                    await asyncio.sleep(delay)
        self._raise_final(last_error)
