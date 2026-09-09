from __future__ import annotations

import asyncio
import math
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from fastmcp.server.dependencies import get_access_token

from zai_passbolt.config import ServiceConfig
from zai_passbolt.errors import SafeToolError, safe_provider_error
from zai_passbolt.profiles import Profiles
from zai_passbolt.records import ApprovalRecord, PassboltAuditRecord, PassboltSelectionRecord
from zai_passbolt.sanitizer import DURABLE_SANITIZER_LIMITS, sanitize_provider_response
from zai_passbolt.state import StateStore
from zai_passbolt.transport import (
    JsonHttpClient,
    LocalPreDispatchDenied,
    ProviderAdmissionDenied,
    ProviderRateLimited,
    ProviderTimeoutError,
    ProviderTransportError,
    canonical_json,
    request_hash,
)

WRITE_TOOLS = frozenset(
    {
        "passbolt_create_resource",
        "passbolt_update_resource",
        "passbolt_create_folder",
        "passbolt_share_resource",
    }
)


@dataclass(frozen=True)
class CallState:
    execution_id: str
    principal_id: str


class _DispatchAdmissionDenied(ProviderAdmissionDenied):
    """Created only by this runtime's HTTP admission boundary."""


class StandaloneHttp(JsonHttpClient):
    """Every initial request and retry shares the durable vault quota."""

    def __init__(self, runtime):
        super().__init__(timeout=30, max_response_bytes=8 * 1024 * 1024)
        self.runtime = runtime

    async def _admit_attempt(self, attempt):
        try:
            self.runtime.store.admit(self.runtime.state.get().principal_id)
        except ProviderAdmissionDenied as exc:
            raise _DispatchAdmissionDenied(
                "local HTTP admission denied", retry_after_seconds=exc.retry_after_seconds
            ) from None
        # Increment only after durable admission and before entering HTTPX.
        # The execution-owned mutable cell also tracks child tasks' admissions.
        self.runtime.dispatched.get()[0] += 1


class Registry:
    def __init__(self, runtime):
        self.runtime = runtime

    def passbolt_for_binding(self, label):
        return self.runtime.profiles.for_binding(label)

    async def call(self, actor, provider, operation, factory):
        if provider != "passbolt" or not self.runtime.config.enabled:
            raise PermissionError("provider is disabled")
        if str(actor) != self.runtime.state.get().principal_id:
            raise PermissionError("execution identity mismatch")
        before = self.runtime.dispatched.get()[0]
        try:
            return self.runtime.clean(await factory())
        except _DispatchAdmissionDenied as exc:
            if self.runtime.dispatched.get()[0] == before:
                raise LocalPreDispatchDenied(
                    "local request admission denied before dispatch",
                    retry_after_seconds=exc.retry_after_seconds,
                ) from None
            raise


class Runtime:
    ApprovalRecord = ApprovalRecord
    PassboltAuditRecord = PassboltAuditRecord
    PassboltSelectionRecord = PassboltSelectionRecord

    def __init__(self, config: ServiceConfig, transport: str, adapter=None):
        self.config = self.settings = config
        self.transport = transport
        self.state: ContextVar[CallState] = ContextVar("passbolt_call")
        self.dispatched: ContextVar[list[int]] = ContextVar("passbolt_dispatch_count")
        self.dispatched.set([0])
        self.profiles = Profiles(config, lambda: StandaloneHttp(self), adapter)
        routes = {
            label: self.profiles.vaults[profile] for label, (profile, _) in self.profiles.routes.items()
        }
        self.store = StateStore(config, self.profiles.fingerprint, routes)
        self.registry = Registry(self)

    def close(self):
        self.profiles.close()

    def require_scopes(self, *scopes):
        def check(context):
            available = (
                self.config.local_scopes
                if self.transport == "stdio"
                else context.token.scopes
                if context.token
                else []
            )
            return set(scopes) <= set(available)

        return check

    def identity(self):
        if self.transport == "stdio":
            actor = self.config.principal_id
        else:
            token = get_access_token()
            claims = token.claims if token else {}
            actor, expires = claims.get("sub"), claims.get("exp")
            if (
                not isinstance(actor, str)
                or not 1 <= len(actor) <= 256
                or claims.get("account_id") != self.config.account_id
                or not isinstance(expires, (int, float))
                or isinstance(expires, bool)
                or not math.isfinite(expires)
                or expires <= time.time()
            ):
                raise PermissionError("account-bound authenticated identity required")
        if actor not in self.config.bindings:
            raise PermissionError("server-owned Passbolt binding required")
        return actor

    def current_access(self):
        return self.state.get()

    def current_request_id(self):
        return self.state.get().execution_id

    def authorize(self, tool):
        required = (
            "passbolt:write"
            if tool in WRITE_TOOLS
            else "passbolt:use"
            if tool == "passbolt_use_secret"
            else "passbolt:read"
        )
        token = get_access_token() if self.transport == "http" else None
        available = self.config.local_scopes if self.transport == "stdio" else token.scopes if token else []
        if required not in available:
            raise PermissionError("required Passbolt scope missing")

    @staticmethod
    def clean(value):
        return sanitize_provider_response(value, limits=DURABLE_SANITIZER_LIMITS)

    async def provider_read(self, provider, operation, arguments, factory, *, validate=None):
        if validate:
            validate()
        return await self.registry.call(self.state.get().principal_id, provider, operation, factory)

    async def execute(self, tool: str, arguments: dict[str, Any], factory):
        execution, token, outcome, began = uuid4().hex, None, "error", False
        dispatch_token = self.dispatched.set([0])
        actor = None
        try:
            self.authorize(tool)
            actor = self.identity()
            if not self.config.enabled and tool != "passbolt_status":
                raise PermissionError("provider is disabled")
            if len(canonical_json(arguments).encode()) > 1_048_576:
                raise ValueError("request exceeds bounded input size")
            self.store.begin(execution, actor, tool, request_hash({"tool": tool, "arguments": arguments}))
            began = True
            token = self.state.set(CallState(execution, actor))
            async with asyncio.timeout(300):
                result = await factory()
            outcome = "success"
            return self.clean(result)
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        except SafeToolError:
            raise
        except Exception as exc:
            if isinstance(exc, TimeoutError):
                outcome = "timeout"
                exc = ProviderTimeoutError("operation deadline exceeded")
            if (
                actor is not None
                and isinstance(exc, (ProviderRateLimited, ProviderTimeoutError, ProviderTransportError))
                and not isinstance(exc, ProviderAdmissionDenied)
            ):
                self.store.cooldown(actor, getattr(exc, "retry_after_seconds", None) or 60)
            raise safe_provider_error("passbolt", exc) from None
        finally:
            self.dispatched.reset(dispatch_token)
            if token is not None:
                self.state.reset(token)
            if began:
                self.store.finish(execution, outcome)
