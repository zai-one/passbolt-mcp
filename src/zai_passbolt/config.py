from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from zai_passbolt.secrets import require_private_file

SCOPES = frozenset({"passbolt:read", "passbolt:write", "passbolt:use"})


@dataclass(frozen=True)
class ServiceConfig:
    state_path: Path
    secret_path: Path
    bindings: Mapping[str, str] = field(default_factory=dict)
    account_id: str = "default"
    principal_id: str = "local-operator"
    public_key: str = ""
    issuer: str = "passbolt-operator"
    audience: str = "passbolt-mcp"
    local_scopes: frozenset[str] = frozenset({"passbolt:read"})
    passbolt_write_enabled: bool = False
    passbolt_use_enabled: bool = False
    passbolt_selection_ttl_seconds: int = 600
    enabled: bool = True
    rate_limit: int = 10
    max_concurrency: int = 1

    def __post_init__(self):
        if not all(
            isinstance(v, str) and 1 <= len(v) <= 256
            for v in (self.account_id, self.principal_id, self.issuer, self.audience)
        ):
            raise ValueError("bounded identity fields required")
        if not self.local_scopes <= SCOPES:
            raise ValueError("unknown scope")
        for value, minimum, maximum in (
            (self.rate_limit, 1, 10),
            (self.max_concurrency, 1, 1),
            (self.passbolt_selection_ttl_seconds, 60, 600),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise ValueError("policy exceeds original default ceiling")
        if not all(
            isinstance(v, bool)
            for v in (self.enabled, self.passbolt_write_enabled, self.passbolt_use_enabled)
        ):
            raise ValueError("boolean runtime policy required")
        copied = dict(self.bindings)
        if any(
            not isinstance(actor, str)
            or not 1 <= len(actor) <= 256
            or not isinstance(label, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,31}", label) is None
            for actor, label in copied.items()
        ):
            raise ValueError("invalid server-owned vault binding")
        object.__setattr__(self, "bindings", MappingProxyType(copied))

    @classmethod
    def from_env(cls):
        secret = Path(os.environ.get("PASSBOLT_SECRET_FILE", ""))
        require_private_file(secret)
        binding_path = Path(os.environ.get("PASSBOLT_BINDINGS_FILE", ""))
        require_private_file(binding_path)
        bindings = json.loads(binding_path.read_text(encoding="utf-8"))
        if not isinstance(bindings, dict):
            raise ValueError("binding map required")
        public = os.environ.get("PASSBOLT_MCP_PUBLIC_KEY_FILE", "")

        def flag(name, default="false"):
            value = os.environ.get(name, default)
            if value not in {"true", "false"}:
                raise ValueError("boolean policy must be true or false")
            return value == "true"

        return cls(
            state_path=Path(os.environ.get("PASSBOLT_STATE_PATH", "state/passbolt.sqlite")),
            secret_path=secret,
            bindings=bindings,
            account_id=os.environ.get("PASSBOLT_ACCOUNT_ID", "default"),
            principal_id=os.environ.get("PASSBOLT_LOCAL_PRINCIPAL", "local-operator"),
            public_key=Path(public).read_text(encoding="utf-8") if public else "",
            issuer=os.environ.get("PASSBOLT_MCP_ISSUER", "passbolt-operator"),
            audience=os.environ.get("PASSBOLT_MCP_AUDIENCE", "passbolt-mcp"),
            local_scopes=frozenset(os.environ.get("PASSBOLT_LOCAL_SCOPES", "passbolt:read").split()),
            passbolt_write_enabled=flag("PASSBOLT_WRITE_ENABLED"),
            passbolt_use_enabled=flag("PASSBOLT_USE_ENABLED"),
            enabled=flag("PASSBOLT_ENABLED", "true"),
            rate_limit=int(os.environ.get("PASSBOLT_RATE_LIMIT", "10")),
            passbolt_selection_ttl_seconds=int(os.environ.get("PASSBOLT_SELECTION_TTL", "600")),
        )
