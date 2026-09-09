from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

PREFIX = "PASSBOLT"


def load_config(filename: str | None) -> None:
    """Load explicit operator settings; resolve file paths relative to this file.

    Explicit config wins over inherited environment. No shell expansion, dotenv
    auto-discovery, global cwd changes or provider requests are performed.
    """
    if not filename:
        return
    path = Path(filename).expanduser().absolute()
    if not path.is_file() or path.stat().st_size > 65536:
        raise ValueError("configuration file missing or too large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"env"} or not isinstance(data["env"], dict):
        raise ValueError("configuration must contain only an env object")
    pending = {}
    for key, value in data["env"].items():
        if not re.fullmatch(PREFIX + r"_[A-Z0-9_]+", key) or not isinstance(value, str):
            raise ValueError("configuration requires service-prefixed string settings")
        if len(value) > 8192 or "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError("configuration value is invalid")
        if value and (key.endswith("_FILE") or key.endswith("_STATE_PATH")):
            candidate = Path(value).expanduser()
            if not candidate.is_absolute():
                candidate = path.parent / candidate
            value = str(candidate.absolute())
        pending[key] = value
    os.environ.update(pending)


def check_config(config: Any, transport: str) -> dict[str, Any]:
    """Report local configuration readiness without accessing provider APIs."""
    checks: dict[str, bool] = {"configuration": True}
    if transport == "http":
        checks["http_verification_key"] = bool(config.public_key)
        if config.public_key:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            try:
                checks["http_verification_key"] = isinstance(
                    load_pem_public_key(config.public_key.encode()), RSAPublicKey
                )
            except (ValueError, TypeError):
                checks["http_verification_key"] = False
    if PREFIX == "KEYSSO":
        checks["transport_auth_mode"] = transport != "stdio" or config.auth_mode == "operator"
    if PREFIX == "YANDEX":
        checks["at_least_one_provider"] = any(
            config.enabled(provider)
            for provider in ("yandex_direct", "yandex_metrika", "yandex_search", "yandex_webmaster")
        )
    if PREFIX == "ARSENKIN":
        checks["provider_credential"] = bool(config.token)
    if PREFIX in {"TELEGRAM", "PASSBOLT"}:
        checks["local_principal_binding"] = transport != "stdio" or config.principal_id in config.bindings
    if PREFIX == "PASSBOLT":
        checks["gnupg_installed"] = shutil.which("gpg") is not None
    return {
        "ready": all(checks.values()),
        "scope": "local_configuration_only",
        "provider_connectivity": "not_checked",
        "checks": checks,
    }
