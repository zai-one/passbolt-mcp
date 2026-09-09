import json
import re
from pathlib import Path

from zai_passbolt.adapter import PassboltAdapter
from zai_passbolt.secrets import read_private_secret_env, require_private_file
from zai_passbolt.transport import request_hash


def adapter_from_secret(secret: dict[str, str]) -> PassboltAdapter:
    token_state = secret.get("PASSBOLT_TOKEN_STATE_FILE")
    return PassboltAdapter(
        secret.get("PASSBOLT_BASE_URL", ""),
        service_user_id=secret.get("PASSBOLT_SERVICE_USER_ID", ""),
        service_username=secret.get("PASSBOLT_SERVICE_USERNAME", ""),
        user_fingerprint=secret.get("PASSBOLT_USER_FINGERPRINT", ""),
        server_fingerprint=secret.get("PASSBOLT_SERVER_FINGERPRINT", ""),
        token_file=Path(token_state) if token_state else None,
        gpg_home=Path(secret["PASSBOLT_GPG_HOME"]) if secret.get("PASSBOLT_GPG_HOME") else None,
        passphrase_file=Path(secret["PASSBOLT_PASSPHRASE_FILE"])
        if secret.get("PASSBOLT_PASSPHRASE_FILE")
        else None,
        sealed_ref_dir=Path(secret["PASSBOLT_SEALED_REF_DIR"])
        if secret.get("PASSBOLT_SEALED_REF_DIR")
        else None,
        sink_config_file=Path(secret["PASSBOLT_SINK_CONFIG_FILE"])
        if secret.get("PASSBOLT_SINK_CONFIG_FILE")
        else None,
        domain_allowlist=secret.get("PASSBOLT_DOMAIN_ALLOWLIST", ""),
        metadata_fingerprints=secret.get("PASSBOLT_METADATA_FINGERPRINTS", ""),
    )


class Profiles:
    """Resolve operator custody once; requests can select only their bound route."""

    def __init__(self, config, http_factory, adapter=None):
        root = read_private_secret_env(config.secret_path)
        self.routes, secrets_by_profile = {}, {}
        registry_value = root.get("PASSBOLT_PROFILE_REGISTRY_FILE")
        if registry_value:
            path = Path(registry_value)
            require_private_file(path, max_bytes=262_144)
            doc = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(doc, dict)
                or set(doc) != {"version", "profiles", "bindings"}
                or doc["version"] != 1
            ):
                raise ValueError("invalid profile registry")
            if not isinstance(doc["profiles"], dict) or not isinstance(doc["bindings"], dict):
                raise ValueError("invalid profiles and bindings")
            for label in set(config.bindings.values()):
                route = doc["bindings"].get(label)
                if not isinstance(route, dict) or set(route) != {"profile", "policy"}:
                    raise ValueError("unregistered binding")
                if any(
                    not isinstance(v, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", v)
                    for v in route.values()
                ):
                    raise ValueError("invalid profile route")
                profile, policy = route["profile"], route["policy"]
                entry = doc["profiles"].get(profile)
                if (
                    not isinstance(entry, dict)
                    or set(entry) != {"env_file"}
                    or not isinstance(entry["env_file"], str)
                ):
                    raise ValueError("invalid profile custody file")
                secrets_by_profile[profile] = read_private_secret_env(Path(entry["env_file"]))
                self.routes[label] = (profile, policy)
        else:
            secrets_by_profile["default"] = root
            self.routes = {label: ("default", label) for label in config.bindings.values()}
        self.adapters = {}
        self.vaults = {}
        for profile, secret in secrets_by_profile.items():
            instance = adapter.get(profile) if isinstance(adapter, dict) else adapter
            if instance is None:
                instance = adapter_from_secret(secret)
                instance.http = http_factory()
            self.adapters[profile] = instance
            self.vaults[profile] = request_hash(
                {
                    key: secret.get(key, "")
                    for key in ("PASSBOLT_BASE_URL", "PASSBOLT_SERVICE_USER_ID", "PASSBOLT_USER_FINGERPRINT")
                }
            )
        self.fingerprint = request_hash(
            {"bindings": dict(config.bindings), "routes": self.routes, "profiles": secrets_by_profile}
        )

    def for_binding(self, label):
        if label not in self.routes:
            raise PermissionError("unregistered principal binding")
        profile, policy = self.routes[label]
        return self.adapters[profile], policy, profile

    def close(self):
        for adapter in {id(v): v for v in self.adapters.values()}.values():
            close = getattr(adapter, "close", None)
            if close:
                close()
