from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4

from zai_passbolt.gpg_paths import gpg_path
from zai_passbolt.transport import (
    JsonHttpClient,
    ProviderAuthenticationError,
    ProviderError,
    ProviderHttpError,
    ProviderResponseError,
)

logger = logging.getLogger(__name__)

MAX_RESULTS = 50
MAX_QUERY_LENGTH = 256
MAX_RESOURCE_SCAN = 2_000
V5_DEFAULT_RESOURCE_TYPE_ID = "dd1f723d-0d1e-513f-8218-4055dc0530d0"
RESOURCE_METADATA_OBJECT_TYPE = "PASSBOLT_RESOURCE_METADATA"
SECRET_DATA_OBJECT_TYPE = "PASSBOLT_SECRET_DATA"  # noqa: S105 -- schema discriminator
METADATA_PRIVATE_KEY_OBJECT_TYPE = (  # noqa: S105 -- schema discriminator
    "PASSBOLT_METADATA_PRIVATE_KEY"
)
_SAFE_FIELDS = frozenset({"id", "name", "uri", "username", "modified", "folder", "group"})
_SEALED_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SINK_REF_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_PERMISSIONS = {"read": 1, "update": 7, "owner": 15}


def _trusted_owner(uid: int) -> bool:
    if os.name == "nt":
        return True
    current_uid = int(getattr(os, "getuid", lambda: -1)())
    return uid in {0, current_uid}


def _private_mode(mode: int) -> bool:
    """Use POSIX mode gates on the Linux runtime; Windows relies on ACL custody."""
    return os.name == "nt" or not bool(mode & (stat.S_IRWXG | stat.S_IRWXO))


def _not_group_writable(mode: int) -> bool:
    return os.name == "nt" or not bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def _private_directory(path: Path | None) -> bool:
    if path is None or not path.is_absolute():
        return False
    try:
        info = path.lstat()
    except OSError:
        return False
    return bool(
        not path.is_symlink()
        and stat.S_ISDIR(info.st_mode)
        and _private_mode(info.st_mode)
        and _trusted_owner(info.st_uid)
    )


def _private_file(path: Path | None, *, max_bytes: int) -> bool:
    if path is None or not path.is_absolute():
        return False
    try:
        info = path.lstat()
    except OSError:
        return False
    return bool(
        not path.is_symlink()
        and stat.S_ISREG(info.st_mode)
        and _private_mode(info.st_mode)
        and _trusted_owner(info.st_uid)
        and 0 < info.st_size <= max_bytes
    )


def _path_present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


class JsonRequester(Protocol):
    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        idempotent: bool = False,
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class DomainDecision:
    matches: bool
    reason: str
    resource_host: str | None
    target_host: str | None


@dataclass(frozen=True, slots=True)
class PassboltAccessPolicy:
    """Principal-bound allowlist loaded from server custody, never from the client."""

    resource_ids: frozenset[str]
    folder_ids: frozenset[str]
    group_ids: frozenset[str]
    user_ids: frozenset[str]
    domain_hosts: frozenset[str]
    sink_refs: frozenset[str]
    allow_create_resource: bool
    allow_create_folder: bool
    resource_scope: str = "explicit"
    folder_scope: str = "explicit"
    allow_share_all: bool = False

    def permits_domain(self, value: str) -> bool:
        return (_origin(value) or "") in self.domain_hosts

    def permits_resource(self, resource_id: str, created: frozenset[str]) -> bool:
        return self.resource_scope == "all" or resource_id in self.resource_ids | created

    def permits_folder(self, folder_id: str, created: frozenset[str]) -> bool:
        return self.folder_scope == "all" or folder_id in self.folder_ids | created


def _https_url(value: str, field: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{field} must be absolute HTTPS without credentials or query")
    try:
        parsed.hostname.encode("idna")
    except UnicodeError as exc:
        raise ValueError(f"{field} hostname is invalid") from exc
    return normalized


def _safe_existing_uri(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().rstrip("/")
    if not normalized or len(normalized) > 2048 or any(ord(char) < 32 for char in normalized):
        return None
    parsed = urlsplit(normalized)
    if (
        not parsed.scheme
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    try:
        parsed.hostname.encode("idna")
    except UnicodeError:
        return None
    return normalized


def _host(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urlsplit(_https_url(value, "URL"))
    except ValueError:
        return None
    if parsed.hostname is None:
        return None
    return parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")


def _origin(value: str | None) -> str | None:
    """Return a normalized HTTPS authority; a bare host means default port 443."""
    if not value:
        return None
    try:
        parsed = urlsplit(_https_url(value, "URL"))
        port = parsed.port
    except ValueError:
        return None
    if parsed.hostname is None:
        return None
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    authority_host = f"[{host}]" if ":" in host else host
    return authority_host if port in (None, 443) else f"{authority_host}:{port}"


def _origin_label(value: str, field: str) -> str:
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    normalized = _https_url(candidate, field)
    parsed = urlsplit(normalized)
    if parsed.path not in {"", "/"}:
        raise ValueError(f"{field} must be an HTTPS host or host:port")
    origin = _origin(normalized)
    if origin is None:
        raise ValueError(f"{field} is invalid")
    return origin


def _bounded_query(value: str, *, required: bool) -> str:
    normalized = value.strip()
    if required and not normalized:
        raise ValueError("Passbolt query is required")
    if len(normalized) > MAX_QUERY_LENGTH:
        raise ValueError(f"Passbolt query must be at most {MAX_QUERY_LENGTH} characters")
    return normalized


def _bounded_limit(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_RESULTS:
        raise ValueError(f"Passbolt limit must be between 1 and {MAX_RESULTS}")
    return value


def _uuid(value: str, field: str) -> str:
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f"{field} must be a UUID") from exc


def _text(value: Any, field: str, limit: int, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if required and not normalized:
        raise ValueError(f"{field} is required")
    if len(normalized) > limit:
        raise ValueError(f"{field} must be at most {limit} characters")
    return normalized or None


def _safe_nested_label(value: Any) -> str | None:
    if isinstance(value, str):
        return value[:256]
    if isinstance(value, dict):
        label = value.get("name") or value.get("id")
        return str(label)[:256] if label is not None else None
    if isinstance(value, list):
        labels = [label for item in value if (label := _safe_nested_label(item))]
        return ", ".join(labels)[:256] or None
    return None


def safe_resource(value: Any) -> dict[str, Any]:
    """Project only fields that are safe to return to an MCP caller."""
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {}
    for key in _SAFE_FIELDS:
        item = value.get(key)
        if item is None:
            continue
        if key in {"folder", "group"}:
            label = _safe_nested_label(item)
            if label is not None:
                result[key] = label
        elif isinstance(item, (str, int, float, bool)):
            result[key] = str(item)[:2048] if isinstance(item, str) else item
    if "id" in result:
        result["resource_id"] = result.pop("id")
    return result


def _unwrap(payload: Any) -> Any:
    return payload.get("body") if isinstance(payload, dict) and "body" in payload else payload


def _jwt_expiry(token: str) -> int | None:
    try:
        segment = token.split(".")[1]
        decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        payload = json.loads(decoded)
        expiry = payload.get("exp") if isinstance(payload, dict) else None
        return int(expiry) if expiry is not None else None
    except (IndexError, ValueError, TypeError, json.JSONDecodeError):
        return None


def validate_v5_metadata(payload: Mapping[str, Any], *, strict_write: bool = True) -> dict[str, Any]:
    if payload.get("object_type") != RESOURCE_METADATA_OBJECT_TYPE:
        raise ValueError("Passbolt v5 metadata object_type is invalid")
    resource_type_id = str(payload.get("resource_type_id") or "")
    if strict_write:
        if resource_type_id != V5_DEFAULT_RESOURCE_TYPE_ID:
            raise ValueError("Passbolt v5 metadata resource_type_id is invalid")
    else:
        resource_type_id = _uuid(resource_type_id, "resource_type_id")
    name = _text(payload.get("name"), "name", 255, required=True)
    username = _text(payload.get("username"), "username", 255)
    description = _text(payload.get("description"), "description", 10_000)
    uris = payload.get("uris")
    if not isinstance(uris, list) or len(uris) > 10:
        raise ValueError("Passbolt v5 metadata uris must be a list with at most 10 entries")
    if strict_write:
        normalized_uris = [_https_url(item, "uri") for item in uris if isinstance(item, str) and item]
        if len(normalized_uris) != len(uris):
            raise ValueError("Passbolt v5 metadata contains an invalid uri")
    else:
        normalized_uris = [uri for item in uris if (uri := _safe_existing_uri(item)) is not None]
    if strict_write and payload.get("custom_fields") != []:
        raise ValueError("decrypted custom fields are not accepted by this provider surface")
    return {
        "object_type": RESOURCE_METADATA_OBJECT_TYPE,
        "resource_type_id": resource_type_id,
        "name": name,
        "username": username,
        "uris": normalized_uris,
        "description": description,
        "custom_fields": [],
    }


class PassboltSinkDispatcher:
    """Deliver plaintext only to pre-registered server-local processes."""

    def __init__(self, config_file: Path | None) -> None:
        self.config_file = config_file

    def ready(self) -> bool:
        if self.config_file is None or not self.config_file.is_file():
            return False
        try:
            return bool(self._load())
        except ProviderError:
            return False

    def _document(self) -> dict[str, Any]:
        if self.config_file is None or not self.config_file.is_file():
            raise ProviderError("Passbolt secure sink registry is not configured")
        try:
            info = self.config_file.lstat()
            if (
                self.config_file.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or not _private_mode(info.st_mode)
                or not _trusted_owner(info.st_uid)
            ):
                raise ProviderError("Passbolt secure sink registry permissions are unsafe")
            payload = json.loads(self.config_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderError("Passbolt secure sink registry is invalid") from exc
        if not isinstance(payload, dict):
            raise ProviderError("Passbolt secure sink registry is invalid")
        return payload

    def _load(self) -> dict[str, dict[str, Any]]:
        sinks = self._document().get("sinks")
        if not isinstance(sinks, dict):
            raise ProviderError("Passbolt secure sink registry is invalid")
        return {str(key): value for key, value in sinks.items() if isinstance(value, dict)}

    def access_policy(self, binding_label: str) -> PassboltAccessPolicy:
        if re.fullmatch(r"[a-z][a-z0-9_]{0,31}", binding_label) is None:
            raise PermissionError("Passbolt principal binding is invalid")
        policies = self._document().get("policies")
        raw = policies.get(binding_label) if isinstance(policies, dict) else None
        if not isinstance(raw, dict):
            raise PermissionError("Passbolt principal policy is not registered")
        required_keys = {
            "resource_ids",
            "folder_ids",
            "group_ids",
            "user_ids",
            "domain_hosts",
            "sink_refs",
            "allow_create_resource",
            "allow_create_folder",
        }
        optional_keys = {"resource_scope", "folder_scope", "allow_share_all"}
        if not required_keys <= set(raw) or set(raw) - required_keys - optional_keys:
            raise ProviderError("Passbolt principal policy schema is invalid")

        def uuid_set(name: str) -> frozenset[str]:
            value = raw.get(name)
            if not isinstance(value, list) or len(value) > 2_000:
                raise ProviderError("Passbolt principal policy schema is invalid")
            try:
                return frozenset(_uuid(str(item), name) for item in value)
            except ValueError as exc:
                raise ProviderError("Passbolt principal policy schema is invalid") from exc

        domains = raw.get("domain_hosts")
        sinks = raw.get("sink_refs")
        resource_scope = raw.get("resource_scope", "explicit")
        folder_scope = raw.get("folder_scope", "explicit")
        allow_share_all = raw.get("allow_share_all", False)
        if (
            not isinstance(domains, list)
            or len(domains) > 200
            or not isinstance(sinks, list)
            or len(sinks) > 200
            or any(
                not isinstance(host, str) or host != host.lower() or _host(f"https://{host}") != host
                for host in domains
            )
            or any(not isinstance(ref, str) or _SINK_REF_RE.fullmatch(ref) is None for ref in sinks)
            or not isinstance(raw.get("allow_create_resource"), bool)
            or not isinstance(raw.get("allow_create_folder"), bool)
            or resource_scope not in {"explicit", "all"}
            or folder_scope not in {"explicit", "all"}
            or not isinstance(allow_share_all, bool)
        ):
            raise ProviderError("Passbolt principal policy schema is invalid")
        registered_sinks = self._load()
        if not set(sinks) <= set(registered_sinks):
            raise ProviderError("Passbolt principal policy names an unregistered sink")
        return PassboltAccessPolicy(
            resource_ids=uuid_set("resource_ids"),
            folder_ids=uuid_set("folder_ids"),
            group_ids=uuid_set("group_ids"),
            user_ids=uuid_set("user_ids"),
            domain_hosts=frozenset(domains),
            sink_refs=frozenset(sinks),
            allow_create_resource=bool(raw["allow_create_resource"]),
            allow_create_folder=bool(raw["allow_create_folder"]),
            resource_scope=str(resource_scope),
            folder_scope=str(folder_scope),
            allow_share_all=bool(allow_share_all),
        )

    @staticmethod
    def _command(config: Mapping[str, Any], *, out_file: Path | None = None) -> list[str]:
        value = config.get("command")
        if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
            raise ProviderError("Passbolt secure sink command is invalid")
        command = [item.replace("{path}", str(out_file) if out_file else "") for item in value]
        executable = Path(command[0])
        expected_hash = config.get("executable_sha256")
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise ProviderError("Passbolt secure sink executable hash is not pinned")
        try:
            info = executable.lstat()
            unsafe = (
                executable.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or not _not_group_writable(info.st_mode)
                or not _trusted_owner(info.st_uid)
            )
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        except OSError as exc:
            raise ProviderError("Passbolt secure sink executable is unavailable") from exc
        if not executable.is_absolute() or unsafe or digest != expected_hash:
            raise ProviderError("Passbolt secure sink executable is not an absolute server path")
        if out_file is not None and not any("{path}" in item for item in value):
            raise ProviderError("Passbolt out_file sink command must contain {path}")
        return command

    @staticmethod
    def _run(command: list[str], *, stdin: str | None, timeout: int) -> None:
        try:
            result = subprocess.run(
                command,
                input=stdin,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
                env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProviderError("Passbolt secure sink failed") from exc
        if result.returncode != 0:
            raise ProviderError("Passbolt secure sink failed")

    async def deliver(
        self,
        sink_ref: str,
        *,
        resource_id: str,
        username: str | None,
        password: str,
        target_url: str | None,
    ) -> bool:
        if not _SINK_REF_RE.fullmatch(sink_ref):
            raise ValueError("sink_ref is invalid")
        config = self._load().get(sink_ref)
        if config is None:
            raise PermissionError("Passbolt sink_ref is not registered")
        kind = config.get("kind")
        timeout = config.get("timeout_seconds", 30)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 120:
            raise ProviderError("Passbolt secure sink timeout is invalid")
        envelope = json.dumps(
            {
                "resource_id": resource_id,
                "username": username,
                "password": password,
                "target_url": target_url,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        if kind == "secure_fill":
            command = self._command(config)
            await asyncio.to_thread(self._run, command, stdin=envelope, timeout=timeout)
            return True
        if kind != "out_file":
            raise PermissionError("Passbolt sink kind is not allowed")
        directory_value = config.get("directory")
        if not isinstance(directory_value, str):
            raise ProviderError("Passbolt out_file sink directory is invalid")
        directory = Path(directory_value)

        def private_spool() -> bool:
            try:
                info = directory.lstat()
            except OSError:
                return False
            return (
                directory.is_dir()
                and not directory.is_symlink()
                and _trusted_owner(info.st_uid)
                and _private_mode(info.st_mode)
            )

        available = await asyncio.to_thread(private_spool)
        if not directory.is_absolute() or not available:
            raise ProviderError("Passbolt out_file sink directory is unavailable")
        descriptor, raw_path = tempfile.mkstemp(prefix="passbolt-use-", suffix=".json", dir=directory)
        path = Path(raw_path)
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(envelope)
                handle.flush()
                os.fsync(handle.fileno())
            command = self._command(config, out_file=path)
            await asyncio.to_thread(self._run, command, stdin=None, timeout=timeout)
            return True
        finally:
            with suppress(OSError):
                await asyncio.to_thread(path.unlink, missing_ok=True)


class PassboltAdapter:
    """Governed Passbolt provider with server-only JWT, GPG and sink custody."""

    def __init__(
        self,
        base_url: str,
        access_token: str = "",
        *,
        service_user_id: str = "",
        service_username: str = "",
        user_fingerprint: str = "",
        server_fingerprint: str = "",
        token_file: Path | None = None,
        gpg_home: Path | None = None,
        passphrase_file: Path | None = None,
        sealed_ref_dir: Path | None = None,
        sink_config_file: Path | None = None,
        domain_allowlist: str = "",
        metadata_fingerprints: str = "",
        http: JsonRequester | None = None,
    ) -> None:
        self.base_url = _https_url(base_url, "Passbolt base URL") if base_url.strip() else ""
        self.service_user_id = service_user_id.strip()
        self.service_username = service_username.strip()
        self.user_fingerprint = user_fingerprint.replace(" ", "").upper()
        self.server_fingerprint = server_fingerprint.replace(" ", "").upper()
        self.token_file = token_file
        self.gpg_home = gpg_home
        self.passphrase_file = passphrase_file
        self.sealed_ref_dir = sealed_ref_dir
        self.sinks = PassboltSinkDispatcher(sink_config_file)
        self.http = http or JsonHttpClient(timeout=30, max_response_bytes=8 * 1024 * 1024)
        self._token_state: dict[str, Any] | None = (
            {"access_token": access_token.strip()} if access_token.strip() else None
        )
        self._token_loaded = bool(access_token.strip())
        self._token_lock = asyncio.Lock()
        self._runtime_gpg_home: Path | None = None
        self._gpg_lock = asyncio.Lock()
        self._metadata_key_cache: dict[str, dict[str, str]] = {}
        self._active_metadata_key_id: str | None = None
        self._metadata_keys_loaded = False
        self._domain_relations = self._parse_domain_allowlist(domain_allowlist)
        self._metadata_fingerprints = frozenset(
            value.strip().replace(" ", "").upper()
            for value in metadata_fingerprints.split(",")
            if value.strip()
        )

    def access_policy(self, binding_label: str) -> PassboltAccessPolicy:
        return self.sinks.access_policy(binding_label)

    @staticmethod
    def _parse_domain_allowlist(value: str) -> frozenset[tuple[str, str]]:
        relations: set[tuple[str, str]] = set()
        for raw in value.split(","):
            if not raw.strip():
                continue
            parts = raw.split(">", 1)
            if len(parts) != 2:
                raise ValueError("PASSBOLT_DOMAIN_ALLOWLIST entries must be resource>target")
            resource = _origin_label(parts[0], "PASSBOLT_DOMAIN_ALLOWLIST resource")
            target = _origin_label(parts[1], "PASSBOLT_DOMAIN_ALLOWLIST target")
            relations.add((resource, target))
        return frozenset(relations)

    def domain_decision(self, resource_uri: str | None, target_url: str | None) -> DomainDecision:
        resource_host = _origin(resource_uri)
        target_host = _origin(target_url)
        if resource_host and target_host and resource_host == target_host:
            return DomainDecision(True, "exact_origin_match", resource_host, target_host)
        if resource_host and target_host and (resource_host, target_host) in self._domain_relations:
            return DomainDecision(True, "explicit_allowlist_match", resource_host, target_host)
        reason = "missing_resource_uri" if not resource_host else "origin_mismatch"
        return DomainDecision(False, reason, resource_host, target_host)

    def _configured(self) -> bool:
        return bool(
            self.base_url
            and self.service_user_id
            and self.user_fingerprint
            and self.server_fingerprint
            and self.token_file
            and self.gpg_home
            and self.passphrase_file
        )

    def _decryption_configured(self) -> bool:
        return bool(
            _private_directory(self.gpg_home)
            and _private_file(self.passphrase_file, max_bytes=65_536)
            and shutil.which("gpg")
            and self.user_fingerprint
        )

    def _writable_gpg_home(self) -> Path:
        if not self._decryption_configured() or self.gpg_home is None:
            raise ProviderResponseError("Passbolt GPG custody is not configured")
        if self._runtime_gpg_home is None:
            target = Path(tempfile.mkdtemp(prefix="mcp-passbolt-gnupg-"))
            try:
                shutil.copytree(
                    self.gpg_home,
                    target,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("S.gpg-agent*", "S.dirmngr*", "*.lock", ".#lk*"),
                )
                target.chmod(0o700)
            except OSError:
                shutil.rmtree(target, ignore_errors=True)
                raise ProviderResponseError("Passbolt private GPG runtime could not be prepared") from None
            self._runtime_gpg_home = target
        return self._runtime_gpg_home

    def close(self) -> None:
        if self._runtime_gpg_home is not None:
            # Kill only the agent for this generated private runtime, never the
            # operator's source keyring. Release open handles before removing keys.
            gpgconf = shutil.which("gpgconf")
            if gpgconf:
                with suppress(OSError, subprocess.SubprocessError):
                    subprocess.run(
                        [
                            gpgconf,
                            "--homedir",
                            gpg_path(gpgconf, self._runtime_gpg_home),
                            "--kill",
                            "gpg-agent",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                        check=False,
                    )
            shutil.rmtree(self._runtime_gpg_home, ignore_errors=True)
            self._runtime_gpg_home = None

    def _gpg_sync(
        self,
        args: list[str],
        *,
        stdin: str | None = None,
        expected_signer: str | None = None,
    ) -> str:
        gpg = shutil.which("gpg")
        if not gpg:
            raise ProviderResponseError("Passbolt GPG custody is not configured")
        command = [
            gpg,
            "--batch",
            "--yes",
            "--no-tty",
            "--homedir",
            gpg_path(gpg, self._writable_gpg_home()),
            "--pinentry-mode",
            "loopback",
        ]
        if self.passphrase_file is not None:
            command.extend(["--passphrase-file", gpg_path(gpg, self.passphrase_file)])
        if expected_signer:
            command.extend(["--status-fd", "2"])
        command.extend(args)
        try:
            result = subprocess.run(
                command,
                input=stdin,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE if expected_signer else subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProviderResponseError("Passbolt GPG operation failed") from exc
        if result.returncode != 0:
            raise ProviderResponseError("Passbolt GPG operation failed")
        if expected_signer:
            expected = expected_signer.replace(" ", "").upper()
            status_lines = result.stderr or ""
            if not any(
                line.startswith("[GNUPG:] VALIDSIG ")
                and expected in {token.replace(" ", "").upper() for token in line.split()[2:]}
                for line in status_lines.splitlines()
                if len(line.split()) >= 3
            ):
                raise ProviderResponseError("Passbolt GPG signer verification failed")
        return result.stdout

    async def _gpg(
        self,
        args: list[str],
        *,
        stdin: str | None = None,
        expected_signer: str | None = None,
    ) -> str:
        async with self._gpg_lock:
            return await asyncio.to_thread(
                self._gpg_sync,
                args,
                stdin=stdin,
                expected_signer=expected_signer,
            )

    async def _decrypt_json(self, armored: str, *, expected_signer: str | None = None) -> dict[str, Any]:
        plaintext = await self._gpg(["--decrypt"], stdin=armored, expected_signer=expected_signer)
        try:
            value = json.loads(plaintext)
        except json.JSONDecodeError:
            # Older Passbolt resources can contain a plaintext password rather
            # than the v5 secret object. Keep it in memory only.
            return {"password": plaintext}
        if not isinstance(value, dict):
            raise ProviderResponseError("Passbolt decrypted payload is invalid")
        return value

    async def _decrypt_text(self, armored: str, *, expected_signer: str | None = None) -> str:
        return await self._gpg(["--decrypt"], stdin=armored, expected_signer=expected_signer)

    async def _encrypt_json(self, value: Mapping[str, Any], recipient: str) -> str:
        plaintext = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return await self._gpg(
            [
                "--armor",
                "--trust-model",
                "always",
                "--local-user",
                self.user_fingerprint,
                "--recipient",
                recipient,
                "--encrypt",
                "--sign",
            ],
            stdin=plaintext,
        )

    async def _gpg_preflight(self) -> bool:
        if not self._decryption_configured():
            return False
        try:
            await self._gpg(
                ["--armor", "--local-user", self.user_fingerprint, "--detach-sign"],
                stdin="mcp-platform-passbolt-readiness",
            )
            return True
        except ProviderError:
            return False

    def _load_token_state_sync(self) -> dict[str, Any] | None:
        if self.token_file is None:
            return None
        if not _private_directory(self.token_file.parent):
            raise ProviderError("Passbolt token state custody is unsafe")
        if not _path_present(self.token_file):
            return None
        if not _private_file(self.token_file, max_bytes=65_536):
            raise ProviderError("Passbolt token state custody is unsafe")
        try:
            payload = json.loads(self.token_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderError("Passbolt token state is invalid") from exc
        return self._validated_token_state(payload)

    def _validated_token_state(self, state: Any) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise ProviderError("Passbolt token state is invalid")
        access = state.get("access_token")
        refresh = state.get("refresh_token")
        if (
            state.get("base_url") != self.base_url
            or state.get("service_user_id") != self.service_user_id
            or not isinstance(access, str)
            or _jwt_expiry(access) is None
            or not isinstance(refresh, str)
            or not refresh
        ):
            raise ProviderError("Passbolt token state identity is invalid")
        return dict(state)

    def _save_token_state_sync(self, state: Mapping[str, Any]) -> None:
        if self.token_file is None:
            raise ProviderError("Passbolt writable token state is not configured")
        if not _private_directory(self.token_file.parent):
            raise ProviderError("Passbolt token state custody is unsafe")
        if _path_present(self.token_file) and not _private_file(self.token_file, max_bytes=65_536):
            raise ProviderError("Passbolt token state custody is unsafe")
        validated = self._validated_token_state(state)
        try:
            descriptor, raw_path = tempfile.mkstemp(
                prefix=f".{self.token_file.name}.", dir=self.token_file.parent
            )
            path = Path(raw_path)
            try:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(validated, handle, separators=(",", ":"), sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
                path.replace(self.token_file)
                if not _private_file(self.token_file, max_bytes=65_536):
                    raise ProviderError("Passbolt token state custody is unsafe")
            finally:
                path.unlink(missing_ok=True)
        except OSError as exc:
            raise ProviderError("Passbolt token state is not writable") from exc

    async def _load_token_state(self) -> dict[str, Any] | None:
        if not self._token_loaded:
            self._token_state = await asyncio.to_thread(self._load_token_state_sync)
            self._token_loaded = True
        return self._token_state

    @staticmethod
    def _token_usable(state: Mapping[str, Any] | None, *, leeway: int = 60) -> bool:
        if not state:
            return False
        token = state.get("access_token")
        if not isinstance(token, str) or not token:
            return False
        expiry = _jwt_expiry(token)
        return expiry is None or expiry > int(time.time()) + leeway

    async def _import_server_key(self) -> int:
        response = await self.http.request_json("GET", f"{self.base_url}/auth/verify.json")
        body = _unwrap(response)
        if not isinstance(body, dict):
            raise ProviderResponseError("Passbolt auth verify response is invalid")
        fingerprint = str(body.get("fingerprint", "")).replace(" ", "").upper()
        keydata = body.get("keydata")
        if fingerprint != self.server_fingerprint or not isinstance(keydata, str):
            raise ProviderResponseError("Passbolt server identity verification failed")
        await self._gpg(["--import"], stdin=keydata)
        header = response.get("header") if isinstance(response, dict) else None
        server_time = header.get("servertime") if isinstance(header, dict) else None
        return int(server_time) if isinstance(server_time, (str, int, float)) else int(time.time())

    async def _jwt_login(self) -> dict[str, Any]:
        if not self._configured():
            raise ProviderError("Passbolt server custody is not configured")
        server_time = await self._import_server_key()
        verify_token = str(uuid4())
        challenge = {
            "version": "1.0.0",
            "domain": self.base_url + "/",
            "verify_token": verify_token,
            "verify_token_expiry": str(server_time + 60),
        }
        encrypted = await self._encrypt_json(challenge, self.server_fingerprint)
        response = await self.http.request_json(
            "POST",
            f"{self.base_url}/auth/jwt/login.json",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            payload={"user_id": self.service_user_id, "challenge": encrypted},
        )
        body = _unwrap(response)
        if not isinstance(body, dict) or not isinstance(body.get("challenge"), str):
            raise ProviderResponseError("Passbolt JWT login response is invalid")
        returned = await self._decrypt_json(body["challenge"], expected_signer=self.server_fingerprint)
        if returned.get("verify_token") != verify_token:
            raise ProviderResponseError("Passbolt JWT challenge verification failed")
        access = returned.get("access_token")
        refresh = returned.get("refresh_token")
        if not isinstance(access, str) or not access or not isinstance(refresh, str) or not refresh:
            raise ProviderResponseError("Passbolt JWT login response is incomplete")
        return {
            "base_url": self.base_url,
            "service_user_id": self.service_user_id,
            "created_at": int(time.time()),
            "access_token": access,
            "refresh_token": refresh,
        }

    async def _refresh(self, refresh_token: str) -> dict[str, Any]:
        response = await self.http.request_json(
            "POST",
            f"{self.base_url}/auth/jwt/refresh.json",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            payload={"user_id": self.service_user_id, "refresh_token": refresh_token},
        )
        body = _unwrap(response)
        if not isinstance(body, dict):
            raise ProviderResponseError("Passbolt JWT refresh response is invalid")
        access = body.get("access_token")
        refresh = body.get("refresh_token")
        if not isinstance(access, str) or not access or not isinstance(refresh, str) or not refresh:
            raise ProviderResponseError("Passbolt JWT refresh response is incomplete")
        return {
            "base_url": self.base_url,
            "service_user_id": self.service_user_id,
            "created_at": int(time.time()),
            "access_token": access,
            "refresh_token": refresh,
        }

    async def _access_token(self, *, force: bool = False, stale_token: str | None = None) -> str:
        async with self._token_lock:
            state = await self._load_token_state()
            current = state.get("access_token") if isinstance(state, dict) else None
            if (
                stale_token
                and isinstance(current, str)
                and current != stale_token
                and self._token_usable(state)
            ):
                return current
            if not force and self._token_usable(state):
                assert isinstance(current, str)
                return current
            refresh = state.get("refresh_token") if isinstance(state, dict) else None
            if isinstance(refresh, str) and refresh:
                try:
                    next_state = await self._refresh(refresh)
                except (ProviderAuthenticationError, ProviderHttpError, ProviderResponseError):
                    # Some Passbolt builds rotate the refresh token only via a
                    # cookie. This transport intentionally never consumes
                    # provider cookies, so a body without both tokens falls
                    # back to a full signed login under the same single-flight.
                    next_state = await self._jwt_login()
            else:
                next_state = await self._jwt_login()
            await asyncio.to_thread(self._save_token_state_sync, next_state)
            self._token_state = next_state
            return str(next_state["access_token"])

    async def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        idempotent: bool = False,
    ) -> Any:
        token = await self._access_token()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "ZAI-MCP-Platform/0.2.0 Passbolt",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        try:
            return await self.http.request_json(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                payload=payload,
                params=params,
                idempotent=idempotent,
            )
        except ProviderAuthenticationError:
            if method.upper() not in {"GET", "HEAD"}:
                # Never replay a dispatched mutation. The durable write ledger
                # keeps the result pending for explicit reconciliation.
                raise
            token = await self._access_token(force=True, stale_token=token)
            headers["Authorization"] = f"Bearer {token}"
            return await self.http.request_json(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                payload=payload,
                params=params,
                idempotent=idempotent,
            )

    async def status(self) -> dict[str, bool]:
        auth_ready = False
        decrypt_ready = False
        resources: Sequence[Any] = []
        if not self._configured():
            # Silence here is indistinguishable from a live outage: the tool
            # still answers provider_enabled=true with both flags false.
            logger.warning(
                "Passbolt readiness probe skipped: server custody is not configured",
                extra={"provider": "passbolt", "operation": "status", "error_code": "custody_not_configured"},
            )
        if self._configured():
            try:
                payload = await self._request("GET", "/resources.json", params={"limit": 5})
                body = _unwrap(payload)
                auth_ready = isinstance(body, (list, dict))
                candidate = (
                    body
                    if isinstance(body, list)
                    else body.get("resources", body.get("data", []))
                    if isinstance(body, dict)
                    else []
                )
                resources = candidate if isinstance(candidate, list) else []
                auth_ready = isinstance(candidate, list)
            except ProviderError as exc:
                # Safe with any embedding application's formatter: never attach
                # exception objects, tracebacks or provider response text.
                logger.warning(
                    "Passbolt auth probe failed",
                    extra={
                        "provider": "passbolt",
                        "operation": "status",
                        "error_code": "auth_probe_failed",
                        "exception_type": type(exc).__name__,
                    },
                )
                auth_ready = False
            if auth_ready:
                encrypted = next(
                    (
                        item.get("metadata")
                        for item in resources[:5]
                        if isinstance(item, dict) and isinstance(item.get("metadata"), str)
                    ),
                    None,
                )
                if encrypted:
                    try:
                        resource = next(
                            (
                                item
                                for item in resources[:5]
                                if isinstance(item, dict) and item.get("metadata") == encrypted
                            ),
                            {},
                        )
                        key_id = resource.get("metadata_key_id") if isinstance(resource, dict) else None
                        key_type = resource.get("metadata_key_type") if isinstance(resource, dict) else None
                        if key_type != "user_key":
                            await self._metadata_key(str(key_id) if key_id else None)
                        validate_v5_metadata(await self._decrypt_json(encrypted), strict_write=False)
                        resource_id = resource.get("id") if isinstance(resource, dict) else None
                        if resource_id:
                            secret = await self._secret_payload(str(resource_id))
                            decrypt_ready = bool(secret)
                    except ProviderError as exc:
                        logger.warning(
                            "Passbolt decrypt canary failed",
                            extra={
                                "provider": "passbolt",
                                "operation": "status",
                                "error_code": "decrypt_canary_failed",
                                "exception_type": type(exc).__name__,
                            },
                        )
                        decrypt_ready = False
                elif resources:
                    resource = resources[0]
                    resource_id = resource.get("id") if isinstance(resource, dict) else None
                    if resource_id:
                        try:
                            secret = await self._secret_payload(str(resource_id))
                            decrypt_ready = bool(secret)
                        except ProviderError as exc:
                            logger.warning(
                                "Passbolt decrypt canary failed",
                                extra={
                                    "provider": "passbolt",
                                    "operation": "status",
                                    "error_code": "decrypt_canary_failed",
                                    "exception_type": type(exc).__name__,
                                },
                            )
                            decrypt_ready = False
        return {
            "provider_enabled": True,
            "auth_ready": auth_ready,
            "decrypt_ready": decrypt_ready,
        }

    @staticmethod
    def validate_search(query: str, target_url: str | None, limit: int) -> tuple[str, str | None, int]:
        normalized_query = _bounded_query(query, required=True)
        normalized_target = _https_url(target_url, "target_url") if target_url else None
        return normalized_query, normalized_target, _bounded_limit(limit)

    @staticmethod
    def validate_select(target_url: str, query: str, limit: int) -> tuple[str, str, int]:
        return (
            _https_url(target_url, "target_url"),
            _bounded_query(query, required=False),
            _bounded_limit(limit),
        )

    async def _hydrate_metadata(self, resource: Any) -> Any:
        if not isinstance(resource, dict) or not resource.get("metadata"):
            return resource
        key_id = resource.get("metadata_key_id")
        if resource.get("metadata_key_type") != "user_key":
            await self._metadata_key(str(key_id) if key_id else None)
        decrypted = await self._decrypt_json(str(resource["metadata"]))
        metadata = validate_v5_metadata(decrypted, strict_write=False)
        uris = metadata["uris"]
        return {
            **resource,
            "name": metadata["name"],
            "username": metadata["username"],
            "uri": uris[0] if uris else None,
            "description": metadata["description"],
        }

    async def _all_resources(self) -> list[dict[str, Any]]:
        payload = await self._request("GET", "/resources.json")
        body = _unwrap(payload)
        if isinstance(body, dict):
            body = body.get("resources", body.get("data", []))
        if isinstance(body, (str, bytes)) or not isinstance(body, Sequence):
            raise ProviderResponseError("Passbolt resources response is not a list")
        if len(body) > MAX_RESOURCE_SCAN:
            raise ProviderResponseError("Passbolt resource scan exceeded the governed bound")
        rows: list[dict[str, Any]] = []
        for item in body:
            hydrated = await self._hydrate_metadata(item)
            safe = safe_resource(hydrated)
            if safe.get("resource_id"):
                rows.append(safe)
        if body and not any(item.get("name") or item.get("uri") or item.get("username") for item in rows):
            raise ProviderResponseError("Passbolt safe metadata is unavailable")
        return rows

    def _score(self, resource: dict[str, Any], query: str, target_url: str | None) -> tuple[int, str]:
        score = 0
        reasons: list[str] = []
        lowered = query.lower()
        for field, weight in (("name", 35), ("uri", 25), ("username", 10)):
            if lowered and lowered in str(resource.get(field, "")).lower():
                score += weight
                reasons.append(f"{field}_contains_query")
        decision = self.domain_decision(str(resource.get("uri") or ""), target_url)
        if target_url and decision.matches:
            score += 60
            reasons.append(decision.reason)
        elif target_url:
            score -= 20
            reasons.append(decision.reason)
        return score, ",".join(reasons) or "metadata_match"

    async def search(
        self,
        query: str,
        target_url: str | None = None,
        limit: int = 20,
        *,
        allowed_resource_ids: frozenset[str] | None = None,
    ) -> dict[str, Any]:
        query, target_url, limit = self.validate_search(query, target_url, limit)
        rows = await self._all_resources()
        if allowed_resource_ids is not None:
            rows = [row for row in rows if str(row.get("resource_id")) in allowed_resource_ids]
        matching = [
            row
            for row in rows
            if query.lower()
            in " ".join(str(row.get(field, "")) for field in ("name", "uri", "username")).lower()
            or (target_url and self.domain_decision(str(row.get("uri") or ""), target_url).matches)
        ]
        ranked = []
        for row in matching:
            score, reason = self._score(row, query, target_url)
            ranked.append({**row, "score": score, "reason": reason})
        ranked.sort(key=lambda item: (-int(item["score"]), str(item.get("name", "")).lower()))
        return {"resources": ranked[:limit], "secret_disclosed": False}

    async def select(
        self,
        target_url: str,
        query: str = "",
        limit: int = 10,
        *,
        allowed_resource_ids: frozenset[str] | None = None,
    ) -> dict[str, Any]:
        target_url, query, limit = self.validate_select(target_url, query, limit)
        search_query = query or (_host(target_url) or "")
        result = await self.search(
            search_query,
            target_url,
            limit,
            allowed_resource_ids=allowed_resource_ids,
        )
        resource = result["resources"][0] if result["resources"] else None
        decision = self.domain_decision(str(resource.get("uri") or "") if resource else None, target_url)
        return {
            "resource": resource,
            "domain_match": decision.matches,
            "confirmation_required": not decision.matches,
            "domain_reason": decision.reason,
            "secret_disclosed": False,
        }

    @staticmethod
    def _metadata(
        *, name: str, uri: str | None, username: str | None, description: str | None
    ) -> dict[str, Any]:
        return validate_v5_metadata(
            {
                "object_type": RESOURCE_METADATA_OBJECT_TYPE,
                "resource_type_id": V5_DEFAULT_RESOURCE_TYPE_ID,
                "name": name,
                "username": username,
                "uris": [uri] if uri else [],
                "description": description,
                "custom_fields": [],
            }
        )

    @staticmethod
    def validate_secret_source(source: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(source, Mapping):
            raise ValueError("secret_source must be an object")
        kind = source.get("kind")
        if kind == "server_generated":
            length = source.get("length", 32)
            if isinstance(length, bool) or not isinstance(length, int) or not 24 <= length <= 128:
                raise ValueError("server-generated secret length must be between 24 and 128")
            if set(source) - {"kind", "length"}:
                raise ValueError("secret_source contains unsupported fields")
            return {"kind": kind, "length": length}
        if kind == "sealed_ref":
            ref = source.get("ref")
            if not isinstance(ref, str) or not _SEALED_REF_RE.fullmatch(ref) or ".." in ref:
                raise ValueError("sealed_ref is invalid")
            if set(source) != {"kind", "ref"}:
                raise ValueError("secret_source contains unsupported fields")
            return {"kind": kind, "ref": ref}
        raise ValueError("secret_source kind must be server_generated or sealed_ref")

    def _secret_from_source(self, source: Mapping[str, Any]) -> tuple[str, Path | None]:
        normalized = self.validate_secret_source(source)
        if normalized["kind"] == "server_generated":
            length = int(normalized["length"])
            return secrets.token_urlsafe(length)[:length], None
        path = self._sealed_ref_path(normalized)
        assert path is not None
        try:
            info = path.lstat()
            if (
                path.is_symlink()
                or not path.is_file()
                or not _private_mode(info.st_mode)
                or not _trusted_owner(info.st_uid)
            ):
                raise ProviderError("Passbolt sealed_ref is not a private regular file")
            if info.st_size > 65_536:
                raise ProviderError("Passbolt sealed_ref exceeds the governed bound")
            value = path.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise ProviderError("Passbolt sealed_ref is unavailable") from exc
        if not value:
            raise ProviderError("Passbolt sealed_ref is empty")
        return value, path

    def _sealed_ref_path(self, source: Mapping[str, Any]) -> Path | None:
        normalized = self.validate_secret_source(source)
        if normalized["kind"] == "server_generated":
            return None
        if self.sealed_ref_dir is None or not self.sealed_ref_dir.is_dir():
            raise ProviderError("Passbolt sealed-ref custody is not configured")
        try:
            directory_info = self.sealed_ref_dir.lstat()
        except OSError as exc:
            raise ProviderError("Passbolt sealed-ref custody is unavailable") from exc
        if (
            not self.sealed_ref_dir.is_absolute()
            or self.sealed_ref_dir.is_symlink()
            or not stat.S_ISDIR(directory_info.st_mode)
            or not _private_mode(directory_info.st_mode)
            or not _trusted_owner(directory_info.st_uid)
        ):
            raise ProviderError("Passbolt sealed-ref custody permissions are unsafe")
        return self.sealed_ref_dir / str(normalized["ref"])

    def secret_source_consumed(self, source: Mapping[str, Any]) -> bool:
        path = self._sealed_ref_path(source)
        if path is None:
            return True
        try:
            return not path.exists() and not path.is_symlink()
        except OSError:
            return False

    @staticmethod
    def _consume_sealed_ref(path: Path | None, *, missing_ok: bool = False) -> None:
        if path is None:
            return
        try:
            path.unlink(missing_ok=missing_ok)
            if path.exists() or path.is_symlink():
                raise OSError("sealed_ref remains present")
        except OSError as exc:
            raise ProviderError("Passbolt sealed_ref could not be consumed after write") from exc

    async def _load_metadata_keys(self) -> None:
        if self._metadata_keys_loaded:
            return
        payload = await self._request(
            "GET", "/metadata/keys.json", params={"contain[metadata_private_keys]": 1}
        )
        body = _unwrap(payload)
        if not isinstance(body, list):
            raise ProviderResponseError("Passbolt metadata keys response is invalid")
        for item in body:
            if not isinstance(item, dict) or item.get("deleted"):
                continue
            key_id = item.get("id")
            fingerprint = item.get("fingerprint")
            armored = item.get("armored_key")
            if all(isinstance(value, str) and value for value in (key_id, fingerprint, armored)):
                private_rows = item.get("metadata_private_keys")
                own = (
                    next(
                        (
                            row
                            for row in private_rows
                            if isinstance(row, dict)
                            and row.get("user_id") == self.service_user_id
                            and isinstance(row.get("data"), str)
                        ),
                        None,
                    )
                    if isinstance(private_rows, list)
                    else None
                )
                if own is None:
                    continue
                plaintext = await self._decrypt_text(str(own["data"]), expected_signer=self.user_fingerprint)
                try:
                    private_data = json.loads(plaintext)
                except json.JSONDecodeError as exc:
                    raise ProviderResponseError("Passbolt metadata private key envelope is invalid") from exc
                if not isinstance(private_data, dict):
                    raise ProviderResponseError("Passbolt metadata private key envelope is invalid")
                expected_fingerprint = str(fingerprint).replace(" ", "").upper()
                actual_fingerprint = str(private_data.get("fingerprint", "")).replace(" ", "").upper()
                domain = str(private_data.get("domain", "")).rstrip("/")
                private_armored = private_data.get("armored_key")
                if (
                    private_data.get("object_type") != METADATA_PRIVATE_KEY_OBJECT_TYPE
                    or domain != self.base_url
                    or actual_fingerprint != expected_fingerprint
                    or expected_fingerprint not in self._metadata_fingerprints
                    or private_data.get("passphrase") not in {None, ""}
                    or not isinstance(private_armored, str)
                    or "PRIVATE KEY BLOCK" not in private_armored
                ):
                    raise ProviderResponseError("Passbolt metadata private key trust verification failed")
                await self._gpg(["--import"], stdin=private_armored)
                fingerprints = await self._gpg(["--with-colons", "--fingerprint", expected_fingerprint])
                if expected_fingerprint not in fingerprints.replace(":", "").upper():
                    raise ProviderResponseError("Passbolt imported metadata key fingerprint does not match")
                normalized_id = str(key_id)
                self._metadata_key_cache[normalized_id] = {
                    "id": str(key_id),
                    "fingerprint": expected_fingerprint,
                }
                if not item.get("expired"):
                    if self._active_metadata_key_id is not None:
                        raise ProviderResponseError("Passbolt has multiple active metadata keys")
                    self._active_metadata_key_id = normalized_id
        self._metadata_keys_loaded = True
        if not self._metadata_key_cache:
            raise ProviderResponseError("Passbolt metadata private keys are unavailable")

    async def _metadata_key(self, key_id: str | None = None) -> dict[str, str]:
        await self._load_metadata_keys()
        selected = key_id or self._active_metadata_key_id
        if selected is None or selected not in self._metadata_key_cache:
            raise ProviderResponseError("Passbolt requested metadata key is unavailable")
        return dict(self._metadata_key_cache[selected])

    async def _folder_id(self, folder: str | None) -> str | None:
        if folder is None:
            return None
        try:
            return _uuid(folder, "folder")
        except ValueError:
            payload = await self._request("GET", "/folders.json")
            body = _unwrap(payload)
            if isinstance(body, list):
                exact = [item for item in body if isinstance(item, dict) and item.get("name") == folder]
                if len(exact) == 1 and exact[0].get("id"):
                    return str(exact[0]["id"])
            raise ValueError("folder must identify exactly one existing folder") from None

    async def create_resource(
        self,
        *,
        name: str,
        uri: str,
        username: str,
        secret_source: Mapping[str, Any],
        description: str | None = None,
        folder: str | None = None,
        share_with_groups: list[str] | None = None,
        share_with_users: list[str] | None = None,
        resource_type: str = "v5-default",
        checkpoint: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        resume_resource_id: str | None = None,
    ) -> dict[str, Any]:
        if resource_type != "v5-default":
            raise ValueError("only resource_type=v5-default is allowed")
        if resume_resource_id is not None:
            resource_id = _uuid(resume_resource_id, "resource_id")
            if not share_with_groups and not share_with_users:
                raise ProviderResponseError("Passbolt resource checkpoint has no remaining share")
            sealed_path = self._sealed_ref_path(secret_source)
            await asyncio.to_thread(self._consume_sealed_ref, sealed_path, missing_ok=True)
            await self.share_resource(
                resource_id=resource_id,
                groups=share_with_groups,
                users=share_with_users,
                permission="read",
            )
            return {"resource_id": resource_id, "created": True}
        metadata = self._metadata(
            name=_text(name, "name", 255, required=True) or "",
            uri=_https_url(uri, "uri"),
            username=_text(username, "username", 255),
            description=_text(description, "description", 10_000),
        )
        secret, sealed_path = await asyncio.to_thread(self._secret_from_source, secret_source)
        metadata_key = await self._metadata_key()
        encrypted_metadata = await self._encrypt_json(metadata, metadata_key["fingerprint"])
        encrypted_secret = await self._encrypt_json(
            {
                "object_type": SECRET_DATA_OBJECT_TYPE,
                "password": secret,
                "description": None,
                "custom_fields": [],
            },
            self.user_fingerprint,
        )
        payload = {
            "folder_parent_id": await self._folder_id(folder),
            "personal": True,
            "expired": None,
            "metadata_key_id": metadata_key["id"],
            "metadata_key_type": "shared_key",
            "metadata": encrypted_metadata,
            "resource_type_id": V5_DEFAULT_RESOURCE_TYPE_ID,
            # Passbolt CE 5.13 accepts the v5 secret as a per-recipient object.
            "secrets": [{"user_id": self.service_user_id, "data": encrypted_secret}],
        }
        result = _unwrap(await self._request("POST", "/resources.json", payload=payload))
        if not isinstance(result, dict) or not result.get("id"):
            raise ProviderResponseError("Passbolt create resource response is invalid")
        resource_id = _uuid(str(result["id"]), "resource_id")
        if checkpoint is not None:
            await checkpoint({"checkpoint": "resource_created", "resource_id": resource_id})
        await asyncio.to_thread(self._consume_sealed_ref, sealed_path)
        if share_with_groups or share_with_users:
            await self.share_resource(
                resource_id=resource_id,
                groups=share_with_groups,
                users=share_with_users,
                permission="read",
            )
        return {"resource_id": resource_id, "created": True}

    async def _resource(self, resource_id: str) -> dict[str, Any]:
        payload = await self._request(
            "GET",
            f"/resources/{quote(_uuid(resource_id, 'resource_id'))}.json",
            params={"contain[secret]": 1, "contain[permissions]": 1},
        )
        body = _unwrap(payload)
        if not isinstance(body, dict):
            raise ProviderResponseError("Passbolt resource response is invalid")
        return body

    async def update_resource(
        self,
        *,
        resource_id: str,
        fields: Mapping[str, Any],
        expected_modified: str,
    ) -> dict[str, Any]:
        resource = await self._resource(resource_id)
        if str(resource.get("modified") or "") != expected_modified:
            raise PermissionError("Passbolt resource changed since confirmation")
        hydrated = await self._hydrate_metadata(resource)
        if not isinstance(hydrated, dict):
            raise ProviderResponseError("Passbolt resource metadata is invalid")
        allowed = {"name", "uri", "username", "description", "secret_source"}
        if not isinstance(fields, Mapping) or not fields or set(fields) - allowed:
            raise ValueError("Passbolt update fields are empty or unsupported")
        metadata = self._metadata(
            name=_text(fields.get("name", hydrated.get("name")), "name", 255, required=True) or "",
            uri=_https_url(str(fields.get("uri", hydrated.get("uri"))), "uri")
            if fields.get("uri", hydrated.get("uri"))
            else None,
            username=_text(fields.get("username", hydrated.get("username")), "username", 255),
            description=_text(fields.get("description"), "description", 10_000)
            if "description" in fields
            else _text(hydrated.get("description"), "description", 10_000),
        )
        metadata_key = await self._metadata_key()
        payload: dict[str, Any] = {
            "folder_parent_id": resource.get("folder_parent_id"),
            "expired": resource.get("expired"),
            "metadata_key_id": metadata_key["id"],
            "metadata_key_type": "shared_key",
            "metadata": await self._encrypt_json(metadata, metadata_key["fingerprint"]),
            "resource_type_id": V5_DEFAULT_RESOURCE_TYPE_ID,
        }
        if "secret_source" in fields:
            source = fields["secret_source"]
            if not isinstance(source, Mapping):
                raise ValueError("secret_source must be an object")
            password, sealed_path = await asyncio.to_thread(self._secret_from_source, source)
            secret_value: dict[str, Any] = {
                "object_type": SECRET_DATA_OBJECT_TYPE,
                "password": password,
                "description": None,
                "custom_fields": [],
            }
            payload["secrets"] = await self._encrypted_secrets_for_resource(resource, secret_value)
        result = _unwrap(
            await self._request(
                "PUT", f"/resources/{quote(_uuid(resource_id, 'resource_id'))}.json", payload=payload
            )
        )
        if not isinstance(result, dict):
            raise ProviderResponseError("Passbolt update resource response is invalid")
        await asyncio.to_thread(
            self._consume_sealed_ref,
            sealed_path if "secret_source" in fields else None,
        )
        return {"resource_id": _uuid(resource_id, "resource_id"), "updated": True}

    async def create_folder(
        self,
        *,
        name: str,
        parent: str | None = None,
        share_with_groups: list[str] | None = None,
        share_with_users: list[str] | None = None,
        checkpoint: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        resume_folder_id: str | None = None,
    ) -> dict[str, Any]:
        if resume_folder_id is not None:
            folder_id = _uuid(resume_folder_id, "folder_id")
            if not share_with_groups and not share_with_users:
                raise ProviderResponseError("Passbolt folder checkpoint has no remaining share")
            await self._share_folder(folder_id, share_with_groups, share_with_users, "read")
            return {"folder_id": folder_id}
        payload = {
            "name": _text(name, "name", 255, required=True),
            "folder_parent_id": await self._folder_id(parent),
        }
        result = _unwrap(await self._request("POST", "/folders.json", payload=payload))
        if not isinstance(result, dict) or not result.get("id"):
            raise ProviderResponseError("Passbolt create folder response is invalid")
        folder_id = _uuid(str(result["id"]), "folder_id")
        if checkpoint is not None:
            await checkpoint({"checkpoint": "folder_created", "folder_id": folder_id})
        if share_with_groups or share_with_users:
            await self._share_folder(folder_id, share_with_groups, share_with_users, "read")
        return {"folder_id": folder_id}

    async def _directory(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        groups_payload, users_payload = await asyncio.gather(
            self._request("GET", "/groups.json", params={"contain[groups_users.user.gpgkey]": 1}),
            self._request("GET", "/users.json", params={"contain[gpgkey]": 1}),
        )
        groups = _unwrap(groups_payload)
        users = _unwrap(users_payload)
        if not isinstance(groups, list) or not isinstance(users, list):
            raise ProviderResponseError("Passbolt sharing directory response is invalid")
        return (
            [
                item
                for item in groups
                if isinstance(item, dict) and not item.get("deleted") and item.get("active") is not False
            ],
            [
                item
                for item in users
                if isinstance(item, dict)
                and not item.get("deleted")
                and not item.get("disabled")
                and item.get("active") is not False
            ],
        )

    async def all_share_user_ids(self) -> list[str]:
        """Resolve all active users in this vault at approval-preparation time.

        Passbolt admins are ordinary directory users for sharing and therefore
        remain included. The service identity is omitted because it already
        owns the decryptable secret copy.
        """

        _groups, users = await self._directory()
        result: list[str] = []
        for user in users:
            if user.get("deleted") or user.get("disabled") or user.get("active") is False:
                continue
            raw_id = user.get("id")
            if raw_id is None:
                continue
            user_id = _uuid(str(raw_id), "user")
            if user_id == self.service_user_id:
                continue
            self._user_key(user)
            result.append(user_id)
        unique = sorted(set(result))
        if not unique:
            raise ProviderResponseError("Passbolt all-share audience has no active recipients")
        return unique

    @staticmethod
    def _user_key(user: Mapping[str, Any]) -> tuple[str, str, str]:
        user_id = user.get("id")
        key = user.get("gpgkey") or user.get("gpg_key")
        fingerprint = key.get("fingerprint") if isinstance(key, dict) else None
        armored = key.get("armored_key") if isinstance(key, dict) else None
        if not all(isinstance(value, str) and value for value in (user_id, fingerprint, armored)):
            raise ProviderResponseError("Passbolt recipient GPG key is unavailable")
        return str(user_id), str(fingerprint), str(armored)

    async def _encrypt_for_users(
        self, users: Sequence[Mapping[str, Any]], secret_payload: Mapping[str, Any]
    ) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        seen: set[str] = set()
        for user in users:
            user_id, fingerprint, armored = self._user_key(user)
            if user_id in seen:
                continue
            seen.add(user_id)
            await self._gpg(["--import"], stdin=armored)
            rows.append({"user_id": user_id, "data": await self._encrypt_json(secret_payload, fingerprint)})
        return rows

    async def _encrypted_secrets_for_resource(
        self, resource: Mapping[str, Any], secret_payload: Mapping[str, Any]
    ) -> list[dict[str, str]]:
        groups, users = await self._directory()
        by_user = {str(user.get("id")): user for user in users if user.get("id")}
        by_group = {str(group.get("id")): group for group in groups if group.get("id")}
        recipient_ids = {self.service_user_id}
        permissions = resource.get("permissions")
        if isinstance(permissions, list):
            for permission in permissions:
                if not isinstance(permission, dict):
                    continue
                target = str(permission.get("aro_foreign_key") or "")
                if permission.get("aro") == "User" and target:
                    recipient_ids.add(target)
                if permission.get("aro") == "Group" and target in by_group:
                    members = by_group[target].get("groups_users")
                    if isinstance(members, list):
                        for member in members:
                            if not isinstance(member, dict):
                                continue
                            user = member.get("user")
                            member_id = user.get("id") if isinstance(user, dict) else member.get("user_id")
                            if member_id:
                                recipient_ids.add(str(member_id))
        missing = recipient_ids - set(by_user)
        if missing:
            raise ProviderResponseError("Passbolt complete recipient key set is unavailable")
        return await self._encrypt_for_users(
            [by_user[user_id] for user_id in sorted(recipient_ids)], secret_payload
        )

    @staticmethod
    def _resolve(items: list[dict[str, Any]], refs: list[str], kind: str) -> list[dict[str, Any]]:
        resolved: list[dict[str, Any]] = []
        for ref in refs:
            normalized = _uuid(ref, kind)
            matches = [item for item in items if str(item.get("id")) == normalized]
            if len(matches) != 1:
                raise ValueError(f"Passbolt {kind} UUID is not an active allowlisted entry")
            resolved.append(matches[0])
        return resolved

    async def _share_permissions(
        self, groups: list[str] | None, users: list[str] | None, permission: str
    ) -> list[dict[str, Any]]:
        if permission not in _PERMISSIONS:
            raise ValueError("permission must be read, update or owner")
        if not groups and not users:
            raise ValueError("groups or users are required")
        directory_groups, directory_users = await self._directory()
        selected_groups = self._resolve(directory_groups, groups or [], "group")
        selected_users = self._resolve(directory_users, users or [], "user")
        return [
            {"is_new": True, "aro": "Group", "aro_foreign_key": item["id"], "type": _PERMISSIONS[permission]}
            for item in selected_groups
        ] + [
            {"is_new": True, "aro": "User", "aro_foreign_key": item["id"], "type": _PERMISSIONS[permission]}
            for item in selected_users
        ]

    @staticmethod
    def _permissions_cover(
        existing: Any,
        desired: Sequence[Mapping[str, Any]],
    ) -> bool:
        if not isinstance(existing, list):
            return False
        normalized: set[tuple[str, str, int]] = set()
        for item in existing:
            if not isinstance(item, Mapping):
                continue
            aro = item.get("aro")
            foreign_key = item.get("aro_foreign_key")
            permission_type = item.get("type")
            if isinstance(aro, str) and isinstance(foreign_key, str):
                if not isinstance(permission_type, (int, str)):
                    continue
                try:
                    normalized.add((aro.casefold(), foreign_key, int(permission_type)))
                except (TypeError, ValueError):
                    continue
        for item in desired:
            aro = str(item.get("aro") or "").casefold()
            foreign_key = str(item.get("aro_foreign_key") or "")
            raw_permission_type = item.get("type")
            if not isinstance(raw_permission_type, (int, str)):
                return False
            try:
                permission_type = int(raw_permission_type)
            except (TypeError, ValueError):
                return False
            if not any(
                current_aro == aro and current_key == foreign_key and current_type >= permission_type
                for current_aro, current_key, current_type in normalized
            ):
                return False
        return bool(desired)

    async def _share_folder(
        self,
        folder_id: str,
        groups: list[str] | None,
        users: list[str] | None,
        permission: str,
    ) -> None:
        folder_id = _uuid(folder_id, "folder_id")
        permissions = await self._share_permissions(groups, users, permission)
        current = _unwrap(
            await self._request(
                "GET",
                f"/folders/{quote(folder_id)}.json",
                params={"contain[permissions]": 1},
            )
        )
        if isinstance(current, dict) and self._permissions_cover(current.get("permissions"), permissions):
            return
        await self._request(
            "PUT", f"/share/folder/{quote(folder_id)}.json", payload={"permissions": permissions}
        )

    async def share_resource(
        self,
        *,
        resource_id: str,
        groups: list[str] | None,
        users: list[str] | None,
        permission: str,
    ) -> dict[str, Any]:
        resource_id = _uuid(resource_id, "resource_id")
        permissions = await self._share_permissions(groups, users, permission)
        current = await self._resource(resource_id)
        if self._permissions_cover(current.get("permissions"), permissions):
            return {"shared": True}
        # Passbolt validates sharing server-side with simulate before apply. The
        # server-side service user remains the only decrypting identity; Passbolt
        # returns the exact recipients requiring encrypted copies.
        simulated = _unwrap(
            await self._request(
                "POST",
                f"/share/simulate/resource/{quote(resource_id)}.json",
                payload={"permissions": permissions},
            )
        )
        needed = simulated.get("changes", {}).get("added", []) if isinstance(simulated, dict) else []
        secret_payload = await self._secret_payload(resource_id)
        if not isinstance(needed, list):
            raise ProviderResponseError("Passbolt share simulation response is invalid")
        _groups, directory_users = await self._directory()
        by_user = {str(user.get("id")): user for user in directory_users if isinstance(user.get("id"), str)}
        needed_ids: list[str] = []
        for item in needed:
            if not isinstance(item, dict):
                continue
            nested_user = item.get("User") or item.get("user")
            user_id = (
                nested_user.get("id")
                if isinstance(nested_user, dict)
                else item.get("user_id") or item.get("aro_foreign_key")
            )
            if user_id:
                needed_ids.append(str(user_id))
        missing = set(needed_ids) - set(by_user)
        if missing:
            raise ProviderResponseError("Passbolt share recipient key set is unavailable")
        encrypted_secrets = await self._encrypt_for_users(
            [by_user[user_id] for user_id in needed_ids], secret_payload
        )
        if needed_ids and len(encrypted_secrets) != len(set(needed_ids)):
            raise ProviderResponseError("Passbolt share recipient encryption is incomplete")
        payload: dict[str, Any] = {"permissions": permissions}
        if encrypted_secrets:
            payload["secrets"] = encrypted_secrets
        await self._request("PUT", f"/share/resource/{quote(resource_id)}.json", payload=payload)
        return {"shared": True}

    async def _secret_payload(self, resource_id: str) -> dict[str, Any]:
        response = await self._request(
            "GET", f"/secrets/resource/{quote(_uuid(resource_id, 'resource_id'))}.json"
        )
        body = _unwrap(response)
        encrypted = body.get("data") if isinstance(body, dict) else None
        if not encrypted and isinstance(body, dict) and isinstance(body.get("secret"), dict):
            encrypted = body["secret"].get("data")
        if not isinstance(encrypted, str) or not encrypted:
            raise ProviderResponseError("Passbolt encrypted secret payload is unavailable")
        return await self._decrypt_json(encrypted)

    async def use_secret(
        self,
        *,
        resource_id: str,
        sink_ref: str,
        target_url: str | None,
        username: str | None,
    ) -> dict[str, bool]:
        secret = await self._secret_payload(resource_id)
        password = secret.get("password")
        if not isinstance(password, str) or not password:
            raise ProviderResponseError("Passbolt decrypted secret has no password")
        delivered = await self.sinks.deliver(
            sink_ref,
            resource_id=_uuid(resource_id, "resource_id"),
            username=username,
            password=password,
            target_url=target_url,
        )
        return {"delivered_to_sink": delivered}
