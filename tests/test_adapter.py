from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from zai_passbolt.adapter import (
    METADATA_PRIVATE_KEY_OBJECT_TYPE,
    PassboltAdapter,
    PassboltSinkDispatcher,
    safe_resource,
    validate_v5_metadata,
)
from zai_passbolt.transport import (
    ProviderAuthenticationError,
    ProviderError,
    ProviderResponseError,
)

STALE_ACCESS = "stale"
REFRESH_FIXTURE = "refresh"
EMBEDDED_PASSPHRASE_FIXTURE = "must-not-be-imported"  # noqa: S105 -- negative fixture
SINK_SECRET_FIXTURE = "sink-only-value"  # noqa: S105 -- sink-only test fixture
JWT_FIXTURE = "e30.eyJleHAiOjQxMDI0NDQ4MDB9.signature"  # noqa: S105 -- unsigned test JWT
PYTHON_EXECUTABLE = Path(sys.executable).resolve()
PYTHON_EXECUTABLE_SHA256 = hashlib.sha256(PYTHON_EXECUTABLE.read_bytes()).hexdigest()


class FakeHttp:
    def __init__(self, payload: Any) -> None:
        self.payload = payload
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

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
        self.calls.append((method, url, params))
        assert headers is not None and headers["Authorization"].startswith("Bearer ")
        assert payload is None
        assert idempotent is False
        return self.payload


def test_safe_resource_never_projects_secret_fields() -> None:
    result = safe_resource(
        {
            "id": "resource-1",
            "name": "Example",
            "uri": "https://example.com/login",
            "username": "operator",
            "password": "must-not-leak",
            "metadata": "encrypted-ciphertext",
            "secrets": [{"data": "must-not-leak"}],
        }
    )

    assert result == {
        "resource_id": "resource-1",
        "name": "Example",
        "uri": "https://example.com/login",
        "username": "operator",
    }


@pytest.mark.asyncio
async def test_search_returns_ranked_safe_metadata() -> None:
    http = FakeHttp(
        {
            "body": [
                {
                    "id": "resource-1",
                    "name": "Example admin",
                    "uri": "https://example.com/login",
                    "username": "operator",
                    "password": "must-not-leak",
                }
            ]
        }
    )
    adapter = PassboltAdapter("https://passbolt.example", "fixture-token", http=http)

    result = await adapter.search("Example", "https://example.com/admin", 10)

    assert result["secret_disclosed"] is False
    assert result["resources"][0]["resource_id"] == "resource-1"
    assert result["resources"][0]["score"] == 120
    assert "password" not in repr(result)
    assert http.calls == [
        (
            "GET",
            "https://passbolt.example/resources.json",
            None,
        )
    ]


@pytest.mark.asyncio
async def test_select_requires_confirmation_for_domain_mismatch() -> None:
    adapter = PassboltAdapter(
        "https://passbolt.example",
        "fixture-token",
        http=FakeHttp([{"id": "resource-1", "name": "Portal", "uri": "https://other.example/login"}]),
    )

    result = await adapter.select("https://target.example/login", "Portal", 10)

    assert result["domain_match"] is False
    assert result["confirmation_required"] is True


@pytest.mark.asyncio
async def test_encrypted_metadata_without_safe_fields_fails_closed() -> None:
    adapter = PassboltAdapter(
        "https://passbolt.example",
        "fixture-token",
        http=FakeHttp([{"id": "resource-1", "metadata": "encrypted"}]),
    )

    with pytest.raises(ProviderResponseError, match="metadata private keys"):
        await adapter.search("Example")


class UserKeyMetadataAdapter(PassboltAdapter):
    async def _metadata_key(self, key_id: str | None = None) -> dict[str, str]:
        raise AssertionError(f"user_key metadata must not load shared metadata key: {key_id}")

    async def _decrypt_json(self, armored: str, *, expected_signer: str | None = None) -> dict[str, Any]:
        assert armored == "user-key-encrypted"
        assert expected_signer is None
        return {
            "object_type": "PASSBOLT_RESOURCE_METADATA",
            "resource_type_id": "dd1f723d-0d1e-513f-8218-4055dc0530d0",
            "name": "User key resource",
            "username": "operator",
            "uris": ["https://example.com/login"],
            "description": None,
            "custom_fields": [],
        }


@pytest.mark.asyncio
async def test_user_key_metadata_decrypts_without_shared_metadata_key_lookup() -> None:
    adapter = UserKeyMetadataAdapter(
        "https://passbolt.example",
        "fixture-token",
        http=FakeHttp(
            [
                {
                    "id": "resource-1",
                    "metadata": "user-key-encrypted",
                    "metadata_key_type": "user_key",
                    "metadata_key_id": str(uuid4()),
                }
            ]
        ),
    )

    result = await adapter.search("User key")

    assert result["resources"][0]["resource_id"] == "resource-1"
    assert result["resources"][0]["uri"] == "https://example.com/login"


@pytest.mark.parametrize(
    "target",
    ["http://example.com", "https://user:pass@example.com", "https://example.com?q=secret"],
)
def test_target_url_is_strict_https(target: str) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        PassboltAdapter.validate_select(target, "", 10)


def test_existing_v5_metadata_read_mode_omits_unsafe_uri_and_custom_fields() -> None:
    payload = {
        "object_type": "PASSBOLT_RESOURCE_METADATA",
        "resource_type_id": "dd1f723d-0d1e-513f-8218-4055dc0530d0",
        "name": "Legacy resource",
        "username": "operator",
        "uris": ["http://legacy.example/login", "https://user:secret@example.com/login"],
        "description": "safe description",
        "custom_fields": [{"id": "opaque", "value": "must-not-project"}],
    }

    result = validate_v5_metadata(payload, strict_write=False)

    assert result["uris"] == ["http://legacy.example/login"]
    assert result["custom_fields"] == []
    assert "secret" not in repr(result)


def test_v5_metadata_write_mode_stays_strict_https_and_custom_field_free() -> None:
    payload = {
        "object_type": "PASSBOLT_RESOURCE_METADATA",
        "resource_type_id": "dd1f723d-0d1e-513f-8218-4055dc0530d0",
        "name": "New resource",
        "username": "operator",
        "uris": ["http://legacy.example/login"],
        "description": None,
        "custom_fields": [],
    }

    with pytest.raises(ValueError, match="HTTPS"):
        validate_v5_metadata(payload)


def test_domain_match_is_exact_origin_unless_relation_is_explicitly_allowlisted() -> None:
    strict = PassboltAdapter("https://passbolt.example", "fixture-token")
    delegated = PassboltAdapter(
        "https://passbolt.example",
        "fixture-token",
        domain_allowlist="example.com>login.example.com",
    )

    assert strict.domain_decision("https://example.com", "https://login.example.com").matches is False
    assert strict.domain_decision("https://example.com", "https://example.com:444").matches is False
    assert (
        strict.domain_decision("https://example.com:444/resource", "https://example.com:444/login").matches
        is True
    )
    decision = delegated.domain_decision("https://example.com", "https://login.example.com")
    assert decision.matches is True
    assert decision.reason == "explicit_allowlist_match"


@pytest.mark.parametrize("ref", ["sealed://one", "../one", "one/../../two", "", " space"])
def test_sealed_ref_is_an_opaque_identifier(ref: str) -> None:
    with pytest.raises(ValueError, match="sealed_ref"):
        PassboltAdapter.validate_secret_source({"kind": "sealed_ref", "ref": ref})


class RefreshAdapter(PassboltAdapter):
    def __init__(self, token_file: Path, *, refresh_fails: bool = False) -> None:
        super().__init__(
            "https://passbolt.example",
            "",
            token_file=token_file,
            http=FakeHttp({}),
        )
        self._token_state = {
            "access_token": STALE_ACCESS,
            "refresh_token": REFRESH_FIXTURE,
        }
        self._token_loaded = True
        self.refresh_calls = 0
        self.login_calls = 0
        self.refresh_fails = refresh_fails

    async def _refresh(self, refresh_token: str) -> dict[str, Any]:
        assert refresh_token == REFRESH_FIXTURE
        self.refresh_calls += 1
        await asyncio.sleep(0)
        if self.refresh_fails:
            raise ProviderResponseError("incomplete refresh")
        return {
            "base_url": self.base_url,
            "service_user_id": self.service_user_id,
            "access_token": JWT_FIXTURE,
            "refresh_token": "rotated-refresh",
        }

    async def _jwt_login(self) -> dict[str, Any]:
        self.login_calls += 1
        return {
            "base_url": self.base_url,
            "service_user_id": self.service_user_id,
            "access_token": JWT_FIXTURE,
            "refresh_token": "relogin-refresh",
        }


@pytest.mark.asyncio
async def test_jwt_refresh_is_singleflight_and_persisted(tmp_path: Path) -> None:
    token_file = tmp_path / "jwt-state.json"
    adapter = RefreshAdapter(token_file)

    first, second = await asyncio.gather(
        adapter._access_token(force=True, stale_token=STALE_ACCESS),
        adapter._access_token(force=True, stale_token=STALE_ACCESS),
    )

    assert first == second == JWT_FIXTURE
    assert adapter.refresh_calls == 1
    assert adapter.login_calls == 0
    persisted = json.loads(token_file.read_text(encoding="utf-8"))
    assert set(persisted) == {
        "base_url",
        "service_user_id",
        "access_token",
        "refresh_token",
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are required")
def test_token_state_rejects_world_readable_file(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    token_file = tmp_path / "jwt-state.json"
    token_file.write_text('{"access_token":"fixture"}', encoding="utf-8")
    token_file.chmod(0o644)
    adapter = PassboltAdapter("https://passbolt.example", token_file=token_file)

    with pytest.raises(ProviderError, match="custody is unsafe"):
        adapter._load_token_state_sync()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink behavior is required")
def test_token_state_rejects_symlink(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    target = tmp_path / "target.json"
    target.write_text('{"access_token":"fixture"}', encoding="utf-8")
    target.chmod(0o600)
    token_file = tmp_path / "jwt-state.json"
    token_file.symlink_to(target)
    adapter = PassboltAdapter("https://passbolt.example", token_file=token_file)

    with pytest.raises(ProviderError, match="custody is unsafe"):
        adapter._load_token_state_sync()


@pytest.mark.asyncio
async def test_incomplete_refresh_falls_back_to_full_signed_login(tmp_path: Path) -> None:
    adapter = RefreshAdapter(tmp_path / "jwt-state.json", refresh_fails=True)

    assert await adapter._access_token(force=True, stale_token=STALE_ACCESS) == JWT_FIXTURE
    assert adapter.refresh_calls == 1
    assert adapter.login_calls == 1


class AuthenticationFailureHttp:
    def __init__(self) -> None:
        self.calls = 0

    async def request_json(self, *_args: Any, **_kwargs: Any) -> Any:
        self.calls += 1
        raise ProviderAuthenticationError(401)


@pytest.mark.asyncio
async def test_mutation_is_never_replayed_after_authentication_failure() -> None:
    http = AuthenticationFailureHttp()
    adapter = PassboltAdapter("https://passbolt.example", "fixture-token", http=http)

    with pytest.raises(ProviderAuthenticationError):
        await adapter._request("POST", "/resources.json", payload={"opaque": True})

    assert http.calls == 1


class RefreshPayloadHttp:
    def __init__(self) -> None:
        self.payload: dict[str, Any] | None = None

    async def request_json(
        self, _method: str, _url: str, *, payload: dict[str, Any] | None = None, **_kwargs: Any
    ) -> Any:
        self.payload = payload
        return {"access_token": "rotated", "refresh_token": "rotated-refresh"}


@pytest.mark.asyncio
async def test_refresh_payload_is_bound_to_service_user_id() -> None:
    http = RefreshPayloadHttp()
    adapter = PassboltAdapter(
        "https://passbolt.example",
        service_user_id="11111111-1111-4111-8111-111111111111",
        http=http,
    )

    await adapter._refresh(REFRESH_FIXTURE)

    assert http.payload == {
        "user_id": "11111111-1111-4111-8111-111111111111",
        "refresh_token": REFRESH_FIXTURE,
    }


class LoginHttp:
    async def request_json(self, _method: str, _url: str, **_kwargs: Any) -> Any:
        return {"challenge": "signed-challenge"}


class SignedLoginAdapter(PassboltAdapter):
    def __init__(self) -> None:
        super().__init__(
            "https://passbolt.example",
            service_user_id="11111111-1111-4111-8111-111111111111",
            server_fingerprint="F" * 40,
            http=LoginHttp(),
        )
        self.expected_signer: str | None = None

    def _configured(self) -> bool:
        return True

    async def _import_server_key(self) -> int:
        return 1_800_000_000

    async def _decrypt_json(self, armored: str, *, expected_signer: str | None = None) -> dict[str, Any]:
        assert armored == "signed-challenge"
        self.expected_signer = expected_signer
        return {
            "verify_token": self.verify_token,
            "access_token": "access",
            "refresh_token": "refresh",
        }

    async def _encrypt_json(self, value: Any, recipient: str) -> str:
        self.verify_token = str(value["verify_token"])
        assert recipient == self.server_fingerprint
        return "encrypted-challenge"


@pytest.mark.asyncio
async def test_jwt_login_response_requires_pinned_server_signer() -> None:
    adapter = SignedLoginAdapter()

    result = await adapter._jwt_login()

    assert result["access_token"]
    assert adapter.expected_signer == adapter.server_fingerprint


class CanaryAdapter(PassboltAdapter):
    def _configured(self) -> bool:
        return True

    async def _request(self, method: str, path: str, **_kwargs: Any) -> Any:
        assert method == "GET"
        assert path == "/resources.json"
        return [{"id": str(uuid4()), "name": "legacy"}]

    async def _secret_payload(self, resource_id: str) -> dict[str, Any]:
        assert resource_id
        return {"password": "memory-only-canary"}


@pytest.mark.asyncio
async def test_status_requires_a_real_bounded_vault_decrypt_canary() -> None:
    result = await CanaryAdapter("https://passbolt.example").status()

    assert result == {
        "provider_enabled": True,
        "auth_ready": True,
        "decrypt_ready": True,
    }
    assert "memory-only-canary" not in repr(result)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are required")
def test_primary_gpg_and_passphrase_custody_fails_closed_on_permissions(
    tmp_path: Path,
) -> None:
    gpg_home = tmp_path / "gnupg"
    gpg_home.mkdir()
    gpg_home.chmod(0o700)
    passphrase = tmp_path / "passphrase"
    passphrase.write_text("fixture", encoding="utf-8")
    passphrase.chmod(0o644)
    adapter = PassboltAdapter(
        "https://passbolt.example",
        user_fingerprint="A" * 40,
        gpg_home=gpg_home,
        passphrase_file=passphrase,
    )

    assert adapter._decryption_configured() is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink behavior is required")
def test_primary_gpg_custody_rejects_symlinked_home(tmp_path: Path) -> None:
    real_home = tmp_path / "real-gnupg"
    real_home.mkdir()
    real_home.chmod(0o700)
    gpg_home = tmp_path / "gnupg"
    gpg_home.symlink_to(real_home, target_is_directory=True)
    passphrase = tmp_path / "passphrase"
    passphrase.write_text("fixture", encoding="utf-8")
    passphrase.chmod(0o600)
    adapter = PassboltAdapter(
        "https://passbolt.example",
        user_fingerprint="A" * 40,
        gpg_home=gpg_home,
        passphrase_file=passphrase,
    )

    assert adapter._decryption_configured() is False


class MetadataKeysAdapter(PassboltAdapter):
    def __init__(self, *, passphrase: str | None = None) -> None:
        self.user_fp = "A" * 40
        self.old_fp = "B" * 40
        self.new_fp = "C" * 40
        super().__init__(
            "https://passbolt.example",
            "fixture-token",
            service_user_id="11111111-1111-4111-8111-111111111111",
            user_fingerprint=self.user_fp,
            metadata_fingerprints=f"{self.old_fp},{self.new_fp}",
        )
        self.passphrase = passphrase
        self.signers: list[str | None] = []
        self.imported: list[str] = []

    async def _request(self, method: str, path: str, **_kwargs: Any) -> Any:
        assert method == "GET"
        assert path == "/metadata/keys.json"
        return [
            {
                "id": "old-key",
                "fingerprint": self.old_fp,
                "armored_key": "public-old",
                "expired": "2026-01-01T00:00:00Z",
                "metadata_private_keys": [{"user_id": self.service_user_id, "data": "old-envelope"}],
            },
            {
                "id": "active-key",
                "fingerprint": self.new_fp,
                "armored_key": "public-new",
                "expired": None,
                "metadata_private_keys": [{"user_id": self.service_user_id, "data": "active-envelope"}],
            },
        ]

    async def _decrypt_text(self, armored: str, *, expected_signer: str | None = None) -> str:
        self.signers.append(expected_signer)
        fingerprint = self.old_fp if armored == "old-envelope" else self.new_fp
        return json.dumps(
            {
                "object_type": METADATA_PRIVATE_KEY_OBJECT_TYPE,
                "domain": self.base_url,
                "fingerprint": fingerprint,
                "armored_key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture",
                "passphrase": self.passphrase,
            }
        )

    async def _gpg(self, args: list[str], *, stdin: str | None = None, **_kwargs: Any) -> str:
        if args == ["--import"]:
            assert stdin is not None
            self.imported.append(stdin)
            return ""
        return ":".join([self.old_fp, self.new_fp])


@pytest.mark.asyncio
async def test_v5_metadata_key_rotation_imports_pinned_history_and_selects_active() -> None:
    adapter = MetadataKeysAdapter()

    assert await adapter._metadata_key("old-key") == {
        "id": "old-key",
        "fingerprint": adapter.old_fp,
    }
    assert await adapter._metadata_key() == {
        "id": "active-key",
        "fingerprint": adapter.new_fp,
    }
    assert adapter.signers == [adapter.user_fp, adapter.user_fp]
    assert len(adapter.imported) == 2


@pytest.mark.asyncio
async def test_v5_metadata_private_key_envelope_rejects_embedded_passphrase() -> None:
    adapter = MetadataKeysAdapter(passphrase=EMBEDDED_PASSPHRASE_FIXTURE)

    with pytest.raises(ProviderResponseError, match="trust verification"):
        await adapter._metadata_key()

    assert adapter.imported == []


class CreateAdapter(PassboltAdapter):
    def __init__(self, sealed_dir: Path) -> None:
        super().__init__(
            "https://passbolt.example",
            "fixture-token",
            service_user_id="11111111-1111-4111-8111-111111111111",
            user_fingerprint="D" * 40,
            sealed_ref_dir=sealed_dir,
        )
        self.payload: dict[str, Any] | None = None
        self.fail = False
        self.share_calls = 0

    async def _metadata_key(self, key_id: str | None = None) -> dict[str, str]:
        assert key_id is None
        return {"id": "metadata-key", "fingerprint": "E" * 40}

    async def _encrypt_json(self, value: Any, recipient: str) -> str:
        assert recipient
        return "armored-metadata" if value.get("object_type", "").endswith("METADATA") else "armored-secret"

    async def _request(
        self, method: str, path: str, *, payload: dict[str, Any] | None = None, **_kwargs: Any
    ) -> Any:
        assert method == "POST"
        assert path == "/resources.json"
        self.payload = payload
        if self.fail:
            raise ProviderAuthenticationError(401)
        return {"id": "22222222-2222-4222-8222-222222222222"}

    async def share_resource(self, **_kwargs: Any) -> dict[str, bool]:
        self.share_calls += 1
        return {"shared": True}


@pytest.mark.asyncio
async def test_create_uses_v5_per_user_secret_array_and_consumes_sealed_ref_on_success(
    tmp_path: Path,
) -> None:
    sealed = tmp_path / "sealed-one"
    sealed.write_text("custody-only-value", encoding="utf-8")
    sealed.chmod(0o600)
    adapter = CreateAdapter(tmp_path)

    result = await adapter.create_resource(
        name="Vault entry",
        uri="https://example.com/login",
        username="operator",
        secret_source={"kind": "sealed_ref", "ref": sealed.name},
    )

    assert result == {
        "resource_id": "22222222-2222-4222-8222-222222222222",
        "created": True,
    }
    assert adapter.payload is not None
    assert adapter.payload["secrets"] == [
        {"user_id": "11111111-1111-4111-8111-111111111111", "data": "armored-secret"}
    ]
    assert adapter.payload["metadata_key_id"] == "metadata-key"
    assert not sealed.exists()
    assert "custody-only-value" not in repr(adapter.payload)


@pytest.mark.asyncio
async def test_search_filters_to_principal_allowed_resource_ids() -> None:
    allowed = "11111111-1111-4111-8111-111111111111"
    denied = "22222222-2222-4222-8222-222222222222"
    adapter = PassboltAdapter(
        "https://passbolt.example",
        "fixture-token",
        http=FakeHttp(
            [
                {"id": allowed, "name": "Allowed", "uri": "https://example.com"},
                {"id": denied, "name": "Denied", "uri": "https://example.com"},
            ]
        ),
    )

    result = await adapter.search(
        "Allowed",
        "https://example.com",
        10,
        allowed_resource_ids=frozenset({allowed}),
    )

    assert [row["resource_id"] for row in result["resources"]] == [allowed]


@pytest.mark.asyncio
async def test_sealed_ref_is_retained_after_ambiguous_upstream_failure(tmp_path: Path) -> None:
    sealed = tmp_path / "sealed-two"
    sealed.write_text("custody-only-value", encoding="utf-8")
    sealed.chmod(0o600)
    adapter = CreateAdapter(tmp_path)
    adapter.fail = True

    with pytest.raises(ProviderAuthenticationError):
        await adapter.create_resource(
            name="Vault entry",
            uri="https://example.com/login",
            username="operator",
            secret_source={"kind": "sealed_ref", "ref": sealed.name},
        )

    assert sealed.exists()


@pytest.mark.asyncio
async def test_resume_consumes_sealed_ref_before_finishing_share(tmp_path: Path) -> None:
    sealed = tmp_path / "sealed-resume"
    sealed.write_text("custody-only-value", encoding="utf-8")
    sealed.chmod(0o600)
    adapter = CreateAdapter(tmp_path)

    result = await adapter.create_resource(
        name="Vault entry",
        uri="https://example.com/login",
        username="operator",
        secret_source={"kind": "sealed_ref", "ref": sealed.name},
        share_with_groups=["44444444-4444-4444-8444-444444444444"],
        resume_resource_id="22222222-2222-4222-8222-222222222222",
    )

    assert result == {
        "resource_id": "22222222-2222-4222-8222-222222222222",
        "created": True,
    }
    assert not sealed.exists()
    assert adapter.payload is None
    assert adapter.share_calls == 1


class UpdateAdapter(PassboltAdapter):
    def __init__(self) -> None:
        super().__init__(
            "https://passbolt.example",
            "fixture-token",
            user_fingerprint="D" * 40,
        )
        self.metadata_plaintext: dict[str, Any] | None = None
        self.update_payload: dict[str, Any] | None = None

    async def _resource(self, resource_id: str) -> dict[str, Any]:
        assert resource_id == "44444444-4444-4444-8444-444444444444"
        return {
            "id": resource_id,
            "name": "Existing",
            "uri": "https://example.com/login",
            "username": "old-user",
            "description": "preserve-me",
            "modified": "2026-07-21T00:00:00Z",
            "folder_parent_id": None,
            "expired": None,
        }

    async def _metadata_key(self, key_id: str | None = None) -> dict[str, str]:
        assert key_id is None
        return {"id": "metadata-key", "fingerprint": "E" * 40}

    async def _encrypt_json(self, value: Any, recipient: str) -> str:
        assert recipient == "E" * 40
        self.metadata_plaintext = dict(value)
        return "armored-metadata"

    async def _request(
        self, method: str, path: str, *, payload: dict[str, Any] | None = None, **_kwargs: Any
    ) -> Any:
        assert method == "PUT"
        assert path.endswith(".json")
        self.update_payload = payload
        return {"id": "44444444-4444-4444-8444-444444444444"}


@pytest.mark.asyncio
async def test_metadata_only_update_preserves_existing_description() -> None:
    adapter = UpdateAdapter()

    result = await adapter.update_resource(
        resource_id="44444444-4444-4444-8444-444444444444",
        fields={"username": "new-user"},
        expected_modified="2026-07-21T00:00:00Z",
    )

    assert result["updated"] is True
    assert adapter.metadata_plaintext is not None
    assert adapter.metadata_plaintext["description"] == "preserve-me"
    assert adapter.metadata_plaintext["username"] == "new-user"
    assert adapter.update_payload is not None
    assert "secrets" not in adapter.update_payload


class RecipientAdapter(PassboltAdapter):
    def __init__(self) -> None:
        super().__init__(
            "https://passbolt.example",
            "fixture-token",
            service_user_id="11111111-1111-4111-8111-111111111111",
            user_fingerprint="A" * 40,
        )

    async def _directory(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        users = [
            {
                "id": "11111111-1111-4111-8111-111111111111",
                "gpgkey": {"fingerprint": "A" * 40, "armored_key": "service-key"},
            },
            {
                "id": "22222222-2222-4222-8222-222222222222",
                "gpgkey": {"fingerprint": "B" * 40, "armored_key": "user-key"},
            },
        ]
        groups = [
            {
                "id": "33333333-3333-4333-8333-333333333333",
                "groups_users": [{"user": {"id": "22222222-2222-4222-8222-222222222222"}}],
            }
        ]
        return groups, users

    async def _gpg(self, _args: list[str], **_kwargs: Any) -> str:
        return ""

    async def _encrypt_json(self, _value: Any, recipient: str) -> str:
        return f"encrypted-for-{recipient}"


@pytest.mark.asyncio
async def test_secret_update_builds_complete_per_recipient_objects() -> None:
    adapter = RecipientAdapter()
    resource = {
        "permissions": [
            {
                "aro": "Group",
                "aro_foreign_key": "33333333-3333-4333-8333-333333333333",
            }
        ]
    }

    rows = await adapter._encrypted_secrets_for_resource(resource, {"password": "memory-only"})

    assert {row["user_id"] for row in rows} == {
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
    }
    assert all(set(row) == {"user_id", "data"} for row in rows)


class ShareAdapter(RecipientAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.requests: list[tuple[str, str, dict[str, Any] | None]] = []

    async def _share_permissions(
        self, groups: list[str] | None, users: list[str] | None, permission: str
    ) -> list[dict[str, Any]]:
        assert groups and not users and permission == "read"
        return [{"aro": "Group", "aro_foreign_key": groups[0], "type": 1}]

    async def _secret_payload(self, resource_id: str) -> dict[str, Any]:
        assert resource_id == "44444444-4444-4444-8444-444444444444"
        return {"password": "memory-only"}

    async def _request(
        self, method: str, path: str, *, payload: dict[str, Any] | None = None, **_kwargs: Any
    ) -> Any:
        self.requests.append((method, path, payload))
        if "/simulate/" in path:
            return {"changes": {"added": [{"User": {"id": "22222222-2222-4222-8222-222222222222"}}]}}
        return {"shared": True}


@pytest.mark.asyncio
async def test_share_consumes_official_nested_simulation_user_shape() -> None:
    adapter = ShareAdapter()

    assert await adapter.share_resource(
        resource_id="44444444-4444-4444-8444-444444444444",
        groups=["33333333-3333-4333-8333-333333333333"],
        users=None,
        permission="read",
    ) == {"shared": True}

    method, path, payload = adapter.requests[-1]
    assert method == "PUT"
    assert path == "/share/resource/44444444-4444-4444-8444-444444444444.json"
    assert payload is not None
    assert [row["user_id"] for row in payload["secrets"]] == ["22222222-2222-4222-8222-222222222222"]


@pytest.mark.asyncio
async def test_share_is_noop_when_permission_is_already_applied() -> None:
    class AlreadySharedAdapter(ShareAdapter):
        async def _resource(self, resource_id: str) -> dict[str, Any]:
            return {
                "id": resource_id,
                "permissions": [
                    {
                        "aro": "Group",
                        "aro_foreign_key": "33333333-3333-4333-8333-333333333333",
                        "type": 7,
                    }
                ],
            }

        async def _secret_payload(self, resource_id: str) -> dict[str, Any]:
            raise AssertionError(f"secret must not be decrypted for applied permission {resource_id}")

    adapter = AlreadySharedAdapter()

    assert await adapter.share_resource(
        resource_id="44444444-4444-4444-8444-444444444444",
        groups=["33333333-3333-4333-8333-333333333333"],
        users=None,
        permission="read",
    ) == {"shared": True}
    assert adapter.requests == []


@pytest.mark.asyncio
async def test_folder_share_is_noop_when_permission_is_already_applied() -> None:
    adapter = ShareAdapter()
    group_id = "33333333-3333-4333-8333-333333333333"

    async def request(
        method: str, path: str, *, payload: dict[str, Any] | None = None, **_kwargs: Any
    ) -> Any:
        adapter.requests.append((method, path, payload))
        return {
            "id": "55555555-5555-4555-8555-555555555555",
            "permissions": [{"aro": "Group", "aro_foreign_key": group_id, "type": 1}],
        }

    adapter._request = request  # type: ignore[method-assign]
    await adapter._share_folder("55555555-5555-4555-8555-555555555555", [group_id], None, "read")

    assert [call[0] for call in adapter.requests] == ["GET"]


def _sink_registry(path: Path, sinks: dict[str, Any]) -> None:
    path.write_text(json.dumps({"sinks": sinks}), encoding="utf-8")
    path.chmod(0o600)


def test_sink_registry_loads_strict_principal_policy(tmp_path: Path) -> None:
    registry = tmp_path / "sinks.json"
    registry.write_text(
        json.dumps(
            {
                "sinks": {
                    "sales_twenty_read_probe": {
                        "kind": "secure_fill",
                        "command": [str(PYTHON_EXECUTABLE), "-c", "pass"],
                        "executable_sha256": PYTHON_EXECUTABLE_SHA256,
                    }
                },
                "policies": {
                    "sales_plugin": {
                        "resource_ids": ["11111111-1111-4111-8111-111111111111"],
                        "folder_ids": [],
                        "group_ids": [],
                        "user_ids": [],
                        "domain_hosts": ["crm.zai.one"],
                        "sink_refs": ["sales_twenty_read_probe"],
                        "allow_create_resource": False,
                        "allow_create_folder": False,
                        "resource_scope": "all",
                        "folder_scope": "all",
                        "allow_share_all": True,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    registry.chmod(0o600)

    policy = PassboltSinkDispatcher(registry).access_policy("sales_plugin")

    assert policy.resource_ids == frozenset({"11111111-1111-4111-8111-111111111111"})
    assert policy.domain_hosts == frozenset({"crm.zai.one"})
    assert policy.sink_refs == frozenset({"sales_twenty_read_probe"})
    assert policy.allow_create_resource is False
    assert policy.resource_scope == "all"
    assert policy.folder_scope == "all"
    assert policy.allow_share_all is True


@pytest.mark.asyncio
async def test_all_share_audience_includes_active_admin_and_excludes_service_and_deleted() -> None:
    service_id = "11111111-1111-4111-8111-111111111111"
    admin_id = "22222222-2222-4222-8222-222222222222"
    user_id = "33333333-3333-4333-8333-333333333333"

    class AllAudienceAdapter(PassboltAdapter):
        async def _directory(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
            def user(
                identifier: str,
                *,
                role: str,
                deleted: bool = False,
                disabled: bool = False,
                active: bool = True,
            ) -> dict[str, Any]:
                return {
                    "id": identifier,
                    "role": {"name": role},
                    "deleted": deleted,
                    "disabled": disabled,
                    "active": active,
                    "gpgkey": {"fingerprint": "A" * 40, "armored_key": "fixture-key"},
                }

            return [], [
                user(service_id, role="user"),
                user(admin_id, role="admin"),
                user(user_id, role="user"),
                user("44444444-4444-4444-8444-444444444444", role="admin", deleted=True),
                user("55555555-5555-4555-8555-555555555555", role="admin", disabled=True),
                user("66666666-6666-4666-8666-666666666666", role="user", active=False),
            ]

    adapter = AllAudienceAdapter(
        "https://passbolt.example",
        service_user_id=service_id,
    )

    assert await adapter.all_share_user_ids() == [admin_id, user_id]


@pytest.mark.asyncio
async def test_sink_returns_only_delivery_boolean_and_out_file_is_deleted(tmp_path: Path) -> None:
    registry = tmp_path / "sinks.json"
    spool = tmp_path / "spool"
    spool.mkdir()
    spool.chmod(0o700)
    _sink_registry(
        registry,
        {
            "fill": {
                "kind": "secure_fill",
                "command": [
                    str(PYTHON_EXECUTABLE),
                    "-c",
                    "import json,sys; json.load(sys.stdin)",
                ],
                "executable_sha256": PYTHON_EXECUTABLE_SHA256,
            },
            "file": {
                "kind": "out_file",
                "directory": str(spool.resolve()),
                "command": [
                    str(PYTHON_EXECUTABLE),
                    "-c",
                    "import json,sys; json.load(open(sys.argv[1], encoding='utf-8'))",
                    "{path}",
                ],
                "executable_sha256": PYTHON_EXECUTABLE_SHA256,
            },
        },
    )
    dispatcher = PassboltSinkDispatcher(registry)
    common = {
        "resource_id": "33333333-3333-4333-8333-333333333333",
        "username": "operator",
        "password": SINK_SECRET_FIXTURE,
        "target_url": "https://example.com/login",
    }

    assert await dispatcher.deliver("fill", **common) is True
    assert await dispatcher.deliver("file", **common) is True
    assert list(spool.iterdir()) == []


@pytest.mark.asyncio
async def test_sink_executable_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    registry = tmp_path / "sinks.json"
    _sink_registry(
        registry,
        {
            "fill": {
                "kind": "secure_fill",
                "command": [str(PYTHON_EXECUTABLE), "-c", "pass"],
                "executable_sha256": "0" * 64,
            }
        },
    )

    with pytest.raises(Exception, match="absolute server path"):
        await PassboltSinkDispatcher(registry).deliver(
            "fill",
            resource_id="33333333-3333-4333-8333-333333333333",
            username=None,
            password=SINK_SECRET_FIXTURE,
            target_url=None,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are required")
def test_world_readable_sink_registry_fails_closed(tmp_path: Path) -> None:
    registry = tmp_path / "sinks.json"
    _sink_registry(registry, {})
    registry.chmod(0o644)

    assert PassboltSinkDispatcher(registry).ready() is False
