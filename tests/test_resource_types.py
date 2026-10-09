from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

from zai_passbolt.adapter import (
    RESOURCE_TYPE_SLUGS,
    V5_DEFAULT_RESOURCE_TYPE_ID,
    V5_PIN_CODE_RESOURCE_TYPE_ID,
    PassboltAdapter,
    validate_v5_metadata,
)
from zai_passbolt.transport import ProviderResponseError

PASSBOLT_SEED = uuid.UUID("d5447ca1-950f-459d-8b20-86ddfdd0f922")  # passbolt_api UuidFactory
PIN_FIXTURE = "48151623"  # synthetic PIN, must never be projected
PASSWORD_FIXTURE = "pw-must-not-leak"  # noqa: S105 -- negative fixture
NOTE_FIXTURE = "secure-note-must-not-leak"


def test_resource_type_ids_follow_passbolt_uuid5_derivation() -> None:
    for type_id, slug in RESOURCE_TYPE_SLUGS.items():
        assert str(uuid.uuid5(PASSBOLT_SEED, f"resource-types.id.{slug}")) == type_id
    assert RESOURCE_TYPE_SLUGS[V5_PIN_CODE_RESOURCE_TYPE_ID] == "v5-pin-code"


def pin_metadata(**extra: Any) -> dict[str, Any]:
    # v5-pin-code metadata: name (required), description, icon. No uris, no username.
    return {
        "object_type": "PASSBOLT_RESOURCE_METADATA",
        "resource_type_id": V5_PIN_CODE_RESOURCE_TYPE_ID,
        "name": "Office door",
        "description": "Main entrance",
        "icon": {"type": "keepass-icon-set", "value": 1},
        **extra,
    }


def test_read_mode_accepts_pin_code_metadata_without_uris() -> None:
    result = validate_v5_metadata(pin_metadata(), strict_write=False)
    assert result["uris"] == [] and result["username"] is None and result["name"] == "Office door"


def test_write_mode_still_requires_v5_default_and_uris() -> None:
    with pytest.raises(ValueError):
        validate_v5_metadata(pin_metadata(), strict_write=True)
    payload = {**pin_metadata(), "resource_type_id": V5_DEFAULT_RESOURCE_TYPE_ID, "custom_fields": []}
    with pytest.raises(ValueError, match="uris"):
        validate_v5_metadata(payload, strict_write=True)


def test_read_mode_accepts_documented_32_uris_but_not_more() -> None:
    base = {**pin_metadata(), "resource_type_id": V5_DEFAULT_RESOURCE_TYPE_ID}
    uris = [f"https://h{i}.example/login" for i in range(32)]
    assert len(validate_v5_metadata({**base, "uris": uris}, strict_write=False)["uris"]) == 32
    with pytest.raises(ValueError, match="at most 32"):
        validate_v5_metadata({**base, "uris": [*uris, "https://x.example"]}, strict_write=False)
    with pytest.raises(ValueError, match="at most 10"):
        validate_v5_metadata({**base, "uris": uris[:11], "custom_fields": []}, strict_write=True)


class VaultAdapter(PassboltAdapter):
    """Mixed vault: a v5 password and a 5.12 PIN code, both with encrypted metadata."""

    def __init__(self, secret: dict[str, Any] | None = None) -> None:
        super().__init__("https://passbolt.example")
        self.secret = secret or {}
        self.delivered: list[Any] = []

    async def _request(self, method: str, path: str, **_kwargs: Any) -> Any:
        assert (method, path) == ("GET", "/resources.json")
        return [
            {
                "id": "11111111-1111-4111-8111-111111111111",
                "metadata": "pin-metadata",
                "metadata_key_type": "user_key",
                "resource_type_id": V5_PIN_CODE_RESOURCE_TYPE_ID,
                "secrets": [{"data": "-----BEGIN PGP MESSAGE-----"}],
            },
            {
                "id": "22222222-2222-4222-8222-222222222222",
                "metadata": "default-metadata",
                "metadata_key_type": "user_key",
                "resource_type_id": V5_DEFAULT_RESOURCE_TYPE_ID,
                "password": PASSWORD_FIXTURE,
            },
            {
                "id": "33333333-3333-4333-8333-333333333333",
                "name": "Future type",
                "resource_type_id": "99999999-9999-4999-8999-999999999999",
            },
        ]

    async def _decrypt_json(self, armored: str, *, expected_signer: str | None = None) -> dict[str, Any]:
        if armored == "pin-metadata":
            return pin_metadata()
        return {
            "object_type": "PASSBOLT_RESOURCE_METADATA",
            "resource_type_id": V5_DEFAULT_RESOURCE_TYPE_ID,
            "name": "Office portal",
            "username": "operator",
            "uris": ["https://example.com/login"],
            "description": None,
            "custom_fields": [],
        }

    async def _secret_payload(self, resource_id: str) -> dict[str, Any]:
        return dict(self.secret)


async def test_search_lists_pin_codes_with_type_and_never_secret_values() -> None:
    result = await VaultAdapter().search("Office")
    by_id = {row["resource_id"]: row for row in result["resources"]}
    pin = by_id["11111111-1111-4111-8111-111111111111"]
    assert pin["resource_type"] == "v5-pin-code" and pin["name"] == "Office door"
    assert "uri" not in pin and "username" not in pin
    assert by_id["22222222-2222-4222-8222-222222222222"]["resource_type"] == "v5-default"
    dumped = json.dumps(result)
    assert PASSWORD_FIXTURE not in dumped and "PGP MESSAGE" not in dumped
    assert "secrets" not in dumped and "metadata" not in dumped
    assert result["secret_disclosed"] is False


async def test_unknown_resource_type_is_labelled_not_dropped() -> None:
    result = await VaultAdapter().search("Future")
    assert result["resources"][0]["resource_type"] == "unknown"


async def test_select_on_pin_code_needs_confirmation_and_discloses_nothing() -> None:
    result = await VaultAdapter().select("https://other.example/door", "Office door", 5)
    assert result["resource"]["resource_type"] == "v5-pin-code"
    assert result["confirmation_required"] is True and result["secret_disclosed"] is False


async def test_use_secret_refuses_pin_codes_without_leaking_them() -> None:
    adapter = VaultAdapter({"object_type": "PASSBOLT_SECRET_DATA", "pin_code": PIN_FIXTURE})

    async def never(*args: Any, **kwargs: Any) -> bool:
        raise AssertionError("PIN must not reach a sink")

    adapter.sinks.deliver = never  # type: ignore[method-assign]
    with pytest.raises(ProviderResponseError) as error:
        await adapter.use_secret(
            resource_id="11111111-1111-4111-8111-111111111111",
            sink_ref="fill",
            target_url="https://example.com/door",
            username=None,
        )
    assert "PIN code" in str(error.value) and PIN_FIXTURE not in repr(error.value)


async def test_use_secret_returns_only_delivery_flag() -> None:
    adapter = VaultAdapter(
        {"object_type": "PASSBOLT_SECRET_DATA", "password": PASSWORD_FIXTURE, "description": NOTE_FIXTURE}
    )
    seen: dict[str, Any] = {}

    async def deliver(sink_ref: str, **kwargs: Any) -> bool:
        seen.update(kwargs)
        return True

    adapter.sinks.deliver = deliver  # type: ignore[method-assign]
    result = await adapter.use_secret(
        resource_id="22222222-2222-4222-8222-222222222222",
        sink_ref="fill",
        target_url="https://example.com/login",
        username="operator",
    )
    assert result == {"delivered_to_sink": True}
    assert seen["password"] == PASSWORD_FIXTURE and NOTE_FIXTURE not in json.dumps(seen)
