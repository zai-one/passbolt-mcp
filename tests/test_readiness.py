"""Real adapter envelopes, synthetic custody: no network or operator keyring."""

from __future__ import annotations

import asyncio
import json
import logging

import pytest

from zai_passbolt.adapter import PassboltAdapter
from zai_passbolt.readiness import _TRACE, log_probe_failure, probe_step, readiness_trace
from zai_passbolt.transport import ProviderResponseError

RESOURCE = "11111111-1111-4111-8111-111111111111"
USER = "22222222-2222-4222-8222-222222222222"
FP = "A" * 40
SENTINEL = "synthetic-confidential-value-must-not-escape"


class Http:
    def __init__(self, failure):
        self.failure = failure
        self.calls = []

    async def request_json(self, method, url, **kwargs):
        self.calls.append((method, url))
        await asyncio.sleep(0)
        assert method == "GET"
        if url.endswith("/resources.json"):
            assert kwargs["params"] == {"limit": 5}
            if self.failure == "resource_fetch":
                raise ProviderResponseError(SENTINEL)
            if self.failure == "empty":
                return {"body": []}
            if self.failure == "resource_shape":
                return {"body": "invalid"}
            item = {
                "id": RESOURCE,
                "metadata": "metadata",
                "metadata_key_id": "key",
                "metadata_key_type": "shared_key",
            }
            if self.failure == "missing_id":
                item.pop("id")
            if self.failure == "user_key":
                item["metadata_key_type"] = "user_key"
            return {"body": [item]}
        if url.endswith("/metadata/keys.json"):
            if self.failure == "metadata_key_fetch":
                raise ProviderResponseError(SENTINEL)
            if self.failure == "keys_unavailable":
                return {"body": []}
            return {
                "body": [
                    {
                        "id": "key",
                        "fingerprint": FP,
                        "armored_key": "public",
                        "metadata_private_keys": [{"user_id": USER, "data": "private-envelope"}],
                    }
                ]
            }
        if url.endswith(f"/secrets/resource/{RESOURCE}.json"):
            if self.failure == "secret_fetch":
                raise ProviderResponseError(SENTINEL)
            return {"body": {} if self.failure == "missing_secret" else {"data": "secret"}}
        raise AssertionError("Unexpected endpoint")


class Adapter(PassboltAdapter):
    def __init__(self, failure=None):
        super().__init__(
            "https://vault.example",
            service_user_id=USER,
            user_fingerprint=FP,
            metadata_fingerprints=FP,
            http=Http(failure),
        )
        self.failure = failure

    def _configured(self):
        return self.failure != "configuration"

    async def _access_token(self, **kwargs):
        return "synthetic-test-token"

    async def _gpg(self, args, *, stdin=None, **kwargs):
        await asyncio.sleep(0)
        if args == ["--import"]:
            if self.failure == "metadata_key_import":
                raise ProviderResponseError(SENTINEL)
            return ""
        if args[0] == "--with-colons":
            return FP
        assert args == ["--decrypt"]
        if stdin == "private-envelope":
            if self.failure == "metadata_key_decrypt":
                raise ProviderResponseError(SENTINEL)
            if self.failure == "envelope":
                return "not-json-" + SENTINEL
            value = {
                "object_type": "PASSBOLT_METADATA_PRIVATE_KEY",
                "domain": self.base_url,
                "fingerprint": FP,
                "armored_key": "PRIVATE KEY BLOCK synthetic",
                "passphrase": None,
            }
            if self.failure == "domain":
                value["domain"] = "https://old.example"
            if self.failure == "fingerprint":
                value["fingerprint"] = "B" * 40
            if self.failure == "passphrase":
                value["passphrase"] = {"untrusted": SENTINEL}
            return json.dumps(value)
        if stdin == "metadata":
            if self.failure == "metadata_decrypt":
                raise ProviderResponseError(SENTINEL)
            return json.dumps(
                {
                    "object_type": "invalid"
                    if self.failure == "metadata_validate"
                    else "PASSBOLT_RESOURCE_METADATA",
                    "name": "Synthetic",
                    "resource_type_id": "dd1f723d-0d1e-513f-8218-4055dc0530d0",
                    "uris": ["https://site.example"],
                    "username": "fixture",
                    "description": None,
                    "custom_fields": [],
                }
            )
        assert stdin == "secret"
        if self.failure == "secret_decrypt":
            raise ProviderResponseError(SENTINEL)
        return json.dumps({} if self.failure == "empty_secret" else {"password": SENTINEL})


@pytest.mark.parametrize(
    "failure,stage,reason",
    [
        ("configuration", "configuration", "custody_not_configured"),
        ("resource_fetch", "resource_fetch", "provider_error"),
        ("resource_shape", "resource_shape", "invalid_response"),
        ("empty", "canary_select", "no_resources"),
        ("metadata_key_fetch", "metadata_key_fetch", "provider_error"),
        ("metadata_key_decrypt", "metadata_key_decrypt", "provider_error"),
        ("envelope", "metadata_key_envelope", "invalid_envelope"),
        ("domain", "metadata_key_trust", "domain_mismatch"),
        ("fingerprint", "metadata_key_trust", "fingerprint_mismatch"),
        ("passphrase", "metadata_key_trust", "embedded_passphrase"),
        ("metadata_key_import", "metadata_key_import", "provider_error"),
        ("keys_unavailable", "metadata_key_select", "metadata_private_keys_unavailable"),
        ("metadata_decrypt", "metadata_decrypt", "provider_error"),
        ("metadata_validate", "metadata_validate", "invalid_metadata"),
        ("missing_id", "canary_select", "resource_id_missing"),
        ("secret_fetch", "secret_fetch", "provider_error"),
        ("missing_secret", "secret_fetch", "secret_payload_missing"),
        ("secret_decrypt", "secret_decrypt", "provider_error"),
        ("empty_secret", "secret_validate", "empty_secret"),
    ],
)
async def test_real_status_failure_stage_and_no_secrets(failure, stage, reason, caplog):
    adapter = Adapter(failure)
    result = await adapter.status()
    assert result == {
        "provider_enabled": True,
        "auth_ready": failure not in {"configuration", "resource_fetch", "resource_shape"},
        "decrypt_ready": False,
    }
    (record,) = [r for r in caplog.records if getattr(r, "operation", None) == "status"]
    assert (record.probe_stage, record.probe_reason) == (stage, reason)
    assert record.exc_info is None and record.exc_text is None
    assert SENTINEL not in json.dumps(record.__dict__, default=str) + json.dumps(result)
    assert SENTINEL not in logging.Formatter().format(record)
    assert _TRACE.get() is None
    assert len(adapter.http.calls) <= 3


@pytest.mark.parametrize("failure", [None, "user_key"])
async def test_status_success_keeps_boolean_contract(failure, caplog):
    adapter = Adapter(failure)
    assert await adapter.status() == {"provider_enabled": True, "auth_ready": True, "decrypt_ready": True}
    assert not caplog.records
    assert len(adapter.http.calls) == (2 if failure == "user_key" else 3)
    assert _TRACE.get() is None


async def test_concurrent_probes_and_cancellation_do_not_share_trace(caplog):
    await asyncio.gather(Adapter("domain").status(), Adapter("secret_decrypt").status())
    assert {(r.probe_stage, r.probe_reason) for r in caplog.records} == {
        ("metadata_key_trust", "domain_mismatch"),
        ("secret_decrypt", "provider_error"),
    }
    adapter = Adapter()

    async def cancel(*args, **kwargs):
        raise asyncio.CancelledError()

    adapter._request = cancel
    with pytest.raises(asyncio.CancelledError):
        await adapter.status()
    assert _TRACE.get() is None
    assert (await Adapter().status())["decrypt_ready"]


def test_unknown_diagnostic_values_are_never_logged(caplog):
    with readiness_trace() as trace:
        probe_step(SENTINEL, SENTINEL)
        log_probe_failure(logging.getLogger(__name__), SENTINEL, trace)
    assert caplog.records[-1].probe_stage == caplog.records[-1].probe_reason == "unknown"
    assert SENTINEL not in repr(caplog.records[-1].__dict__)
