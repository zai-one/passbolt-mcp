import base64
import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from zai_passbolt.doctor import diagnose, local_check
from zai_passbolt.https_probe import probe, validate_probe
from zai_passbolt.transport import ProviderError

URL = "https://example.com/protected-health"
SECRET = "synthetic-probe-credential"
PROBE = {"kind": "https_probe", "url": URL}


class UnreadableBody(httpx.AsyncByteStream):
    async def __aiter__(self):
        raise AssertionError("probe must not consume the response body")
        yield b""  # pragma: no cover


@pytest.fixture
def probe_transport(monkeypatch):
    from zai_passbolt import https_probe

    original = httpx.AsyncClient
    captured = {"requests": [], "options": [], "status": 200, "error": None}

    async def respond(request):
        captured["requests"].append(request)
        if captured["error"]:
            raise captured["error"]
        return httpx.Response(
            captured["status"], headers={"Location": "https://other.example/"}, stream=UnreadableBody()
        )

    def client(**options):
        captured["options"].append(options)
        return original(**options, transport=httpx.MockTransport(respond))

    monkeypatch.setattr(https_probe.httpx, "AsyncClient", client)
    return captured


@pytest.mark.parametrize("auth", ["bearer", "basic"])
async def test_probe_fixed_get_auth_tls_no_proxy_no_body(auth, probe_transport, caplog, capsys):
    options = {**PROBE, "auth": auth}
    if auth == "basic":
        options["username"] = "fixed-user"
    assert await probe(options, SECRET, URL) is True
    (request,) = probe_transport["requests"]
    assert request.method == "GET" and str(request.url) == URL and request.content == b""
    expected = (
        "Bearer " + SECRET
        if auth == "bearer"
        else "Basic " + base64.b64encode(("fixed-user:" + SECRET).encode()).decode()
    )
    assert request.headers["Authorization"] == expected
    (client_options,) = probe_transport["options"]
    assert client_options["verify"] is True
    assert client_options["trust_env"] is False and client_options["follow_redirects"] is False
    assert SECRET not in caplog.text + capsys.readouterr().out


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 500])
async def test_probe_failure_never_follows_retries_or_returns_response(status, probe_transport):
    probe_transport["status"] = status
    with pytest.raises(ProviderError) as error:
        await probe(PROBE, SECRET, URL)
    assert len(probe_transport["requests"]) == 1
    assert SECRET not in str(error.value) and "other.example" not in str(error.value)


async def test_probe_transport_error_scrubs_secret_and_is_not_retried(probe_transport):
    probe_transport["error"] = httpx.ReadTimeout("provider reflected " + SECRET)
    with pytest.raises(ProviderError) as error:
        await probe(PROBE, SECRET, URL)
    assert SECRET not in str(error.value)
    assert len(probe_transport["requests"]) == 1


@pytest.mark.parametrize("target", [None, "https://other.example/protected-health", URL + "/", URL + "?x=1"])
async def test_probe_target_is_operator_owned(target, probe_transport):
    with pytest.raises(ProviderError):
        await probe(PROBE, SECRET, target)
    assert not probe_transport["requests"] and not probe_transport["options"]


@pytest.mark.parametrize("password", ["", "x\r\nInjected: yes", "x\x00", "x\x7f", "x" * 8193, "я"])
async def test_probe_invalid_bearer_is_rejected_before_network(password, probe_transport):
    with pytest.raises(ProviderError):
        await probe(PROBE, password, URL)
    assert not probe_transport["requests"]


@pytest.mark.parametrize(
    "update",
    [
        {"url": "http://example.com/"},
        {"url": "https://user:password@example.com/"},
        {"url": URL + "?key=value"},
        {"url": URL + "#fragment"},
        {"url": "https://example.com:0/"},
        {"url": "https://example.com:65536/"},
        {"url": "https://example.com/\n"},
        {"method": "POST"},
        {"auth": "custom"},
        {"auth": "basic"},
        {"auth": "basic", "username": "bad:user"},
        {"username": "unused"},
        {"timeout_seconds": True},
        {"timeout_seconds": 31},
        {"expected_status": 401},
    ],
)
def test_probe_config_rejects_unsafe_or_ambiguous_input(update):
    with pytest.raises((ValueError, TypeError)):
        validate_probe({**PROBE, **update})


def doctor_adapter():
    fingerprint = "A" * 40
    return SimpleNamespace(
        base_url="https://vault.example",
        service_user_id="11111111-1111-4111-8111-111111111111",
        user_fingerprint=fingerprint,
        server_fingerprint=fingerprint,
        _configured=lambda: True,
        _gpg_preflight=AsyncMock(return_value=True),
        _gpg=AsyncMock(return_value="fpr:::::::::" + fingerprint + ":"),
        access_policy=lambda label: SimpleNamespace(sink_refs={"health"}),
        sinks=SimpleNamespace(_load=lambda: {"health": PROBE}),
    )


async def test_doctor_reports_local_proof_only(config):
    adapter = doctor_adapter()
    result = await diagnose(adapter, "default", config)
    assert result["ready"] and all(result["checks"].values())
    assert result["provider_connectivity"] == result["destination_connectivity"] == "not_checked"
    assert result["secret_use"]["sinks"]["health"] == "configuration_valid_endpoint_not_checked"
    assert adapter.user_fingerprint not in json.dumps(result)
    assert "vault.example" not in json.dumps(result)


async def test_doctor_bad_keys_and_sink_give_actionable_failure(config):
    adapter = doctor_adapter()
    adapter._gpg_preflight.return_value = False
    adapter.sinks._load = lambda: {"health": {**PROBE, "url": "http://example.com"}}
    result = await diagnose(adapter, "default", config)
    assert not result["ready"]
    assert "check_private_key_usable" in result["next_steps"]
    assert "check_https_sink_configuration" in result["next_steps"]
    adapter._gpg.assert_not_called()


async def test_local_doctor_works_without_keys_or_network_and_closes(config):
    result = await local_check(replace(config, passbolt_use_enabled=False))
    assert not result["ready"] and result["checks"]["access_policy"]
    assert result["provider_connectivity"] == "not_checked"
    assert not config.state_path.exists()
