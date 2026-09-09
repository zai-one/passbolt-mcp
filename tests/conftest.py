import json
import socket

import pytest

from zai_passbolt.config import SCOPES, ServiceConfig


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    original = socket.socket.connect

    def guarded(sock, address):
        if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1", "localhost"}:
            return original(sock, address)
        raise AssertionError("external network is prohibited in synthetic tests")

    monkeypatch.setattr(socket.socket, "connect", guarded)


@pytest.fixture
def config(tmp_path):
    policy = dict(
        resource_ids=[],
        folder_ids=[],
        group_ids=[],
        user_ids=[],
        domain_hosts=["example.com", "other.example"],
        sink_refs=["fill"],
        allow_create_resource=True,
        allow_create_folder=True,
        resource_scope="all",
        folder_scope="all",
        allow_share_all=False,
    )
    sinks = tmp_path / "policy.json"
    sinks.write_text(
        json.dumps({"sinks": {"fill": {"kind": "secure_fill"}}, "policies": {"default": policy}}),
        encoding="utf-8",
    )
    sinks.chmod(0o600)
    secret = tmp_path / "passbolt.env"
    secret.write_text(
        f"PASSBOLT_BASE_URL=https://vault.example\nPASSBOLT_SINK_CONFIG_FILE={sinks}\n", encoding="utf-8"
    )
    secret.chmod(0o600)
    return ServiceConfig(
        state_path=tmp_path / "state.sqlite",
        secret_path=secret,
        principal_id="alice",
        bindings={"alice": "default", "bob": "default"},
        local_scopes=SCOPES,
        passbolt_write_enabled=True,
        passbolt_use_enabled=True,
    )
