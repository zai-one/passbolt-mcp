"""Offline crypto tests using disposable keys; no vault or user keyring is used."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from test_product_tools import PROBE, SECRET, URL, probe_transport  # noqa: F401
from test_runtime import RESOURCE, harness

from zai_passbolt.adapter import PassboltAdapter, PassboltSinkDispatcher
from zai_passbolt.doctor import diagnose
from zai_passbolt.errors import SafeToolError
from zai_passbolt.gpg_paths import gpg_path
from zai_passbolt.transport import ProviderResponseError


@pytest.fixture
def gpg_directory():
    # GPG/MSYS agent socket paths have a shorter limit than ordinary file paths.
    # Pytest's per-test path plus a hosted runner username can exceed that limit.
    with tempfile.TemporaryDirectory(prefix="pg-") as directory:
        yield Path(directory)


@pytest.fixture
def real_gpg(gpg_directory):
    gpg = shutil.which("gpg")
    if not gpg:
        if os.environ.get("REQUIRE_GPG_TESTS") == "1":
            pytest.fail("GnuPG is required by this release gate")
        pytest.skip("GnuPG unavailable; Linux release CI requires this fixture")
    home = gpg_directory / "gnupg"
    home.mkdir(mode=0o700)
    password = gpg_directory / "passphrase"
    password.write_text("synthetic-ephemeral-passphrase", encoding="utf-8")
    password.chmod(0o600)
    prefix = [
        gpg,
        "--homedir",
        gpg_path(gpg, home),
        "--batch",
        "--no-tty",
        "--pinentry-mode",
        "loopback",
        "--passphrase-file",
        gpg_path(gpg, password),
    ]
    generation = subprocess.run(
        [
            *prefix,
            "--quick-generate-key",
            "MCP fixture <fixture@example.invalid>",
            "rsa2048",
            "sign,encr",
            "1d",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert generation.returncode == 0, generation.stderr  # Synthetic test keyring only.
    listing = subprocess.run(
        [*prefix, "--with-colons", "--list-secret-keys"],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout
    fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
    gpgconf = shutil.which("gpgconf")

    def stop_agent(directory):
        if gpgconf:
            subprocess.run(
                [gpgconf, "--homedir", gpg_path(gpgconf, directory), "--kill", "gpg-agent"],
                capture_output=True,
                timeout=15,
                check=False,
            )

    # Keep the source agent active, as it is immediately after an operator imports a key.
    adapter = PassboltAdapter(
        "https://vault.example",
        service_user_id="fixture-user",
        user_fingerprint=fingerprint,
        server_fingerprint=fingerprint,
        gpg_home=home,
        passphrase_file=password,
        token_file=gpg_directory / "tokens.json",
    )
    try:
        yield adapter, fingerprint, stop_agent
    finally:
        adapter.close()
        stop_agent(home)


async def test_real_signed_encryption_roundtrip_and_wrong_signer(real_gpg, capsys, caplog):
    adapter, fingerprint, _ = real_gpg
    value = {"password": "synthetic-plaintext-never-log", "name": "Ключ"}
    encrypted = await adapter._encrypt_json(value, fingerprint)
    assert "BEGIN PGP MESSAGE" in encrypted and value["password"] not in encrypted
    assert await adapter._decrypt_json(encrypted, expected_signer=fingerprint) == value
    with pytest.raises(ProviderResponseError, match="signer verification failed"):
        await adapter._decrypt_json(encrypted, expected_signer="A" * 40)
    assert value["password"] not in caplog.text + capsys.readouterr().out


async def test_corrupt_ciphertext_and_wrong_passphrase_fail_closed(real_gpg, tmp_path):
    adapter, fingerprint, stop_agent = real_gpg
    encrypted = await adapter._encrypt_json({"password": "synthetic-payload"}, fingerprint)
    with pytest.raises(ProviderResponseError):
        await adapter._decrypt_json("corrupt fixture ciphertext", expected_signer=fingerprint)
    stop_agent(adapter._runtime_gpg_home)
    wrong = tmp_path / "wrong-passphrase"
    wrong.write_text("synthetic-wrong", encoding="utf-8")
    wrong.chmod(0o600)
    adapter.passphrase_file = wrong
    with pytest.raises(ProviderResponseError) as failure:
        await adapter._decrypt_json(encrypted, expected_signer=fingerprint)
    assert "synthetic-payload" not in str(failure.value)


async def test_active_keyring_uses_private_agent_and_cleanup(real_gpg):
    adapter, fingerprint, _ = real_gpg
    runtime = adapter._writable_gpg_home()
    assert runtime != adapter.gpg_home
    assert not list(runtime.glob("S.gpg-agent*")), "source agent sockets must not be copied"
    ciphertext = await adapter._encrypt_json({"password": "synthetic-isolated"}, fingerprint)
    assert await adapter._decrypt_json(ciphertext, expected_signer=fingerprint) == {
        "password": "synthetic-isolated"
    }
    adapter.close()
    assert not runtime.exists()
    assert adapter.gpg_home.is_dir()


def attach_policy(adapter, config):
    path = config.secret_path.parent / "policy.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["sinks"]["fill"] = PROBE
    path.write_text(json.dumps(document), encoding="utf-8")
    adapter.sinks = PassboltSinkDispatcher(path)
    adapter.service_user_id = RESOURCE


async def test_real_gpg_doctor_success_and_missing_server_key(real_gpg, config):
    adapter, _, _ = real_gpg
    attach_policy(adapter, config)
    result = await diagnose(adapter, "default", config)
    assert result["ready"] and result["provider_connectivity"] == "not_checked"
    adapter.server_fingerprint = "A" * 40
    result = await diagnose(adapter, "default", config)
    assert not result["ready"] and not result["checks"]["server_public_key_present"]


async def test_real_decrypt_selection_probe_replay_and_no_plaintext(
    real_gpg, config, monkeypatch, probe_transport, capsys, caplog  # noqa: F811
):
    adapter, fingerprint, _ = real_gpg
    attach_policy(adapter, config)
    encrypted = await adapter._encrypt_json({"password": SECRET}, fingerprint)
    metadata = {"resource_id": RESOURCE, "uri": URL, "username": "local-user", "name": "Protected health"}
    monkeypatch.setattr(adapter, "search", AsyncMock(return_value={"resources": [metadata]}))
    requests = []

    async def request(method, path, **kwargs):
        requests.append((method, path))
        assert method == "GET" and path == f"/secrets/resource/{RESOURCE}.json"
        return {"body": {"data": encrypted}}

    monkeypatch.setattr(adapter, "_request", request)
    _, call = harness(config, adapter)
    selected = await call("passbolt_select", target_url=URL)
    args = {"selection_id": selected["selection_id"], "sink_ref": "fill"}
    _, bob = harness(replace(config, principal_id="bob"), adapter)
    _, read_only = harness(replace(config, local_scopes={"passbolt:read"}), adapter)
    for denied_call, denied_args in [
        (bob, args),
        (read_only, args),
        (call, {**args, "sink_ref": "other"}),
        (call, {**args, "target_url": "https://other.example/"}),
    ]:
        with pytest.raises(SafeToolError):
            await denied_call("passbolt_use_secret", **denied_args)
    assert not requests and not probe_transport["requests"]
    result = await call("passbolt_use_secret", **args)
    assert result == {"delivered_to_sink": True}
    assert len(requests) == len(probe_transport["requests"]) == 1
    assert probe_transport["requests"][0].headers["Authorization"] == "Bearer " + SECRET
    _, restarted = harness(config, adapter)
    with pytest.raises(SafeToolError):
        await restarted("passbolt_use_secret", **args)
    assert len(requests) == 1
    assert SECRET not in json.dumps([selected, result]) + caplog.text + capsys.readouterr().out
    for file in config.state_path.parent.glob(config.state_path.name + "*"):
        assert SECRET.encode() not in file.read_bytes()
