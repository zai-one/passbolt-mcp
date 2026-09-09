from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from zai_passbolt.onboarding import PREFIX, check_config, load_config


def test_paths_are_config_relative_and_explicit_settings_win(tmp_path, monkeypatch):
    settings = tmp_path / "settings.json"
    key = PREFIX + "_STATE_PATH"
    monkeypatch.setenv(key, "inherited-state.sqlite")
    settings.write_text(json.dumps({"env": {key: "state/service.sqlite"}}), encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    load_config(str(settings))
    assert os.environ[key] == str(tmp_path / "state/service.sqlite")
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"env": []},
        {"env": {}, "command": "bad"},
        {"env": {"PYTHONPATH": "bad"}},
        {"env": {PREFIX + "_RATE_LIMIT": 10}},
        {"env": {PREFIX + "_STATE_PATH": "line\nbreak"}},
    ],
)
def test_invalid_config_is_rejected_atomically_without_value_disclosure(tmp_path, monkeypatch, payload):
    key = PREFIX + "_STATE_PATH"
    monkeypatch.setenv(key, "untouched")
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(str(settings))
    assert os.environ[key] == "untouched"


def test_http_doctor_rejects_wrong_key_without_leaking_material():
    config = SimpleNamespace(
        public_key="synthetic-private-marker",
        auth_mode="operator",
        token="fixture",
        principal_id="local-operator",
        bindings={"local-operator": "default"},
        enabled=lambda _: True,
    )
    result = check_config(config, "http")
    assert result["ready"] is False
    assert result["checks"]["http_verification_key"] is False
    assert result["provider_connectivity"] == "not_checked"
    assert "synthetic-private-marker" not in json.dumps(result)
