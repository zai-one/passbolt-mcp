from __future__ import annotations

import json
import os
import stat
import sys
import tomllib
from importlib.resources import files
from pathlib import Path

import pytest

from zai_passbolt import setup


@pytest.mark.parametrize("reserved", ["mcp.local.json", "secrets", "mcp-client.json", "mcp-client.toml"])
def test_setup_never_overwrites_existing_files_or_requests_credentials(tmp_path, monkeypatch, reserved):
    target = tmp_path / reserved
    target.write_text("keep this", encoding="utf-8")
    monkeypatch.setattr(setup.getpass, "getpass", lambda _: pytest.fail("must not ask for credentials"))
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("must not prompt"))
    with pytest.raises(ValueError, match="already exist"):
        setup.configure(tmp_path)
    assert target.read_text(encoding="utf-8") == "keep this"
    assert list(tmp_path.iterdir()) == [target]


def test_setup_works_outside_checkout_and_keeps_tokens_out_of_client_config(tmp_path, monkeypatch, capsys):
    private = tmp_path / "existing-provider.env"
    private.write_text("SYNTHETIC_PRIVATE_MARKER=local-only", encoding="utf-8")
    private.chmod(0o600)
    monkeypatch.setattr(
        "builtins.input", lambda prompt: str(private) if "_SECRET_FILE" in prompt else "12345"
    )
    monkeypatch.setattr(setup.getpass, "getpass", lambda _: "synthetic-token-local-only")
    unrelated = tmp_path / "elsewhere"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)
    root = tmp_path / "settings with spaces"
    config = setup.configure(root)
    values = json.loads(config.read_text(encoding="utf-8"))["env"]
    assert all("synthetic" not in value.lower() for value in values.values())
    config_text = (root / "mcp-client.json").read_text(encoding="utf-8")
    snippet = json.loads(config_text)["mcpServers"][setup.SERVICE]
    assert snippet["command"] == sys.executable
    assert snippet["args"] == ["-m", setup.PACKAGE, "--config", str(config)]
    table = tomllib.loads((root / "mcp-client.toml").read_text(encoding="utf-8"))
    assert table["mcp_servers"][setup.SERVICE] == snippet
    assert "synthetic" not in config_text
    captured = capsys.readouterr()
    assert "synthetic" not in (captured.out + captured.err).lower()
    assert not list(unrelated.iterdir())
    for value in values.values():
        if value.endswith(".token"):
            token = root / value
            assert token.read_text(encoding="utf-8") == "synthetic-token-local-only"
            if os.name != "nt":
                assert stat.S_IMODE(token.stat().st_mode) == 0o600
    if os.name != "nt":
        assert stat.S_IMODE((root / "secrets").stat().st_mode) == 0o700


def test_client_only_does_not_read_credentials_or_modify_settings(tmp_path, monkeypatch, capsys):
    config = tmp_path / "mcp.local.json"
    config.write_text("Contents need not be read to print a client snippet.", encoding="utf-8")
    monkeypatch.setattr(Path, "read_text", lambda *a, **k: pytest.fail("should not read file contents"))
    setup.main(["--directory", str(tmp_path), "--client-only", "--format", "toml"])
    result = tomllib.loads(capsys.readouterr().out)
    assert result["mcp_servers"][setup.SERVICE]["args"][-1] == str(config)
    assert list(tmp_path.iterdir()) == [config]


def test_json_and_toml_escape_windows_paths_and_quotes(tmp_path):
    executable = 'C:\\Users\\Someone\\path "with quotes"\\python.exe'
    config = tmp_path / 'a "quoted" path' / "mcp.local.json"
    json_value = setup.client_config(config, executable)["mcpServers"][setup.SERVICE]
    toml_value = tomllib.loads(setup.client_toml(config, executable))["mcp_servers"][setup.SERVICE]
    assert json_value == toml_value


@pytest.mark.parametrize("value", ["", "\n", "one\ntwo", "one\rsecond", "one\0two", "x" * 4097])
def test_hidden_input_rejects_multiline_or_empty_values_without_echo(value, monkeypatch):
    monkeypatch.setattr(setup.getpass, "getpass", lambda _: value)
    with pytest.raises(ValueError, match="single-line") as exc:
        setup._required("token", hidden=True)
    if value.strip():
        assert value not in str(exc.value)


def test_interactive_cli_rejects_piped_credentials_before_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit) as exc:
        setup.main(["--directory", str(tmp_path)])
    assert exc.value.code == 2
    assert not list(tmp_path.iterdir())


def test_provider_failure_does_not_disclose_exception_text(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def fail(_):
        raise RuntimeError("synthetic-password-local-only")

    monkeypatch.setattr(setup, "configure", fail)
    with pytest.raises(SystemExit) as exc:
        setup.main(["--directory", str(tmp_path)])
    assert "synthetic-password" not in str(exc.value)
    assert "synthetic-password" not in capsys.readouterr().err


def test_packaged_template_matches_documented_template():
    repo = Path(__file__).resolve().parents[1]
    bundled = json.loads(files(setup.PACKAGE).joinpath("setup.example.json").read_text(encoding="utf-8"))
    assert bundled == json.loads((repo / "mcp.example.json").read_text(encoding="utf-8"))
