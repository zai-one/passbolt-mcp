"""Local interactive setup and portable client snippets for an installed package."""

from __future__ import annotations

import argparse
import csv
import getpass
import io
import json
import os
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

PACKAGE = "zai_passbolt"
SERVICE = "passbolt"


def _exists(path: Path) -> bool:
    return os.path.lexists(path)


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    if os.name == "nt":
        who = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"], check=True, capture_output=True, text=True
        ).stdout
        sid = next(csv.reader(io.StringIO(who.strip())))[1]
        subprocess.run(
            [
                "icacls",
                str(path),
                "/inheritance:r",
                "/grant:r",
                "*" + sid + ":(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
            ],
            check=True,
            capture_output=True,
        )


def _write_new(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)


def client_config(config: Path, executable: str | None = None) -> dict:
    """Bind a snippet to this installed interpreter, not the caller's working directory."""
    return {
        "mcpServers": {
            SERVICE: {
                "command": executable or sys.executable,
                "args": ["-m", PACKAGE, "--config", str(config.resolve())],
            }
        }
    }


def client_toml(config: Path, executable: str | None = None) -> str:
    entry = client_config(config, executable)["mcpServers"][SERVICE]
    # JSON strings/arrays are valid TOML basic strings/arrays (including Windows paths).
    return (
        f"[mcp_servers.{json.dumps(SERVICE)}]\n"
        f"command = {json.dumps(entry['command'], ensure_ascii=False)}\n"
        f"args = {json.dumps(entry['args'], ensure_ascii=False)}\n"
    )


def _required(prompt: str, *, hidden: bool = False) -> str:
    value = (getpass.getpass(prompt) if hidden else input(prompt)).strip()
    if not value or len(value) > (4096 if hidden else 8192) or any(c in value for c in "\r\n\0"):
        raise ValueError("A nonempty single-line setting is required.")
    return value


def configure(directory: Path) -> Path:
    """Create new local files only; never modify existing client or provider settings."""
    root = directory.expanduser().resolve()
    targets = [root / name for name in ("mcp.local.json", "secrets", "mcp-client.json", "mcp-client.toml")]
    if any(_exists(p) for p in targets):
        raise ValueError(
            "Setup files already exist. Use a new directory or edit your existing configuration."
        )
    template = json.loads(files(PACKAGE).joinpath("setup.example.json").read_text(encoding="utf-8"))
    values = template["env"]
    pending: dict[Path, str] = {}
    telegram_login = False
    print("Settings stay on this computer. Credentials are entered privately, never in MCP chat.")
    for key, default in list(values.items()):
        if key.endswith("_STATE_PATH") or not default:
            continue
        if default.endswith(".token"):
            pending[root / default] = _required(key + " (provider token): ", hidden=True)
        elif key.endswith("_BINDINGS_FILE"):
            pending[root / default] = json.dumps({"local-operator": "default"}) + "\n"
        elif key.endswith("_SECRET_FILE"):
            if SERVICE == "telegram":
                entered = input(key + " (existing private env file; Enter for local login): ").strip()
                if not entered:
                    telegram_login = True
                    values[key] = str(root / "secrets/telegram.env")
                    continue
            else:
                print("Prepare the private provider file using the installation guide first.")
                entered = _required(key + " (absolute path to existing private file): ")
            source = Path(entered).expanduser()
            if not source.is_absolute() or not source.is_file():
                raise ValueError("An existing absolute private file path is required.")
            values[key] = str(source.resolve())
        else:
            values[key] = _required(key + ": ")
    root.mkdir(parents=True, exist_ok=True)
    _private_directory(root / "secrets")
    for path, value in pending.items():
        _write_new(path, value)
    if telegram_login:
        import asyncio

        from .login_telegram import create_session

        asyncio.run(create_session(root / "secrets/telegram.env"))
    target = root / "mcp.local.json"
    _write_new(target, json.dumps(template, indent=2, ensure_ascii=False) + "\n")
    _write_new(
        root / "mcp-client.json", json.dumps(client_config(target), indent=2, ensure_ascii=False) + "\n"
    )
    _write_new(root / "mcp-client.toml", client_toml(target))
    return target


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Create local configuration for Passbolt MCP.")
    parser.add_argument("--directory", type=Path, default=Path.cwd(), help="Directory for new setup files")
    parser.add_argument(
        "--client-only", action="store_true", help="Print a snippet for an existing configuration"
    )
    parser.add_argument(
        "--format", choices=("json", "toml"), default="json", help="Snippet format with --client-only"
    )
    args = parser.parse_args(argv)
    if args.client_only:
        config = args.directory.expanduser().resolve() / "mcp.local.json"
        if not config.is_file():
            parser.error("mcp.local.json does not exist in the selected directory")
        print(client_toml(config) if args.format == "toml" else json.dumps(client_config(config), indent=2))
        return
    if not sys.stdin.isatty():
        parser.error(
            "Interactive setup needs a terminal. Do not pipe credentials or include them in arguments."
        )
    try:
        target = configure(args.directory)
    except (Exception, KeyboardInterrupt):
        # Provider/login errors may contain phone numbers or tokens. Do not echo exception text.
        raise SystemExit(
            "Setup did not finish. Check inputs and existing files locally; no server was started. "
            "Any files already created stay in the chosen directory. Use a fresh directory to retry."
        ) from None
    print(f"Created {target}. Client snippets: mcp-client.json and mcp-client.toml in the same directory.")
    print("Merge the snippet into your client's configuration, then run the server with --check-config.")


if __name__ == "__main__":
    main()
