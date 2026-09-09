"""Create local configuration interactively. No credentials in command-line arguments."""

from __future__ import annotations

import csv
import getpass
import io
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "PASSBOLT"


def main():
    target = ROOT / "mcp.local.json"
    secret_dir = ROOT / "secrets"
    if target.exists() or secret_dir.exists():
        raise SystemExit("Local configuration or secrets already exist; edit your existing files explicitly.")
    template = json.loads((ROOT / "mcp.example.json").read_text(encoding="utf-8"))
    print("Settings stay on this computer. Use only your own or authorized accounts.")
    secret_dir.mkdir(mode=0o700)
    if os.name == "nt":
        who = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"], check=True, capture_output=True, text=True
        ).stdout
        sid = next(csv.reader(io.StringIO(who.strip())))[1]
        subprocess.run(
            [
                "icacls",
                str(secret_dir),
                "/inheritance:r",
                "/grant:r",
                "*" + sid + ":(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
            ],
            check=True,
            capture_output=True,
        )
    values = template["env"]
    for key, default in list(values.items()):
        if key.endswith("_STATE_PATH"):
            continue
        if default.endswith(".token"):
            credential = getpass.getpass(key + " (paste provider token): ").strip()
            if not credential:
                raise SystemExit("Credential is required. No server started.")
            path = ROOT / default
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(credential)
        elif key.endswith("_BINDINGS_FILE"):
            label = "owner_all"
            path = ROOT / default
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"local-operator": label}, stream)
        elif key.endswith("_SECRET_FILE"):
            print("Prepare the private provider env file as described in INSTALL.md.")
            entered = input(key + " (absolute path to existing private file): ").strip()
            if not Path(entered).is_absolute() or not Path(entered).is_file():
                raise SystemExit("Existing absolute private file path required.")
            values[key] = entered
        elif default:
            values[key] = input(key + ": ").strip()
            if not values[key]:
                raise SystemExit("Setting is required.")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(template, stream, indent=2)
        stream.write("\n")
    print("Created mcp.local.json. Run the --check-config command from INSTALL.md.")


if __name__ == "__main__":
    main()
