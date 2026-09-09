"""Build and exercise an installed wheel outside the checkout, without provider requests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAME = "Passbolt"
PACKAGE = "zai_passbolt"
CHILD = """
import runpy, socket, sys
original = socket.socket.connect
def local_only(sock, address):
    if not isinstance(address, tuple) or address[0] not in {'127.0.0.1', '::1', 'localhost'}:
        raise RuntimeError('external network disabled in clean-install gate')
    return original(sock, address)
socket.socket.connect = local_only
package, config = sys.argv[1:]
sys.argv = [package, '--config', config]
runpy.run_module(package, run_name='__main__')
"""
SMOKE = """
import asyncio, importlib, importlib.metadata, json, pathlib, sys
from fastmcp import Client
from fastmcp.client.transports import StdioTransport
package, distribution, expected_version, config, minimum, child = sys.argv[1:]
module = importlib.import_module(package)
assert importlib.metadata.version(distribution) == expected_version == module.__version__
assert pathlib.Path(sys.prefix).resolve() in pathlib.Path(module.__file__).resolve().parents
async def check():
    transport = StdioTransport(command=sys.executable, args=['-c', child, package, config],
                               cwd=str(pathlib.Path(config).parent), keep_alive=False)
    async with Client(transport, timeout=30) as client:
        tools = await client.list_tools()
        assert len(tools) >= int(minimum)
        assert all(tool.name for tool in tools)
        print(json.dumps({'version': expected_version, 'tools': sorted(tool.name for tool in tools)}))
asyncio.run(check())
"""


def run(args, *, cwd=ROOT):
    result = subprocess.run(args, cwd=cwd, text=True, encoding="utf-8", capture_output=True, timeout=240)
    if result.returncode:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(result.returncode)
    return result.stdout


def private(path, value):
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)
    return str(path)


def main():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    extra = ["--extra", "standalone"] if "standalone" in project.get("optional-dependencies", {}) else []
    with tempfile.TemporaryDirectory(prefix="mcp-install-gate-") as directory:
        work = Path(directory).resolve()
        assert work.name.startswith("mcp-install-gate-")
        wheel_dir, environment = work / "dist", work / "environment"
        run(["uv", "build", "--wheel", "--out-dir", str(wheel_dir)])
        (wheel,) = wheel_dir.glob("*.whl")
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            assert any(path.endswith("/licenses/LICENSE") for path in names)
            assert any(path.endswith("/licenses/NOTICE") for path in names)
            assert not any("Service/Handoffs" in path for path in names)
            if NAME == "Telegram":
                assert PACKAGE + "/_vendor/LICENSE" in names
        requirements = work / "requirements.txt"
        run(
            [
                "uv",
                "export",
                "--frozen",
                "--no-dev",
                "--no-emit-project",
                *extra,
                "--output-file",
                str(requirements),
            ]
        )
        run(["uv", "venv", "--python", sys.executable, str(environment)])
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run(["uv", "pip", "install", "--python", str(python), "--require-hashes", "-r", str(requirements)])
        run(["uv", "pip", "install", "--python", str(python), "--no-deps", str(wheel)])
        cwd = work / "unrelated"
        cwd.mkdir(mode=0o700)
        prefix = NAME.upper()
        env = {prefix + "_STATE_PATH": "state/service.sqlite"}
        token = private(cwd / "synthetic.token", "synthetic-install-gate-token")
        if NAME == "Keysso":
            env["KEYSSO_API_TOKEN_FILE"] = token
        elif NAME == "Topvisor":
            env.update(TOPVISOR_API_KEY_FILE=token, TOPVISOR_USER_ID="1")
        elif NAME == "Roistat":
            env.update(ROISTAT_API_KEY_FILE=token, ROISTAT_PROJECT_ALLOWLIST="12345")
        elif NAME == "Yandex":
            env["YANDEX_METRIKA_TOKEN_FILE"] = token
        elif NAME == "Arsenkin":
            env["ARSENKIN_TOKEN_FILE"] = token
        else:
            env[prefix + "_BINDINGS_FILE"] = private(cwd / "bindings.json", '{"local-operator":"default"}')
            if NAME == "Telegram":
                secret = (
                    "TELEGRAM_API_ID=12345\nTELEGRAM_API_HASH=synthetic-hash\n"
                    "TELEGRAM_SESSION_STRING=synthetic-session\n"
                )
            else:
                policy = {
                    "sinks": {},
                    "policies": {
                        "default": {
                            "resource_ids": [],
                            "folder_ids": [],
                            "group_ids": [],
                            "user_ids": [],
                            "domain_hosts": [],
                            "sink_refs": [],
                            "allow_create_resource": False,
                            "allow_create_folder": False,
                            "resource_scope": "all",
                            "folder_scope": "all",
                            "allow_share_all": False,
                        }
                    },
                }
                file = private(cwd / "policy.json", json.dumps(policy))
                secret = "PASSBOLT_BASE_URL=https://vault.example\nPASSBOLT_SINK_CONFIG_FILE=" + file + "\n"
            env[prefix + "_SECRET_FILE"] = private(cwd / "synthetic.env", secret)
        config = cwd / "mcp.local.json"
        config.write_text(json.dumps({"env": env}), encoding="utf-8")
        minimum = {
            "Keysso": 1,
            "Topvisor": 18,
            "Roistat": 22,
            "Yandex": 47,
            "Arsenkin": 12,
            "Telegram": 7,
            "Passbolt": 3,
        }[NAME]
        print(
            run(
                [
                    str(python),
                    "-c",
                    SMOKE,
                    PACKAGE,
                    project["name"],
                    project["version"],
                    str(config),
                    str(minimum),
                    CHILD,
                ],
                cwd=cwd,
            ).strip()
        )
        print(json.dumps({"clean_install": True, "stdio": True, "external_sockets": "blocked"}))


if __name__ == "__main__":
    main()
