from __future__ import annotations

import json
import time

import httpx
import pytest
from fastmcp import Client
from test_runtime import FixtureAdapter

from zai_passbolt import __version__, update_check
from zai_passbolt.server import create_server

REPO_API = "https://api.github.com/repos/zai-one/passbolt-mcp"


def bump(version: str) -> str:
    major, minor, patch = (update_check.parse_version(version) or (0, 0, 0))[:3]
    return f"{major}.{minor + 1}.0"


NEWER = bump(__version__)


def client_for(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.delenv("PASSBOLT_DISABLE_UPDATE_CHECK", raising=False)


def release_handler(tag: str, calls: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        assert "authorization" not in request.headers
        assert str(request.url) == f"{REPO_API}/releases/latest"
        return httpx.Response(
            200,
            json={"tag_name": tag, "html_url": f"https://github.com/zai-one/passbolt-mcp/releases/tag/{tag}"},
        )

    return handler


async def test_newer_release_is_suggested_and_cached(tmp_path, enabled):
    calls: list[str] = []
    cache = tmp_path / "update-check.json"
    async with client_for(release_handler(f"v{NEWER}", calls)) as client:
        result = await update_check.check_for_update(cache, client=client)
        again = await update_check.check_for_update(cache, client=client)
    assert result["update_available"] is True
    assert result["current_version"] == __version__ and result["latest_version"] == NEWER
    assert result["release_notes_url"].endswith(f"/releases/tag/v{NEWER}")
    assert result["auto_update"] is False and result["update_command"]
    assert (
        f"/releases/download/v{NEWER}/zai_passbolt_mcp-{NEWER}-py3-none-any.whl"
        in (result["update_commands"]["release_package"])
    )
    assert again["source"] == "cache" and len(calls) == 1
    assert json.loads(cache.read_text())["latest"] == f"v{NEWER}"


async def test_same_version_reports_no_update(tmp_path, enabled):
    async with client_for(release_handler(f"v{__version__}", [])) as client:
        result = await update_check.check_for_update(tmp_path / "c.json", client=client)
    assert result["update_available"] is False and result["update_command"] is None


async def test_falls_back_to_tags_when_no_release(tmp_path, enabled):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/releases/latest"):
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(200, json=[{"name": "v0.1.0"}, {"name": f"v{NEWER}"}, {"name": "junk"}])

    async with client_for(handler) as client:
        result = await update_check.check_for_update(tmp_path / "c.json", client=client)
    assert result["latest_version"] == NEWER and result["update_available"] is True


async def test_offline_failure_is_graceful_and_uses_stale_cache(tmp_path, enabled):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    cache = tmp_path / "c.json"
    async with client_for(boom) as client:
        result = await update_check.check_for_update(cache, client=client)
    assert result["status"] == "unknown" and result["update_available"] is False
    cache.write_text(
        json.dumps(
            {
                "repository": "zai-one/passbolt-mcp",
                "latest": f"v{NEWER}",
                "release_notes_url": "https://github.com/zai-one/passbolt-mcp/releases",
                "checked_at": time.time() - 10 * 86400,
            }
        )
    )
    async with client_for(boom) as client:
        stale = await update_check.check_for_update(cache, client=client)
    assert stale["source"] == "stale_cache" and stale["update_available"] is True


async def test_http_error_and_bad_payload_are_unknown(tmp_path, enabled):
    async with client_for(lambda request: httpx.Response(403, json={})) as client:
        assert (await update_check.check_for_update(tmp_path / "a.json", client=client))[
            "status"
        ] == "unknown"
    async with client_for(lambda request: httpx.Response(200, json={"tag_name": None})) as client:
        assert (await update_check.check_for_update(tmp_path / "b.json", client=client))[
            "status"
        ] == "unknown"


async def test_opt_out_makes_no_request(tmp_path, monkeypatch):
    monkeypatch.setenv("PASSBOLT_DISABLE_UPDATE_CHECK", "1")

    def fail(request: httpx.Request) -> httpx.Response:
        raise AssertionError("network used while disabled")

    async with client_for(fail) as client:
        result = await update_check.check_for_update(tmp_path / "c.json", client=client)
    assert result["status"] == "disabled"
    assert update_check.startup_hint(tmp_path / "c.json") == ""


def test_version_parsing():
    assert update_check.parse_version("v1.2") == (1, 2, 0)
    assert update_check.parse_version("0.10.1") > update_check.parse_version("0.9.9")
    assert update_check.parse_version("main") is None


def _cache(path, tag):
    path.write_text(
        json.dumps(
            {
                "repository": "zai-one/passbolt-mcp",
                "latest": tag,
                "release_notes_url": f"https://github.com/zai-one/passbolt-mcp/releases/tag/{tag}",
                "checked_at": time.time(),
            }
        )
    )


async def test_server_instructions_tool_and_status_surface_cached_hint(config, enabled, monkeypatch):
    _cache(config.state_path.parent / "update-check.json", f"v{NEWER}")

    async def no_network(*args, **kwargs):
        raise AssertionError("status must not fetch")

    async with Client(create_server(config, transport="stdio", adapter=FixtureAdapter())) as client:
        assert f"Update available: zai-passbolt-mcp {NEWER}" in (client.initialize_result.instructions or "")
        monkeypatch.setattr(update_check, "_fetch_latest", no_network)
        result = (await client.call_tool("passbolt_check_update", {})).data
        status = (await client.call_tool("passbolt_status", {})).data
    assert result["update_available"] is True and result["source"] == "cache"
    assert status["update"]["latest_version"] == NEWER
    assert "standalone" in status["update"]["update_command"]


async def test_no_hint_without_cache(config, enabled):
    async with Client(create_server(config, transport="stdio", adapter=FixtureAdapter())) as client:
        assert "Update available" not in (client.initialize_result.instructions or "")
        status = (await client.call_tool("passbolt_status", {})).data
    assert "update" not in status
