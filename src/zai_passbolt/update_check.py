"""Opt-out, read-only update checker.

Compares the installed package version with the latest GitHub release (or tag)
of the public repository. It never installs anything: it only reports the
current and latest versions, the release notes link and the update command.

* Public GitHub API, no credentials, short timeout.
* Results are cached for 24 hours in a small JSON file.
* Any network or parsing failure degrades to ``status="unknown"``.
* ``PASSBOLT_DISABLE_UPDATE_CHECK=1`` disables all network access.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

import httpx

from zai_passbolt import __version__

REPOSITORY = "zai-one/passbolt-mcp"
DIST_NAME = "zai-passbolt-mcp"
WHEEL_NAME = "zai_passbolt_mcp-{version}-py3-none-any.whl"
DISABLE_ENV = "PASSBOLT_DISABLE_UPDATE_CHECK"
API_ROOT = "https://api.github.com"
CACHE_TTL_SECONDS = 24 * 3600
TIMEOUT_SECONDS = 3.0
MAX_RESPONSE_BYTES = 512_000
_VERSION = re.compile(r"v?(\d+(?:\.\d+){0,3})")
_TRUE = {"1", "true", "yes", "on"}


def disabled() -> bool:
    return os.environ.get(DISABLE_ENV, "").strip().lower() in _TRUE


def parse_version(value: object) -> tuple[int, ...] | None:
    if not isinstance(value, str):
        return None
    match = _VERSION.match(value.strip())
    if match is None:
        return None
    parts = tuple(int(part) for part in match.group(1).split("."))
    return parts + (0,) * (3 - len(parts)) if len(parts) < 3 else parts


def _is_checkout() -> bool:
    return (Path(__file__).resolve().parents[2] / ".git").exists()


def update_commands(latest: str | None) -> dict[str, str]:
    version = (latest or "").lstrip("v")
    commands = {
        "git_checkout": "git pull --ff-only && uv sync --frozen --extra standalone",
    }
    if version:
        wheel = WHEEL_NAME.format(version=version)
        commands["release_package"] = (
            f'uv tool install --force "{DIST_NAME}[standalone] @ https://github.com/{REPOSITORY}'
            f'/releases/download/v{version}/{wheel}"'
        )
    return commands


def _result(latest: str | None, notes_url: str | None, *, status: str, source: str, **extra: Any):
    current = parse_version(__version__)
    newest = parse_version(latest)
    available = bool(current and newest and newest > current)
    commands = update_commands(latest if available else None)
    method = "git_checkout" if _is_checkout() else "release_package"
    payload: dict[str, Any] = {
        "current_version": __version__,
        "latest_version": latest.lstrip("v") if isinstance(latest, str) else None,
        "update_available": available,
        "status": status,
        "source": source,
        "release_notes_url": notes_url,
        "install_method": method,
        "update_command": commands.get(method) if available else None,
        "update_commands": commands if available else {},
        "auto_update": False,
        "disable_with": f"{DISABLE_ENV}=1",
    }
    payload.update(extra)
    return payload


def _read_cache(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("checked_at"), int | float):
        return None
    if data.get("repository") != REPOSITORY:
        return None
    return data


def _write_cache(path: Path | None, latest: str, notes_url: str | None) -> None:
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "repository": REPOSITORY,
                    "latest": latest,
                    "release_notes_url": notes_url,
                    "checked_at": time.time(),
                }
            ),
            encoding="utf-8",
        )
        os.replace(temporary, path)
    except OSError:
        return


def _decode(response: httpx.Response) -> Any:
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise ValueError("response too large")
    return response.json()


async def _fetch_latest(client: httpx.AsyncClient) -> tuple[str, str | None]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": f"{DIST_NAME}/{__version__}"}
    response = await client.get(f"{API_ROOT}/repos/{REPOSITORY}/releases/latest", headers=headers)
    if response.status_code == 200:
        data = _decode(response)
        tag = data.get("tag_name") if isinstance(data, dict) else None
        if parse_version(tag) is None:
            raise ValueError("release without a version tag")
        url = data.get("html_url")
        notes = url if isinstance(url, str) and url.startswith("https://github.com/") else None
        return str(tag), notes or f"https://github.com/{REPOSITORY}/releases/tag/{tag}"
    if response.status_code != 404:
        raise ValueError(f"GitHub API returned HTTP {response.status_code}")
    response = await client.get(f"{API_ROOT}/repos/{REPOSITORY}/tags?per_page=100", headers=headers)
    if response.status_code != 200:
        raise ValueError(f"GitHub API returned HTTP {response.status_code}")
    data = _decode(response)
    names = [item.get("name") for item in data if isinstance(item, dict)] if isinstance(data, list) else []
    versions = [(parse_version(name), name) for name in names if parse_version(name) is not None]
    if not versions:
        raise ValueError("no version tags")
    tag = max(versions)[1]
    return str(tag), f"https://github.com/{REPOSITORY}/releases/tag/{tag}"


def cached_status(cache_path: Path | None) -> dict[str, Any] | None:
    """Return the last known result without any network access."""
    if disabled():
        return None
    cached = _read_cache(cache_path)
    if cached is None:
        return None
    return _result(
        cached.get("latest"),
        cached.get("release_notes_url"),
        status="ok",
        source="cache",
        checked_at=int(cached["checked_at"]),
    )


async def check_for_update(
    cache_path: Path | None,
    *,
    force: bool = False,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    if disabled():
        return _result(None, None, status="disabled", source="none")
    cached = _read_cache(cache_path)
    if cached is not None and not force and time.time() - cached["checked_at"] < CACHE_TTL_SECONDS:
        return _result(
            cached.get("latest"),
            cached.get("release_notes_url"),
            status="ok",
            source="cache",
            checked_at=int(cached["checked_at"]),
        )
    try:
        if client is None:
            async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False) as owned:
                latest, notes = await _fetch_latest(owned)
        else:
            latest, notes = await _fetch_latest(client)
    except (httpx.HTTPError, ValueError, TypeError, AttributeError) as exc:
        return _result(
            cached.get("latest") if cached else None,
            cached.get("release_notes_url") if cached else None,
            status="unknown",
            source="stale_cache" if cached else "none",
            error=type(exc).__name__,
        )
    _write_cache(cache_path, latest, notes)
    return _result(latest, notes, status="ok", source="github")


def startup_hint(cache_path: Path | None) -> str:
    """One short sentence for server instructions; empty unless an update is known."""
    status = cached_status(cache_path)
    if not status or not status["update_available"]:
        return ""
    return (
        f"Update available: {DIST_NAME} {status['latest_version']} "
        f"(installed {status['current_version']}). Tell the user once; do not update automatically. "
        f"Details: {status['release_notes_url']}"
    )


def refresh_in_background(cache_path: Path | None) -> None:
    """Best-effort cache refresh on a daemon thread; never blocks or raises."""
    if disabled():
        return
    import asyncio
    import threading

    def run() -> None:
        try:
            asyncio.run(check_for_update(cache_path))
        except Exception:  # noqa: BLE001 - background hint must never crash the server
            return

    threading.Thread(target=run, name="update-check", daemon=True).start()
