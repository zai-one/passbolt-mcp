"""Opt-out, read-only update checker.

Compares the installed package version with the latest GitHub release (or tag)
of the public repository. It never installs anything: it only reports the
current and latest versions, the release notes link and the update command.

* Public GitHub API, no credentials, short timeout.
* Results are cached for 24 hours in a small JSON file.
* Every fetch attempt is recorded; after a failure no new request is made for
  30 minutes, and ``force=True`` is honoured at most once a minute.
* Only plain version tags (``v1.2.3``) are accepted; anything else is treated as
  "no release" and never reaches results, commands or server instructions.
* Any network or parsing failure degrades to ``status="unknown"``.
* ``PASSBOLT_DISABLE_UPDATE_CHECK=1`` disables all network access.
"""

from __future__ import annotations

import json
import os
import re
import secrets
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
FAILURE_RETRY_SECONDS = 30 * 60
FORCE_MIN_INTERVAL_SECONDS = 60
TIMEOUT_SECONDS = 3.0
MAX_RESPONSE_BYTES = 512_000
# Plain version tags only: ASCII digits, at most four parts, nothing before or after.
_VERSION = re.compile(r"v?([0-9]{1,9}(?:\.[0-9]{1,9}){0,3})")
_NOTES_URL = re.compile(r"https://github\.com/" + re.escape(REPOSITORY) + r"/[A-Za-z0-9._~/-]{1,200}")
_TRUE = {"1", "true", "yes", "on"}


def disabled() -> bool:
    return os.environ.get(DISABLE_ENV, "").strip().lower() in _TRUE


def parse_version(value: object) -> tuple[int, ...] | None:
    if not isinstance(value, str):
        return None
    match = _VERSION.fullmatch(value)
    if match is None:
        return None
    parts = tuple(int(part) for part in match.group(1).split("."))
    return parts + (0,) * (3 - len(parts)) if len(parts) < 3 else parts


def _plain_tag(value: object) -> str | None:
    """Return the tag only if it is a plain version tag; otherwise treat it as no release."""
    return value if isinstance(value, str) and parse_version(value) is not None else None


def _notes_url(value: object, tag: str | None) -> str | None:
    if isinstance(value, str) and _NOTES_URL.fullmatch(value):
        return value
    return f"https://github.com/{REPOSITORY}/releases/tag/{tag}" if tag else None


def _is_checkout() -> bool:
    return (Path(__file__).resolve().parents[2] / ".git").exists()


def update_commands(latest: str | None) -> dict[str, str]:
    tag = _plain_tag(latest)
    version = tag.lstrip("v") if tag else ""
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
    latest = _plain_tag(latest)
    notes_url = _notes_url(notes_url, latest) if latest else None
    current = parse_version(__version__)
    newest = parse_version(latest)
    available = bool(current and newest and newest > current)
    commands = update_commands(latest if available else None)
    method = "git_checkout" if _is_checkout() else "release_package"
    payload: dict[str, Any] = {
        "current_version": __version__,
        "latest_version": latest.lstrip("v") if latest else None,
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


def _timestamp(value: object) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def _read_cache(path: Path | None) -> dict[str, Any] | None:
    """Read and re-validate the cache; a tampered tag or URL is dropped, never trusted."""
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("repository") != REPOSITORY:
        return None
    checked_at = _timestamp(data.get("checked_at"))
    attempted_at = _timestamp(data.get("attempted_at"))
    if attempted_at is None:
        attempted_at = checked_at
    if attempted_at is None:
        return None
    latest = _plain_tag(data.get("latest"))
    if latest is None:
        checked_at = None
    return {
        "latest": latest,
        "release_notes_url": _notes_url(data.get("release_notes_url"), latest) if latest else None,
        "checked_at": checked_at,
        "attempted_at": attempted_at,
        "failed": data.get("failed") is True,
    }


def _write_cache(
    path: Path | None,
    *,
    latest: str | None,
    notes_url: str | None,
    checked_at: float | None,
    attempted_at: float,
    failed: bool,
) -> None:
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(
            json.dumps(
                {
                    "repository": REPOSITORY,
                    "latest": latest,
                    "release_notes_url": notes_url,
                    "checked_at": checked_at,
                    "attempted_at": attempted_at,
                    "failed": failed,
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
        tag = _plain_tag(data.get("tag_name") if isinstance(data, dict) else None)
        if tag is None:
            raise ValueError("release without a plain version tag")
        return tag, _notes_url(data.get("html_url"), tag)
    if response.status_code != 404:
        raise ValueError(f"GitHub API returned HTTP {response.status_code}")
    response = await client.get(f"{API_ROOT}/repos/{REPOSITORY}/tags?per_page=100", headers=headers)
    if response.status_code != 200:
        raise ValueError(f"GitHub API returned HTTP {response.status_code}")
    data = _decode(response)
    names = [item.get("name") for item in data if isinstance(item, dict)] if isinstance(data, list) else []
    tags = [tag for name in names if (tag := _plain_tag(name)) is not None]
    if not tags:
        raise ValueError("no plain version tags")
    tag = max(tags, key=lambda item: parse_version(item) or ())
    return tag, _notes_url(None, tag)


def _cached_result(cached: dict[str, Any], *, status: str, source: str, **extra: Any) -> dict[str, Any]:
    if cached["checked_at"] is not None:
        extra["checked_at"] = int(cached["checked_at"])
    return _result(cached["latest"], cached["release_notes_url"], status=status, source=source, **extra)


def cached_status(cache_path: Path | None) -> dict[str, Any] | None:
    """Return the last known good result without any network access."""
    if disabled():
        return None
    cached = _read_cache(cache_path)
    if cached is None or cached["latest"] is None:
        return None
    return _cached_result(cached, status="ok", source="cache")


def _without_fetch(cached: dict[str, Any] | None, *, force: bool, now: float) -> dict[str, Any] | None:
    """Return a cache-only result when the throttle rules forbid a new request, else None."""
    if cached is None:
        return None
    good = cached["latest"] is not None
    since_attempt = now - cached["attempted_at"]
    if since_attempt < 0:
        # A timestamp in the future (clock change, edited cache) never blocks a fetch.
        return None
    if force:
        if since_attempt >= FORCE_MIN_INTERVAL_SECONDS:
            return None
        retry = int(FORCE_MIN_INTERVAL_SECONDS - since_attempt) + 1
        if good and not cached["failed"]:
            return _cached_result(cached, status="ok", source="cache", throttled=True, retry_after=retry)
        source = "stale_cache" if good else "none"
        return _cached_result(cached, status="unknown", source=source, throttled=True, retry_after=retry)
    if good and cached["checked_at"] is not None and 0 <= now - cached["checked_at"] < CACHE_TTL_SECONDS:
        return _cached_result(cached, status="ok", source="cache")
    if cached["failed"] and since_attempt < FAILURE_RETRY_SECONDS:
        retry = int(FAILURE_RETRY_SECONDS - since_attempt) + 1
        source = "stale_cache" if good else "none"
        return _cached_result(cached, status="unknown", source=source, retry_after=retry)
    return None


async def check_for_update(
    cache_path: Path | None,
    *,
    force: bool = False,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    if disabled():
        return _result(None, None, status="disabled", source="none")
    now = time.time()
    cached = _read_cache(cache_path)
    known = _without_fetch(cached, force=force, now=now)
    if known is not None:
        return known
    try:
        if client is None:
            async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False) as owned:
                latest, notes = await _fetch_latest(owned)
        else:
            latest, notes = await _fetch_latest(client)
    except (httpx.HTTPError, ValueError, TypeError, AttributeError) as exc:
        # Negative cache: record the failed attempt and keep the last good result.
        previous = cached or {"latest": None, "release_notes_url": None, "checked_at": None}
        _write_cache(
            cache_path,
            latest=previous["latest"],
            notes_url=previous["release_notes_url"],
            checked_at=previous["checked_at"],
            attempted_at=now,
            failed=True,
        )
        if cached is not None and cached["latest"] is not None:
            return _cached_result(cached, status="unknown", source="stale_cache", error=type(exc).__name__)
        return _result(None, None, status="unknown", source="none", error=type(exc).__name__)
    _write_cache(cache_path, latest=latest, notes_url=notes, checked_at=now, attempted_at=now, failed=False)
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
