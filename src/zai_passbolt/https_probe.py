"""One operator-configured HTTPS check; never return response data or credentials."""

from __future__ import annotations

import asyncio
import base64
from urllib.parse import urlsplit

import httpx

from zai_passbolt.transport import ProviderError


def validate_probe(config):
    allowed = {"kind", "url", "auth", "username", "timeout_seconds", "expected_status"}
    if not isinstance(config, dict) or set(config) - allowed or config.get("kind") != "https_probe":
        raise ValueError("invalid HTTPS probe configuration")
    url = config.get("url")
    if not isinstance(url, str) or not 1 <= len(url) <= 2048 or any(ord(c) <= 32 for c in url):
        raise ValueError("fixed HTTPS probe URL required")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or "\\" in url
    ):
        raise ValueError("HTTPS probe requires an HTTPS URL without user info, query or fragment")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid probe port")
    auth = config.get("auth", "bearer")
    if auth not in {"bearer", "basic"}:
        raise ValueError("probe authentication must be bearer or basic")
    username = config.get("username")
    if auth == "basic" and (
        not isinstance(username, str)
        or not 1 <= len(username) <= 256
        or any(ord(c) < 32 or c == ":" for c in username)
    ):
        raise ValueError("basic probe requires a fixed username")
    if auth == "bearer" and username is not None:
        raise ValueError("bearer probe does not accept a username")
    timeout, status = config.get("timeout_seconds", 10), config.get("expected_status", 200)
    if type(timeout) is not int or not 1 <= timeout <= 30:
        raise ValueError("probe timeout must be between 1 and 30 seconds")
    if type(status) is not int or not 200 <= status <= 299:
        raise ValueError("probe expected status must be a successful HTTP status")
    return url, auth, username, timeout, status


async def probe(config, password: str, target_url: str | None) -> bool:
    try:
        url, auth, username, timeout, expected = validate_probe(config)
        if target_url != url:
            raise PermissionError("probe destination must exactly match the registered URL")
        if (
            not isinstance(password, str)
            or not 1 <= len(password) <= 8192
            or any(ord(c) < 32 or ord(c) == 127 for c in password)
        ):
            raise ValueError("invalid probe credential")
        if auth == "basic":
            authorization = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        else:
            password.encode("ascii")
            authorization = "Bearer " + password
        async with (
            asyncio.timeout(timeout),
            httpx.AsyncClient(
                timeout=timeout,
                verify=True,
                trust_env=False,
                follow_redirects=False,
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
            ) as client,
            client.stream(
                "GET", url, headers={"Authorization": authorization, "Accept": "application/json"}
            ) as response,
        ):
            # Do not read a body, echo headers, follow a redirect or retry an authentication request.
            if response.status_code != expected:
                raise ProviderError("registered HTTPS probe did not return the expected status")
            return True
    except asyncio.CancelledError:
        raise
    except Exception:
        raise ProviderError(
            "registered HTTPS probe failed; check its local configuration and endpoint"
        ) from None
