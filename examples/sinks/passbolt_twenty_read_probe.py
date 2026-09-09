#!/usr/local/bin/python3.14
"""Use one Passbolt credential for a fixed, read-only Twenty API probe.

The process intentionally emits no stdout/stderr and persists no response or
credential material. Exit zero is the only ACK and is reached only after an
authenticated HTTP 200 with a bounded JSON response.
"""

from __future__ import annotations

import http.client
import json
import ssl
import sys
from collections.abc import Callable, Mapping
from typing import Any, Protocol
from urllib.parse import urlsplit

RESOURCE_ID = "ed21dd90-1f1e-444b-bf6f-e84fdd5aa279"
TARGET_ORIGIN = "https://crm.zai.one"
TARGET_HOST = "crm.zai.one"
PROBE_PATH = "/rest/tasks?limit=1"
MAX_ENVELOPE_BYTES = 128 * 1024
MAX_RESPONSE_BYTES = 256 * 1024


class Response(Protocol):
    status: int

    def getheader(self, name: str, default: str | None = None) -> str | None: ...

    def read(self, amount: int | None = None) -> bytes: ...


class Connection(Protocol):
    def request(
        self, method: str, url: str, body: bytes | None = None, headers: Mapping[str, str] = {}
    ) -> None: ...

    def getresponse(self) -> Response: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[[str, int, float, ssl.SSLContext], Connection]


def _connection(host: str, port: int, timeout: float, context: ssl.SSLContext) -> Connection:
    return http.client.HTTPSConnection(host, port=port, timeout=timeout, context=context)


def _envelope(value: Any) -> tuple[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "resource_id",
        "username",
        "password",
        "target_url",
    }:
        raise ValueError("invalid envelope")
    if value["resource_id"] != RESOURCE_ID:
        raise PermissionError("resource denied")
    password = value["password"]
    if not isinstance(password, str) or not password or len(password) > 65_536:
        raise ValueError("invalid credential")
    target = value["target_url"]
    if not isinstance(target, str) or target.rstrip("/") != TARGET_ORIGIN:
        raise PermissionError("target denied")
    parsed = urlsplit(target)
    if (
        parsed.scheme != "https"
        or parsed.hostname != TARGET_HOST
        or parsed.port not in {None, 443}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise PermissionError("target denied")
    return password, target


def probe(value: Any, *, connection_factory: ConnectionFactory = _connection) -> None:
    password, _target = _envelope(value)
    context = ssl.create_default_context()
    connection = connection_factory(TARGET_HOST, 443, 15.0, context)
    try:
        connection.request(
            "GET",
            PROBE_PATH,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {password}",
                "User-Agent": "mcp-platform-passbolt-sink/1",
            },
        )
        response = connection.getresponse()
        content_type = (response.getheader("Content-Type", "") or "").lower()
        length = response.getheader("Content-Length")
        if response.status != 200 or "application/json" not in content_type:
            raise PermissionError("authenticated probe rejected")
        if isinstance(length, str) and length.isdigit() and int(length) > MAX_RESPONSE_BYTES:
            raise ValueError("response too large")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if not body or len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("invalid response size")
        json.loads(body.decode("utf-8"))
    finally:
        connection.close()


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_ENVELOPE_BYTES + 1)
        if not raw or len(raw) > MAX_ENVELOPE_BYTES:
            return 1
        probe(json.loads(raw.decode("utf-8")))
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
