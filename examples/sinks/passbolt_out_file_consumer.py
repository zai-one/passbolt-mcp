#!/usr/local/bin/python3.14
"""Consume one Passbolt out_file envelope without exposing or persisting it."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

SPOOL_ROOT = Path("/run/passbolt-use")
MAX_ENVELOPE_BYTES = 128 * 1024


def _trusted_owner(uid: int) -> bool:
    effective_uid = os.geteuid() if hasattr(os, "geteuid") else 0
    return uid in {0, effective_uid}


def _private_directory(path: Path) -> bool:
    info = path.lstat()
    return (
        path.is_absolute()
        and not path.is_symlink()
        and stat.S_ISDIR(info.st_mode)
        and _trusted_owner(info.st_uid)
        and stat.S_IMODE(info.st_mode) & 0o077 == 0
    )


def _validate_envelope(payload: Any) -> None:
    if not isinstance(payload, dict) or set(payload) != {
        "resource_id",
        "username",
        "password",
        "target_url",
    }:
        raise ValueError("invalid envelope")
    UUID(str(payload["resource_id"]))
    username = payload["username"]
    if username is not None and (not isinstance(username, str) or len(username) > 255):
        raise ValueError("invalid username")
    password = payload["password"]
    if not isinstance(password, str) or not password or len(password) > 65_536:
        raise ValueError("invalid password")
    target = payload["target_url"]
    if target is not None:
        if not isinstance(target, str):
            raise ValueError("invalid target")
        parsed = urlsplit(target)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("invalid target")


def consume(raw_path: str) -> None:
    path = Path(raw_path)
    if not _private_directory(SPOOL_ROOT) or not path.is_absolute() or path.parent != SPOOL_ROOT:
        raise PermissionError("invalid spool")
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or not _trusted_owner(info.st_uid)
        or stat.S_IMODE(info.st_mode) & 0o077
        or not 0 < info.st_size <= MAX_ENVELOPE_BYTES
    ):
        raise PermissionError("invalid envelope file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != info.st_dev
            or opened.st_ino != info.st_ino
        ):
            raise PermissionError("envelope changed")
        data = bytearray()
        while len(data) <= MAX_ENVELOPE_BYTES:
            chunk = os.read(descriptor, min(8192, MAX_ENVELOPE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if not data or len(data) > MAX_ENVELOPE_BYTES:
            raise ValueError("invalid envelope size")
        _validate_envelope(json.loads(data.decode("utf-8")))
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        return 2
    try:
        consume(arguments[0])
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
