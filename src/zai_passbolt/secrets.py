from __future__ import annotations

import os
import stat
from pathlib import Path


def read_secret_env(path: Path) -> dict[str, str]:
    """Read a root-mounted env file without ever logging its values."""
    if not path.is_file():
        return {}
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        normalized_key = key.strip()
        if normalized_key and normalized_key.replace("_", "").isalnum():
            result[normalized_key] = value.strip()
    return result


def require_private_file(path: Path, *, max_bytes: int = 65_536) -> None:
    """Fail closed unless ``path`` is a bounded server-custody regular file."""
    if not path.is_absolute():
        raise ValueError("private file path must be absolute")
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("private file is unavailable") from exc
    current_uid = int(getattr(os, "getuid", lambda: -1)())
    unsafe = (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_size <= 0
        or info.st_size > max_bytes
        or (os.name != "nt" and bool(info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)))
        or (os.name != "nt" and info.st_uid not in {0, current_uid})
    )
    if unsafe:
        raise ValueError("private file custody is unsafe")


def read_private_secret_env(path: Path, *, max_bytes: int = 65_536) -> dict[str, str]:
    """Read one bounded, non-symlink server-custody env file.

    POSIX deployments require an owner-only file owned by root or the current
    service uid. Windows test/runtime custody is delegated to the host ACL.
    Values are never included in an exception.
    """

    require_private_file(path, max_bytes=max_bytes)
    return read_secret_env(path)
