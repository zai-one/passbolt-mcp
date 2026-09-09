"""Path arguments for native GnuPG and Git for Windows' MSYS GnuPG."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def gpg_path(binary: str, path: Path) -> str:
    directory = Path(binary).resolve().parent
    converter = directory / "cygpath.exe"
    if os.name != "nt" or not (directory / "msys-2.0.dll").is_file():
        return str(path)
    if not converter.is_file():
        raise OSError("MSYS GnuPG requires its companion cygpath executable")
    result = subprocess.run(
        [str(converter), "-u", str(path.resolve())],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if not result.startswith("/") or "\n" in result or "\r" in result:
        raise OSError("MSYS GnuPG path conversion failed")
    return result
