from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    for args in (["-m", "ruff", "check", "src", "tests", "scripts"], ["-m", "pytest", "-q"]):
        result = subprocess.run([sys.executable, *args], cwd=ROOT)
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
