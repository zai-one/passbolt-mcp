"""Backward-compatible checkout entry point for the installed setup wizard."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from zai_passbolt.setup import main  # noqa: E402

if __name__ == "__main__":
    main(["--directory", str(Path(__file__).resolve().parents[1]), *sys.argv[1:]])
