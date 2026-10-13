"""Static token-budget gate: router, tool descriptions, prompts and SKILL.md frontmatter.

Run: uv run python scripts/token_budget.py  (also exercised by tests/test_agent_layer.py)
"""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
PACKAGE = "zai_passbolt"
NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"{path}: missing frontmatter")
    head = text[4 : text.index("\n---", 4)]
    data: dict[str, str] = {}
    for line in head.splitlines():
        if line and not line.startswith(" ") and ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip().strip('"')
    return data


def problems() -> list[str]:
    layer = importlib.import_module(f"{PACKAGE}.agent_layer")
    profile = importlib.import_module(f"{PACKAGE}.agent_profile").PROFILE
    found: list[str] = []
    if len(profile.router) > layer.INSTRUCTIONS_LIMIT:
        found.append(f"router instructions {len(profile.router)} > {layer.INSTRUCTIONS_LIMIT}")
    for name, text in profile.descriptions.items():
        if len(text) > layer.DESCRIPTION_LIMIT:
            found.append(f"{name}: description {len(text)} > {layer.DESCRIPTION_LIMIT}")
        if len(text.split(". ")[0]) > 120:
            found.append(f"{name}: first sentence > 120")
    topics = layer.guide_topics(profile)
    for skill in sorted((ROOT / "skills").glob("*/SKILL.md")):
        meta = frontmatter(skill)
        folder = skill.parent.name
        if meta.get("name") != folder or not NAME.match(folder) or len(folder) > 64:
            found.append(f"{skill}: name must equal folder and match a-z0-9-")
        if not 0 < len(meta.get("description", "")) <= 300:
            found.append(f"{skill}: description must be 1..300 chars")
        if len(skill.read_text(encoding="utf-8").splitlines()) > 80:
            found.append(f"{skill}: body > 80 lines")
        for ref in skill.parent.rglob("*.md"):
            topic = ref.stem
            if topic in topics and topics[topic] != ref.read_text(encoding="utf-8"):
                found.append(f"{ref}: differs from resources/guide/{topic}.md (keep copies identical)")
        for link in re.findall(r"\(references/([^)]+)\)", skill.read_text(encoding="utf-8")):
            if not (skill.parent / "references" / link).is_file():
                found.append(f"{skill}: broken reference {link}")
    return found


def main() -> None:
    found = problems()
    for line in found:
        print(line)
    raise SystemExit(1 if found else 0)


if __name__ == "__main__":
    main()
