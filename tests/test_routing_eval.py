"""Routing eval: casual RU/EN requests -> router line -> first tool / skill / guide.

The router (server instructions) is all an agent sees at startup. Each case must match exactly
one router line by its intent words, and the expected tool must be reachable from that line
(named on it, in its skill, or in its guide). The suite also fails if any tool, skill or guide
topic is unreachable from the router.
"""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

import pytest

PACKAGE = "zai_passbolt"
ROOT = Path(__file__).resolve().parents[1]
layer = importlib.import_module(f"{PACKAGE}.agent_layer")
PROFILE = importlib.import_module(f"{PACKAGE}.agent_profile").PROFILE
CASES = json.loads((ROOT / "tests/evals/routing_cases.json").read_text(encoding="utf-8"))
WORD = re.compile(r"[a-zа-яё0-9]+")
SCHEME = PROFILE.service


def stems(text: str) -> set[str]:
    return {w[:4] for w in WORD.findall(text.lower().replace("ё", "е")) if len(w) >= 3}


def route_for(request: str) -> str:
    words = stems(request)
    scores = {route.id: len(stems(route.intent) & words) for route in PROFILE.routes}
    best = max(scores.values())
    winners = [rid for rid, score in scores.items() if score == best and score > 0]
    assert len(winners) == 1, (request, winners or "no route")
    return winners[0]


def topics() -> dict[str, str]:
    found = layer.guide_topics(PROFILE)
    found.setdefault("tool-map", layer.tool_map(PROFILE))
    return found


def skill_text(name: str) -> str:
    return (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8") if name else ""


def all_tools() -> set[str]:
    return {name for names in PROFILE.toolsets.values() for name in names}


def test_eval_has_enough_realistic_cases():
    assert 15 <= len(CASES) <= 25
    assert {case["route"] for case in CASES} == {route.id for route in PROFILE.routes}
    langs = {"ru" if re.search("[а-я]", c["request"].lower()) else "en" for c in CASES}
    assert langs == {"ru", "en"}


@pytest.mark.parametrize("case", CASES, ids=[c["request"][:40] for c in CASES])
def test_request_routes_to_tool_skill_and_guide(case):
    rid = route_for(case["request"])
    assert rid == case["route"]
    route = next(r for r in PROFILE.routes if r.id == rid)
    line = next(ln for ln in PROFILE.router.splitlines() if ln.startswith(f"- {route.intent}:"))
    for part in (route.tool, route.skill, route.topic):
        assert not part or part in line
    if route.skill:
        assert (ROOT / "skills" / route.skill / "SKILL.md").is_file()
    assert route.topic in topics() or route.topic == "playbook"
    guide = topics().get(route.topic, topics().get("playbook", ""))
    reachable = " ".join((line, skill_text(route.skill), guide))
    assert not case["tool"] or case["tool"] in reachable, (case["tool"], rid)
    assert not route.tool or route.tool in all_tools()


def test_every_tool_skill_and_guide_is_reachable_from_router():
    router = PROFILE.router
    assert len(router) <= layer.INSTRUCTIONS_LIMIT
    assert f"{SCHEME}://playbook" in router and f"{SCHEME}://guide/tool-map" in router
    tool_map = layer.tool_map(PROFILE)
    missing = sorted(t for t in all_tools() if f"`{t}`" not in tool_map)
    assert not missing, f"tools missing from tool-map: {missing}"
    skills = {p.name for p in (ROOT / "skills").iterdir() if (p / "SKILL.md").is_file()}
    routed_skills = {r.skill for r in PROFILE.routes if r.skill}
    assert skills <= routed_skills, f"skills without a router line: {sorted(skills - routed_skills)}"
    assert routed_skills <= skills
    routed_topics = {r.topic for r in PROFILE.routes}
    playbook = topics().get("playbook", "")
    for topic in set(topics()) - routed_topics - {"playbook", "tool-map"}:
        assert f"guide/{topic}" in playbook or any(f"references/{topic}" in skill_text(s) for s in skills), (
            f"guide topic {topic} unreachable"
        )


def test_optin_toolsets_stay_off_by_default():
    names = all_tools()
    default = layer.selected_tools(PROFILE, names, names, {})
    everything = layer.selected_tools(PROFILE, names, names, {f"{PROFILE.env}_TOOLSETS": "all"})
    assert everything == names
    base = {t for ts, tools in PROFILE.toolsets.items() if ts not in PROFILE.optin for t in tools}
    assert default == base
