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
ALL_CASES = json.loads((ROOT / "tests/evals/routing_cases.json").read_text(encoding="utf-8"))
CASES = [c for c in ALL_CASES if c["route"]]
NEGATIVE = [c for c in ALL_CASES if not c["route"]]
WORD = re.compile(r"[a-zа-яё0-9]+")
SCHEME = PROFILE.service


_RU_ENDINGS = (
    "ировать ировал ование ения ение ости ость ться ются ется ишь ить ать ять еть уть ывать ивать "
    "ами ями ого его ому ему ыми ими ией иям иях ях ах ов ев ей ой ий ый ая яя ое ее ые ие ую юю "
    "ом ем ам ям а я о е ы и у ю ь"
)
_EN_ENDINGS = "ization ations ation ings ing ies ied ers er ed es s ly"
_STOPWORDS = (
    "the and for with from into this that what how can you please my our me all any get show give "
    "make let need want just some about over then also are was its use using "
    "и в во на по с со к ко из за для от до как что это мне мой моя мои наш все всё ли не "
    "же бы или а но у о об при так ещё еще есть был была было надо нужно можно пожалуйста дай покажи "
    "сделай хочу"
)
RU_SUFFIXES = sorted(_RU_ENDINGS.split(), key=len, reverse=True)
EN_SUFFIXES = sorted(_EN_ENDINGS.split(), key=len, reverse=True)
STOP = set(_STOPWORDS.split())


def stem(word: str) -> str:
    word = word.replace("ё", "е")
    suffixes = RU_SUFFIXES if re.search("[а-я]", word) else EN_SUFFIXES
    for suffix in suffixes:
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            return word[: -len(suffix)]
    return word


def stems(text: str) -> set[str]:
    return {stem(w) for w in WORD.findall(text.lower()) if len(w) >= 3 and w not in STOP}


def scores_for(request: str) -> dict[str, int]:
    words = stems(request)
    return {route.id: len(stems(route.intent) & words) for route in PROFILE.routes}


def route_for(request: str) -> str | None:
    scores = scores_for(request)
    ranked = sorted(scores.values(), reverse=True)
    if ranked[0] == 0:
        return None
    winners = [rid for rid, score in scores.items() if score == ranked[0]]
    assert len(winners) == 1, (request, winners)
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
    routes = {route.id for route in PROFILE.routes}
    assert {case["route"] for case in CASES} == routes
    for rid in routes:  # every route needs at least two independent paraphrases
        assert sum(c["route"] == rid for c in CASES) >= 2, rid
    assert len(NEGATIVE) >= 3 and len(ALL_CASES) <= 60
    langs = {"ru" if re.search("[а-я]", c["request"].lower()) else "en" for c in CASES}
    assert langs == {"ru", "en"}


def test_paraphrases_are_not_router_copies():
    for case in CASES:
        intent = next(r.intent for r in PROFILE.routes if r.id == case["route"])
        extra = stems(case["request"]) - stems(intent)
        assert extra, f"case is a copy of the router intent: {case['request']}"


def test_every_route_has_a_distinctive_stem():
    for route in PROFILE.routes:
        others = set().union(*(stems(r.intent) for r in PROFILE.routes if r.id != route.id))
        assert stems(route.intent) - others, f"route {route.id} has no stem of its own"


@pytest.mark.parametrize("case", NEGATIVE, ids=[c["request"][:40] for c in NEGATIVE])
def test_out_of_scope_requests_match_no_route(case):
    assert route_for(case["request"]) is None, (case["request"], scores_for(case["request"]))


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
