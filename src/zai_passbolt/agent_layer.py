"""Agent layer: router instructions, compact descriptions, toolsets, guide resources and prompts.

Applied once after every tool is registered. Pure local logic: no provider calls.
"""

from __future__ import annotations

import inspect
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

from . import lazy_loading

INSTRUCTIONS_LIMIT = 1200
DESCRIPTION_LIMIT = 300
ALWAYS_ON = "meta"


@dataclass(frozen=True)
class Prompt:
    name: str
    description: str
    arguments: tuple[str, ...]
    template: str


@dataclass(frozen=True)
class Route:
    """One router line: casual intent words -> first tool; skill; guide topic."""

    id: str
    intent: str
    tool: str
    skill: str
    topic: str


def build_router(service: str, header: str, routes: tuple[Route, ...], footer: str = "") -> str:
    """Compose router instructions: header, one line per intent, footer, docs + playbook fallback."""
    lines = [header.strip(), f"Intent -> first tool; skill; {service}://guide/<topic>:"]
    for route in routes:
        parts = (route.tool, route.skill, route.topic)
        lines.append(f"- {route.intent}: " + "; ".join(part for part in parts if part))
    if footer:
        lines.append(footer.strip())
    lines.append(
        f"Unsure? {service}://playbook (flows, skills) or {service}://guide/tool-map (every tool, toolsets)."
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class Profile:
    service: str  # uri scheme and env prefix source, e.g. "topvisor"
    package: str  # python package holding resources/guide/*.md
    router: str
    descriptions: Mapping[str, str]
    toolsets: Mapping[str, tuple[str, ...]]
    prompts: tuple[Prompt, ...] = ()
    titles: Mapping[str, str] = field(default_factory=dict)
    routes: tuple[Route, ...] = ()
    optin: tuple[str, ...] = ()  # heavy/rare toolsets: only with <ENV>_TOOLSETS=all or by name
    lazy_core: tuple[str, ...] = ()  # entry tools listed at start with <ENV>_TOOL_LOADING=lazy

    @property
    def env(self) -> str:
        return self.service.upper()


def guide_topics(profile: Profile) -> dict[str, str]:
    root = resources.files(profile.package).joinpath("resources", "guide")
    return {
        item.name.removesuffix(".md"): item.read_text(encoding="utf-8")
        for item in sorted(root.iterdir(), key=lambda entry: entry.name)
        if item.name.endswith(".md")
    }


def _split(value: str | None) -> set[str]:
    return {part.strip() for part in (value or "").split(",") if part.strip()}


def selected_tools(
    profile: Profile, names: set[str], read_only_names: set[str], environ: Mapping[str, str] | None = None
) -> set[str]:
    env = os.environ if environ is None else environ
    requested = _split(env.get(f"{profile.env}_TOOLSETS")) or {"default"}
    if "all" in requested:
        requested = set(profile.toolsets)
    elif "default" in requested:
        requested = (requested - {"default"}) | (set(profile.toolsets) - set(profile.optin))
    unknown = requested - set(profile.toolsets)
    if unknown:
        raise ValueError(f"unknown {profile.env}_TOOLSETS: {', '.join(sorted(unknown))}")
    keep = {name for toolset in requested for name in profile.toolsets[toolset]}
    keep |= set(profile.toolsets.get(ALWAYS_ON, ()))
    keep |= _split(env.get(f"{profile.env}_TOOLS"))
    keep -= _split(env.get(f"{profile.env}_DISABLED_TOOLS"))
    if env.get(f"{profile.env}_READ_ONLY", "").strip().lower() in {"1", "true", "yes", "on"}:
        keep &= read_only_names
    return keep & names


def router_instructions(profile: Profile, hint: str | None = None) -> str:
    text = profile.router.strip()
    if hint:
        text = f"{text}\n{hint.strip()}"
    return text


def apply(server: Any, profile: Profile, environ: Mapping[str, str] | None = None) -> set[str]:
    """Rewrite descriptions/titles, filter toolsets and add guide resources and prompts."""
    components = server.local_provider._components  # fastmcp is pinned; no public sync accessor
    tools = {key: tool for key, tool in components.items() if key.startswith("tool:")}
    by_name = {tool.name: key for key, tool in tools.items()}
    read_only = {
        tool.name for tool in tools.values() if tool.annotations is not None and tool.annotations.readOnlyHint
    }
    keep = selected_tools(profile, set(by_name), read_only, environ)
    for name, key in by_name.items():
        if name not in keep:
            del components[key]
            continue
        tool = components[key]
        if name in profile.descriptions:
            tool.description = profile.descriptions[name]
        if not tool.title:
            tool.title = profile.titles.get(name) or _title(profile.service, name)
    lazy_loading.install(server, profile, keep, environ)
    _register_resources(server, profile, keep)
    _register_prompts(server, profile)
    return keep


def _title(service: str, name: str) -> str:
    words = name.removeprefix(f"{service}_").replace("_", " ")
    return f"{service.capitalize()}: {words}"


def toolsets_markdown(profile: Profile, active: set[str]) -> str:
    lines = [
        f"# {profile.service} toolsets",
        f"Select with {profile.env}_TOOLSETS=default|all|<a,b> "
        f"(opt-in: {', '.join(profile.optin) or 'none'}); add tools with {profile.env}_TOOLS; "
        f"drop with {profile.env}_DISABLED_TOOLS; {profile.env}_READ_ONLY=1 removes every write tool; "
        f"{profile.env}_TOOL_LOADING=lazy lists only core tools until {profile.service}_enable_toolsets.",
        "",
    ]
    for toolset, names in profile.toolsets.items():
        on = [name for name in names if name in active]
        lines.append(f"- **{toolset}** ({len(on)}/{len(names)} active): {', '.join(names)}")
    return "\n".join(lines) + "\n"


def tool_map(profile: Profile) -> str:
    """Fuller docs behind the router: every tool by toolset with its description."""
    lines = [
        f"# {profile.service} tool map",
        f"Toolsets marked opt-in need {profile.env}_TOOLSETS=all or by name.",
        "",
    ]
    for toolset, names in profile.toolsets.items():
        lines.append(f"## {toolset}" + (" (opt-in)" if toolset in profile.optin else ""))
        for name in names:
            desc = profile.descriptions.get(name, "")
            lines.append(f"- `{name}`: {desc.split('. ')[0]}" if desc else f"- `{name}`")
        lines.append("")
    if profile.routes:
        lines.append("## Router intents")
        for route in profile.routes:
            tool = route.tool or "-"
            lines.append(f"- {route.intent} -> `{tool}`; skill {route.skill or '-'}; guide {route.topic}")
    return "\n".join(lines) + "\n"


def _register_resources(server: Any, profile: Profile, active: set[str]) -> None:
    topics = guide_topics(profile)
    topics.setdefault("tool-map", tool_map(profile))
    scheme = profile.service

    def reader(text: str) -> Callable[[], str]:
        return lambda: text

    server.resource(f"{scheme}://playbook", name=f"{scheme}_playbook", mime_type="text/markdown")(
        reader(topics.get("playbook", ""))
    )
    toolsets_text = toolsets_markdown(profile, active)
    server.resource(f"{scheme}://toolsets", name=f"{scheme}_toolsets", mime_type="text/markdown")(
        reader(toolsets_text)
    )
    for topic, text in topics.items():
        if topic == "playbook":
            continue
        server.resource(
            f"{scheme}://guide/{topic}", name=f"{scheme}_guide_{topic}", mime_type="text/markdown"
        )(reader(text))

    def guide(topic: str) -> str:
        if topic not in topics:
            return f"Unknown topic. Available: {', '.join(sorted(topics))}"
        return topics[topic]

    server.resource(f"{scheme}://guide/{{topic}}", name=f"{scheme}_guide", mime_type="text/markdown")(guide)


def _register_prompts(server: Any, profile: Profile) -> None:
    for prompt in profile.prompts:
        server.prompt(name=prompt.name, description=prompt.description)(_prompt_fn(prompt))


def _prompt_fn(prompt: Prompt) -> Callable[..., str]:
    def render(**values: str) -> str:
        filled = {name: values.get(name) or f"<{name}>" for name in prompt.arguments}
        return prompt.template.format(**filled)

    render.__name__ = prompt.name
    render.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        [
            inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, default="", annotation=str)
            for name in prompt.arguments
        ]
    )
    render.__annotations__ = {name: str for name in prompt.arguments} | {"return": str}
    return render
