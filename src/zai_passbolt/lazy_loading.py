"""Optional lazy tool loading: start with a small core, enable toolsets at runtime.

<ENV>_TOOL_LOADING=eager (default) keeps every selected tool in tools/list. With
<ENV>_TOOL_LOADING=lazy only the core (meta toolset, router entry tools and
<service>_enable_toolsets) is listed at start; enabling a toolset registers its tools
and sends notifications/tools/list_changed. Only tools that survived the toolset
allowlist, <ENV>_TOOLS/<ENV>_DISABLED_TOOLS and <ENV>_READ_ONLY can be enabled, and
enabled tools keep their own approval/confirm gates.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

import mcp.types
from fastmcp import Context

MODES = ("eager", "lazy")
ENABLE_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}


def loading_mode(profile: Any, environ: Mapping[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    value = (env.get(f"{profile.env}_TOOL_LOADING") or "eager").strip().lower()
    if value not in MODES:
        raise ValueError(f"{profile.env}_TOOL_LOADING must be eager or lazy")
    return value


def enable_tool_name(profile: Any) -> str:
    return f"{profile.service}_enable_toolsets"


def router_line(profile: Any) -> str:
    name = enable_tool_name(profile)
    return f"Lazy tools: {name}() lists toolsets; {name}(toolsets=[...]) adds them."


def fallback_hint(profile: Any) -> str:
    return (
        "If the new tools do not appear, this client ignores tools/list_changed: reconnect the "
        f"MCP server, or set {profile.env}_TOOL_LOADING=eager."
    )


def estimate_tokens(payload: Any) -> int:
    """Rough token estimate (~4 characters per token) of a JSON-serialised MCP object."""
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    return (len(text) + 3) // 4


def tool_tokens(tool: Any) -> int:
    return estimate_tokens(tool.to_mcp_tool().model_dump(mode="json", exclude_none=True))


def _summary(profile: Any, toolset: str, names: list[str]) -> str:
    notes = getattr(profile, "toolset_notes", None) or {}
    if toolset in notes:
        return notes[toolset]
    for name in names:
        text = getattr(profile, "descriptions", {}).get(name, "")
        if text:
            first = text.split(". ")[0].rstrip(".")
            return first if len(first) <= 100 else first[:97] + "..."
    return ", ".join(names)


def install(server: Any, profile: Any, keep: set[str], environ: Mapping[str, str] | None = None) -> set[str]:
    """Defer non-core tools in lazy mode. Returns the names listed at start."""
    if loading_mode(profile, environ) != "lazy":
        return set(keep)
    components = server.local_provider._components  # fastmcp is pinned; no public sync accessor
    by_name = {tool.name: key for key, tool in components.items() if key.startswith("tool:")}
    grouped = {name for names in profile.toolsets.values() for name in names}
    # Core: meta toolset, router entry tools and anything outside every toolset (never stranded).
    core = (
        set(profile.toolsets.get("meta", ())) | set(getattr(profile, "lazy_core", ())) | (keep - grouped)
    ) & keep
    deferred: dict[str, Any] = {}
    for name in sorted(keep - core):
        key = by_name.get(name)
        if key is not None:
            deferred[name] = components.pop(key)
    groups: dict[str, list[str]] = {}
    for toolset, names in profile.toolsets.items():
        members = [name for name in names if name in deferred]
        if members:
            groups[toolset] = members
    enabled: set[str] = set()
    hint = fallback_hint(profile)
    tool_name = enable_tool_name(profile)

    def catalog() -> list[dict[str, Any]]:
        return [
            {
                "toolset": toolset,
                "description": _summary(profile, toolset, names),
                "tools": names,
                "token_cost": sum(tool_tokens(deferred[name]) for name in names),
                "enabled": all(name in enabled for name in names),
            }
            for toolset, names in groups.items()
        ]

    async def enable_toolsets(
        toolsets: list[str] | None = None, ctx: Context | None = None
    ) -> dict[str, Any]:
        requested = [item.strip() for item in (toolsets or []) if item and item.strip()]
        if not requested:
            return {"mode": "lazy", "toolsets": catalog(), "hint": f"Call {tool_name}(toolsets=[...])."}
        if "all" in requested:
            requested = list(groups)
        unknown = sorted(set(requested) - set(groups))
        if unknown:
            return {
                "error": "unknown_toolset",
                "unknown": unknown,
                "available": sorted(groups),
                "note": "Toolsets outside the allowlist or removed by read-only mode cannot be enabled.",
            }
        added: list[str] = []
        for toolset in requested:
            for name in groups[toolset]:
                if name not in enabled:
                    server.add_tool(deferred[name])
                    enabled.add(name)
                    added.append(name)
        if added and ctx is not None:
            await ctx.send_notification(mcp.types.ToolListChangedNotification())
        return {
            "mode": "lazy",
            "enabled": requested,
            "added_tools": added,
            "already_enabled": not added,
            "hint": hint,
        }

    enable_toolsets.__name__ = tool_name
    enable_toolsets.__doc__ = (
        "List toolsets that are not loaded yet (description, tools, token cost), or enable them by "
        "name ('all' enables every one). Enabled tools appear via tools/list_changed."
    )
    server.tool(
        name=tool_name,
        title=f"{profile.service.capitalize()}: enable toolsets",
        annotations=ENABLE_ANNOTATIONS,
    )(enable_toolsets)
    line = router_line(profile)
    server.instructions = f"{server.instructions}\n{line}" if server.instructions else line
    return core | {tool_name}
