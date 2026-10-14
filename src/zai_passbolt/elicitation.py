"""MCP elicitation confirmation before any share (resource, folder, create-with-share).

Elicitation is an extra human-in-the-loop gate on top of operator approval; it never replaces it.
Modes (PASSBOLT_SHARE_ELICITATION): ``auto`` (default) asks when the client supports elicitation and
otherwise relies on operator approval; ``required`` refuses the share when the client cannot ask;
``off`` skips the prompt.
"""

from __future__ import annotations

from typing import Any

try:  # pragma: no cover - import guard for older FastMCP
    from fastmcp.server.dependencies import get_context
except Exception:  # pragma: no cover
    get_context = None  # type: ignore[assignment]

MODES = ("auto", "required", "off")


def share_summary(kind: str, target: str, groups: list[str], users: list[str], permission: str) -> str:
    who = []
    if groups:
        who.append(f"{len(groups)} group(s): " + ", ".join(groups[:5]) + (" …" if len(groups) > 5 else ""))
    if users:
        who.append(f"{len(users)} user(s): " + ", ".join(users[:5]) + (" …" if len(users) > 5 else ""))
    return f"Share Passbolt {kind} {target} with {'; '.join(who) or 'nobody'} as '{permission}'. Confirm?"


async def confirm_share(message: str, mode: str = "auto") -> str:
    """Return 'accepted', 'skipped' (off/unsupported in auto); raise PermissionError on decline/cancel."""
    if mode not in MODES:
        raise ValueError("PASSBOLT_SHARE_ELICITATION must be auto, required or off")
    if mode == "off":
        return "skipped"
    ctx = None
    if get_context is not None:
        try:
            ctx = get_context()
        except Exception:
            ctx = None
    supported = False
    if ctx is not None:
        caps = getattr(getattr(getattr(ctx, "session", None), "client_params", None), "capabilities", None)
        supported = getattr(caps, "elicitation", None) is not None
    if not supported:
        if mode == "required":
            raise PermissionError(
                "Passbolt share requires MCP elicitation, but the client does not support it"
            )
        return "skipped"
    try:
        result: Any = await ctx.elicit(message, response_type=None)  # type: ignore[union-attr]
    except Exception as exc:  # fail closed: a broken prompt never counts as consent
        raise PermissionError("Passbolt share confirmation failed; nothing was shared") from exc
    action = getattr(result, "action", None)
    if action == "accept":
        return "accepted"
    raise PermissionError(f"Passbolt share was {action or 'not confirmed'} by the user")
