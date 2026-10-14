"""Passbolt agent profile: router, compact descriptions, toolsets and prompts.

Invariant: no tool returns a password, TOTP seed or secret note to the conversation.
"""

from __future__ import annotations

from zai_passbolt.agent_layer import Profile, Prompt, Route, build_router

ROUTES = (
    Route("login", "войти, залогиниться, пароль, доступ к сайту, login, sign in, password",
          "passbolt_use_secret", "passbolt-secret-handoff", "sinks"),
    Route("find", "найти учётку, креды, поиск, find, search, credential", "passbolt_search",
          "passbolt-secret-handoff", "security"),
    Route("review", "аудит, ревизия, папки, кто видит, права, review, audit, folders",
          "passbolt_list_folders", "passbolt-access-review", "security"),
    Route("onboard", "новый клиент, создать запись, папку, onboard, create, new", "passbolt_create_resource",
          "passbolt-onboard-client", "playbook"),
    Route("share", "поделиться, расшарить, выдать доступ, share, grant, группы", "passbolt_share_resource",
          "", "security"),
    Route("status", "статус, проверка, ключ, ошибка, setup, status, error", "passbolt_status", "", "errors"),
)  # fmt: skip

ROUTER = build_router(
    "passbolt",
    "Passbolt MCP: use vault credentials WITHOUT seeing them; no tool returns passwords. "
    "Secrets go only to registered sinks: "
    "search -> select(target_url) -> use_secret(selection_id, sink_ref).",
    ROUTES,
    "Update/share: first call returns approval_id; operator accepts outside MCP (never yourself); repeat "
    "with approval_id; shares also ask the user via elicitation. Never ask to paste a password.",
)

DESCRIPTIONS = {
    "passbolt_move_resource": "Move one resource into a folder or to root (approval-gated). First call "
    "returns approval_id; operator accepts outside MCP. Permissions are not changed; share separately.",
    "passbolt_move_folder": "Move one folder under another or to root (approval-gated). First call "
    "returns approval_id; operator accepts outside MCP.",
    "passbolt_unshare": "Remove user/group access to a resource or folder; owners are kept "
    "(approval-gated). First call returns approval_id; operator accepts outside MCP.",
    "passbolt_directory": "List group/user UUIDs for sharing, or who can access one resource. Use before "
    "share or in access reviews. Metadata only; no emails, never secrets.",
    "passbolt_local_diagnostics": "Check local key usability and binding policy. Use when setup fails; "
    "vault auth via `passbolt_status`. Cost: no vault call; never returns secrets.",
    "passbolt_status": "Probe Passbolt auth and a v5 decrypt canary. Use before first real task. "
    "Returns booleans only; never secrets.",
    "passbolt_search": "Search resource metadata (name, URI, username) within policy. Use to find a "
    "credential; then `passbolt_select`. Never returns passwords.",
    "passbolt_list_folders": "List folder metadata (id, name, parent, personal) within policy. Use for "
    "access reviews and before create/share. Never returns secrets.",
    "passbolt_select": "Bind one matching resource to this principal and exact target URL; returns "
    "selection_id. Use before `passbolt_use_secret`. Metadata only.",
    "passbolt_use_secret": "Deliver a selected secret to one registered sink (secure_fill/out_file/"
    "https_probe). Use to log in or hand off; the secret never enters the chat. Requires passbolt:use.",
    "passbolt_create_resource": "Create a v5 resource with a server_generated or sealed_ref secret (no "
    "plaintext input). Use for onboarding. Writes: idempotent, within policy.",
    "passbolt_update_resource": "Update a resource (approval-gated, optimistic concurrency). First call "
    "returns approval_id; repeat after operator acceptance. Writes: overwrites.",
    "passbolt_create_folder": "Create one folder idempotently; group refs are UUIDs. Use for client "
    "onboarding. Writes: within folder policy.",
    "passbolt_share_resource": "Share a resource with groups/users (approval-gated; UUID refs). First call "
    "returns approval_id; operator accepts outside MCP. Writes: grants access.",
    "passbolt_check_update": "Check for a newer server release; never installs or contacts the vault.",
}

TOOLSETS = {
    "meta": ("passbolt_check_update", "passbolt_status", "passbolt_local_diagnostics"),
    "read": ("passbolt_search", "passbolt_list_folders", "passbolt_select"),
    "use": ("passbolt_use_secret",),
    "write": (
        "passbolt_create_resource",
        "passbolt_update_resource",
        "passbolt_create_folder",
        "passbolt_share_resource",
    ),
    "directory": ("passbolt_directory",),
    "organize": ("passbolt_move_resource", "passbolt_move_folder", "passbolt_unshare"),
}
OPTIN = ("directory", "organize")

PROMPTS = (
    Prompt(
        "secret_handoff",
        "Use a vault credential for a site without exposing it (sink delivery).",
        ("target_url", "sink_ref"),
        "I need to sign in to {target_url}. Follow skill passbolt-secret-handoff: passbolt_search, "
        "passbolt_select(target_url), then passbolt_use_secret to sink {sink_ref}. Never show the secret.",
    ),
    Prompt(
        "access_review",
        "Review folders and credentials visible to this binding (metadata only).",
        ("scope",),
        "Run a Passbolt access review for {scope} following skill passbolt-access-review. Metadata only; "
        "report folders, resources per folder, duplicates and stale items.",
    ),
)

PROFILE = Profile(
    service="passbolt",
    package="zai_passbolt",
    router=ROUTER,
    descriptions=DESCRIPTIONS,
    toolsets=TOOLSETS,
    prompts=PROMPTS,
    routes=ROUTES,
    optin=OPTIN,
    lazy_core=("passbolt_search",),
)
