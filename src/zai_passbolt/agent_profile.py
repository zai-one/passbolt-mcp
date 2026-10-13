"""Passbolt agent profile: router, compact descriptions, toolsets and prompts.

Invariant: no tool returns a password, TOTP seed or secret note to the conversation.
"""

from __future__ import annotations

from zai_passbolt.agent_layer import Profile, Prompt

ROUTER = """Passbolt MCP: use vault credentials WITHOUT seeing them. No tool returns passwords to the chat.
Toolsets: meta, read, use, write (see passbolt://toolsets); PASSBOLT_READ_ONLY=1 keeps metadata reads only.
Secrets go only to operator-registered sinks (secure_fill, out_file, https_probe): \
passbolt_search -> passbolt_select(target_url) -> passbolt_use_secret(selection_id, sink_ref).
Never ask the user to paste a password; never print, log or summarise a secret; new secrets are \
server_generated or sealed_ref.
Update/share are approval-gated: the first call returns approval_id; the operator accepts it outside MCP \
(passbolt-approval CLI); repeat the call with approval_id.
Playbooks: skills passbolt-secret-handoff, passbolt-access-review, passbolt-onboard-client; or \
passbolt://playbook, passbolt://guide/{security,sinks,errors}.
Errors: retry only when retryable; policy denials are final."""

DESCRIPTIONS = {
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
}

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
)
