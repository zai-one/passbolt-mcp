# Passbolt playbook

Golden rule: **the secret never enters the conversation.** No tool returns passwords, TOTP seeds or
secret notes; the agent only handles metadata and IDs.

1. **Check** — `passbolt_status` (auth + decrypt canary, booleans) or `passbolt_local_diagnostics`.
2. **Find** — `passbolt_search(query, target_url)` → metadata (name, URI, username), within policy.
   Folders: `passbolt_list_folders`.
3. **Select** — `passbolt_select(target_url, query)` binds one resource to you and the exact URL;
   returns `selection_id`.
4. **Use** — `passbolt_use_secret(selection_id, sink_ref, target_url)` delivers the secret to an
   operator-registered sink (see `passbolt://guide/sinks`). The tool answers with delivery status only.
5. **Create** — `passbolt_create_folder`, `passbolt_create_resource(secret_source=server_generated |
   sealed_ref)`; plaintext passwords are not accepted.
6. **Change/share** — `passbolt_update_resource`, `passbolt_share_resource` return `approval_id`
   first; the operator accepts it outside MCP (never accept it yourself); then repeat the same
   call with `approval_id`.

Skills: `passbolt-secret-handoff`, `passbolt-access-review`, `passbolt-onboard-client`.
Security rules: `passbolt://guide/security`.

Sharing: every approved share (`passbolt_share_resource`, create with `share_with_*`) also asks the user
through MCP elicitation when the client supports it (`PASSBOLT_SHARE_ELICITATION=auto|required|off`,
default `auto`: no prompt if the client cannot elicit).
Opt-in `directory` toolset (`PASSBOLT_TOOLSETS=default,directory`): `passbolt_directory` lists the group/user
UUIDs the binding policy allows for sharing or who can access one resource. Opt-in `organize` (all approval-gated): `passbolt_move_resource`
(folder or root; folder policy applies), `passbolt_move_folder`, `passbolt_unshare` (never removes owners).
Guides: `passbolt://guide/security`, `passbolt://guide/sinks`, `passbolt://guide/errors`,
`passbolt://guide/tool-map`. Errors: retry only when retryable; policy denials are final.
