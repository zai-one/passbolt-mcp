---
name: passbolt-secret-handoff
description: Use a Passbolt credential without exposing it - search metadata, select for the exact URL, deliver to a registered sink, confirm, clean up. Use for "войди с паролем из Passbolt", "use vault credential", "передай доступ скрипту".
license: LicenseRef-ZAI-ONE
compatibility: Requires passbolt-mcp with passbolt:use scope and at least one sink registered by the operator.
metadata:
  service: passbolt
---
# Secret handoff (never in chat)

Read [references/security.md](references/security.md) and [references/sinks.md](references/sinks.md).

## Steps
1. Confirm the exact target URL and which sink fits (ask the user if several `sink_ref`s exist).
2. `passbolt_search(query, target_url)` → pick the resource by name/username (metadata only).
3. `passbolt_select(target_url, query)` → `selection_id`.
4. `passbolt_use_secret(selection_id, sink_ref, target_url)` → report only the delivery status.
5. Let the consumer (autofill / script) do its job; for `out_file` remind that the consumer deletes the
   spool file. Never open or print it.
6. Summarise: which resource (name), which sink, success/failure. No secret material.

## Guardrails
- If no sink fits: stop and ask the operator to register one; never offer to show the password.
- Errors: [references/errors.md](references/errors.md).
