---
name: passbolt-access-review
description: Metadata-only Passbolt access review - folders, resources per folder, duplicates and incomplete records, with recommendations. Use for "аудит доступов", "ревизия паролей", "access review", "что лежит в Passbolt".
license: LicenseRef-ZAI-ONE
compatibility: Requires passbolt-mcp with passbolt:read; works in PASSBOLT_READ_ONLY mode.
metadata:
  service: passbolt
---
# Access review (metadata only)

Rules: [references/security.md](references/security.md).

## Steps
1. `passbolt_status` (auth ok?).
2. `passbolt_list_folders` → folder tree (parent_id) within policy.
3. `passbolt_search` with broad queries for the scope (client name, domain) — `limit` up to the bound;
   collect name, URI, username, folder.
4. Detect: duplicates (same URI host + username), missing URI/username, resources outside folders.
5. Fill [templates/access-review.md](templates/access-review.md).
6. Group/permission lists are not exposed by this server: recommend checking shares in the Passbolt UI.

## Guardrails
- Never call `passbolt_use_secret` in a review. Errors: [references/errors.md](references/errors.md).
