---
name: passbolt-onboard-client
description: Onboard a client into Passbolt - folder, resources with server-generated secrets, approval-gated sharing with the team group. Use for "заведи клиента в Passbolt", "создай доступы для клиента", "client onboarding vault".
license: LicenseRef-ZAI-ONE
compatibility: Requires passbolt-mcp with passbolt:write; sharing needs operator approval.
metadata:
  service: passbolt
---
# Client onboarding

Rules: [references/security.md](references/security.md).

## Steps
1. Collect: client name, list of services (name, URI, username), team group UUID. No passwords.
2. Draft the plan with [templates/onboarding-plan.md](templates/onboarding-plan.md); get the user's OK.
3. `passbolt_create_folder(name=client)` (idempotent).
4. For each service: `passbolt_create_resource(..., secret_source={"kind": "server_generated"},
   folder=<folder_id>)`. If the service already has a password, the operator prepares a `sealed_ref`.
5. `passbolt_share_resource` per resource → returns `approval_id`. Show the IDs; the operator accepts
   them with `passbolt-approval`; then repeat each call with its `approval_id`.
6. Report created folder/resources (names, IDs) and share status. No secrets.

## Guardrails
- Never accept approvals yourself. Errors: [references/errors.md](references/errors.md).
