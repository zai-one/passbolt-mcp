# Passbolt MCP maintenance

Independent source. Preserve secret custody, scopes, approvals, selections, policy and durable write checkpoints.
Python scripts and synthetic offline tests only. No real vault APIs or credentials in fixtures.
Follow the ZAI task/verifier/full-skeptic protocol when working in that workspace.

Use Python for scripts. Preserve existing MCP names/schemas and server-owned
authorization, account boundaries, budgets, approvals and unknown-outcome state.
Do not use live provider accounts or credentials in tests. Keep setup local and explicit.
Run scripts/verify.py and scripts/verify_install.py before releases.
Use Issues for requested changes. Preserve LICENSE, NOTICE and third-party licenses.
Never publish operational handoffs, private extraction refs, credentials or runtime state.
Production deployment is a separate action.
When operating in a workspace with a task/verifier protocol, follow that protocol.

## Using this server from an agent

Agent playbooks live in `skills/` (self-contained `SKILL.md` + `references/`/`templates/`), mirrored as MCP
prompts and `passbolt://playbook` / `passbolt://guide/{topic}`. Keep `resources/guide/*.md` and copies inside
skills identical (`scripts/token_budget.py` checks this and all size budgets).
