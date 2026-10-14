# Project development guidance

- Python 3.12+; secret custody, selection and registered sinks.
- Never return secret plaintext; preserve scopes, vault/folder policy, approvals and durable writes.
- Checks: `uv run python scripts/verify.py`; `python scripts/check_engineering.py --check`. Run install checks before release.

Read only the task-relevant public documentation. Personal workspace notes are optional and remain outside Git.

- [README](../../README.md): supported features and installation.
- [Contributing](../../CONTRIBUTING.md): development and release checks.

Agent usage playbooks live in `skills/` and MCP `passbolt://playbook` / `passbolt://guide/{topic}`. Keep topic copies and installed resources consistent; run token-budget and clean-install checks before releases.
