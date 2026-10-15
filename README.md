🇬🇧 English · [🇷🇺 Русский](README.ru.md)

# Passbolt MCP

**Work with your password vault from your AI assistant.**

> MCP server for the Passbolt password manager that lets an AI agent search, organise, share and use vault credentials without passwords ever entering the conversation.

Find the right account, organise vault entries and prepare access for a colleague in the same conversation. Passbolt MCP connects your assistant to your vault and keeps passwords out of MCP responses. When a task needs a secret, the server delivers it to a handler you have configured.

[Quick start](#quick-start) · [Connect your assistant](#connect-your-assistant) · [Issues](https://github.com/zai-one/passbolt-mcp/issues)

Try asking your assistant:

> Find the vault entry for https://example.com. Show its name and username so I can choose the right account.

## What you can do

| Your task | What the MCP server provides |
|---|---|
| Find an account | Search entry metadata and select an entry for a specific URL. Results show the entry type (for example `v5-default` or the Passbolt 5.12 `v5-pin-code`), never its secret. |
| Keep the vault organised | Create and update entries, create folders and manage sharing within your access policy. |
| Use a secret in an automation | Deliver a selected secret to a registered server-side handler, with a status result returned to the assistant. |
| Check a protected endpoint | Use the built-in HTTPS probe with a selected vault credential; receive the outcome without the password or response body. |
| Diagnose setup locally | Check key usability, the server public key and your access policy before connecting to the vault. |

The [protected endpoint walkthrough](docs/SECRET_PROBE.md) includes private configuration, example requests and the local `passbolt-mcp-doctor` command.

## Why this MCP

- Optional lazy tool loading: set `PASSBOLT_TOOL_LOADING=lazy` (or choose it in the setup wizard) to start with a small core and enable toolsets on demand; see [Lazy tool loading](#lazy-tool-loading).
- No tool returns a password: secrets go only to operator-registered sinks (secure fill, file, HTTPS probe) and the assistant receives a status.
- Toolsets (meta, read, use, write); `PASSBOLT_READ_ONLY=1` keeps metadata reads only; sharing follows an access policy.
- Local `passbolt-mcp-doctor` checks keys and policy before connecting; supports Passbolt v5 resource types.
- Other Passbolt MCP on GitHub ([mapix-etnc/passbolt-mcp-server](https://github.com/mapix-etnc/passbolt-mcp-server), AGPL) has no CI; [bitwarden/mcp-server](https://github.com/bitwarden/mcp-server) is the official option for Bitwarden, not Passbolt.

## Lazy tool loading

Optional lazy tool loading: `PASSBOLT_TOOL_LOADING=lazy` starts with a small core plus `passbolt_enable_toolsets` and adds toolsets on demand (`tools/list_changed`). Startup cost (tools/list + instructions, ≈chars/4): eager ≈2448 tokens, lazy ≈1048 tokens (−57%). Default `eager` is unchanged; if your client ignores `tools/list_changed`, keep `eager` or reconnect after enabling. Scope: enablement is per MCP session (FastMCP session visibility), so one client's enabled toolsets never appear for another. The HTTP transport here is stateless (every request is its own session), so enabled toolsets do not persist there: for shared HTTP use `eager` or `PASSBOLT_TOOLSETS`.

Clients and `notifications/tools/list_changed` (verified against official docs, changelogs or maintainer statements, 2026-10):

| Client | `tools/list_changed` | Source |
|---|---|---|
| Claude Code | Supported (interactive: tools, prompts, resources; `-p`/Agent SDK: tools) | [docs: Dynamic tool updates](https://code.claude.com/docs/en/mcp) |
| VS Code (GitHub Copilot) | Supported (dynamic tool discovery); new tools may reach the agent only on the next turn | [docs](https://code.visualstudio.com/api/extension-guides/ai/mcp), [#303012](https://github.com/microsoft/vscode/issues/303012) |
| Gemini CLI | Supported (refreshes the tool registry) | [PR #14375](https://github.com/google-gemini/gemini-cli/pull/14375), [PR #21050](https://github.com/google-gemini/gemini-cli/pull/21050) |
| Cursor | Unreliable: staff confirm a regression in 3.12.x; restart Cursor after enabling | [forum](https://forum.cursor.com/t/mcp-server-regression-does-not-reload-tools-disconnect-does-nothing-ignores-mcp-json-changes-etc/166216) |
| Claude Desktop, Windsurf, Codex CLI, Cline, Zed, Continue | Unverified: no official statement found; use `eager` or reconnect after enabling | — |

## Maintained and up to date

- Actively maintained by ZAI.ONE: current version 0.6.0; release notes in [CHANGELOG.md](CHANGELOG.md) and [Releases](https://github.com/zai-one/passbolt-mcp/releases).
- Built-in update check: ask the assistant to run `passbolt_check_update` (public GitHub API, no credentials, cached; nothing is installed automatically; `PASSBOLT_DISABLE_UPDATE_CHECK=1` turns it off).
- Follows current MCP practice: tool annotations (read-only / destructive hints), toolsets and read-only mode, server `instructions`, prompts and resources, structured errors with recovery hints, secrets kept out of tool output, a token budget for tool descriptions enforced in tests.
- CI runs the test suite on Linux and Windows for every pull request.

## Quick start

Prefer a ready package? [Install the release and generate your client configuration](INSTALL.md#install-a-release-package). No source checkout is required.

Install **Python 3.12–3.14** and [uv](https://docs.astral.sh/uv/getting-started/installation/). Clone with Git or [download the ZIP](https://github.com/zai-one/passbolt-mcp/archive/refs/heads/main.zip). With a ZIP, open the extracted directory and skip the first two commands.

Install GnuPG and prepare a Passbolt service account, its GPG key and passphrase, and the vault access policy. Follow the [Passbolt setup instructions](INSTALL.md#from-a-clone-or-source-zip) before running the commands below. The configuration wizard uses these prepared files; it does not create the account or its keys.

```sh
git clone https://github.com/zai-one/passbolt-mcp.git
cd passbolt-mcp
uv sync --frozen --extra standalone
uv run --frozen --extra standalone python scripts/configure.py
uv run --frozen --extra standalone passbolt-mcp --config mcp.local.json --check-config
```

The wizard creates a local configuration and stores secrets in private files. It refuses to overwrite an existing setup. `--check-config` validates local settings; the first request below checks your account connection.

## Connect your assistant

Add this configuration to an MCP client that uses `mcpServers`, such as Claude Desktop or Cursor. Replace `/ABSOLUTE/PATH/` with your absolute path; Windows JSON paths can use forward slashes, such as `D:/Tools/`.

```json
{
  "mcpServers": {
    "passbolt": {
      "command": "uv",
      "args": [
        "--directory",
        "/ABSOLUTE/PATH/passbolt-mcp",
        "run",
        "--frozen",
        "--extra",
        "standalone",
        "passbolt-mcp",
        "--config",
        "/ABSOLUTE/PATH/passbolt-mcp/mcp.local.json"
      ]
    }
  }
}
```

The client starts the MCP server for you. Refresh its tool list, then make your first request. For clients with a different config format, reuse the same `command` and `args`; `uv` must be available to the client process.

### First request

> Check the Passbolt connection with passbolt_status, then search for an entry I have access to.

A configured vault returns connection/decryption status and matching entry metadata. Passwords are not part of the response. If setup is incomplete, use the status fields to finish the vault configuration.

If tools do not appear, check the absolute path, whether the client can find `uv`, and the `--check-config` result. For access errors, check account credentials and permissions. [Installation and troubleshooting](INSTALL.md).


<!-- agent-block:start -->
## Install in your agent

Run `passbolt-mcp` straight from GitHub with [uv](https://docs.astral.sh/uv/). Pin a release tag (`@vX.Y.Z`) for
reproducible installs; placeholders below are examples, keep secrets in files outside the repo.

**Claude Code**

```bash
claude mcp add passbolt --env PASSBOLT_SECRET_FILE=/path/to/passbolt.env --env PASSBOLT_BINDINGS_FILE=/path/to/bindings.json --env PASSBOLT_STATE_PATH=/path/to/passbolt.sqlite -- uvx --from "zai-passbolt-mcp[standalone] @ git+https://github.com/zai-one/passbolt-mcp@v0.6.0" passbolt-mcp
```

Skills for Claude Code: copy `skills/*` into `~/.claude/skills/` (or install this repo as a plugin — it
ships `.claude-plugin/plugin.json` with the skills and the MCP server).

**Cursor** — `.cursor/mcp.json` ([one-click install](cursor://anysphere.cursor-deeplink/mcp/install?name=passbolt&config=eyJjb21tYW5kIjogInV2eCIsICJhcmdzIjogWyItLWZyb20iLCAiemFpLXBhc3Nib2x0LW1jcFtzdGFuZGFsb25lXSBAIGdpdCtodHRwczovL2dpdGh1Yi5jb20vemFpLW9uZS9wYXNzYm9sdC1tY3BAdjAuNi4wIiwgInBhc3Nib2x0LW1jcCJdLCAiZW52IjogeyJQQVNTQk9MVF9TRUNSRVRfRklMRSI6ICIvcGF0aC90by9wYXNzYm9sdC5lbnYiLCAiUEFTU0JPTFRfQklORElOR1NfRklMRSI6ICIvcGF0aC90by9iaW5kaW5ncy5qc29uIiwgIlBBU1NCT0xUX1NUQVRFX1BBVEgiOiAiL3BhdGgvdG8vcGFzc2JvbHQuc3FsaXRlIn19)):

```json
{
  "mcpServers": {
    "passbolt": {
      "command": "uvx",
      "args": [
        "--from",
        "zai-passbolt-mcp[standalone] @ git+https://github.com/zai-one/passbolt-mcp@v0.6.0",
        "passbolt-mcp"
      ],
      "env": {
        "PASSBOLT_SECRET_FILE": "/path/to/passbolt.env",
        "PASSBOLT_BINDINGS_FILE": "/path/to/bindings.json",
        "PASSBOLT_STATE_PATH": "/path/to/passbolt.sqlite"
      }
    }
  }
}
```

**Codex** — `~/.codex/config.toml` (skills: copy `skills/*` into `~/.codex/skills/`, or keep the
repo's `.agents/skills` link):

```toml
[mcp_servers.passbolt]
command = "uvx"
args = ["--from", "zai-passbolt-mcp[standalone] @ git+https://github.com/zai-one/passbolt-mcp@v0.6.0", "passbolt-mcp"]
env = { PASSBOLT_SECRET_FILE = "/path/to/passbolt.env", PASSBOLT_BINDINGS_FILE = "/path/to/bindings.json", PASSBOLT_STATE_PATH = "/path/to/passbolt.sqlite" }
```

**Claude Desktop** — `claude_desktop_config.json`: the same `mcpServers` block as Cursor.

## Skills (agent playbooks)

Each skill is a self-contained folder `skills/<name>/` (`SKILL.md` + its own `references/`,
`templates/`); copy the folder and it works. Agents load the short `SKILL.md` only when the task matches
and open the other files on demand. Clients without skills get the same flows as MCP prompts and the
`passbolt://playbook` / `passbolt://guide/{topic}` resources.

| Skill | What it does |
|---|---|
| `passbolt-secret-handoff` | Use a credential via a registered sink; the secret never enters the chat. |
| `passbolt-access-review` | Metadata-only review: folders, resources, duplicates, incomplete records. |
| `passbolt-onboard-client` | Folder + resources with server-generated secrets + approval-gated sharing. |

## Toolsets and read-only mode

`PASSBOLT_TOOLSETS=all` (default) or a comma list (see `passbolt://toolsets`); `PASSBOLT_TOOLS=a,b` adds single tools,
`PASSBOLT_DISABLED_TOOLS=a,b` removes them, `PASSBOLT_READ_ONLY=1` removes every write/paid tool.

## Example requests

- Войди в админку example.com с паролем из Passbolt (без показа пароля).
- Какие доступы лежат в папке клиента X?
- Сделай ревизию дублей в Passbolt.
- Заведи клиента Y: папка, доступы к CMS и хостингу, расшарь команде.
- Проверь, что подключение к Passbolt работает.
<!-- agent-block:end -->

## Access and limits

Start with read-only access. Creating or updating entries and delivering secrets require separate permissions and server settings. The handler is configured by the operator; this project does not automatically fill every browser or application login form.

PIN code entries (Passbolt 5.12+) are searchable by name and description, but their PIN is never returned and is not delivered to handlers, because it is not a credential for a URL. Updating a PIN code entry changes only its name and description and keeps it a PIN code entry; the PIN itself is not changed. Updates of other non-password entry types are refused.

New secrets must be generated by the server or supplied through a separately prepared server-side file. This version has no MCP tool for submitting a plaintext password. See [secret handling and approvals](docs/RUNTIME.md).

Authenticated HTTP is available for a server deployment. See [HTTP setup](INSTALL.md#http), [configuration and permissions](docs/RUNTIME.md) and [Python package integration](INSTALL.md#python-package-and-platform-integration).

<details>
<summary>For developers: project checks</summary>

```sh
uv sync --frozen --all-groups --extra standalone
uv run --frozen --extra standalone python scripts/verify.py
uv run --frozen --extra standalone python scripts/verify_install.py
```

Tests use synthetic fixtures. A passing test run does not establish live provider connectivity.

</details>

## Updates

Ask your assistant to run `passbolt_check_update`. It compares the installed version with the
[latest release](https://github.com/zai-one/passbolt-mcp/releases) through the public GitHub API
(no credentials, no vault access, 3-second timeout, result cached for 24 hours next to the state file) and
returns the current and latest versions, the release notes link and the matching update command
(`git pull --ff-only && uv sync --frozen --extra standalone` for a checkout, `uv tool install --force ...` for a release package).
When a newer version is already known from the cache, the server mentions it once in its startup
instructions and in `passbolt_status`. Nothing is ever installed automatically. Offline, the check
reports `status: unknown` and the server keeps working; after a failed request it waits 30 minutes before trying
again, and a forced check runs at most once a minute. Only plain version tags such as `v1.2.3` are accepted.
At startup the server itself makes this anonymous request to `api.github.com` at most once a day, also in HTTP
deployments. Set `PASSBOLT_DISABLE_UPDATE_CHECK=1` to turn it off, for example on servers without outbound internet access.

## Built by ZAI.ONE

[ZAI.ONE](https://zai.one) is a digital agency working on websites, SEO, advertising and analytics. We also build tools that connect AI assistants to everyday work. [Talk to us on Telegram](https://t.me/zai_one) about setup, automation or an integration for your team.

## License, use and contributing

- **Use:** you may install and use this MCP server freely for yourself and your organisation, including commercial work. If it helps, please consider giving the repository a ⭐ — appreciated, never required.
- **Contribute:** [issues](https://github.com/zai-one/passbolt-mcp/issues/new/choose) and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Never post tokens, cookies, sessions or account data.
- **Not allowed without written permission from ZAI.ONE:** copying code into other projects, forking for redistribution, embedding the server in other products or offering it as a competing service.
- License: [LicenseRef-ZAI-ONE 2.0](LICENSE) (source-available, not open source). Third-party notices and license history: [NOTICE](NOTICE).


## Share confirmation and opt-in toolsets

Right before an approved share executes, the server asks the user via MCP elicitation. `PASSBOLT_SHARE_ELICITATION`: `auto` (default) asks only when the client supports elicitation and otherwise relies on operator approval alone; `required` refuses the share if the client cannot ask; `off` skips the prompt. The prompt is one required yes/no field; only accept with the box ticked counts. It is shown for a valid, accepted approval of the exact request, and again when a create-with-share resumes a share that is still pending (the first attempt consumed the approval); operator approval is always required. `PASSBOLT_TOOLSETS=default,directory,organize` adds `passbolt_directory` (UUIDs and display names of the groups/users the binding policy allows as share targets, no emails; per-resource permissions) and, approval-gated, `passbolt_move_resource`, `passbolt_move_folder` and `passbolt_unshare` (removes user/group permissions, never owner permissions; resources are simulated first; permissions are re-read right before the change and the call is refused if a selected permission became owner. Passbolt has no conditional permission update, so a promotion in the short window between that re-read and the change is not caught). Full map: `passbolt://guide/tool-map`.
