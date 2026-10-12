# Changelog

## Unreleased

- Passbolt 5.12 PIN code resources (`v5-pin-code`): their metadata has no `uris`, which previously failed the whole
  search. They are now listed by name and description. The PIN is never returned, and `passbolt_use_secret`
  refuses to deliver it.
- `passbolt_update_resource` keeps the existing resource type and never converts one type into another. It reads the
  type from the resource's `resource_type_id` and refuses the update if the decrypted metadata names a different type.
  `v5-default` updates are unchanged. `v5-pin-code` entries accept only `name` and `description`: the metadata is
  rebuilt in the v5-pin-code shape (name, description, icon kept), the PIN secret is not read, re-encrypted or sent,
  and `uri`, `username` and `secret_source` are refused because the generator produces passwords, not PINs.
  Every other or unknown type (TOTP, custom fields, notes, v4 types) is refused before any write.
- Search and select results carry `resource_type` (the Passbolt slug, or `unknown`) derived from `resource_type_id`.
- Read mode accepts the documented 32 `uris` per v5 resource (writes stay limited to 10).
- `passbolt_check_update`: suggests a newer GitHub release with its notes link and update command;
  public API, 3 s timeout, 24 h cache, graceful offline, never auto-updates and never touches the vault.
  A cached "update available" hint appears in server instructions and `passbolt_status`.
  Opt out with `PASSBOLT_DISABLE_UPDATE_CHECK=1`.
- MCP tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) on every tool.
- Tests assert that passwords, PINs, secure notes and encrypted payloads never appear in search, select or use results.

## 0.3.1

- Add request-local, closed-vocabulary readiness stage/reason logs without exception text or secret material; retain the three-boolean MCP status contract.
- Distinguish metadata key trust checks, metadata decryption, secret fetching and secret decryption without relaxing any trust predicate.
- Test concurrent/cancelled probes, malformed key envelopes, real-GPG diagnostic refusal and approved encrypted password updates with disposable keys.
- Document embedded composition, registered authentication handlers and the distinction between updating a vault record and rotating a website password.

## 0.3.0

- Installable setup wizard and JSON/TOML client snippets that work outside the checkout.
- English and Russian agency information, integration contact and package installation guide.
- Local key/policy diagnostics via `passbolt_local_diagnostics` and `passbolt-mcp-doctor`; signs a synthetic marker and checks the configured server public key without vault requests.
- Built-in `https_probe` secret handler: one fixed HTTPS GET with bearer or basic authentication, verified TLS, no redirects/proxy environment/retries, and no response data returned to MCP.
- Real disposable-key selection/decryption/probe tests, target/scope/owner/replay checks and installed-wheel diagnostics.

## 0.2.0

- Explicit config-file startup and offline configuration doctor.
- Install/client guide, local setup wizard and clean-wheel validation.
- Isolate active GPG keyrings without copying agent sockets; stop the private runtime agent on close. Support MSYS GnuPG paths on Windows.
- Passwords remain in server custody. GnuPG must be installed separately. Real disposable-key crypto tests run in the Linux gate. Secret producer and automatic unknown-write reconciliation are future work.
- LicenseRef-ZAI-ONE and Issues-based feedback policy.
