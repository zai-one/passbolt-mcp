# Readiness diagnostics and embedded operation

`passbolt_status` retains its three-boolean contract. A ready result requires
successful authentication and a real bounded metadata/secret decrypt canary.
An empty vault does not prove decryption readiness. The probe stops at its
selected canary; it does not scan for a resource that hides an earlier failure.

Failures log `provider=passbolt`, `operation=status`, the existing `error_code`,
and closed-vocabulary `probe_stage` / `probe_reason`. Only these codes are logged:
no exception object, traceback, resource identifier, fingerprint, ciphertext or
plaintext. Codes are defined in `zai_passbolt.readiness`. Embedders must preserve
these allowlisted fields in their formatter. Never log an exception to obtain
more detail. Concurrent probes and cancellation have separate trace lifetimes.

Examples:

| Stage / reason | What the operator can conclude |
|---|---|
| `canary_select / no_resources` | No control resource was available; not proof of missing keys |
| `metadata_key_trust / domain_mismatch` | The private-key envelope domain does not match the configured vault |
| `metadata_key_trust / fingerprint_not_pinned` | The envelope's fingerprint is outside the operator pin set |
| `metadata_key_select / metadata_private_keys_unavailable` | No usable shared private metadata keys were loaded |
| `metadata_decrypt / gpg_operation_failed` | GPG failed at metadata decryption; this alone does not identify why |
| `secret_fetch / secret_payload_missing` | The secret endpoint did not return a usable encrypted payload |
| `secret_decrypt / gpg_operation_failed` | GPG failed while decrypting the selected secret |

Do not disable domain, fingerprint, permissions or approval checks to make
readiness green. Investigate the indicated stage within server custody. A generic
GPG error deliberately does not claim that the passphrase is wrong.

## Composition and password operations

Independent source repositories do not require separate services or containers.
A host can embed an exact version of this package and inject its authorization,
scope, policy, approvals, selection store, audit and admission implementations.
Standalone runtime state must not replace the host's state during embedding.

For task-driven authentication, select safe metadata, then deliver the secret
through `passbolt_use_secret` to an operator-registered handler with an exact
target origin and principal-bound selection. The handler obtains the password
inside custody; the model receives only a delivery result. `secure_fill` is a
handler protocol, not proof that a browser login implementation is registered or
that a site authenticated successfully. MFA and site-specific login flows require
their own supported handling and result verification.

Updating a vault password uses `passbolt_update_resource` with
`fields.secret_source`, `expected_modified`, an idempotency key and the matching
accepted approval. Secret sources are server-generated values or server-issued
opaque sealed references. This operation updates the Passbolt record; it does not
change a password on the destination website. A destination rotation requires a
separate workflow that handles partial success and verifies both states.

`decrypt_ready=false` is a readiness result, not a universal tool-disable flag.
Each operation retains its server-side authorization, crypto and delivery gates.
Offline test success does not establish readiness of a deployed vault or browser
handler.
