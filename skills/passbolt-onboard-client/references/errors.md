# Passbolt errors

| Error | Meaning | Action |
|---|---|---|
| policy denied (resource/folder/domain/sink) | binding policy forbids it | report; operator may change policy |
| required scope missing | token lacks passbolt:read/write/use | operator issues proper scopes |
| secret-use runtime is not enabled | PASSBOLT_USE_ENABLED off | operator decision |
| approval required / not accepted | update/share need operator acceptance | show approval_id; wait |
| selection expired / mismatch | select again with the same target_url | |
| decrypt/auth failure | key or session problem | `passbolt_local_diagnostics`, `passbolt_status` |
