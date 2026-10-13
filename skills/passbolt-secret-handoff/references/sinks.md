# Sinks (where secrets go instead of the chat)

Sinks are registered by the operator in the sink policy file (`PASSBOLT_SINK_CONFIG_FILE`); the agent
can only pick a `sink_ref` allowed for its binding.

| Kind | What happens | Typical use |
|---|---|---|
| `secure_fill` | runs an operator-configured local command and passes the credential on stdin | browser/CLI autofill |
| `out_file` | writes a short-lived envelope file into a private spool directory | handing off to a local script that reads and deletes it |
| `https_probe` | sends the secret to the configured HTTPS check and returns only pass/fail | verifying a credential still works |

Rules: the agent never reads `out_file` spools back into the chat, never `cat`s or echoes them, and
asks the operator to configure a sink when none fits. After use, the consumer must delete the spool
file (the example consumer in `examples/sinks/` does).
