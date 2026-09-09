# Check a protected endpoint with a vault credential

Passbolt MCP can use a selected credential to call an operator-configured HTTPS endpoint. The assistant receives `{"delivered_to_sink": true}` only when the configured success status is returned. The password, response headers and response body are not returned to MCP.

Use a read-only endpoint such as your application's protected health check. It must reject an invalid credential: a public endpoint returning 200 proves availability, not authentication. A GET can still have side effects in a poorly designed application; choose the endpoint deliberately.

## 1. Check local keys and policy

After [preparing your service account and private files](../INSTALL.md#from-a-clone-or-source-zip), run:

```sh
passbolt-mcp-doctor --config /absolute/path/mcp.local.json
```

For a source checkout, prefix this command with `uv run --frozen --extra standalone`. Exit 0 means the local checks passed; exit 2 lists `next_steps`. You can also call `passbolt_local_diagnostics` with read permission from your assistant.

The check signs a synthetic marker using a private copy of your keyring, checks the configured server public-key fingerprint and validates the binding's policy. It does not contact Passbolt or a destination, execute an external handler, create a token or return fingerprints, paths or key material. `auth_files_configured` checks that required settings are present, not that a cached token is valid. Use `passbolt_status` separately to check live vault access.

## 2. Register the endpoint privately

In your existing private `PASSBOLT_SINK_CONFIG_FILE`, add this entry to `sinks`:

```json
{
  "protected-health": {
    "kind": "https_probe",
    "url": "https://app.example.com/protected-health",
    "auth": "bearer",
    "timeout_seconds": 10,
    "expected_status": 200
  }
}
```

This is a `sinks` fragment, not the entire policy file. Add `protected-health` to your binding's `sink_refs` and `app.example.com` to its `domain_hosts`, and restrict its resource policy to the intended credential. Enable `PASSBOLT_USE_ENABLED=true` and grant `passbolt:use` alongside `passbolt:read` only to that client. Existing selection, resource, domain and approval checks still apply. The default remains read-only.

For HTTP Basic, set `auth` to `basic` and add a fixed `username` in this private registry. The username is operator-owned, not taken from client arguments. The selected vault password supplies the credential; never paste it into MCP arguments or this example.

## 3. Ask your assistant

> Select the vault entry for https://app.example.com/protected-health with passbolt_select. Show me the entry metadata. Then use that selection with passbolt_use_secret and sink_ref protected-health to check the endpoint.

The target must exactly equal the registered HTTPS URL, including its path. No query string, URL credentials or fragment is accepted. Each selection is consumed before delivery and cannot be replayed, including after a timeout or restart. Investigate an uncertain result before selecting again.

The handler sends at most one GET, waits 1–30 seconds and expects a configured 2xx status. TLS certificate verification is enabled; redirects, proxy environment variables and retries are disabled. It streams headers without consuming the body. Endpoint requests belong to the local handler and are separate from the vault API request quota; the normal secret-use execution lock and selection checks still apply. Custom local process handlers remain available.

Transport behavior uses [HTTPX streaming](https://www.python-httpx.org/async/#streaming-responses) and [certificate verification](https://www.python-httpx.org/advanced/ssl/).

## Русский

### Проверка защищённого адреса с учётными данными из Passbolt

Готовый обработчик `https_probe` выполняет один GET на адрес из приватной серверной политики. Пароль попадает в заголовок авторизации этого запроса. Ассистент получает только `delivered_to_sink: true`, если пришёл ожидаемый HTTP-статус; тело и заголовки ответа ему не передаются.

1. Подготовьте учётную запись, ключи и приватные файлы по [инструкции установки](../INSTALL.md#from-a-clone-or-source-zip). Запустите `passbolt-mcp-doctor --config /absolute/path/mcp.local.json`. Код 0 означает успешные локальные проверки, код 2 — список `next_steps`. В MCP доступен `passbolt_local_diagnostics` с правом чтения.
2. Добавьте показанный выше объект в `sinks` существующего приватного реестра. Разрешите его имя в `sink_refs`, домен в `domain_hosts`, ограничьте ресурсы нужной записью. Отдельно включите `PASSBOLT_USE_ENABLED=true` и право `passbolt:use`. По умолчанию разрешено только чтение.
3. Попросите ассистента выбрать запись через `passbolt_select` для точного адреса, показать метаданные и вызвать `passbolt_use_secret` с полученным `selection_id` и `sink_ref: protected-health`.

Для Basic укажите `auth: basic` и фиксированный `username` в приватном реестре. Для Bearer логин не задаётся. Пароль берётся из выбранной записи; через MCP его вводить не нужно.

Диагностика подписывает тестовую строку приватной копией ключа, проверяет наличие публичного ключа сервера и политику. Она не подключается к vault или назначению и не запускает внешние обработчики. Наличие настроек `auth_files_configured` не доказывает валидность токена. Живое подключение проверяется отдельно через `passbolt_status`.

Выберите защищённый адрес без побочных действий: он должен отклонять неверный пароль. Ответ 200 от публичного адреса не подтверждает авторизацию. HTTPS, точный URL без query/fragment, проверка сертификата, отсутствие редиректов и повторов заданы обработчиком; ожидание ограничено 1–30 секундами. Секретные данные не возвращаются в ответах MCP. Выбор одноразовый даже при ошибке или перезапуске. После неизвестного результата сначала выясните исход операции.

Запрос обработчика не входит в квоту API vault; действуют общая блокировка выполнения и прежние проверки доступа, ресурса, домена и выбора. Внешние обработчики `secure_fill` и `out_file` продолжают работать.
