import json
import sys
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from test_runtime import CREATE, FixtureAdapter

from zai_passbolt.server import create_server


@asynccontextmanager
async def connection(server, token):
    app = server.http_app(path="/mcp", stateless_http=True, json_response=True)

    def factory(**kwargs):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), **kwargs)

    async with (
        app.router.lifespan_context(app),
        Client(
            StreamableHttpTransport("http://fixture/mcp", auth=token, httpx_client_factory=factory)
        ) as client,
    ):
        yield client


async def test_frozen_original_eight_tools_match(config):
    expected = json.loads((Path(__file__).parents[1] / "contracts/tools.json").read_text(encoding="utf-8"))
    async with Client(create_server(config, transport="stdio", adapter=FixtureAdapter())) as client:
        actual = {
            tool.name: dict(
                inputSchema=tool.inputSchema, outputSchema=tool.outputSchema, description=tool.description
            )
            for tool in await client.list_tools()
        }
    assert {name: actual[name] for name in expected} == expected
    assert set(actual) - set(expected) == {"passbolt_local_diagnostics"}


async def test_http_auth_scopes_actor_account_and_selection_ownership(config):
    pair = RSAKeyPair.generate()
    settings = replace(config, public_key=pair.public_key)
    adapter = FixtureAdapter()
    server = create_server(settings, adapter=adapter)

    def token(
        actor="alice", scopes=("passbolt:read", "passbolt:write", "passbolt:use"), account="default", **claims
    ):
        return pair.create_token(
            subject=actor,
            issuer=config.issuer,
            audience=config.audience,
            scopes=list(scopes),
            expires_in_seconds=60,
            additional_claims={"account_id": account, **claims},
        )

    async with connection(server, token(scopes=["passbolt:read"])) as client:
        assert len(await client.list_tools()) == 4
        with pytest.raises(ToolError):
            await client.call_tool("passbolt_create_resource", CREATE)
    for bearer in [token(account="other"), token(actor="unbound")]:
        async with connection(server, bearer) as client:
            with pytest.raises(ToolError):
                await client.call_tool("passbolt_search", {"query": "fixture"})
    async with connection(server, token(passbolt_binding="other", rate_limit=9999)) as client:
        chosen = await client.call_tool("passbolt_select", {"target_url": "https://example.com/login"})
        selection = chosen.data["selection_id"]
    async with connection(server, token(actor="bob")) as client:
        with pytest.raises(ToolError):
            await client.call_tool("passbolt_use_secret", {"selection_id": selection, "sink_ref": "fill"})
    async with connection(server, token()) as client:
        result = await client.call_tool(
            "passbolt_use_secret", {"selection_id": selection, "sink_ref": "fill"}
        )
        assert result.data == {"delivered_to_sink": True}
    assert len(adapter.calls) == 1
    app = server.http_app(path="/mcp", stateless_http=True, json_response=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://fixture") as client:
        response = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert response.status_code in {401, 403}


async def test_real_stdio_discovery_without_vault_network(config, tmp_path):
    bindings = tmp_path / "bindings.json"
    bindings.write_text(json.dumps(dict(config.bindings)), encoding="utf-8")
    bindings.chmod(0o600)
    env = {
        "PASSBOLT_STATE_PATH": str(tmp_path / "stdio.sqlite"),
        "PASSBOLT_SECRET_FILE": str(config.secret_path),
        "PASSBOLT_BINDINGS_FILE": str(bindings),
        "PASSBOLT_LOCAL_PRINCIPAL": "alice",
    }
    async with Client(StdioTransport(command=sys.executable, args=["-m", "zai_passbolt"], env=env)) as client:
        assert len(await client.list_tools()) == 4


def test_http_fails_without_public_key(config):
    with pytest.raises(ValueError, match="public"):
        create_server(config)


async def test_stdio_enforces_local_scope_even_with_writes_enabled(config):
    adapter = FixtureAdapter()
    settings = replace(config, local_scopes=frozenset({"passbolt:read"}))
    async with Client(create_server(settings, transport="stdio", adapter=adapter)) as client:
        assert len(await client.list_tools()) == 4
        with pytest.raises(ToolError):
            await client.call_tool("passbolt_create_resource", CREATE)
    assert not adapter.calls
