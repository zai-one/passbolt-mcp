"""Share elicitation through a real MCP client: the prompt is extra consent, never operator approval."""

from __future__ import annotations

import pytest
from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError
from test_runtime import RESOURCE, FixtureAdapter

from zai_passbolt.runtime import Runtime
from zai_passbolt.server import create_server

SHARE = "passbolt_share_resource"
ARGS = {"resource_id": RESOURCE, "permission": "read", "idempotency_key": "e2e-1", "users": [RESOURCE]}


async def _accept_out_of_band(config, approval_id: str) -> None:
    operator = Runtime(config, "stdio")
    record = await operator.store.get_approval(approval_id)
    assert operator.store.transition_approval(
        approval_id, status="accepted", actor="alice", digest=record.request_hash
    )


def _handler(action: str, seen: list[str], value: object = True, schemas: list | None = None):
    async def handler(message, response_type, params, context):
        seen.append(message)
        if schemas is not None:
            schemas.append(params.requestedSchema)
        return ElicitResult(action=action, content={"value": value} if action == "accept" else None)

    return handler


async def test_elicitation_accept_cannot_replace_operator_approval(config):
    adapter = FixtureAdapter()
    seen: list[str] = []
    schemas: list[dict] = []
    server = create_server(config, transport="stdio", adapter=adapter)
    async with Client(server, elicitation_handler=_handler("accept", seen, schemas=schemas)) as client:
        prepared = (await client.call_tool(SHARE, ARGS)).data
        assert prepared["confirmation_required"] and not seen and not adapter.calls
        # A client that always answers "accept" still cannot execute an unapproved share.
        with pytest.raises(ToolError):
            await client.call_tool(SHARE, {**ARGS, "approval_id": prepared["approval_id"]})
        assert not seen and not adapter.calls
        await _accept_out_of_band(config, prepared["approval_id"])
        result = (await client.call_tool(SHARE, {**ARGS, "approval_id": prepared["approval_id"]})).data
    assert result["shared"] and result["elicitation"] == "accepted"
    assert len(seen) == 1 and RESOURCE in seen[0]
    assert [kind for kind, _ in adapter.calls] == ["share"]
    # A real, non-empty form: one required boolean confirmation field (empty forms hang some clients).
    [schema] = schemas
    assert schema["properties"]["value"]["type"] == "boolean" and schema["required"] == ["value"]


async def test_elicitation_accept_with_unticked_box_aborts_share(config):
    adapter = FixtureAdapter()
    seen: list[str] = []
    server = create_server(config, transport="stdio", adapter=adapter)
    async with Client(server, elicitation_handler=_handler("accept", seen, value=False)) as client:
        prepared = (await client.call_tool(SHARE, ARGS)).data
        await _accept_out_of_band(config, prepared["approval_id"])
        with pytest.raises(ToolError):
            await client.call_tool(SHARE, {**ARGS, "approval_id": prepared["approval_id"]})
    assert len(seen) == 1 and not adapter.calls


@pytest.mark.parametrize("action", ["decline", "cancel"])
async def test_elicitation_decline_aborts_approved_share(config, action):
    adapter = FixtureAdapter()
    seen: list[str] = []
    server = create_server(config, transport="stdio", adapter=adapter)
    async with Client(server, elicitation_handler=_handler(action, seen)) as client:
        prepared = (await client.call_tool(SHARE, ARGS)).data
        await _accept_out_of_band(config, prepared["approval_id"])
        with pytest.raises(ToolError):
            await client.call_tool(SHARE, {**ARGS, "approval_id": prepared["approval_id"]})
    assert len(seen) == 1 and not adapter.calls
