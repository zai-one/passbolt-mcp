from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

from fastmcp import Client
from test_runtime import FixtureAdapter

from zai_passbolt.adapter import PassboltAdapter
from zai_passbolt.agent_layer import DESCRIPTION_LIMIT, INSTRUCTIONS_LIMIT
from zai_passbolt.agent_profile import PROFILE
from zai_passbolt.server import create_server

ROOT = Path(__file__).resolve().parents[1]
TOOLS_LIST_BUDGET = 20_000


async def test_token_budget_and_agent_surface(config):
    async with Client(create_server(config, transport="stdio", adapter=FixtureAdapter())) as client:
        instructions = client.initialize_result.instructions or ""
        assert len(instructions) <= INSTRUCTIONS_LIMIT and "never" in instructions.lower()
        tools = await client.list_tools()
        names = {tool.name for tool in tools}
        assert names <= {n for group in PROFILE.toolsets.values() for n in group}
        assert "passbolt_list_folders" in names
        for tool in tools:
            assert tool.title and len(tool.description or "") <= DESCRIPTION_LIMIT, tool.name
            assert (tool.description or "").isascii()
        assert len(json.dumps([tool.model_dump(exclude_none=True) for tool in tools])) <= TOOLS_LIST_BUDGET
        uris = {str(item.uri) for item in await client.list_resources()}
        assert {"passbolt://playbook", "passbolt://toolsets", "passbolt://guide/security"} <= uris
        assert {p.name for p in await client.list_prompts()} == {"secret_handoff", "access_review"}


async def test_read_only_mode_keeps_metadata_reads_only(config, monkeypatch):
    monkeypatch.setenv("PASSBOLT_READ_ONLY", "1")
    async with Client(create_server(config, transport="stdio", adapter=FixtureAdapter())) as client:
        tools = await client.list_tools()
    assert all(tool.annotations.readOnlyHint for tool in tools)
    assert "passbolt_use_secret" not in {tool.name for tool in tools}


async def test_list_folders_filters_policy_and_never_returns_metadata_blobs():
    async def request(method, path, **kwargs):
        assert (method, path) == ("GET", "/folders.json")
        return {
            "body": [
                {"id": "f1", "name": "Client A", "folder_parent_id": None, "personal": False},
                {"id": "f2", "metadata": "-----BEGIN PGP MESSAGE-----", "folder_parent_id": "f1"},
                {"id": "f3", "name": "Hidden"},
            ]
        }

    async def decrypt(item):
        return {"name": "Sub", "secret_like": "never-returned"}

    fake = SimpleNamespace(_request=request, _decrypt_metadata=decrypt)
    result = await PassboltAdapter.list_folders(fake, allowed_folder_ids=frozenset({"f1", "f2"}))
    assert result["folders"] == [
        {"folder_id": "f1", "name": "Client A", "parent_id": None, "personal": False},
        {"folder_id": "f2", "name": "Sub", "parent_id": "f1", "personal": False},
    ]
    dumped = json.dumps(result)
    assert "PGP" not in dumped and "never-returned" not in dumped and result["secret_disclosed"] is False


def test_static_budget_script_passes():
    sys.path.insert(0, str(ROOT / "scripts"))
    import token_budget

    assert token_budget.problems() == []
