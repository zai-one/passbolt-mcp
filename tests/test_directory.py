from zai_passbolt.adapter import PassboltAdapter


async def test_resource_permissions_maps_levels(monkeypatch):
    adapter = object.__new__(PassboltAdapter)

    async def fake_request(method, path, **kw):
        assert path.startswith("/permissions/resource/")
        return {
            "body": [
                {"aro": "Group", "aro_foreign_key": "g", "type": 15},
                {"aro": "User", "aro_foreign_key": "u", "type": 1},
            ]
        }

    monkeypatch.setattr(adapter, "_request", fake_request, raising=False)
    out = await adapter.resource_permissions("6f1d3b8e-1111-4222-8333-444455556666")
    assert [p["permission"] for p in out["permissions"]] == ["owner", "read"]


async def test_directory_hides_emails(monkeypatch):
    adapter = object.__new__(PassboltAdapter)

    async def fake_directory():
        return [{"id": "g", "name": "Ops", "groups_users": [1, 2]}], [
            {"id": "u", "username": "a@b.c", "profile": {"first_name": "A", "last_name": "B"}}
        ]

    monkeypatch.setattr(adapter, "_directory", fake_directory, raising=False)
    out = await adapter.list_directory()
    assert out["groups"][0]["members"] == 2 and "a@b.c" not in str(out)
