from zai_passbolt.adapter import PassboltAdapter

G1 = "aaaaaaaa-1111-4111-8111-111111111111"
G2 = "aaaaaaaa-2222-4222-8222-222222222222"
U1 = "bbbbbbbb-1111-4111-8111-111111111111"
U2 = "bbbbbbbb-2222-4222-8222-222222222222"


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
        return [{"id": G1, "name": "Ops", "groups_users": [1, 2]}], [
            {"id": U1, "username": "a@b.c", "profile": {"first_name": "A", "last_name": "B"}}
        ]

    monkeypatch.setattr(adapter, "_directory", fake_directory, raising=False)
    out = await adapter.list_directory(group_ids=frozenset({G1}), user_ids=frozenset({U1}))
    assert out["groups"][0]["members"] == 2 and "a@b.c" not in str(out)


async def test_directory_lists_only_policy_share_targets(monkeypatch):
    """Regression: the directory must not enumerate the whole vault's people beyond the binding."""
    adapter = object.__new__(PassboltAdapter)

    async def fake_directory():
        return [{"id": G1, "name": "Ops"}, {"id": G2, "name": "Finance"}, {"id": "junk", "name": "X"}], [
            {"id": U1.upper(), "profile": {"first_name": "Allowed"}},
            {"id": U2, "profile": {"first_name": "Outsider", "last_name": "CFO"}},
        ]

    monkeypatch.setattr(adapter, "_directory", fake_directory, raising=False)
    out = await adapter.list_directory(group_ids=frozenset({G1}), user_ids=frozenset({U1}))
    assert [g["group_id"] for g in out["groups"]] == [G1]
    assert [u["name"] for u in out["users"]] == ["Allowed"]
    assert "Finance" not in str(out) and "Outsider" not in str(out)
    empty = await adapter.list_directory(group_ids=frozenset(), user_ids=frozenset())
    assert empty == {"groups": [], "users": []}
