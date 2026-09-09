import asyncio
from dataclasses import replace
from uuid import uuid4

import pytest

from zai_passbolt.adapter import DomainDecision, PassboltAccessPolicy, PassboltAdapter
from zai_passbolt.errors import SafeToolError
from zai_passbolt.runtime import Runtime, StandaloneHttp
from zai_passbolt.tools import register_tools
from zai_passbolt.transport import ProviderAdmissionDenied, ProviderError, ProviderHttpError

RESOURCE = "11111111-1111-4111-8111-111111111111"
CREATE = dict(
    name="Fixture",
    uri="https://example.com/login",
    username="operator",
    secret_source={"kind": "server_generated"},
    idempotency_key="create-1",
    share_mode="none",
)


class FixtureAdapter:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.match = True
        self.wait = None
        self.entered = asyncio.Event()
        self.checkpoint_failure = False

    def access_policy(self, label):
        return PassboltAccessPolicy(
            resource_ids=frozenset({RESOURCE}),
            folder_ids=frozenset(),
            group_ids=frozenset(),
            user_ids=frozenset({RESOURCE}),
            domain_hosts=frozenset({"example.com", "other.example"}),
            sink_refs=frozenset({"fill"}),
            allow_create_resource=True,
            allow_create_folder=True,
            resource_scope="all",
            folder_scope="all",
        )

    async def status(self):
        return {"auth_ready": True, "decrypt_ready": True}

    async def search(self, *args, **kwargs):
        self.calls.append(("search", args))
        return {
            "resources": [{"resource_id": RESOURCE, "uri": "https://example.com/login"}],
            "secret_disclosed": False,
        }

    async def select(self, *args, **kwargs):
        return {
            "resource": {"resource_id": RESOURCE, "uri": "https://example.com/login", "username": "user"},
            "domain_match": self.match,
            "confirmation_required": not self.match,
        }

    def domain_decision(self, resource, target):
        return DomainDecision(
            self.match, "same_host" if self.match else "host_mismatch", "example.com", "example.com"
        )

    async def create_resource(self, **kwargs):
        PassboltAdapter.validate_secret_source(kwargs["secret_source"])
        self.calls.append(("create", kwargs))
        self.entered.set()
        if self.wait:
            await self.wait.wait()
        if self.fail:
            raise self.fail
        if kwargs.get("checkpoint"):
            await kwargs["checkpoint"]({"checkpoint": "resource_created", "resource_id": RESOURCE})
            if self.checkpoint_failure:
                self.checkpoint_failure = False
                raise ProviderError("sharing interrupted")
        return {"resource_id": RESOURCE, "created": True, "secret_disclosed": False}

    async def update_resource(self, **kwargs):
        self.calls.append(("update", kwargs))
        return {"resource_id": RESOURCE, "updated": True}

    async def share_resource(self, **kwargs):
        self.calls.append(("share", kwargs))
        return {"resource_id": RESOURCE, "shared": True}

    async def create_folder(self, **kwargs):
        self.calls.append(("folder", kwargs))
        return {"folder_id": RESOURCE}

    async def use_secret(self, **kwargs):
        self.calls.append(("use", kwargs))
        if self.fail:
            raise self.fail
        return {"delivered_to_sink": True}

    def secret_source_consumed(self, source):
        return True


class Capture:
    def __init__(self):
        self.functions = {}

    def tool(self, **options):
        def register(function):
            self.functions[function.__name__] = function
            return function

        return register


def harness(config, adapter=None):
    runtime = Runtime(config, "stdio", adapter or FixtureAdapter())
    capture = Capture()
    register_tools(capture, runtime)

    async def call(tool, **args):
        return await runtime.execute(tool, args, lambda: capture.functions[tool](**args))

    return runtime, call


async def approve(runtime, prepared):
    identifier = uuid4() if "approval_id" not in prepared else prepared["approval_id"]
    record = await runtime.store.get_approval(identifier)
    assert record
    assert runtime.store.transition_approval(
        identifier, status="accepted", actor="alice", digest=record.request_hash
    )
    return str(identifier)


async def test_create_replay_restart_hash_ownership_and_no_secret_state(config):
    adapter = FixtureAdapter()
    runtime, call = harness(config, adapter)
    first = await call("passbolt_create_resource", **CREATE)
    assert first["created"] and not first["idempotent"]
    runtime, call = harness(config, adapter)
    assert (await call("passbolt_create_resource", **CREATE))["idempotent"]
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **{**CREATE, "name": "changed"})
    assert len(adapter.calls) == 1
    _, bob = harness(replace(config, principal_id="bob"), adapter)
    assert not (await bob("passbolt_create_resource", **CREATE))["idempotent"]
    raw = config.state_path.read_bytes()
    assert b"Fixture" not in raw and b"server_generated" not in raw


@pytest.mark.parametrize("error", [ProviderError("unknown"), ProviderHttpError(503)])
async def test_unknown_outcome_blocks_same_and_new_keys_after_restart(config, error):
    adapter = FixtureAdapter()
    adapter.fail = error
    _, call = harness(config, adapter)
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **CREATE)
    _, call = harness(config, adapter)
    for key in ["create-1", "create-2"]:
        with pytest.raises(SafeToolError):
            await call("passbolt_create_resource", **{**CREATE, "idempotency_key": key})
    assert len(adapter.calls) == 1


async def test_definitive_failure_requires_new_key(config):
    adapter = FixtureAdapter()
    adapter.fail = ProviderHttpError(400)
    runtime, call = harness(config, adapter)
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **CREATE)
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "create-1")
    assert record["status"] == "failed"
    adapter.fail = None
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **CREATE)
    assert (await call("passbolt_create_resource", **{**CREATE, "idempotency_key": "corrected"}))["created"]


async def test_approval_exact_actor_hash_single_use_and_update(config):
    adapter = FixtureAdapter()
    runtime, call = harness(config, adapter)
    args = dict(
        resource_id=RESOURCE, fields={"name": "changed"}, expected_modified="v1", idempotency_key="u1"
    )
    prepared = await call("passbolt_update_resource", **args)
    assert prepared["confirmation_required"] and not adapter.calls
    record = await runtime.store.get_approval(prepared["approval_id"])
    with pytest.raises(PermissionError):
        runtime.store.transition_approval(
            record.approval_id, status="accepted", actor="bob", digest=record.request_hash
        )
    with pytest.raises(PermissionError):
        runtime.store.transition_approval(
            record.approval_id, status="accepted", actor="alice", digest="wrong"
        )
    approval = await approve(runtime, prepared)
    assert (await call("passbolt_update_resource", **args, approval_id=approval))["updated"]
    assert not await runtime.store.consume_approval(approval)
    with pytest.raises(SafeToolError):
        await call("passbolt_update_resource", **{**args, "idempotency_key": "u2"}, approval_id=approval)
    assert len(adapter.calls) == 1


async def test_checkpoint_resumes_share_without_fresh_create(config):
    adapter = FixtureAdapter()
    adapter.checkpoint_failure = True
    runtime, call = harness(config, adapter)
    args = {**CREATE, "share_mode": "explicit", "share_with_users": [RESOURCE]}
    prepared = await call("passbolt_create_resource", **args)
    approval = await approve(runtime, prepared)
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **args, approval_id=approval)
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "create-1")
    assert record["result"]["resource_id"] == RESOURCE and record["result"]["state"] == "resume_ready"
    _, call = harness(config, adapter)
    result = await call("passbolt_create_resource", **args, approval_id=approval)
    assert result["idempotent"]
    assert adapter.calls[0][1]["resume_resource_id"] is None
    assert adapter.calls[1][1]["resume_resource_id"] == RESOURCE


async def test_selection_bound_actor_target_single_use_and_durable(config):
    adapter = FixtureAdapter()
    _, call = harness(config, adapter)
    chosen = await call("passbolt_select", target_url="https://example.com/login")
    selection = chosen["selection_id"]
    _, bob = harness(replace(config, principal_id="bob"), adapter)
    with pytest.raises(SafeToolError):
        await bob("passbolt_use_secret", selection_id=selection, sink_ref="fill")
    with pytest.raises(SafeToolError):
        await call(
            "passbolt_use_secret", selection_id=selection, sink_ref="fill", target_url="https://other.example"
        )
    _, call = harness(config, adapter)
    assert await call("passbolt_use_secret", selection_id=selection, sink_ref="fill") == {
        "delivered_to_sink": True
    }
    with pytest.raises(SafeToolError):
        await call("passbolt_use_secret", selection_id=selection, sink_ref="fill")
    assert len(adapter.calls) == 1


async def test_mismatched_domain_requires_accepted_approval(config):
    adapter = FixtureAdapter()
    adapter.match = False
    runtime, call = harness(config, adapter)
    chosen = await call("passbolt_select", target_url="https://other.example/login")
    args = dict(selection_id=chosen["selection_id"], sink_ref="fill")
    prepared = await call("passbolt_use_secret", **args)
    assert not prepared["delivered_to_sink"]
    approval = await approve(runtime, prepared)
    assert (await call("passbolt_use_secret", **args, approval_id=approval))["delivered_to_sink"]


async def test_cancelled_create_leaves_pending_and_conservative_lease(config):
    adapter = FixtureAdapter()
    adapter.wait = asyncio.Event()
    runtime, call = harness(config, adapter)
    task = asyncio.create_task(call("passbolt_create_resource", **CREATE))
    await asyncio.wait_for(adapter.entered.wait(), timeout=5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "create-1")
    assert record["status"] == "pending"
    with pytest.raises(ProviderAdmissionDenied):
        runtime.store.begin("next", "bob", "passbolt_status", "hash")


async def test_quota_counts_initial_and_retry_and_is_shared_by_actors(config):
    runtime, _ = harness(replace(config, rate_limit=2))
    runtime.state.set(type("Call", (), {"principal_id": "alice"})())
    http = StandaloneHttp(runtime)
    await http._admit_attempt(1)
    await http._admit_attempt(2)
    runtime, _ = harness(replace(config, rate_limit=2, principal_id="bob"))
    runtime.state.set(type("Call", (), {"principal_id": "bob"})())
    with pytest.raises(ProviderAdmissionDenied):
        await StandaloneHttp(runtime)._admit_attempt(1)


def test_custody_change_cannot_reuse_ledger(config):
    harness(config)
    with pytest.raises(ValueError, match="custody changed"):
        harness(replace(config, bindings={"alice": "different"}))


@pytest.mark.parametrize("args", [dict(rate_limit=11), dict(max_concurrency=2), dict(local_scopes={"admin"})])
def test_policy_cannot_exceed_default_ceiling(config, args):
    with pytest.raises(ValueError):
        replace(config, **args)


async def test_write_use_disabled_and_plaintext_source_rejected(config):
    adapter = FixtureAdapter()
    _, call = harness(replace(config, passbolt_write_enabled=False, passbolt_use_enabled=False), adapter)
    for tool, args in [
        ("passbolt_create_resource", CREATE),
        ("passbolt_use_secret", dict(selection_id=str(uuid4()), sink_ref="fill")),
    ]:
        with pytest.raises(SafeToolError):
            await call(tool, **args)
    assert not adapter.calls
    _, call = harness(config, adapter)
    with pytest.raises(SafeToolError) as error:
        await call(
            "passbolt_create_resource",
            **{**CREATE, "secret_source": {"kind": "plaintext", "value": "do-not-log"}},
        )
    assert "do-not-log" not in str(error.value)
    assert b"do-not-log" not in config.state_path.read_bytes()
