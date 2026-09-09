import asyncio
from dataclasses import replace

import pytest
from test_runtime import RESOURCE, FixtureAdapter, approve, harness

from zai_passbolt.errors import SafeToolError
from zai_passbolt.runtime import StandaloneHttp
from zai_passbolt.transport import ProviderAdmissionDenied


async def test_proven_pre_dispatch_quota_denial_is_retryable_with_new_approval_and_key(config):
    adapter = FixtureAdapter()
    runtime, call = harness(config, adapter)
    sends = []

    async def update(**kwargs):
        await StandaloneHttp(runtime)._admit_attempt(1)
        sends.append(kwargs)
        return {"updated": True, "resource_id": RESOURCE}

    adapter.update_resource = update
    args = dict(resource_id=RESOURCE, fields={"name": "new"}, expected_modified="v1", idempotency_key="u1")
    prepared = await call("passbolt_update_resource", **args)
    approval = await approve(runtime, prepared)
    for _ in range(config.rate_limit):
        runtime.store.admit("alice")
    with pytest.raises(SafeToolError):
        await call("passbolt_update_resource", **args, approval_id=approval)
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "u1")
    assert record["status"] == "failed"
    assert sends == []
    with runtime.store.connect() as db:
        db.execute("UPDATE attempts SET started=0")
    args["idempotency_key"] = "u2"
    prepared = await call("passbolt_update_resource", **args)
    approval = await approve(runtime, prepared)
    assert (await call("passbolt_update_resource", **args, approval_id=approval))["updated"]
    assert len(sends) == 1


@pytest.mark.parametrize("child_task", [False, True])
async def test_later_admission_denial_remains_pending_including_child_task_dispatch(config, child_task):
    adapter = FixtureAdapter()
    runtime, call = harness(replace(config, rate_limit=1), adapter)

    async def update(**kwargs):
        http = StandaloneHttp(runtime)
        if child_task:
            await asyncio.create_task(http._admit_attempt(1))
        else:
            await http._admit_attempt(1)
        await http._admit_attempt(2)
        raise AssertionError("second dispatch must be denied")

    adapter.update_resource = update
    args = dict(resource_id=RESOURCE, fields={"name": "new"}, expected_modified="v1", idempotency_key="u1")
    prepared = await call("passbolt_update_resource", **args)
    approval = await approve(runtime, prepared)
    with pytest.raises(SafeToolError):
        await call("passbolt_update_resource", **args, approval_id=approval)
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "u1")
    assert record["status"] == "pending"


async def test_arbitrary_factory_admission_error_cannot_claim_no_dispatch(config):
    adapter = FixtureAdapter()
    runtime, call = harness(config, adapter)

    async def update(**kwargs):
        raise ProviderAdmissionDenied("not minted at the local HTTP boundary")

    adapter.update_resource = update
    args = dict(resource_id=RESOURCE, fields={"name": "new"}, expected_modified="v1", idempotency_key="u1")
    prepared = await call("passbolt_update_resource", **args)
    approval = await approve(runtime, prepared)
    with pytest.raises(SafeToolError):
        await call("passbolt_update_resource", **args, approval_id=approval)
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "u1")
    assert record["status"] == "pending"
