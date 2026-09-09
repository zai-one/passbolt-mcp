from __future__ import annotations

import inspect
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from zai_passbolt.adapter import PassboltAccessPolicy, PassboltAdapter
from zai_passbolt.transport import LocalPreDispatchDenied, ProviderError, ProviderHttpError, request_hash


def register_tools(server: Any, runtime: Any) -> None:
    registry, settings, store = runtime.registry, runtime.settings, runtime.store
    current_access, require_scopes = runtime.current_access, runtime.require_scopes
    current_request_id, _provider_read = runtime.current_request_id, runtime.provider_read
    ApprovalRecord = runtime.ApprovalRecord
    PassboltSelectionRecord = runtime.PassboltSelectionRecord
    PassboltAuditRecord = runtime.PassboltAuditRecord

    @server.tool(auth=require_scopes("passbolt:read"))
    async def passbolt_local_diagnostics() -> dict[str, Any]:
        """Check this binding's local key usability and policy, without vault or destination requests."""
        from zai_passbolt.doctor import diagnose

        actor = current_access().principal_id
        label = settings.bindings[actor]
        adapter, policy_label, _ = registry.passbolt_for_binding(label)
        return await diagnose(adapter, policy_label, settings)

    async def _passbolt_audit(
        scope: str,
        action: str,
        outcome: str,
        *,
        resource_id: str | None = None,
        domain_decision: str | None = None,
        sink_ref: str | None = None,
    ) -> None:
        access = current_access()
        safe_resource_id: str | None = None
        if resource_id is not None:
            try:
                safe_resource_id = str(UUID(resource_id))
            except (TypeError, ValueError, AttributeError):
                safe_resource_id = None
        safe_sink_ref = (
            sink_ref
            if isinstance(sink_ref, str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", sink_ref)
            else None
        )
        vault_profile: str | None = None
        binding = await store.provider_binding(access.principal_id, "passbolt")
        if binding is not None:
            try:
                _adapter, _policy_label, vault_profile = registry.passbolt_for_binding(binding)
            except (PermissionError, ProviderError):
                vault_profile = None
        await store.record_passbolt_audit(
            PassboltAuditRecord(
                access.principal_id,
                current_request_id(),
                scope,
                action,
                outcome,
                safe_resource_id,
                domain_decision,
                safe_sink_ref,
                vault_profile,
            )
        )

    def _passbolt_idempotency_key(value: str) -> str:
        key = value.strip()
        if not key or len(key) > 128:
            raise ValueError("Passbolt idempotency_key is required and must be at most 128 characters")
        return key

    async def _passbolt_prepare_approval(operation: str, digest: str) -> str:
        access = current_access()
        approval_id = uuid4()
        await store.create_approval(
            ApprovalRecord(
                approval_id,
                access.principal_id,
                "passbolt",
                operation,
                digest,
                0,
                0,
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
                budget_unlimited=True,
            )
        )
        return str(approval_id)

    async def _passbolt_matching_approval(operation: str, digest: str, approval_id: str) -> UUID:
        access = current_access()
        try:
            identifier = UUID(approval_id)
        except ValueError as exc:
            raise PermissionError("a matching accepted Passbolt approval is required") from exc
        approval = await store.get_approval(identifier)
        if (
            approval is None
            or approval.principal_id != access.principal_id
            or approval.provider != "passbolt"
            or approval.operation != operation
            or approval.request_hash != digest
            or approval.status != "accepted"
            or approval.expires_at <= datetime.now(UTC)
        ):
            raise PermissionError("a matching accepted Passbolt approval is required")
        return identifier

    async def _passbolt_access_policy() -> tuple[
        PassboltAdapter,
        PassboltAccessPolicy,
        frozenset[str] | None,
        frozenset[str] | None,
        str,
    ]:
        access = current_access()
        binding = await store.provider_binding(access.principal_id, "passbolt")
        if binding is None:
            raise PermissionError("Passbolt principal policy is not bound")
        adapter, policy_label, vault_profile = registry.passbolt_for_binding(binding)
        policy = adapter.access_policy(policy_label)
        created_resources = await store.provider_write_applied_ids(
            access.principal_id, "passbolt", "create_resource", "resource_id"
        )
        created_folders = await store.provider_write_applied_ids(
            access.principal_id, "passbolt", "create_folder", "folder_id"
        )
        return (
            adapter,
            policy,
            None if policy.resource_scope == "all" else policy.resource_ids | created_resources,
            None if policy.folder_scope == "all" else policy.folder_ids | created_folders,
            vault_profile,
        )

    def _passbolt_subset(values: list[str] | None, allowed: frozenset[str], label: str) -> None:
        if values is None:
            return
        try:
            normalized = {str(UUID(value)) for value in values}
        except (TypeError, ValueError) as exc:
            raise PermissionError(f"Passbolt {label} policy denied") from exc
        if not normalized <= allowed:
            raise PermissionError(f"Passbolt {label} policy denied")

    async def _passbolt_share_targets(
        adapter: PassboltAdapter,
        policy: PassboltAccessPolicy,
        share_mode: str,
        groups: list[str] | None,
        users: list[str] | None,
        *,
        none_allowed: bool,
    ) -> tuple[list[str] | None, list[str] | None]:
        if share_mode not in {"none", "explicit", "all"}:
            raise ValueError("Passbolt share_mode must be none, explicit or all")
        if share_mode == "none":
            if groups or users or not none_allowed:
                raise ValueError("Passbolt share_mode=none does not accept recipients here")
            return None, None
        if share_mode == "all":
            if groups or users:
                raise ValueError("Passbolt share_mode=all does not accept explicit recipients")
            if not policy.allow_share_all:
                raise PermissionError("Passbolt all-share policy denied")
            return None, await adapter.all_share_user_ids()
        _passbolt_subset(groups, policy.group_ids, "group")
        _passbolt_subset(users, policy.user_ids, "user")
        if not none_allowed and not groups and not users:
            raise ValueError("Passbolt explicit share requires groups or users")
        return groups, users

    def _passbolt_write_checkpoint(operation: str, value: Any) -> dict[str, str] | None:
        shape = {
            "create_resource": ("resource_created", "resource_id"),
            "create_folder": ("folder_created", "folder_id"),
        }.get(operation)
        if shape is None or not isinstance(value, dict):
            return None
        phase, identifier_field = shape
        if value.get("checkpoint") != phase:
            return None
        try:
            identifier = str(UUID(str(value.get(identifier_field))))
        except (TypeError, ValueError):
            return None
        checkpoint = {"checkpoint": phase, identifier_field: identifier}
        state = value.get("state")
        if state in {"in_progress", "resume_ready"}:
            checkpoint["state"] = str(state)
        lease_until = value.get("lease_until")
        if isinstance(lease_until, str):
            checkpoint["lease_until"] = lease_until
        lease_id = value.get("lease_id")
        if isinstance(lease_id, str):
            try:
                checkpoint["lease_id"] = str(UUID(lease_id))
            except ValueError:
                return None
        return checkpoint

    async def _passbolt_write(
        operation: str,
        arguments: dict[str, Any],
        idempotency_key: str,
        factory: Callable[[], Awaitable[dict[str, Any]]],
        *,
        approval_id: str | None = None,
        approval_required: bool = False,
        resumable_factory: Callable[
            [Callable[[dict[str, Any]], Awaitable[None]], dict[str, str] | None],
            Awaitable[dict[str, Any]],
        ]
        | None = None,
        result_validator: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None,
    ) -> dict[str, Any]:
        access = current_access()
        key = _passbolt_idempotency_key(idempotency_key)
        digest = request_hash({"provider": "passbolt", "operation": operation, "arguments": arguments})

        async def execute(
            checkpoint: dict[str, str] | None = None,
            expected_checkpoint: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            checkpoint_state: dict[str, Any] | None = None
            resumed = checkpoint is not None

            if checkpoint is not None:
                staged = {
                    **checkpoint,
                    "state": "in_progress",
                    "lease_id": str(uuid4()),
                    "lease_until": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                }
                if expected_checkpoint is None or not await store.provider_write_claim_checkpoint(
                    access.principal_id,
                    "passbolt",
                    key,
                    digest,
                    expected_checkpoint,
                    staged,
                ):
                    raise ProviderError("Passbolt write is pending reconciliation")
                checkpoint_state = staged

            async def save_checkpoint(value: dict[str, Any]) -> None:
                nonlocal checkpoint_state
                normalized = _passbolt_write_checkpoint(operation, value)
                if normalized is None:
                    raise ProviderError("Passbolt partial-write checkpoint is invalid")
                staged = {
                    **normalized,
                    "state": "in_progress",
                    "lease_id": str(uuid4()),
                    "lease_until": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                }
                if not await store.provider_write_checkpoint(
                    access.principal_id, "passbolt", key, digest, staged
                ):
                    raise ProviderError("Passbolt partial-write checkpoint was not persisted")
                checkpoint_state = staged

            async def release_checkpoint() -> None:
                nonlocal checkpoint_state
                if checkpoint_state is None:
                    return
                ready = {**checkpoint_state, "state": "resume_ready"}
                ready.pop("lease_id", None)
                ready.pop("lease_until", None)
                if await store.provider_write_claim_checkpoint(
                    access.principal_id,
                    "passbolt",
                    key,
                    digest,
                    checkpoint_state,
                    ready,
                ):
                    checkpoint_state = ready

            try:
                call = (
                    (lambda: resumable_factory(save_checkpoint, checkpoint))
                    if resumable_factory is not None
                    else factory
                )
                result = await registry.call(access.principal_id, "passbolt", operation, call)
                if result_validator is not None:
                    validation = result_validator(result)
                    if inspect.isawaitable(validation):
                        await validation
            except LocalPreDispatchDenied:
                if checkpoint_state is not None:
                    await release_checkpoint()
                else:
                    await store.provider_write_settle(
                        access.principal_id,
                        "passbolt",
                        key,
                        status="failed",
                        result={"error": "local_pre_dispatch_denied"},
                    )
                raise
            except ProviderHttpError as exc:
                if checkpoint_state is not None:
                    await release_checkpoint()
                elif exc.status_code < 500 and exc.status_code not in {408, 425, 429}:
                    await store.provider_write_settle(
                        access.principal_id,
                        "passbolt",
                        key,
                        status="failed",
                        result={"error": f"provider_http_{exc.status_code}"},
                    )
                else:
                    await store.provider_write_settle(
                        access.principal_id, "passbolt", key, status="pending", result=None
                    )
                raise
            except Exception:
                # Once Passbolt returned a created identifier, never erase it or
                # permit a fresh create. The same key may resume only the share.
                if checkpoint_state is not None:
                    await release_checkpoint()
                else:
                    await store.provider_write_settle(
                        access.principal_id, "passbolt", key, status="pending", result=None
                    )
                raise
            stored_result = {**result, "idempotent": False}
            if checkpoint_state is not None:
                if not await store.provider_write_settle_checkpoint(
                    access.principal_id,
                    "passbolt",
                    key,
                    digest,
                    checkpoint_state,
                    status="applied",
                    result=stored_result,
                ):
                    raise ProviderError("Passbolt write lease was lost before settlement")
            else:
                await store.provider_write_settle(
                    access.principal_id, "passbolt", key, status="applied", result=stored_result
                )
            return {**stored_result, "idempotent": resumed}

        async def resume_pending(record: dict[str, Any]) -> dict[str, Any]:
            raw_checkpoint = record.get("result")
            checkpoint = _passbolt_write_checkpoint(operation, raw_checkpoint)
            if checkpoint is None or resumable_factory is None:
                raise ProviderError("Passbolt write is pending reconciliation")
            if checkpoint.get("state") == "in_progress":
                try:
                    lease_until = datetime.fromisoformat(checkpoint.get("lease_until", ""))
                except ValueError:
                    lease_until = datetime.max.replace(tzinfo=UTC)
                if lease_until.tzinfo is None:
                    lease_until = datetime.max.replace(tzinfo=UTC)
                if lease_until > datetime.now(UTC):
                    raise ProviderError("Passbolt write is pending reconciliation")
            if not isinstance(raw_checkpoint, dict):
                raise ProviderError("Passbolt write is pending reconciliation")
            return await execute(checkpoint, raw_checkpoint)

        existing = await store.provider_write_lookup(access.principal_id, "passbolt", key)
        if existing is not None:
            if existing.get("request_hash") != digest:
                raise PermissionError("Passbolt idempotency_key belongs to a different write")
            if existing.get("status") == "applied" and isinstance(existing.get("result"), dict):
                return {**existing["result"], "idempotent": True}
            if existing.get("status") == "failed":
                raise ProviderError(
                    "Passbolt write failed definitively; use a new idempotency_key after correction"
                )
            return await resume_pending(existing)
        approval: UUID | None = None
        if approval_required:
            if not approval_id:
                return {
                    "confirmation_required": True,
                    "approval_id": await _passbolt_prepare_approval(operation, digest),
                    "idempotent": False,
                }
            approval = await _passbolt_matching_approval(operation, digest, approval_id)
        is_new, raced = await store.provider_write_reserve(
            access.principal_id,
            "passbolt",
            key,
            tool=operation,
            request_hash=digest,
        )
        if not is_new:
            if raced and raced.get("request_hash") == digest and raced.get("status") == "applied":
                cached_result = raced.get("result")
                return {**cached_result, "idempotent": True} if isinstance(cached_result, dict) else {}
            if raced and raced.get("request_hash") == digest:
                return await resume_pending(raced)
            raise ProviderError("Passbolt write is pending reconciliation")
        if approval is not None and not await store.consume_approval(approval):
            await store.provider_write_settle(
                access.principal_id,
                "passbolt",
                key,
                status="failed",
                result={"error": "approval_state"},
            )
            raise PermissionError("Passbolt approval was already consumed")
        return await execute()

    @server.tool(auth=require_scopes("passbolt:read"))
    async def passbolt_status() -> dict[str, Any]:
        """Probe real Passbolt auth and a bounded v5 decrypt canary without returning secrets."""
        records = await store.provider_records()
        enabled = any(record.name == "passbolt" and record.enabled for record in records)
        if not enabled:
            result = {"provider_enabled": False, "auth_ready": False, "decrypt_ready": False}
            await _passbolt_audit("passbolt:read", "status", "disabled")
            return result
        adapter, _policy, _resources, _folders, _vault_profile = await _passbolt_access_policy()

        async def probe() -> dict[str, Any]:
            value = adapter.status()
            return await value if inspect.isawaitable(value) else value

        try:
            result = await registry.call(current_access().principal_id, "passbolt", "status", probe)
        except Exception:
            await _passbolt_audit("passbolt:read", "status", "error")
            raise
        result["provider_enabled"] = True
        await _passbolt_audit("passbolt:read", "status", "success")
        return result

    @server.tool(auth=require_scopes("passbolt:read"))
    async def passbolt_search(query: str, target_url: str | None = None, limit: int = 20) -> dict[str, Any]:
        """Search only v5 metadata decrypted inside server custody."""
        adapter, policy, resources, _folders, _vault_profile = await _passbolt_access_policy()
        normalized_target = PassboltAdapter.validate_search(query, target_url, limit)[1]
        if normalized_target is not None and not policy.permits_domain(normalized_target):
            raise PermissionError("Passbolt target domain policy denied")
        try:
            result = await _provider_read(
                "passbolt",
                "search",
                {"query": query, "target_url": target_url, "limit": limit},
                lambda: adapter.search(query, target_url, limit, allowed_resource_ids=resources),
                validate=lambda: PassboltAdapter.validate_search(query, target_url, limit),
            )
        except Exception:
            await _passbolt_audit("passbolt:read", "search", "error")
            raise
        await _passbolt_audit("passbolt:read", "search", "success")
        return result

    @server.tool(auth=require_scopes("passbolt:read"))
    async def passbolt_select(target_url: str, query: str = "", limit: int = 10) -> dict[str, Any]:
        """Bind a safe metadata selection to this principal and exact target URL."""
        adapter, policy, resources, _folders, vault_profile = await _passbolt_access_policy()
        normalized_target = PassboltAdapter.validate_select(target_url, query, limit)[0]
        if not policy.permits_domain(normalized_target):
            raise PermissionError("Passbolt target domain policy denied")
        try:
            result = await _provider_read(
                "passbolt",
                "select",
                {"target_url": target_url, "query": query, "limit": limit},
                lambda: adapter.select(target_url, query, limit, allowed_resource_ids=resources),
                validate=lambda: PassboltAdapter.validate_select(target_url, query, limit),
            )
            resource = result.get("resource")
            selection_id: str | None = None
            if isinstance(resource, dict) and resource.get("resource_id"):
                identifier = uuid4()
                await store.create_passbolt_selection(
                    PassboltSelectionRecord(
                        identifier,
                        current_access().principal_id,
                        str(resource["resource_id"]),
                        str(resource.get("uri")) if resource.get("uri") else None,
                        str(resource.get("username")) if resource.get("username") else None,
                        PassboltAdapter.validate_select(target_url, query, limit)[0],
                        bool(result.get("domain_match")),
                        str(result.get("domain_reason") or "host_mismatch"),
                        expires_at=datetime.now(UTC)
                        + timedelta(seconds=settings.passbolt_selection_ttl_seconds),
                        vault_profile=vault_profile,
                    )
                )
                selection_id = str(identifier)
            public = {
                "resource": resource,
                "domain_match": bool(result.get("domain_match")),
                "confirmation_required": bool(result.get("confirmation_required")),
                "selection_id": selection_id,
            }
        except Exception:
            await _passbolt_audit("passbolt:read", "select", "error")
            raise
        await _passbolt_audit(
            "passbolt:read",
            "select",
            "success",
            resource_id=str(resource.get("resource_id")) if isinstance(resource, dict) else None,
            domain_decision="match" if public["domain_match"] else "confirmation_required",
        )
        return public

    @server.tool(auth=require_scopes("passbolt:write"))
    async def passbolt_create_resource(
        name: str,
        uri: str,
        username: str,
        secret_source: dict[str, Any],
        idempotency_key: str,
        description: str | None = None,
        folder: str | None = None,
        share_with_groups: list[str] | None = None,
        share_with_users: list[str] | None = None,
        share_mode: str = "explicit",
        resource_type: str = "v5-default",
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a v5 resource from server-generated or sealed server ingress."""
        if not settings.passbolt_write_enabled:
            await _passbolt_audit("passbolt:write", "create_resource", "disabled")
            raise PermissionError("Passbolt write runtime is not enabled")
        adapter, policy, _resources, folders, _vault_profile = await _passbolt_access_policy()
        if not policy.allow_create_resource or not policy.permits_domain(uri):
            raise PermissionError("Passbolt create resource policy denied")
        if folder is not None:
            try:
                normalized_folder = str(UUID(folder))
            except ValueError as exc:
                raise PermissionError("Passbolt folder policy requires a UUID") from exc
            if folders is not None and normalized_folder not in folders:
                raise PermissionError("Passbolt folder policy denied")
        resolved_groups, resolved_users = await _passbolt_share_targets(
            adapter,
            policy,
            share_mode,
            share_with_groups,
            share_with_users,
            none_allowed=True,
        )
        arguments = {
            "name": name,
            "uri": uri,
            "username": username,
            "secret_source": secret_source,
            "description": description,
            "folder": folder,
            "share_with_groups": resolved_groups,
            "share_with_users": resolved_users,
            "share_mode": share_mode,
            "resource_type": resource_type,
        }

        async def verify_secret_cleanup(value: dict[str, Any]) -> None:
            if secret_source.get("kind") != "sealed_ref" or not value.get("created"):
                return
            resource_id = str(value.get("resource_id")) if value.get("resource_id") else None
            consumed_check = getattr(adapter, "secret_source_consumed", None)
            consumed = consumed_check(secret_source) if callable(consumed_check) else False
            if inspect.isawaitable(consumed):
                consumed = await consumed
            if consumed is not True:
                await _passbolt_audit(
                    "passbolt:write", "sealed_ref_consumed", "error", resource_id=resource_id
                )
                raise ProviderError("Passbolt sealed_ref cleanup was not verified")

        try:
            result = await _passbolt_write(
                "create_resource",
                arguments,
                idempotency_key,
                lambda: adapter.create_resource(
                    name=name,
                    uri=uri,
                    username=username,
                    secret_source=secret_source,
                    description=description,
                    folder=folder,
                    share_with_groups=resolved_groups,
                    share_with_users=resolved_users,
                    resource_type=resource_type,
                ),
                approval_id=approval_id,
                approval_required=bool(resolved_groups or resolved_users),
                result_validator=verify_secret_cleanup,
                resumable_factory=(
                    (
                        lambda checkpoint, saved: adapter.create_resource(
                            name=name,
                            uri=uri,
                            username=username,
                            secret_source=secret_source,
                            description=description,
                            folder=folder,
                            share_with_groups=resolved_groups,
                            share_with_users=resolved_users,
                            resource_type=resource_type,
                            checkpoint=checkpoint,
                            resume_resource_id=saved.get("resource_id") if saved else None,
                        )
                    )
                    if resolved_groups or resolved_users
                    else None
                ),
            )
        except Exception:
            await _passbolt_audit("passbolt:write", "create_resource", "error")
            raise
        resource_id = str(result.get("resource_id")) if result.get("resource_id") else None
        sealed_consumed = secret_source.get("kind") == "sealed_ref" and bool(result.get("created"))
        await _passbolt_audit(
            "passbolt:write",
            "create_resource" if result.get("created") else "create_resource_prepare",
            "success" if result.get("created") else "prepared",
            resource_id=resource_id,
        )
        if sealed_consumed:
            await _passbolt_audit("passbolt:write", "sealed_ref_consumed", "success", resource_id=resource_id)
        return result

    @server.tool(auth=require_scopes("passbolt:write"))
    async def passbolt_update_resource(
        resource_id: str,
        fields: dict[str, Any],
        expected_modified: str,
        idempotency_key: str,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Approval-gated v5 resource update with optimistic concurrency."""
        if not settings.passbolt_write_enabled:
            await _passbolt_audit("passbolt:write", "update_resource", "disabled", resource_id=resource_id)
            raise PermissionError("Passbolt write runtime is not enabled")
        adapter, _policy, resources, _folders, _vault_profile = await _passbolt_access_policy()
        if resources is not None and resource_id not in resources:
            raise PermissionError("Passbolt resource policy denied")
        arguments = {
            "resource_id": resource_id,
            "fields": fields,
            "expected_modified": expected_modified,
        }
        try:
            result = await _passbolt_write(
                "update_resource",
                arguments,
                idempotency_key,
                lambda: adapter.update_resource(
                    resource_id=resource_id,
                    fields=fields,
                    expected_modified=expected_modified,
                ),
                approval_id=approval_id,
                approval_required=True,
            )
        except Exception:
            await _passbolt_audit("passbolt:write", "update_resource", "error", resource_id=resource_id)
            raise
        await _passbolt_audit(
            "passbolt:write",
            "update_resource" if result.get("updated") else "update_resource_prepare",
            "success" if result.get("updated") else "prepared",
            resource_id=resource_id,
        )
        return result

    @server.tool(auth=require_scopes("passbolt:write"))
    async def passbolt_create_folder(
        name: str,
        idempotency_key: str,
        parent: str | None = None,
        share_with_groups: list[str] | None = None,
        share_with_users: list[str] | None = None,
        share_mode: str = "explicit",
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Create one folder idempotently; group refs are UUID-only."""
        if not settings.passbolt_write_enabled:
            await _passbolt_audit("passbolt:write", "create_folder", "disabled")
            raise PermissionError("Passbolt write runtime is not enabled")
        adapter, policy, _resources, folders, _vault_profile = await _passbolt_access_policy()
        if not policy.allow_create_folder:
            raise PermissionError("Passbolt create folder policy denied")
        if parent is not None:
            try:
                normalized_parent = str(UUID(parent))
            except ValueError as exc:
                raise PermissionError("Passbolt parent folder policy requires a UUID") from exc
            if folders is not None and normalized_parent not in folders:
                raise PermissionError("Passbolt parent folder policy denied")
        resolved_groups, resolved_users = await _passbolt_share_targets(
            adapter,
            policy,
            share_mode,
            share_with_groups,
            share_with_users,
            none_allowed=True,
        )
        arguments = {
            "name": name,
            "parent": parent,
            "share_with_groups": resolved_groups,
            "share_with_users": resolved_users,
            "share_mode": share_mode,
        }
        try:
            result = await _passbolt_write(
                "create_folder",
                arguments,
                idempotency_key,
                lambda: adapter.create_folder(
                    name=name,
                    parent=parent,
                    share_with_groups=resolved_groups,
                    share_with_users=resolved_users,
                ),
                approval_id=approval_id,
                approval_required=bool(resolved_groups or resolved_users),
                resumable_factory=(
                    (
                        lambda checkpoint, saved: adapter.create_folder(
                            name=name,
                            parent=parent,
                            share_with_groups=resolved_groups,
                            share_with_users=resolved_users,
                            checkpoint=checkpoint,
                            resume_folder_id=saved.get("folder_id") if saved else None,
                        )
                    )
                    if resolved_groups or resolved_users
                    else None
                ),
            )
        except Exception:
            await _passbolt_audit("passbolt:write", "create_folder", "error")
            raise
        await _passbolt_audit(
            "passbolt:write",
            "create_folder" if result.get("folder_id") else "create_folder_prepare",
            "success" if result.get("folder_id") else "prepared",
        )
        return result

    @server.tool(auth=require_scopes("passbolt:write"))
    async def passbolt_share_resource(
        resource_id: str,
        permission: str,
        idempotency_key: str,
        groups: list[str] | None = None,
        users: list[str] | None = None,
        share_mode: str = "explicit",
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Approval-gated share; group/user references are UUID-only."""
        if not settings.passbolt_write_enabled:
            await _passbolt_audit("passbolt:write", "share_resource", "disabled", resource_id=resource_id)
            raise PermissionError("Passbolt write runtime is not enabled")
        adapter, policy, resources, _folders, _vault_profile = await _passbolt_access_policy()
        if resources is not None and resource_id not in resources:
            raise PermissionError("Passbolt resource policy denied")
        resolved_groups, resolved_users = await _passbolt_share_targets(
            adapter,
            policy,
            share_mode,
            groups,
            users,
            none_allowed=False,
        )
        arguments = {
            "resource_id": resource_id,
            "groups": resolved_groups,
            "users": resolved_users,
            "permission": permission,
            "share_mode": share_mode,
        }
        try:
            result = await _passbolt_write(
                "share_resource",
                arguments,
                idempotency_key,
                lambda: adapter.share_resource(
                    resource_id=resource_id,
                    groups=resolved_groups,
                    users=resolved_users,
                    permission=permission,
                ),
                approval_id=approval_id,
                approval_required=True,
            )
        except Exception:
            await _passbolt_audit("passbolt:write", "share_resource", "error", resource_id=resource_id)
            raise
        await _passbolt_audit(
            "passbolt:write",
            "share_resource" if result.get("shared") else "share_resource_prepare",
            "success" if result.get("shared") else "prepared",
            resource_id=resource_id,
        )
        return result

    @server.tool(auth=require_scopes("passbolt:use"))
    async def passbolt_use_secret(
        selection_id: str,
        sink_ref: str,
        target_url: str | None = None,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Deliver a selected secret to one registered server-local sink only."""
        if not settings.passbolt_use_enabled:
            await _passbolt_audit("passbolt:use", "use_secret", "disabled", sink_ref=sink_ref)
            raise PermissionError("Passbolt secret-use runtime is not enabled")
        access = current_access()
        adapter, policy, resources, _folders, vault_profile = await _passbolt_access_policy()
        if sink_ref not in policy.sink_refs:
            await _passbolt_audit("passbolt:use", "use_secret", "sink_policy_denied")
            raise PermissionError("Passbolt sink policy denied")
        try:
            identifier = UUID(selection_id)
        except ValueError as exc:
            await _passbolt_audit("passbolt:use", "use_secret", "invalid_selection")
            raise PermissionError("Passbolt selection is invalid") from exc
        selection = await store.get_passbolt_selection(identifier, access.principal_id)
        if selection is None or selection.status != "prepared" or selection.expires_at <= datetime.now(UTC):
            await _passbolt_audit("passbolt:use", "use_secret", "invalid_selection")
            raise PermissionError("Passbolt selection is missing, expired or already used")
        if selection.vault_profile != vault_profile:
            await _passbolt_audit(
                "passbolt:use", "use_secret", "vault_profile_mismatch", resource_id=selection.resource_id
            )
            raise PermissionError("Passbolt selection belongs to another vault profile")
        if resources is not None and selection.resource_id not in resources:
            await _passbolt_audit(
                "passbolt:use", "use_secret", "resource_policy_denied", resource_id=selection.resource_id
            )
            raise PermissionError("Passbolt resource policy denied")
        effective_target = target_url or selection.target_url
        normalized_target = PassboltAdapter.validate_select(effective_target, "", 1)[0]
        if not policy.permits_domain(normalized_target):
            await _passbolt_audit(
                "passbolt:use",
                "use_secret",
                "domain_policy_denied",
                resource_id=selection.resource_id,
                sink_ref=sink_ref,
            )
            raise PermissionError("Passbolt target domain policy denied")
        if normalized_target != selection.target_url:
            await _passbolt_audit(
                "passbolt:use",
                "use_secret",
                "target_binding_mismatch",
                resource_id=selection.resource_id,
                sink_ref=sink_ref,
            )
            raise PermissionError("Passbolt target_url does not match the bound selection")
        decision = adapter.domain_decision(selection.resource_uri, normalized_target)
        digest = request_hash(
            {
                "provider": "passbolt",
                "operation": "use_secret",
                "selection_id": selection_id,
                "resource_id": selection.resource_id,
                "target_url": normalized_target,
                "sink_ref": sink_ref,
            }
        )
        if not decision.matches:
            if not approval_id:
                result = {
                    "delivered_to_sink": False,
                    "confirmation_required": True,
                    "approval_id": await _passbolt_prepare_approval("use_secret", digest),
                }
                await _passbolt_audit(
                    "passbolt:use",
                    "use_secret_prepare",
                    "prepared",
                    resource_id=selection.resource_id,
                    domain_decision="confirmation_required",
                    sink_ref=sink_ref,
                )
                return result
            approval = await _passbolt_matching_approval("use_secret", digest, approval_id)
            if not await store.consume_approval(approval):
                raise PermissionError("Passbolt approval was already consumed")
        if not await store.consume_passbolt_selection(identifier, access.principal_id):
            await _passbolt_audit(
                "passbolt:use",
                "use_secret",
                "invalid_selection",
                resource_id=selection.resource_id,
                sink_ref=sink_ref,
            )
            raise PermissionError("Passbolt selection was already used")

        async def deliver() -> dict[str, Any]:
            return await adapter.use_secret(
                resource_id=selection.resource_id,
                sink_ref=sink_ref,
                target_url=normalized_target,
                username=selection.username,
            )

        try:
            result = await registry.call(
                access.principal_id,
                "passbolt",
                "use_secret",
                deliver,
            )
        except Exception:
            await _passbolt_audit(
                "passbolt:use",
                "use_secret",
                "error",
                resource_id=selection.resource_id,
                domain_decision="match" if decision.matches else "mismatch_confirmed",
                sink_ref=sink_ref,
            )
            raise
        await _passbolt_audit(
            "passbolt:use",
            "use_secret",
            "delivered",
            resource_id=selection.resource_id,
            domain_decision="match" if decision.matches else "mismatch_confirmed",
            sink_ref=sink_ref,
        )
        return {"delivered_to_sink": bool(result.get("delivered_to_sink"))}
