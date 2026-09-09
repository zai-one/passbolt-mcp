from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID


@dataclass(slots=True)
class ApprovalRecord:
    approval_id: UUID
    principal_id: UUID
    provider: str
    operation: str
    request_hash: str
    estimated_cost: float
    budget_limit: float
    status: str = "prepared"
    expires_at: datetime = field(default_factory=lambda: datetime.now(UTC) + timedelta(minutes=30))
    budget_unlimited: bool = False
    acceptance_type: str | None = None
    acceptance_origin: str | None = None
    standing_policy_id: str | None = None


def validate_approval_acceptance_provenance(
    acceptance_type: str | None,
    acceptance_origin: str | None,
    standing_policy_id: str | None,
    *,
    allow_legacy_null: bool = False,
) -> None:
    """Enforce the only valid approval-acceptance provenance tuples.

    Historical accepted rows predate provenance columns and therefore remain
    readable as an all-NULL tuple. New acceptance transitions must identify
    either an admin-confirmed manual acceptance or a server-minted standing
    policy child.
    """
    if acceptance_type is None and acceptance_origin is None and standing_policy_id is None:
        if allow_legacy_null:
            return
        raise ValueError("new approval acceptance requires typed provenance")
    if acceptance_type == "manual" and acceptance_origin == "admin" and standing_policy_id is None:
        return
    if (
        acceptance_type == "standing_policy_child"
        and acceptance_origin == "server"
        and isinstance(standing_policy_id, str)
        and 1 <= len(standing_policy_id) <= 128
    ):
        return
    raise ValueError("invalid approval acceptance provenance")


@dataclass(slots=True)
class PassboltSelectionRecord:
    selection_id: UUID
    principal_id: UUID
    resource_id: str
    resource_uri: str | None
    username: str | None
    target_url: str
    domain_match: bool
    domain_reason: str
    status: str = "prepared"
    expires_at: datetime = field(default_factory=lambda: datetime.now(UTC) + timedelta(minutes=10))
    vault_profile: str = "default"


@dataclass(frozen=True, slots=True)
class PassboltAuditRecord:
    principal_id: UUID
    request_id: str
    scope: str
    action: str
    outcome: str
    resource_id: str | None = None
    domain_decision: str | None = None
    sink_ref: str | None = None
    vault_profile: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
