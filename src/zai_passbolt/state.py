"""Private SQLite custody for approvals, selections, checkpoints and admission.

No request arguments or secret values are persisted. Account/actor records are
bound to immutable operator profile routing; identity changes require migration.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
from dataclasses import asdict
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

from zai_passbolt.records import ApprovalRecord, PassboltSelectionRecord
from zai_passbolt.transport import ProviderAdmissionDenied, ProviderError, canonical_json


def document(record):
    return json.dumps(asdict(record), default=str, sort_keys=True, separators=(",", ":"))


def restore(kind, raw):
    if raw is None:
        return None
    data = json.loads(raw)
    for key in ("approval_id", "selection_id"):
        if key in data:
            data[key] = UUID(data[key])
    data["expires_at"] = datetime.fromisoformat(data["expires_at"])
    return kind(**data)


class StateStore:
    def __init__(self, config, fingerprint, routes):
        self.config, self.path, self.account = config, config.state_path, config.account_id
        self.routes = dict(routes)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink() or (self.path.exists() and not self.path.is_file()):
            raise ValueError("private regular state database required")
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        if os.name != "nt" and self.path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("owner-private state database required")
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS custody(account TEXT PRIMARY KEY, fingerprint TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS writes(
                    account TEXT, actor TEXT, key TEXT, tool TEXT, digest TEXT, status TEXT, result TEXT,
                    PRIMARY KEY(account,actor,key));
                CREATE INDEX IF NOT EXISTS pending_writes ON writes(account,actor,digest,status);
                CREATE TABLE IF NOT EXISTS approvals(account TEXT, id TEXT, data TEXT,
                    PRIMARY KEY(account,id));
                CREATE TABLE IF NOT EXISTS selections(account TEXT, id TEXT, data TEXT,
                    PRIMARY KEY(account,id));
                CREATE TABLE IF NOT EXISTS audit(
                    account TEXT, execution TEXT, actor TEXT, tool TEXT, digest TEXT,
                    started REAL, outcome TEXT, PRIMARY KEY(account,execution));
                CREATE TABLE IF NOT EXISTS passbolt_audit(account TEXT, data TEXT);
                CREATE TABLE IF NOT EXISTS attempts(account TEXT, vault TEXT, started REAL);
                CREATE INDEX IF NOT EXISTS attempt_window ON attempts(account,vault,started);
                CREATE TABLE IF NOT EXISTS leases(account TEXT, execution TEXT, vault TEXT, expires REAL,
                    PRIMARY KEY(account,execution));
                CREATE TABLE IF NOT EXISTS cooldowns(account TEXT, vault TEXT, until_time REAL,
                    PRIMARY KEY(account,vault));
            """)
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT fingerprint FROM custody WHERE account=?", (self.account,)).fetchone()
            if old and old[0] != fingerprint:
                raise ValueError("state custody changed; explicit operator migration required")
            db.execute("INSERT OR IGNORE INTO custody VALUES(?,?)", (self.account, fingerprint))

    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def vault(self, actor):
        binding = self.config.bindings.get(str(actor))
        if binding not in self.routes:
            raise PermissionError("server-owned vault binding required")
        return self.routes[binding]

    async def provider_binding(self, actor, provider):
        if provider != "passbolt":
            raise PermissionError("unknown provider")
        return self.config.bindings.get(str(actor))

    async def provider_records(self):
        return [SimpleNamespace(name="passbolt", enabled=self.config.enabled)]

    def key(self, actor, provider, key):
        self.vault(actor)
        if provider != "passbolt":
            raise PermissionError("unknown provider")
        return self.account, str(actor), key

    @staticmethod
    def record(row):
        return (
            dict(
                tool=row["tool"],
                request_hash=row["digest"],
                status=row["status"],
                result=json.loads(row["result"]) if row["result"] else None,
            )
            if row
            else None
        )

    async def provider_write_lookup(self, actor, provider, key):
        with self.connect() as db:
            return self.record(
                db.execute(
                    "SELECT * FROM writes WHERE account=? AND actor=? AND key=?",
                    self.key(actor, provider, key),
                ).fetchone()
            )

    async def provider_write_reserve(self, actor, provider, key, *, tool, request_hash):
        identity = self.key(actor, provider, key)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT * FROM writes WHERE account=? AND actor=? AND key=?", identity
            ).fetchone()
            if old:
                return False, self.record(old)
            pending = db.execute(
                "SELECT 1 FROM writes WHERE account=? AND actor=? AND digest=? AND status='pending'",
                (self.account, str(actor), request_hash),
            ).fetchone()
            if pending:
                raise ProviderError("same write is pending reconciliation; do not resubmit")
            db.execute("INSERT INTO writes VALUES(?,?,?,?,?,'pending',NULL)", (*identity, tool, request_hash))
            return True, None

    async def provider_write_settle(self, actor, provider, key, *, status, result):
        if status not in {"pending", "applied", "failed"}:
            raise ValueError("invalid write status")
        with self.connect() as db:
            db.execute(
                "UPDATE writes SET status=?,result=? WHERE account=? AND actor=? AND key=? "
                "AND status='pending'",
                (status, canonical_json(result), *self.key(actor, provider, key)),
            )

    def checkpoint(self, actor, provider, key, digest, expected, result, status="pending", *, compare=True):
        identity = self.key(actor, provider, key)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = self.record(
                db.execute("SELECT * FROM writes WHERE account=? AND actor=? AND key=?", identity).fetchone()
            )
            if (
                not old
                or old["status"] != "pending"
                or old["request_hash"] != digest
                or (compare and old["result"] != expected)
            ):
                return False
            db.execute(
                "UPDATE writes SET status=?,result=? WHERE account=? AND actor=? AND key=?",
                (status, canonical_json(result), *identity),
            )
            return True

    async def provider_write_checkpoint(self, actor, provider, key, digest, result):
        return self.checkpoint(actor, provider, key, digest, None, result, compare=False)

    async def provider_write_claim_checkpoint(self, actor, provider, key, digest, expected, result):
        return self.checkpoint(actor, provider, key, digest, expected, result)

    async def provider_write_settle_checkpoint(
        self, actor, provider, key, digest, expected, *, status, result
    ):
        return self.checkpoint(actor, provider, key, digest, expected, result, status)

    async def provider_write_applied_ids(self, actor, provider, tool, result_field):
        self.key(actor, provider, "")
        with self.connect() as db:
            rows = db.execute(
                "SELECT result FROM writes WHERE account=? AND actor=? AND tool=? AND status='applied'",
                (self.account, str(actor), tool),
            ).fetchall()
        results = [json.loads(row[0]) for row in rows]
        return frozenset(
            item[result_field]
            for item in results
            if isinstance(item, dict) and isinstance(item.get(result_field), str)
        )

    async def create_approval(self, approval):
        with self.connect() as db:
            db.execute(
                "INSERT INTO approvals VALUES(?,?,?)",
                (self.account, str(approval.approval_id), document(approval)),
            )

    async def get_approval(self, identifier):
        with self.connect() as db:
            row = db.execute(
                "SELECT data FROM approvals WHERE account=? AND id=?", (self.account, str(identifier))
            ).fetchone()
            return restore(ApprovalRecord, row[0]) if row else None

    def transition_approval(self, identifier, *, status, actor=None, digest=None):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT data FROM approvals WHERE account=? AND id=?", (self.account, str(identifier))
            ).fetchone()
            record = restore(ApprovalRecord, row[0]) if row else None
            previous = "prepared" if status == "accepted" else "accepted"
            if not record or record.status != previous or record.expires_at <= datetime.now(UTC):
                return False
            if status == "accepted":
                if str(record.principal_id) != str(actor) or record.request_hash != digest:
                    raise PermissionError("approval actor and exact digest required")
                record.acceptance_type, record.acceptance_origin = "manual", "admin"
            record.status = status
            db.execute(
                "UPDATE approvals SET data=? WHERE account=? AND id=?",
                (document(record), self.account, str(identifier)),
            )
            return True

    async def consume_approval(self, identifier):
        return self.transition_approval(identifier, status="consumed")

    async def create_passbolt_selection(self, selection):
        with self.connect() as db:
            db.execute(
                "INSERT INTO selections VALUES(?,?,?)",
                (self.account, str(selection.selection_id), document(selection)),
            )

    async def get_passbolt_selection(self, identifier, actor):
        with self.connect() as db:
            row = db.execute(
                "SELECT data FROM selections WHERE account=? AND id=?", (self.account, str(identifier))
            ).fetchone()
            record = restore(PassboltSelectionRecord, row[0]) if row else None
            return record if record and str(record.principal_id) == str(actor) else None

    async def consume_passbolt_selection(self, identifier, actor):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT data FROM selections WHERE account=? AND id=?", (self.account, str(identifier))
            ).fetchone()
            record = restore(PassboltSelectionRecord, row[0]) if row else None
            if (
                not record
                or str(record.principal_id) != str(actor)
                or record.status != "prepared"
                or record.expires_at <= datetime.now(UTC)
            ):
                return False
            record.status = "consumed"
            db.execute(
                "UPDATE selections SET data=? WHERE account=? AND id=?",
                (document(record), self.account, str(identifier)),
            )
            return True

    async def record_passbolt_audit(self, audit):
        with self.connect() as db:
            db.execute("INSERT INTO passbolt_audit VALUES(?,?)", (self.account, document(audit)))

    def begin(self, execution, actor, tool, digest):
        vault = self.vault(actor)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = time.time()
            db.execute("DELETE FROM leases WHERE expires<=?", (now,))
            active = db.execute(
                "SELECT COUNT(*) FROM leases WHERE account=? AND vault=?", (self.account, vault)
            ).fetchone()[0]
            if active >= self.config.max_concurrency:
                raise ProviderAdmissionDenied("vault concurrency reached", retry_after_seconds=60)
            db.execute("INSERT INTO leases VALUES(?,?,?,?)", (self.account, execution, vault, now + 900))
            db.execute(
                "INSERT INTO audit VALUES(?,?,?,?,?,?,'started')",
                (self.account, execution, str(actor), tool, digest, now),
            )

    def admit(self, actor):
        vault = self.vault(actor)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = time.time()
            cooldown = db.execute(
                "SELECT until_time FROM cooldowns WHERE account=? AND vault=?", (self.account, vault)
            ).fetchone()
            count = db.execute(
                "SELECT COUNT(*) FROM attempts WHERE account=? AND vault=? AND started>?",
                (self.account, vault, now - 60),
            ).fetchone()[0]
            if (cooldown and cooldown[0] > now) or count >= self.config.rate_limit:
                raise ProviderAdmissionDenied("vault request quota reached", retry_after_seconds=60)
            db.execute("INSERT INTO attempts VALUES(?,?,?)", (self.account, vault, now))

    def cooldown(self, actor, seconds):
        with self.connect() as db:
            db.execute(
                "INSERT INTO cooldowns VALUES(?,?,?) ON CONFLICT(account,vault) DO UPDATE "
                "SET until_time=MAX(until_time,excluded.until_time)",
                (self.account, self.vault(actor), time.time() + max(1, min(seconds, 3600))),
            )

    def finish(self, execution, outcome):
        with self.connect() as db:
            db.execute(
                "UPDATE audit SET outcome=? WHERE account=? AND execution=?",
                (outcome, self.account, execution),
            )
            # A cancelled synchronous GPG/sink subprocess may still finish.
            # Keep its conservative lease until expiry instead of admitting overlap.
            if outcome not in {"cancelled", "timeout"}:
                db.execute("DELETE FROM leases WHERE account=? AND execution=?", (self.account, execution))
