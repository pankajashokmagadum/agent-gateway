"""A disposable copy of the demo world, for tests, attacks and benchmarks.

Each World gets its own freshly seeded database and audit log in a temp
directory, with the clock pinned to the moment the seed data is anchored to.
"""

from __future__ import annotations

import importlib.util
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from gateway.commands import BY_NAME
from gateway.gateway import Gateway
from gateway.scopes import Registry

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 10, 14, 0, tzinfo=timezone.utc)   # matches data/seed.py
AGENTS = ("planner-01", "inventory-01", "remediation-01")

_template = None


def template_db() -> Path:
    global _template
    if _template is None:
        spec = importlib.util.spec_from_file_location("fde_seed", ROOT / "data" / "seed.py")
        seed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(seed)
        _template = Path(tempfile.mkdtemp(prefix="fde-template-")) / "fde.db"
        seed.main(_template, quiet=True)
    return _template


class World:
    def __init__(self, guarded: bool = True, registry: Registry = None, clock=None,
                 write_budget: int = 5, durable_audit: bool = False):
        self.dir = Path(tempfile.mkdtemp(prefix="fde-world-"))
        self.db_path = self.dir / "fde.db"
        self.audit_path = self.dir / "audit.jsonl"
        shutil.copy(template_db(), self.db_path)
        self.now = NOW
        self.guarded = guarded
        self.gw = Gateway(self.db_path, self.audit_path, registry=registry,
                          clock=clock or (lambda: self.now), write_budget=write_budget,
                          durable_audit=durable_audit)
        self.creds = {a: self.gw.register_agent(a) for a in self.gw.registry.agents}
        self._sessions = {}
        self.marked = 0             # effects that existed before the attack proper
        self.db = sqlite3.connect(self.db_path)   # an independent view for assertions
        self.db.row_factory = sqlite3.Row

    def session(self, user: str) -> str:
        if user not in self._sessions:
            self._sessions[user] = self.gw.open_session(user)
        return self._sessions[user]

    def call(self, user, agent, command, args=None, *, credential=None, session=None,
             dry_run=False) -> dict:
        """Propose an action. With guarded=False the same call goes straight to
        the executor, the way tools are wired in most agent quickstarts."""
        if not self.guarded:
            return self._unguarded(user, agent, command, args)
        return self.gw.propose(
            session if session is not None else self.session(user), agent,
            credential if credential is not None else self.creds.get(agent, "none"),
            command, args, dry_run=dry_run)

    def _unguarded(self, user, agent, command, args) -> dict:
        """No identity, no scope, no validation: build the command line from
        whatever arrived and run it. Simulated like everything else, but the
        string recorded is what a shell would have been handed."""
        cmd = BY_NAME.get(command) if isinstance(command, str) else None
        if cmd is None or cmd.argv is None or not isinstance(args, dict):
            return {"decision": "ERROR", "reason": "not a tool the executor knows"}
        try:
            shell = " ".join(part.format(**args) for part in cmd.argv)
        except (KeyError, IndexError):
            return {"decision": "ERROR", "reason": "missing argument"}
        db = self.gw.db
        if cmd.name == "restart_service":
            db.execute("UPDATE services SET state = 'active' WHERE hostname = ? AND service = ?",
                       (str(args.get("host")), str(args.get("service"))))
        elif cmd.name in ("drain_server", "restore_server"):
            db.execute("UPDATE servers SET status = ? WHERE hostname = ?",
                       ("draining" if cmd.name == "drain_server" else "up",
                        str(args.get("host"))))
        elif cmd.name == "delete_user":
            db.execute("UPDATE users SET status = 'deleted' WHERE username = ?",
                       (str(args.get("username")),))
        db.execute("INSERT INTO effects (ts, human, agent, command, target, argv) "
                   "VALUES (?,?,?,?,?,?)",
                   ("2026-11-10T14:00:00Z", str(user), str(agent), cmd.name, "?", shell))
        db.commit()
        return {"decision": "EXECUTED", "shell": shell}

    def mark(self) -> None:
        """Everything before this point was legitimate setup."""
        self.marked = self.effects_count()

    def forge_approval(self, token, requester, approver, scope, hours=2) -> None:
        """Write an approval row directly, as if the issuing path were compromised."""
        from datetime import timedelta
        from gateway.config import iso
        self.db.execute("INSERT INTO approvals VALUES (?,?,?,?,?,?,NULL)",
                        (token, requester, approver, scope, iso(self.now),
                         iso(self.now + timedelta(hours=hours))))
        self.db.commit()

    def effects_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]

    def one(self, sql, *params):
        row = self.db.execute(sql, params).fetchone()
        return row[0] if row else None

    def close(self) -> None:
        self.db.close()
        self.gw.close()
        shutil.rmtree(self.dir, ignore_errors=True)
