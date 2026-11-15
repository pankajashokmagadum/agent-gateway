"""The gateway: the only path from an agent to an effect.

    authenticate   is this really the agent it claims to be?
    decide         authorize.decide(), on database state only
    act            apply the effect, consume approvals
    account        append a hash-chained audit entry

The effect and the audit entry commit together. If the audit write fails the
effect is rolled back: no record, no action.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable, Optional

from . import approve, effects
from .audit import AuditLog
from .authorize import Decision, decide
from .config import AUDIT_PATH, DB_PATH, WRITE_BUDGET, iso, utcnow
from .policies import clause
from .rules import Reason
from .scopes import Registry, RegistryError
from .validate import render_argv


class SessionError(Exception):
    pass


@dataclass
class Session:
    session_id: str
    username: str
    writes_used: int = 0


def _digest(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _safe(value: Any, depth: int = 0) -> Any:
    """Make untrusted arguments safe to store: bounded size, plain JSON types."""
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    if isinstance(value, str):
        return value if len(value) <= 200 else value[:200] + "…"
    if isinstance(value, dict) and depth < 2:
        return {str(k)[:60]: _safe(v, depth + 1) for k, v in list(value.items())[:20]}
    if isinstance(value, (list, tuple)) and depth < 2:
        return [_safe(v, depth + 1) for v in list(value)[:20]]
    return repr(value)[:200]


class Gateway:
    def __init__(self, db_path=DB_PATH, audit_path=AUDIT_PATH,
                 registry: Optional[Registry] = None, clock: Callable = utcnow,
                 write_budget: int = WRITE_BUDGET,
                 policy_search: Optional[Callable] = None, durable_audit: bool = True):
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(effects.EFFECTS_SCHEMA)
        self.audit = AuditLog(audit_path, durable=durable_audit)
        self.registry = registry or Registry()
        self.clock = clock
        self.write_budget = write_budget
        self.policy_search = policy_search
        self._credentials = {}      # agent_id -> digest of its secret
        self._sessions = {}         # session_id -> Session
        self._lock = threading.Lock()

    # -- identity -----------------------------------------------------------

    def register_agent(self, agent_id: str) -> str:
        """Issue an agent its credential. Once only, and only to known agents."""
        if agent_id not in self.registry.agents:
            raise RegistryError(f"{agent_id!r} is not a registered agent")
        if agent_id in self._credentials:
            raise RegistryError(f"{agent_id} already holds a credential")
        secret = secrets.token_urlsafe(24)
        self._credentials[agent_id] = _digest(secret)
        return secret

    def _authentic(self, agent_id: Any, credential: Any) -> bool:
        if not isinstance(agent_id, str) or not isinstance(credential, str):
            return False
        expected = self._credentials.get(agent_id)
        return expected is not None and hmac.compare_digest(expected, _digest(credential))

    def open_session(self, username: str) -> str:
        """Bind a human to a session. Called by application code after login,
        never by a model. The account is re-checked on every proposal."""
        row = self.db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None or row["is_service_account"] or row["status"] != "active":
            raise SessionError(f"{username!r} cannot sponsor a session")
        session_id = "sess_" + secrets.token_hex(8)
        self._sessions[session_id] = Session(session_id, username)
        return session_id

    def issue_approval(self, approver: str, requester: str, scope: str,
                       ttl: timedelta = timedelta(hours=2)) -> dict:
        with self._lock:
            return approve.issue(self.db, self.audit, self.clock(), approver, requester,
                                 scope, ttl)

    # -- the one entry point for agents ---------------------------------------

    def propose(self, session_id: Any, agent_id: Any, credential: Any, command: Any,
                args: Any = None, dry_run: bool = False) -> dict:
        with self._lock:
            started = time.perf_counter()
            now = iso(self.clock())
            session = self._sessions.get(session_id) if isinstance(session_id, str) else None

            if not self._authentic(agent_id, credential):
                d = Decision().deny(Reason("AGENT_UNAUTHENTICATED",
                                           "unknown agent or wrong credential", "ops-04"))
                session = None      # an unauthenticated caller learns nothing about sessions
            else:
                d = decide(self.db, now, self.registry, agent_id,
                           session.username if session else None, command,
                           args if args is not None else {},
                           session.writes_used if session else 0, self.write_budget)
            decision_ms = (time.perf_counter() - started) * 1000

            result = None
            executed = False
            try:
                if d.allow and d.command.risk == 0:
                    result = effects.read(self.db, now, d.command, d.validated.values,
                                          self.policy_search)
                elif d.allow and dry_run:
                    result = {"would_run": render_argv(d.command, d.validated.values)}
                elif d.allow:
                    result = effects.apply(self.db, now, d.command, d.validated.values,
                                           session.username, agent_id)
                    for approval in d.approvals:
                        used = self.db.execute(
                            "UPDATE approvals SET used_at = ? WHERE token = ? AND used_at IS NULL",
                            (now, approval["token"]))
                        if used.rowcount != 1:
                            raise RuntimeError("approval was consumed concurrently")
                    executed = True
                entry = self.audit.append(self._entry(now, session, agent_id, command, args, d,
                                                      dry_run, decision_ms))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            if executed:
                session.writes_used += 1
            return self._reply(d, result, dry_run, entry, session)

    # -- records ------------------------------------------------------------------

    def _entry(self, now, session, agent_id, command, args, d: Decision, dry_run, ms) -> dict:
        authenticated = not any(r.code == "AGENT_UNAUTHENTICATED" for r in d.reasons)
        try:
            chain = self.registry.chain(agent_id) if authenticated else None
        except RegistryError:
            chain = None
        entry = {
            "event": "decision",
            "ts": now,
            "session": session.session_id if session else None,
            "human": session.username if session else None,
            "human_level": d.human_level,
            "agent": _safe(agent_id),
            "agent_authenticated": authenticated,
            "chain": chain,
            "command": d.command.name if d.command else _safe(command),
            "args": _safe(d.validated.values if d.validated else args),
            "decision": "ALLOW" if d.allow else "DENY",
            "reasons": [{"code": r.code, "message": r.message, "policy": r.policy}
                        for r in d.reasons],
            "write_ceiling": d.write_ceiling,
            "approvals": [{"token": a["token"], "approved_by": a["approved_by"]}
                          for a in d.approvals],
            "dry_run": bool(dry_run),
            "decision_ms": round(ms, 3),
        }
        if d.allow and d.command.risk > 0:
            entry["argv"] = render_argv(d.command, d.validated.values)
        return entry

    def _reply(self, d: Decision, result, dry_run, entry, session) -> dict:
        """What the calling agent sees."""
        reply = {
            "decision": "ALLOW" if d.allow else "DENY",
            "command": entry["command"],
            "dry_run": bool(dry_run),
            "audit_seq": entry["seq"],
        }
        if d.allow:
            reply["result"] = result
            if d.approvals:
                reply["approvals_used"] = entry["approvals"]
            return reply
        reply["reasons"] = [{"code": r.code, "message": r.message, "policy": r.policy,
                             "policy_text": clause(r.policy)} for r in d.reasons]
        if d.approval_scope and session is not None:
            reply["approval"] = {
                "scope": d.approval_scope,
                "required": d.approvals_required,
                "rejected": d.approvals_rejected,
                "how": (f"{d.approvals_required} admin(s) other than {session.username} "
                        f"must run: python -m gateway.approve --by <admin> "
                        f"--for {session.username} --scope {d.approval_scope}"),
            }
        return reply

    def close(self) -> None:
        self.db.close()
