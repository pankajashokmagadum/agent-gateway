"""Issue an approval. Run by a human, out of band; no agent can call this.

    python -m gateway.approve --by jchen --for pnair \\
        --scope restart_service:core-use1-02:authd --ttl 2h
    python -m gateway.approve --list

An approval is a row, not a conversation. It names one requester and one exact
action, expires, and is consumed by the action it permits. In this demo the
CLI trusts --by; a real deployment would authenticate the approver first.
"""

from __future__ import annotations

import argparse
import re
import secrets
import sqlite3
import sys
from datetime import timedelta

from .audit import AuditLog
from .commands import BY_NAME
from .config import AUDIT_PATH, DB_PATH, iso, utcnow
from .rules import approver_problem
from .validate import ValidationError, validate

MAX_TTL = timedelta(hours=8)


class ApprovalError(Exception):
    pass


def parse_scope(db, scope: str):
    """Check that `scope` names a real write command and a real target."""
    parts = scope.split(":") if isinstance(scope, str) else []
    command = BY_NAME.get(parts[0]) if parts else None
    if command is None or command.approval_scope is None:
        raise ApprovalError("scope must start with a command that can be approved")
    fields = re.findall(r"\{(\w+)\}", command.approval_scope)
    if len(parts) - 1 != len(fields):
        raise ApprovalError(f"scope must look like {command.approval_scope}")
    try:
        validated = validate(command, dict(zip(fields, parts[1:])), db)
    except ValidationError as err:
        raise ApprovalError(f"scope does not name a valid target ({err})")
    return command, validated


def issue(db, audit: AuditLog, now, approver: str, requester: str, scope: str,
          ttl: timedelta = timedelta(hours=2)) -> dict:
    problem = approver_problem(db, approver)
    if problem:
        raise ApprovalError(f"{approver} cannot approve: {problem}")
    if approver == requester:
        raise ApprovalError("requesters cannot approve their own request")
    person = db.execute("SELECT * FROM users WHERE username = ?", (requester,)).fetchone()
    if person is None or person["is_service_account"] or person["status"] != "active":
        raise ApprovalError(f"{requester} is not an active human account")
    if not timedelta(0) < ttl <= MAX_TTL:
        raise ApprovalError("ttl must be between 1 minute and 8 hours")
    parse_scope(db, scope)

    row = {
        "token": "tok_" + secrets.token_hex(4),
        "requested_by": requester,
        "approved_by": approver,
        "scope": scope,
        "created_at": iso(now),
        "expires_at": iso(now + ttl),
        "used_at": None,
    }
    try:
        db.execute("INSERT INTO approvals VALUES (:token, :requested_by, :approved_by, "
                   ":scope, :created_at, :expires_at, :used_at)", row)
        audit.append({"event": "approval_issued", "ts": row["created_at"],
                      **{k: row[k] for k in ("token", "requested_by", "approved_by",
                                             "scope", "expires_at")}})
        db.commit()
    except Exception:
        db.rollback()
        raise
    return row


def _ttl(text: str) -> timedelta:
    match = re.fullmatch(r"(\d+)([mh])", text)
    if not match:
        raise argparse.ArgumentTypeError("use a duration like 30m or 2h")
    amount = int(match.group(1))
    return timedelta(minutes=amount) if match.group(2) == "m" else timedelta(hours=amount)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gateway.approve",
                                     description="Issue or list approvals.")
    parser.add_argument("--by", help="approving admin")
    parser.add_argument("--for", dest="requester", help="the human the approval is for")
    parser.add_argument("--scope", help="exact action, e.g. restart_service:core-use1-02:authd")
    parser.add_argument("--ttl", type=_ttl, default=timedelta(hours=2))
    parser.add_argument("--list", action="store_true", help="show approvals and their state")
    args = parser.parse_args(argv)

    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    now = utcnow()
    if args.list:
        for r in db.execute("SELECT * FROM approvals ORDER BY created_at, token"):
            state = ("used" if r["used_at"] else
                     "expired" if r["expires_at"] <= iso(now) else "valid")
            print(f"{r['token']:<12} {state:<8} {r['approved_by']} -> {r['requested_by']:<8} "
                  f"{r['scope']}  (expires {r['expires_at']})")
        return 0
    if not (args.by and args.requester and args.scope):
        parser.error("--by, --for and --scope are required")
    try:
        row = issue(db, AuditLog(AUDIT_PATH), now, args.by, args.requester, args.scope, args.ttl)
    except ApprovalError as err:
        print(f"refused: {err}")
        return 1
    print(f"issued {row['token']} · {row['approved_by']} approves {row['scope']} "
          f"for {row['requested_by']} · expires {row['expires_at']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
