"""The conditions a write has to meet.

Two kinds. Hard limits can never be lifted. Approval conditions can be met by
a valid approval from an admin, the way an emergency change is signed off.
Every function here reads live database state; none of them consults a model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .config import MAX_UNAVAILABLE
from .scopes import APPROVER_LEVEL, TIER_RANK


@dataclass(frozen=True)
class Reason:
    code: str
    message: str
    policy: Optional[str] = None


def window_open(db, env: str, now: str) -> bool:
    return db.execute(
        "SELECT 1 FROM change_windows WHERE env = ? AND starts_at <= ? AND ends_at > ?",
        (env, now, now)).fetchone() is not None


def hard_limits(db, command, v, requester: str) -> list:
    """Limits no approval can lift."""
    out = []
    if command.name == "drain_server":
        s = v.server
        size, out_of_rotation = db.execute(
            "SELECT COUNT(*), SUM(status != 'up' AND hostname != ?) FROM servers "
            "WHERE owner_team = ? AND env = ? AND tier = ?",
            (s["hostname"], s["owner_team"], s["env"], s["tier"])).fetchone()
        after = (out_of_rotation or 0) + 1
        if after / size > MAX_UNAVAILABLE:
            out.append(Reason(
                "BLAST_RADIUS",
                f"draining {s['hostname']} would leave {after} of {size} "
                f"{s['owner_team']} {s['env']} {s['tier']} servers out of rotation "
                f"(limit {int(MAX_UNAVAILABLE * 100)}%)", "ops-13"))
    if command.name == "delete_user":
        if v.user["is_service_account"]:
            out.append(Reason("PROTECTED_TARGET",
                              f"{v.user['username']} is a service account; its lifecycle "
                              "is owned by automation", "ops-15"))
        if v.user["username"] == requester:
            out.append(Reason("SELF_TARGET", "a requester cannot delete their own account",
                              "ops-15"))
    return out


def approval_conditions(db, now: str, command, v, ceiling: str) -> list:
    """Conditions that hold the action back unless an approval covers it."""
    out = []
    if v.server is not None:
        s = v.server
        if TIER_RANK[s["tier"]] > TIER_RANK[ceiling]:
            out.append(Reason(
                "TIER_ABOVE_CEILING",
                f"{s['hostname']} is {s['tier']} tier; the effective write ceiling "
                f"for this request is {ceiling}", "ops-07"))
        if not window_open(db, s["env"], now):
            out.append(Reason(
                "OUTSIDE_CHANGE_WINDOW",
                f"no {s['env']} change window is open", "ops-03"))
    if command.risk >= 2:
        out.append(Reason("IRREVERSIBLE",
                          f"{command.name} cannot be undone; two admins must approve",
                          "ops-19"))
    return out


def usable_approvals(db, now: str, scope: str, requester: str):
    """Approvals that genuinely cover `scope` for `requester`, plus why others don't.

    An approval counts only if it names this exact action, was issued to this
    requester, has not expired or been used, and was signed by an active admin
    who is neither the requester nor an approver already counted.
    """
    valid, rejected, approvers = [], [], set()
    rows = db.execute("SELECT * FROM approvals WHERE scope = ? ORDER BY created_at, token",
                      (scope,)).fetchall()
    for row in rows:
        problem = _problem(db, now, row, requester, approvers)
        if problem:
            rejected.append(f"{row['token']}: {problem}")
        else:
            valid.append(dict(row))
            approvers.add(row["approved_by"])
    return valid, rejected


def _problem(db, now, row, requester, approvers) -> Optional[str]:
    if row["used_at"] is not None:
        return "already used"
    if row["expires_at"] <= now:
        return "expired"
    if row["requested_by"] != requester:
        return "issued to a different requester"
    if row["approved_by"] == requester:
        return "requesters cannot approve their own request"
    if row["approved_by"] in approvers:
        return "same approver as another approval"
    return approver_problem(db, row["approved_by"])


def approver_problem(db, username: str) -> Optional[str]:
    """Why `username` may not approve, or None if they may."""
    a = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if a is None:
        return "approver does not exist"
    if a["is_service_account"]:
        return "service accounts cannot approve"
    if a["status"] != "active":
        return "approver account is not active"
    if a["auth_level"] != APPROVER_LEVEL:
        return f"approver is not {APPROVER_LEVEL} level"
    return None
