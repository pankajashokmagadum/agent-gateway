"""The decision.

decide() answers one question: may this agent, acting for this human, run this
command with these arguments right now? It is ordinary code over database
state. No model is consulted, so nothing a model reads or is told can change
the outcome.

Order matters. Each step can only deny or narrow; nothing later in the
function can widen what an earlier step allowed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from . import rules
from .commands import BY_NAME
from .rules import Reason
from .scopes import LEVELS, lower_tier
from .validate import ValidationError, validate


@dataclass
class Decision:
    allow: bool = False
    reasons: list = field(default_factory=list)
    command: Optional[Any] = None
    validated: Optional[Any] = None
    human_level: Optional[str] = None
    write_ceiling: Optional[str] = None
    max_risk: Optional[int] = None
    approvals: list = field(default_factory=list)      # consumed by this action
    approval_scope: Optional[str] = None               # what would unblock a denial
    approvals_required: int = 0
    approvals_rejected: list = field(default_factory=list)

    def deny(self, *reasons: Reason) -> "Decision":
        self.allow = False
        self.reasons.extend(reasons)
        return self

    def permit(self) -> "Decision":
        self.allow = True
        return self


def decide(db, now: str, registry, agent_id: str, username: Optional[str],
           command_name: str, args: Any, writes_used: int, write_budget: int) -> Decision:
    d = Decision()

    # 1. The sponsor. Every action traces to an active human account.
    human = None
    if username is not None:
        human = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if human is None:
        return d.deny(Reason("NO_SPONSOR", "no human is bound to this session", "ops-06"))
    d.human_level = human["auth_level"]
    if human["is_service_account"]:
        return d.deny(Reason("SPONSOR_IS_SERVICE_ACCOUNT",
                             "service accounts cannot sponsor agent sessions", "ops-06"))
    if human["status"] != "active":
        return d.deny(Reason("SPONSOR_INACTIVE",
                             f"account {username} is {human['status']}", "ops-06"))

    # 2. The command must exist and sit inside the agent's scope, taken as the
    #    intersection of every role on its delegation chain.
    command = BY_NAME.get(command_name) if isinstance(command_name, str) else None
    if command is None:
        return d.deny(Reason("UNKNOWN_COMMAND", "not a registered command", "ops-01"))
    d.command = command
    scope = registry.effective_scope(agent_id)
    if command.id not in scope.commands:
        return d.deny(Reason("OUT_OF_SCOPE",
                             f"{command.name} is outside the scope of {agent_id}", "ops-01"))

    # 3. Arguments: typed, and every reference resolved to a real row.
    try:
        v = validate(command, args, db)
    except ValidationError as err:
        return d.deny(Reason("INVALID_ARGS", str(err), "ops-09"))
    d.validated = v

    if command.risk == 0:
        return d.permit()

    # 4. Standing limits for writes: the narrower of human and agent.
    level = LEVELS[human["auth_level"]]
    d.write_ceiling = lower_tier(level.write_ceiling, scope.write_ceiling)
    d.max_risk = min(level.max_risk, scope.max_risk)
    if d.write_ceiling is None:
        return d.deny(Reason("NO_WRITE_AUTHORITY",
                             f"{username} ({human['auth_level']}) may not request changes",
                             "ops-05"))
    if command.risk > d.max_risk:
        return d.deny(Reason("RISK_ABOVE_LIMIT",
                             f"{command.name} is risk {command.risk}; this request is "
                             f"limited to risk {d.max_risk}", "ops-05"))
    if writes_used >= write_budget:
        return d.deny(Reason("WRITE_BUDGET_EXHAUSTED",
                             f"this session has used its {write_budget} changes", "ops-12"))
    hard = rules.hard_limits(db, command, v, username)
    if hard:
        return d.deny(*hard)

    # 5. Conditions an approval can satisfy.
    conditions = rules.approval_conditions(db, now, command, v, d.write_ceiling)
    if not conditions:
        return d.permit()

    d.approval_scope = command.approval_scope.format(**v.values)
    d.approvals_required = 2 if command.risk >= 2 else 1
    valid, d.approvals_rejected = rules.usable_approvals(db, now, d.approval_scope, username)
    if len(valid) >= d.approvals_required:
        d.approvals = valid[:d.approvals_required]
        return d.permit()
    return d.deny(*conditions, Reason(
        "APPROVAL_REQUIRED",
        f"{len(valid)} of {d.approvals_required} required approvals present for "
        f"{d.approval_scope}", "ops-08"))
