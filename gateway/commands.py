"""The command registry: everything an agent can ever ask for.

Each command is defined once. An agent never supplies a command line; it picks
a command and supplies parameters, which validate.py checks before any rule
runs. Who may call which command is a separate question, answered in scopes.py.

risk 0  read
risk 1  reversible write    may need one approval (tier or change window)
risk 2  irreversible        always needs two approvals from two admins
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

from .validate import Choice, Flag, Param, ServerRef, ServiceOn, Text, UserRef

UNITS = ("authd", "nginx", "sshd", "node_exporter", "checkout-api",
         "payments-api", "postgres", "redis")
TEAMS = ("network-core", "platform", "payments", "checkout", "data-eng", "sre")
ENVS = ("prod", "staging", "dev")
TIERS = ("core", "edge", "access")
DATASETS = ("tmp-cache", "build-artifacts", "session-store")


@dataclass(frozen=True)
class Command:
    id: int
    name: str
    summary: str
    risk: int
    params: Mapping[str, Param]
    argv: Optional[tuple] = None          # fixed template; None for database reads
    approval_scope: Optional[str] = None  # what an approval for this action must say
    policy: Optional[str] = None


_OPT = dict(required=False)

_ALL = [
    Command(1, "query_servers", "List servers, filtered.", 0, {
        "owner_team": Choice(options=TEAMS, **_OPT),
        "env": Choice(options=ENVS, **_OPT),
        "tier": Choice(options=TIERS, **_OPT),
        "status": Choice(options=("up", "down", "draining"), **_OPT),
        "below_min_os": Flag(**_OPT),
    }),
    Command(2, "get_server", "One server and the services on it.", 0, {
        "host": ServerRef(),
    }),
    Command(3, "query_users", "List directory accounts, filtered.", 0, {
        "team": Choice(options=TEAMS, **_OPT),
        "status": Choice(options=("active", "disabled", "deleted"), **_OPT),
        "auth_level": Choice(options=("viewer", "engineer", "operator", "admin"), **_OPT),
        "service_accounts": Flag(**_OPT),
    }),
    Command(4, "query_services", "List services by state, team or host.", 0, {
        "host": ServerRef(**_OPT),
        "service": Choice(options=UNITS, **_OPT),
        "state": Choice(options=("active", "degraded", "failed"), **_OPT),
        "owner_team": Choice(options=TEAMS, **_OPT),
        "env": Choice(options=ENVS, **_OPT),
    }),
    Command(5, "list_change_windows", "Open and upcoming change windows.", 0, {
        "env": Choice(options=ENVS, **_OPT),
    }),
    Command(6, "search_policies", "Search policies and runbooks.", 0, {
        "query": Text(),
    }),
    Command(7, "restart_service", "Restart one unit on one server.", 1, {
        "host": ServerRef(),
        "service": ServiceOn(options=UNITS),
    }, argv=("systemctl", "restart", "{service}"),
       approval_scope="restart_service:{host}:{service}", policy="rb-01"),
    Command(8, "drain_server", "Take a server out of rotation.", 1, {
        "host": ServerRef(),
    }, argv=("fleetctl", "drain", "{host}"),
       approval_scope="drain_server:{host}", policy="rb-02"),
    Command(9, "restore_server", "Return a drained server to rotation.", 1, {
        "host": ServerRef(),
    }, argv=("fleetctl", "restore", "{host}"),
       approval_scope="restore_server:{host}", policy="rb-02"),
    Command(10, "delete_user", "Permanently remove a directory account.", 2, {
        "username": UserRef(),
    }, argv=("userdel", "--remove", "--", "{username}"),
       approval_scope="delete_user:{username}", policy="ops-19"),
    Command(11, "erase_data", "Permanently erase a named dataset on a server.", 2, {
        "host": ServerRef(),
        "dataset": Choice(options=DATASETS),
    }, argv=("rm", "-rf", "--", "/var/data/{dataset}"),
       approval_scope="erase_data:{host}:{dataset}", policy="ops-19"),
]

COMMANDS = {c.id: c for c in _ALL}
BY_NAME = {c.name: c for c in _ALL}
READS = frozenset(c.id for c in _ALL if c.risk == 0)
