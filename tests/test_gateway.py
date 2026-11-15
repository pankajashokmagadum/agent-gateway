"""The paths that must work. The attack suite covers what must not."""

from datetime import datetime, timedelta, timezone

import pytest

from evals.world import NOW, World
from gateway.approve import ApprovalError
from gateway.audit import verify
from gateway.commands import BY_NAME
from gateway.scopes import AGENTS, READS, ROLES, Registry, RegistryError, Scope
from gateway.validate import render_argv

REM, INV = "remediation-01", "inventory-01"
STAGING = {"host": "app-usw2-32", "service": "nginx"}
CORE_02 = {"host": "core-use1-02", "service": "authd"}
CORE_07 = {"host": "core-use1-07", "service": "authd"}


@pytest.fixture
def w():
    world = World()
    yield world
    world.close()


def codes(reply):
    return [r["code"] for r in reply.get("reasons", [])]


def test_anyone_active_can_read(w):
    viewer = w.one("SELECT username FROM users WHERE auth_level = 'viewer' "
                   "AND is_service_account = 0 ORDER BY 1")
    reply = w.call(viewer, INV, "query_servers", {"below_min_os": True})
    assert reply["decision"] == "ALLOW"
    assert reply["result"]["total"] == 45
    assert max(reply["result"]["by_team"], key=reply["result"]["by_team"].get) == "payments"


def test_restart_within_standing_authority(w):
    reply = w.call("pnair", REM, "restart_service", STAGING)
    assert reply["decision"] == "ALLOW"
    assert reply["result"]["previous_state"] == "failed"
    assert w.one("SELECT state FROM services WHERE hostname = ? AND service = ?",
                 "app-usw2-32", "nginx") == "active"
    assert w.effects_count() == 1


def test_engineer_can_change_access_tier_in_staging(w):
    assert w.call("tkim", REM, "restart_service", STAGING)["decision"] == "ALLOW"


def test_deny_then_approve_then_allow(w):
    first = w.call("pnair", REM, "restart_service", CORE_07)
    assert first["decision"] == "DENY"
    assert {"TIER_ABOVE_CEILING", "OUTSIDE_CHANGE_WINDOW", "APPROVAL_REQUIRED"} <= set(codes(first))
    assert first["approval"]["scope"] == "restart_service:core-use1-07:authd"
    assert w.effects_count() == 0

    token = w.gw.issue_approval("onovak", "pnair", first["approval"]["scope"])["token"]
    second = w.call("pnair", REM, "restart_service", CORE_07)
    assert second["decision"] == "ALLOW"
    assert second["approvals_used"] == [{"token": token, "approved_by": "onovak"}]
    assert w.one("SELECT used_at FROM approvals WHERE token = ?", token) is not None

    third = w.call("pnair", REM, "restart_service", CORE_07)
    assert third["decision"] == "DENY"
    assert any("already used" in r for r in third["approval"]["rejected"])


def test_open_change_window_lifts_the_window_condition_only():
    thursday = datetime(2026, 11, 12, 3, 0, tzinfo=timezone.utc)   # inside the prod window
    w = World(clock=lambda: thursday)
    try:
        edge = w.one("SELECT s.hostname FROM servers s JOIN services v ON v.hostname = s.hostname "
                     "WHERE s.env = 'prod' AND s.tier = 'edge' AND v.service = 'nginx' "
                     "AND s.hostname != 'edge-use1-14' ORDER BY 1")
        in_window = w.call("pnair", REM, "restart_service", {"host": edge, "service": "nginx"})
        assert in_window["decision"] == "ALLOW" and "approvals_used" not in in_window
        core = w.one("SELECT hostname FROM servers WHERE env = 'prod' AND tier = 'core' "
                     "AND hostname NOT IN ('core-use1-02', 'core-use1-07') ORDER BY 1")
        above_ceiling = w.call("pnair", REM, "restart_service", {"host": core, "service": "authd"})
        assert codes(above_ceiling) == ["TIER_ABOVE_CEILING", "APPROVAL_REQUIRED"]
    finally:
        w.close()


def test_two_person_rule_allows_with_two_distinct_admins(w):
    w.gw.issue_approval("onovak", "jchen", "delete_user:mrios")
    w.gw.issue_approval("lhaddad", "jchen", "delete_user:mrios")
    reply = w.call("jchen", REM, "delete_user", {"username": "mrios"})
    assert reply["decision"] == "ALLOW"
    assert sorted(a["approved_by"] for a in reply["approvals_used"]) == ["lhaddad", "onovak"]
    assert w.one("SELECT status FROM users WHERE username = 'mrios'") == "deleted"
    assert w.one("SELECT COUNT(*) FROM approvals WHERE scope = 'delete_user:mrios' "
                 "AND used_at IS NOT NULL") == 2


def test_dry_run_changes_nothing(w):
    reply = w.call("pnair", REM, "restart_service", CORE_02, dry_run=True)
    assert reply["decision"] == "ALLOW" and reply["dry_run"] is True
    assert reply["result"] == {"would_run": ["systemctl", "restart", "authd"]}
    assert w.effects_count() == 0
    assert w.one("SELECT used_at FROM approvals WHERE token = 'tok_4c1e'") is None
    assert w.one("SELECT state FROM services WHERE hostname = 'core-use1-02' "
                 "AND service = 'authd'") == "failed"
    assert w.gw._sessions[w.session("pnair")].writes_used == 0


def test_no_audit_record_means_no_action(w):
    w.audit_path.unlink(missing_ok=True)
    w.audit_path.mkdir()                      # appending to the log now fails
    with pytest.raises(OSError):
        w.call("pnair", REM, "restart_service", STAGING)
    assert w.effects_count() == 0
    assert w.one("SELECT state FROM services WHERE hostname = 'app-usw2-32' "
                 "AND service = 'nginx'") == "failed"


def test_every_decision_and_approval_is_chained(w):
    w.call("pnair", INV, "get_server", {"host": "core-use1-02"})
    w.gw.issue_approval("jchen", "pnair", "restart_service:core-use1-07:authd")
    w.call("pnair", REM, "restart_service", CORE_07)
    entries = w.gw.audit.entries()
    assert [e["event"] for e in entries] == ["decision", "approval_issued", "decision"]
    assert [e["seq"] for e in entries] == [1, 2, 3]
    assert entries[2]["human"] == "pnair" and entries[2]["human_level"] == "operator"
    assert entries[2]["chain"] == ["planner-01", "remediation-01"]
    assert entries[2]["argv"] == ["systemctl", "restart", "authd"]
    assert verify(w.audit_path) == (True, 3, None)


def test_registry_refuses_a_child_wider_than_its_parent():
    Registry()                                   # the shipped registry is consistent
    roles = dict(ROLES, planner=Scope(READS, None, 0))
    with pytest.raises(RegistryError):
        Registry(roles, AGENTS)


def test_effective_scope_is_the_intersection_along_the_chain():
    scope = Registry().effective_scope("inventory-01")
    assert scope.commands == READS and scope.write_ceiling is None and scope.max_risk == 0
    rem = Registry().effective_scope("remediation-01")
    assert BY_NAME["query_users"].id not in rem.commands        # not in the role
    assert rem.write_ceiling == "edge"


def test_each_value_fills_exactly_one_argv_slot():
    argv = render_argv(BY_NAME["delete_user"], {"username": "a b; rm -rf /"})
    assert argv == ["userdel", "--remove", "--", "a b; rm -rf /"]   # one argument, not a shell line


@pytest.mark.parametrize("approver, requester, scope, ttl", [
    ("jchen", "pnair", "restart_service:no-such-host:authd", timedelta(hours=1)),
    ("jchen", "pnair", "query_servers", timedelta(hours=1)),            # reads need no approval
    ("jchen", "pnair", "restart_service:core-use1-07", timedelta(hours=1)),
    ("jchen", "pnair", "restart_service:core-use1-07:authd", timedelta(hours=9)),
    ("jchen", "svc-bkp", "restart_service:core-use1-07:authd", timedelta(hours=1)),
    ("jchen", "mrios", "restart_service:core-use1-07:authd", timedelta(hours=1)),
    ("svc-reaper", "pnair", "restart_service:core-use1-07:authd", timedelta(hours=1)),
])
def test_approvals_that_cannot_be_issued(w, approver, requester, scope, ttl):
    with pytest.raises(ApprovalError):
        w.gw.issue_approval(approver, requester, scope, ttl)
    assert w.one("SELECT COUNT(*) FROM approvals") == 4


def test_seed_anchor_matches_harness_clock():
    assert NOW == datetime(2026, 11, 10, 14, 0, tzinfo=timezone.utc)
