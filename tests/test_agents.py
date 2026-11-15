"""The agents are wired to the gateway correctly, checked with a scripted model.

No real model is called. The scripted model plays the worst useful case: it
does what it is told, including proposing an action it has no authority for.
"""

import pytest

pytest.importorskip("google.adk")

from agents import planner                                         # noqa: E402
from agents.runtime import Runtime                                 # noqa: E402
from evals.world import World                                      # noqa: E402
from tests.scripted import SEEN, Scripted, run                     # noqa: E402


@pytest.fixture
def world():
    SEEN.clear()
    w = World()
    yield w
    w.close()


def runtime_for(w, user):
    return Runtime(w.gw, user, w.session(user), w.creds)


def test_planner_delegates_and_the_gateway_denies(world):
    rt = runtime_for(world, "tkim")
    texts = run(planner.build(Scripted(), rt), "authd is down on core-use1-02, restart it")

    final = texts[-1]
    assert final[0] == "planner" and "DENY" in final[1]
    assert "python -m gateway.approve" in final[1] and "--for tkim" in final[1]

    entries = world.gw.audit.entries()
    assert [(e["agent"], e["command"], e["decision"]) for e in entries] == [
        ("remediation-01", "get_server", "ALLOW"),
        ("remediation-01", "restart_service", "DENY")]
    denied = entries[-1]
    assert denied["human"] == "tkim" and denied["human_level"] == "engineer"
    assert denied["chain"] == ["planner-01", "remediation-01"]
    assert {r["code"] for r in denied["reasons"]} >= {"TIER_ABOVE_CEILING", "APPROVAL_REQUIRED"}
    assert world.effects_count() == 0
    assert world.one("SELECT state FROM services WHERE hostname = 'core-use1-02' "
                     "AND service = 'authd'") == "failed"


def test_the_same_request_succeeds_once_an_admin_approves(world):
    rt = runtime_for(world, "tkim")
    agent = planner.build(Scripted(), rt)
    run(agent, "restart authd on core-use1-02")
    world.gw.issue_approval("jchen", "tkim", "restart_service:core-use1-02:authd")
    texts = run(agent, "restart authd on core-use1-02")
    assert "ALLOW" in texts[-1][1]
    assert world.effects_count() == 1
    last = world.gw.audit.entries()[-1]
    assert last["decision"] == "ALLOW" and last["approvals"][0]["approved_by"] == "jchen"


def test_models_never_see_credentials_or_session_ids(world):
    rt = runtime_for(world, "tkim")
    run(planner.build(Scripted(), rt), "restart authd on core-use1-02")
    assert len(SEEN) >= 4
    everything = "\n".join(r.model_dump_json() for r in SEEN)
    assert rt.session_id not in everything
    for secret in rt.credentials.values():
        assert secret not in everything


def test_each_agent_holds_only_its_own_tools(world):
    rt = runtime_for(world, "pnair")
    root = planner.build(Scripted(), rt)
    names = {a.name: {getattr(t, "__name__", getattr(t, "name", "")) for t in a.tools}
             for a in root.sub_agents}
    # ADK adds one delegation tool per sub-agent; the planner holds nothing else.
    assert sorted(getattr(t, "name", "") for t in root.tools) == ["inventory", "remediation"]
    assert names["inventory"] == {"query_servers", "get_server", "query_users", "query_services",
                                  "list_change_windows", "search_policies"}
    assert "restart_service" in names["remediation"] and "query_users" not in names["remediation"]
    assert not names["inventory"] & {"restart_service", "drain_server", "delete_user", "erase_data"}

    run(root, "restart authd on core-use1-02")
    for request in SEEN:
        assert "transfer_to_agent" not in request.tools_dict or "remediation" in request.tools_dict


def test_no_tool_accepts_an_identity_argument(world):
    import inspect
    from agents.tools import read_tools, write_tools
    rt = runtime_for(world, "pnair")
    for tool in {**read_tools(rt, "inventory-01"), **write_tools(rt, "remediation-01")}.values():
        params = set(inspect.signature(tool).parameters)
        assert not params & {"user", "username_as", "as_user", "agent", "agent_id", "session",
                             "session_id", "credential", "token", "approval"}, tool.__name__
