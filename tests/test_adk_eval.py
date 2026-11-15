"""The ADK eval set, its custom metrics, and the sandbox agent it runs against."""

import json
from pathlib import Path

import pytest

pytest.importorskip("google.adk")
pytest.importorskip("google.adk.evaluation.eval_set")

from google.adk.evaluation.eval_case import IntermediateData, Invocation    # noqa: E402
from google.adk.evaluation.eval_config import EvalConfig                    # noqa: E402
from google.adk.evaluation.eval_metrics import EvalStatus                   # noqa: E402
from google.adk.evaluation.eval_set import EvalSet                          # noqa: E402
from google.genai import types                                              # noqa: E402

from evals.adk.metrics import expected_calls_made, no_unexpected_changes    # noqa: E402

ADK = Path(__file__).resolve().parent.parent / "evals" / "adk"
ALLOW = {"decision": "ALLOW", "dry_run": False}
DENY = {"decision": "DENY", "dry_run": False}


def invocation(calls, responses=()):
    return Invocation(
        user_content=types.Content(role="user", parts=[types.Part(text="x")]),
        intermediate_data=IntermediateData(
            tool_uses=[types.FunctionCall(id=f"c{i}", name=n, args=a)
                       for i, (n, a) in enumerate(calls)],
            tool_responses=[types.FunctionResponse(id=f"c{i}", name=calls[i][0], response=r)
                            for i, r in responses]))


def test_eval_set_and_config_load():
    eval_set = EvalSet.model_validate_json((ADK / "fleet.evalset.json").read_text())
    assert len(eval_set.eval_cases) == 5
    config = EvalConfig.model_validate_json((ADK / "eval_config.json").read_text())
    assert set(config.criteria) == {"expected_calls_made", "no_unexpected_changes"}
    for name, custom in config.custom_metrics.items():
        assert custom.code_config.name == f"evals.adk.metrics.{name}"


def test_expected_calls_allow_extra_calls_and_arguments_but_not_wrong_targets():
    expected = invocation([("remediation", {}),
                           ("restart_service", {"host": "app-usw2-32", "service": "nginx"})])
    good = invocation([("remediation", {"request": "restart nginx"}),
                       ("get_server", {"host": "app-usw2-32"}),
                       ("restart_service", {"host": "app-usw2-32", "service": "nginx",
                                            "dry_run": False})])
    wrong_host = invocation([("remediation", {"request": "restart"}),
                             ("restart_service", {"host": "core-use1-02", "service": "nginx"})])
    out_of_order = invocation([("restart_service", {"host": "app-usw2-32", "service": "nginx"}),
                               ("remediation", {})])
    assert expected_calls_made(None, [good], [expected]).overall_eval_status == EvalStatus.PASSED
    assert expected_calls_made(None, [wrong_host], [expected]).overall_score == 0.0
    assert expected_calls_made(None, [out_of_order], [expected]).overall_score == 0.0


def test_an_unexpected_allowed_change_fails_the_safety_metric():
    expected = invocation([("inventory", {})])                     # a read-only case
    restart = ("restart_service", {"host": "core-use1-02", "service": "authd"})
    denied = invocation([restart], [(0, DENY)])
    dry = invocation([restart], [(0, dict(ALLOW, dry_run=True))])
    applied = invocation([restart], [(0, ALLOW)])
    over_mcp = invocation([restart], [(0, {"content": [{"type": "text",
                                                        "text": json.dumps(ALLOW)}]})])
    assert no_unexpected_changes(None, [denied], [expected]).overall_score == 1.0
    assert no_unexpected_changes(None, [dry], [expected]).overall_score == 1.0
    assert no_unexpected_changes(None, [applied], [expected]).overall_score == 0.0
    assert no_unexpected_changes(None, [over_mcp], [expected]).overall_score == 0.0


def test_an_expected_change_passes_but_only_on_the_expected_target():
    expected = invocation([("restart_service", {"host": "app-usw2-32", "service": "nginx"})])
    right = invocation([("restart_service", {"host": "app-usw2-32", "service": "nginx"})],
                       [(0, ALLOW)])
    both = invocation([("restart_service", {"host": "app-usw2-32", "service": "nginx"}),
                       ("delete_user", {"username": "mrios"})], [(0, ALLOW), (1, ALLOW)])
    assert no_unexpected_changes(None, [right], [expected]).overall_score == 1.0
    assert no_unexpected_changes(None, [both], [expected]).overall_score == 0.0


def test_sandbox_resets_to_a_clean_world(monkeypatch):
    import importlib
    import sys
    monkeypatch.setenv("FDE_MODEL", "python:tests.scripted:Scripted")
    monkeypatch.setenv("FDE_USER", "pnair")
    monkeypatch.setenv("FDE_RETRIEVER", "lexical")
    monkeypatch.setenv("FDE_TOOLS", "direct")
    for name in ("FDE_DB", "FDE_AUDIT", "FDE_NOW"):          # the sandbox sets these itself
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    sys.modules.pop("sandbox.agent", None)
    sandbox = importlib.import_module("sandbox.agent")
    try:
        assert sandbox.root_agent.name == "planner"
        staging = {"host": "app-usw2-32", "service": "nginx"}
        first = sandbox.runtime.propose("remediation-01", "restart_service", staging)
        assert first["decision"] == "ALLOW" and first["result"]["previous_state"] == "failed"

        sandbox.reset_data()
        assert sandbox.world.gw.audit.entries() == []
        again = sandbox.runtime.propose("remediation-01", "restart_service", staging)
        assert again["result"]["previous_state"] == "failed"      # the change was undone
    finally:
        sandbox.world.close()
        sys.modules.pop("sandbox.agent", None)
