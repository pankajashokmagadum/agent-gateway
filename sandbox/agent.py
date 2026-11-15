"""The same agents against a throwaway copy of the seeded world.

    FDE_USER=tkim adk run sandbox
    FDE_USER=tkim adk eval sandbox evals/adk/fleet.evalset.json \\
        --config_file_path evals/adk/eval_config.json --print_detailed_results

Unlike `agents`, nothing here touches data/fde.db or data/audit.jsonl. The
clock is pinned to the moment the seed data is anchored to, so approvals and
change windows are the same on every run. ADK's eval runner calls reset_data()
between cases, so every case starts from the same world.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:                 # `adk eval` does not add the repo root
    sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

from agents import planner                    # noqa: E402
from agents.models import build_model         # noqa: E402
from agents.runtime import DEFAULT_USER, Runtime   # noqa: E402
from evals.world import NOW, World            # noqa: E402
from gateway.config import iso                # noqa: E402
from rag import make_policy_search            # noqa: E402

USER = os.environ.get("FDE_USER", DEFAULT_USER)


def _fresh_world() -> World:
    world = World()
    world.gw.policy_search = make_policy_search(os.environ.get("FDE_RETRIEVER", "auto"))
    # For FDE_TOOLS=mcp: the server process must look at this world, not data/.
    os.environ.update(FDE_DB=str(world.db_path), FDE_AUDIT=str(world.audit_path),
                      FDE_NOW=iso(NOW))
    return world


world = _fresh_world()
runtime = Runtime(world.gw, USER, world.session(USER), world.creds)
root_agent = planner.build(build_model(), runtime)


def reset_data() -> None:
    """Start the next eval case from a clean world. The tools hold `runtime`,
    so swapping what it points at is enough. (In mcp mode the server process
    keeps the world it started with.)"""
    global world
    old, world = world, _fresh_world()
    runtime.gateway = world.gw
    runtime.session_id = world.session(USER)
    runtime.credentials = world.creds
    old.close()
