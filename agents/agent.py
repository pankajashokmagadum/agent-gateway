"""Entry point for `adk web` and `adk run agents`.

    FDE_USER=tkim adk run agents      act as tkim (engineer)
    FDE_USER=jchen adk web            act as jchen (admin), in the browser
"""

from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:                      # the gateway itself needs nothing from .env
    pass

from . import planner
from .models import build_model
from .runtime import start

runtime = start()
root_agent = planner.build(build_model(), runtime)
