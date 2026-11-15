"""First-contact check for a model and its credentials.

    python -m agents.check

Runs one read-only question through the real agents on whatever FDE_MODEL
points at, against a throwaway copy of the world. It proves the credentials
work, the model can call tools, and the tool calls reach the gateway. Nothing
in data/ is touched. Exit status is 0 only if the model answered and at least
one proposal reached the gateway.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")
    except ImportError:
        pass
    from evals.models import Scenario, _run_one

    from .models import DEFAULT, build_model
    from .wiring import mode

    name = os.environ.get("FDE_MODEL", DEFAULT)
    vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").upper() in ("TRUE", "1")
    print(f"model      {name}")
    print(f"tools      {mode()}")
    if not name.startswith(("litellm:", "python:")):
        print(f"backend    {'Vertex AI' if vertex else 'Gemini API key'}")
        if vertex:
            print(f"project    {os.environ.get('GOOGLE_CLOUD_PROJECT') or 'NOT SET'}")
            print(f"location   {os.environ.get('GOOGLE_CLOUD_LOCATION') or 'NOT SET'}")
        else:
            print(f"api key    {'set' if os.environ.get('GOOGLE_API_KEY') else 'NOT SET'}")

    scenario = Scenario(
        "check", "tkim",
        "Which team owns the most servers below the minimum OS version? Use your tools.",
        frozenset())
    run = asyncio.run(_run_one(build_model(name), scenario, max_llm_calls=12, timeout=180))

    print(f"\ntime       {run['seconds']} s · {run['llm_calls']} model calls · "
          f"{run['prompt_tokens']} tokens in, {run['output_tokens']} out")
    print(f"gateway    {run['proposals']} proposals, {run['denied']} denied, "
          f"{len(run['applied'])} changes applied")
    if run["error"]:
        print(f"\nFAILED     {run['error']}")
        return 1
    print(f"\nanswer     {run['final'] or '(the model returned no text)'}")
    if run["proposals"] == 0:
        print("\nFAILED     the model answered without calling a tool; the expected answer "
              "(payments, 32 of 45) can only come from the inventory")
        return 1
    print("\nok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
