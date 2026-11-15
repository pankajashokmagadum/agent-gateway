"""Which model the agents run on. The gateway does not care; that is the point.

FDE_MODEL=litellm:openai/fde-router   (default) the local LiteLLM router in config.yaml
FDE_MODEL=litellm:openai/fde-gemini   the hosted model, through the same router
FDE_MODEL=gemini-2.5-flash            Gemini directly. With GOOGLE_GENAI_USE_VERTEXAI=TRUE,
                                      GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION set, it
                                      runs on Vertex AI; otherwise it uses GOOGLE_API_KEY.
FDE_MODEL=python:pkg.module:Class     any ADK BaseLlm subclass, e.g. a scripted model in tests
"""

import importlib
import os

DEFAULT = "litellm:openai/fde-router"


def build_model(name: str = None):
    name = name or os.environ.get("FDE_MODEL", DEFAULT)
    if name.startswith("litellm:"):
        from google.adk.models.lite_llm import LiteLlm
        return LiteLlm(model=name[len("litellm:"):],
                       api_base=os.environ.get("FDE_LITELLM_BASE", "http://localhost:4000/v1"),
                       api_key=os.environ.get("LITELLM_MASTER_KEY"))
    if name.startswith("python:"):
        module, _, attr = name[len("python:"):].partition(":")
        return getattr(importlib.import_module(module), attr)()
    return name
