"""The three agents. `agent.py` is the entry point ADK loads.

`agent` is imported on first use rather than here: importing it opens the
real database and builds the model, which the tests and the MCP server do not
want as a side effect of `import agents.tools`.
"""

import importlib


def __getattr__(name):
    if name == "agent":
        return importlib.import_module(".agent", __name__)
    raise AttributeError(name)
