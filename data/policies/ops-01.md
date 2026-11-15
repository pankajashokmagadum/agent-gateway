# ops-01 · Command registry and agent scope

**Rule:** An agent may only propose commands that are in the registry and inside its own scope; anything else is refused before arguments are read.

## Why
Agents do not get a shell. They choose from a fixed list of named commands, and each agent role is granted a subset of that list. An agent that proposes a command it was never granted has either been misconfigured or steered, and both cases are treated the same way.

## Details
The registry lives in `gateway/commands.py` and the grants in `gateway/scopes.py`. Both are code, so adding a command or widening a role is a reviewed change. The inventory agent holds read commands only. The remediation agent holds the write commands. No approval can add a command to an agent's scope: approvals satisfy conditions on commands the agent already holds.
