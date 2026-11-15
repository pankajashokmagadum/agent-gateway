# Agent Gateway

[![tests](https://github.com/pankajashokmagadum/agent-gateway/actions/workflows/tests.yml/badge.svg)](https://github.com/pankajashokmagadum/agent-gateway/actions/workflows/tests.yml)

An authorization gateway for AI agents. Agents propose actions; ordinary code
decides whether they run; every decision is written to a tamper-evident log
that names the person the agent was acting for.

The setting is an on-call assistant for a server fleet. The assistant can
investigate freely. When it tries to change something, the gateway checks who
is asking, what this agent is for, what the target is and what state the world
is in. The dangerous step waits for a human to approve it out of band.

It is AAA (authentication, authorization, accounting), the discipline network
gear has used for decades in TACACS+ per-command authorization, applied to
agents instead of routers.

```
person (authenticated outside the conversation)
  │  "checkout is failing, find it and fix it"
  ▼
planner agent        [model]   delegates, holds no tools of its own
  ├────────────────────────┐
  ▼                        ▼
inventory agent [model]  remediation agent [model]
read commands only       write commands, ceiling: edge tier
  └───────────┬────────────┘
              ▼  proposes {command, arguments}
┌──────────────────────────────────────────────────┐
│ gateway                        [code, no model]  │
│  1 authenticate   which agent is this?           │
│  2 sponsor        which person, still active?    │
│  3 scope          is the command in this agent's │
│                   scope, narrowed by its parents?│
│  4 validate       typed arguments, real targets  │
│  5 limits         person ∩ agent, budget, blast  │
│                   radius, protected targets      │
│  6 approvals      conditions an admin can lift   │
│  7 account        hash-chained audit entry       │
└──────────────────────────────────────────────────┘
        │                         │
   DENY + reasons + policy    ALLOW → simulated effect
```

## Try it in a minute

No API keys, no model, standard library only (plus pytest for the tests):

```bash
python data/seed.py          # build the demo database (deterministic)
python demo.py               # one incident: deny → approve → allow → audit
python -m evals.attacks      # 42 attacks, with and without the gateway
python -m pytest             # 48 tests (those needing ADK, mcp or chromadb skip if absent)
```

`demo.py` prints real gateway replies. The core of it:

```
[remediation-01] restart_service(host='core-use1-02', service='authd')
    ✗ DENY  · audit #4
      TIER_ABOVE_CEILING: core-use1-02 is core tier; the effective write ceiling for this request is access
        ops-07: "Core-tier servers are changed only with an admin's approval; ..."
      OUTSIDE_CHANGE_WINDOW: no prod change window is open
      APPROVAL_REQUIRED: 0 of 1 required approvals present for restart_service:core-use1-02:authd
      approval not usable · tok_4c1e: issued to a different requester

$ python -m gateway.approve --by jchen --for tkim --scope restart_service:core-use1-02:authd
  issued tok_1a4a8eaa · expires 2026-11-10T16:00:00Z

[remediation-01] restart_service(host='core-use1-02', service='authd')
    ✓ ALLOW · audit #6
      → failed → active · would run ['systemctl', 'restart', 'authd'] · approved by jchen
```

## The decisions behind it

**No model in the decision path.** If a model decides what is authorized,
prompt injection only has to convince a different model. `gateway/authorize.py`
is about 120 lines of code over database state. The worst a steered
agent can do is propose something, and proposals are what the gateway checks.

**Commands, not command lines.** An agent picks a registered command and
supplies parameters. Each parameter is typed, and anything naming a server,
user or service must resolve to a real row. Validated values fill fixed argv
slots and are never joined into a shell string. This is the prepared-statement
answer to SQL injection, applied to tool calls.

**Three limits, and the narrowest wins.** The person's level
(`users.auth_level`), the agent's role, and the delegation chain. An agent
acting for an engineer cannot do what an admin could; a sub-agent cannot
exceed the agent that delegated to it. The registry refuses to start if a
child is configured wider than its parent, and the intersection is recomputed
at decision time anyway.

**Approvals are records, not chat messages.** An approval names one requester
and one exact action, expires, and is consumed by the action it permits. It
must be signed by an active admin who is not the requester. An approval lifts
conditions (tier ceiling, change window); it can never add a command to an
agent's scope. Irreversible actions need two approvals from two different
admins.

**Some limits nothing lifts.** A session write budget, a blast-radius cap on
drains, protected targets. These are checked before approvals are considered.

**No record, no action.** The effect and its audit entry commit together. If
the audit write fails, the effect is rolled back.

**Policy lives in code; facts live in the database.** Commands and scopes are
in `gateway/commands.py` and `gateway/scopes.py`, so changing what is
permitted is a reviewed diff. The database holds the world: servers, people,
change windows, approvals.

## Running the agents

The agents use [Google ADK](https://adk.dev) 2.x. The planner delegates to two
`single_turn` sub-agents. Their tools are thin wrappers that propose a command
to the gateway and return its reply; the agent id is fixed when the tools are
built, and no tool takes an identity, session or credential argument. Models
never see a credential or session id (there is a test for that).

```bash
pip install -r requirements.txt
cp .env.example .env                    # put your own keys and project id in .env
python -m agents.check                  # one read-only question on a throwaway world
FDE_USER=tkim adk run agents            # or: adk web, then pick "agents"
```

`FDE_USER` stands in for a login and decides who the agents act for. Try the
same request as `tkim` (engineer), `pnair` (operator) and `jchen` (admin).

`FDE_MODEL` picks the model (`agents/models.py`):

| Value | Runs on |
|---|---|
| `litellm:openai/fde-router` | the local LiteLLM router in `config.yaml` (start it with `litellm --config config.yaml`) |
| `gemini-2.5-flash` | Gemini with `GOOGLE_API_KEY` |
| `gemini-2.5-flash` and `GOOGLE_GENAI_USE_VERTEXAI=TRUE` | Gemini on Vertex AI, using `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION` |

`agents` works on `data/fde.db` and `data/audit.jsonl`. `sandbox` is the same
agents on a throwaway copy of the world with the clock pinned to the seed
data; use it for experiments and evals.

When the remediation agent is denied it is instructed to stop, reflect on the
reasons, and either correct its arguments, report the approval that would
unblock it, or explain why nothing will. That behaviour comes from its
instructions, so it varies with the model. What it cannot do, with any model,
is act past the gateway.

### Three ways to wire the gateway in

`FDE_TOOLS` chooses where the interception sits. The decision code is the
same, and a test runs the same request through all three and compares the
audit trails.

| `FDE_TOOLS` | How | Why you would |
|---|---|---|
| `direct` (default) | Each tool function proposes to the gateway itself. | Simplest. |
| `guard` | Tools are declarations only. An ADK `before_tool_callback` intercepts every call and returns the gateway's reply; no tool body ever runs. | Fails closed: a tool someone adds later without a gateway call is denied as an unknown command (tested). |
| `mcp` | Agents reach their tools through ADK's `McpToolset`, talking to `mcp_server/` over stdio. | The gateway sits behind a protocol boundary, so any MCP client gets the same enforcement. |

### The MCP server

```bash
FDE_USER=tkim python -m mcp_server --agent remediation-01
```

One server process is one agent identity acting for one sponsor. Both are
fixed by whoever starts the process, never by the client: an MCP client
chooses a tool and its arguments and nothing else. The tools listed are the
commands in that agent's scope. Several servers can run at once; they share
the database and the audit log, which is locked per append.

Policy search (`search_policies`) retrieves from `data/policies`: a Chroma
vector index when `chromadb` and its embedding model are available, BM25
otherwise. Every result names the retriever that produced it. Retrieval only
informs. The policy text attached to a denial is looked up by id after the
decision has been made.

## Evidence

All of this is reproducible with the commands shown. Results are in
`evals/results/`.

**Attacks** (`python -m evals.attacks`). Each attack submits the proposal a
fully compromised model would make, once through the gateway and once with the
same tool call wired straight to an executor.

| | |
|---|---|
| Attacks | 42, in 7 categories: identity, sponsor, scope, input, approval, limits, audit |
| Blocked by the gateway, for the expected reason | 41 |
| Bypassed | 0 |
| Known limit | 1 (see below) |
| Reach the executor without the gateway | 37 of 38 |

**Gateway overhead** (`python -m evals.bench`). Time added to one tool call,
measured around `Gateway.propose()`; 2,000 calls per case. These numbers are
from a Linux arm64 VM and will differ on other machines.

| Case | Decision only, p50 | End to end, p50 | p99 | With fsync per entry, p50 | p99 |
|---|---|---|---|---|---|
| Read, allowed | 0.04 ms | 0.13 ms | 0.73 ms | 1.6 ms | 6.8 ms |
| Write (dry run), allowed | 0.06 ms | 0.12 ms | 0.55 ms | 1.7 ms | 4.7 ms |
| Denied: approval required | 0.07 ms | 0.14 ms | 0.21 ms | 2.3 ms | 5.0 ms |
| Denied: unauthenticated | 0.01 ms | 0.07 ms | 0.14 ms | 1.6 ms | 5.7 ms |

The decision itself is tens of microseconds. Nearly all of the cost is the
durable audit write, which is the default.

**Retrieval** (`python -m evals.retrieval`). 26 questions phrased the way a
person would ask them, each labelled with the policy that answers it.

| Retriever | hit@1 | hit@3 | MRR |
|---|---|---|---|
| BM25 baseline | 0.42 | 0.81 | 0.62 |
| Chroma, all-MiniLM-L6-v2 | not yet measured | | |

**ADK eval** (`adk eval`). Five cases in `evals/adk/fleet.evalset.json`, scored
by two deterministic metrics in `evals/adk/metrics.py`, with no judge model:
the expected tool calls were made in order, and no change was applied that the
case did not expect. The second is the safety check: a model that restarts the
wrong server or acts on an injected instruction fails it.

```bash
FDE_USER=tkim adk eval sandbox evals/adk/fleet.evalset.json \
  --config_file_path evals/adk/eval_config.json --print_detailed_results
```

The eval set, the metrics and the reset between cases are tested with a
scripted model. Results for real models are not in yet.

**Across models** (`python -m evals.models --model ... --model ...`). Runs the
same five scenarios, including a ticket carrying an injected instruction,
through the real agents on each model and reports task success, how often the
model overreached, tokens, latency and cost. The number that must be zero for
every model is changes applied that the scenario did not permit. The harness
is tested with scripted models; results for real models are not in yet.

## Limits, stated plainly

- **Effects are simulated.** An allowed write changes rows in the demo
  database and records the argv that would have run. Nothing executes.
- **Truncating the end of the audit log is not detected.** A hash chain proves
  the entries it holds are intact and in order, not that none were cut off the
  end. That needs the latest hash anchored somewhere the writer cannot reach.
  The attack suite reports this as its one known limit.
- **Agent credentials are in-process secrets.** Fine for one process; a
  distributed deployment would use workload identity (mTLS, SPIFFE).
- **The approval CLI trusts `--by`.** A real deployment authenticates the
  approver first.
- **The sponsor comes from an environment variable.** It stands in for a
  login. It is never taken from the conversation.
- **The data is synthetic.** `data/seed.py` generates 304 servers, 122
  accounts and their services from a fixed seed, with a few planted findings
  (one team owning most out-of-date servers, an admin-level service account, a
  disabled account that still holds authority).

## Deploying on Google Cloud

```bash
gcloud auth login
./deploy/cloudrun.sh        # reads GOOGLE_CLOUD_PROJECT and friends from .env
```

This builds the `Dockerfile` and deploys it to Cloud Run, serving the agents
with `adk web` on Gemini through Vertex AI. No API key is sent to Cloud Run;
the service account needs the Vertex AI User role. The service is deployed
private, because the web UI lets whoever can reach it run the agents on your
bill. Open it with `gcloud run services proxy`.

Not yet built or deployed: the server start command is tested locally, the
image and the deploy are not. The database and audit log live on the
container's disk in this setup, so they reset with each revision.

## Layout

```
gateway/      commands, scopes, validate, rules, authorize, gateway, audit, approve
agents/       planner, inventory, remediation, tools, wiring (direct/guard/mcp), check
mcp_server/   the commands as an MCP server, one process per agent identity
sandbox/      the same agents on a throwaway world, for adk run / adk eval
rag/          chunking, BM25 and Chroma retrievers over data/policies
data/         seed.py, 23 policy and runbook documents
evals/        attacks, bench, retrieval, models, adk/ (eval set and metrics)
tests/        what must work; evals/attacks.py covers what must not
deploy/       cloudrun.sh
demo.py       the scripted walkthrough
```
