# ops-04 · Agent authentication

**Rule:** Every agent holds its own credential, and a proposal from an unknown agent or with a wrong credential is refused and recorded.

## Why
Shared API keys make every agent indistinguishable. If the read-only agent and the write agent present the same key, scope means nothing and the audit log cannot say who acted.

## Details
Each registered agent is issued one credential at startup. The gateway stores only a digest and compares in constant time. Credentials are never placed in prompts, tool arguments or model-visible text. In this demo agents run in one process; a distributed deployment would replace the shared secret with workload identity such as mTLS or SPIFFE.
