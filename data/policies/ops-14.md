# ops-14 · Delegation narrows scope

**Rule:** A sub-agent's scope is the intersection of its own role and every agent above it in the delegation chain; delegation can only narrow authority.

## Why
If a planner could hand a sub-agent more than the planner itself holds, delegation would be a privilege escalation path.

## Details
The registry refuses to start if any agent's role exceeds its parent's scope. The same intersection is computed again at decision time, so a misconfigured registry still cannot widen authority. The delegation chain is recorded with every audit entry.
