# ops-07 · Tier write ceilings

**Rule:** Core-tier servers are changed only with an admin's approval; an agent's standing write authority stops at edge tier.

## Why
Core servers carry authentication and routing for everything else. A mistaken restart there is an outage for every team, so no agent holds standing authority over them.

## Details
Tiers rank access, edge, core. The write ceiling for a request is the lower of the sponsor's ceiling (ops-05) and the agent role's ceiling. A change to a server above that ceiling is held until an approval naming that exact action is present (ops-08). The denial names the scope string an approver needs.
