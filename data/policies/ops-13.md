# ops-13 · Blast radius for drains

**Rule:** A drain is refused if it would leave more than half of a team's servers in the same environment and tier out of rotation, and no approval lifts this limit.

## Why
Draining one server is safe. Draining servers one at a time until a service has no capacity is an outage built from individually approved steps.

## Details
The group is every server with the same owner team, environment and tier. Servers that are already down or draining count toward the limit. Restore a server before draining another when a group is at its limit.
