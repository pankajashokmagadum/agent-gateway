# ops-03 · Change windows

**Rule:** Changes to production servers are made inside a scheduled change window; outside a window a production change needs an approval, as an emergency change.

## Why
A change made while the on-call team is staffed and expecting it is recoverable. The same change at an arbitrary time becomes an incident with nobody ready.

## Details
The production window is weekly, Thursday 02:00 to 06:00 UTC. Staging and dev are always open. An approval from an admin (ops-08) stands in for the window when a change cannot wait: that is the emergency change path, and the approval is recorded with the action. Reads are never restricted by change windows.
