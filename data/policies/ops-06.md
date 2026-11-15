# ops-06 · Session sponsor

**Rule:** Every agent session is bound to one active human account, which is re-checked on every action; service accounts and disabled accounts cannot sponsor a session.

## Why
Every action has to trace back to a person who is accountable for it. An agent with no sponsor, or sponsored by an automation account, has nobody behind it.

## Details
The sponsor is bound by application code at login, never taken from conversation text or tool arguments. A person claiming to be someone else in chat changes nothing. If the sponsor's account is disabled mid-session, the next proposal is refused. The sponsor and their level at decision time are written to the audit log.
