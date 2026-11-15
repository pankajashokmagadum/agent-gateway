# ops-10 · Audit log

**Rule:** Every decision, allow or deny, and every approval issued is appended to a hash-chained audit log; an action whose audit record cannot be written does not happen.

## Why
A log that can be quietly edited is not evidence. Chaining each entry to the one before it makes edits, deletions and reordering detectable.

## Details
The log is `data/audit.jsonl`, one JSON entry per line, each carrying the hash of the previous entry. Verify with `python -m gateway.audit verify`. Entries record the sponsor, their level, the agent, its delegation chain, the command, arguments, decision, reasons, approvals used and decision time. A chain cannot detect entries removed from the very end; that needs the latest hash anchored somewhere the writer cannot reach.
