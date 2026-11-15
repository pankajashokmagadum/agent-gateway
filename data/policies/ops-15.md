# ops-15 · Protected targets

**Rule:** Service accounts cannot be deleted through an agent, and a session can never delete its own sponsor's account, whatever approvals are present.

## Why
Service account lifecycle belongs to the automation that owns the account; deleting one by hand breaks whatever depends on it. Self-deletion removes the accountable person from their own audit trail.

## Details
These are hard limits. They are checked before approvals are considered and no approval lifts them.
