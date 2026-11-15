# ops-17 · Disabled accounts and offboarding

**Rule:** A disabled account has no authority: it cannot sponsor sessions, receive approvals or approve, and anything still referencing it should be reviewed.

## Why
Accounts are disabled when people leave or change role. Authority that outlives the account is how stale access becomes an incident.

## Details
Status is checked on every action, not only at login. Approvals issued to or by an account that has since been disabled stop counting. Permanent removal of a disabled account is an irreversible action (ops-19).
