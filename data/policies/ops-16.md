# ops-16 · Service account privileges

**Rule:** Service accounts hold the lowest level that lets their job run and never hold admin; an admin-level service account is a finding to be corrected.

## Why
Automation credentials are long-lived and widely distributed. Over-privileged service accounts are the most common finding in access reviews.

## Details
List service accounts by level with the directory query. A service account found at admin level should be reported to its owning team and reduced. Service accounts cannot sponsor sessions (ops-06) or approve changes (ops-08) even when their level would otherwise allow it.
