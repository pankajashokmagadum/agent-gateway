# ops-02 · Minimum operating system version

**Rule:** Every server must run Ubuntu 22.04 or later; servers below that are out of compliance and must be scheduled for upgrade.

## Why
Releases older than 22.04 no longer receive the security updates our baseline assumes. An out-of-date server is a finding in every access review and audit.

## Details
Compliance is checked against the `os_version` column of the inventory. Teams with out-of-compliance servers are expected to file an upgrade plan within one change window. Use the inventory query with the below-minimum filter to list affected servers by team. Upgrades themselves are changes and follow the change window policy (ops-03).
