# ops-11 · Dry runs

**Rule:** A dry run goes through the same authorization as the real action but changes nothing, consumes no approval and uses no write budget.

## Why
People and agents should be able to ask "would this be allowed, and what exactly would run" without committing to it.

## Details
A dry run returns the argv that would execute. It is recorded in the audit log and marked as a dry run. Because it is authorized identically, a dry run that is denied tells you exactly what the real action would need.
