# ops-19 · Irreversible actions

**Rule:** Irreversible actions, such as deleting an account or erasing data, always need two approvals from two different admins, and only an admin may request them.

## Why
A reversible mistake costs minutes. An irreversible one cannot be bought back, so no single person, and no agent acting for one, can cause it alone.

## Details
This is the two-person rule. Both approvals must name the exact action and requester, and must come from two distinct active admins, neither of whom is the requester. Two approvals from the same admin count as one. The requirement applies in every environment, including staging and dev, and inside change windows.
