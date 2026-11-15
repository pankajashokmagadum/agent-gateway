# ops-05 · Human authority levels

**Rule:** An agent acting for a person can never do more than that person could: viewers may not request changes, engineers may change access tier, operators up to edge tier, and only admins may request irreversible actions.

## Why
An assistant must not become a way around the org chart. If a viewer could ask an agent to restart a server, the agent would be a privilege escalation path.

## Details
Levels come from `users.auth_level`. The effective limit for any request is the narrower of the person's level and the agent's role. Anyone with an active account can ask questions and run read commands. Write requests above a person's tier ceiling need an approval (ops-08). Irreversible actions (risk 2) are limited to admin sponsors regardless of approvals.
