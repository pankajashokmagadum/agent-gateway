# ops-08 · Approvals

**Rule:** An approval is issued by an admin, out of band, for one requester and one exact action; it expires, is used once, and can never be issued or satisfied by the requester themselves.

## Why
Typing "yes, go ahead" into a chat leaves nothing verifiable. An approval is a record that can be checked in code and pointed at months later.

## Details
Issue with `python -m gateway.approve --by <admin> --for <requester> --scope <action>`. The scope names the command and target, for example `restart_service:core-use1-02:authd`. Default lifetime is two hours, maximum eight. An approval is rejected if it has expired, was already used, names a different action or requester, or if the approver is no longer an active admin. Service accounts cannot approve. Agents cannot issue approvals.
