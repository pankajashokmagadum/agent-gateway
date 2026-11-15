# ops-12 · Session write budget

**Rule:** A single agent session may make at most five changes; further changes are refused until a new session is opened.

## Why
Individually reasonable changes add up. An agent in a loop, or one steered by text it read, should run out of room quickly.

## Details
Only executed writes count. Reads, denials and dry runs do not. The budget is per session and is not lifted by approvals. If a task legitimately needs more than five changes, it should be split and reviewed by a person between sessions.
