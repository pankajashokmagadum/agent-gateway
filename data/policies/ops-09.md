# ops-09 · Argument validation

**Rule:** Command arguments are typed and checked before any rule runs, every server, user and service named must exist, and values are placed into fixed argument slots, never joined into a shell string.

## Why
The same lesson as SQL injection: a fixed statement with bound parameters cannot be rewritten by its inputs. A model's output is untrusted input.

## Details
Hostnames and usernames must match a strict pattern and resolve to a real row. Service names must be a known unit that is installed on the named server. Unknown parameters are refused. Each validated value fills exactly one slot of the command's argv template, so a value such as `nginx; rm -rf /` can only ever be one rejected argument.
