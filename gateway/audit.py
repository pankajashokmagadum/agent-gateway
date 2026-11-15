"""Append-only, hash-chained audit log.

One JSON object per line. Each entry carries the hash of the entry before it,
so changing or removing any earlier line breaks every hash after it.

    python -m gateway.audit verify      check the whole chain
    python -m gateway.audit tail [n]    show the last n entries

Limit worth knowing: a chain proves the entries it holds are intact and in
order. It cannot prove nothing was cut off the end. Detecting that needs the
latest hash to be stored somewhere the writer cannot reach.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sys
from pathlib import Path

from .config import AUDIT_PATH

GENESIS = "0" * 64


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _last_line(handle) -> bytes:
    handle.seek(0, os.SEEK_END)
    end = handle.tell()
    if end == 0:
        return b""
    pos, chunk = end, b""
    while pos > 0 and chunk.count(b"\n") < 2:
        step = min(4096, pos)
        pos -= step
        handle.seek(pos)
        chunk = handle.read(step) + chunk
    lines = [ln for ln in chunk.split(b"\n") if ln.strip()]
    return lines[-1] if lines else b""


class AuditLog:
    def __init__(self, path: Path = AUDIT_PATH, durable: bool = True):
        self.path = Path(path)
        self.durable = durable
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, entry: dict) -> dict:
        """Chain `entry` onto the log and return it with seq, prev_hash and hash.

        The file lock makes this safe across processes: the gateway and the
        approval CLI both write here.
        """
        with open(self.path, "a+b") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                last = _last_line(handle)
                prev = json.loads(last) if last else None
                record = dict(entry)
                record["seq"] = prev["seq"] + 1 if prev else 1
                record["prev_hash"] = prev["hash"] if prev else GENESIS
                record["hash"] = entry_hash(record)
                handle.seek(0, os.SEEK_END)
                handle.write(_canonical(record) + b"\n")
                handle.flush()
                if self.durable:
                    os.fsync(handle.fileno())
                return record
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def entries(self) -> list:
        if not self.path.exists():
            return []
        with open(self.path, "r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]


def verify(path: Path = AUDIT_PATH):
    """Return (ok, entries_checked, problem)."""
    path = Path(path)
    if not path.exists():
        return True, 0, None
    prev_hash, expected_seq, count = GENESIS, 1, 0
    with open(path, "r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, count, f"line {line_no}: not valid JSON"
            if entry.get("seq") != expected_seq:
                return False, count, (f"line {line_no}: expected seq {expected_seq}, "
                                      f"found {entry.get('seq')}")
            if entry.get("prev_hash") != prev_hash:
                return False, count, f"seq {expected_seq}: does not link to the entry before it"
            if entry.get("hash") != entry_hash(entry):
                return False, count, f"seq {expected_seq}: contents do not match the hash"
            prev_hash, expected_seq, count = entry["hash"], expected_seq + 1, count + 1
    return True, count, None


def _summary(e: dict) -> str:
    if e.get("event") == "approval_issued":
        return (f"{e['seq']:>4}  {e['ts']}  APPROVAL  {e['token']}  {e['approved_by']} -> "
                f"{e['requested_by']}  {e['scope']}")
    codes = ",".join(r["code"] for r in e.get("reasons", [])) or "-"
    mark = "ALLOW" if e.get("decision") == "ALLOW" else "DENY "
    dry = " (dry run)" if e.get("dry_run") else ""
    return (f"{e['seq']:>4}  {e['ts']}  {mark}  {e.get('human') or '?':<8} "
            f"{e.get('agent') or '?':<15} {e.get('command')}{dry}  {codes}")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    action = argv[0] if argv else "verify"
    if action == "verify":
        ok, count, problem = verify()
        if ok:
            print(f"chain ok · {count} entries · no breaks")
            return 0
        print(f"CHAIN BROKEN after {count} good entries · {problem}")
        return 1
    if action == "tail":
        n = int(argv[1]) if len(argv) > 1 else 10
        for entry in AuditLog().entries()[-n:]:
            print(_summary(entry))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
