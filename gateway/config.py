"""Paths, limits and the clock. Everything the gateway treats as configuration."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("FDE_DB", ROOT / "data" / "fde.db"))
AUDIT_PATH = Path(os.environ.get("FDE_AUDIT", ROOT / "data" / "audit.jsonl"))
POLICY_DIR = ROOT / "data" / "policies"

MIN_OS = "22.04"            # ops-02: servers below this are out of compliance
WRITE_BUDGET = 5            # ops-12: allowed writes per session
MAX_UNAVAILABLE = 0.5       # ops-13: share of a service group that may be out of rotation
READ_LIMIT = 25             # rows returned to a model per query


def utcnow() -> datetime:
    """Current time. FDE_NOW pins it, so tests and demos are reproducible."""
    pinned = os.environ.get("FDE_NOW")
    if pinned:
        return parse_ts(pinned)
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))
