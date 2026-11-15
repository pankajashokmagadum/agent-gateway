"""Look up the written rule behind a decision, by policy id.

This is a direct file read, not a search. The decision is already made by the
time this runs; it only attaches the text a human would want to see next to it.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Optional

from .config import POLICY_DIR

_RULE = re.compile(r"^\*\*Rule:\*\*\s*(.+)$", re.M)


@lru_cache(maxsize=None)
def clause(policy_id: Optional[str]) -> Optional[str]:
    if not policy_id or not re.fullmatch(r"[a-z]+-\d+", policy_id):
        return None
    path = POLICY_DIR / f"{policy_id}.md"
    if not path.is_file():
        return None
    match = _RULE.search(path.read_text(encoding="utf-8"))
    return match.group(1).strip() if match else None
