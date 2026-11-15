"""Load the policy documents and split them into retrievable chunks.

One chunk for each document's rule, and one for each `##` section under it.
Every chunk carries the document title, so a short section still says what
it is about.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from gateway.config import POLICY_DIR

_TITLE = re.compile(r"^#\s+(\S+)\s+·\s+(.+)$", re.M)
_RULE = re.compile(r"^\*\*Rule:\*\*\s*(.+)$", re.M)
_SECTION = re.compile(r"^##\s+(.+)$", re.M)


@dataclass(frozen=True)
class Chunk:
    id: str          # e.g. ops-07#details
    policy: str      # e.g. ops-07
    title: str
    section: str
    text: str        # title, section name and body: what gets indexed

    @property
    def body(self) -> str:
        return self.text.split("\n", 1)[1] if "\n" in self.text else self.text


def load(policy_dir: Path = POLICY_DIR) -> list:
    chunks = []
    for path in sorted(Path(policy_dir).glob("*.md")):
        text = path.read_text(encoding="utf-8")
        title = _TITLE.search(text)
        if title is None:
            continue
        policy, name = title.group(1), title.group(2).strip()
        rule = _RULE.search(text)
        if rule:
            chunks.append(Chunk(f"{policy}#rule", policy, name, "Rule",
                                f"{name}. Rule\n{rule.group(1).strip()}"))
        parts = _SECTION.split(text)[1:]            # [heading, body, heading, body, ...]
        for heading, body in zip(parts[0::2], parts[1::2]):
            body = " ".join(body.split())
            if body:
                chunks.append(Chunk(f"{policy}#{heading.strip().lower()}", policy, name,
                                    heading.strip(), f"{name}. {heading.strip()}\n{body}"))
    return chunks


def fingerprint(chunks) -> str:
    """Changes whenever any chunk changes, so a stale index is rebuilt."""
    digest = hashlib.sha256()
    for c in chunks:
        digest.update(c.id.encode() + b"\0" + c.text.encode() + b"\0")
    return digest.hexdigest()[:16]
