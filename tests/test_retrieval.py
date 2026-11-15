"""Retrieval: chunking, the BM25 baseline, the Chroma index, and the fallback."""

import hashlib
import math

import pytest

from evals.world import World
from gateway.policies import clause
from rag.corpus import fingerprint, load
from rag.retrievers import Lexical, _tokens, make_policy_search


def test_every_policy_the_gateway_cites_exists_and_has_a_rule():
    import gateway.authorize, gateway.commands, gateway.gateway, gateway.rules   # noqa: E401
    import inspect, re
    cited = set()
    for module in (gateway.authorize, gateway.commands, gateway.gateway, gateway.rules):
        cited |= set(re.findall(r'"((?:ops|rb)-\d+)"', inspect.getsource(module)))
    assert cited, "expected the gateway to cite policies"
    for policy in sorted(cited):
        assert clause(policy), f"{policy} is cited but has no document with a **Rule:** line"


def test_chunks_cover_every_document():
    chunks = load()
    policies = {c.policy for c in chunks}
    assert len(policies) == 23
    assert all(any(c.policy == p and c.section == "Rule" for c in chunks) for p in policies)
    assert len({c.id for c in chunks}) == len(chunks)
    assert fingerprint(chunks) == fingerprint(load())


def test_lexical_finds_the_obvious_policy():
    lx = Lexical()
    assert lx.search("two admins irreversible delete account", 1)[0]["policy"] == "ops-19"
    assert lx.search("session write budget of five changes", 1)[0]["policy"] == "ops-12"
    assert lx.search("zzzz qqqq", 3) == []


class HashEmbedding:
    """Deterministic bag-of-words vectors: enough to exercise the index offline."""

    def __init__(self, dim=256):
        self.dim = dim

    def name(self):
        return "hash-bow"

    def _one(self, text):
        v = [0.0] * self.dim
        for t in _tokens(text):
            v[int(hashlib.md5(t.encode()).hexdigest(), 16) % self.dim] += 1.0
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / norm for x in v]

    def __call__(self, input):
        return [self._one(t) for t in input]

    def embed_query(self, input):
        return self(input)

    def embed_documents(self, input):
        return self(input)


def test_vector_index_builds_queries_and_rebuilds(tmp_path):
    pytest.importorskip("chromadb")
    from rag.retrievers import Vector
    chunks = load()
    v = Vector(chunks, path=tmp_path / "chroma", embedding_function=HashEmbedding())
    assert v.collection.count() == len(chunks)
    top = v.search("irreversible actions need two approvals from two different admins", 3)
    assert top[0]["policy"] == "ops-19" and len({h["policy"] for h in top}) == len(top)

    again = Vector(chunks, path=tmp_path / "chroma", embedding_function=HashEmbedding())
    assert again.collection.count() == len(chunks)          # reused, not duplicated

    fewer = chunks[:-3]                                     # the corpus changed
    rebuilt = Vector(fewer, path=tmp_path / "chroma", embedding_function=HashEmbedding())
    assert rebuilt.collection.count() == len(fewer)


def test_search_policies_command_reports_its_backend():
    w = World()
    try:
        w.gw.policy_search = make_policy_search(backend="lexical")
        reply = w.call("tkim", "inventory-01", "search_policies",
                       {"query": "who must approve erasing data"})
        assert reply["decision"] == "ALLOW"
        hits = reply["result"]["results"]
        assert hits[0]["policy"] == "ops-19" and hits[0]["backend"] == "lexical-bm25"
    finally:
        w.close()


def test_denials_carry_the_policy_text():
    w = World()
    try:
        reply = w.call("pnair", "remediation-01", "restart_service",
                       {"host": "core-use1-07", "service": "authd"})
        by_code = {r["code"]: r for r in reply["reasons"]}
        assert by_code["TIER_ABOVE_CEILING"]["policy"] == "ops-07"
        assert "Core-tier servers" in by_code["TIER_ABOVE_CEILING"]["policy_text"]
        assert "change window" in by_code["OUTSIDE_CHANGE_WINDOW"]["policy_text"]
    finally:
        w.close()
