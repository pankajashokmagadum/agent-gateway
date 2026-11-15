"""Two retrievers over the same chunks.

Vector   embeddings in a Chroma collection, cosine similarity
Lexical  BM25 over word tokens, no dependencies

Both return whole policies ranked by their best-matching chunk. The lexical
retriever is the baseline the vector retriever is measured against in
evals/retrieval.py, and the fallback when chromadb or its embedding model is
not available.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Callable, Optional

from gateway.config import ROOT

from .corpus import fingerprint, load

CHROMA_DIR = ROOT / "data" / "chroma"
_WORD = re.compile(r"[a-z0-9]+")
_STOP = frozenset("a an and are as at be by can do does for from how i if in is it may my "
                  "of on or should that the this to was what when which who why with".split())


def _tokens(text: str) -> list:
    return [t for t in _WORD.findall(text.lower()) if t not in _STOP]


def _by_policy(scored, chunks, k: int) -> list:
    """Collapse ranked chunks to ranked policies, keeping each policy's best chunk."""
    out, seen = [], set()
    for score, index in scored:
        chunk = chunks[index]
        if chunk.policy in seen:
            continue
        seen.add(chunk.policy)
        out.append({"policy": chunk.policy, "title": chunk.title, "section": chunk.section,
                    "text": chunk.body, "score": round(float(score), 4)})
        if len(out) == k:
            break
    return out


class Lexical:
    name = "lexical-bm25"

    def __init__(self, chunks=None, k1: float = 1.5, b: float = 0.75):
        self.chunks = chunks if chunks is not None else load()
        self.k1, self.b = k1, b
        self.docs = [Counter(_tokens(c.text)) for c in self.chunks]
        self.lengths = [sum(d.values()) for d in self.docs]
        self.avg = sum(self.lengths) / max(len(self.docs), 1)
        df = Counter(term for d in self.docs for term in d)
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def search(self, query: str, k: int = 3) -> list:
        terms = _tokens(query)
        scored = []
        for i, doc in enumerate(self.docs):
            score = 0.0
            for t in terms:
                tf = doc.get(t, 0)
                if tf:
                    norm = tf + self.k1 * (1 - self.b + self.b * self.lengths[i] / self.avg)
                    score += self.idf[t] * tf * (self.k1 + 1) / norm
            if score > 0:
                scored.append((score, i))
        scored.sort(key=lambda s: (-s[0], s[1]))
        return _by_policy(scored, self.chunks, k)


class Vector:
    """Chroma collection over the chunks.

    `embedding_function` defaults to Chroma's built-in local model
    (all-MiniLM-L6-v2, downloaded on first use). The index is rebuilt whenever
    the policy files change.
    """
    name = "vector-chroma"

    def __init__(self, chunks=None, path: Optional[Path] = CHROMA_DIR,
                 embedding_function=None):
        import chromadb                                   # optional dependency

        self.chunks = chunks if chunks is not None else load()
        client = chromadb.PersistentClient(path=str(path)) if path else chromadb.Client()
        kwargs = {"embedding_function": embedding_function} if embedding_function else {}
        stamp = fingerprint(self.chunks)
        name = "policies"
        existing = {c.name for c in client.list_collections()}
        if name in existing:
            collection = client.get_collection(name, **kwargs)
            stale = (collection.metadata or {}).get("fingerprint") != stamp
            if stale or collection.count() != len(self.chunks):
                client.delete_collection(name)
                existing.discard(name)
        if name not in existing:
            collection = client.create_collection(
                name, metadata={"fingerprint": stamp, "hnsw:space": "cosine"}, **kwargs)
            try:
                collection.add(ids=[c.id for c in self.chunks],
                               documents=[c.text for c in self.chunks],
                               metadatas=[{"policy": c.policy} for c in self.chunks])
            except Exception:
                client.delete_collection(name)      # never leave a half-built index behind
                raise
        self.collection = collection
        self.index = {c.id: i for i, c in enumerate(self.chunks)}

    def search(self, query: str, k: int = 3) -> list:
        n = min(len(self.chunks), max(k * 4, 8))        # several chunks can share a policy
        found = self.collection.query(query_texts=[query], n_results=n)
        scored = [(1.0 - distance, self.index[chunk_id])
                  for chunk_id, distance in zip(found["ids"][0], found["distances"][0])]
        return _by_policy(scored, self.chunks, k)


def make_policy_search(backend: str = "auto", k: int = 3) -> Callable:
    """The search function handed to the gateway for the search_policies command.

    "auto" uses the vector index when it works and BM25 otherwise. The backend
    actually used is named in every result, so a fallback is never silent.
    """
    state = {"retriever": None}

    def retriever():
        if state["retriever"] is None:
            if backend in ("auto", "vector"):
                try:
                    candidate = Vector()
                    candidate.search("probe", 1)          # forces the embedding model to load
                    state["retriever"] = candidate
                except Exception:
                    if backend == "vector":
                        raise
            if state["retriever"] is None:
                state["retriever"] = Lexical()
        return state["retriever"]

    def search(query: str) -> list:
        r = retriever()
        return [dict(hit, backend=r.name) for hit in r.search(query, k)]

    return search
