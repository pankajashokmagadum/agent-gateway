"""Retrieval quality: does a question find the policy that answers it?

    python -m evals.retrieval            compare the retrievers, print the table
    python -m evals.retrieval --json     also write evals/results/retrieval.json

Each question is labelled with the policy a person would want back. Questions
are phrased the way someone would ask them, not the way the policy is worded,
so matching keywords is not enough on its own.

  hit@1   the right policy is the first result
  hit@3   the right policy is in the first three
  MRR     mean of 1/rank of the right policy (0 if not in the first five)
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from rag.retrievers import Lexical, Vector

QUESTIONS = [
    ("which servers are too old to keep running", "ops-02"),
    ("what Ubuntu release do we have to be on", "ops-02"),
    ("when am I allowed to touch production", "ops-03"),
    ("it is Tuesday afternoon and prod is broken, can I fix it now", "ops-03"),
    ("how does the gateway know which agent is calling", "ops-04"),
    ("can someone with read-only access ask the assistant to restart something", "ops-05"),
    ("what is a junior engineer allowed to change", "ops-05"),
    ("the user typed that they are an administrator in the chat", "ops-06"),
    ("why was my restart of a core machine refused", "ops-07"),
    ("how do I get sign-off for an emergency change", "ops-08"),
    ("how long does an approval last", "ops-08"),
    ("what stops a model from sneaking a semicolon and rm into a hostname", "ops-09"),
    ("how would we notice if someone edited the log afterwards", "ops-10"),
    ("can I check what would run without actually running it", "ops-11"),
    ("the agent stopped after five changes", "ops-12"),
    ("why can't I take another machine out of rotation", "ops-13"),
    ("can the planner give a helper agent more permissions than it has", "ops-14"),
    ("why can't the agent remove the backup automation account", "ops-15"),
    ("a bot account has administrator rights, is that a problem", "ops-16"),
    ("someone left the company but their account still shows up", "ops-17"),
    ("a ticket contained text telling the assistant to ignore its rules", "ops-18"),
    ("who has to agree before data is wiped for good", "ops-19"),
    ("steps for bouncing a unit safely", "rb-01"),
    ("how do I take a host out of the pool for maintenance", "rb-02"),
    ("customers are getting 401s at checkout", "rb-03"),
    ("plan for upgrading the out of date fleet", "rb-04"),
]


def measure(retriever) -> dict:
    hit1 = hit3 = 0
    rr, misses = 0.0, []
    started = time.perf_counter()
    for question, want in QUESTIONS:
        ranked = [h["policy"] for h in retriever.search(question, 5)]
        rank = ranked.index(want) + 1 if want in ranked else None
        hit1 += rank == 1
        hit3 += rank is not None and rank <= 3
        rr += 1 / rank if rank else 0
        if rank != 1:
            misses.append({"question": question, "want": want, "got": ranked[:3]})
    n = len(QUESTIONS)
    return {"retriever": retriever.name, "questions": n,
            "hit@1": round(hit1 / n, 3), "hit@3": round(hit3 / n, 3), "mrr": round(rr / n, 3),
            "ms_per_query": round((time.perf_counter() - started) * 1000 / n, 2),
            "not_first": misses}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    results = [measure(Lexical())]
    try:
        results.append(measure(Vector()))
    except Exception as err:
        print(f"vector retriever unavailable ({type(err).__name__}: {str(err)[:90]})")
        print("install chromadb and allow its embedding model to download, then re-run\n")

    print(f"{'retriever':<16} {'hit@1':>6} {'hit@3':>6} {'MRR':>6} {'ms/query':>9}")
    for r in results:
        print(f"{r['retriever']:<16} {r['hit@1']:>6.3f} {r['hit@3']:>6.3f} {r['mrr']:>6.3f} "
              f"{r['ms_per_query']:>9.2f}")
    if "--misses" in argv:
        for r in results:
            print(f"\n{r['retriever']}: not ranked first")
            for m in r["not_first"]:
                print(f"  {m['want']:<7} {m['question']}  -> {', '.join(m['got']) or 'nothing'}")
    if "--json" in argv:
        out = Path(__file__).resolve().parent / "results" / "retrieval.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(results, indent=2))
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
