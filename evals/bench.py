"""What the gateway costs: time added to every tool call.

    python -m evals.bench               print the table
    python -m evals.bench --json        also write evals/results/bench.json
    python -m evals.bench -n 5000       iterations per case (default 2000)

Measured end to end around Gateway.propose(): authenticate, validate, decide,
apply or refuse, and append the audit entry. Two columns matter. "buffered"
leaves the audit write to the OS; "fsync" forces each entry to disk before the
call returns, which is the setting the gateway ships with and where nearly all
of the time goes. Numbers depend on the machine and disk they are run on.
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from pathlib import Path

from .world import World

REM, INV = "remediation-01", "inventory-01"

CASES = [
    ("read, allowed", "pnair", INV, "get_server", {"host": "core-use1-02"}, {}),
    ("write (dry run), allowed", "pnair", REM, "restart_service",
     {"host": "app-usw2-32", "service": "nginx"}, {"dry_run": True}),
    ("denied: outside agent scope", "pnair", INV, "restart_service",
     {"host": "app-usw2-32", "service": "nginx"}, {}),
    ("denied: approval required", "pnair", REM, "restart_service",
     {"host": "core-use1-07", "service": "authd"}, {}),
    ("denied: invalid arguments", "pnair", REM, "restart_service",
     {"host": "app-usw2-32", "service": "nginx; rm -rf /"}, {}),
    ("denied: unauthenticated agent", "pnair", REM, "restart_service",
     {"host": "app-usw2-32", "service": "nginx"}, {"credential": "wrong"}),
]


def percentile(samples, q: float) -> float:
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))]


def run(n: int, durable: bool) -> list:
    rows = []
    for label, user, agent, command, args, extra in CASES:
        w = World(durable_audit=durable)
        try:
            for _ in range(50):                               # warm up
                w.call(user, agent, command, args, **extra)
            samples = []
            for _ in range(n):
                started = time.perf_counter()
                w.call(user, agent, command, args, **extra)
                samples.append((time.perf_counter() - started) * 1000)
            decide = [e["decision_ms"] for e in w.gw.audit.entries()[50:]]
            rows.append({"case": label, "n": n,
                         "p50_ms": round(percentile(samples, 0.50), 3),
                         "p95_ms": round(percentile(samples, 0.95), 3),
                         "p99_ms": round(percentile(samples, 0.99), 3),
                         "mean_ms": round(statistics.fmean(samples), 3),
                         "decide_only_p50_ms": round(percentile(decide, 0.50), 3)})
        finally:
            w.close()
    return rows


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    n = int(argv[argv.index("-n") + 1]) if "-n" in argv else 2000
    buffered = run(n, durable=False)
    durable = run(max(200, n // 10), durable=True)            # fsync is slow; fewer samples

    print(f"{'case':<32} {'decide p50':>10} | {'buffered p50':>12} {'p95':>7} {'p99':>7} | "
          f"{'fsync p50':>9} {'p95':>7} {'p99':>7}   (ms)")
    for b, d in zip(buffered, durable):
        print(f"{b['case']:<32} {b['decide_only_p50_ms']:>10.3f} | {b['p50_ms']:>12.3f} "
              f"{b['p95_ms']:>7.3f} {b['p99_ms']:>7.3f} | {d['p50_ms']:>9.3f} "
              f"{d['p95_ms']:>7.3f} {d['p99_ms']:>7.3f}")
    print(f"\n{n} calls per case buffered, {durable[0]['n']} with fsync · "
          f"{platform.system()} {platform.machine()} · Python {platform.python_version()}")

    if "--json" in argv:
        out = Path(__file__).resolve().parent / "results" / "bench.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps({
            "machine": f"{platform.system()} {platform.machine()}",
            "python": platform.python_version(),
            "buffered_audit": buffered, "fsync_audit": durable}, indent=2))
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
