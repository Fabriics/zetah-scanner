"""Scale benchmark (T-14): a generated tenant, read by the real collector from a simulated Graph, then scanned.

    python tests/scale_benchmark.py --identities 100000
    python tests/scale_benchmark.py --identities 100000 --no-expand   # Graph refuses the expanded listing

Not part of the test suite: it takes minutes and measures this machine. The simulated latency and throttling are
assumptions, printed with the results; see fake_graph.py.
"""

from __future__ import annotations

import argparse
import resource
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

import pytest  # noqa: E402

from fake_graph import FakeGraph, install  # noqa: E402
from src.nhi_scanner import collector  # noqa: E402
from src.nhi_scanner.demo import build_scale_snapshot  # noqa: E402
from src.nhi_scanner.engine import run_scan, write_payload_json  # noqa: E402
from src.nhi_scanner.pdf_report import write_pdf_report  # noqa: E402


def peak_mb() -> int:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(rss / 1e6 if sys.platform == "darwin" else rss / 1e3)  # bytes on macOS, KiB on Linux


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--identities", type=int, default=100_000)
    p.add_argument("--latency", type=float, default=0.15, help="seconds per request (default 0.15)")
    p.add_argument("--per-object", type=float, default=0.0015, help="seconds per object returned (default 0.0015)")
    p.add_argument("--ru", type=int, default=8000, help="resource units per 10 seconds (default 8000)")
    p.add_argument("--no-expand", action="store_true", help="Graph refuses $expand=federatedIdentityCredentials")
    args = p.parse_args()

    rows: list[tuple[str, str]] = []
    t = time.perf_counter()

    def step(name: str, detail: str = "") -> None:
        nonlocal t
        rows.append((name, f"{time.perf_counter() - t:.1f} s{detail}, peak {peak_mb()} MB"))
        t = time.perf_counter()

    tenant = build_scale_snapshot(args.identities)
    step("Generate the tenant")
    graph = FakeGraph(tenant, base_latency=args.latency, per_object=args.per_object, ru_per_10s=args.ru,
                      expand_federation=not args.no_expand)
    mp = pytest.MonkeyPatch()
    install(mp, graph)
    try:
        snap = collector.collect(include_azure_rbac=False)
    finally:
        mp.undo()
    kinds = ", ".join(f"{n} {k}" for k, n in sorted(graph.stats.by_kind.items()))
    step("Collect from the simulated Graph", f" ({graph.stats.requests} requests: {kinds}; "
                                             f"{graph.stats.throttled} throttled)")
    del tenant, graph
    payload = run_scan(snap)
    step("Scan", f" ({len(payload.entities)} identities, {len(payload.findings)} findings)")
    with tempfile.TemporaryDirectory() as out:
        write_payload_json(payload, Path(out) / "scan.json")
        size = (Path(out) / "scan.json").stat().st_size // 1_000_000
        step("Write the JSON payload", f" ({size} MB)")
        write_pdf_report(payload, Path(out) / "report.pdf")
        step("Write the PDF report")

    print(f"Assumptions: {args.latency}s per request + {args.per_object}s per object returned, "
          f"{args.ru} resource units per 10 s, {collector.PARALLEL_READS} reads in parallel, "
          f"expanded federated credentials {'refused' if args.no_expand else 'accepted'}.\n")
    print("| Step | Result |\n|---|---|")
    for name, result in rows:
        print(f"| {name} | {result} |")
    if snap.warnings:
        print("\nWarnings:", *snap.warnings, sep="\n- ")


if __name__ == "__main__":
    main()
