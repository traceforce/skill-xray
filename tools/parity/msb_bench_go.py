"""Score the Go binary on the materialised MaliciousSkillBench split.

    python tools/parity/msb_bench_go.py --data <frozen snapshot> --corpus corpus/msb-test \
        --exe bin/skill-xray.exe --out out/msb_test_go.jsonl [--workers 6] [--compare py.jsonl]

Every manifest row of the materialised corpus becomes one row in benchmark/msb_run.py's
deterministic-mode shape (findings as vector/rule/severity/tier/line), so the oracle's
benchmark/msb_score.py scores the Go binary exactly as it scores the Python scanner. With
--compare, the Go rows are checked record by record against a Python run of the same split.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import msb_materialize  # noqa: E402

FIELDS = ("vector", "rule", "severity", "tier", "line")


def scan_one(exe, env, manifest_row, meta, corpus):
    row = {"benchmark_id": manifest_row["benchmark_id"], "split": manifest_row["split"],
           "label": int(manifest_row["label"]), "source_name": meta[0],
           "attack_categories": meta[1], "tlen": manifest_row["bytes"],
           "oversize": bool(manifest_row["oversize"]),
           "findings": [], "error": manifest_row["error"], "ledger_skipped": 0, "analyzed": 0,
           "elapsed_ms": 0}
    if row["error"]:
        return row
    root = os.path.join(corpus, manifest_row["package"])
    t0 = time.perf_counter()
    try:
        proc = subprocess.run([exe, "--analyze", "--json", root], capture_output=True, env=env,
                              timeout=600)
        if proc.returncode not in (0, 2):
            row["error"] = "exit %d: %s" % (proc.returncode,
                                            proc.stderr.decode("utf-8", "replace")[:200])
        else:
            doc = json.loads(proc.stdout.decode("utf-8"))
            row["ledger_skipped"] = doc["ledger"]["artifactsSkipped"]
            row["analyzed"] = doc["ledger"]["artifactsAnalyzed"]
            row["findings"] = [{k: f.get(k, "" if k == "vector" else None) for k in FIELDS}
                               for f in doc["findings"]]
    except Exception as exc:  # a crashing record is a coverage gap, recorded not hidden
        row["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
    row["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
    return row


def compare(go_rows, py_path):
    """Records whose findings, error, oversize or ledger_skipped differ between the two runs."""
    with open(py_path, encoding="utf-8") as fh:
        py = {r["benchmark_id"]: r for r in map(json.loads, fh) if r}
    def key(r):
        return (sorted(json.dumps([f.get(k) for k in FIELDS]) for f in r["findings"]),
                bool(r.get("error")), bool(r.get("oversize")), r.get("ledger_skipped", 0))
    missing = [r["benchmark_id"] for r in go_rows if r["benchmark_id"] not in py]
    differing = [r["benchmark_id"] for r in go_rows
                 if r["benchmark_id"] in py and key(r) != key(py[r["benchmark_id"]])]
    return len(py), missing, differing


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--exe", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--compare", metavar="PY_JSONL")
    args = ap.parse_args(argv)
    df = msb_materialize.load(args.data)
    meta = {rec.benchmark_id: (rec.source_name, list(rec.attack_categories)
                               if rec.attack_categories is not None
                               and not isinstance(rec.attack_categories, float) else [])
            for rec in df.itertuples(index=False)}
    with open(os.path.join(args.corpus, "manifest.jsonl"), encoding="utf-8") as fh:
        manifest = [json.loads(line) for line in fh if line.strip()]
    env = {k: v for k, v in os.environ.items() if not k.startswith("SKILLXRAY_LLM_")}
    exe = os.path.abspath(args.exe)
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(lambda m: scan_one(exe, env, m, meta[m["benchmark_id"]], args.corpus),
                             manifest))
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=True) + "\n")
    errors = sum(r["error"] is not None for r in rows)
    print("msb_bench_go: %d records, %d with errors, %.1fs -> %s" % (
        len(rows), errors, time.perf_counter() - t0, args.out))
    if args.compare:
        total, missing, differing = compare(rows, args.compare)
        print("compare: %d python rows, %d go rows missing there, %d records differ" % (
            total, len(missing), len(differing)))
        for bid in differing[:20]:
            print("  differs:", bid)
        return 1 if missing or differing else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
