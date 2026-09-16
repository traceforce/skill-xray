"""Run skill-xray over leolee99/NotInject (339 benign prompts built around injection trigger
words) and score the injection-class false-positive rate.

Each prompt becomes a one-file package (SKILL.md = front matter + prompt), is scanned in-process
and removed; nothing is executed. The three level splits (one / two / three trigger words) are
the whole dataset; the Hub's train / validation / test files repeat the same rows and are ignored.

    python benchmark/adapters/notinject_run.py --data <snapshot dir> --out <jsonl> [--workers 4]
    python benchmark/adapters/notinject_run.py --score <jsonl> [--summary SUMMARY.json]

Headline: an injection-class vector (``INJECTION``) at severity >= medium on a benign text, with
an exact Clopper-Pearson 95% CI. Also reported: injection-class at any severity, any real vector
at MEDIUM+ / HIGH+ / CRITICAL, and the blocking verdict.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import sys
import tempfile
import time
import traceback
from collections import Counter
from multiprocessing import Pool

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from skill_xray.ingest import build_package  # noqa: E402
from skill_xray.parse import parse_package  # noqa: E402
from skill_xray.scan import scan  # noqa: E402

DATASET = "leolee99/NotInject"
REVISION = "847ae76cf8fea5ed325429e569ae8cfef022d2e0"
LEVELS = ("one", "two", "three")
INJECTION = {"SXV-027", "SXV-028", "SXV-029", "SXV-030", "SXV-031", "SXV-041", "SXV-042",
             "SXV-043"}
_MP = {"medium", "high", "critical"}
_HC = {"high", "critical"}
_ATTACK = {"T1", "T2"}
_KEYS = ("vector", "rule", "severity", "tier", "line")


def scan_one(rec):
    """Materialize <work>/<id>/SKILL.md from the prompt, scan it, delete it."""
    row = {"id": rec["id"], "label": 0, "category": rec["category"], "level": rec["level"],
           "triggers": rec["triggers"], "tlen": len(rec["text"]), "findings": [], "error": None}
    root = os.path.join(rec["work"], rec["id"])
    path = os.path.join(root, "SKILL.md")
    try:
        os.makedirs(root, exist_ok=True)
        body = "---\nname: %s\n---\n%s" % (rec["id"], rec["text"])
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(body)
        with open(path, encoding="utf-8") as fh:
            if fh.read() != body:
                raise OSError("materialized SKILL.md does not read back identically")
        row["findings"] = [{k: d.get(k) for k in _KEYS} for d in (
            f.to_dict() for f in scan(parse_package(build_package(root))))]
    except Exception as exc:  # a crashing record is a coverage gap, recorded not hidden
        row["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
        row["trace"] = traceback.format_exc()[-800:]
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return row


def load_records(data_dir, work):
    """All three level splits, ids <level>_<row index>; snapshot fetched if data/ is absent."""
    if not os.path.isdir(os.path.join(data_dir, "data")):
        from huggingface_hub import snapshot_download
        snapshot_download(DATASET, repo_type="dataset", revision=REVISION, local_dir=data_dir)
    records = []
    for level in LEVELS:
        path = os.path.join(data_dir, "data", "NotInject_%s-00000-of-00001.parquet" % level)
        for i, r in enumerate(pd.read_parquet(path).itertuples(index=False)):
            records.append({"id": "%s_%03d" % (level, i), "level": level, "text": r.prompt,
                            "category": r.category, "triggers": [str(w) for w in r.word_list],
                            "work": work})
    return records


def run(args):
    work = tempfile.mkdtemp(prefix="notinject-pkgs-",
                            dir=args.work or os.path.dirname(os.path.abspath(args.out)))
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    records = load_records(args.data, work)
    t0, n_err = time.perf_counter(), 0
    with open(args.out, "w", encoding="utf-8") as out, Pool(max(1, min(4, args.workers))) as pool:
        for i, row in enumerate(pool.imap_unordered(scan_one, records, chunksize=4), 1):
            n_err += row["error"] is not None
            out.write(json.dumps(row, ensure_ascii=True) + "\n")
            if i % 100 == 0 or i == len(records):
                sys.stderr.write("  %d/%d  errors=%d  %.0fs\n" % (
                    i, len(records), n_err, time.perf_counter() - t0))
    shutil.rmtree(work, ignore_errors=True)
    sys.stderr.write("done: %d records, %d errors, %.1fs -> %s\n" % (
        len(records), n_err, time.perf_counter() - t0, args.out))


def clopper_pearson(k, n, alpha=0.05):
    """Exact binomial CI by bisection on the binomial CDF, which is decreasing in p: lower solves
    cdf(p, k-1) = 1 - alpha/2 (i.e. P(X >= k) = alpha/2), upper solves cdf(p, k) = alpha/2."""
    def solve(upto, target):
        lo, hi = 0.0, 1.0
        for _ in range(200):
            mid = (lo + hi) / 2
            c = sum(math.comb(n, i) * mid ** i * (1 - mid) ** (n - i) for i in range(upto + 1))
            lo, hi = (mid, hi) if c > target else (lo, mid)
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else solve(k - 1, 1 - alpha / 2)
    upper = 1.0 if k == n else solve(k, alpha / 2)
    return lower, upper


def wilson_upper(k, n, z=1.959964):
    """Wilson score upper bound."""
    ph, q = k / n, z * z / n
    return (ph + q / 2 + z * math.sqrt(ph * (1 - ph) / n + q / (4 * n))) / (1 + q)


def _real(fs):
    return [f for f in fs if f.get("vector")]


def _any(pred):
    return lambda fs: any(pred(f) for f in _real(fs))


VERDICTS = {
    "injection_medium_plus": _any(lambda f: f["vector"] in INJECTION and f["severity"] in _MP),
    "injection_any": _any(lambda f: f["vector"] in INJECTION),
    "medium_plus": _any(lambda f: f["severity"] in _MP),
    "high_plus": _any(lambda f: f["severity"] in _HC),
    "critical": _any(lambda f: f["severity"] == "critical"),
    "blocking": _any(lambda f: f["tier"] in _ATTACK and f["severity"] in _HC),
    "any_vector": _any(lambda f: True),
}


def cell(k, n):
    lo, hi = clopper_pearson(k, n)
    return "%d/%d (%.2f%%; 95%% CI %.2f-%.2f%%)" % (k, n, 100 * k / n, 100 * lo, 100 * hi)


def score(rows):
    n = len(rows)
    counts = {name: sum(fn(r["findings"]) for r in rows) for name, fn in VERDICTS.items()}
    per_vector = Counter(v for r in rows for v in {f["vector"] for f in _real(r["findings"])})
    per_rule = Counter("%s/%s" % (f["vector"], f["rule"]) for r in rows
                       for f in _real(r["findings"]))
    k = counts["injection_medium_plus"]
    lo, hi = clopper_pearson(k, n)
    return {
        "dataset": DATASET, "revision": REVISION, "total": n,
        "levels": dict(Counter(r["level"] for r in rows)),
        "categories": dict(Counter(r["category"] for r in rows)),
        "errors": sum(r["error"] is not None for r in rows), "counts": counts,
        "headline": {"metric": "injection-class flag rate at MEDIUM+", "count": k, "total": n,
                     "rate_pct": 100 * k / n, "ci95_clopper_pearson_pct": [100 * lo, 100 * hi],
                     "ci95_wilson_upper_pct": 100 * wilson_upper(k, n), "cell": cell(k, n)},
        "cells": {name: cell(c, n) for name, c in counts.items()},
        "per_vector": dict(per_vector.most_common()), "per_rule": dict(per_rule.most_common()),
        "fired": [{"id": r["id"], "level": r["level"], "category": r["category"],
                   "triggers": r["triggers"],
                   "findings": [{k2: f[k2] for k2 in _KEYS[:4]} for f in _real(r["findings"])]}
                  for r in sorted(rows, key=lambda r: r["id"]) if _real(r["findings"])],
        "error_ids": [r["id"] for r in rows if r["error"]],
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", help="snapshot dir holding data/NotInject_*.parquet (downloaded "
                                   "at the pinned revision when absent)")
    ap.add_argument("--out", help="JSONL to write (run mode)")
    ap.add_argument("--work", default=None,
                    help="parent for the scratch packages; a fresh subdirectory is created and "
                         "removed (default: next to --out)")
    ap.add_argument("--workers", type=int, default=4, help="capped at 4")
    ap.add_argument("--score", metavar="JSONL", help="score an existing run instead")
    ap.add_argument("--summary", metavar="JSON", help="with --score: write every number here")
    args = ap.parse_args(argv)
    if args.score:
        with open(args.score, encoding="utf-8") as fh:
            summary = score([json.loads(line) for line in fh if line.strip()])
        if args.summary:
            with open(args.summary, "w", encoding="utf-8") as fh:
                json.dump(summary, fh, indent=1, ensure_ascii=True)
        print("NotInject %s @ %s  n=%d  errors=%d" % (
            DATASET, REVISION[:12], summary["total"], summary["errors"]))
        print("HEADLINE injection-class at MEDIUM+: %s  [Wilson upper %.2f%%]" % (
            summary["headline"]["cell"], summary["headline"]["ci95_wilson_upper_pct"]))
        for name, c in summary["cells"].items():
            print("  %-22s %s" % (name, c))
        print("per vector (texts):", summary["per_vector"] or "none")
        for item in summary["fired"]:
            print("  FIRED %s %s triggers=%s -> %s" % (
                item["id"], item["category"], item["triggers"],
                ["%s/%s/%s/%s" % tuple(f.values()) for f in item["findings"]]))
        return 0
    if not (args.data and args.out):
        ap.error("run mode needs --data and --out (or use --score JSONL)")
    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
