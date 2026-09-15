"""Run skill-xray over the public true-positive subset of "Indirect Prompt Injection in the Wild"
(Khodayari et al., arXiv 2604.27202): validated injection prompts from real web pages, collapsed
by NFKC + casefold + whitespace into canonical groups. Each group's lowest-ID prompt becomes
<out dir>/pkgs/<id>/SKILL.md (front matter + prompt), is scanned in-process and removed; nothing
is executed. Headline: an injection-class vector (``INJECTION``) at any severity; MEDIUM+, HIGH+,
CRITICAL and the blocking verdict are reported alongside.

    python benchmark/adapters/inpage_pi_run.py --csv <dataset_tp.csv> --out <dir>/run.jsonl
    python benchmark/adapters/inpage_pi_run.py --score <dir>/run.jsonl   # writes <dir>/SUMMARY.json
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import shutil
import sys
import time
import traceback
import unicodedata
from collections import Counter
from multiprocessing import Pool

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from skill_xray.ingest import build_package  # noqa: E402
from skill_xray.parse import parse_package  # noqa: E402
from skill_xray.scan import scan  # noqa: E402

DATASET = "SoheilKhodayari/in_page_prompt_injection_pub"
REVISION = "0a04d1762cf60957f954f16a6cb9525ab32d6bca"
CSV_SHA256 = "aa4cae8559f6b6b7a3a35075a12958933c7f194b3801fe80b32f8c54b28d43c7"  # raw LF blob
INJECTION = {"SXV-027", "SXV-028", "SXV-029", "SXV-030", "SXV-031", "SXV-041", "SXV-042",
             "SXV-043"}
_MP, _HC = {"medium", "high", "critical"}, {"high", "critical"}
_KEYS = ("rule", "severity", "tier", "line")


def scan_one(rec):
    """Materialize <work>/<id>/SKILL.md from the canonical prompt, scan it, delete it."""
    row = {"id": rec["id"], "label": 1, "category": rec["category"], "members": rec["members"],
           "tlen": len(rec["text"]), "findings": [], "error": None, "elapsed_ms": 0}
    root, t0 = os.path.join(rec["work"], rec["id"]), time.perf_counter()
    try:
        os.makedirs(root, exist_ok=True)
        body = "---\nname: %s\n---\n%s\n" % (rec["id"], rec["text"])
        path = os.path.join(root, "SKILL.md")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(body)
        with open(path, encoding="utf-8", newline="") as fh:
            if fh.read() != body:
                raise OSError("materialized SKILL.md does not read back identically")
        for f in scan(parse_package(build_package(root))):
            d = f.to_dict()
            row["findings"].append({"vector": d.get("vector") or "",
                                    **{k: d.get(k) for k in _KEYS}})
    except Exception as exc:  # a crashing record is a coverage gap, recorded not hidden
        row["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
        row["trace"] = traceback.format_exc()[-800:]
    finally:
        row["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
        shutil.rmtree(root, ignore_errors=True)
    return row


def canonical_key(text):
    """Cisco skill-scanner's normalized-content rule: NFKC, casefold, collapse whitespace."""
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def load_groups(csv_path):
    """Collapse the fp=0 rows into canonical groups keyed by ``canonical_key(prompt)``; the
    lowest upstream ID is the representative. Returns (records, meta)."""
    with open(csv_path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    groups, n_rows = {}, 0
    with open(csv_path, encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        header = list(reader.fieldnames)
        taxonomy = header[header.index("asn_org") + 1:header.index("honeypot")]
        for r in reader:
            n_rows += 1
            if r["fp"] != "0" or not r["prompt"]:
                raise ValueError("row %s is not a validated non-empty prompt" % r["row"])
            g = groups.setdefault(canonical_key(r["prompt"]),
                                  {"min_id": None, "text": None, "members": 0, "cats": set()})
            rid = int(r["ID"])
            if g["min_id"] is None or rid < g["min_id"]:
                g["min_id"], g["text"] = rid, r["prompt"]
            g["members"] += 1
            g["cats"].update(c for c in taxonomy if r[c] == "1.0")
    records = [{"id": "in-page-tp-%05d" % g["min_id"], "text": g["text"],
                "members": g["members"], "category": sorted(g["cats"]) or ["unlabeled"]}
               for g in sorted(groups.values(), key=lambda g: g["min_id"])]
    meta = {"dataset": DATASET, "revision": REVISION, "csv_sha256": digest,
            "csv_sha256_matches_pin": digest == CSV_SHA256, "rows": n_rows,
            "canonical_groups": len(records), "taxonomy_fields": taxonomy}
    return records, meta


def run(args):
    records, meta = load_groups(args.csv)
    work = os.path.join(os.path.dirname(os.path.abspath(args.out)), "pkgs")
    os.makedirs(work, exist_ok=True)
    records = [dict(r, work=work) for r in records]
    with open(args.out + ".meta.json", "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=1)
    t0, n_err = time.perf_counter(), 0
    with open(args.out, "w", encoding="utf-8") as out, Pool(max(1, min(4, args.workers))) as pool:
        for i, row in enumerate(pool.imap_unordered(scan_one, records, chunksize=4), 1):
            n_err += row["error"] is not None
            out.write(json.dumps(row, ensure_ascii=True) + "\n")
            if i % 100 == 0 or i == len(records):
                sys.stderr.write("  %d/%d  errors=%d  %.0fs\n" % (
                    i, len(records), n_err, time.perf_counter() - t0))
    shutil.rmtree(work, ignore_errors=True)
    sys.stderr.write("done: %d rows -> %d groups, %d errors, %.1fs, csv sha256 pin match=%s\n" % (
        meta["rows"], len(records), n_err, time.perf_counter() - t0,
        meta["csv_sha256_matches_pin"]))


def wilson(k, n, z=1.959964):
    """Wilson score 95% interval."""
    ph = k / n
    centre = (ph + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return centre - half, centre + half


def _has(fs, sev=None, vectors=None, tiers=None):
    return any(f["vector"] and (sev is None or f["severity"] in sev)  # vector "" is a note
               and (vectors is None or f["vector"] in vectors)
               and (tiers is None or f["tier"] in tiers) for f in fs)


VERDICTS = {
    "injection_any": lambda fs: _has(fs, vectors=INJECTION),
    "injection_medium_plus": lambda fs: _has(fs, _MP, INJECTION),
    "medium_plus": lambda fs: _has(fs, _MP), "high_plus": lambda fs: _has(fs, _HC),
    "critical": lambda fs: _has(fs, {"critical"}),
    "blocking": lambda fs: _has(fs, _HC, tiers={"T1", "T2"}), "any_vector": _has,
}


def cell(k, n):
    lo, hi = wilson(k, n)
    return "%d/%d (%.2f%%; 95%% CI %.2f-%.2f%%)" % (k, n, 100 * k / n, 100 * lo, 100 * hi)


def score(rows, meta):
    n = len(rows)
    counts = {name: sum(fn(r["findings"]) for r in rows) for name, fn in VERDICTS.items()}
    hit = {r["id"]: VERDICTS["injection_any"](r["findings"]) for r in rows}
    total_rows = sum(r["members"] for r in rows)
    hit_rows = sum(r["members"] for r in rows if hit[r["id"]])
    vectors = {r["id"]: sorted({f["vector"] for f in r["findings"] if f["vector"]}) for r in rows}
    per_rule = Counter(k for r in rows for k in {
        "%s/%s" % (f["vector"], f["rule"]) for f in r["findings"] if f["vector"]})
    per_category = {}
    for r in rows:
        for c in r["category"]:
            d = per_category.setdefault(c, {"groups": 0, "detected": 0})
            d["groups"], d["detected"] = d["groups"] + 1, d["detected"] + int(hit[r["id"]])
    k = counts["injection_any"]
    misses = [{"id": r["id"], "category": r["category"], "members": r["members"],
               "tlen": r["tlen"], "other_vectors": vectors[r["id"]]}
              for r in sorted(rows, key=lambda r: (-r["members"], r["id"]))
              if not hit[r["id"]] and not r["error"]]
    return {
        "dataset": DATASET, "revision": REVISION, "meta": meta, "total": n,
        "total_rows_covered": total_rows, "errors": sum(r["error"] is not None for r in rows),
        "counts": counts, "cells": {name: cell(c, n) for name, c in counts.items()},
        "headline": {"metric": "injection-class signal recall at any severity, canonical groups",
                     "count": k, "total": n, "rate_pct": 100 * k / n,
                     "ci95_wilson_pct": [100 * b for b in wilson(k, n)], "cell": cell(k, n),
                     "row_weighted": "%d/%d (%.2f%%)" % (
                         hit_rows, total_rows, 100 * hit_rows / max(1, total_rows))},
        "per_vector": dict(Counter(v for vs in vectors.values() for v in vs).most_common()),
        "per_rule": dict(per_rule.most_common()),
        "per_category": dict(sorted(per_category.items())), "misses": misses,
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="path to data/dataset_tp.csv from the pinned checkout")
    ap.add_argument("--out", help="JSONL to write (run mode); packages go to <out dir>/pkgs/")
    ap.add_argument("--workers", type=int, default=4, help="capped at 4")
    ap.add_argument("--score", metavar="JSONL", help="score an existing run; needs its .meta.json")
    args = ap.parse_args(argv)
    if not args.score:
        if not (args.csv and args.out):
            ap.error("run mode needs --csv and --out (or use --score JSONL)")
        return run(args)
    with open(args.score, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    with open(args.score + ".meta.json", encoding="utf-8") as fh:
        s = score(rows, json.load(fh))
    with open(os.path.join(os.path.dirname(os.path.abspath(args.score)), "SUMMARY.json"), "w",
              encoding="utf-8") as fh:
        json.dump(s, fh, indent=1, ensure_ascii=True)
    print("In-Page PI %s @ %s  groups=%d rows=%d errors=%d" % (
        DATASET, REVISION[:12], s["total"], s["total_rows_covered"], s["errors"]))
    print("HEADLINE injection-class signal recall (any severity): %s" % s["headline"]["cell"])
    print("  row-weighted (raw-row diagnostic): %s" % s["headline"]["row_weighted"])
    for name, c in s["cells"].items():
        print("  %-22s %s" % (name, c))
    print("per vector (groups):", s["per_vector"], " per rule:", s["per_rule"])
    print("misses: %d groups (largest first, metadata only; per category in SUMMARY.json)" % len(
        s["misses"]))
    for m in s["misses"][:30]:
        print("  MISS %(id)s members=%(members)d tlen=%(tlen)d %(category)s" % m)


if __name__ == "__main__":
    sys.exit(main())
