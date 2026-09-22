"""Materialise the frozen MaliciousSkillBench split as one-file packages,
as benchmark/msb_run.py does.

    python tools/parity/msb_materialize.py --data <snapshot dir> --split test|dev|all [--out DIR]

The snapshot is first verified against benchmark-reports/frozen-dataset/MSB_FROZEN.json (file
digests, record count, per-split id-list digests); on any mismatch nothing
is written and the exit code is 1. Each record's text (skill_text, else public_skill_text) is
written to <out>/<sanitized id>-<sha1[:10]>/SKILL.md with encoding utf-8, errors surrogatepass,
newline "", and one row per record goes to <out>/manifest.jsonl.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN = os.path.normpath(os.path.join(HERE, "..", "..", "..", "benchmark-reports",
                                       "frozen-dataset"))
MAX_FILE_BYTES = 1_048_576  # ingest.MAX_FILE_BYTES; oversize records are flagged, not dropped
SPLITS = {"test": {"test"}, "dev": {"train", "validation"},
          "all": {"train", "validation", "test", "excluded"}}


def package_dir(benchmark_id):
    """The directory name msb_run.scan_one gives a record: the id is data, never a path."""
    return "%s-%s" % (re.sub(r"[^A-Za-z0-9_-]", "_", benchmark_id)[:40],
                      hashlib.sha1(benchmark_id.encode("utf-8")).hexdigest()[:10])


def load(data_dir):
    """Every record joined to its source-disjoint split, text chosen as
    msb_run.load_records does."""
    primary = pd.read_parquet(os.path.join(data_dir, "primary.parquet"))
    splits = pd.read_parquet(os.path.join(data_dir, "splits", "source_disjoint.parquet"))
    df = splits.rename(columns={"label": "split_label"}).merge(primary, on="benchmark_id",
                                                               how="inner")
    df["label"] = df["label"].astype(int)
    df["text"] = df["skill_text"].where(df["skill_text"].notna(),
                                        df["public_skill_text"]).fillna("")
    return df.sort_values("benchmark_id")


def verify(data_dir, df):
    with open(os.path.join(FROZEN, "MSB_FROZEN.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    problems = []
    for rel, meta in manifest["files"].items():
        path = os.path.join(data_dir, rel)
        if not os.path.isfile(path):
            problems.append("missing file %s" % rel)
            continue
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        if digest != meta["sha256"] or os.path.getsize(path) != meta["bytes"]:
            problems.append("%s: sha256 %s, frozen %s" % (rel, digest[:12], meta["sha256"][:12]))
    if len(df) != manifest["records"]:
        problems.append("records %d, frozen %d" % (len(df), manifest["records"]))
    for split, digest in manifest["id_list_sha256"].items():
        ids = sorted(df[df["split"].isin(SPLITS.get(split, {split}))]["benchmark_id"])
        if hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest() != digest:
            problems.append("id list for split %s differs" % split)
    return manifest, problems


def materialize(df, out):
    os.makedirs(out, exist_ok=True)
    rows, written, total = [], 0, 0
    for rec in df.itertuples(index=False):
        text = rec.text
        size = len(text.encode("utf-8", "surrogatepass"))
        row = {"benchmark_id": rec.benchmark_id, "split": rec.split, "label": int(rec.label),
               "package": package_dir(rec.benchmark_id), "bytes": size,
               "oversize": size > MAX_FILE_BYTES, "error": None}
        if not text:
            row["error"] = "record has no skill_text"
        else:
            root = os.path.join(out, row["package"])
            os.makedirs(root, exist_ok=True)
            with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8",
                      errors="surrogatepass", newline="") as fh:
                fh.write(text)
            written += 1
            total += size
        rows.append(row)
    with open(os.path.join(out, "manifest.jsonl"), "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=True) + "\n")
    return written, total, sum(r["error"] is not None for r in rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True, help="snapshot root (holds primary.parquet)")
    ap.add_argument("--split", default="test", choices=sorted(SPLITS))
    ap.add_argument("--out", default=None, help="default corpus/msb-<split>")
    args = ap.parse_args(argv)
    out = args.out or os.path.join("corpus", "msb-%s" % args.split)

    t0 = time.perf_counter()
    df = load(args.data)
    manifest, problems = verify(args.data, df)
    for p in problems:
        sys.stderr.write("frozen dataset mismatch: %s\n" % p)
    if problems:
        return 1
    part = df[df["split"].isin(SPLITS[args.split])]
    written, total, empty = materialize(part, out)
    print("msb-%s: snapshot matches MSB_FROZEN.json (%s @ %s); %d records, %d written, %d empty, "
          "%d bytes, %.1fs -> %s" % (
              args.split, manifest["dataset"], manifest["pinned_revision"][:12],
              len(part), written, empty, total, time.perf_counter() - t0, out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
