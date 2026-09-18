"""Freeze and verify the MaliciousSkillBench snapshot the benchmark numbers are quoted on.

    python benchmark/msb_freeze.py --data <snapshot dir> --write      # rewrite MSB_FROZEN.json
    python benchmark/msb_freeze.py --data <snapshot dir> --verify     # exit 1 on any difference

The manifest records the pinned Hugging Face revision, the SHA-256 and size of every file in the
snapshot, the record and split counts, and a digest of the sorted benchmark ids per split (the ids
themselves are in msb_frozen_ids.json). A run whose snapshot fails --verify is not comparable to
the published figures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "MSB_FROZEN.json")
IDS = os.path.join(HERE, "msb_frozen_ids.json")
DATASET = "ProtectSkills/MaliciousSkillBench"
REVISION = "d4b42ce5766a6e0359c987cf59c1007cb3795a90"
DEV = ("train", "validation")


def _files(root):
    out = {}
    for dirpath, dirnames, names in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".cache"]
        for name in sorted(names):
            path = os.path.join(dirpath, name)
            with open(path, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            out[os.path.relpath(path, root).replace(os.sep, "/")] = {
                "sha256": digest, "bytes": os.path.getsize(path)}
    return out


def _splits(root):
    prim = pd.read_parquet(os.path.join(root, "primary.parquet"), columns=["benchmark_id", "label"])
    spl = pd.read_parquet(os.path.join(root, "splits", "source_disjoint.parquet"),
                          columns=["benchmark_id", "split"])
    df = prim.merge(spl, on="benchmark_id", how="left")
    df["label"] = df["label"].astype(str)
    groups = {s: g for s, g in df.groupby("split")}
    groups["dev"] = df[df["split"].isin(DEV)]
    counts = {s: {"total": int(len(g)), "malicious": int((g["label"] == "1").sum()),
                  "benign": int((g["label"] == "0").sum())} for s, g in groups.items()}
    ids = {s: sorted(g["benchmark_id"].tolist()) for s, g in groups.items()}
    digests = {s: hashlib.sha256("\n".join(v).encode("utf-8")).hexdigest() for s, v in ids.items()}
    return int(len(prim)), counts, ids, digests


def build(root):
    records, counts, ids, digests = _splits(root)
    return {"dataset": DATASET, "pinned_revision": REVISION, "files": _files(root),
            "records": records, "split_counts": counts, "id_list_sha256": digests}, ids


def verify(root, manifest):
    current, _ = build(root)
    problems = []
    for rel, meta in manifest["files"].items():
        got = current["files"].get(rel)
        if got is None:
            problems.append("missing file %s" % rel)
        elif got["sha256"] != meta["sha256"]:
            problems.append("%s: sha256 %s, frozen %s"
                            % (rel, got["sha256"][:12], meta["sha256"][:12]))
    for rel in current["files"]:
        if rel not in manifest["files"]:
            problems.append("extra file %s" % rel)
    if current["records"] != manifest["records"]:
        problems.append("records %d, frozen %d" % (current["records"], manifest["records"]))
    for split, digest in manifest["id_list_sha256"].items():
        if current["id_list_sha256"].get(split) != digest:
            problems.append("id list for split %s differs" % split)
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True, help="local snapshot root (holds primary.parquet)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = ap.parse_args(argv)
    if args.write:
        manifest, ids = build(args.data)
        with open(MANIFEST, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=1)
        with open(IDS, "w", encoding="utf-8") as fh:
            json.dump(ids, fh)
        print("frozen %d records, %d files -> %s"
              % (manifest["records"], len(manifest["files"]), MANIFEST))
        return 0
    with open(MANIFEST, encoding="utf-8") as fh:
        manifest = json.load(fh)
    problems = verify(args.data, manifest)
    for p in problems:
        sys.stderr.write("frozen dataset mismatch: %s\n" % p)
    if problems:
        return 1
    print("snapshot matches MSB_FROZEN.json (%s @ %s, %d records)" % (
        manifest["dataset"], manifest["pinned_revision"][:12], manifest["records"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
