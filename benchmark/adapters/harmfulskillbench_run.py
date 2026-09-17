"""Run skill-xray over TrustAIRLab/HarmfulSkillBench and score severity-threshold coverage.

HarmfulSkillBench (arXiv:2604.15415) is 200 harmful-content skills with no benign controls, so
precision and FPR are not measurable; the unit is coverage at a severity threshold (MEDIUM+,
HIGH+). The Hugging Face repo is gated: request access on the dataset page, export HF_TOKEN, then

    python benchmark/adapters/harmfulskillbench_run.py --fetch --data hsb_raw \
        --revision 0a30e25f20a391e1b6956c55d6806867944c2232
    python benchmark/adapters/harmfulskillbench_run.py --data hsb_raw --out out/hsb.jsonl
    python benchmark/adapters/harmfulskillbench_run.py --score out/hsb.jsonl [--summary s.json]

Each skill directory is copied verbatim as its own package, scanned in-process (nothing is
executed) and deleted. Only text files the scanner itself decodes (UTF-8 or CP-1252) are
materialized; anything else is counted in ``skipped_binary``, and a skipped archive, compiled or
PDF file also in ``files_skipped_opaque``, which marks the scan incomplete. Per-item exceptions
are recorded in ``error``, never dropped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import traceback
from collections import Counter, defaultdict
from multiprocessing import Pool

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from skill_xray.ingest import (  # noqa: E402
    COMPILED_EXT,
    MAX_FILE_BYTES,
    NESTED_ARCHIVE_EXT,
    _decode,
    build_ledger,
    build_package,
)
from skill_xray.parse import parse_package  # noqa: E402
from skill_xray.scan import scan  # noqa: E402

REPO = "TrustAIRLab/HarmfulSkillBench"
_HC = {"high", "critical"}
_MP = {"medium", "high", "critical"}
_ATTACK = {"T1", "T2"}
_INJECTION = {"SXV-027", "SXV-028", "SXV-029", "SXV-030", "SXV-031", "SXV-041", "SXV-042",
              "SXV-043"}
# archives, compiled code and PDFs: the scanner cannot read them and marks the package incomplete
_OPAQUE_EXT = NESTED_ARCHIVE_EXT | set(COMPILED_EXT) | {".pdf"}
_WORK = None


def _init(work):
    global _WORK
    _WORK = work


def discover(data_dir):
    """One record per directory under skills/ holding a SKILL.md; labels from _meta.json."""
    root = os.path.join(data_dir, "skills")
    recs = []
    for dirpath, _dirs, files in os.walk(root):
        if "SKILL.md" not in files:
            continue
        rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
        meta = {}
        if "_meta.json" in files:
            with open(os.path.join(dirpath, "_meta.json"), encoding="utf-8") as fh:
                meta = json.load(fh)
        parts = rel.split("/")                   # original/{category}/{name} has no anon_id
        recs.append({"id": meta.get("anon_id") or rel.replace("/", "__"), "dir": dirpath,
                     "platform": meta.get("platform") or parts[0],
                     "category": meta.get("category") or (parts[1] if len(parts) > 2 else None),
                     "harm_tier": meta.get("tier")})
    return sorted(recs, key=lambda r: r["id"])


def _copy_text_files(src, dst):
    """Copy text files (as the scanner decodes them) at their relative paths, judged by content;
    archives, compiled code and PDFs are skipped by extension and also counted as opaque;
    symlinks and binaries are counted as skipped, never followed. The dataset's own label file
    (_meta.json at the package root) is not skill content and is left out. Returns (copied,
    skipped, oversize, opaque)."""
    copied = skipped = oversize = opaque = 0
    for dirpath, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(dirpath, d))]
        for name in files:
            if dirpath == src and name == "_meta.json":
                continue
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                skipped += 1
                continue
            if os.path.splitext(name)[1].lower() in _OPAQUE_EXT:
                skipped += 1
                opaque += 1
                continue
            with open(path, "rb") as fh:
                raw = fh.read(MAX_FILE_BYTES + 1)         # bounded: the scanner skips it too
            if len(raw) > MAX_FILE_BYTES:
                oversize += 1
                continue
            if _decode(raw)[0] is None:
                skipped += 1
                continue
            out = os.path.join(dst, os.path.relpath(path, src))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "wb") as fh:
                fh.write(raw)
            copied += 1
    return copied, skipped, oversize, opaque


def _finding_row(f):
    d = f.to_dict()
    return {"vector": d.get("vector", ""), "rule": d.get("rule"), "severity": d.get("severity"),
            "tier": d.get("tier"), "line": d.get("line")}


def scan_one(rec):
    """Materialize <work>/pkgs/<id>/ from the skill directory, scan it in-process, delete it."""
    row = {"id": rec["id"], "label": 1, "category": rec["category"], "harm_tier": rec["harm_tier"],
           "platform": rec["platform"], "files": 0, "skipped_binary": 0, "oversize": 0,
           "files_skipped_opaque": 0, "ledger_skipped": 0, "analyzed": 0, "findings": [],
           "error": None, "elapsed_ms": 0}
    # the dataset id is data, not a path: a sanitized stem plus a hash keeps every package in
    # its own child of the scratch root, whatever the id contains
    pkg_dir = os.path.join(_WORK, "pkgs", "%s-%s" % (
        re.sub(r"[^A-Za-z0-9_-]", "_", rec["id"])[:40],
        hashlib.sha1(rec["id"].encode("utf-8")).hexdigest()[:10]))
    t0 = time.perf_counter()
    try:
        os.makedirs(pkg_dir, exist_ok=True)
        (row["files"], row["skipped_binary"], row["oversize"],
         row["files_skipped_opaque"]) = _copy_text_files(rec["dir"], pkg_dir)
        if not os.path.isfile(os.path.join(pkg_dir, "SKILL.md")):
            raise RuntimeError("SKILL.md could not be materialized or read back")
        pkg = build_package(pkg_dir)
        ledger = build_ledger(pkg)
        row["ledger_skipped"] = ledger["artifactsSkipped"]
        row["analyzed"] = ledger["artifactsAnalyzed"]
        row["findings"] = [_finding_row(f) for f in scan(parse_package(pkg))]
    except Exception as exc:  # a crashing item is a coverage gap: recorded, never dropped
        row["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
        row["trace"] = traceback.format_exc()[-600:]
    finally:
        row["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
        shutil.rmtree(pkg_dir, ignore_errors=True)
    return row


def _real(fs):
    return [f for f in fs if f.get("vector")]


def _incomplete(r):
    """A crashed scan, an oversize or opaque (archive, compiled, PDF) file left out, a ledger
    skip, or a high-severity diagnostic without a vector (OpenGrep unavailable, analysis cut
    short): the package was not fully analyzed. On this all-malicious set it still counts as a
    miss in every rate (the scanner did not catch it); the count is reported so those misses can
    be told apart from real ones."""
    return bool(r["error"] is not None or r.get("oversize") or r.get("files_skipped_opaque")
                or r.get("ledger_skipped") or any(
                    f.get("severity") in _HC and not f.get("vector") for f in r["findings"]))


VERDICTS = {
    "medium_plus": lambda fs: any(f["severity"] in _MP for f in _real(fs)),
    "high_plus": lambda fs: any(f["severity"] in _HC for f in _real(fs)),
    "critical": lambda fs: any(f["severity"] == "critical" for f in _real(fs)),
    "blocking": lambda fs: any(f["tier"] in _ATTACK and f["severity"] in _HC for f in _real(fs)),
    "any_vector": lambda fs: bool(_real(fs)),
    "injection_any": lambda fs: any(f["vector"] in _INJECTION for f in _real(fs)),
    "injection_medium_plus": lambda fs: any(
        f["vector"] in _INJECTION and f["severity"] in _MP for f in _real(fs)),
}


def _wilson(k, n, z=1.96):
    if not n:
        return None
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return [round(100 * (c - h), 2), round(100 * (c + h), 2)]


def score(rows):
    """Coverage at each severity threshold plus per-vector and per-category package counts."""
    n = len(rows)
    out = {"evaluated": n, "errors": sum(r["error"] is not None for r in rows),
           "incomplete": sum(_incomplete(r) for r in rows),
           "skipped_binary_files": sum(r.get("skipped_binary", 0) for r in rows),
           "oversize_files": sum(r.get("oversize", 0) for r in rows),
           "files_skipped_opaque": sum(r.get("files_skipped_opaque", 0) for r in rows)}
    for name, fn in VERDICTS.items():
        hit = sum(fn(r["findings"]) for r in rows)
        out[name] = {"count": hit, "pct": round(100.0 * hit / n, 2) if n else None,
                     "ci95": _wilson(hit, n)}
    out["result"] = "%d MEDIUM+ (%.2f%%); %d HIGH+ (%.2f%%)" % (
        out["medium_plus"]["count"], out["medium_plus"]["pct"] or 0,
        out["high_plus"]["count"], out["high_plus"]["pct"] or 0)
    out["per_vector"] = dict(Counter(
        v for r in rows for v in {f["vector"] for f in _real(r["findings"])}).most_common())
    keys = ("any_vector", "medium_plus", "high_plus", "blocking")
    by_cat = defaultdict(lambda: dict.fromkeys(("total",) + keys, 0))
    for r in rows:
        c = by_cat[r.get("category") or "(none)"]
        c["total"] += 1
        for k in keys:
            c[k] += VERDICTS[k](r["findings"])
    out["per_category"] = dict(sorted(by_cat.items()))
    for k in ("any_vector", "medium_plus"):
        out["categories_missed_entirely_" + k] = sorted(c for c, v in by_cat.items() if not v[k])
    return out


def fetch(data_dir, revision):
    from huggingface_hub import snapshot_download
    token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_HUB_TOKEN")
    if not token:
        raise SystemExit("%s is gated: request access on the dataset page, set HF_TOKEN" % REPO)
    return snapshot_download(REPO, repo_type="dataset", revision=revision, local_dir=data_dir,
                             token=token, ignore_patterns=["*.png"])


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", help="local snapshot root (contains skills/)")
    ap.add_argument("--fetch", action="store_true", help="snapshot_download into --data first")
    ap.add_argument("--revision", default=None, help="dataset commit to pin")
    ap.add_argument("--out", help="JSONL to write (run mode)")
    ap.add_argument("--score", metavar="JSONL", help="score an existing run instead of scanning")
    ap.add_argument("--summary", help="also write the score dict as JSON to this path")
    ap.add_argument("--work", default=None,
                    help="parent for the scratch packages; a fresh subdirectory is created and "
                         "removed (default: the system temp dir)")
    ap.add_argument("--workers", type=int, default=4, help="max 4")
    args = ap.parse_args(argv)
    if args.score:
        with open(args.score, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
        s = score(rows)
        if args.summary:
            with open(args.summary, "w", encoding="utf-8") as fh:
                json.dump(s, fh, indent=1)
        print(json.dumps(s, indent=1))
        return 0
    if not args.data:
        ap.error("run mode needs --data")
    if args.fetch:
        fetch(args.data, args.revision)
        if not args.out:                    # fetch-only step of the documented two-step flow
            return 0
    if not args.out:
        ap.error("run mode needs --out")
    records = discover(args.data)
    if not records:
        raise SystemExit("no skills/**/SKILL.md under %s" % args.data)
    if args.work:
        os.makedirs(args.work, exist_ok=True)
    work = tempfile.mkdtemp(prefix="hsb-work-", dir=args.work)
    os.makedirs(os.path.join(work, "pkgs"), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    t0, n_err = time.perf_counter(), 0
    with open(args.out, "w", encoding="utf-8") as out, \
            Pool(max(1, min(4, args.workers)), initializer=_init, initargs=(work,)) as pool:
        for i, row in enumerate(pool.imap_unordered(scan_one, records, chunksize=4), 1):
            n_err += row["error"] is not None
            out.write(json.dumps(row, ensure_ascii=True) + "\n")
            if i % 50 == 0 or i == len(records):
                sys.stderr.write("  %d/%d  errors=%d  %.0fs\n" % (
                    i, len(records), n_err, time.perf_counter() - t0))
    shutil.rmtree(work, ignore_errors=True)
    sys.stderr.write("done: %d packages, %d errors -> %s\n" % (len(records), n_err, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
