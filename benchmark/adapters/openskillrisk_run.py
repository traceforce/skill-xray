"""Run skill-xray over Miaow-Lab/OpenSkillRisk (Hugging Face, gated) and score coverage.

OpenSkillRisk ships positive-risk skill packages and no benign controls, so the only valid metric
is severity-threshold coverage. The tree holds more SKILL.md roots than the gated task specs
select, so pass --ids <file of package ids>. With HF_TOKEN set:

    python benchmark/adapters/openskillrisk_run.py --download --work <scratch> --out osr.jsonl
    python benchmark/adapters/openskillrisk_run.py --source-dir <hf snapshot> --out osr.jsonl
    python benchmark/adapters/openskillrisk_run.py --score osr.jsonl [--summary SUMMARY.json]

Read-only static analysis: each package is copied file-by-file (text only; binary assets,
compiled code, nested archives and NUL-carrying files are counted and skipped) into its own
directory, scanned in-process, then deleted. Nothing is executed.
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
from collections import Counter
from functools import partial
from multiprocessing import Pool

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from skill_xray import ingest  # noqa: E402
from skill_xray.parse import parse_package  # noqa: E402
from skill_xray.scan import scan  # noqa: E402

REPO = "Miaow-Lab/OpenSkillRisk"
BINARY_EXT = (set(ingest.ASSET_EXT) | set(ingest.COMPILED_EXT)
              | set(ingest.NESTED_ARCHIVE_EXT) | {".pdf"})
_HC, _MP = {"high", "critical"}, {"medium", "high", "critical"}
_INJ = {"SXV-027", "SXV-028", "SXV-029", "SXV-030", "SXV-031", "SXV-041", "SXV-042",
        "SXV-043"}


def enumerate_packages(root, only_ids=None):
    """Outermost directories holding a SKILL.md under <root>/skills (a nested SKILL.md dir is
    owned by its parent package, as skill-xray discovery does). id = POSIX path under skills/."""
    base = os.path.join(root, "skills")
    pkgs = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        if any(f.lower() == "skill.md" for f in filenames):
            rel = os.path.relpath(dirpath, base).replace(os.sep, "/")
            parts = rel.split("/")
            cat = parts[1] if parts[0] == "contextually_risky_skills" and len(parts) > 2 else ""
            pkgs.append({"id": rel, "src": dirpath, "split": parts[0],
                         "category": cat or "unspecified"})
            dirnames[:] = []
        else:
            dirnames.sort()
    return sorted((p for p in pkgs if only_ids is None or p["id"] in only_ids),
                  key=lambda p: p["id"])


def materialize(src, dst, row):
    """Copy text files only, byte-exact; count binaries and record unreadable files."""
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, src)
            if os.path.islink(path) or os.path.splitext(name)[1].lower() in BINARY_EXT:
                row["files_skipped_binary"] += 1
                continue
            try:
                with open(path, "rb") as fh:
                    raw = fh.read(ingest.MAX_FILE_BYTES + 1)     # bounded: the scanner skips it too
                if len(raw) > ingest.MAX_FILE_BYTES:
                    row["files_oversize"] = row.get("files_oversize", 0) + 1
                    continue
                if b"\x00" in raw[:8192]:
                    row["files_skipped_binary"] += 1
                    continue
                out = os.path.join(dst, rel)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "wb") as fh:
                    fh.write(raw)
                with open(out, "rb") as fh:
                    if fh.read() != raw:
                        raise OSError("read-back mismatch")
                row["files_written"] += 1
            except OSError as exc:
                row["mat_errors"].append("%s: %s" % (rel.replace(os.sep, "/"), exc))


def scan_one(work, pkg):
    row = {"id": pkg["id"], "label": 1, "split": pkg["split"], "category": pkg["category"],
           "findings": [], "error": None, "files_written": 0, "files_skipped_binary": 0,
           "mat_errors": [], "analyzed": 0, "ledger_skipped": 0, "elapsed_ms": 0}
    dst = os.path.join(work, "pkgs", pkg["id"].replace("/", "__"))
    t0 = time.perf_counter()
    try:
        os.makedirs(dst, exist_ok=True)
        materialize(pkg["src"], dst, row)
        if not any(f.lower() == "skill.md" for f in os.listdir(dst)):
            raise OSError("SKILL.md could not be materialized")
        package = ingest.build_package(dst)
        led = ingest.build_ledger(package)
        row["analyzed"], row["ledger_skipped"] = led["artifactsAnalyzed"], led["artifactsSkipped"]
        for f in scan(parse_package(package)):
            d = f.to_dict()
            row["findings"].append({"vector": d.get("vector", ""), "rule": d.get("rule"),
                                    "severity": d.get("severity"), "tier": d.get("tier"),
                                    "line": d.get("line")})
    except Exception as exc:  # a crashing package is a coverage gap, recorded not hidden
        row["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
    finally:
        row["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
        shutil.rmtree(dst, ignore_errors=True)
    return row


def download(work, revision):
    """Text files only; binaries never leave the Hub. Needs HF_TOKEN with approved access."""
    from huggingface_hub import HfApi, snapshot_download
    sha = HfApi().dataset_info(REPO, revision=revision).sha
    path = snapshot_download(REPO, repo_type="dataset", revision=sha, allow_patterns=["skills/**"],
                             ignore_patterns=["*" + e for e in sorted(BINARY_EXT)],
                             local_dir=os.path.join(work, "snapshot"))
    return path, sha


def wilson(k, n, z=1.96):
    if not n:
        return (0.0, 0.0)
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(100 * (c - h), 2), round(100 * (c + h), 2))


def _incomplete(r):
    """A crashed scan or a high-severity diagnostic without a vector (OpenGrep unavailable,
    analysis cut short): the package was not fully analyzed, so a miss on it says nothing."""
    return r["error"] is not None or any(
        f.get("severity") in _HC and not f.get("vector") for f in r["findings"])


def score(rows):
    n = len(rows)
    tests = {"medium_plus": lambda fs: any(f["severity"] in _MP for f in fs),
             "high_plus": lambda fs: any(f["severity"] in _HC for f in fs),
             "critical": lambda fs: any(f["severity"] == "critical" for f in fs),
             "blocking": lambda fs: any(f["tier"] in ("T1", "T2") and f["severity"] in _HC
                                        for f in fs),
             "any_vector": lambda fs: bool(fs),
             "injection_any": lambda fs: any(f["vector"] in _INJ for f in fs),
             "injection_medium_plus": lambda fs: any(f["vector"] in _INJ and f["severity"] in _MP
                                                     for f in fs)}
    counts, per_vector, per_cat = Counter(), Counter(), {}
    for r in rows:
        real = [f for f in r["findings"] if f.get("vector")]
        cat = per_cat.setdefault("%s/%s" % (r["split"], r["category"]), Counter())
        cat["total"] += 1
        for name, test in tests.items():
            hit = test(real)
            counts[name] += hit
            cat[name] += hit
        for v in {f["vector"] for f in real}:
            per_vector[v] += 1
    pct = {k: round(100 * counts[k] / n, 2) if n else 0.0 for k in tests}
    return {"total": n, "errors": sum(r["error"] is not None for r in rows),
            "incomplete": sum(_incomplete(r) for r in rows),
            "files_skipped_binary": sum(r["files_skipped_binary"] for r in rows),
            "files_oversize": sum(r.get("files_oversize", 0) for r in rows),
            "materialization_errors": sum(len(r["mat_errors"]) for r in rows),
            **{k: counts[k] for k in tests}, "pct": pct,
            "ci95_medium_plus": wilson(counts["medium_plus"], n),
            "per_vector": dict(per_vector.most_common()),
            "per_category": {k: dict(v) for k, v in sorted(per_cat.items())},
            "categories_missed_entirely": [k for k, v in sorted(per_cat.items())
                                           if v["any_vector"] == 0],
            "result": "%d MEDIUM+ (%.2f%%); %d HIGH+ (%.2f%%); %d CRITICAL (%.2f%%)" % (
                counts["medium_plus"], pct["medium_plus"], counts["high_plus"], pct["high_plus"],
                counts["critical"], pct["critical"])}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--score", metavar="JSONL", help="score an existing run and exit")
    ap.add_argument("--summary", help="with --score: also write the numbers as JSON")
    ap.add_argument("--source-dir", help="local Hugging Face snapshot root (holds skills/)")
    ap.add_argument("--download", action="store_true", help="snapshot_download text files")
    ap.add_argument("--revision", default="main")
    ap.add_argument("--ids", help="file of package ids (one per line) to restrict the population")
    ap.add_argument("--work", default="osr-work", help="scratch root for pkgs/ and snapshot/")
    ap.add_argument("--out", help="JSONL output path")
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args(argv)
    if args.score:
        with open(args.score, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
        s = score(rows)
        if args.summary:
            with open(args.summary, "w", encoding="utf-8") as fh:
                json.dump(s, fh, indent=1)
        sys.stdout.write(json.dumps(s, indent=1) + "\n")
        return 0
    if not args.out or not (args.source_dir or args.download):
        ap.error("--out plus --source-dir or --download is required (or --score)")
    os.makedirs(args.work, exist_ok=True)
    root, sha = (download(args.work, args.revision) if args.download
                 else (args.source_dir, args.revision))
    only = None
    if args.ids:
        with open(args.ids, encoding="utf-8") as fh:
            only = {line.strip() for line in fh if line.strip()}
    pkgs = enumerate_packages(root, only)
    if not pkgs:
        sys.exit("no packages selected: check --source-dir / --download and --ids")
    if only is not None:
        missing = sorted(only - {p["id"] for p in pkgs})
        if missing:
            sys.exit("%d requested ids are not in the snapshot, e.g. %s"
                     % (len(missing), ", ".join(missing[:3])))
    scratch = tempfile.mkdtemp(prefix="osr-pkgs-", dir=args.work)   # only this run's dir is removed
    sys.stderr.write("revision=%s packages=%d workers=%d\n" % (sha, len(pkgs), args.workers))
    t0, n_err = time.perf_counter(), 0
    with open(args.out, "w", encoding="utf-8") as out, Pool(max(1, min(4, args.workers))) as pool:
        for i, row in enumerate(pool.imap_unordered(partial(scan_one, scratch), pkgs, 4), 1):
            n_err += row["error"] is not None
            out.write(json.dumps(row, ensure_ascii=True) + "\n")
            if i % 50 == 0 or i == len(pkgs):
                sys.stderr.write("  %d/%d errors=%d %.0fs\n" % (
                    i, len(pkgs), n_err, time.perf_counter() - t0))
    shutil.rmtree(scratch, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
