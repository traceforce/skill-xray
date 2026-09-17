"""Run skill-xray over the public ``anthropics/skills`` repo (Cisco's "official bundled skills"
row): a compatibility flag rate, every flag on these presumed-benign real packages being a
false-positive proxy. Each directory holding a SKILL.md is one package; the whole package is
materialized (text/markdown/source only, binaries skipped and counted), scanned in-process with
the code lane and OpenGrep active, then removed. Nothing is executed; only bytes are read.

    python benchmark/adapters/official_skills_run.py --repo <clone> --out <jsonl> [--workers 4]
    python benchmark/adapters/official_skills_run.py --score <jsonl> [--summary SUMMARY.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from collections import Counter
from multiprocessing import Pool

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from skill_xray.ingest import (  # noqa: E402
    ASSET_EXT,
    COMPILED_EXT,
    MAX_FILE_BYTES,
    NESTED_ARCHIVE_EXT,
    _decode,
    build_ledger,
    build_package,
)
from skill_xray.parse import parse_package  # noqa: E402
from skill_xray.scan import scan  # noqa: E402

_HC = {"high", "critical"}
_MP = {"medium", "high", "critical"}
_ATTACK = {"T1", "T2"}
_INJECTION = {"SXV-027", "SXV-028", "SXV-029", "SXV-030", "SXV-031", "SXV-041", "SXV-042",
              "SXV-043"}
# archives, compiled code and PDFs: the scanner cannot read them and marks the package incomplete
_OPAQUE_EXT = NESTED_ARCHIVE_EXT | set(COMPILED_EXT) | {".pdf"}
_BINARY_EXT = ASSET_EXT | _OPAQUE_EXT | {".otf"}


def find_packages(repo):
    """Every directory under ``repo`` that holds a SKILL.md, as repo-relative POSIX ids."""
    items = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        if "SKILL.md" in filenames:
            items.append({"id": os.path.relpath(dirpath, repo).replace(os.sep, "/"),
                          "src": dirpath})
    return items


def _is_text(data):
    """The scanner's own decode decision (UTF-8 or CP-1252; a NUL byte means binary)."""
    return _decode(data)[0] is not None


def materialize(src, dst):
    """Copy text/markdown/source files at their relative paths; skip binaries and symlinks.
    Returns the counts (text, binary, symlink, opaque) plus the files that could not be written
    or read back; opaque files (archives, compiled code, PDFs) are also counted as binary."""
    n_text = n_bin = n_link = n_opaque = 0
    errors = []
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d != ".git"
                       and not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, src).replace(os.sep, "/")
            if os.path.islink(path):            # may point outside the package; never read
                n_link += 1
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in _BINARY_EXT:
                n_bin += 1
                n_opaque += ext in _OPAQUE_EXT
                continue
            try:
                with open(path, "rb") as fh:
                    data = fh.read(MAX_FILE_BYTES + 1)    # bounded: the scanner skips it too
                if len(data) > MAX_FILE_BYTES:
                    errors.append("%s: over %d bytes, skipped" % (rel, MAX_FILE_BYTES))
                    continue
                if not _is_text(data):
                    n_bin += 1
                    continue
                target = os.path.join(dst, rel)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as fh:
                    fh.write(data)
                if os.path.getsize(target) != len(data):
                    raise OSError("read-back size mismatch")
                n_text += 1
            except OSError as exc:
                errors.append("%s: %s" % (rel, str(exc)[:120]))
    return n_text, n_bin, n_link, n_opaque, errors


def _finding_row(f):
    d = f.to_dict()
    row = {k: d.get(k) for k in ("vector", "rule", "severity", "tier", "path", "line")}
    return {**row, "vector": row["vector"] or "", "message": (d.get("message") or "")[:300]}


def _scratch_name(pkg_id):
    """One scratch directory per package id: a sanitized stem plus a hash of the full id, so two
    ids that differ only in separators never share a directory (workers delete their own)."""
    return "%s-%s" % (re.sub(r"[^A-Za-z0-9_-]", "_", pkg_id)[:40],
                      hashlib.sha1(pkg_id.encode("utf-8")).hexdigest()[:10])


def scan_one(item):
    """Materialize one package under its own scratch directory, scan it whole, delete it."""
    row = {"id": item["id"], "name": os.path.basename(item["src"]), "label": 0,
           "category": "official", "files_text": 0, "files_binary_skipped": 0,
           "files_skipped_opaque": 0, "materialize_errors": [], "analyzed": 0,
           "ledger_skipped": 0, "findings": [], "error": None, "elapsed_ms": 0}
    root, t0 = os.path.join(item["work"], _scratch_name(item["id"])), time.perf_counter()
    try:
        os.makedirs(root, exist_ok=True)
        n_text, n_bin, n_link, n_opaque, errs = materialize(item["src"], root)
        row.update(files_text=n_text, files_binary_skipped=n_bin, files_symlinks_skipped=n_link,
                   files_skipped_opaque=n_opaque, materialize_errors=errs)
        if not os.path.isfile(os.path.join(root, "SKILL.md")):
            raise RuntimeError("SKILL.md could not be materialized: " + "; ".join(errs)[:200])
        pkg = build_package(root)
        ledger = build_ledger(pkg)
        row.update(analyzed=ledger["artifactsAnalyzed"], ledger_skipped=ledger["artifactsSkipped"])
        row["findings"] = [_finding_row(f) for f in scan(parse_package(pkg))]
    except Exception as exc:  # a crashing package is a coverage gap, recorded not hidden
        row["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
        row["trace"] = traceback.format_exc()[-800:]
    finally:
        row["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
        shutil.rmtree(root, ignore_errors=True)
    return row


def _wilson(k, n, z=1.96):
    """95% Wilson interval for a package rate, in percent."""
    if not n:
        return [0.0, 0.0]
    p, d = k / n, 1 + z * z / n
    c, h = (p + z * z / (2 * n)) / d, z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [100 * max(0.0, c - h), 100 * min(1.0, c + h)]


def score(rows):
    """Package-level flag rates from the JSONL; every real finding is a compatibility flag. A
    package whose scan failed is reported under errors and leaves every rate. A package that
    ended in a high-severity diagnostic without a vector (OpenGrep unavailable, analysis cut
    short), lost a file at materialization or to a skipped symlink, carried an archive, compiled
    or PDF file (the scanner marks such a package incomplete), or had an artifact skipped by the
    ledger was not fully analyzed: an unflagged outcome on it is unknown rather than clean, so at
    each threshold it counts only where it is flagged, and the eligible count is reported."""
    errored = [r["id"] for r in rows if r.get("error")]
    rows = [r for r in rows if not r.get("error")]
    incomplete = [r["id"] for r in rows
                  if r.get("materialize_errors") or r.get("ledger_skipped")
                  or r.get("files_symlinks_skipped") or r.get("files_skipped_opaque")
                  or any(f.get("severity") in _HC and not f.get("vector") for f in r["findings"])]
    unknown = set(incomplete)
    n = len(rows)
    real = {r["id"]: [f for f in r["findings"] if f.get("vector")] for r in rows}

    def rate(pred):
        """(flagged, eligible, pct) at one threshold; eligible = flagged or fully analyzed."""
        hits = {rid for rid, fs in real.items() if any(pred(f) for f in fs)}
        eligible = len(hits) + sum(1 for rid in real if rid not in hits and rid not in unknown)
        return len(hits), eligible, (100.0 * len(hits) / eligible if eligible else 0.0)

    med = rate(lambda f: f["severity"] in _MP)
    high = rate(lambda f: f["severity"] in _HC)
    block = rate(lambda f: f["tier"] in _ATTACK and f["severity"] in _HC)
    keys = ("vector", "rule", "severity", "tier", "path", "line")
    flags = [{"id": r["id"], **{k: f[k] for k in keys}}
             for r in rows for f in real[r["id"]] if f["severity"] in _MP]
    summary = {
        "dataset": "anthropics/skills", "commit": rows[0].get("commit") if rows else None,
        "packages": n, "errors": len(errored), "error_ids": errored,
        "incomplete": len(incomplete), "incomplete_ids": incomplete,
        "materialize_errors": sum(len(r["materialize_errors"]) for r in rows),
        "files_text": sum(r["files_text"] for r in rows),
        "files_binary_skipped": sum(r["files_binary_skipped"] for r in rows),
        "files_symlinks_skipped": sum(r.get("files_symlinks_skipped", 0) for r in rows),
        "files_skipped_opaque": sum(r.get("files_skipped_opaque", 0) for r in rows),
        "medium_plus": med[0], "medium_plus_eligible": med[1], "medium_plus_pct": med[2],
        "high_plus": high[0], "high_plus_eligible": high[1], "high_plus_pct": high[2],
        "critical": rate(lambda f: f["severity"] == "critical")[0],
        "blocking": block[0], "blocking_eligible": block[1], "blocking_pct": block[2],
        "any_vector": rate(lambda f: True)[0],
        "injection_any": rate(lambda f: f["vector"] in _INJECTION)[0],
        "injection_medium_plus": rate(
            lambda f: f["vector"] in _INJECTION and f["severity"] in _MP)[0],
        "ci95_medium_plus_pct": _wilson(med[0], med[1]),
        "ci95_high_plus_pct": _wilson(high[0], high[1]),
        "per_vector_packages": dict(Counter(
            v for fs in real.values() for v in {f["vector"] for f in fs}).most_common()),
        "per_rule_medium_plus_flags": dict(Counter(
            "%s/%s" % (f["vector"], f["rule"]) for f in flags).most_common()),
        "medium_plus_flags": flags,
        "result": "%d MEDIUM+ (%.2f%% of %d); %d HIGH+ (%.2f%% of %d)" % (
            med[0], med[2], med[1], high[0], high[2], high[1]),
    }
    print(json.dumps({k: v for k, v in summary.items() if k != "medium_plus_flags"}, indent=1))
    for f in flags:  # one line per MEDIUM+ flag: package, vector, rule, severity, tier, file:line
        print("  %-28s %s %s %s %s %s:%s" % (f["id"], f["vector"], f["rule"], f["severity"],
                                            f["tier"], f["path"], f["line"]))
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", help="clone of anthropics/skills")
    ap.add_argument("--out", help="JSONL to write, one row per package")
    ap.add_argument("--work", default=None,
                    help="parent for the scratch packages; a fresh subdirectory is created and "
                         "removed (default: the system temp dir)")
    ap.add_argument("--workers", type=int, default=4, help="max 4")
    ap.add_argument("--score", metavar="JSONL", help="print the metric from an existing run")
    ap.add_argument("--summary", metavar="JSON", help="with --score: write every number here")
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.score:
        with open(args.score, encoding="utf-8") as fh:
            summary = score([json.loads(line) for line in fh if line.strip()])
        if args.summary:
            with open(args.summary, "w", encoding="utf-8") as fh:
                json.dump(summary, fh, indent=1)
        return 0
    if not (args.repo and args.out):
        ap.error("--repo and --out are required unless --score is given")
    try:
        commit = subprocess.run(["git", "-C", args.repo, "rev-parse", "HEAD"], check=True,
                                capture_output=True, text=True).stdout.strip()
        if subprocess.run(["git", "-C", args.repo, "status", "--porcelain"], check=True,
                          capture_output=True, text=True).stdout.strip():
            commit += "-dirty"                # the working tree, not the commit, was scanned
    except (OSError, subprocess.CalledProcessError):
        commit = None
    if args.work:
        os.makedirs(args.work, exist_ok=True)
    work = tempfile.mkdtemp(prefix="official-work-", dir=args.work)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    items = [{**it, "work": work} for it in find_packages(args.repo)]
    if not items:
        sys.exit("no SKILL.md packages found under %s" % args.repo)
    t0, n_err = time.perf_counter(), 0
    with open(args.out, "w", encoding="utf-8") as out, Pool(min(4, max(1, args.workers))) as pool:
        for i, row in enumerate(pool.imap_unordered(scan_one, items, chunksize=4), 1):
            row["commit"] = commit
            n_err += row["error"] is not None
            out.write(json.dumps(row, ensure_ascii=True) + "\n")
            sys.stderr.write("  %d/%d %-30s findings=%d err=%s %.0fs\n" % (
                i, len(items), row["id"], len(row["findings"]), row["error"] is not None,
                time.perf_counter() - t0))
    shutil.rmtree(work, ignore_errors=True)
    sys.stderr.write("done: %d packages, %d errors, commit=%s -> %s\n" % (
        len(items), n_err, commit, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
