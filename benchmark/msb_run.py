"""Run skill-xray over ProtectSkills/MaliciousSkillBench and write one JSONL row per identity.

Each identity's inline ``skill_text`` is materialized as a one-file package, scanned in-process
and removed; nothing is executed. Per-record errors, oversize texts (ingest skips files over
1 MiB) and unreadable materializations are recorded, never counted as clean.

    python benchmark/msb_run.py --data <dir with primary.parquet + splits/> --split test \
        --out out/msb_test.jsonl [--workers N] [--sample-per-label 150]

LLM modes (opt-in; they send skill text to the configured provider, see README): ``--llm-mode
review`` (the judge with ``--llm-apply`` demotion; pair with ``--only-flagged <det.jsonl>``),
``--llm-mode additive`` (the SXV-038 pass), ``--llm-mode both``. ``--fake-llm`` is a plumbing
check with a canned client. Rows from LLM modes carry ``effective_severity`` and
``disposition``; score them with ``msb_score.py --effective``.
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
from collections import Counter
from multiprocessing import Pool
from types import SimpleNamespace

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from skill_xray.findings import vector_meta  # noqa: E402
from skill_xray.ingest import MAX_FILE_BYTES, build_ledger, build_package  # noqa: E402
from skill_xray.parse import parse_package  # noqa: E402
from skill_xray.scan import scan, scan_report  # noqa: E402

_WORK = None
_MODE = "none"
_CLIENT = None


class _FakeLLM:
    """Plumbing check only: disputes every reviewable directive with a verbatim quote and
    returns a benign SXV-038 verdict, so the harness path can be exercised without a network."""

    cfg = SimpleNamespace(provider="fake", model="fake-1")

    def complete(self, system, user):
        request = json.loads(user) if user.lstrip().startswith("{") else None
        if request and "candidate" in request:
            quote = request["snippet"].strip().split("\n")[0][:120] or "x"
            return json.dumps({
                "candidate_id": request["candidate"]["candidate_id"],
                "verdict": "propose_false_positive", "confidence": "high",
                "mechanism": "not_supported", "intent": "legitimate",
                "reason": "fake plumbing check", "impact": "none", "evidence_quote": quote})
        return '{"prompt_injection": false, "severity": "low", "reason": "fake"}'


def _build_client(fake):
    if fake:
        return _FakeLLM()
    from skill_xray.llm import build_client, from_env
    cfg = from_env()
    if cfg is None:
        raise SystemExit("LLM mode needs SKILLXRAY_LLM_PROVIDER and an API key in the environment")
    return build_client(cfg)


def _init(work_root, mode, fake):
    global _WORK, _MODE, _CLIENT
    _WORK = work_root
    _MODE = mode
    _CLIENT = _build_client(fake) if mode != "none" else None


def _finding_row(f):
    d = f.to_dict()
    return {"vector": d.get("vector", ""), "rule": d.get("rule"), "severity": d.get("severity"),
            "tier": d.get("tier"), "line": d.get("line")}


def _result_row(result):
    finding = result["finding"]
    meta = vector_meta(finding.get("vector") or "") or {}
    return {"vector": finding.get("vector", ""), "rule": finding.get("rule"),
            "severity": finding.get("severity"), "effective_severity": result["effective_severity"],
            "disposition": result["disposition"], "provenance": result["decision_provenance"],
            "tier": meta.get("tier"), "line": finding.get("line")}


def _decision_row(d, cands):
    """One judge decision: the finding it reviewed, how it validated, what it proposed."""
    finding = cands.get(d.get("candidate_id"), {})
    proposal = d.get("proposal") or {}
    return {"vector": finding.get("vector", ""), "rule": finding.get("rule"),
            "status": d.get("status"), "disposition": d.get("disposition"),
            "failure_reason": d.get("failure_reason"),
            "verdict": proposal.get("verdict"), "confidence": proposal.get("confidence"),
            "mechanism": proposal.get("mechanism"), "intent": proposal.get("intent")}


def scan_one(rec):
    """Materialize one identity as <work>/<benchmark_id>/SKILL.md, scan it, delete it."""
    bid, text = rec["benchmark_id"], rec["text"]
    row = {"benchmark_id": bid, "split": rec["split"], "label": int(rec["label"]),
           "source_name": rec["source_name"], "attack_categories": rec["attack_categories"],
           "tlen": len(text),
           "oversize": len(text.encode("utf-8", "surrogatepass")) > MAX_FILE_BYTES,
           "findings": [], "error": None, "ledger_skipped": 0, "analyzed": 0, "elapsed_ms": 0}
    # the dataset id is data, not a path: a sanitized stem plus a hash keeps every record in
    # its own child of the scratch root, whatever the id contains
    root = os.path.join(_WORK, "%s-%s" % (re.sub(r"[^A-Za-z0-9_-]", "_", bid)[:40],
                                          hashlib.sha1(bid.encode("utf-8")).hexdigest()[:10]))
    t0 = time.perf_counter()
    try:
        os.makedirs(root, exist_ok=True)
        with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8",
                  errors="surrogatepass", newline="") as fh:
            fh.write(text)
        pkg = build_package(root)
        ledger = build_ledger(pkg)
        row["ledger_skipped"] = ledger["artifactsSkipped"]
        row["analyzed"] = ledger["artifactsAnalyzed"]
        parsed = parse_package(pkg)
        if _MODE == "none":
            row["findings"] = [_finding_row(f) for f in scan(parsed)]
        else:
            review = _MODE in ("review", "both")
            report = scan_report(parsed, client=_CLIENT, llm_review=review, llm_apply=review,
                                 llm_advisory=_MODE in ("additive", "both"), max_llm_calls=25)
            row["findings"] = [_result_row(r) for r in report.correlation.get("results", [])]
            row["review"] = dict(Counter(
                "%s/%s" % (d.get("status"), d.get("disposition")) for d in report.dispositions))
            row["llm_applied"] = report.correlation.get("llm_applied", 0)
            row["llm_usage"] = report.llm_usage
            row["context_errors"] = report.context_errors
            cands = {c["candidate_id"]: c["finding"] for c in report.raw_candidates}
            row["review_decisions"] = [_decision_row(d, cands) for d in report.dispositions
                                       if d.get("status") != "ineligible"]
            row["notes"] = dict(Counter(f.rule for f in report.findings if not f.vector))
    except Exception as exc:  # a crashing record is a coverage gap, recorded not hidden
        row["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
        row["trace"] = traceback.format_exc()[-800:]
    finally:
        row["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
        shutil.rmtree(root, ignore_errors=True)
    return row


def load_records(data_dir, split, sample_per_label=None, seed=7, only_ids=None):
    primary = pd.read_parquet(os.path.join(data_dir, "primary.parquet"))
    splits = pd.read_parquet(os.path.join(data_dir, "splits", "source_disjoint.parquet"))
    splits = splits.rename(columns={"label": "split_label"})
    df = splits.merge(primary, on="benchmark_id", how="inner")
    df["label"] = df["label"].astype(int)
    wanted = {"dev": {"train", "validation"}}.get(split, {split})
    df = df[df["split"].isin(wanted)].copy()
    df["text"] = df["skill_text"].where(df["skill_text"].notna(), df["public_skill_text"])
    df = df[df["text"].notna()]
    if only_ids is not None:
        df = df[df["benchmark_id"].isin(only_ids)]
    if sample_per_label:
        df = (df.groupby("label", group_keys=False)
                .apply(lambda g: g.sample(min(len(g), sample_per_label), random_state=seed)))
    df["attack_categories"] = df["attack_categories"].apply(
        lambda v: list(v) if v is not None and not isinstance(v, float) else [])
    cols = ["benchmark_id", "split", "label", "source_name", "attack_categories", "text"]
    return df[cols].to_dict("records")


def _flagged_ids(path):
    """benchmark_ids that had any real finding in a prior deterministic run."""
    ids = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            if any(f.get("vector") for f in row["findings"]):
                ids.add(row["benchmark_id"])
    return ids


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--split", default="test", choices=("test", "dev", "train", "validation"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--sample-per-label", type=int, default=None)
    ap.add_argument("--work", default=None,
                    help="parent for the scratch packages; a fresh subdirectory is created and "
                         "removed (default: the system temp dir)")
    ap.add_argument("--llm-mode", choices=("none", "review", "additive", "both"), default="none")
    ap.add_argument("--fake-llm", action="store_true", help="plumbing check only, no network")
    ap.add_argument("--only-flagged", metavar="DET_JSONL",
                    help="restrict to records a prior deterministic run flagged")
    args = ap.parse_args(argv)

    if args.fake_llm and args.llm_mode == "none":
        ap.error("--fake-llm requires an --llm-mode")
    if args.llm_mode != "none" and not args.fake_llm:
        _build_client(False)                       # fail on a missing key BEFORE any scan
    only = _flagged_ids(args.only_flagged) if args.only_flagged else None
    records = load_records(args.data, args.split, args.sample_per_label, only_ids=only)
    workers = args.workers or (4 if args.llm_mode != "none" else max(4, (os.cpu_count() or 8) - 1))
    work = tempfile.mkdtemp(prefix="msb-work-", dir=args.work)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    t0 = time.perf_counter()
    n_err = 0
    with open(args.out, "w", encoding="utf-8") as out, \
            Pool(workers, initializer=_init, initargs=(work, args.llm_mode, args.fake_llm)) as pool:
        for i, row in enumerate(pool.imap_unordered(scan_one, records, chunksize=4), 1):
            n_err += row["error"] is not None
            out.write(json.dumps(row, ensure_ascii=True) + "\n")
            if i % 250 == 0 or i == len(records):
                sys.stderr.write("  %d/%d  errors=%d  %.0fs\n" % (
                    i, len(records), n_err, time.perf_counter() - t0))
    shutil.rmtree(work, ignore_errors=True)
    sys.stderr.write("done: %d records, %d errors, %.1fs, mode=%s -> %s\n" % (
        len(records), n_err, time.perf_counter() - t0, args.llm_mode, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
