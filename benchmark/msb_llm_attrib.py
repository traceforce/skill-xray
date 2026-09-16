"""Attribute what the LLM lanes changed in a ``msb_run.py --llm-mode`` run.

    python benchmark/msb_llm_attrib.py out/llm.jsonl [--base out/det.jsonl] [--md out/llm.md]
        [--price-in 0.40 --price-out 1.60]      # USD per 1M tokens; default = gpt-4.1-mini

Two lanes: ``review`` (judge disputes on SXV-028/029/030/031 candidates, applied as demotions to
low, visible at every threshold) and ``additive`` (the SXV-038 pass, severity-capped at medium,
visible at MEDIUM+ only). Every package verdict is recomputed four ways -- deterministic, review
only, additive only, both -- at blocking, HIGH+ and MEDIUM+, so each flip is charged to exactly
one lane. Judge decisions are summarised by status and failure cause, and every demotion applied
to a malicious package is listed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from msb_score import _ATTACK, _HC, _MP, incomplete  # noqa: E402

_VIEWS = {"deterministic": (False, False), "review only": (True, False),
          "additive only": (False, True), "review + additive": (True, True)}
_THRESHOLDS = ("blocking", "high+", "medium+")
_SEVS = ("low", "medium", "high", "critical")


def _flag(findings, *, effective, with_038, threshold):
    for f in findings:
        vector = f.get("vector")
        if not vector or (vector == "SXV-038" and not with_038):
            continue
        if effective and f.get("disposition") == "suppressed":
            continue
        sev = f.get("severity")
        if effective and f.get("effective_severity"):
            sev = f["effective_severity"]
        if threshold == "blocking":
            if f.get("tier") in _ATTACK and sev in _HC:
                return True
        elif threshold == "high+":
            if sev in _HC:
                return True
        elif sev in _MP:
            return True
    return False


def _metrics(rows, view, threshold):
    effective, with_038 = _VIEWS[view]
    tp = fp = tn = fn = 0
    for r in rows:
        flagged = _flag(r["findings"], effective=effective, with_038=with_038,
                        threshold=threshold)
        if r["label"] == 1:
            tp += flagged
            fn += not flagged                   # an unscanned attack is a miss, not a pass
        elif flagged:
            fp += 1                             # a positive prediction counts, complete or not
        elif incomplete(r):
            continue                            # an unscanned benign record is not a verified TN
        else:
            tn += 1
    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "precision": p, "recall": rc,
            "f1": 2 * p * rc / (p + rc) if p + rc else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0}


def _flips(rows, view, threshold):
    """Per-label verdict changes between the deterministic view and ``view``."""
    effective, with_038 = _VIEWS[view]
    out = {"benign cleared": [], "benign added": [], "malicious lost": [],
           "malicious gained": []}
    for r in rows:
        before = _flag(r["findings"], effective=False, with_038=False, threshold=threshold)
        after = _flag(r["findings"], effective=effective, with_038=with_038,
                      threshold=threshold)
        if before == after:
            continue
        if r["label"] == 0:
            out["benign cleared" if before else "benign added"].append(r["benchmark_id"])
        else:
            out["malicious lost" if before else "malicious gained"].append(r["benchmark_id"])
    return out


def _pct(x):
    return "%.2f%%" % (100 * x)


def _fmt_row(m):
    return "%s | %s | %s | %s | %d / %d / %d / %d" % (
        _pct(m["precision"]), _pct(m["recall"]), _pct(m["f1"]), _pct(m["fpr"]),
        m["TP"], m["FP"], m["TN"], m["FN"])


def _label(r):
    return "malicious" if r["label"] == 1 else "benign"


def _usage_section(llm_rows, price_in, price_out):
    calls = sum(r["llm_usage"].get("calls", 0) for r in llm_rows)
    in_bytes = sum(r["llm_usage"].get("input_bytes", 0) for r in llm_rows)
    failures = sum(r["llm_usage"].get("failures", 0) for r in llm_rows)
    unavailable = sum(bool(r["llm_usage"].get("unavailable")) for r in llm_rows)
    models = Counter("%s/%s" % (r["llm_usage"].get("provider"), r["llm_usage"].get("model"))
                     for r in llm_rows)
    tokens_in = in_bytes / 4.0
    est = tokens_in / 1e6 * price_in + calls * 250 / 1e6 * price_out
    return ["## Usage", "",
            "| logical calls | input bytes | ~input tokens | transport failures | "
            "records ending unavailable | model |", "|---|---|---|---|---|---|",
            "| %d | %s | %s | %d | %d | %s |" % (
                calls, format(in_bytes, ","), format(int(tokens_in), ","), failures,
                unavailable, ", ".join("%s (%d)" % kv for kv in models.most_common())),
            "",
            "Estimated spend: **$%.2f** (input at $%.2f/M from bytes/4, output assumed 250 "
            "tokens per call at $%.2f/M)." % (
                est, price_in, price_out), ""]


def _verdict_section(rows):
    out = ["## Package verdicts by lane", ""]
    names = {"blocking": "blocking (T1/T2 at high/critical)", "high+": "HIGH+ any tier",
             "medium+": "MEDIUM+ any tier"}
    for threshold in _THRESHOLDS:
        out += ["### %s" % names[threshold], "",
                "| view | precision | recall | F1 | FPR | TP / FP / TN / FN |",
                "|---|---|---|---|---|---|"]
        for view in _VIEWS:
            out.append("| %s | %s |" % (view, _fmt_row(_metrics(rows, view, threshold))))
        out.append("")
        for view in ("review only", "additive only"):
            fl = _flips(rows, view, threshold)
            if not any(fl.values()):
                continue
            out.append("- **%s** flips at %s: %s." % (view, threshold, ", ".join(
                "%s %d" % (k, len(v)) for k, v in fl.items() if v)))
            for k in ("malicious lost", "benign added"):
                if fl[k]:
                    tail = " ..." if len(fl[k]) > 25 else ""
                    out.append("  - %s: %s%s" % (k, ", ".join(fl[k][:25]), tail))
        out.append("")
    return out


def _base_section(rows, base_rows):
    base = {r["benchmark_id"]: r for r in base_rows}
    mismatched = []
    for r in rows:
        b = base.get(r["benchmark_id"])
        if b is None:
            continue
        for threshold in _THRESHOLDS:
            before = _flag(b["findings"], effective=False, with_038=False, threshold=threshold)
            now = _flag(r["findings"], effective=False, with_038=False, threshold=threshold)
            if before != now:
                mismatched.append("%s@%s" % (r["benchmark_id"], threshold))
                break
    matched = sum(r["benchmark_id"] in base for r in rows)
    out = ["## Deterministic consistency against the base run", "",
           "%d of %d records are in the base file; **%d** differ in their deterministic "
           "verdict (should be 0: the LLM run re-scans the same text)." % (
               matched, len(rows), len(mismatched))]
    if mismatched:
        out.append("Differing: " + ", ".join(mismatched[:20]))
    return out + [""]


def _judge_section(llm_rows):
    decisions = [(r, d) for r in llm_rows for d in r.get("review_decisions", [])]
    status = Counter(d["status"] for _, d in decisions)
    failure = Counter(d.get("failure_reason") for _, d in decisions
                      if d["status"] == "invalid-response")
    verdicts = Counter(d.get("verdict") for _, d in decisions if d["status"] == "proposed")
    by_vector = defaultdict(Counter)
    for _, d in decisions:
        by_vector[d["vector"]][d["status"]] += 1
    disputed = [(r, d) for r, d in decisions if d.get("disposition") == "llm-disputed"]
    applied = sum(r.get("llm_applied", 0) for r in llm_rows)
    out = ["## Review lane (the judge)", "",
           "%d eligible decisions on %d records; %d proposals validated; %d disputes "
           "(propose_false_positive at high confidence, mechanism not_supported, intent "
           "legitimate); %d results demoted to low by --llm-apply." % (
               len(decisions), len({r["benchmark_id"] for r, _ in decisions}),
               status.get("proposed", 0), len(disputed), applied), "",
           "| status | count |", "|---|---|"]
    out += ["| %s | %d |" % kv for kv in status.most_common()]
    out.append("")
    if failure:
        out += ["Validation failures by cause:", "", "| failure_reason | count |", "|---|---|"]
        out += ["| %s | %d |" % kv for kv in failure.most_common()]
        out.append("")
        examples = defaultdict(list)
        for r, d in decisions:
            if d["status"] == "invalid-response":
                examples[d.get("failure_reason")].append(
                    "%s/%s" % (r["benchmark_id"], d["vector"]))
        out += ["Validation-failure examples:", ""]
        out += ["- %s: %s" % (k, ", ".join(v[:8])) for k, v in examples.items()]
        out.append("")
    if verdicts:
        out += ["Validated proposals by verdict:", "", "| verdict | count |", "|---|---|"]
        out += ["| %s | %d |" % kv for kv in verdicts.most_common()]
        out.append("")
    if by_vector:
        cols = sorted({s for c in by_vector.values() for s in c})
        out += ["Decisions per vector:", "",
                "| vector | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
        for vector in sorted(by_vector):
            out.append("| %s | %s |" % (vector, " | ".join(
                str(by_vector[vector].get(c, 0)) for c in cols)))
        out.append("")
    if disputed:
        lab = Counter(_label(r) for r, _ in disputed)
        out += ["Disputes by label: benign %d, malicious %d." % (
            lab.get("benign", 0), lab.get("malicious", 0)), ""]
        bad = [(r, d) for r, d in disputed if r["label"] == 1]
        if bad:
            out += ["**Disputes on malicious packages** (each is the judge excusing a labeled "
                    "attack; whether it changed the verdict is in the flips above):", ""]
            out += ["- %s (%s) %s/%s" % (r["benchmark_id"], r.get("source_name"), d["vector"],
                                        d["rule"]) for r, d in bad[:40]]
            out.append("")
        good = [(r, d) for r, d in disputed if r["label"] == 0]
        if good:
            out += ["Disputes on benign packages (sample):", ""]
            out += ["- %s (%s) %s/%s" % (r["benchmark_id"], r.get("source_name"), d["vector"],
                                        d["rule"]) for r, d in good[:15]]
            out.append("")
    return out


def _additive_section(llm_rows):
    hits = defaultdict(Counter)
    recs = Counter()
    notes = Counter()
    for r in llm_rows:
        hit = False
        for f in r["findings"]:
            if f.get("vector") == "SXV-038":
                hits[_label(r)][f.get("severity")] += 1
                hit = True
        recs[_label(r)] += hit
        notes.update({k: v for k, v in (r.get("notes") or {}).items()
                      if str(k).startswith("llm-")})
    out = ["## Additive lane (SXV-038 semantic pass)", "",
           "Records with an SXV-038 finding: benign %d, malicious %d." % (
               recs.get("benign", 0), recs.get("malicious", 0)), "",
           "| label | " + " | ".join(_SEVS) + " |", "|---|---|---|---|---|"]
    for label in ("benign", "malicious"):
        out.append("| %s | %s |" % (label, " | ".join(
            str(hits[label].get(s, 0)) for s in _SEVS)))
    out.append("")
    if notes:
        out += ["LLM coverage notes (fail-closed markers; each is a record the pass could not "
                "judge):", "", "| note | count |", "|---|---|"]
        out += ["| %s | %d |" % kv for kv in notes.most_common()]
        out.append("")
    return out


def report(rows, base_rows, price_in, price_out, title):
    llm_rows = [r for r in rows if r.get("llm_usage") is not None]
    errors = [r for r in rows if r.get("error")]
    out = ["# %s" % title, "",
           "%d records, %d with an LLM session, %d record errors." % (
               len(rows), len(llm_rows), len(errors))]
    if errors:
        out.append("Errors: " + "; ".join(
            "%s: %s" % (r["benchmark_id"], r["error"][:80]) for r in errors[:5]))
    out.append("")
    out += _usage_section(llm_rows, price_in, price_out)
    out += _verdict_section(rows)
    if base_rows is not None:
        out += _base_section(rows, base_rows)
    out += _judge_section(llm_rows)
    out += _additive_section(llm_rows)
    return "\n".join(out)


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--base", metavar="DET_JSONL", help="deterministic run on the same split")
    ap.add_argument("--md")
    ap.add_argument("--title", default=None)
    ap.add_argument("--price-in", type=float, default=0.40)
    ap.add_argument("--price-out", type=float, default=1.60)
    args = ap.parse_args(argv)
    rows = _load(args.jsonl)
    base = _load(args.base) if args.base else None
    text = report(rows, base, args.price_in, args.price_out,
                  args.title or "LLM-lane attribution: %s" % os.path.basename(args.jsonl))
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
