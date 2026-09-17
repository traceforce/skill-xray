"""Score a msb_run.py JSONL under several package-level verdict definitions.

"blocking" (the headline) mirrors Cisco skill-scanner's HIGH/CRITICAL threshold plus the attack
tiers: a package is flagged only by a T1/T2 vector at high or critical severity. T3 findings are
reported as a separate rate and never count in that headline; the HIGH+, MEDIUM+ and any-finding
views include every tier.

    python benchmark/msb_score.py out/msb_test.jsonl [--md out/msb_test.md]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict

_HC = {"high", "critical"}
_MP = {"medium", "high", "critical"}
_ATTACK = {"T1", "T2"}


_EFFECTIVE = False


def _real(fs):
    """Real findings, with the correlated effective severity when --effective is on: a result an
    LLM review demoted (or an operator suppressed) then scores at its corrected level."""
    out = []
    for f in fs:
        if not f.get("vector") or f.get("disposition") == "suppressed" and _EFFECTIVE:
            continue
        if _EFFECTIVE and f.get("effective_severity"):
            f = {**f, "severity": f["effective_severity"]}
        out.append(f)
    return out


VERDICTS = {
    "blocking (T1/T2 and high/critical)": lambda fs: any(
        f["tier"] in _ATTACK and f["severity"] in _HC for f in _real(fs)),
    "high/critical any tier": lambda fs: any(f["severity"] in _HC for f in _real(fs)),
    "medium+ any tier": lambda fs: any(f["severity"] in _MP for f in _real(fs)),
    "any finding": lambda fs: bool(_real(fs)),
}


_LLM_FAILED = {"llm-error", "llm-unavailable", "llm-budget", "llm-unparseable", "llm-inconclusive"}


def incomplete(r):
    """The scan of this record did not complete: an exception, an oversize or skipped file, a
    high-severity diagnostic without a vector (a check error, an OpenGrep failure, an incomplete
    analysis), or an LLM lane that did not run or gave no verdict (error, unavailable, budget,
    unparseable, inconclusive); truncation is not a failure. Derived from the row so runs written
    before this field existed score the same."""
    return bool(r.get("error") or r.get("oversize") or r.get("ledger_skipped")
                or any(not f.get("vector")
                       and (f.get("severity") == "high" or f.get("rule") in _LLM_FAILED)
                       for f in r["findings"]))


def metrics(rows, verdict):
    tp = fp = tn = fn = unanalyzed = 0
    for r in rows:
        flagged = verdict(r["findings"])
        if r["label"] == 1:
            tp += flagged
            fn += not flagged                   # an unscanned attack is a miss, not a pass
        elif flagged:
            fp += 1                             # a positive prediction counts, complete or not
        elif incomplete(r):
            unanalyzed += 1                     # an unscanned benign record is not a verified TN
        else:
            tn += 1
    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "precision": p, "recall": rc,
            "f1": f1, "fpr": fpr, "unanalyzed_benign": unanalyzed}


def analyze(rows, blocking):
    """Rank what drives false positives and what the misses look like."""
    fp_vectors, fp_rules, fp_sources = Counter(), Counter(), Counter()
    t3_only_benign = 0
    for r in rows:
        if r["label"] != 0:
            continue
        real = _real(r["findings"])
        if blocking(r["findings"]):
            fp_sources[r["source_name"]] += 1
            seen = set()
            for f in real:
                if f["tier"] in _ATTACK and f["severity"] in _HC and f["vector"] not in seen:
                    seen.add(f["vector"])
                    fp_vectors[f["vector"]] += 1
                    fp_rules[(f["vector"], f["rule"])] += 1
        elif real and all(f["tier"] not in _ATTACK for f in real):
            t3_only_benign += 1
    fn_cats, fn_sources, tp_cats = Counter(), Counter(), Counter()
    for r in rows:
        if r["label"] != 1:
            continue
        cats = r["attack_categories"] or ["(unmapped)"]
        if blocking(r["findings"]):
            for c in cats:
                tp_cats[c] += 1
        else:
            fn_sources[r["source_name"]] += 1
            for c in cats:
                fn_cats[c] += 1
    recall_by_cat = {c: (tp_cats[c], tp_cats[c] + fn_cats[c]) for c in set(tp_cats) | set(fn_cats)}
    return {"fp_vectors": fp_vectors, "fp_rules": fp_rules, "fp_sources": fp_sources,
            "t3_only_benign": t3_only_benign, "fn_sources": fn_sources,
            "recall_by_category": recall_by_cat}


def report(rows, title):
    lines = ["# %s" % title, "",
             "records: %d  (malicious %d / benign %d)  errors: %d  oversize: %d" % (
                 len(rows), sum(r["label"] == 1 for r in rows), sum(r["label"] == 0 for r in rows),
                 sum(r.get("error") is not None for r in rows),
                 sum(bool(r.get("oversize")) for r in rows)),
             "", "| verdict | TP | FP | TN | FN | precision | recall | F1 | FPR |",
             "|---|---|---|---|---|---|---|---|---|"]
    for name, fn in VERDICTS.items():
        m = metrics(rows, fn)
        lines.append("| %s | %d | %d | %d | %d | %.2f%% | %.2f%% | %.2f%% | %.2f%% |" % (
            name, m["TP"], m["FP"], m["TN"], m["FN"], 100 * m["precision"], 100 * m["recall"],
            100 * m["f1"], 100 * m["fpr"]))
    unanalyzed = metrics(rows, VERDICTS["any finding"])["unanalyzed_benign"]
    if unanalyzed:
        lines += ["", "benign records whose scan did not complete and that carry no finding, "
                  "excluded from TN and FPR: %d" % unanalyzed]
    a = analyze(rows, VERDICTS["blocking (T1/T2 and high/critical)"])
    lines += ["", "## Where the blocking false positives come from",
              "benign packages with ONLY T3 capability findings (correctly not counted): %d" %
              a["t3_only_benign"], "", "| vector | benign FPs |", "|---|---|"]
    lines += ["| %s | %d |" % kv for kv in a["fp_vectors"].most_common()]
    lines += ["", "| vector / rule | benign FPs |", "|---|---|"]
    lines += ["| %s / %s | %d |" % (v, r, n) for (v, r), n in a["fp_rules"].most_common(25)]
    lines += ["", "| benign source | FPs |", "|---|---|"]
    lines += ["| %s | %d |" % kv for kv in a["fp_sources"].most_common()]
    lines += ["", "## Recall by attack category (blocking verdict)", "",
              "| attack category | caught / total | recall |", "|---|---|---|"]
    for c, (tp, tot) in sorted(a["recall_by_category"].items(), key=lambda kv: -kv[1][1]):
        lines.append("| %s | %d / %d | %.1f%% |" % (c, tp, tot, 100 * tp / tot if tot else 0))
    lines += ["", "| malicious source | misses |", "|---|---|"]
    lines += ["| %s | %d |" % kv for kv in a["fn_sources"].most_common()]
    vec_by_label = defaultdict(Counter)
    for r in rows:
        for v in {f["vector"] for f in _real(r["findings"])}:
            vec_by_label[r["label"]][v] += 1
    lines += ["", "## Vector hit counts (packages), malicious vs benign", "",
              "| vector | tier | malicious | benign |", "|---|---|---|---|"]
    tiers = {f["vector"]: f["tier"] for r in rows for f in _real(r["findings"])}
    for v in sorted(set(vec_by_label[1]) | set(vec_by_label[0])):
        lines.append("| %s | %s | %d | %d |" % (v, tiers.get(v), vec_by_label[1][v],
                                               vec_by_label[0][v]))
    errs = Counter(r["error"].split(":")[0] for r in rows if r.get("error"))
    if errs:
        lines += ["", "## Errors", ""] + ["- %s: %d" % kv for kv in errs.most_common()]
    return "\n".join(lines) + "\n"


def compare(rows, base_rows):
    """Before/after on the same identities: metrics per verdict, blocking-FP vectors, and which
    vectors carry the newly caught malicious packages. An after-run that covers a subset of the
    base identities (``--only-flagged``) leaves every other base record unchanged, so the numbers
    describe the whole split rather than the subset."""
    base = {r["benchmark_id"]: r for r in base_rows}
    after_by = {r["benchmark_id"]: r for r in rows if r["benchmark_id"] in base}
    unknown = sorted(r["benchmark_id"] for r in rows if r["benchmark_id"] not in base)
    if unknown:
        raise SystemExit("--compare: %d after-run identities are not in the base run, e.g. %s"
                         % (len(unknown), ", ".join(unknown[:3])))
    if rows and not after_by:
        raise SystemExit("--compare: the after-run shares no identity with the base run")
    carried = len(base) - len(after_by)
    paired = [(after_by.get(bid, b), b) for bid, b in base.items()]
    after, before = [a for a, _ in paired], [b for _, b in paired]
    lines = ["", "## Before / after on %d paired identities%s" % (
        len(paired), " (%d carried over unchanged from the base run: the after-run is a subset)"
        % carried if carried else ""), "",
             "| verdict | before P / R / F1 / FPR | after P / R / F1 / FPR "
             "| TP FP TN FN before -> after |",
             "|---|---|---|---|"]
    for name, fn in VERDICTS.items():
        mb, ma = metrics(before, fn), metrics(after, fn)
        lines.append("| %s | %.2f%% / %.2f%% / %.2f%% / %.2f%% | %.2f%% / %.2f%% / %.2f%% / %.2f%% "
                     "| %d %d %d %d -> %d %d %d %d |" % (
                         name, 100 * mb["precision"], 100 * mb["recall"], 100 * mb["f1"],
                         100 * mb["fpr"], 100 * ma["precision"], 100 * ma["recall"],
                         100 * ma["f1"], 100 * ma["fpr"], mb["TP"], mb["FP"], mb["TN"], mb["FN"],
                         ma["TP"], ma["FP"], ma["TN"], ma["FN"]))
    blocking = VERDICTS["blocking (T1/T2 and high/critical)"]

    def hot(fs):
        return {f["vector"] for f in _real(fs) if f["tier"] in _ATTACK and f["severity"] in _HC}

    def fp_vectors(rs):
        c = Counter()
        for r in rs:
            if r["label"] == 0 and blocking(r["findings"]):
                for v in hot(r["findings"]):
                    c[v] += 1
        return c

    fb, fa = fp_vectors(before), fp_vectors(after)
    lines += ["", "| blocking FP vector (benign) | before | after |", "|---|---|---|"]
    lines += ["| %s | %d | %d |" % (v, fb[v], fa[v]) for v in sorted(set(fb) | set(fa))]
    new_tp = [a for a, b in paired if a["label"] == 1
              and blocking(a["findings"]) and not blocking(b["findings"])]
    lost_tp = [a for a, b in paired if a["label"] == 1
               and not blocking(a["findings"]) and blocking(b["findings"])]
    new_fp = [a for a, b in paired if a["label"] == 0
              and blocking(a["findings"]) and not blocking(b["findings"])]
    fixed_fp = [a for a, b in paired if a["label"] == 0
                and not blocking(a["findings"]) and blocking(b["findings"])]
    lines += ["", "newly caught malicious: %d | malicious lost: %d | benign FPs fixed: %d | "
              "new benign FPs: %d" % (len(new_tp), len(lost_tp), len(fixed_fp), len(new_fp))]
    carrier = Counter(v for a in new_tp for v in hot(a["findings"]))
    lines += ["", "| vector carrying the newly caught malicious | packages |", "|---|---|"]
    lines += ["| %s | %d |" % kv for kv in carrier.most_common()]
    cats = Counter(c for a in new_tp for c in (a["attack_categories"] or ["(unmapped)"]))
    lines += ["", "| attack category of the newly caught | packages |", "|---|---|"]
    lines += ["| %s | %d |" % kv for kv in cats.most_common()]
    if new_fp:
        lines += ["", "new benign FP ids: " + ", ".join(a["benchmark_id"] for a in new_fp[:25])]
    if lost_tp:
        lines += ["lost malicious ids: " + ", ".join(a["benchmark_id"] for a in lost_tp[:25])]
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--md")
    ap.add_argument("--title", default=None)
    ap.add_argument("--compare", metavar="BASE_JSONL",
                    help="a prior run over the same identities; appends a before/after section")
    ap.add_argument("--exclude-vectors", default="",
                    help="comma-separated vectors to drop before scoring; detection is additive "
                         "and deterministic, so this reconstructs a pre-detector baseline from "
                         "the same run (e.g. --exclude-vectors SXV-042)")
    ap.add_argument("--effective", action="store_true",
                    help="score on each result's correlated effective_severity (LLM-mode runs)")
    args = ap.parse_args(argv)
    global _EFFECTIVE
    _EFFECTIVE = args.effective
    with open(args.jsonl, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    drop = {v.strip() for v in args.exclude_vectors.split(",") if v.strip()}
    if drop:
        for r in rows:
            r["findings"] = [f for f in r["findings"] if f.get("vector") not in drop]
    text = report(rows, args.title or args.jsonl)
    if args.compare:
        with open(args.compare, encoding="utf-8") as fh:
            base_rows = [json.loads(line) for line in fh if line.strip()]
        text += "\n".join(compare(rows, base_rows)) + "\n"
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
