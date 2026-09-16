"""Run-to-run reproducibility of the LLM lanes: compare two or more ``msb_run.py --llm-mode``
runs over the same identities.

    python benchmark/msb_llm_repro.py out/run_a.jsonl out/run_b.jsonl [out/run_c.jsonl ...]

For every pair of runs it reports, per label, how many packages carry an SXV-038 finding in
one run but not the other, the Jaccard agreement of the SXV-038 hit sets, and how many
MEDIUM+ effective verdicts differ.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from msb_llm_attrib import _flag  # noqa: E402


def _load(path):
    rows = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                rows[r["benchmark_id"]] = r
    return rows


def _hits(rows):
    return {bid for bid, r in rows.items()
            if any(f.get("vector") == "SXV-038" for f in r["findings"])}


def _medium(rows):
    return {bid for bid, r in rows.items()
            if _flag(r["findings"], effective=True, with_038=True, threshold="medium+")}


def compare(name_a, a, name_b, b):
    common = set(a) & set(b)
    conflict = sorted(bid for bid in common if a[bid]["label"] != b[bid]["label"])
    if conflict:
        raise SystemExit("%s and %s disagree on the label of %d shared identities, e.g. %s" % (
            name_a, name_b, len(conflict), ", ".join(conflict[:3])))
    labels = {bid: a[bid]["label"] for bid in common}
    out = ["### %s vs %s (%d shared identities)" % (name_a, name_b, len(common)), ""]
    for title, pick in (("SXV-038 hit", _hits), ("MEDIUM+ effective verdict", _medium)):
        sa, sb = pick(a) & common, pick(b) & common
        union = sa | sb
        jac = len(sa & sb) / len(union) if union else 1.0
        only_a, only_b = sa - sb, sb - sa
        out += ["| %s | benign | malicious | total |" % title, "|---|---|---|---|"]
        rows = [("in both", sa & sb), ("only in " + name_a, only_a), ("only in " + name_b, only_b)]
        for label_text, group in rows:
            ben = sum(labels[x] == 0 for x in group)
            mal = sum(labels[x] == 1 for x in group)
            out.append("| %s | %d | %d | %d |" % (label_text, ben, mal, len(group)))
        out += ["", "Jaccard agreement of the %s sets: **%.4f**; %d packages disagree "
                "(%d benign, %d malicious)." % (
                    title, jac, len(only_a | only_b),
                    sum(labels[x] == 0 for x in only_a | only_b),
                    sum(labels[x] == 1 for x in only_a | only_b)), ""]
        flips = sorted(only_a | only_b)
        if flips:
            out.append("Disagreeing identities (first 30): " + ", ".join(flips[:30]))
            out.append("")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", nargs="+")
    ap.add_argument("--md")
    args = ap.parse_args(argv)
    runs = [(os.path.basename(p), _load(p)) for p in args.jsonl]
    out = ["# LLM-lane reproducibility", ""]
    for (na, a), (nb, b) in itertools.combinations(runs, 2):
        out += compare(na, a, nb, b)
    text = "\n".join(out)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
