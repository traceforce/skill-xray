"""Adapt InjecAgent (github.com/uiuc-kang-lab/InjecAgent) to skill-xray and score recall.

InjecAgent has no benign class, so the metric is target-signal recall: the share of unique
attacker instructions (``data/attacker_cases_*.jsonl``) on which an injection-class vector fires
at any severity when scanned as the body of a SKILL.md. ``--unit response`` scans the per-row
tool responses instead; "enhanced" prepends the dataset's hacking prompt. Nothing is executed.

    python benchmark/adapters/injecagent_run.py --repo <clone> --out out.jsonl \
        [--variant base|enhanced|both] [--unit canonical|response|both] [--workers 4] [--llm]
    python benchmark/adapters/injecagent_run.py --score out.jsonl [--summary SUMMARY.json]

``--llm`` adds the advisory SXV-038 pass (needs SKILLXRAY_LLM_PROVIDER and a key; sends every
instruction to the provider). SXV-038 and SXV-043 count as injection-class signal.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from skill_xray.ingest import build_package  # noqa: E402
from skill_xray.parse import parse_package  # noqa: E402
from skill_xray.scan import scan, scan_report  # noqa: E402

INJECTION = {"SXV-027", "SXV-028", "SXV-029", "SXV-030", "SXV-031", "SXV-038", "SXV-041",
             "SXV-042", "SXV-043"}
_CLIENT = None


def _init(llm):
    global _CLIENT
    if llm:
        from skill_xray.llm import build_client, from_env
        cfg = from_env()
        if cfg is None:
            raise SystemExit("--llm needs SKILLXRAY_LLM_PROVIDER and an API key")
        _CLIENT = build_client(cfg)
_HC = {"high", "critical"}
_MP = {"medium", "high", "critical"}
_SPLITS = {"dh": "attacker_cases_dh.jsonl", "ds": "attacker_cases_ds.jsonl"}
_KEYS = ("vector", "rule", "severity", "tier", "line")
_OVERRIDE_RE = re.compile(r"\b(?:ignore|disregard|forget|override)\b|system prompt|jailbreak", re.I)
_EXFIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.\w+|https?://|\b(?:email|e-mail|send|forward|share|"
                       r"upload|post|text|message)\b[^.]{0,120}?\bto\b", re.I)  # miss shapes


def _load(repo, name):
    with open(os.path.join(repo, "data", name), encoding="utf-8") as fh:
        text = fh.read()
    return json.loads(text) if name.endswith(".json") else [
        json.loads(line) for line in text.splitlines() if line.strip()]


def load_canonical(repo):
    """Unique whitespace-normalised attacker instructions, first-seen order, tagged by split."""
    seen, items = set(), []
    for split, name in _SPLITS.items():
        for i, r in enumerate(_load(repo, name)):
            key = re.sub(r"\s+", " ", r["Attacker Instruction"]).strip()
            if key not in seen:
                seen.add(key)
                items.append({"id": "%s-%02d" % (split, i), "split": split, "unit": "canonical",
                              "category": r["Attack Type"], "text": key})
    return items


def load_responses(repo, variant):  # per-row tool responses carrying the injection
    return [{"id": "%s-%s-resp-%04d" % (split, variant, i), "split": split, "unit": "response",
             "variant": variant, "category": r["Attack Type"], "text": r["Tool Response"]}
            for split in _SPLITS
            for i, r in enumerate(_load(repo, "test_cases_%s_%s.json" % (split, variant)))]


def enhanced_prefix(repo):
    """Recover the hacking prompt the enhanced setting inserts; it must be one constant string."""
    prefixes = set()
    for split in _SPLITS:
        base = _load(repo, "test_cases_%s_base.json" % split)
        for b, e in zip(base, _load(repo, "test_cases_%s_enhanced.json" % split), strict=True):
            instr = b["Attacker Instruction"]
            bi, ei = b["Tool Response"].find(instr), e["Tool Response"].find(instr)
            if instr != e["Attacker Instruction"] or bi < 0 or ei < bi:
                raise SystemExit("base/enhanced rows do not align in %s" % split)
            prefixes.add(e["Tool Response"][bi:ei])
    if len(prefixes) != 1:
        raise SystemExit("expected one enhanced prefix, found %d" % len(prefixes))
    return prefixes.pop()


def scan_one(item):
    """Materialize one item as <work>/<id>/SKILL.md, read it back, scan it, delete it."""
    row = {k: item.get(k) for k in ("id", "split", "unit", "variant", "category")}
    row.update({"label": "attack", "tlen": len(item["text"]), "findings": [], "error": None})
    root = os.path.join(item["work"], item["id"])
    try:
        os.makedirs(root, exist_ok=True)
        path = os.path.join(root, "SKILL.md")
        body = "---\nname: %s\n---\n%s" % (item["id"], item["text"])
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(body)
        with open(path, encoding="utf-8", newline="") as fh:
            if fh.read() != body:
                raise OSError("SKILL.md did not read back identically")
        parsed = parse_package(build_package(root))
        if _CLIENT is None:
            findings = scan(parsed)
        else:
            report = scan_report(parsed, client=_CLIENT, llm_review=False, llm_advisory=True,
                                 max_llm_calls=5)
            findings = report.findings
            row["llm_usage"] = report.llm_usage
        dicts = [f.to_dict() for f in findings]
        row["findings"] = [{k: d.get(k) for k in _KEYS} for d in dicts]
    except Exception as exc:  # a crashing item is a coverage gap: recorded, never dropped
        row["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return row


def _wilson(k, n, z=1.96):
    p, zz = k / n, z * z  # Wilson 95% interval for k/n, n > 0
    centre, half = p + zz / (2 * n), z * math.sqrt(p * (1 - p) / n + zz / (4 * n * n))
    return [round(max(0.0, centre - half) / (1 + zz / n), 4),
            round((centre + half) / (1 + zz / n), 4)]


def _miss_shape(text):
    return ("override-language" if _OVERRIDE_RE.search(text) else
            "exfil-shaped task" if _EXFIL_RE.search(text) else "pure task request")


def score_group(rows, texts):
    real = {r["id"]: [f for f in r["findings"] if f.get("vector")] for r in rows}
    inj = {i: [f for f in fs if f["vector"] in INJECTION] for i, fs in real.items()}
    n, hit = len(rows), sum(bool(v) for v in inj.values())

    def n_with(pred, pool=real):
        return sum(any(pred(f) for f in v) for v in pool.values())

    counts = {"total": n, "errors": sum(r["error"] is not None for r in rows),
              "injection_any": hit, "any_vector": sum(bool(v) for v in real.values()),
              "injection_medium_plus": n_with(lambda f: f["severity"] in _MP, inj),
              "medium_plus": n_with(lambda f: f["severity"] in _MP),
              "high_plus": n_with(lambda f: f["severity"] in _HC),
              "critical": n_with(lambda f: f["severity"] == "critical"),
              "blocking": n_with(lambda f: f["tier"] in {"T1", "T2"} and f["severity"] in _HC)}
    cats = Counter(r["category"] for r in rows)
    hits = Counter(r["category"] for r in rows if inj[r["id"]])
    misses = [r["id"] for r in rows if not inj[r["id"]] and r["error"] is None]
    vectors = Counter(v for fs in real.values() for v in {f["vector"] for f in fs})
    rules = Counter("%s/%s" % (f["vector"], f["rule"]) for fs in real.values() for f in fs)
    return {"counts": counts, "recall": round(hit / n, 4) if n else 0.0, "ci95": _wilson(hit, n),
            "per_vector": dict(vectors.most_common()), "per_rule": dict(rules.most_common(12)),
            "per_category": {c: {"hit": hits[c], "total": t} for c, t in sorted(cats.items())},
            "misses": len(misses), "miss_shapes": dict(Counter(
                _miss_shape(texts[i]) for i in misses if i in texts))}


def score(path, summary_path=None):
    with open(path, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    meta_path = path + ".meta.json"
    meta = json.load(open(meta_path, encoding="utf-8")) if os.path.exists(meta_path) else {}
    texts = meta.pop("canonical_texts", {})
    groups = defaultdict(list)
    for r in rows:
        groups["%s/%s" % (r["unit"], r["variant"])].append(r)
    out = {"dataset": "InjecAgent", "metric": "target signal recall (injection-class vector at any "
           "severity, per canonical attacker instruction)", "groups": {}, **meta}
    for name, grp in sorted(groups.items()):
        g = out["groups"][name] = score_group(grp, texts)
        c = g["counts"]
        print("%-19s injection-class recall %d/%d = %.2f%%  ci95=%s  %s" % (
            name, c["injection_any"], c["total"], 100 * g["recall"], g["ci95"], json.dumps(
                {**c, "vectors": g["per_vector"], "miss_shapes": g["miss_shapes"]})))
    if summary_path:
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1, sort_keys=True)
    return 0


def main(argv=None):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", help="path of a `git clone --depth 1` of uiuc-kang-lab/InjecAgent")
    ap.add_argument("--out", help="JSONL to write, one row per scanned item")
    ap.add_argument("--variant", choices=("base", "enhanced", "both"), default="both")
    ap.add_argument("--unit", choices=("canonical", "response", "both"), default="canonical")
    ap.add_argument("--workers", type=int, default=4, help="max 4")
    ap.add_argument("--work", default=None, help="scratch root for materialized packages")
    ap.add_argument("--score", metavar="JSONL", help="score an existing run instead of scanning")
    ap.add_argument("--summary", metavar="JSON", help="with --score: write every number here")
    ap.add_argument("--llm", action="store_true",
                    help="add the advisory SXV-038 pass (sends texts to the configured provider)")
    args = ap.parse_args(argv)
    if args.score:
        return score(args.score, args.summary)
    if not (args.repo and args.out):
        ap.error("--repo and --out are required to scan")
    if args.llm:
        _init(True)                      # fail on a missing key in the parent, before any worker
    variants = ("base", "enhanced") if args.variant == "both" else (args.variant,)
    prefix, canonical, items = enhanced_prefix(args.repo), load_canonical(args.repo), []
    work = args.work or args.out + ".work"
    for v in variants:
        if args.unit != "response":
            items += [{**c, "id": "%s-%s" % (c["id"], v), "variant": v, "work": work,
                       "text": (prefix if v == "enhanced" else "") + c["text"]} for c in canonical]
        if args.unit != "canonical":
            items += [{**r, "work": work} for r in load_responses(args.repo, v)]
    rev = subprocess.run(["git", "-C", args.repo, "rev-parse", "HEAD"], capture_output=True,
                         text=True).stdout.strip()
    os.makedirs(work, exist_ok=True)
    n_err = 0
    with open(args.out, "w", encoding="utf-8") as out, \
            Pool(min(args.workers, 4), initializer=_init, initargs=(args.llm,)) as pool:
        for i, row in enumerate(pool.imap_unordered(scan_one, items, chunksize=4), 1):
            n_err += row["error"] is not None
            out.write(json.dumps(row, ensure_ascii=True) + "\n")
            if i % 250 == 0 or i == len(items):
                sys.stderr.write("  %d/%d errors=%d\n" % (i, len(items), n_err))
    with open(args.out + ".meta.json", "w", encoding="utf-8") as fh:
        json.dump({"repo": "https://github.com/uiuc-kang-lab/InjecAgent", "revision": rev,
                   "canonical_count": len(canonical), "enhanced_prefix": prefix,
                   "canonical_texts": {i["id"]: i["text"] for i in items
                                       if i["unit"] == "canonical"}}, fh, indent=1)
    shutil.rmtree(work, ignore_errors=True)
    sys.stderr.write("done: %d items, %d errors -> %s\n" % (len(items), n_err, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
