"""Write internal/correlate/testdata/canonical.jsonl from the oracle's correlate.canonical.

Run: python tools/parity/gen_correlate_golden.py
Rows are {"value", "canonical", "digest"}: values shaped like the objects correlate digests
(candidate values, anchors, artifact contexts with tuple diagnostics, context documents, results)
captured from the oracle on two temporary packages, plus adversarial JSON values.
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(ROOT, "internal", "correlate", "testdata", "canonical.jsonl")
ORACLE = ROOT
sys.path[:0] = [os.path.join(ORACLE, "src"), os.path.join(ORACLE, "tests")]
from test_correlate import candidate, loc  # noqa: E402

from skill_xray import correlate as c  # noqa: E402
from skill_xray import ingest, parse  # noqa: E402


def package(files):
    root = os.path.join(tempfile.mkdtemp(), "pkg")
    os.makedirs(root)
    for rel, body in files.items():
        dest = os.path.join(root, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(body if isinstance(body, bytes) else body.encode("utf-8"))
    return parse.parse_package(ingest.build_package(root))


def oracle_values():
    trace = {"taint_source": loc(1, "source = input()"), "intermediate_vars": [],
             "taint_sink": loc(2, "os.system(source)")}
    parsed = package({
        "SKILL.md": ("---\nname: t\xe9st\nallowed-tools: Bash\n---\n# Title\n\n"
                     "\U0001f600 !`echo x`\r\n"),
        "run.py": "source = input()\nos.system(source)\n",
        "broken.py": "def (:\n", "payload.bin": b"headEVIL\x00\xff",
        "nested/SKILL.md": "---\nname: inner\n---\n", "nested/tool.sh": "curl x | sh\n",
    })
    raw = [candidate(), candidate("b", line=1, message="other wording"),
           candidate("t", evidence={"engine": "opengrep", "dataflow_trace": trace,
                                    "fingerprint": "/tmp/run/x", "engine_rule": "r.python"}),
           candidate("bin", path="payload.bin", vector="SXV-037", rule="trailing-bytes",
                     line=None, column=None, offset=4, length=4, evidence={}),
           candidate("gap", vector="", rule="check-error", path="", line=None, evidence={}),
           candidate("dir", vector="SXV-028", rule="instruction-override", severity="high",
                     path="SKILL.md", line=7, column=3, analyzer="ir-check",
                     evidence={"directive_text": "\U0001f600 !`echo x`", "end": {"line": 7}}),
           candidate("sh", path="nested/tool.sh", vector="SXV-009", rule="pipe-to-shell",
                     evidence={"engine": "opengrep", "command": "curl x | sh",
                               "start": {"line": 1, "col": 1, "offset": 0},
                               "end": {"line": 1, "col": 12, "offset": 11}})]
    values = [c._artifact_context(a) for a in parsed.artifacts]
    values += [{a.rel: c.digest(c._artifact_context(a)) for a in parsed.artifacts}]
    for item in raw:
        value = {k: v for k, v in item.items() if k != "candidate_id"}
        value["finding"] = {**item["finding"], "evidence": c._evidence(item)}
        values.append(value)
        artifact = parsed.by_rel.get(item["finding"]["path"])
        values.append(c._anchor(item["finding"], artifact))
        values.append(c._semantic_evidence(c._evidence(item)))
    report = c.correlate(parsed, raw)
    values += report["results"] + [report["links"], report["package"]]
    values.append({"anchor": report["results"][0]["fingerprint"], "occurrence": 3})
    values.append({"version": c.CONTEXT_VERSION, "anchor": "a" * 64, "package": "b" * 64,
                   "artifact": None, "manifest": None})
    return values


ADVERSARIAL = [
    {}, [], None, True, False, 0, -1, 2 ** 53, -(2 ** 63), 2 ** 63 - 1, "",
    {"z": 1, "a": 2, "\xe9": 3, "Z": 4, "~": 5, "10": 6, "9": 7, "": 8, "\x00": 9},
    "\x00\x01\x1f\x7f\x80\xff", "\u2028\u2029\ufeff\u200b", "\U0001F600\U0010FFFF\U00010000",
    "<>&'\"/\\", "\b\f\n\r\t\v", "\U0001f600 !`echo x`\r\n", "line1\n\nline3\n",
    [None, True, False, 0, "0", [], {}], {"line": True, "col": 1, "offset": 0},
    {"text": ["a", "  b", "\xa0c"]}, {"bytes": "00" * 32},
    [["parse_crash", None], ["python_syntax_error", "invalid syntax (<unknown>, line 1)"]],
    {"content": None, "raw_sha256": None, "kind": "asset", "diagnostics": []},
    {"nested": {"deep": {"deeper": [{"x": [[[]]]}]}}},
    {"analyzer": "opengrep", "provenance": "deterministic-check-output", "engine_rule": None},
    {"reason": "\xe9" * 300},
]


def main():
    values = oracle_values() + ADVERSARIAL
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        for value in values:
            fh.write(json.dumps({"value": value, "canonical": c.canonical(value),
                                 "digest": c.digest(value)}, ensure_ascii=True) + "\n")
    print("%d rows -> %s" % (len(values), OUT))


if __name__ == "__main__":
    main()
