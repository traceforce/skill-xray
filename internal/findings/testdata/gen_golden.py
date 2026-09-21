"""Regenerate golden.json from the Python oracle.

    PYTHONPATH=<oracle>/src python internal/findings/testdata/gen_golden.py

The inputs are chosen to hit every branch of _sort_key, _engine_occurrence, dedupe_findings,
cap_findings and Finding.to_dict: unknown severities, None vs -1 positions, offset 0, code-point
string order, unvalidated OpenGrep occurrences with non-int coordinates, SXV-033 capability groups,
rule-grouped vectorless findings and unregistered vectors.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from skill_xray.findings import (
    FINDING_CAP,
    Finding,
    cap_findings,
    dedupe_findings,
    sort_findings,
)


def occurrence(start, end, mapping="unvalidated", engine="opengrep"):
    return {"engine": engine, "location_mapping": mapping,
            "engine_location": {"start": start, "end": end}}


def point(line, col, offset):
    return {"line": line, "col": col, "offset": offset}


INPUTS = [
    Finding("SXV-008", "taint", "critical", "b.py", "same spot", line=3),
    Finding("SXV-008", "taint", "high", "b.py", "same spot", line=3),
    Finding("SXV-008", "taint", "bogus", "a.md", "unknown severity sorts last"),
    Finding("SXV-001", "rule", "low", "a.md", "x"),
    Finding("SXV-001", "rule", "low", "a.md", "y", line=-1),
    Finding("SXV-001", "rule", "low", "a.md", "offset zero", offset=0),
    Finding("SXV-001", "rule", "low", "a.md", "offset zero"),
    Finding("SXV-001", "rule", "low", "a.md", "column", column=7),
    Finding("SXV-001", "rule", "low", "a.md", "column", column=2, line=1),
    Finding("SXV-001", "rule", "low", "a.md", "aé"),
    Finding("SXV-001", "rule", "low", "a.md", "a😀"),
    Finding("SXV-001", "rule", "low", "a.md", "aZ"),
    Finding("SXV-001", "rule", "low", "a.md", "a~"),
    Finding("SXV-001", "rule", "low", "a.md", "a￿"),
    Finding("SXV-008", "taint", "critical", "gen.py", "m", line=1,
            evidence=occurrence(point(1, 2, 3), point(4, 5, 6))),
    Finding("SXV-008", "taint", "critical", "gen.py", "m", line=1,
            evidence=occurrence(point(1, 2, 3), point(4, 5, 7))),
    Finding("SXV-008", "taint", "critical", "gen.py", "m", line=1,
            evidence=occurrence(point(1, 2, 3), point(4, 5, 7))),
    Finding("SXV-008", "taint", "critical", "gen.py", "m", line=1,
            evidence=occurrence(point(1, 2, 3), point(4, 5, 6), mapping="validated")),
    Finding("SXV-008", "taint", "critical", "gen.py", "m", line=1,
            evidence=occurrence(point(1, 2, 3), point(4, 5, 6), engine="other")),
    Finding("SXV-008", "taint", "critical", "gen.py", "m", line=1,
            evidence=occurrence(point(1, "3", 3), point(True, 5, 3.0))),
    Finding("SXV-008", "taint", "critical", "gen.py", "m", line=1,
            evidence=occurrence(point(0, 0, 0), None)),
    Finding("SXV-008", "taint", "critical", "gen.py", "m", line=1,
            evidence=occurrence(point(0, 0, 0), point(0, 0, 0))),
    Finding("SXV-008", "taint", "critical", "gen.py", "m", line=1,
            evidence={"engine": "opengrep", "location_mapping": "unvalidated",
                      "engine_location": [1, 2]}),
    Finding("SXV-008", "taint", "critical", "gen.py", "m", line=1,
            evidence={"engine": "opengrep", "location_mapping": "unvalidated"}),
    Finding("SXV-999", "unregistered", "medium", "c.md", "no meta", line=4, length=2),
    Finding("", "coverage-note", "low", "c.md", "vectorless", evidence={"phase": "static"}),
    Finding("SXV-034", "unsafe-yaml-tag", "high", "SKILL.md", "nested evidence", line=2, column=1,
            offset=10, length=5,
            evidence={"tag": "!!python/object", "flags": [True, False, None, 1, "s"],
                      "inner": {"k": [], "z": {}}}),
]

for index in range(FINDING_CAP + 1):
    INPUTS.append(Finding("SXV-016", "unpinned", "medium", "z/req.txt", "dep %02d" % index,
                          line=index + 1))
for index in range(FINDING_CAP + 3):
    INPUTS.append(Finding("", "coverage-note", "low", "z/req.txt", "note %02d" % index,
                          line=index + 1))
for index in range(FINDING_CAP + 1):
    INPUTS.append(Finding("SXV-033", "manifest-capability-understated", "medium", "run.py",
                          "execution %02d" % index, line=index + 1,
                          evidence={"understated_capability": "execution"}))
INPUTS.append(Finding("SXV-033", "manifest-capability-understated", "medium", "run.py",
                      "network", line=FINDING_CAP + 2,
                      evidence={"understated_capability": "network"}))
INPUTS.append(Finding("SXV-033", "manifest-capability-understated", "medium", "run.py",
                      "no capability string", line=FINDING_CAP + 3,
                      evidence={"understated_capability": ""}))
INPUTS.append(Finding("SXV-033", "manifest-capability-understated", "medium", "run.py",
                      "capability not a string", line=FINDING_CAP + 4,
                      evidence={"understated_capability": 3}))


def record(f: Finding) -> dict:
    return {"vector": f.vector, "rule": f.rule, "severity": f.severity, "path": f.path,
            "message": f.message, "line": f.line, "column": f.column, "offset": f.offset,
            "length": f.length, "evidence": f.evidence}


golden = {
    "inputs": [record(f) for f in INPUTS],
    "to_dict": [{"keys": list(f.to_dict()), "value": f.to_dict()} for f in INPUTS],
    "sorted": [record(f) for f in sort_findings(INPUTS)],
    "deduped": [record(f) for f in dedupe_findings(INPUTS)],
    "capped": [record(f) for f in cap_findings(INPUTS)],
}

out = Path(__file__).with_name("golden.json")
out.write_text(json.dumps(golden, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
print("wrote %s: %d inputs, %d sorted, %d deduped, %d capped" % (
    out, len(INPUTS), len(golden["sorted"]), len(golden["deduped"]), len(golden["capped"])),
    file=sys.stderr)
