"""The inline vector registry must cover every vector the checks can emit. A finding whose
vector is missing from the registry still reports, but silently loses its title/CWE/tier
enrichment -- so a new vector added to a check without a registry entry fails nothing at
runtime. This guard turns that silent gap into a test failure."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from skill_xray.findings import FINDING_CAP, Finding, cap_findings, vector_registry

_PKG = Path(__file__).resolve().parent.parent / "src" / "skill_xray"
_SXV = re.compile(r"SXV-\d+")


def _referenced_vectors() -> set:
    """Every SXV id that appears as a string literal in the package source (the check that
    emits a finding names its vector as a literal, e.g. vector="SXV-009")."""
    ids = set()
    for path in _PKG.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and _SXV.fullmatch(node.value):
                ids.add(node.value)
    return ids


def test_every_referenced_vector_is_registered():
    missing = _referenced_vectors() - set(vector_registry())
    assert not missing, "vectors emitted in source but absent from _VECTORS: %s" % sorted(missing)


def test_duplicates_do_not_consume_finding_cap():
    duplicate = Finding("SXV-008", "taint", "critical", "run.py", "duplicate", line=1)
    unique = Finding("SXV-008", "taint", "critical", "run.py", "unique", line=2)

    findings = cap_findings([duplicate] * FINDING_CAP + [unique])

    assert findings == [duplicate, unique]


def test_legacy_positional_finding_fields_keep_their_meaning():
    finding = Finding("SXV-001", "rule", "high", "SKILL.md", "message", 2, 9, 4, {"x": 1})

    assert (finding.line, finding.offset, finding.length, finding.evidence) == (2, 9, 4, {"x": 1})
