"""Registry-drift guards for the inline vector table (findings._VECTORS).

Two invariants, so enrichment never silently rots as vectors are added or a batch is split
out: (1) a finding whose vector is absent from the table still reports, just without
title/cwe/tier; (2) the set of SXV ids the shipped checks can emit equals the table's keys,
so no emitted vector loses enrichment and no dead entry lingers (the fluff we just cut)."""

from __future__ import annotations

import ast
import pathlib
import re

import skill_xray
from skill_xray.findings import Finding, vector_registry

_SXV = re.compile(r"SXV-\d{3}")


def _docstring_constants(tree):
    """ids of the Constant nodes that are module/class/function docstrings, so an SXV id
    mentioned in prose is not mistaken for one the code emits."""
    out = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            out.add(id(body[0].value))
    return out


def _emitted_vectors():
    """Every SXV id that appears as a real string literal (not a docstring) in the shipped
    check and llm modules -- i.e. the vectors the code can actually emit."""
    pkg = pathlib.Path(skill_xray.__file__).parent
    found = set()
    for sub in ("checks", "llm"):
        d = pkg / sub
        if not d.is_dir():
            continue
        for py in sorted(d.glob("*.py")):
            tree = ast.parse(py.read_text(encoding="utf-8"))
            docs = _docstring_constants(tree)
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and id(node) not in docs and _SXV.fullmatch(node.value)):
                    found.add(node.value)
    return found


def test_unknown_vector_reports_without_enrichment():
    d = Finding(vector="SXV-999", rule="x", severity="low", path="p", message="m").to_dict()
    assert d["vector"] == "SXV-999"
    assert "title" not in d and "cwe" not in d and "tier" not in d


def test_registry_matches_emitted_vectors():
    emitted = _emitted_vectors()
    registered = set(vector_registry())
    assert emitted == registered, (
        "vector drift -- emitted but unregistered: %s ; registered but never emitted: %s"
        % (sorted(emitted - registered), sorted(registered - emitted)))
