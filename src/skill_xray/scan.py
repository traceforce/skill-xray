"""Run every detection over a parsed package and return unified findings.

The IR checks (taint over the OpenGrep lane, coverage, ... in ``checks``) read the parsed
structure and emit the shared Finding model; this module runs them and returns one
de-duplicated, severity-ordered list. It reads only the IR."""

from __future__ import annotations

from .checks import run_checks
from .findings import dedupe_findings

__all__ = ["scan"]


def scan(parsed, *, opengrep_executable=None) -> list:
    """All findings for a parsed package, most severe first and deterministically ordered."""
    findings = list(run_checks(parsed, opengrep_executable=opengrep_executable))
    return dedupe_findings(findings)
