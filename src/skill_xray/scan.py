"""Run every detection check over a parsed package and return unified findings.

The IR checks read the parsed structure and emit the Finding model; this module runs them
and returns one de-duplicated, severity-ordered list. It reads only the IR."""

from __future__ import annotations

from .checks import run_checks
from .findings import dedupe_findings

__all__ = ["scan"]


def scan(parsed) -> list:
    """All findings for a parsed package, most severe first and deterministically ordered."""
    return dedupe_findings(list(run_checks(parsed)))
