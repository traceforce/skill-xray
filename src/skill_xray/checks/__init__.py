"""Detection checks over the shared IR.

Each check module exposes ``check(parsed) -> list[Finding]`` and reads the parsed IR
(never the filesystem, never re-parsing). ``run_checks`` runs the registered checks and
returns the combined, de-duplicated findings."""

from __future__ import annotations

from ..findings import Finding, dedupe_findings
from . import taint_python

# Registered checks, in a stable order. Each is a module-level check(parsed)->[Finding].
_CHECKS = [
    taint_python.check,
]

__all__ = ["run_checks"]


def run_checks(parsed) -> list:
    """Run every registered check over the parsed package and return combined findings.
    Per-check isolated: one check raising cannot suppress the others."""
    findings = []
    for check in _CHECKS:
        try:
            findings.extend(check(parsed) or [])
        except Exception as exc:
            # A crashing check must not abort the scan, and must not read as clean: record
            # it as a finding so the coverage loss is visible (silence != clean).
            findings.append(Finding(
                vector="", rule="check-error", severity="low", path="",
                message="check %s failed: %s" % (
                    getattr(check, "__module__", "?"), type(exc).__name__)))
    return dedupe_findings(findings)
