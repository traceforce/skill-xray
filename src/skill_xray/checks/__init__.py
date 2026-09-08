"""Detection checks over the shared IR.

Each check receives the parsed IR. The OpenGrep adapter materializes only
IR-selected code into an isolated temporary directory; no check reopens package files."""

from __future__ import annotations

from ..analyze import analyze_package
from ..findings import Finding
from . import (
    coverage,
    grants,
    hooks,
    instruction_exfil,
    metadata,
    obfuscation,
    persistence,
    preproc,
    taint_engine,
)
from .code_lane import build_code_lane

# Registered checks, in a stable order. Each is a module-level check(parsed)->[Finding].
_CHECKS = (
    analyze_package,
    coverage.check,
    grants.check,
    hooks.check,
    instruction_exfil.check,
    metadata.check,
    obfuscation.check,
    persistence.check,
    preproc.check,
    taint_engine.check,
)

__all__ = ["run_checks"]


def run_checks(parsed, *, opengrep_executable=None) -> list:
    """Run every registered check over the parsed package and return combined findings.
    Per-check isolated: one check raising cannot suppress the others."""
    findings = []
    try:
        code_units, lane_notes = build_code_lane(parsed)
    except Exception as exc:
        code_units = ()
        lane_notes = (Finding(
            vector="", rule="check-error", severity="high", path="",
            message="executable code selection failed: %s" % type(exc).__name__,
        ),)
    for check in _CHECKS:
        try:
            if check is taint_engine.check:
                findings.extend(check(
                    parsed,
                    executable=opengrep_executable,
                    code_units=code_units,
                    lane_notes=lane_notes,
                ) or [])
            else:
                findings.extend(check(parsed) or [])
        except Exception as exc:
            # A crashing check must not abort the scan, and must not read as clean: record
            # it as a finding so the coverage loss is visible (silence != clean).
            findings.append(Finding(
                vector="", rule="check-error", severity="high", path="",
                message="check %s failed: %s" % (
                    getattr(check, "__module__", "?"), type(exc).__name__)))
    return findings
