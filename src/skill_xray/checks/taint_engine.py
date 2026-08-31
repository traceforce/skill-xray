"""Run the enforced OpenGrep execution-policy rules."""

from __future__ import annotations

from ..findings import Finding, cap_findings
from ..opengrep_bridge import check as opengrep_check

__all__ = ["check"]


def check(
    parsed,
    *,
    executable=None,
    opengrep_runner=None,
    code_units=None,
    lane_notes=None,
) -> list[Finding]:
    """Analyze the shared Python and shell lane in one OpenGrep process."""
    findings = list(lane_notes or ())
    try:
        findings.extend(opengrep_check(
            parsed,
            executable=executable,
            runner=opengrep_runner,
            code_units=code_units,
            languages=("python",),
        ))
    except Exception as exc:
        findings.append(Finding(
            vector="",
            rule="opengrep-internal-error",
            severity="high",
            path="",
            message="OpenGrep analysis failed unexpectedly: %s" % type(exc).__name__,
            evidence={"engine": "opengrep"},
        ))
    return cap_findings(findings)
