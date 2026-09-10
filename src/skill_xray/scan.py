"""Run every detection over a parsed package and return unified findings.

The IR checks (taint over the OpenGrep lane, coverage, ... in ``checks``) read the parsed
structure and emit the shared Finding model; this module runs them and returns one
de-duplicated, severity-ordered list. When the operator passes a configured LLM client, an
advisory semantic pass is folded in on top of the deterministic findings. It reads only the IR."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass

from .capability import build_triads
from .checks import run_checks
from .findings import Finding, dedupe_findings
from .llm import adjudicate

__all__ = ["scan", "scan_report", "ScanReport"]


def _collect(parsed, executable, observations=None):
    return list(run_checks(parsed, opengrep_executable=executable,
                           **({"observations": observations} if observations is not None else {})))


def _advisory(parsed, client):
    try:
        return adjudicate(parsed, client)
    except Exception as exc:
        return [Finding(
            vector="", rule="llm-error", severity="low", path="",
            message="LLM adjudication pass failed (%s); deterministic findings stand"
                    % type(exc).__name__)]


def scan(parsed, *, client=None, opengrep_executable=None) -> list:
    """All findings for a parsed package, most severe first and deterministically ordered.

    Deterministic by default. When `client` is a configured LLM client (opt-in, the operator's
    own key), an advisory semantic-prompt-injection pass is added on top; it never removes or
    blocks a deterministic finding and fails closed on error."""
    findings = _collect(parsed, opengrep_executable)
    if client is not None:
        findings += _advisory(parsed, client)
    return dedupe_findings(findings)


@dataclass
class ScanReport:
    findings: list
    raw_candidates: list
    triads: dict
    llm_usage: dict
    context_errors: list

    def to_dict(self):
        return deepcopy({"schema_version": "context-v1",
                         "raw_scope": "emitted-check-results-before-reporting-deduplication",
                         "raw_candidates": self.raw_candidates,
                         "triads": {key: asdict(value) for key, value in self.triads.items()},
                         "llm_usage": self.llm_usage, "context_errors": self.context_errors})


def scan_report(parsed, *, client=None, opengrep_executable=None) -> ScanReport:
    """Report deterministic raw candidates and context; additive LLM output stays in findings."""
    observations = []
    raw = _collect(parsed, opengrep_executable, observations)
    gaps = {f.path for f in raw if not f.vector}
    candidates = [
        {"candidate_id": "candidate-%06d" % i, "finding": deepcopy(f.to_dict()),
         "analyzer": f.evidence.get("engine", "ir-check"),
         "provenance": "deterministic-check-output",
         "coverage": "incomplete" if "" in gaps or f.path in gaps else "no-reported-gap"}
        for i, f in enumerate(raw)
    ]
    errors = []
    try:
        triads = build_triads(parsed, observations, raw)
    except Exception as exc:
        triads = {}
        errors.append("capability-context-error: %s" % type(exc).__name__)
    findings = list(raw)
    if client is not None:
        findings += _advisory(parsed, client)
    return ScanReport(dedupe_findings(findings), candidates, triads, {}, errors)
