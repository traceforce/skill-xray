"""Run every detection over a parsed package and return unified findings.

The IR checks (taint over the OpenGrep lane, coverage, ... in ``checks``) read the parsed
structure and emit the shared Finding model; this module runs them and returns one
de-duplicated, severity-ordered list. When the operator passes a configured LLM client, an
advisory semantic pass is folded in on top of the deterministic findings. It reads only the IR."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field

from .capability import build_triads
from .checks import run_checks
from .checks.coverage import is_inventory_note
from .correlate import correlate
from .disposition import apply_dispositions
from .findings import Finding, dedupe_findings
from .llm import adjudicate
from .llm.judge import POLICY_VERSION, REVIEW_POLICY_VERSION, judge_candidates
from .llm.session import LLMSession

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
        findings += _advisory(parsed, LLMSession(client))
    return dedupe_findings(findings)


@dataclass
class ScanReport:
    findings: list
    raw_candidates: list
    triads: dict
    shadow: list
    llm_usage: dict
    context_errors: list
    dispositions: list = field(default_factory=list)
    review_mode: bool = False
    correlation: dict = field(default_factory=dict)

    def to_dict(self):
        return deepcopy({"schema_version": "context-shadow-v1",
                         "findings": [finding.to_dict() for finding in self.findings],
                         "raw_scope": "emitted-check-results-before-reporting-deduplication",
                         "raw_candidates": self.raw_candidates,
                         "triads": {key: asdict(value) for key, value in self.triads.items()},
                         "shadow": self.shadow, "llm_usage": self.llm_usage,
                         "context_errors": self.context_errors,
                         "correlation": self.correlation,
                         **({"review_mode": "annotated", "dispositions": self.dispositions,
                             "final_findings": [f.to_dict() for f in self.findings]}
                            if self.review_mode else {})})


def scan_report(parsed, *, client=None, llm_shadow=False, opengrep_executable=None,
                max_llm_calls=25, llm_advisory=None, llm_review=False,
                disposition_policy=None) -> ScanReport:
    """Compatible opt-in context report. Candidate IDs are scan-local, not baseline identities."""
    if llm_shadow and llm_review:
        raise ValueError("Choose shadow or annotated LLM review, not both")
    review_enabled = llm_shadow or llm_review
    if review_enabled and client is None:
        raise ValueError("LLM review requires an explicitly supplied client")
    if llm_advisory is None:
        llm_advisory = not review_enabled
    session = LLMSession(client, max_calls=max_llm_calls) if client is not None else None
    observations = []
    raw = _collect(parsed, opengrep_executable, observations)
    gaps = {f.path for f in raw if not f.vector and not is_inventory_note(f.to_dict())}
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
    shadow = []
    dispositions = []
    if review_enabled:
        try:
            decisions = judge_candidates(parsed, candidates, triads, session,
                                         **({"apply_review": True} if llm_review else {}))
            if [d["candidate_id"] for d in decisions] != [c["candidate_id"] for c in candidates]:
                raise ValueError("Review candidate identity mismatch")
        except Exception as exc:
            errors.append("%s-review-error: %s" % (
                "llm" if llm_review else "shadow", type(exc).__name__))
            decisions = [{"candidate_id": c["candidate_id"], "disposition": "reported",
                          "status": "error", "proposal": None, "reason": "Review failed; retained",
                          "policy_version": REVIEW_POLICY_VERSION if llm_review else POLICY_VERSION,
                          "provenance": "deterministic-policy"} for c in candidates]
        if llm_review:
            dispositions = decisions
            # Model opinions must not change finding membership or severity.
        else:
            shadow = decisions
    supplemental = _advisory(parsed, session) if session is not None and llm_advisory else []
    findings += supplemental
    usage = session.usage() if session else {}
    if session is not None:
        usage.update(advisory_enabled=llm_advisory, judge_enabled=review_enabled)
    report_candidates = candidates + [
        {"candidate_id": "advisory-%06d" % i, "finding": deepcopy(f.to_dict()),
         "analyzer": "llm", "provenance": "advisory-output",
         "coverage": "no-reported-gap" if f.vector else "incomplete"}
        for i, f in enumerate(supplemental)]
    correlation = {"raw_candidates": deepcopy(report_candidates), "results": [], "links": []}
    try:
        correlation = correlate(parsed, report_candidates)
    except Exception as exc:
        errors.append("correlation-error: %s" % type(exc).__name__)
        correlation["errors"] = [errors[-1]]
    else:
        try:
            try:
                correlation = apply_dispositions(parsed, correlation, triads,
                                                 policy=disposition_policy, context_errors=errors)
            except ValueError as exc:
                errors.append("disposition-policy-error: %s" % type(exc).__name__)
                correlation = apply_dispositions(parsed, correlation, triads, context_errors=errors)
        except Exception as exc:
            errors.append("disposition-error: %s" % type(exc).__name__)
            correlation["errors"] = [errors[-1]]
    return ScanReport(dedupe_findings(findings), candidates, triads, shadow,
                      usage, errors, dispositions, llm_review, correlation)
