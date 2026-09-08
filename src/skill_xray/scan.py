"""Run every detection over a parsed package and return unified findings.

The IR checks (taint over the OpenGrep lane, coverage, ... in ``checks``) read the parsed
structure and emit the shared Finding model; this module runs them and returns one
de-duplicated, severity-ordered list. When the operator passes a configured LLM client, an
advisory semantic pass is folded in on top of the deterministic findings. It reads only the IR."""

from __future__ import annotations

from .analyze import analyze_package
from .checks import run_checks
from .findings import Finding, dedupe_findings
from .llm import adjudicate

__all__ = ["scan"]


def scan(parsed, *, client=None, opengrep_executable=None) -> list:
    """All findings for a parsed package, most severe first and deterministically ordered.

    Deterministic by default. When `client` is a configured LLM client (opt-in, the operator's
    own key), an advisory semantic-prompt-injection pass is added on top; it never removes or
    blocks a deterministic finding and fails closed on error."""
    # Byte-forensics reads the raw bytes the IR carries and is fail-closed per artifact. Guard the
    # package-level call too, so a malformed IR is recorded as an error rather than aborting the
    # scan (silence is not clean), matching run_checks' per-check isolation.
    try:
        findings = list(analyze_package(parsed))
    except Exception as exc:
        findings = [Finding(vector="", rule="analyzer-error", severity="low", path="",
                            message="byte-forensics pass failed (%s); IR checks stand"
                                    % type(exc).__name__)]
    findings += list(run_checks(parsed, opengrep_executable=opengrep_executable))
    if client is not None:
        # The advisory pass is contracted never to raise, but it must never be ABLE to discard the
        # deterministic findings either: on any unexpected error keep them and record a low coverage
        # note (silence is not clean), never let the advisory layer abort the scan.
        try:
            findings += adjudicate(parsed, client)
        except Exception as exc:
            findings.append(Finding(
                vector="", rule="llm-error", severity="low", path="",
                message="LLM adjudication pass failed (%s); deterministic findings stand"
                        % type(exc).__name__))
    return dedupe_findings(findings)
