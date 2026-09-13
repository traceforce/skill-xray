"""Turn material analysis gaps into findings instead of a clean verdict."""

from __future__ import annotations

from ..findings import Finding

_LOW_PARSE = {
    "config_parse_error", "dep_manifest_unparsed", "frontmatter_parse_error",
    "grants_unparsed_shape", "markdown_parse_error", "requirement_unparsed",
    "unmodeled_content", "unsupported_markup",
}
_LOW_STATIC = {"excluded_dir"}


def is_inventory_note(finding: dict) -> bool:
    evidence = finding.get("evidence", {})
    return (not finding["vector"] and finding["rule"] == "coverage-note"
            and finding["severity"] == "low" and evidence.get("phase") == "static"
            and evidence.get("reason") in _LOW_STATIC)


def _static_severity(reason: str, kind: str | None) -> str | None:
    if reason in _LOW_STATIC:
        return "low"
    if reason.startswith(("unreadable:", "walk_error:")):
        return "high"
    if reason == "binary_content" and kind == "asset":
        return None
    return "high"


def check(parsed) -> list[Finding]:
    by_rel = {artifact.rel: artifact for artifact in parsed.artifacts}
    findings = []
    seen = set()
    for entry in parsed.ledger_exceptions:
        phase = str(entry.get("phase") or "static")
        reason = str(entry.get("reasonCode") or "unknown")
        path = str(entry.get("path") or "")
        key = phase, reason, path
        if key in seen:
            continue
        seen.add(key)
        if phase == "parse":
            severity = "low" if reason in _LOW_PARSE else "high"
        else:
            artifact = by_rel.get(path)
            severity = _static_severity(reason, artifact.kind if artifact else None)
        if severity is None:
            continue
        findings.append(Finding(
            vector="",
            rule="analysis-incomplete" if severity == "high" else "coverage-note",
            severity=severity,
            path=path,
            message="%s analysis coverage is incomplete (%s)." % (phase, reason),
            evidence={"phase": phase, "reason": reason},
        ))
    return findings
