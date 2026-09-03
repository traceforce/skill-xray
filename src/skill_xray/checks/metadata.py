"""Manifest-truth integration and parser-proven unsafe metadata findings."""

from __future__ import annotations

from ..findings import Finding, cap_findings


def check(parsed):
    findings = []
    for artifact in parsed.artifacts:
        for tag in artifact.unsafe_yaml_tags:
            findings.append(Finding(
                vector="SXV-034", rule="unsafe-yaml-tag", severity="critical",
                path=artifact.rel, line=tag.line, column=tag.column,
                message="frontmatter requests unsafe object construction (%s)" % tag.tag,
                evidence={"tag": tag.tag},
            ))
    return cap_findings(findings)
