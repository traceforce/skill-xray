"""Load-time preprocessing findings derived from parsed Markdown tokens."""

from __future__ import annotations

import hashlib

from ..findings import FINDING_CAP, Finding, sort_findings

_ROOT_KINDS = {"skill_manifest", "agent_identity"}
_LIFTABLE_KINDS = {"instruction", "doc"}
_EVIDENCE_LIMIT = 400


def _loaded_paths(parsed):
    adjacency = {}
    for ref in parsed.refs:
        adjacency.setdefault(ref["from"], []).append(ref["to"])
    loaded = {artifact.rel for artifact in parsed.artifacts if artifact.kind in _ROOT_KINDS}
    queue = list(loaded)
    while queue:
        source = queue.pop()
        for target in adjacency.get(source, []):
            artifact = parsed.by_rel.get(target)
            if target in loaded or artifact is None or artifact.kind not in _LIFTABLE_KINDS:
                continue
            loaded.add(target)
            queue.append(target)
    return loaded


def _bounded_text(value):
    return value[:_EVIDENCE_LIMIT], len(value) > _EVIDENCE_LIMIT


def _inline_finding(artifact, token):
    command = token.code
    if not token.runs or not command.strip():
        return None
    shown, truncated = _bounded_text(command)
    digest = hashlib.sha256(command.encode("utf-8")).hexdigest()
    return Finding(
        vector="SXV-001",
        rule="preproc-inline-bang",
        severity="critical",
        path=artifact.rel,
        line=token.line,
        column=token.column,
        message=(
            "inline preprocessing executes `%s` while loading the skill, before its "
            "instructions are evaluated" % command[:160]
        ),
        evidence={
            "command_text": shown,
            "command_length": len(command),
            "command_sha256": digest,
            "truncated": truncated,
            "column": token.column,
            "fence_state": "outside",
            "selector": "inline-bang:%s" % digest[:12],
        },
    )


def _fenced_finding(artifact, token):
    if not token.code.strip():
        return None
    normalized = token.code.rstrip("\n")
    command_lines = normalized.split("\n")
    executable_lines = sum(bool(line.strip()) for line in command_lines)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    shown, truncated = _bounded_text(normalized)
    return Finding(
        vector="SXV-002",
        rule="preproc-fenced-bang",
        severity="critical",
        path=artifact.rel,
        line=token.line,
        column=token.column,
        message=(
            "bang-tagged fenced preprocessing executes %d command line(s) while "
            "loading the skill" % executable_lines
        ),
        evidence={
            "command_text": shown.split("\n"),
            "command_length": len(normalized),
            "command_sha256": digest,
            "truncated": truncated,
            "column": token.column,
            "fence_info": token.info,
            "block_line_count": executable_lines,
            "selector": "fenced-bang:%s" % digest[:12],
        },
    )


def check(parsed) -> list[Finding]:
    findings = []
    loaded = _loaded_paths(parsed)
    for artifact in parsed.artifacts:
        if artifact.rel not in loaded:
            continue
        for token in artifact.preprocessing:
            if token.kind == "inline":
                if not token.runs or not token.code.strip():
                    continue
                vector = "SXV-001"
            elif token.kind == "fenced":
                if not any(line.strip() for line in token.code.splitlines()):
                    continue
                vector = "SXV-002"
            else:
                continue
            if token.kind == "inline":
                finding = _inline_finding(artifact, token)
            else:
                finding = _fenced_finding(artifact, token)
            if finding is not None:
                findings.append(finding)
        for kind, vector in (("inline", "SXV-001"), ("fenced", "SXV-002")):
            count = artifact.preprocessing_counts[kind]
            if count > FINDING_CAP:
                findings.append(Finding(
                    vector="", rule="findings-capped", severity="low", path=artifact.rel,
                    message="%d more %s findings in %s were suppressed (cap %d per file)"
                            % (count - FINDING_CAP, vector, artifact.rel, FINDING_CAP),
                ))
    return sort_findings(findings)
