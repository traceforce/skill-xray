"""Manifest-scoped capability context; none of these states authorize behavior."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass, field

from .checks.code_lane import _governing_manifest, _manifest_index
from .checks.grants import (
    _EXECUTION_TOOLS,
    _NETWORK_TOOLS,
    declared_capabilities,
    denied_capabilities,
    effective_grants,
)

__all__ = ["CapabilityTriad", "build_triads"]

AXES = ("execution", "network")
_CLAIMS = {
    "execution": r"(?:runs?|executes?) (?:shell commands|commands|scripts)\b",
    "network": r"(?:uploads? (?:diagnostic logs|logs|data)|"
               r"sends? (?:diagnostic logs|logs|data) (?:over the network|via http)|"
               r"(?:access(?:es)?|uses?) the network|makes? (?:http|network) requests)\b",
}
_DENIALS = {
    "execution": r"(?:runs?|executes?) commands",
    "network": r"(?:access(?:es)?|uses?) the network",
}


def _unknown():
    return dict.fromkeys(AXES, "unknown")


@dataclass
class CapabilityTriad:
    manifest: str | None
    claimed: dict = field(default_factory=_unknown)
    declared: dict = field(default_factory=_unknown)
    observed: dict = field(default_factory=_unknown)
    evidence: list = field(default_factory=list)
    limitations: list = field(default_factory=list)


def _claims(manifest, triad):
    description = (manifest.frontmatter or {}).get("description")
    sources = []
    if isinstance(description, str):
        sources.append((description, manifest.frontmatter_key_lines.get("description")))
    if manifest.markdown is not None:
        lines = (manifest.text or "").splitlines()
        for start, end in manifest.markdown.prose_spans:
            block = lines[start - 1:min(end, len(lines))]
            if block and block[0].lower().startswith("this skill "):
                sources.append(("\n".join(block), start))
    states = {axis: set() for axis in AXES}
    for text, line in sources:
        evidence = []
        supported = True
        # A matching prefix cannot excuse an unsupported qualification elsewhere in the source.
        for statement in re.split(r"(?<=[.!])\s+", text.strip()):
            sentence = " ".join(statement.lower().split()).rstrip(".!")
            clauses = sentence.split(" and ")
            if len(statement) > 400 or (len(clauses) > 1 and re.search(
                    r"\b(?:does not|never)\b", sentence)):
                supported = False
                break
            for clause in clauses:
                clause = clause.removeprefix("this skill ")
                negative = re.match(r"^(?:does not|never)\s+", clause)
                action = clause[negative.end():] if negative else clause
                patterns = _DENIALS if negative else _CLAIMS
                matched = [axis for axis, pattern in patterns.items()
                           if re.fullmatch(pattern, action)]
                if not matched:
                    supported = False
                    break
                for axis in matched:
                    evidence.append({"path": manifest.rel, "line": line,
                                     "leg": "claimed", "capability": axis,
                                     "state": "denied" if negative else "present",
                                     "text": statement})
            if not supported:
                break
        if supported:
            for hit in evidence:
                states[hit["capability"]].add(hit["state"])
            triad.evidence.extend(evidence)
    for axis, values in states.items():
        if len(values) == 1:
            triad.claimed[axis] = next(iter(values))
        elif values:
            triad.limitations.append("conflicting-%s-claims" % axis)


def _declarations(manifest, triad):
    fm = manifest.frontmatter or {}
    fields = [key for key in ("allowed-tools", "disallowed-tools") if key in fm]
    grants = manifest.grants or ()
    if (any(code in {"frontmatter_parse_error", "grants_unparsed_shape"}
            for code, _ in manifest.diagnostics)
            or any(fm[key] is None or isinstance(fm[key], str) and not fm[key].strip()
                   or isinstance(fm[key], list) and any(
                       isinstance(item, str) and not item.strip() for item in fm[key])
                   for key in fields) or any(not grant.parsed for grant in grants)):
        triad.limitations.append("declaration-unparsed")
        return
    allowed = declared_capabilities(grants)
    # A denial of one URL or command does not deny the entire capability axis.
    denied = denied_capabilities(
        g for g in grants if (g.pattern or "").strip() in {"", "*", "**", ":*"})
    uncertain = set()
    for grant in effective_grants(grants):
        if grant.tool in _EXECUTION_TOOLS:
            # A command not recognized as network-capable is not proven network-free.
            uncertain.update(set(AXES) - declared_capabilities([grant]))
        elif grant.tool not in _NETWORK_TOOLS | {"Read", "Write", "Edit", "MultiEdit",
                                               "Glob", "Grep", "LS"}:
            uncertain.update(AXES)
    if uncertain:
        triad.limitations.append("declaration-capability-unknown")
    for axis in AXES:
        if axis in allowed:
            triad.declared[axis] = "present"
        elif axis not in uncertain and ("allowed-tools" in fm or axis in denied):
            triad.declared[axis] = "denied"
    for key in fields:
        triad.evidence.append({"path": manifest.rel, "leg": "declared", "field": key,
                               "line": manifest.frontmatter_key_lines.get(key)})


def build_triads(parsed, observations=(), coverage=()) -> dict[str, CapabilityTriad]:
    """Reuse governing manifests and validated engine observations; absence stays unknown.

    Claims recognize narrow English templates in descriptions and self-referential manifest
    prose. Other documents and arbitrary language remain unknown, not a positive disclosure.
    """
    manifests = _manifest_index(parsed)
    triads = {p.rel: CapabilityTriad(p.rel) for p in manifests.values()}
    observations = list(observations)
    coverage = list(coverage)
    for finding in coverage:
        if (finding.rule in {"preproc-inline-bang", "preproc-fenced-bang"}
                and finding.vector in {"SXV-001", "SXV-002"}
                and finding.evidence.get("command_sha256")):
            observations.append({"path": finding.path, "line": finding.line,
                                 "column": finding.column, "capability": "execution",
                                 "state": "present", "analyzer": "preproc-ir",
                                 "rule": finding.rule, "vector": finding.vector,
                                 "command_sha256": finding.evidence["command_sha256"]})
    for observation in observations:
        path, axis = observation.get("path", ""), observation.get("capability")
        manifest = _governing_manifest(manifests, path)
        key = manifest.rel if manifest else ""
        triad = triads.setdefault(key, CapabilityTriad(key or None))
        triad.evidence.append(deepcopy(observation))
        if axis in AXES and observation.get("state") == "present":
            triad.observed[axis] = "present"
        else:
            triad.limitations.append(observation.get("reason", "observation-unvalidated"))
    for manifest in manifests.values():
        triad = triads[manifest.rel]
        _claims(manifest, triad)
        _declarations(manifest, triad)
        if manifest.text is None:
            triad.limitations.append("manifest-unread")
    for finding in coverage:
        if finding.vector:
            continue
        manifest = _governing_manifest(manifests, finding.path) if finding.path else None
        affected = [triads[manifest.rel]] if manifest else list(triads.values())
        for triad in affected:
            triad.limitations.append(finding.rule)
    for triad in triads.values():
        triad.limitations = sorted(set(triad.limitations))
    return dict(sorted(triads.items()))
