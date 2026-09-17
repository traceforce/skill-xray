"""The finding model and the vector registry every check emits against.

A check returns Findings; each Finding names the vector (SXV-nnn) it proves, carries its
own severity and the evidence a reviewer needs, and points at a location in the package.
The registry below maps a vector id to its title, CWE tags and tier so a check never
restates them. Deterministic: findings sort and de-duplicate to a stable order regardless
of scan order."""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Finding", "SEVERITY_RANK", "vector_registry", "vector_meta",
           "sort_findings", "dedupe_findings", "cap_findings", "findings_to_dicts"]

FINDING_CAP = 25

# critical > high > medium > low; unknown sorts last.
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Vector metadata keyed by SXV id: title, CWE tags and tier. The code reads only these three
# fields, so the registry lives inline like every other lookup table in the package; each
# vector's full threat-model write-up lives in the reference docs, not here.
_VECTORS = {
    "SXV-001": {"title": "Load-time preprocessing execution via inline dynamic-context injection",
                "tier": "T2", "cwe": ["CWE-94", "CWE-829"]},
    "SXV-002": {"title": "Load-time preprocessing execution via bang-tagged fenced block",
                "tier": "T2", "cwe": ["CWE-94", "CWE-829"]},
    "SXV-003": {"title": "Unresolvable variable substitution inside an execution pre-grant",
                "tier": "T3", "cwe": ["CWE-829", "CWE-732"]},
    "SXV-004": {"title": "Over-broad execution or network pre-grant in allowed-tools",
                "tier": "T3", "cwe": ["CWE-732"]},
    "SXV-005": {"title": "Agent-identity file persistence write with a concealment or "
                         "priority aggravator",
                "tier": "T2", "cwe": ["CWE-829", "CWE-94"]},
    "SXV-006": {"title": "Startup-hook persistence installation into the agent configuration root",
                "tier": "T2", "cwe": ["CWE-829", "CWE-94"]},
    "SXV-007": {"title": "Instructed concealment of the skill's own actions from the operator",
                "tier": "T2", "cwe": ["CWE-451"]},
    "SXV-008": {"title": "Untrusted-argument command injection with a proven assignment chain",
                "tier": "T1", "cwe": ["CWE-78", "CWE-77"]},
    "SXV-009": {"title": "Unverified remote code execution from a network source",
                "tier": "T2", "cwe": ["CWE-494", "CWE-829"]},
    "SXV-010": {"title": "Staged fetch-then-execute across separate statements",
                "tier": "T2", "cwe": ["CWE-494", "CWE-829"]},
    "SXV-011": {"title": "Credential read directed to network egress in the instruction lane",
                "tier": "T2", "cwe": ["CWE-522", "CWE-200"]},
    "SXV-012": {"title": "Package-root hook auto-execution surface with an unresolvable target",
                "tier": "T3", "cwe": ["CWE-829"]},
    "SXV-013": {"title": "Floating remote package in an auto-start server configuration",
                "tier": "T3", "cwe": ["CWE-1395", "CWE-494"]},
    "SXV-014": {"title": "Hidden-codepoint smuggling",
                "tier": "T1", "cwe": ["CWE-1007", "CWE-94"]},
    "SXV-015": {"title": "Homoglyph or confusable substitution",
                "tier": "T1", "cwe": ["CWE-1007", "CWE-829"]},
    "SXV-016": {"title": "Unpinned or direct-URL dependency",
                "tier": "T3", "cwe": ["CWE-1395", "CWE-937"]},
    "SXV-017": {"title": "Credential committed in the package",
                "tier": "T1", "cwe": ["CWE-798", "CWE-540"]},
    "SXV-018": {"title": "Remote payload fetched and executed by a bundled script",
                "tier": "T2", "cwe": ["CWE-494", "CWE-829"]},
    "SXV-019": {"title": "Encoded payload decoded directly into an interpreter",
                "tier": "T2", "cwe": ["CWE-506"]},
    "SXV-020": {"title": "Executable payload staged on an anonymous file drop",
                "tier": "T2", "cwe": ["CWE-829"]},
    "SXV-021": {"title": "Cloud instance-metadata access from a skill script",
                "tier": "T2", "cwe": ["CWE-918", "CWE-522"]},
    "SXV-022": {"title": "Container or host-escape primitive in a skill script",
                "tier": "T2", "cwe": ["CWE-250"]},
    "SXV-023": {"title": "Private-credential file read in a skill script",
                "tier": "T2", "cwe": ["CWE-522", "CWE-538"]},
    "SXV-024": {"title": "Cloud storage upload sink in a skill script",
                "tier": "T3", "cwe": ["CWE-200"]},
    "SXV-025": {"title": "Home-directory or secret-path enumeration in a skill script",
                "tier": "T2", "cwe": ["CWE-200", "CWE-538"]},
    "SXV-026": {"title": "Whole-environment harvesting in a skill script",
                "tier": "T3", "cwe": ["CWE-526", "CWE-200"]},
    "SXV-027": {"title": "Hidden agent directive inside an HTML comment",
                "tier": "T2", "cwe": ["CWE-506"]},
    "SXV-028": {"title": "Instruction-override or jailbreak directive",
                "tier": "T2", "cwe": ["CWE-77", "CWE-1427"]},
    "SXV-029": {"title": "Anti-refusal or safety-bypass directive",
                "tier": "T3", "cwe": ["CWE-1427"]},
    "SXV-030": {"title": "Cross-session memory-persistence directive",
                "tier": "T3", "cwe": ["CWE-1427"]},
    "SXV-031": {"title": "Covert behavior-manipulation directive",
                "tier": "T3", "cwe": ["CWE-1427"]},
    "SXV-032": {"title": "Cross-agent configuration snooping in a skill script",
                "tier": "T2", "cwe": ["CWE-200", "CWE-497"]},
    # T3: a manifest that under-declares what its fenced commands use is a capability-consistency
    # signal (like an over-broad grant), not evidence of malicious behavior on its own; the
    # behavior the fences show is reported by its own vector.
    "SXV-033": {"title": "Permission understatement: manifest declares less than the code does",
                "tier": "T3", "cwe": ["CWE-280", "CWE-863"]},
    "SXV-034": {"title": "Unsafe YAML deserialisation tag in skill metadata",
                "tier": "T2", "cwe": ["CWE-502", "CWE-94"]},
    "SXV-035": {"title": "File byte-signature contradicts its declared type",
                "tier": "T2", "cwe": ["CWE-646", "CWE-506"]},
    "SXV-036": {"title": "Polyglot file valid as two container formats",
                "tier": "T2", "cwe": ["CWE-506", "CWE-838"]},
    "SXV-037": {"title": "Unreferenced trailing bytes after a container's logical end",
                "tier": "T2", "cwe": ["CWE-506"]},
    "SXV-038": {"title": "Semantic prompt-injection, covert exfiltration, or user-manipulation "
                         "in skill text (LLM-adjudicated)",
                # CWE-1427 (prompt injection) anchors the instruction-override case; CWE-200 the
                # exfiltration/user-manipulation one. NOT CWE-94: nothing here generates or runs
                # code, so a code-injection tag would mis-route CWE-based triage.
                "tier": "T2", "cwe": ["CWE-1427", "CWE-200"]},
    "SXV-039": {"title": "OS-level persistence write (shell-rc, cron, systemd, "
                         "autostart) with a remote-execution payload",
                "tier": "T2", "cwe": ["CWE-506", "CWE-829"]},
    "SXV-040": {"title": "Reverse shell / socket-backed interactive shell in a skill script",
                "tier": "T1", "cwe": ["CWE-506", "CWE-912"]},
    "SXV-041": {"title": "Remote instruction loading in the instruction lane "
                         "(fetch-and-follow / progressive disclosure)",
                "tier": "T2", "cwe": ["CWE-829", "CWE-1427"]},
}


def vector_registry() -> dict:
    """The vector registry keyed by SXV id. A finding whose vector is absent still reports;
    it just carries no title, CWE or tier enrichment."""
    return _VECTORS


def vector_meta(vector: str) -> dict:
    return _VECTORS.get(vector, {})


@dataclass(frozen=True)
class Finding:
    """One proven finding. vector links to the registry; rule is a short human slug;
    severity is this instance's severity (a detector may raise or lower the registry
    default for a specific case). line is 1-based; offset/length locate a byte span for
    the byte-level checks; evidence carries the reviewer-facing specifics."""

    vector: str
    rule: str
    severity: str
    path: str
    message: str
    line: int | None = None
    offset: int | None = None
    length: int | None = None
    evidence: dict = field(default_factory=dict)
    column: int | None = None

    def to_dict(self) -> dict:
        meta = vector_meta(self.vector)
        d = {"vector": self.vector, "rule": self.rule, "severity": self.severity,
             "path": self.path, "message": self.message}
        if self.line is not None:
            d["line"] = self.line
        if self.column is not None:
            d["column"] = self.column
        if self.offset is not None:
            d["offset"] = self.offset
        if self.length is not None:
            d["length"] = self.length
        if self.evidence:
            d["evidence"] = self.evidence
        if meta:
            d["title"] = meta.get("title")
            d["cwe"] = meta.get("cwe", [])
            d["tier"] = meta.get("tier")
        return d


def _engine_occurrence(f: Finding):
    if (not isinstance(f.evidence, dict) or f.evidence.get("engine") != "opengrep"
            or f.evidence.get("location_mapping") != "unvalidated"):
        return ()
    location = f.evidence.get("engine_location")
    if not isinstance(location, dict):
        return ()
    positions = []
    for boundary in ("start", "end"):
        point = location.get(boundary)
        if not isinstance(point, dict):
            return ()
        positions.extend(point.get(key) if type(point.get(key)) is int else -1
                         for key in ("line", "col", "offset"))
    return tuple(positions)


def _sort_key(f: Finding):
    return (SEVERITY_RANK.get(f.severity, 9), f.path, f.vector,
            f.line if f.line is not None else -1,
            f.column if f.column is not None else -1,
            f.offset if f.offset is not None else -1, f.rule, f.message, _engine_occurrence(f))


def sort_findings(findings) -> list:
    """Most severe first, then by path/vector/location. Stable and deterministic."""
    return sorted(findings, key=_sort_key)


def dedupe_findings(findings) -> list:
    """Drop exact duplicates (same vector, path, location, message) that two checks or
    two passes can produce, preserving the sorted order."""
    seen = set()
    out = []
    for f in sort_findings(findings):
        # Unverified source positions do not erase distinct generated-code occurrences.
        key = (f.vector, f.path, f.line, f.column, f.offset, f.rule, f.message,
               _engine_occurrence(f))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def cap_findings(findings) -> list:
    """Keep at most 25 findings per path/vector and report any suppression."""
    kept, counts = [], {}
    for finding in dedupe_findings(findings):
        group = finding.vector or finding.rule
        if finding.vector == "SXV-033" and isinstance(finding.evidence, dict):
            capability = finding.evidence.get("understated_capability")
            if isinstance(capability, str) and capability:
                group = "%s:%s" % (group, capability)
        key = finding.path, group
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= FINDING_CAP:
            kept.append(finding)
    for (path, group), count in counts.items():
        if count > FINDING_CAP:
            kept.append(Finding(
                vector="", rule="findings-capped", severity="low", path=path,
                message="%d more %s findings in %s were suppressed (cap %d per file)"
                        % (count - FINDING_CAP, group, path, FINDING_CAP)))
    return kept


def findings_to_dicts(findings) -> list:
    return [f.to_dict() for f in sort_findings(findings)]
