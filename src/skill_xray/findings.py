"""The finding model and the vector registry every check emits against.

A check returns Findings; each Finding names the vector it proves by its SXV id -- a
"skill-xray vector", this tool's own stable id per threat class, its equivalent of a CWE --
plus its own severity, the evidence a reviewer needs, and a location in the package.
The registry below maps a vector id to its title, CWE tags and tier so a check never
restates them. Deterministic: findings sort and de-duplicate to a stable order regardless
of scan order."""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Finding", "SEVERITY_RANK", "vector_registry", "vector_meta",
           "sort_findings", "dedupe_findings", "findings_to_dicts"]

# critical > high > medium > low; unknown sorts last.
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Vector metadata keyed by SXV id: title, CWE tags and tier. Only these three fields are
# consumed, so the registry lives inline like every other lookup table in the package; each
# vector's full threat-model description lives in the reference docs, not here.
_VECTORS = {
    "SXV-008": {"title": "Untrusted-argument command injection with a proven assignment chain",
                "tier": "T1", "cwe": ["CWE-78", "CWE-77"]},
    "SXV-018": {"title": "Remote payload fetched and executed by a bundled script",
                "tier": "T2", "cwe": ["CWE-494", "CWE-829"]},
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
    default for a specific case). line is 1-based; evidence carries the reviewer-facing
    specifics."""

    vector: str
    rule: str
    severity: str
    path: str
    message: str
    line: int | None = None
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        meta = vector_meta(self.vector)
        d = {"vector": self.vector, "rule": self.rule, "severity": self.severity,
             "path": self.path, "message": self.message}
        if self.line is not None:
            d["line"] = self.line
        if self.evidence:
            d["evidence"] = self.evidence
        if meta:
            d["title"] = meta.get("title")
            d["cwe"] = meta.get("cwe", [])
            d["tier"] = meta.get("tier")
        return d


def _sort_key(f: Finding):
    return (SEVERITY_RANK.get(f.severity, 9), f.path, f.vector,
            f.line if f.line is not None else -1, f.rule, f.message)


def sort_findings(findings) -> list:
    """Most severe first, then by path/vector/location. Stable and deterministic."""
    return sorted(findings, key=_sort_key)


def dedupe_findings(findings) -> list:
    """Drop exact duplicates (same vector, path, location, message) that two checks or
    two passes can produce, preserving the sorted order."""
    seen = set()
    out = []
    for f in sort_findings(findings):
        key = (f.vector, f.path, f.line, f.rule, f.message)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def findings_to_dicts(findings) -> list:
    return [f.to_dict() for f in dedupe_findings(findings)]
