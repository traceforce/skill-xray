"""Explicit operator decisions, separate from raw evidence and model opinions."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import asdict
from pathlib import PurePosixPath

from .checks.coverage import _static_severity, is_inventory_note
from .correlate import canonical, source_region
from .findings import SEVERITY_RANK
from .ingest import _BENIGN_LEDGER

POLICY_VERSION = "skill-xray/scoped-policy/v1"
_SCOPE = ("rule_id", "path", "fingerprint", "context_digest")


def _policy_entries(policy):
    if policy is None:
        return {}
    if (not isinstance(policy, dict) or set(policy) != {"version", "decisions"}
            or policy["version"] != POLICY_VERSION or not isinstance(policy["decisions"], list)
            or len(policy["decisions"]) > 512):
        raise ValueError("Invalid operator policy")
    entries = {}
    for entry in policy["decisions"]:
        required = set(_SCOPE) | {"action", "reason"}
        if isinstance(entry, dict) and entry.get("action") == "demote":
            required.add("effective_severity")
        if (not isinstance(entry, dict) or set(entry) != required
                or any(not isinstance(value, str) or not value.strip() for value in entry.values())
                or entry["action"] not in {"suppress", "demote"}
                or len(entry["reason"]) > 1024
                or any(not re.fullmatch(r"[0-9a-f]{64}", entry[key])
                       for key in ("fingerprint", "context_digest"))
                or PurePosixPath(entry["path"]).is_absolute()
                or ".." in entry["path"].split("/")
                or entry.get("effective_severity", "low") not in SEVERITY_RANK):
            raise ValueError("Invalid operator policy decision")
        # Paths are exact IR identities, never filesystem paths to open or normalize.
        key = tuple(entry[field] for field in _SCOPE)
        if key in entries:
            raise ValueError("Duplicate operator policy scope")
        entries[key] = entry
    return entries


def _source_known(result, parsed):
    finding = result["finding"]
    artifact = parsed.by_rel.get(finding["path"])
    if artifact is None or artifact.diagnostics:
        return False
    offset, length = finding.get("offset"), finding.get("length")
    if offset is not None:
        return (artifact.raw is not None and type(offset) is int and offset >= 0
                and type(length) is int and length > 0 and offset + length <= len(artifact.raw))
    line, column = finding.get("line"), finding.get("column")
    lines = artifact.text.split("\n") if artifact.text is not None else []
    if type(line) is not int or not 1 <= line <= len(lines):
        return False
    start = {"line": line, "col": column if column is not None else 1}
    evidence = finding.get("evidence", {})
    end = evidence["end"] if "end" in evidence else start
    try:
        source_region(artifact, start, end, byte_columns=evidence.get("engine") == "opengrep")
    except (ValueError, TypeError):
        return False
    return True


def _material_ledger_entry(entry, parsed):
    if (entry.get("phase") or "static") != "static":
        return True
    reason = str(entry.get("reasonCode") or "unknown")
    artifact = parsed.by_rel.get(str(entry.get("path") or ""))
    return (reason not in _BENIGN_LEDGER
            and _static_severity(reason, artifact.kind if artifact else None) is not None)


def apply_dispositions(parsed, correlated, triads, *, policy=None, context_errors=()):
    """Retain by default. Only exact operator scope may suppress or lower severity.

    All results remain in the audit list, including suppressed results. Unknown capability
    axes are explanation, not permission. Material gaps block policy package-wide:
    an unanalyzed artifact may change cross-file capability or flow context.
    """
    entries = _policy_entries(policy)
    final = deepcopy(correlated)
    raw = final["raw_candidates"]
    contexts = {key: asdict(triad) for key, triad in sorted(triads.items())}
    for context in contexts.values():
        context["evidence"].sort(key=canonical)
    final["capability_contexts"] = contexts
    context_limits = [{"manifest": key, "limitations": sorted(value.limitations)}
                      for key, value in sorted(triads.items()) if value.limitations]
    package_gap = bool(context_errors or context_limits or any(
        _material_ledger_entry(entry, parsed) for entry in parsed.ledger_exceptions) or any(
        (not item["finding"]["vector"] or item.get("coverage") != "no-reported-gap")
        and not is_inventory_note(item["finding"]) for item in raw))
    decisions = {}
    for result in final["results"]:
        finding = result["finding"]
        context = contexts.get(result["manifest"] or "")
        incomplete = (package_gap or result["manifest"] is None
                      or context is None or bool(context["limitations"])
                      or (not is_inventory_note(finding)
                          and (bool(result["limitations"]) or not _source_known(result, parsed))))
        protected = (not finding["vector"] or any(
            item["provenance"] != "deterministic-check-output" for item in result["provenance"]))
        disposition, reason, provenance = (
            "reported", "Original deterministic evidence retained", "deterministic-policy")
        original = effective = finding["severity"]
        entry = entries.get((result["rule_id"], finding["path"], result["fingerprint"],
                             result["context_digest"]))
        if incomplete or protected:
            reason = "Incomplete context or protected operational evidence; retained"
        elif entry is not None:
            if entry["action"] == "suppress":
                disposition = "suppressed"
            elif SEVERITY_RANK[entry["effective_severity"]] > SEVERITY_RANK.get(original, 99):
                disposition, effective = "corrected", entry["effective_severity"]
            if disposition != "reported":
                reason, provenance = entry["reason"], "operator-policy"
            else:
                reason = "Policy cannot raise severity or make a no-op correction; retained"
        result.update(disposition=disposition, decision_reason=reason,
                      decision_provenance=provenance, policy_version=POLICY_VERSION,
                      original_severity=original, effective_severity=effective,
                      capability_context={key: deepcopy(value) for key, value in context.items()
                                          if key != "evidence"} if context is not None else None,
                      coverage="incomplete" if incomplete
                      else "no-reported-gap")
        decisions[result["id"]] = result
    for link in final["links"]:
        result = decisions[link["result_id"]]
        if link["disposition"] != "duplicate":
            link.update(disposition=result["disposition"], reason=result["decision_reason"])
        link.update(policy_version=POLICY_VERSION,
                    provenance="deterministic-correlation" if link["disposition"] == "duplicate"
                    else result["decision_provenance"])
    final["coverage"] = "incomplete" if package_gap or any(
        r["coverage"] == "incomplete" for r in final["results"]) else "no-reported-gap"
    final["context_limitations"] = context_limits
    final["execution_successful"] = not bool(context_errors or any(
        not item["finding"]["vector"] and item["finding"]["severity"] in {"critical", "high"}
        for item in raw))
    return final


LLM_APPLY_VERSION = "skill-xray/llm-apply/v1"
# Only the text-pattern directive vectors the review contracts cover. Code-lane, taint, byte
# forensics and every other mechanically anchored vector are never model-adjustable.
LLM_APPLY_VECTORS = frozenset({"SXV-028", "SXV-029", "SXV-030", "SXV-031"})


def apply_llm_review(final, decisions, *, effective_severity="low"):
    """Opt-in: a validated ``llm-disputed`` review demotes its result to ``effective_severity``.

    Only the one text-pattern result the dispute covers, only for vectors in the review
    contracts, and never a result the deterministic policy already protected (incomplete
    context, non-deterministic provenance, coverage gap). It never suppresses and never raises.
    The result stays in the audit as ``corrected`` with ``llm-review-policy`` provenance, like an
    operator demote.
    """
    if effective_severity not in SEVERITY_RANK:
        raise ValueError("Invalid LLM demotion severity")
    disputed = {d["candidate_id"]: d for d in decisions
                if d.get("disposition") == "llm-disputed" and d.get("status") == "proposed"}
    results = {r["id"]: r for r in final["results"]}
    applied = 0
    for link in final["links"]:
        decision, result = disputed.get(link["candidate_id"]), results.get(link["result_id"])
        if decision is None or result is None or result.get("llm_applied"):
            continue
        finding = result["finding"]
        if (result["disposition"] != "reported" or result["coverage"] != "no-reported-gap"
                or finding["vector"] not in LLM_APPLY_VECTORS
                or any(p["provenance"] != "deterministic-check-output"
                       for p in result["provenance"])
                or SEVERITY_RANK[effective_severity] <= SEVERITY_RANK.get(finding["severity"], 99)):
            continue
        result.update(disposition="corrected", effective_severity=effective_severity,
                      decision_reason=decision.get("reason") or "LLM review disputed the finding",
                      decision_provenance="llm-review-policy", policy_version=LLM_APPLY_VERSION,
                      llm_applied=True, llm_candidate_id=link["candidate_id"])
        applied += 1
    for link in final["links"]:
        result = results[link["result_id"]]
        if link["disposition"] != "duplicate" and result.get("llm_applied"):
            link.update(disposition="corrected", reason=result["decision_reason"],
                        provenance="llm-review-policy", policy_version=LLM_APPLY_VERSION)
    final["llm_applied"] = applied
    return final
