"""Evidence-preserving correlation of emitted candidates; no detection or policy decisions."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from copy import deepcopy
from urllib.parse import quote

from .checks.code_lane import _governing_manifest, _manifest_index
from .findings import SEVERITY_RANK

__all__ = ["correlate"]

FINGERPRINT_VERSION = "skill-xray/evidence/v1"
CONTEXT_VERSION = "skill-xray/context/v1"


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                      allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _evidence(candidate):
    evidence = deepcopy(candidate["finding"].get("evidence", {}))
    if candidate.get("analyzer") == "opengrep" or evidence.get("engine") == "opengrep":
        evidence.pop("fingerprint", None)  # Engine fingerprints include temporary-run identity.
    return evidence


def _semantic_evidence(value):
    if isinstance(value, list):
        return [_semantic_evidence(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {key: _semantic_evidence(item) for key, item in value.items()
            if not (key in {"line", "col", "column", "offset", "end_line", "end_column"}
                    and type(item) is int)}


def _nonblank(text):
    return [line for line in text.split("\n") if line.strip()]


def _artifact_context(artifact):
    if artifact is None:
        return None
    raw_digest = hashlib.sha256(artifact.raw).hexdigest() if artifact.raw is not None else None
    return {"content": artifact.text, "raw_sha256": raw_digest, "kind": artifact.kind,
            "diagnostics": artifact.diagnostics}


def _anchor(finding, artifact):
    if artifact is None:
        return None
    offset, length = finding.get("offset"), finding.get("length")
    if (artifact.raw is not None and type(offset) is int and offset >= 0
            and type(length) is int and length > 0 and offset + length <= len(artifact.raw)):
        return {"bytes": hashlib.sha256(artifact.raw[offset:offset + length]).hexdigest()}
    line = finding.get("line")
    if artifact.text is not None and type(line) is int:
        lines = artifact.text.split("\n")
        end = finding.get("evidence", {}).get("end", {})
        end = end.get("line", line) if isinstance(end, dict) else None
        if type(end) is int and 1 <= line <= end <= len(lines):
            return {"text": _nonblank("\n".join(lines[line - 1:end]))}
    return None


def source_region(artifact, start, end, *, byte_columns=True, lines=None):
    """Validate native byte columns or IR character columns against captured source."""
    if artifact is None or artifact.text is None:
        raise ValueError("source unavailable")
    lines = artifact.text.split("\n") if lines is None else lines
    positions = []
    for position in (start, end):
        if not isinstance(position, dict):
            raise ValueError("invalid source position")
        line, col = position.get("line"), position.get("col")
        if type(line) is not int or type(col) is not int or not 1 <= line <= len(lines):
            raise ValueError("invalid source position")
        text = lines[line - 1]
        encoded = text.encode("utf-8") if byte_columns else text
        if not 1 <= col <= len(encoded) + 1:
            raise ValueError("invalid source column")
        character = len(encoded[:col - 1].decode("utf-8")) if byte_columns else col - 1
        positions.append((line, character))
    (first, start_col), (last, end_col) = positions
    if positions[1] < positions[0]:
        raise ValueError("inverted source region")
    span = lines[first - 1:last]
    span[-1] = span[-1][:end_col]
    span[0] = span[0][start_col:]
    return "\n".join(span), start_col + 1, end_col + 1


def _trace_location(value, parsed, role):
    if not isinstance(value, list) or len(value) != 2 or value[0] != "CliLoc":
        raise ValueError("unsupported trace")
    payload = value[1]
    if not isinstance(payload, list) or len(payload) != 2 or not isinstance(payload[1], str):
        raise ValueError("invalid trace location")
    location = payload[0]
    if not isinstance(location, dict):
        raise ValueError("invalid trace location")
    path = location.get("path")
    artifact = parsed.by_rel.get(path) if isinstance(path, str) else None
    content, _, _ = source_region(artifact, location.get("start"), location.get("end"))
    if not content.strip() or content.strip() != payload[1].strip():
        raise ValueError("trace content does not match source")
    return {"role": role, "path": path, "start": deepcopy(location["start"]),
            "end": deepcopy(location["end"]), "content": payload[1]}


def _code_flow(evidence, parsed):
    if evidence.get("trace_mapping") == "unvalidated":
        return [], ["trace-unvalidated"]
    if "dataflow_trace" not in evidence:
        return [], []
    try:
        trace = evidence["dataflow_trace"]
        if not isinstance(trace, dict):
            raise ValueError("invalid trace")
        steps = [_trace_location(trace["taint_source"], parsed, "source")]
        intermediate = trace.get("intermediate_vars", [])
        if not isinstance(intermediate, list) or len(intermediate) > 128:
            raise ValueError("invalid trace steps")
        for item in intermediate:
            if not isinstance(item, dict):
                raise ValueError("invalid trace step")
            steps.append(_trace_location(["CliLoc", [item["location"], item["content"]]],
                                         parsed, "intermediate"))
        steps.append(_trace_location(trace["taint_sink"], parsed, "sink"))
        return steps, []
    except (KeyError, TypeError, ValueError):
        return [], ["trace-unvalidated"]


def _occurrence(finding):
    return tuple(finding.get(key) if type(finding.get(key)) is int else -1 for key in
                 ("line", "column", "offset", "length"))


def correlate(parsed, candidates):
    """Keep raw candidates intact and link only equivalent occurrences to one result.

    Fingerprints ignore line shifts. Identical anchors at different occurrences get an
    ordered occurrence suffix; context digests invalidate scoped decisions after other edits.
    """
    raw = deepcopy(list(candidates))
    ids = [candidate["candidate_id"] for candidate in raw]
    if any(not isinstance(cid, str) or not cid for cid in ids) or len(set(ids)) != len(ids):
        raise ValueError("candidate IDs must be unique nonempty strings")
    manifests = _manifest_index(parsed)
    signatures, candidate_order = {}, {}
    for candidate in raw:
        value = {key: item for key, item in candidate.items() if key != "candidate_id"}
        value["finding"] = {**candidate["finding"], "evidence": _evidence(candidate)}
        signatures[candidate["candidate_id"]] = digest(value)
        candidate_order[candidate["candidate_id"]] = canonical(value)
    counts, stable_ids = defaultdict(int), {}
    for cid in sorted(ids, key=lambda cid: (signatures[cid], cid)):
        signature = signatures[cid]
        stable_ids[cid] = "candidate-%s-%d" % (signature, counts[signature])
        counts[signature] += 1
    groups = defaultdict(list)
    for candidate in raw:
        finding = deepcopy(candidate["finding"])
        evidence = _evidence(candidate)
        comparable = {key: value for key, value in evidence.items()
                      if key not in {"engine", "engine_rule"}}
        finding["evidence"] = comparable
        # Wording is not identity when matching security evidence has a known source.
        if finding["vector"] and comparable and _anchor(
                finding, parsed.by_rel.get(finding["path"])) is not None:
            finding.pop("message", None)
        groups[canonical(finding)].append(candidate)
    results, links = [], []
    occurrences = defaultdict(int)
    ordered = sorted(groups.items(), key=lambda item: (
        item[1][0]["finding"]["path"], _occurrence(item[1][0]["finding"]), item[0]))
    context_cache = {artifact.rel: digest(_artifact_context(artifact))
                     for artifact in parsed.artifacts}
    package_context = digest(context_cache)
    for _, group in ordered:
        group.sort(key=lambda item: (candidate_order[item["candidate_id"]], item["candidate_id"]))
        finding = deepcopy(group[0]["finding"])
        finding["evidence"] = _evidence(group[0])
        path = finding["path"]
        artifact = parsed.by_rel.get(path)
        manifest = _governing_manifest(manifests, path)
        rule_id = "skill-xray/" + quote(finding["rule"] or "unknown-rule", safe="-._")
        comparable = {key: value for key, value in finding["evidence"].items()
                      if key not in {"engine", "engine_rule"}}
        flow, limitations = _code_flow(finding["evidence"], parsed)
        if finding["evidence"].get("location_mapping") == "unvalidated":
            limitations.append("location-unvalidated")
        if flow:
            comparable["dataflow_trace"] = [
                {"path": step["path"], "role": step["role"], "content": _nonblank(step["content"])}
                for step in flow]
        anchor = {"version": FINGERPRINT_VERSION, "rule": rule_id, "path": path,
                  "vector": finding["vector"], "severity": finding["severity"],
                  "evidence": _semantic_evidence(comparable), "source": _anchor(finding, artifact)}
        base = digest(anchor)
        ordinal = occurrences[base]
        occurrences[base] += 1
        fingerprint = digest({"anchor": base, "occurrence": ordinal})
        result_id = "finding-" + fingerprint
        context = {"version": CONTEXT_VERSION, "anchor": base,
                   "package": package_context,
                   "artifact": context_cache.get(path),
                   "manifest": context_cache.get(manifest.rel) if manifest else None}
        if artifact is None or (artifact.text is None and artifact.raw is None):
            limitations.append("source-unavailable")
        evidence = {canonical(_evidence(item)): _evidence(item) for item in group}
        provenance = [{"analyzer": item.get("analyzer", "unknown"),
                       "provenance": item.get("provenance", "unknown"),
                       "engine_rule": item["finding"].get("evidence", {}).get("engine_rule")}
                      for item in group]
        provenance = {canonical(item): item for item in provenance}
        results.append({"id": result_id, "rule_id": rule_id, "fingerprint": fingerprint,
                        "fingerprint_version": FINGERPRINT_VERSION,
                        "context_digest": digest(context), "finding": finding,
                        "manifest": manifest.rel if manifest else None,
                        "candidate_ids": sorted(item["candidate_id"] for item in group),
                        "provenance": [provenance[key] for key in sorted(provenance)],
                        "evidence": [evidence[key] for key in sorted(evidence)],
                        "code_flow": flow, "limitations": limitations})
        links.extend({"candidate_id": item["candidate_id"], "result_id": result_id,
                      "stable_candidate_id": stable_ids[item["candidate_id"]],
                      "disposition": "duplicate" if index else "reported",
                      "reason": "Equivalent occurrence; evidence and provenance preserved"
                      if index else "Original deterministic evidence retained"}
                     for index, item in enumerate(group))
    results.sort(key=lambda item: (SEVERITY_RANK.get(item["finding"]["severity"], 9),
                                  item["finding"]["path"],
                                  _occurrence(item["finding"]), item["id"]))
    return {"raw_candidates": raw, "results": results,
            "package": {"name": parsed.name, "content_digest": package_context,
                        "digest_version": CONTEXT_VERSION},
            "links": sorted(links, key=lambda item: item["candidate_id"])}
