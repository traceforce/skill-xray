"""Validated SARIF serialization of already-correlated, audited results."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from copy import deepcopy
from functools import lru_cache
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import quote, quote_from_bytes

from jsonschema import Draft4Validator

from . import __version__
from .correlate import canonical, source_region
from .disposition import POLICY_VERSION
from .findings import SEVERITY_RANK
from .opengrep_runtime import VERSION as OPENGREP_VERSION

__all__ = ["build_sarif", "encode_sarif", "validate_sarif", "write_sarif"]

_SCHEMA = Path(__file__).with_name("schemas") / "sarif-schema-2.1.0.json"
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_MAX_REPORT_BYTES = 64 * 1024 * 1024


@lru_cache(maxsize=1)
def _validator():
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    Draft4Validator.check_schema(schema)
    return Draft4Validator(schema)


def _location(parsed, path, line_cache, start=None, end=None, offset=None, length=None,
              byte_columns=False):
    if (not isinstance(path, str) or not path or PurePosixPath(path).is_absolute()
            or ".." in path.split("/")):
        return None, True
    artifact = parsed.by_rel.get(path)
    if artifact is None and (PureWindowsPath(path).drive or "\\" in path):
        return None, True
    physical = {"artifactLocation": {"uri": quote_from_bytes(os.fsencode(path), safe="/")}}
    try:
        if offset is not None:
            if (artifact is None or artifact.raw is None or type(offset) is not int
                    or offset < 0 or type(length) is not int or length <= 0
                    or offset + length > len(artifact.raw)):
                raise ValueError("invalid byte region")
            physical["region"] = {"byteOffset": offset, "byteLength": length}
        elif start and start.get("line") is not None:
            if artifact is None or artifact.text is None:
                raise ValueError("source unavailable")
            if path not in line_cache:
                line_cache[path] = artifact.text.split("\n")
            lines = line_cache[path]
            positions = []
            for position in (start, end or start):
                line, col = position.get("line"), position.get("col")
                point = {"line": line, "col": 1 if col is None else col}
                _, character, _ = source_region(artifact, point, point,
                                                byte_columns=byte_columns, lines=lines)
                positions.append((line, None if col is None else character))
            (line, col), (last, last_col) = positions
            if (last, last_col or 1) < (line, col or 1):
                raise ValueError("inverted text region")
            region = {"startLine": line}
            if col is not None:
                region["startColumn"] = col
            if end is not None:
                region["endLine"] = last
                if last_col is not None:
                    region["endColumn"] = last_col
            physical["region"] = region
        return {"physicalLocation": physical}, artifact is None
    except (ValueError, TypeError, AttributeError):
        return {"physicalLocation": physical}, True


def _raw_view(candidate, stable_id):
    value = deepcopy(candidate)
    value["candidate_id"] = stable_id
    evidence = value["finding"].get("evidence", {})
    if value.get("analyzer") == "opengrep" or evidence.get("engine") == "opengrep":
        evidence.pop("fingerprint", None)
    return value


def build_sarif(parsed, report):
    """Map final decisions without applying policy, model opinions or detection logic."""
    correlation = report.correlation
    line_cache = {}
    if correlation.get("errors"):
        raise ValueError("Cannot emit final SARIF after correlation failure; raw report retained")
    identities = {link["candidate_id"]: link.get("stable_candidate_id", link["candidate_id"])
                  for link in correlation["links"]}
    raw = [_raw_view(c, identities[c["candidate_id"]]) for c in correlation["raw_candidates"]]
    raw.sort(key=lambda item: item["candidate_id"])
    links = [{**link, "candidate_id": identities[link["candidate_id"]]}
             for link in correlation["links"]]
    for link in links:
        link.pop("stable_candidate_id", None)
    links.sort(key=lambda item: item["candidate_id"])
    rule_ids = sorted({r["rule_id"] for r in correlation["results"]})
    titles = {}
    for entry in correlation["results"]:
        finding = entry["finding"]
        titles.setdefault(entry["rule_id"], set()).add(finding.get("title") or finding["rule"])
    rules = [{"id": rid, "shortDescription": {"text": min(titles[rid])}} for rid in rule_ids]
    indexes = {rid: i for i, rid in enumerate(rule_ids)}
    results = []
    for entry in correlation["results"]:
        finding = entry["finding"]
        evidence = finding.get("evidence", {})
        properties = {
            "id": entry["id"], "title": finding.get("title") or finding["rule"],
            "category": "security-finding" if finding["vector"] else "analysis-diagnostic",
            "originalSeverity": entry["original_severity"],
            "effectiveSeverity": entry["effective_severity"], "evidence": entry["evidence"],
            "disposition": entry["disposition"], "reason": entry["decision_reason"],
            "policyVersion": entry["policy_version"],
            "decisionProvenance": entry["decision_provenance"],
            "candidateIds": sorted(identities[cid] for cid in entry["candidate_ids"]),
            "provenance": entry["provenance"], "contextDigest": entry["context_digest"],
            "coverage": entry["coverage"], "governingManifest": entry["manifest"],
            "limitations": list(entry["limitations"]),
        }
        properties.update({key: finding[source] for key, source in
                           (("sxv", "vector"), ("cwe", "cwe"), ("tier", "tier"))
                           if finding.get(source)})
        result = {"ruleId": entry["rule_id"], "ruleIndex": indexes[entry["rule_id"]],
                  "message": {"text": finding["message"]},
                  "level": _LEVEL[entry["effective_severity"]],
                  "partialFingerprints": {entry["fingerprint_version"]: entry["fingerprint"]},
                  "properties": properties}
        unmapped = evidence.get("location_mapping") == "unvalidated"
        location, invalid = _location(
            parsed, finding["path"], line_cache, {"line": finding.get("line"),
                                     "col": None if unmapped else finding.get("column")},
            None if unmapped else evidence.get("end"), finding.get("offset"), finding.get("length"),
            evidence.get("engine") == "opengrep")
        if location:
            result["locations"] = [location]
        if invalid and finding["path"]:
            properties["limitations"].append("location-unvalidated")
        if invalid or unmapped or not location or "region" not in location["physicalLocation"]:
            properties["reportedLocation"] = {k: finding.get(k) for k in
                                              ("path", "line", "column", "offset", "length")}
        if entry["code_flow"]:
            steps = []
            for i, step in enumerate(entry["code_flow"]):
                location, invalid = _location(parsed, step["path"], line_cache,
                                               step["start"], step["end"],
                                               byte_columns=True)
                if invalid:
                    raise ValueError("Validated code flow lost its source mapping")
                steps.append({"location": location, "kinds": [step["role"]], "executionOrder": i})
            result["codeFlows"] = [{"threadFlows": [{"locations": steps}]}]
        if entry["disposition"] == "suppressed":
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": entry["decision_reason"]}]
        results.append(result)
    results.sort(key=lambda r: (SEVERITY_RANK[r["properties"]["effectiveSeverity"]],
                                r["properties"]["id"]))
    run = {"tool": {"driver": {"name": "skill-xray", "version": __version__, "rules": rules}},
           "columnKind": "unicodeCodePoints", "results": results,
           "invocations": [{"executionSuccessful": correlation["execution_successful"]}],
           "properties": {"opengrepVersion": OPENGREP_VERSION, "policyVersion": POLICY_VERSION,
                          "package": {"name": correlation["package"]["name"],
                                      "contentDigest": correlation["package"]["content_digest"],
                                      "digestVersion": correlation["package"]["digest_version"]},
                          "capabilityContexts": correlation["capability_contexts"],
                          "rulesetDigest": hashlib.sha256((Path(__file__).with_name("rules") /
                                           "opengrep-phase1.yml").read_bytes()).hexdigest(),
                          "coverage": correlation["coverage"],
                          "contextLimitations": correlation["context_limitations"],
                          "contextErrors": sorted(report.context_errors),
                          "rawScope": "emitted-results-before-reporting-deduplication",
                          "rawCandidates": raw, "candidateLinks": links}}
    return {"version": "2.1.0", "$schema": json.loads(_SCHEMA.read_text(encoding="utf-8"))["id"],
            "runs": [run]}


def validate_sarif(document):
    try:
        _validator().validate(document)
        run, = document["runs"]
        rules = run["tool"]["driver"]["rules"]
        raw = run["properties"]["rawCandidates"]
        links = run["properties"]["candidateLinks"]
        results = run["results"]
        contexts = run["properties"]["capabilityContexts"]
        if not isinstance(contexts, dict) or any(
                not isinstance(context, dict) or (context.get("manifest") or "") != key
                for key, context in contexts.items()):
            raise ValueError("Invalid governing capability contexts")
        by_candidate = {c["candidate_id"]: c for c in raw}
        by_result = {r["properties"]["id"]: r for r in results}
        linked = {rid: [] for rid in by_result}
        primary = {rid: 0 for rid in by_result}
        for link in links:
            linked[link["result_id"]].append(link["candidate_id"])
            primary[link["result_id"]] += link["disposition"] != "duplicate"
        if (len(by_candidate) != len(raw) or len(by_result) != len(results)
                or len(links) != len(raw)
                or {link["candidate_id"] for link in links} != set(by_candidate)
                or len({r["id"] for r in rules}) != len(rules)):
            raise ValueError("Invalid candidate/result identities")
        for result in results:
            props = result["properties"]
            manifest = props["governingManifest"]
            context = contexts.get(manifest or "")
            if context is None and (props["coverage"] != "incomplete" or (
                    manifest is not None and not run["properties"]["contextErrors"])):
                raise ValueError("Invalid capability context reference")
            if (rules[result["ruleIndex"]]["id"] != result["ruleId"] or not props["candidateIds"]
                    or not props["reason"] or not props["policyVersion"]
                    or props["disposition"] not in {"reported", "suppressed", "corrected"}
                    or sorted(linked[props["id"]]) != sorted(props["candidateIds"])
                    or primary[props["id"]] != 1
                    or SEVERITY_RANK[props["effectiveSeverity"]]
                    < SEVERITY_RANK[props["originalSeverity"]]
                    or result["level"] != _LEVEL[props["effectiveSeverity"]]):
                raise ValueError("Invalid result contract")
            if props["coverage"] == "incomplete" and run["properties"]["coverage"] != "incomplete":
                raise ValueError("Inconsistent run completeness")
            suppressed = props["disposition"] == "suppressed"
            corrected = props["disposition"] == "corrected"
            changed = props["effectiveSeverity"] != props["originalSeverity"]
            if corrected != changed or corrected and (
                    not props.get("sxv") or props["decisionProvenance"] != "operator-policy"
                    or props["coverage"] != "no-reported-gap"):
                raise ValueError("Invalid severity correction audit")
            if suppressed != bool(result.get("suppressions")) or suppressed and (
                    not props.get("sxv") or props["decisionProvenance"] != "operator-policy"
                    or props["coverage"] != "no-reported-gap"
                    or result["suppressions"][0]["justification"] != props["reason"]):
                raise ValueError("Invalid suppression audit")
            expected = sorted({canonical(by_candidate[cid]["finding"].get("evidence", {}))
                               for cid in props["candidateIds"]})
            if [canonical(evidence) for evidence in props["evidence"]] != expected:
                raise ValueError("Result evidence contradicts raw findings")
            for cid in props["candidateIds"]:
                finding = by_candidate[cid]["finding"]
                category = "security-finding" if finding["vector"] else "analysis-diagnostic"
                rule = "skill-xray/" + quote(finding["rule"] or "unknown-rule", safe="-._")
                if result["ruleId"] != rule or props["category"] != category or any(
                        (props.get(key) or None) != (finding.get(source) or None)
                        for key, source in (("sxv", "vector"), ("cwe", "cwe"), ("tier", "tier"))):
                    raise ValueError("Result classification contradicts raw finding")
                if finding["severity"] != props["originalSeverity"]:
                    raise ValueError("Raw severity changed")
        for link in links:
            result = by_result[link["result_id"]]["properties"]
            if (link["candidate_id"] not in result["candidateIds"] or not link["reason"]
                    or link["disposition"] not in {"duplicate", result["disposition"]}):
                raise ValueError("Invalid candidate result link")
    except Exception as exc:
        raise ValueError("SARIF validation failed (%s)" % type(exc).__name__) from exc


def encode_sarif(document):
    validate_sarif(document)
    data = (canonical(document) + "\n").encode("ascii")
    if len(data) > _MAX_REPORT_BYTES:
        raise ValueError("SARIF report exceeds 64 MiB; no partial report written")
    return data


def write_sarif(document, target, *, source_root):
    """Validate first; never place a generated report among scanner input artifacts."""
    target, source_root = Path(target), Path(source_root).resolve()
    if target.is_symlink():
        raise ValueError("SARIF output must be outside the scanned package")
    target = target.resolve()
    if target.is_relative_to(source_root):
        raise ValueError("SARIF output must be outside the scanned package")
    if target.exists() and not target.is_file():
        raise ValueError("SARIF output must be a regular file")
    data = encode_sarif(document)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".skill-xray-",
                                         delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
