"""Validated SARIF serialization of already-correlated, audited results."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from copy import deepcopy
from functools import lru_cache
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import quote, quote_from_bytes

from jsonschema import Draft4Validator

from . import __version__
from .correlate import FINGERPRINT_VERSION, canonical, source_region
from .disposition import POLICY_VERSION
from .findings import SEVERITY_RANK
from .llm.judge import POLICY_VERSION as SHADOW_POLICY_VERSION
from .llm.judge import RESPONSE_SCHEMA, REVIEW_POLICY_VERSION
from .opengrep_runtime import VERSION as OPENGREP_VERSION

__all__ = ["build_sarif", "encode_sarif", "validate_sarif", "write_sarif"]

_SCHEMA = Path(__file__).with_name("schemas") / "sarif-schema-2.1.0.json"
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_MAX_REPORT_BYTES = 64 * 1024 * 1024
_REVIEW_FIELDS = ("candidate_id", "disposition", "status", "reason", "policy_version", "provenance",
                  "proposal", "tags", "reviewer", "request_sha256", "response_sha256",
                  "reviewed_candidate_id", "failure_reason")


@lru_cache(maxsize=1)
def _validator():
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    Draft4Validator.check_schema(schema)
    return Draft4Validator(schema)


def _location(parsed, path, line_cache, start=None, end=None, offset=None, length=None,
              byte_columns=False):
    artifact = parsed.by_rel.get(path) if isinstance(path, str) else None
    if (not isinstance(path, str) or not path or PurePosixPath(path).is_absolute()
            or ".." in path.split("/")
            or artifact is None and (PureWindowsPath(path).drive or "\\" in path)):
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
            if end is not None and end.get("col") is None:
                raise ValueError("incomplete end boundary")
            if path not in line_cache:
                line_cache[path] = artifact.text.split("\n")
            positions = []
            for position in (start, end or start):
                line, col = position.get("line"), position.get("col")
                point = {"line": line, "col": 1 if col is None else col}
                _, character, _ = source_region(artifact, point, point,
                                                byte_columns=byte_columns, lines=line_cache[path])
                positions.append((line, None if col is None else character))
            (line, col), (last, last_col) = positions
            if (last, last_col or 1) < (line, col or 1):
                raise ValueError("inverted text region")
            region = {"startLine": line}
            if col is not None:
                region["startColumn"] = col
            if end is not None:
                region.update(endLine=last, endColumn=last_col)
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


def _review_audit(report, identities):
    decisions = report.dispositions if report.review_mode else report.shadow
    records = []
    for decision in decisions:
        # Requests contain whole source files; export only the compact review and audit hashes.
        record = {key: deepcopy(decision[key]) for key in _REVIEW_FIELDS if key in decision}
        for key in ("candidate_id", "reviewed_candidate_id"):
            if key in record:
                if record[key] not in identities:
                    raise ValueError("Unknown LLM review candidate")
                record[key] = identities[record[key]]
        if record.get("proposal") is not None:
            if record["proposal"]["candidate_id"] != decision["candidate_id"]:
                raise ValueError("LLM proposal candidate mismatch")
            record["proposal"]["candidate_id"] = record["candidate_id"]
        records.append(record)
    return {"mode": "annotated" if report.review_mode else "shadow", "authoritative": False,
            "decisions": sorted(records, key=lambda d: d["candidate_id"])}


def _validate_review(audit, raw):
    """Validate audit structure; judgment semantics belong to the trusted producer."""
    if (set(audit) != {"mode", "authoritative", "decisions"}
            or audit["mode"] not in {"annotated", "shadow"} or audit["authoritative"] is not False):
        raise ValueError("Invalid LLM review mode")
    candidates = {c["candidate_id"]: c for c in raw if c["provenance"] != "advisory-output"}
    records = {d["candidate_id"]: d for d in audit["decisions"]}
    if len(records) != len(audit["decisions"]) or set(records) != set(candidates):
        raise ValueError("Invalid LLM review identities")
    annotated = audit["mode"] == "annotated"
    policy = REVIEW_POLICY_VERSION if annotated else SHADOW_POLICY_VERSION
    for cid, decision in records.items():
        if (not set(decision).issubset(_REVIEW_FIELDS)
                or decision["policy_version"] != policy
                or decision["status"] not in {"ineligible", "proposed", "duplicate-review",
                    "budget", "unavailable", "incomplete-context", "invalid-response", "error"}
                or decision["disposition"] not in {"reported", "llm-disputed"}
                or decision["provenance"] not in {
                    "deterministic-policy", "llm-review-policy", "llm-shadow"}
                or not annotated and decision["disposition"] != "reported"
                or any(not isinstance(decision[key], str) or not decision[key].strip()
                       or len(decision[key]) > 200
                       for key in ("reason", "policy_version", "provenance"))):
            raise ValueError("Invalid LLM review decision")
        if ({"request_sha256", "reviewer", "response_sha256"}.intersection(decision)
                and not {"request_sha256", "reviewer"}.issubset(decision)):
            raise ValueError("Incomplete LLM request provenance")
        hashes = [decision[key] for key in ("request_sha256", "response_sha256") if key in decision]
        if "reviewer" in decision:
            reviewer = decision["reviewer"]
            if (not isinstance(reviewer, dict)
                    or set(reviewer) != {"provider", "model", "prompt_sha256", "schema_sha256"}
                    or any(not isinstance(reviewer[key], str) or not reviewer[key]
                           or len(reviewer[key]) > 200 or reviewer[key] != reviewer[key].strip()
                           or not reviewer[key].isprintable() for key in ("provider", "model"))):
                raise ValueError("Invalid LLM reviewer identity")
            hashes.extend(reviewer[key] for key in ("prompt_sha256", "schema_sha256"))
        if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
               for value in hashes):
            raise ValueError("Invalid LLM audit hash")
        if "failure_reason" in decision and (
                not isinstance(decision["failure_reason"], str)
                or not decision["failure_reason"].strip() or len(decision["failure_reason"]) > 200):
            raise ValueError("Invalid LLM failure reason")
        if "tags" in decision and decision["tags"] != (
                ["llm-disputed"] if decision["disposition"] == "llm-disputed" else []):
            raise ValueError("LLM tags contradict disposition")
        proposal = decision["proposal"]
        if proposal is not None:
            if not {"reviewer", "request_sha256", "response_sha256"}.issubset(decision):
                raise ValueError("Missing LLM proposal provenance")
            Draft4Validator(RESPONSE_SCHEMA).validate(proposal)
            if (proposal["candidate_id"] != cid or decision["status"] != "proposed"
                    or proposal["verdict"] == "propose_false_positive" and (
                        proposal["mechanism"] != "not_supported"
                        or proposal["intent"] == "malicious")):
                raise ValueError("Invalid LLM proposal")
        elif decision["status"] == "proposed":
            raise ValueError("Missing LLM proposal")
        original = decision.get("reviewed_candidate_id")
        if original is not None:
            if (original == cid or original not in records
                    or "reviewed_candidate_id" in records[original] or proposal is not None
                    or candidates[cid]["finding"] != candidates[original]["finding"]
                    or decision["disposition"] != records[original]["disposition"]):
                raise ValueError("Invalid duplicate review reference")
            proposal = records[original]["proposal"]
            expected = "duplicate-review" if proposal is not None else records[original]["status"]
            if decision["status"] != expected:
                raise ValueError("Duplicate review changed the original outcome")
        elif decision["status"] == "duplicate-review":
            raise ValueError("Missing duplicate review reference")
        if decision["disposition"] == "llm-disputed" and proposal is None:
            raise ValueError("LLM dispute has no review proposal")


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
    if report.llm_usage.get("judge_enabled"):
        run["properties"]["llmReview"] = _review_audit(report, identities)
    return {"version": "2.1.0", "$schema": _validator().schema["id"], "runs": [run]}


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
        primary = [link["result_id"] for link in links if link["disposition"] != "duplicate"]
        for link in links:
            linked[link["result_id"]].append(link["candidate_id"])
        if (len(by_candidate) != len(raw) or len(by_result) != len(results)
                or len(links) != len(raw)
                or {link["candidate_id"] for link in links} != set(by_candidate)
                or sorted(primary) != sorted(by_result)
                or len({r["id"] for r in rules}) != len(rules)):
            raise ValueError("Invalid candidate/result identities")
        if "llmReview" in run["properties"]:
            _validate_review(run["properties"]["llmReview"], raw)
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
                    or props["id"] != "finding-" + result[
                        "partialFingerprints"][FINGERPRINT_VERSION]
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


def is_within_source(path, root):
    # Filesystem identity catches case/Unicode aliases that lexical paths miss.
    return path.is_relative_to(root) or any(
        ancestor.exists() and ancestor.samefile(root) for ancestor in (path, *path.parents))


def write_sarif(document, target, *, source_root):
    """Validate first; never place a generated report among scanner input artifacts."""
    target, source_root = Path(target), Path(source_root).resolve()
    if target.is_symlink():
        raise ValueError("SARIF output must be outside the scanned package")
    target = target.resolve()
    if is_within_source(target, source_root):
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
