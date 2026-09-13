"""LLM audit export must not change deterministic reporting decisions."""

import hashlib
import json
import sys
from copy import deepcopy

import pytest
from test_llm_review import BODY, Reviewer, finding, fixture, run

from skill_xray import cli
from skill_xray.findings import Finding
from skill_xray.llm import LLMError
from skill_xray.sarif import build_sarif, encode_sarif, validate_sarif, write_sarif

scanmod = sys.modules["skill_xray.scan"]


def document(make_package, monkeypatch, **options):
    report = run(make_package, monkeypatch, **options)
    parsed = fixture(make_package, options.get("body", BODY))
    return report, build_sarif(parsed, report)


def test_compact_audit_survives_written_sarif(make_package, monkeypatch, tmp_path):
    report, data = document(make_package, monkeypatch)
    before = deepcopy(report.to_dict())
    target = tmp_path / "review.sarif"
    write_sarif(data, target, source_root=tmp_path / "pkg")
    written = json.loads(target.read_bytes())
    validate_sarif(written)
    output = written["runs"][0]
    audit = output["properties"]["llmReview"]
    assert audit["mode"] == "annotated" and audit["authoritative"] is False
    decision, = audit["decisions"]
    result, = output["results"]
    assert decision["candidate_id"] == result["properties"]["candidateIds"][0]
    assert decision["proposal"]["candidate_id"] == decision["candidate_id"]
    assert decision["disposition"] == "llm-disputed"
    assert decision["proposal"]["confidence"] == "high"
    assert decision["proposal"]["evidence_quote"] == BODY.strip()
    assert decision["reviewer"]["model"] == "fixture-1"
    assert decision["request_sha256"] == report.dispositions[0]["request_sha256"]
    assert decision["response_sha256"] == report.dispositions[0]["response_sha256"]
    assert decision["policy_version"] and decision["reason"] and decision["provenance"]
    assert "request" not in decision and "source" not in decision
    assert result["properties"]["disposition"] == "reported" and "suppressions" not in result
    assert result["properties"]["originalSeverity"] == "high"
    assert result["properties"]["effectiveSeverity"] == "high"
    assert report.to_dict() == before
    assert encode_sarif(build_sarif(fixture(make_package), report)) == target.read_bytes()


def test_duplicate_reviews_use_stable_links(make_package, monkeypatch):
    client = Reviewer()
    _, data = document(make_package, monkeypatch, raw=[finding(), finding()], client=client)
    output = data["runs"][0]
    first, duplicate = sorted(output["properties"]["llmReview"]["decisions"],
                              key=lambda d: d["status"] == "duplicate-review")
    assert len(client.calls) == 1 and len(output["results"]) == 1
    assert duplicate["reviewed_candidate_id"] == first["candidate_id"]
    assert duplicate["proposal"] is None and first["proposal"] is not None
    assert {first["candidate_id"], duplicate["candidate_id"]} == set(
        output["results"][0]["properties"]["candidateIds"])
    validate_sarif(data)


@pytest.mark.parametrize("change,status", [
    ({"verdict": "retain_finding", "mechanism": "supported"}, "proposed"),
    ({"verdict": "insufficient_context", "mechanism": "unknown"}, "proposed"),
    ({"candidate_id": "wrong"}, "invalid-response"),
    ({"evidence_quote": "invented quote"}, "invalid-response"),
    ({"confidence": "certain"}, "invalid-response"),
])
def test_judge_fail_safe_results_reach_sarif(make_package, monkeypatch, change, status):
    _, data = document(make_package, monkeypatch, client=Reviewer(change))
    output = data["runs"][0]
    decision, = output["properties"]["llmReview"]["decisions"]
    assert decision["status"] == status and decision["disposition"] == "reported"
    assert output["results"][0]["level"] == "error"
    assert "suppressions" not in output["results"][0]
    validate_sarif(data)


@pytest.mark.parametrize("options,status", [
    ({"max_llm_calls": 0}, "budget"),
    ({"client": Reviewer(error=LLMError())}, "unavailable"),
    ({"body": BODY + "x" * 6100}, "incomplete-context"),
    ({"body": BODY + "\n[external](https://example.invalid)"}, "incomplete-context"),
])
def test_unreviewed_is_visible_not_a_clean_verdict(make_package, monkeypatch, options, status):
    _, data = document(make_package, monkeypatch, **options)
    decision, = data["runs"][0]["properties"]["llmReview"]["decisions"]
    assert decision["status"] == status and decision["proposal"] is None
    assert decision["disposition"] == "reported"
    validate_sarif(data)


def test_error_and_mechanical_candidates_cannot_be_disputed(make_package, monkeypatch):
    raw = [finding(evidence={"engine": "opengrep"}),
           Finding("", "check-error", "high", "SKILL.md", "failed")]
    client = Reviewer()
    _, data = document(make_package, monkeypatch, raw=raw, client=client)
    assert not client.calls
    output = data["runs"][0]
    assert len(output["properties"]["llmReview"]["decisions"]) == 2
    assert all(d["status"] == "ineligible" and d["disposition"] == "reported"
               for d in output["properties"]["llmReview"]["decisions"])
    assert output["invocations"][0]["executionSuccessful"] is False
    validate_sarif(data)


@pytest.mark.parametrize("mode", ["off", "annotated", "shadow"])
def test_empty_review_and_disabled_output(make_package, monkeypatch, mode):
    monkeypatch.setattr(scanmod, "run_checks", lambda *_a, **_kw: [])
    parsed = fixture(make_package)
    options = {} if mode == "off" else {"client": Reviewer(),
                "llm_review" if mode == "annotated" else "llm_shadow": True}
    report = scanmod.scan_report(parsed, **options)
    data = build_sarif(parsed, report)
    props = data["runs"][0]["properties"]
    if mode == "off":
        assert "llmReview" not in props
    else:
        assert props["llmReview"] == {"mode": mode, "authoritative": False, "decisions": []}
    validate_sarif(data)


def test_shadow_proposal_remains_distinct(make_package, monkeypatch):
    monkeypatch.setattr(scanmod, "run_checks", lambda *_a, **_kw: [finding()])
    parsed = fixture(make_package)
    report = scanmod.scan_report(parsed, client=Reviewer(), llm_shadow=True)
    data = build_sarif(parsed, report)
    audit = data["runs"][0]["properties"]["llmReview"]
    assert audit["mode"] == "shadow" and audit["authoritative"] is False
    assert audit["decisions"][0]["proposal"]["verdict"] == "propose_false_positive"
    assert audit["decisions"][0]["disposition"] == "reported"
    validate_sarif(data)


@pytest.mark.parametrize("mode", ["annotated", "shadow"])
@pytest.mark.parametrize("field", ["reason", "impact"])
@pytest.mark.parametrize("padding,valid", [(181, True), (182, False), (190, False)])
def test_redaction_bounds_preserve_report(make_package, monkeypatch, mode, field, padding, valid):
    raw = [finding()]
    monkeypatch.setattr(scanmod, "run_checks", lambda *_a, **_kw: raw)
    parsed = fixture(make_package)
    client = Reviewer({field: "A" * padding + " api_key=a"})
    report = scanmod.scan_report(parsed, client=client,
                                **{"llm_review" if mode == "annotated" else "llm_shadow": True})
    decision, = report.dispositions if mode == "annotated" else report.shadow
    assert len(client.calls) == 1
    assert decision["status"] == ("proposed" if valid else "invalid-response")
    if valid:
        assert len(decision["proposal"][field]) == 200
        assert decision["proposal"][field].endswith("api_key=[REDACTED]")
    else:
        assert decision["proposal"] is None and decision["disposition"] == "reported"
        assert decision["failure_reason"] == "field-bounds"
    data = json.loads(encode_sarif(build_sarif(parsed, report)))
    result, = data["runs"][0]["results"]
    assert result["properties"]["disposition"] == "reported"
    assert result["properties"]["effectiveSeverity"] == "high"
    assert report.findings == raw
    assert [c["finding"] for c in report.raw_candidates] == [f.to_dict() for f in raw]


@pytest.mark.parametrize("reply", ["{", "[]", "{}", "x" * 16385])
def test_malformed_or_truncated_response_is_retained(make_package, monkeypatch, reply):
    client = Reviewer()
    monkeypatch.setattr(client, "complete", lambda *_: reply)
    _, data = document(make_package, monkeypatch, client=client)
    decision, = data["runs"][0]["properties"]["llmReview"]["decisions"]
    assert decision["status"] == "invalid-response" and decision["proposal"] is None
    assert data["runs"][0]["results"][0]["properties"]["disposition"] == "reported"
    validate_sarif(data)


def test_review_failure_and_additive_output_remain_separate(make_package, monkeypatch):
    def fail(*_args, **_kwargs):
        raise ValueError("unusable review")
    monkeypatch.setattr(scanmod, "judge_candidates", fail)
    advisory = Finding("SXV-038", "semantic-prompt-injection", "medium", "SKILL.md", "advisory")
    monkeypatch.setattr(scanmod, "_advisory", lambda *_: [advisory])
    _, data = document(make_package, monkeypatch, llm_advisory=True)
    output = data["runs"][0]
    assert len(output["results"]) == 2
    assert len(output["properties"]["rawCandidates"]) == 2
    decision, = output["properties"]["llmReview"]["decisions"]
    assert decision["status"] == "error" and decision["proposal"] is None
    assert output["properties"]["contextErrors"] == ["llm-review-error: ValueError"]
    validate_sarif(data)


def test_redaction_cannot_leak_whole_source_into_audit(make_package, monkeypatch):
    client = Reviewer()
    _, data = document(make_package, monkeypatch, client=client,
                       body=BODY + '\napi_key: "a-sensitive-value"\n')
    assert not client.calls
    audit = data["runs"][0]["properties"]["llmReview"]
    assert audit["decisions"][0]["status"] == "incomplete-context"
    assert "a-sensitive-value" not in json.dumps(audit)
    validate_sarif(data)


def test_duplicate_review_cannot_reference_unrelated_evidence(make_package, monkeypatch):
    _, data = document(make_package, monkeypatch, raw=[finding(), finding(message="different")])
    decisions = data["runs"][0]["properties"]["llmReview"]["decisions"]
    decisions[1].update(reviewed_candidate_id=decisions[0]["candidate_id"],
                        proposal=None, status="duplicate-review")
    with pytest.raises(ValueError, match="SARIF validation failed"):
        validate_sarif(data)


@pytest.mark.parametrize("prior_failed,status", [(True, "duplicate-review"), (False, "budget"),
                                               (True, "error")])
def test_reused_review_preserves_original_outcome(make_package, monkeypatch, prior_failed, status):
    client = Reviewer(error=LLMError() if prior_failed else None)
    _, data = document(make_package, monkeypatch, raw=[finding(), finding()], client=client)
    validate_sarif(data)
    decisions = data["runs"][0]["properties"]["llmReview"]["decisions"]
    duplicate = next(d for d in decisions if "reviewed_candidate_id" in d)
    duplicate["status"] = status
    with pytest.raises(ValueError, match="SARIF validation failed"):
        validate_sarif(data)


@pytest.mark.parametrize("mode", ["annotated", "shadow"])
@pytest.mark.parametrize("malformed", [False, True])
def test_returned_response_provenance_survives_even_invalid_json(
        make_package, monkeypatch, mode, malformed):
    monkeypatch.setattr(scanmod, "run_checks", lambda *_a, **_kw: [finding()])
    client, replies = Reviewer(), []
    complete = client.complete
    def record(*args):
        reply = "{" if malformed else complete(*args)
        replies.append(reply)
        return reply
    monkeypatch.setattr(client, "complete", record)
    parsed = fixture(make_package)
    report = scanmod.scan_report(parsed, client=client,
                                **{"llm_review" if mode == "annotated" else "llm_shadow": True})
    data = build_sarif(parsed, report)
    decision, = data["runs"][0]["properties"]["llmReview"]["decisions"]
    assert decision["reviewer"]["model"] == "fixture-1"
    assert decision["response_sha256"] == hashlib.sha256(replies[0].encode()).hexdigest()
    assert decision["status"] == ("invalid-response" if malformed else "proposed")
    assert "response" not in decision
    validate_sarif(data)


@pytest.mark.parametrize("mutation", ["identity", "missing", "duplicate", "proposal-id",
    "duplicate-link", "authority", "disposition", "verdict", "confidence", "status",
    "missing-proposal", "disputed-unknown", "shadow-dispute", "hidden-dispute"])
def test_validation_rejects_broken_review_audit(make_package, monkeypatch, mutation):
    _, data = document(make_package, monkeypatch)
    audit = data["runs"][0]["properties"]["llmReview"]
    decision = audit["decisions"][0]
    if mutation == "identity":
        decision["candidate_id"] = "unrelated"
    elif mutation == "missing":
        audit["decisions"] = []
    elif mutation == "duplicate":
        audit["decisions"].append(deepcopy(decision))
    elif mutation == "proposal-id":
        decision["proposal"]["candidate_id"] = "unrelated"
    elif mutation == "duplicate-link":
        decision["reviewed_candidate_id"] = decision["candidate_id"]
    elif mutation == "authority":
        audit["authoritative"] = True
    elif mutation == "disposition":
        decision["disposition"] = "suppressed"
    elif mutation == "verdict":
        decision["proposal"]["verdict"] = "delete"
    elif mutation == "confidence":
        decision["proposal"]["confidence"] = 0.99
    elif mutation == "missing-proposal":
        decision["proposal"] = None
    elif mutation == "disputed-unknown":
        decision["proposal"]["intent"] = "unknown"
    elif mutation == "shadow-dispute":
        audit["mode"] = "shadow"
    elif mutation == "hidden-dispute":
        decision["disposition"] = "reported"
    else:
        decision["status"] = "approved"
    with pytest.raises(ValueError, match="SARIF validation failed"):
        validate_sarif(data)


@pytest.mark.parametrize("native_code", [False, True])
def test_cli_full_pipeline_keeps_detections_and_exports_review(
        make_package, tmp_path, monkeypatch, capsys, native_code):
    files = {"SKILL.md": "---\nname: demo\n---\n" + BODY}
    if native_code:
        files["run.py"] = "import os, sys\nos.system(sys.argv[1])\n"
    root = make_package(files)
    target = tmp_path / "result.sarif"
    args = [str(root), "--analyze", "--json", "--sarif", str(target)]
    assert cli.main(args) == 0
    baseline_json = json.loads(capsys.readouterr().out)
    baseline = json.loads(target.read_bytes())
    assert "llmReview" not in baseline["runs"][0]["properties"]
    client = Reviewer()
    monkeypatch.setattr(cli, "llm_from_env", lambda: object())
    monkeypatch.setattr(cli, "build_client", lambda _: client)
    outputs = []
    for _ in range(2):
        assert cli.main([*args, "--llm", "--llm-review"]) == 0
        current = json.loads(capsys.readouterr().out)
        # Native run IDs are volatile; compare all detection fields and SARIF bytes.
        for emitted in (baseline_json, current):
            for item in emitted["findings"]:
                evidence = item.get("evidence", {})
                if evidence.get("engine") == "opengrep":
                    evidence.pop("fingerprint", None)
        assert current["findings"] == baseline_json["findings"]
        outputs.append(target.read_bytes())
    assert len(client.calls) == 2 and outputs[0] == outputs[1]
    data = json.loads(outputs[0])
    validate_sarif(data)
    output = data["runs"][0]
    audit = output["properties"].pop("llmReview")
    assert any(d["disposition"] == "llm-disputed" for d in audit["decisions"])
    assert data == baseline
    if native_code:
        assert any(r["properties"].get("sxv") == "SXV-008" and r.get("codeFlows")
                   for r in output["results"])
