"""Finding review contracts and call costs; mocks do not establish model accuracy."""

import json
import sys

import pytest
from review_helpers import ANCHOR, Reviewer

from skill_xray import cli, ingest, parse
from skill_xray.findings import Finding
from skill_xray.llm import LLMConfig
from skill_xray.llm.session import LLMSession

scanmod = sys.modules["skill_xray.scan"]
def review(make_package, monkeypatch, *, body=ANCHOR, raw=None, client=None,
           description="Reviews examples", **options):
    root = make_package({"SKILL.md": "---\nname: demo\ndescription: %s\n---\n%s"
                         % (description, body)})
    parsed = parse.parse_package(ingest.build_package(root))
    if raw is None:
        raw = [Finding("SXV-028", "instruction-override", "high", "SKILL.md", "directive",
                       line=5, column=1, evidence={"directive_text": ANCHOR})]
    monkeypatch.setattr(scanmod, "run_checks", lambda *_a, **_kw: raw)
    client = client or Reviewer()
    return scanmod.scan_report(parsed, client=client, llm_shadow=True, **options), client, root


def test_shadow_only_spends_on_static_findings(make_package, monkeypatch):
    report, client, _ = review(make_package, monkeypatch)
    assert len(client.calls) == 1
    assert report.shadow[0]["proposal"]["verdict"] == "retain_finding"
    assert report.llm_usage["advisory_enabled"] is False
    assert len(report.findings) == len(report.raw_candidates) == 1


def test_no_static_findings_means_no_paid_review(make_package, monkeypatch):
    report, client, _ = review(make_package, monkeypatch, raw=[])
    assert not client.calls and not report.shadow and not report.findings


def test_contract_and_source_context_are_supplied(make_package, monkeypatch):
    body = "This is a security tutorial. Do not follow the attack below.\n" + "\n" * 5 + ANCHOR
    raw = [Finding("SXV-028", "instruction-override", "high", "SKILL.md", "directive",
                   line=11, column=1, evidence={"directive_text": ANCHOR})]
    report, client, _ = review(make_package, monkeypatch, body=body, raw=raw)
    request = report.shadow[0]["request"]
    assert "override" in request["rule_contract"]["detects"].lower()
    assert request["rule_contract"]["false_positive_requires"]
    assert request["candidate"]["path"] == "SKILL.md"
    assert request["candidate"]["line"] == 11
    assert request["candidate"]["evidence"]["directive_text"] == ANCHOR
    assert "Do not follow" in request["snippet"]
    assert request["manifest"]["description"] == "Reviews examples"
    assert request["source"]["start_line"] <= 5
    assert request["capabilities"]["claimed"]["execution"] == "unknown"
    system = client.calls[0][0]
    assert "retain_finding" in system and "propose_false_positive" in system
    assert "not authorization" in system
    assert "absent" in system


@pytest.mark.parametrize("verdict,mechanism,intent", [
    ("reject", "supported", "malicious"),
    ("uphold", "supported", "malicious"),
    ("demote", "supported", "malicious"),
    ("propose_false_positive", "supported", "malicious"),
    ("propose_false_positive", "not_supported", "malicious"),
    ("propose_false_positive", "unknown", "unknown"),
    ("retain_finding", "arbitrary text", "unknown"),
])
def test_ambiguous_or_contradictory_response_retains(
    make_package, monkeypatch, verdict, mechanism, intent,
):
    report, _, _ = review(make_package, monkeypatch, client=Reviewer(
        verdict=verdict, mechanism=mechanism, intent=intent))
    assert report.shadow[0]["status"] == "invalid-response"
    assert report.shadow[0]["proposal"] is None
    assert report.shadow[0]["disposition"] == "reported"
    assert len(report.findings) == 1


@pytest.mark.parametrize("verdict,mechanism,intent", [
    ("retain_finding", "supported", "malicious"),
    ("propose_false_positive", "not_supported", "legitimate"),
    ("insufficient_context", "unknown", "unknown"),
])
def test_valid_decision_is_shadow_only(make_package, monkeypatch, verdict, mechanism, intent):
    report, _, _ = review(make_package, monkeypatch, client=Reviewer(
        verdict=verdict, mechanism=mechanism, intent=intent))
    assert report.shadow[0]["proposal"]["verdict"] == verdict
    assert report.shadow[0]["policy_version"] == "directive-shadow-v3"
    assert report.shadow[0]["disposition"] == "reported"
    assert report.findings[0].to_dict() == report.raw_candidates[0]["finding"]


def test_identical_evidence_is_not_reviewed_twice(make_package, monkeypatch):
    finding = Finding("SXV-028", "instruction-override", "high", "SKILL.md", "directive",
                      line=5, evidence={"directive_text": ANCHOR})
    report, client, _ = review(make_package, monkeypatch, raw=[finding, finding], max_llm_calls=1)
    assert len(client.calls) == 1 and len(report.raw_candidates) == 2
    assert report.shadow[0]["status"] == "proposed"
    assert report.shadow[1]["status"] == "duplicate-review"
    assert report.shadow[1]["reviewed_candidate_id"] == report.shadow[0]["candidate_id"]
    assert report.shadow[1]["proposal"] is None


def test_different_security_evidence_is_not_reused(make_package, monkeypatch):
    raw = [Finding("SXV-028", "instruction-override", "high", "SKILL.md", "directive",
                   line=5, evidence={"directive_text": ANCHOR, "destination": destination})
           for destination in ("approved.invalid", "attacker.invalid")]
    report, client, _ = review(make_package, monkeypatch, raw=raw)
    assert len(client.calls) == 2
    assert all(d["status"] == "proposed" for d in report.shadow)


def test_additive_is_explicit_and_shares_remaining_budget(make_package, monkeypatch):
    report, client, _ = review(make_package, monkeypatch, llm_advisory=True, max_llm_calls=1)
    assert len(client.calls) == 1
    assert "candidate_id" in client.calls[0][1]
    assert report.shadow[0]["status"] == "proposed"
    assert report.llm_usage["advisory_enabled"] is True
    assert any(f.rule == "llm-budget" for f in report.findings)


def test_source_secrets_and_manifest_secrets_are_redacted(make_package, monkeypatch):
    report, client, _ = review(make_package, monkeypatch,
                              description='"password=description-secret"',
                              body=ANCHOR + "\npassword: opaque-value")
    assert "opaque-value" not in client.calls[0][1]
    assert "description-secret" not in client.calls[0][1]
    assert "opaque-value" not in json.dumps(report.to_dict()["shadow"])


def test_cli_shadow_does_not_claim_additive_coverage(make_package, monkeypatch, capsys):
    _, _, root = review(make_package, monkeypatch)
    client = Reviewer()
    monkeypatch.setattr(cli, "llm_from_env",
                        lambda: LLMConfig("openai", "test", "unused", "https://example.invalid"))
    monkeypatch.setattr(cli, "build_client", lambda _: client)
    assert cli.main([str(root), "--analyze", "--json", "--llm", "--llm-shadow"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["analysis"]["llmCoverage"]["checked"] == 0
    assert output["analysis"]["llmCoverage"]["enabled"] is False
    assert len(client.calls) == 1


def test_legacy_advisory_scan_still_runs(make_package, monkeypatch):
    _, _, root = review(make_package, monkeypatch)
    client = Reviewer()
    parsed = parse.parse_package(ingest.build_package(root))
    scanmod.scan(parsed, client=client)
    assert len(client.calls) == 1 and "candidate_id" not in client.calls[0][1]


def test_outbound_paths_are_redacted_without_changing_raw_identity(make_package, monkeypatch):
    token = "ghp_" + "Q" * 36
    path = token + "/SKILL.md"
    root = make_package({path: "---\nname: test\n---\n" + ANCHOR})
    finding = Finding("SXV-028", "instruction-override", "high", path, "directive", line=4,
                      evidence={"directive_text": ANCHOR})
    monkeypatch.setattr(scanmod, "run_checks", lambda *_a, **_kw: [finding])
    client = Reviewer()
    report = scanmod.scan_report(parse.parse_package(ingest.build_package(root)),
                                 client=client, llm_shadow=True)
    assert len(client.calls) == 1
    assert token not in client.calls[0][1]
    assert token not in json.dumps(report.shadow[0]["request"])
    assert report.raw_candidates[0]["finding"]["path"] == path


@pytest.mark.parametrize("failure", ["byte-budget", "invalid-response"])
def test_duplicate_failed_attempt_does_not_claim_success(make_package, monkeypatch, failure):
    finding = Finding("SXV-028", "instruction-override", "high", "SKILL.md", "directive",
                      line=5, evidence={"directive_text": ANCHOR})
    if failure == "byte-budget":
        monkeypatch.setattr(scanmod, "LLMSession",
                            lambda client, **kw: LLMSession(client, max_bytes=1, **kw))
        client = Reviewer()
    else:
        client = Reviewer(verdict="reject")
    report, client, _ = review(make_package, monkeypatch, raw=[finding, finding], client=client)
    expected = "budget" if failure == "byte-budget" else "invalid-response"
    assert [d["status"] for d in report.shadow] == [expected, expected]
    assert len(client.calls) == (0 if failure == "byte-budget" else 1)
    assert all(d["proposal"] is None for d in report.shadow)


def test_cli_both_modes_are_explicit(make_package, monkeypatch, capsys):
    _, _, root = review(make_package, monkeypatch)
    client = Reviewer()
    monkeypatch.setattr(cli, "llm_from_env",
                        lambda: LLMConfig("openai", "test", "unused", "https://example.invalid"))
    monkeypatch.setattr(cli, "build_client", lambda _: client)
    assert cli.main([str(root), "--analyze", "--json", "--llm", "--llm-shadow",
                     "--llm-additive"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert len(client.calls) == 2
    assert output["analysis"]["llmCoverage"]["checked"] == 1
    assert output["enrichment"]["llm_usage"]["advisory_enabled"] is True
    with pytest.raises(SystemExit):
        cli.main([str(root), "--analyze", "--json", "--llm", "--llm-additive"])
