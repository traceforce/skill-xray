"""Regressions from the v2 response failures; no paid model calls."""

import json

import pytest
from review_helpers import ANCHOR, Reviewer, direct_review

from skill_xray.llm import HTTPLLMClient, LLMConfig, LLMError, LLMResponseError, judge
from skill_xray.llm.session import LLMBudgetError, LLMSession


def test_prompt_has_separate_reason_and_impact_fields():
    schema = json.loads(judge._SYSTEM.split("Response schema: ", 1)[1])
    assert schema == judge.RESPONSE_SCHEMA
    assert set(schema["required"]) == judge._FIELDS == set(schema["properties"])
    assert schema["additionalProperties"] is False
    assert schema["properties"]["reason"]["maxLength"] == 200
    assert schema["properties"]["impact"]["maxLength"] == 200
    assert schema["properties"]["evidence_quote"]["maxLength"] == 160


@pytest.mark.parametrize("provider", ["openai", "openai-compatible", "anthropic"])
def test_judge_response_schema_reaches_transport_without_changing_legacy(
    make_package, monkeypatch, provider,
):
    client = HTTPLLMClient(LLMConfig(provider, "test", "unused", "https://example.invalid"))
    bodies = []
    oracle = Reviewer()

    def post(url, headers, body):
        bodies.append(body)
        system = body.get("system", body["messages"][0]["content"])
        answer = oracle.complete(system, body["messages"][-1]["content"])
        if provider == "anthropic":
            return {"content": [{"text": answer}], "stop_reason": "end_turn"}
        return {"choices": [{"message": {"content": answer}, "finish_reason": "stop"}]}

    monkeypatch.setattr(client, "_post", post)
    decisions, _, _, _ = direct_review(make_package, client)
    assert decisions[0]["status"] == "proposed"
    assert decisions[0]["policy_version"] == "directive-shadow-v3"
    if provider == "openai":
        fmt = bodies[0]["response_format"]
        assert fmt["type"] == "json_schema"
        assert fmt["json_schema"]["strict"] is True
        assert fmt["json_schema"]["schema"] == judge.RESPONSE_SCHEMA
    else:
        assert "response_format" not in bodies[0]
    client.complete("legacy", "legacy")
    assert "response_format" not in bodies[1]
    assert len(bodies) == 2


def test_shared_budget_counts_structured_schema_bytes():
    class Structured:
        def complete_structured(self, system, user, schema):
            return "{}"

    schema = {"type": "object", "description": "x" * 30}
    encoded = len(json.dumps(schema, sort_keys=True, ensure_ascii=False).encode())
    session = LLMSession(Structured(), max_calls=1, max_bytes=2 + encoded)
    assert session.complete("s", "u", response_schema=schema) == "{}"
    assert session.input_bytes == 2 + encoded
    with pytest.raises(LLMBudgetError):
        session.complete("s", "u", response_schema=schema)
    too_small = LLMSession(Structured(), max_bytes=2 + encoded - 1)
    with pytest.raises(LLMBudgetError):
        too_small.complete("s", "u", response_schema=schema)
    assert too_small.calls == 0


def test_custom_client_keeps_two_argument_interface(make_package, monkeypatch):
    decisions, client, candidates, original = direct_review(make_package)
    assert len(client.calls) == 1
    assert decisions[0]["status"] == "proposed"
    assert candidates[0]["finding"] == original


@pytest.mark.parametrize("override", ["subclass", "instance", "class"])
def test_existing_complete_interceptor_cannot_be_bypassed(make_package, monkeypatch, override):
    oracle = Reviewer()

    class Intercepted(HTTPLLMClient):
        def complete(self, system, user):
            return oracle.complete(system, user)

    cls = Intercepted if override == "subclass" else HTTPLLMClient
    client = cls(LLMConfig("openai", "test", "unused", "https://example.invalid"))
    if override == "instance":
        monkeypatch.setattr(client, "complete", oracle.complete)
    elif override == "class":
        monkeypatch.setattr(HTTPLLMClient, "complete", Intercepted.complete)
    transports = []

    def forbidden(*args):
        transports.append(args)
        raise AssertionError("offline client must not reach transport")

    monkeypatch.setattr(client, "_post", forbidden)
    decisions, _, _, _ = direct_review(make_package, client)
    assert not transports
    assert len(oracle.calls) == 1
    assert decisions[0]["status"] == "proposed"


@pytest.mark.parametrize("mutation,expected", [
    ("merged-fields", "field-set"),
    ("duplicate-key", "duplicate-key"),
    ("invalid-json", "invalid-json"),
    ("field-bound", "field-bounds"),
    ("wrong-id", "identity-or-enum"),
    ("false-quote", "evidence-quote"),
    ("contradiction", "inconsistent-verdict"),
])
def test_invalid_responses_have_safe_diagnostic_codes(
    make_package, monkeypatch, mutation, expected,
):
    class Broken(Reviewer):
        def complete(self, system, user):
            text = super().complete(system, user)
            obj = json.loads(text)
            if mutation == "merged-fields":
                obj["reason and impact"] = obj.pop("reason") + obj.pop("impact")
            elif mutation == "duplicate-key":
                return '{"verdict":"retain_finding",' + text[1:]
            elif mutation == "invalid-json":
                return "password=do-not-echo"
            elif mutation == "field-bound":
                obj["reason"] = "x" * 201
            elif mutation == "wrong-id":
                obj["candidate_id"] = "another-candidate"
            elif mutation == "false-quote":
                obj["evidence_quote"] = "invented secret text"
            elif mutation == "contradiction":
                obj["verdict"] = "propose_false_positive"
            return json.dumps(obj)

    decisions, client, candidates, original = direct_review(make_package, Broken())
    decision = decisions[0]
    assert decision["status"] == "invalid-response"
    assert decision["failure_reason"] == expected
    assert decision["proposal"] is None and decision["disposition"] == "reported"
    assert candidates[0]["finding"] == original
    assert "do-not-echo" not in json.dumps(decisions)
    assert "invented secret text" not in json.dumps(decisions)
    assert len(client.calls) == 1


@pytest.mark.parametrize("error,status", [
    (LLMResponseError("provider body must not be echoed"), "invalid-response"),
    (LLMError("credential must not be echoed"), "unavailable"),
])
def test_structured_provider_failure_retains_without_downgrade_retry(
    make_package, monkeypatch, error, status,
):
    client = HTTPLLMClient(LLMConfig("openai", "test", "unused", "https://example.invalid"))
    calls = []

    def fail(url, headers, body):
        calls.append(body)
        raise error

    monkeypatch.setattr(client, "_post", fail)
    decisions, _, candidates, original = direct_review(make_package, client)
    assert "response_format" in calls[0]
    assert len(calls) == 1
    assert decisions[0]["status"] == status
    assert decisions[0]["proposal"] is None
    assert candidates[0]["finding"] == original
    assert "must not be echoed" not in json.dumps(decisions)


def test_schema_does_not_make_a_fabricated_quote_trusted():
    reply = json.loads(Reviewer().complete("", json.dumps({
        "candidate": {"candidate_id": "candidate-000000"}})))
    reply["evidence_quote"] = "fabricated quote"
    with pytest.raises(ValueError):
        judge._proposal(json.dumps(reply), "candidate-000000", ANCHOR)
