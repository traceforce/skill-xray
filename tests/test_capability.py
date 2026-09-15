"""Context is scoped evidence, never permission to remove a finding."""

from copy import deepcopy

import pytest

from skill_xray import checks, ingest, opengrep_bridge, parse
from skill_xray.capability import build_triads
from skill_xray.checks.preproc import check as preproc_check
from skill_xray.findings import Finding
from skill_xray.opengrep_bridge import SelectedCode, check, findings_from_report


def _parsed(make_package, files):
    return parse.parse_package(ingest.build_package(str(make_package(files))))


def _triads(parsed, observations=()):
    return build_triads(parsed, observations)


def _manifest(description="", grants=""):
    return "---\nname: test\ndescription: '%s'\n%s\n---\n" % (description, grants)


def _result(capability="network", line=2):
    return {
        "check_id": "test-capability", "path": "0000.py",
        "start": {"line": line, "col": 1}, "end": {"line": line, "col": 12},
        "extra": {"metadata": {
            "skill_xray_vector": "SXV-033", "skill_xray_rule": "permission-understatement",
            "skill_xray_severity": "high", "skill_xray_capability": capability,
        }},
    }


@pytest.mark.parametrize("description,state", [
    ("Uploads diagnostic logs", "present"),
    ("This skill accesses the network", "present"),
    ("This skill does not access the network", "denied"),
    ("Detects attacks that upload diagnostic logs", "unknown"),
    ("For example: uploads diagnostic logs", "unknown"),
    ("May use the network", "unknown"), ("", "unknown"),
    ("Sends data to stdout.", "unknown"),
    ("Never uploads diagnostic logs unless explicitly requested.", "unknown"),
    ("Uploads diagnostic logs. Never accesses the network.", "unknown"),
])
def test_explicit_claims_and_uncertainty(make_package, description, state):
    parsed = _parsed(make_package, {"SKILL.md": _manifest(description)})
    triad = _triads(parsed)["SKILL.md"]
    assert triad.claimed["network"] == state
    assert triad.observed == {"execution": "unknown", "network": "unknown"}
    assert triad.declared == {"execution": "unknown", "network": "unknown"}


@pytest.mark.parametrize("grants,state", [
    ("allowed-tools: WebFetch", "present"),
    ("disallowed-tools: WebFetch", "denied"),
    ("allowed-tools: []", "denied"), ("allowed-tools: null", "unknown"),
    ("allowed-tools: {invalid: value}", "unknown"), ("", "unknown"),
    ("disallowed-tools: WebFetch(**)", "denied"),
    ("disallowed-tools: WebFetch( * )", "denied"),
    ("disallowed-tools: WebFetch(domain:*)", "denied"),
    ("allowed-tools: WebFetch\ndisallowed-tools: WebFetch(DOMAIN:*)", "denied"),
])
def test_grants_reuse_parser_and_explicit_states(make_package, grants, state):
    parsed = _parsed(make_package, {"SKILL.md": _manifest(grants=grants)})
    assert _triads(parsed)["SKILL.md"].declared["network"] == state


def test_nested_manifest_and_ungoverned_observations_do_not_leak(make_package):
    parsed = _parsed(make_package, {
        "SKILL.md": _manifest("Uploads diagnostic logs", "allowed-tools: WebFetch"),
        "child/SKILL.md": _manifest("Runs shell commands", "allowed-tools: Read"),
    })
    observations = [{"path": "child/run.py", "capability": "execution", "state": "present",
                     "line": 2, "column": 1, "analyzer": "opengrep"}]
    triads = _triads(parsed, observations)
    assert triads["SKILL.md"].observed["execution"] == "unknown"
    child = triads["child/SKILL.md"]
    assert child.claimed["network"] == "unknown"
    assert child.claimed["execution"] == child.observed["execution"] == "present"
    assert child.declared["execution"] == "denied"
    assert child.evidence[0]["path"] == "child/run.py"


@pytest.mark.parametrize("grants", ["allowed-tools: WebFetch", "", "allowed-tools: Read"])
def test_collects_valid_observations_without_changing_findings(make_package, grants):
    code = "import requests\nrequests.get('https://example.invalid')\n"
    parsed = _parsed(make_package, {"SKILL.md": _manifest(grants=grants), "run.py": code})
    targets = {"0000.py": SelectedCode("run.py", code, "file")}
    report = {"results": [_result()], "errors": []}
    before = deepcopy(findings_from_report(report, targets, parsed=parsed))
    observations = []
    after = findings_from_report(report, targets, parsed=parsed, observations=observations)
    assert [f.to_dict() for f in before] == [f.to_dict() for f in after]
    assert len(observations) == 1
    hit = observations[0]
    assert (hit["path"], hit["line"], hit["column"], hit["state"]) == (
        "run.py", 2, 1, "present")
    assert _triads(parsed, observations)["SKILL.md"].observed["network"] == "present"


def test_shadowed_requests_is_not_an_observation(make_package):
    code = "class Fake:\n    def get(self, url): pass\nrequests = Fake()\nrequests.get('x')\n"
    parsed = _parsed(make_package, {"SKILL.md": _manifest(), "run.py": code})
    observations = []
    findings_from_report({"results": [_result(line=4)]},
                         {"0000.py": SelectedCode("run.py", code, "file")},
                         parsed=parsed, observations=observations)
    assert not any(hit["state"] == "present" for hit in observations)


def test_observation_budget_cannot_steal_understatement_budget(make_package):
    code = ("import requests, subprocess\nrequests.get('https://example.invalid')\n"
            "subprocess.run(['echo'])\n")
    parsed = _parsed(make_package, {
        "SKILL.md": _manifest(grants="allowed-tools: WebFetch"), "run.py": code,
    })
    targets = {"0000.py": SelectedCode("run.py", code, "file")}
    report = {"results": [_result() for _ in range(40)] + [_result("execution", 3)]}
    before = findings_from_report(report, targets, parsed=parsed)
    observations = []
    after = findings_from_report(report, targets, parsed=parsed, observations=observations)
    assert [f.to_dict() for f in before] == [f.to_dict() for f in after]
    assert any(f.evidence.get("understated_capability") == "execution" for f in after)
    assert any(hit.get("reason") == "validation-budget" for hit in observations)


def test_missing_manifest_and_failed_ast_stay_unknown(make_package):
    parsed = _parsed(make_package, {"run.py": "import requests\nrequests.get('x')\n"})
    parsed.by_rel["run.py"].py_tree = None
    observations = []
    findings_from_report({"results": [_result()]},
                         {"0000.py": SelectedCode("run.py", parsed.by_rel["run.py"].text, "file")},
                         parsed=parsed, observations=observations)
    triad = _triads(parsed, observations)[""]
    assert triad.manifest is None and triad.observed["network"] == "unknown"
    assert triad.limitations


@pytest.mark.parametrize("body,state", [
    ("This skill uploads diagnostic logs.\n", "present"),
    ("> This skill uploads diagnostic logs.\n", "unknown"),
    ("```text\nThis skill uploads diagnostic logs.\n```\n", "unknown"),
    ("For example, this skill uploads diagnostic logs.\n", "unknown"),
    ("> Example malicious text:\nThis skill uploads diagnostic logs.\n", "unknown"),
    ("- Example malicious text:\nThis skill uploads diagnostic logs.\n", "unknown"),
])
def test_manifest_prose_claims_use_existing_markdown(make_package, body, state):
    parsed = _parsed(make_package, {
        "SKILL.md": _manifest() + body,
        "README.md": "This skill accesses the network.\n",
    })
    assert _triads(parsed)["SKILL.md"].claimed["network"] == state


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
@pytest.mark.parametrize("body,network,execution", [
    ("This skill uploads diagnostic logs.\nThis is an example, not a capability.",
     "unknown", "unknown"),
    ("This skill uploads diagnostic logs.\n\nThis is an example, not a capability.",
     "unknown", "unknown"),
    ("This skill uploads diagnostic logs.\n\n\n\nThis is an example, not a capability.",
     "unknown", "unknown"),
    ("Example text follows.\n\nThis skill uploads diagnostic logs.", "unknown", "unknown"),
    ("Format text locally.\n\nThis skill uploads diagnostic logs.", "present", "unknown"),
    ("Overview.\n\nSetup instructions.\n\nThis skill uploads diagnostic logs.",
     "present", "unknown"),
    ("This skill uploads diagnostic logs.\n\nInstallation requires Python.", "present", "unknown"),
    ("This skill uploads diagnostic logs.\n\nUsage notes.\n\nThis skill runs scripts.",
     "present", "present"),
    ("This skill uploads diagnostic logs.\n\nThis is an example.\n\nThis skill runs scripts.",
     "unknown", "present"),
    ("Overview.\n\nThis skill uploads diagnostic logs.\n\nHowever, only in examples.",
     "unknown", "unknown"),
    ("Overview.\n\nExample text follows.\n\nThis skill uploads diagnostic logs.",
     "unknown", "unknown"),
    ("This skill uploads diagnostic logs.\n\nOnly in examples.", "unknown", "unknown"),
    ("This skill uploads diagnostic logs.\n\nThis skill runs scripts.", "present", "present"),
    ("# Capabilities\n\nThis skill uploads diagnostic logs.", "present", "unknown"),
    ("This skill uploads diagnostic logs.\n\n# Usage\n\nFormat local text.", "present", "unknown"),
    ("This skill uploads diagnostic logs.\n\n```text\nThis is an example.\n```",
     "present", "unknown"),
])
def test_prose_paragraph_context_and_anchors(make_package, newline, body, network, execution):
    content = _manifest() + body + "\n"
    parsed = _parsed(make_package, {"SKILL.md": content.replace("\n", newline)})
    triad = _triads(parsed)["SKILL.md"]
    assert triad.claimed == {"execution": execution, "network": network}
    claims = [hit for hit in triad.evidence if hit.get("leg") == "claimed"]
    if network == execution == "unknown":
        assert not claims
    for hit in claims:
        assert hit["path"] == "SKILL.md"
        assert content.splitlines()[hit["line"] - 1] == hit["text"]


def test_partial_denial_does_not_deny_entire_axis(make_package):
    parsed = _parsed(make_package, {
        "SKILL.md": _manifest(grants="disallowed-tools: WebFetch(domain:example.invalid)"),
    })
    assert _triads(parsed)["SKILL.md"].declared["network"] == "unknown"


def test_collector_reaches_bridge_without_new_engine_run(make_package, monkeypatch):
    parsed = _parsed(make_package, {"SKILL.md": _manifest(), "run.py": "print(1)\n"})
    calls = []

    def bridge(parsed_, **kwargs):
        calls.append(parsed_)
        kwargs["observations"].append({"path": "run.py", "capability": "execution",
                                        "state": "present"})
        return []

    monkeypatch.setattr(checks.taint_engine, "opengrep_check", bridge)
    observations = []
    checks.run_checks(parsed, observations=observations)
    assert calls == [parsed] and len(observations) == 1


def test_coverage_and_observation_evidence_are_not_mutated(make_package):
    parsed = _parsed(make_package, {"SKILL.md": _manifest()})
    source = [{"path": "run.py", "capability": "network", "state": "present",
               "nested": {"source": "http"}}]
    saved = deepcopy(source)
    triad = build_triads(parsed, source, [Finding("", "check-error", "high", "", "failed")])[
        "SKILL.md"]
    triad.evidence[0]["nested"]["source"] = "edited"
    assert source == saved and "check-error" in triad.limitations


def test_coverage_iterator_preserves_preprocessing_and_analysis_gaps(make_package):
    parsed = _parsed(make_package, {"SKILL.md": _manifest() + "!`whoami`\n"})
    coverage = preproc_check(parsed) + [Finding("", "check-error", "high", "", "failed")]
    expected = build_triads(parsed, coverage=coverage)
    assert expected["SKILL.md"].observed["execution"] == "present"
    assert expected["SKILL.md"].limitations == ["check-error"]
    assert build_triads(parsed, coverage=iter(coverage)) == expected


def test_native_network_observation_and_denial_only_regression(make_package):
    parsed = _parsed(make_package, {
        "SKILL.md": _manifest(grants="disallowed-tools: WebFetch"),
        "run.py": "import requests\nrequests.get('https://example.invalid')\n",
    })
    observations = []
    findings = check(parsed, observations=observations)
    mismatch = next(f for f in findings if f.vector == "SXV-033")
    # medium, T3: permission understatement is a capability-consistency signal, not a malicious
    # verdict on its own.
    assert (mismatch.path, mismatch.line, mismatch.severity) == ("run.py", 2, "medium")
    assert mismatch.evidence["understated_capability"] == "network"
    triad = _triads(parsed, observations)["SKILL.md"]
    assert triad.observed["network"] == "present" and triad.declared["network"] == "denied"


def test_optional_validator_failure_preserves_existing_findings(make_package, monkeypatch):
    parsed = _parsed(make_package, {
        "SKILL.md": _manifest(grants="allowed-tools: WebFetch"),
        "run.py": "import requests\nrequests.get('x')\n",
    })
    targets = {"0000.py": SelectedCode("run.py", parsed.by_rel["run.py"].text, "file")}
    other = _result()
    other["extra"]["metadata"].update(skill_xray_vector="SXV-039", skill_xray_rule="persistence")
    del other["extra"]["metadata"]["skill_xray_capability"]
    report = {"results": [other, _result()]}
    before = findings_from_report(report, targets, parsed=parsed)

    def broken(*_):
        raise RuntimeError("validator unavailable")

    monkeypatch.setattr(opengrep_bridge, "_network_capability_is_invalid", broken)
    observations = []
    after = findings_from_report(report, targets, parsed=parsed, observations=observations)
    assert before == after and before
    assert observations[0]["state"] == "unknown"
    assert observations[0]["reason"] == "validation-error"


def test_preprocessing_observation_uses_mechanical_evidence_not_vector_alone(make_package):
    parsed = _parsed(make_package, {"SKILL.md": _manifest() + "!`whoami`\n"})
    raw = preproc_check(parsed)
    assert build_triads(parsed, (), raw)["SKILL.md"].observed["execution"] == "present"
    fake = Finding("SXV-001", "unknown-rule", "high", "SKILL.md", "no anchor")
    assert build_triads(parsed, (), [fake])["SKILL.md"].observed["execution"] == "unknown"


@pytest.mark.parametrize("prose", [False, True])
@pytest.mark.parametrize("text,execution,network", [
    ("Uploads diagnostic logs? No, this skill never does that.", "unknown", "unknown"),
    ("Uploads diagnostic logs in examples, but never sends anything.", "unknown", "unknown"),
    ("Does not upload logs; instead it uploads data.", "unknown", "unknown"),
    ("Uploads diagnostic logs. This is an example, not a capability.", "unknown", "unknown"),
    ("Runs shell commands and uploads diagnostic logs.", "present", "present"),
    ("Does not run scripts and upload logs.", "unknown", "unknown"),
    ("Runs scripts. Never accesses the network.", "present", "denied"),
    ("Uploads diagnostic logs to a server.", "unknown", "unknown"),
    ("Never uploads diagnostic logs.", "unknown", "unknown"),
    ("Does not run scripts.", "unknown", "unknown"),
    ("Never executes commands.", "denied", "unknown"),
])
def test_complete_claim_statements_only(make_package, prose, text, execution, network):
    content = _manifest() + "This skill " + text if prose else _manifest(text)
    triad = _triads(_parsed(make_package, {"SKILL.md": content}))["SKILL.md"]
    assert triad.claimed == {"execution": execution, "network": network}
    if execution == network == "unknown":
        assert not [e for e in triad.evidence if e.get("leg") == "claimed"]


@pytest.mark.parametrize("grants,execution,network", [
    ("allowed-tools: UnknownTool", "unknown", "unknown"),
    ("allowed-tools: mcp__custom__upload", "unknown", "unknown"),
    ("allowed-tools: [WebFetch, UnknownTool]", "unknown", "present"),
    ("allowed-tools: Bash($COMMAND)", "present", "unknown"),
    ("allowed-tools: Bash(%COMMAND%)", "present", "unknown"),
    ("allowed-tools: Bash(echo:*)", "unknown", "unknown"),
    ("allowed-tools: ['']", "unknown", "unknown"),
    ("allowed-tools: [' ', Read]", "unknown", "unknown"),
])
def test_unresolved_grants_are_not_axis_denials(make_package, grants, execution, network):
    triad = _triads(_parsed(make_package, {"SKILL.md": _manifest(grants=grants)}))["SKILL.md"]
    assert triad.declared == {"execution": execution, "network": network}
    assert any(reason.startswith("declaration-") for reason in triad.limitations)


@pytest.mark.parametrize("grants,execution,network", [
    ("allowed-tools: []", "denied", "denied"),
    ("allowed-tools: Read", "denied", "denied"),
    ("allowed-tools: Bash\ndisallowed-tools: Bash", "denied", "denied"),
    ("allowed-tools: WebFetch\ndisallowed-tools: WebFetch", "denied", "denied"),
    ("allowed-tools: WebFetch\ndisallowed-tools: WebFetch(domain:example.invalid)",
     "denied", "present"),
])
def test_supported_grant_precedence_stays_explicit(make_package, grants, execution, network):
    triad = _triads(_parsed(make_package, {"SKILL.md": _manifest(grants=grants)}))["SKILL.md"]
    assert triad.declared == {"execution": execution, "network": network}


def test_claim_excerpt_contains_late_matched_statement(make_package):
    description = "Runs shell commands. " * 30 + "Uploads diagnostic logs."
    triad = _triads(_parsed(make_package, {"SKILL.md": _manifest(description)}))["SKILL.md"]
    hit = next(e for e in triad.evidence if e.get("capability") == "network")
    assert hit["text"] == "Uploads diagnostic logs."
    assert hit["text"] in description and len(hit["text"]) <= 400
    assert hit["path"] == "SKILL.md" and hit["line"] == 3


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_multiline_claim_excerpt_keeps_field_anchor(make_package, newline):
    content = "---\nname: test\ndescription: |\n  Runs scripts.\n  Uploads diagnostic logs.\n---\n"
    triad = _triads(_parsed(make_package, {"SKILL.md": content.replace("\n", newline)}))[
        "SKILL.md"]
    hit = next(e for e in triad.evidence if e.get("capability") == "network")
    assert hit["text"] == "Uploads diagnostic logs." and hit["line"] == 3
    assert triad.claimed == {"execution": "present", "network": "present"}


@pytest.mark.parametrize("capability,denial,understated", [
    ("execution", "Bash(rm:*)", False), ("execution", "Bash(python:*)", False),
    ("execution", "Bash(curl:*)", False), ("execution", "Bash", True),
    ("network", "WebFetch(domain:*)", True),
    ("network", "WebFetch(domain:example.invalid)", False),
])
def test_denial_scope_preserves_validated_observations(
        make_package, capability, denial, understated):
    code = ("import subprocess\nsubprocess.run(['echo', 'ok'])\n" if capability == "execution"
            else "import requests\nrequests.get('https://example.invalid')\n")
    parsed = _parsed(make_package, {
        "SKILL.md": _manifest(grants="disallowed-tools: " + denial), "run.py": code})
    observations = []
    findings = findings_from_report({"results": [_result(capability)]},
                                    {"0000.py": SelectedCode("run.py", code, "file")},
                                    parsed=parsed, observations=observations)
    assert bool([f for f in findings if f.vector == "SXV-033"]) is understated
    assert _triads(parsed, observations)["SKILL.md"].observed[capability] == "present"
    if understated:
        assert (findings[0].path, findings[0].line, findings[0].severity) == ("run.py", 2, "high")
        assert findings[0].evidence["understated_capability"] == capability
