"""Correlation preserves emitted candidates; fixtures are data, never executed."""

from copy import deepcopy

import pytest

from skill_xray import ingest, parse
from skill_xray.correlate import correlate
from skill_xray.findings import Finding

SOURCE = "import os, sys\nos.system(sys.argv[1])\n"


def package(make_package, source=SOURCE, manifest="---\nname: test\n---\n", name="pkg"):
    return parse.parse_package(ingest.build_package(make_package({
        "SKILL.md": manifest, "run.py": source,
    }, name=name)))


def candidate(cid="c0", analyzer="opengrep", **changes):
    fields = dict(vector="SXV-008", rule="command-injection", severity="critical",
                  path="run.py", line=2, column=1, message="Input reaches a shell",
                  evidence={"engine": analyzer, "command": "os.system(sys.argv[1])"})
    finding = Finding(**(fields | changes))
    return {"candidate_id": cid, "finding": finding.to_dict(), "analyzer": analyzer,
            "provenance": "deterministic-check-output", "coverage": "no-reported-gap"}


def loc(line, text, path="run.py"):
    return ["CliLoc", [{"path": path, "start": {"line": line, "col": 1},
                        "end": {"line": line, "col": len(text) + 1}}, text]]


def test_duplicates_preserve_candidates_evidence_and_provenance(make_package):
    parsed = package(make_package)
    raw = [candidate("a"), candidate("b"), candidate("c", analyzer="other-engine")]
    original = deepcopy(raw)
    report = correlate(parsed, raw)
    assert raw == original and report["raw_candidates"] == original
    assert len(report["results"]) == 1 and len(report["links"]) == 3
    result = report["results"][0]
    assert result["rule_id"] == "skill-xray/command-injection"
    assert result["id"] != "SXV-008" and len(result["fingerprint"]) == 64
    assert result["candidate_ids"] == ["a", "b", "c"]
    assert {p["analyzer"] for p in result["provenance"]} == {"opengrep", "other-engine"}
    assert len(result["evidence"]) == 2
    assert {link["result_id"] for link in report["links"]} == {result["id"]}
    assert [link["disposition"] for link in report["links"]] == [
        "reported", "duplicate", "duplicate"]
    assert all(link["reason"] for link in report["links"])
    report["raw_candidates"][0]["finding"]["evidence"].clear()
    assert raw == original


@pytest.mark.parametrize("changes", [
    {"evidence": {"command": "curl https://attacker.invalid"}},
    {"evidence": {"source": "~/.ssh/id_rsa"}},
    {"evidence": {"sink": "/etc/cron.d/start"}},
    {"evidence": {"endpoint": "https://attacker.invalid"}},
    {"line": 1}, {"column": 2}, {"offset": 1}, {"length": 2},
    {"severity": "high"}, {"vector": "SXV-019"}, {"rule": "other-rule"},
])
def test_distinct_security_evidence_or_occurrences_do_not_merge(make_package, changes):
    report = correlate(package(make_package), [candidate("a"), candidate("b", **changes)])
    assert len(report["results"]) == 2
    assert len({result["id"] for result in report["results"]}) == 2
    assert len(report["links"]) == 2


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_blank_lines_and_install_path_do_not_change_identity(make_package, newline):
    old = correlate(package(make_package, name="one"), [candidate()])["results"][0]
    source = ("\n\n" + SOURCE).replace("\n", newline)
    new = correlate(package(make_package, source, name="two"),
                    [candidate(line=4)])["results"][0]
    assert (old["id"], old["fingerprint"]) == (new["id"], new["fingerprint"])
    assert old["context_digest"] != new["context_digest"]


@pytest.mark.parametrize("change", [
    "https://approved.invalid", "https://attacker.invalid", "~/.ssh/id_rsa",
    "~/.aws/credentials", "/etc/cron.d/evil", "C:/Users/me/Startup/run.cmd",
])
def test_changed_security_context_invalidates_decision_identity(make_package, change):
    original = correlate(package(make_package), [candidate()])["results"][0]
    changed = correlate(package(make_package, SOURCE + "destination = %r\n" % change),
                        [candidate()])["results"][0]
    assert original["fingerprint"] == changed["fingerprint"]
    assert original["context_digest"] != changed["context_digest"]


def test_repeated_identical_calls_remain_distinct_after_line_shift(make_package):
    raw = [candidate("a"), candidate("b", line=3)]
    source = SOURCE + SOURCE.splitlines()[1] + "\n"
    old = correlate(package(make_package, source), raw)["results"]
    moved = [candidate("a", line=4), candidate("b", line=5)]
    new = correlate(package(make_package, "\n\n" + source), moved)["results"]
    assert len({r["fingerprint"] for r in old}) == 2
    assert [r["id"] for r in old] == [r["id"] for r in new]


def test_permuted_candidates_do_not_change_correlation(make_package):
    parsed = package(make_package)
    raw = [candidate("c"), candidate("b", line=1), candidate("a")]
    first, second = correlate(parsed, raw), correlate(parsed, list(reversed(raw)))
    assert first["results"] == second["results"]
    assert first["links"] == second["links"]


def test_engine_fingerprints_are_not_finding_identity(make_package):
    parsed = package(make_package)
    raw = candidate()
    raw["finding"]["evidence"]["fingerprint"] = "/tmp/engine-one/random"
    first = correlate(parsed, [raw])
    raw["finding"]["evidence"]["fingerprint"] = "/tmp/engine-two/random"
    second = correlate(parsed, [raw])
    assert first["results"] == second["results"]
    assert first["raw_candidates"] != second["raw_candidates"]


def test_equivalent_analyzer_wording_merges_without_losing_messages(make_package):
    parsed = package(make_package)
    raw = [candidate("a"), candidate("b", analyzer="other-engine",
                                    message="An untrusted argument reaches command execution")]
    report = correlate(parsed, raw)
    result, = report["results"]
    assert result["candidate_ids"] == ["a", "b"]
    assert report["raw_candidates"] == raw
    assert len({item["finding"]["message"] for item in report["raw_candidates"]}) == 2
    assert {item["analyzer"] for item in result["provenance"]} == {"opengrep", "other-engine"}
    assert result["fingerprint"] == correlate(parsed, raw[:1])["results"][0]["fingerprint"]
    reversed_report = correlate(parsed, list(reversed(raw)))
    assert report["results"] == reversed_report["results"]
    assert report["links"] == reversed_report["links"]


@pytest.mark.parametrize("changes", [
    {"vector": "", "rule": "check-error"}, {"evidence": {}},
    {"path": "absent.py"}, {"line": None},
])
def test_uncertain_or_diagnostic_messages_remain_separate(make_package, changes):
    raw = [candidate("a", message="First distinct detail", **changes),
           candidate("b", message="Second distinct detail", **changes)]
    report = correlate(package(make_package), raw)
    assert len(report["results"]) == 2
    assert report["raw_candidates"] == raw


def test_real_trace_is_preserved_without_stitching_findings(make_package):
    source = "source = input()\nos.system(source)\n"
    trace = {"taint_source": loc(1, "source = input()"),
             "intermediate_vars": [], "taint_sink": loc(2, "os.system(source)")}
    raw = candidate(evidence={"engine": "opengrep", "dataflow_trace": trace})
    result = correlate(package(make_package, source), [raw])["results"][0]
    assert result["evidence"][0]["dataflow_trace"] == trace
    assert [step["role"] for step in result["code_flow"]] == ["source", "sink"]
    assert [step["path"] for step in result["code_flow"]] == ["run.py", "run.py"]
    assert not result["limitations"]
    unrelated = correlate(package(make_package), [candidate("read", vector="SXV-023"),
                                                   candidate("network", vector="SXV-024")])
    assert len(unrelated["results"]) == 2
    assert all(not result["code_flow"] for result in unrelated["results"])


@pytest.mark.parametrize("trace", [None, "bad", [], {"taint_source": ["source"]},
    {"taint_source": loc(1, "source", "../outside.py"), "taint_sink": loc(2, "sink")},
    {"taint_source": loc(True, "source"), "taint_sink": loc(2, "sink")},
    {"taint_source": loc(1, "source"), "taint_sink": loc(999, "sink")},
    {"taint_source": loc(1, "source"), "taint_sink": loc(2, "sink"),
     "intermediate_vars": "unsupported"},
])
def test_malformed_or_unsupported_trace_retains_evidence_without_flow(make_package, trace):
    raw = candidate(evidence={"engine": "opengrep", "dataflow_trace": trace})
    report = correlate(package(make_package), [raw])
    result, = report["results"]
    assert not result["code_flow"] and "trace-unvalidated" in result["limitations"]
    assert report["raw_candidates"][0] == raw
    assert result["evidence"][0]["dataflow_trace"] == trace


def test_governing_manifest_changes_context_but_not_evidence_identity(make_package):
    old = correlate(package(make_package), [candidate()])["results"][0]
    new = correlate(package(make_package, manifest="---\nname: test\nallowed-tools: Bash\n---\n"),
                    [candidate()])["results"][0]
    assert old["manifest"] == new["manifest"] == "SKILL.md"
    assert old["fingerprint"] == new["fingerprint"]
    assert old["context_digest"] != new["context_digest"]


def test_missing_source_and_coverage_records_are_retained(make_package):
    raw = [candidate(path="absent.py"),
           candidate("gap", vector="", rule="check-error", path="", line=None, evidence={})]
    result = correlate(package(make_package), raw)
    assert len(result["results"]) == len(result["links"]) == 2
    assert any("source-unavailable" in item["limitations"] for item in result["results"])
    assert any(not item["finding"]["vector"] for item in result["results"])


def test_duplicate_candidate_ids_fail_visibly(make_package):
    with pytest.raises(ValueError, match="candidate"):
        correlate(package(make_package), [candidate(), candidate()])


@pytest.mark.parametrize("end", [None, [], "unknown", {"line": True}, {"line": 999}])
def test_malformed_evidence_position_retains_candidate(make_package, end):
    raw = candidate(evidence={"end": end})
    result = correlate(package(make_package), [raw])
    assert result["raw_candidates"] == [raw]
    assert result["results"][0]["candidate_ids"] == ["c0"]


def test_binary_evidence_identity_and_byte_occurrences(make_package):
    def scan(data, offset):
        parsed = parse.parse_package(ingest.build_package(make_package({"payload.bin": data})))
        raw = candidate(path="payload.bin", vector="SXV-037", rule="trailing-bytes",
                        line=None, column=None, offset=offset, length=4, evidence={})
        return correlate(parsed, [raw])["results"][0]
    first = scan(b"headEVIL", 4)
    assert first["fingerprint"] == scan(b"paddingheadEVIL", 11)["fingerprint"]
    assert first["context_digest"] != scan(b"headSAFE", 4)["context_digest"]
