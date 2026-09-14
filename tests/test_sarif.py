"""SARIF is a serializer of audited results, not a second decision engine."""

import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from test_correlate import candidate, loc, package
from test_disposition import policy_for

from skill_xray import ingest, parse
from skill_xray.capability import build_triads
from skill_xray.correlate import correlate
from skill_xray.disposition import apply_dispositions
from skill_xray.findings import Finding
from skill_xray.sarif import build_sarif, encode_sarif, validate_sarif, write_sarif
from skill_xray.scan import ScanReport


def test_writer_rejects_filesystem_alias_before_encoding(tmp_path, monkeypatch):
    root, alias = tmp_path / "Package", tmp_path / "package"
    root.mkdir()
    alias.mkdir(exist_ok=True)
    samefile = Path.samefile
    monkeypatch.setattr(Path, "samefile", lambda path, other:
                        True if path == alias and other == root else samefile(path, other))
    target = alias / "report.sarif"
    with pytest.raises(ValueError, match="outside the scanned package"):
        write_sarif({}, target, source_root=root)
    assert not target.exists()


def report_for(parsed, raw, policy=None, errors=()):
    triads = build_triads(parsed)
    correlation = apply_dispositions(parsed, correlate(parsed, raw), triads,
                                     policy=policy, context_errors=errors)
    return ScanReport([], raw, triads, [], {}, list(errors), correlation=correlation)


def test_native_fields_preserve_classification_identity_and_audit(make_package):
    parsed = package(make_package)
    raw = [candidate("a"), candidate("b")]
    report = report_for(parsed, raw)
    document = build_sarif(parsed, report)
    validate_sarif(document)
    run, = document["runs"]
    result, = run["results"]
    rule, = run["tool"]["driver"]["rules"]
    assert document["version"] == "2.1.0"
    assert result["ruleId"] == rule["id"] == "skill-xray/command-injection"
    assert result["ruleIndex"] == 0 and result["level"] == "error"
    properties = result["properties"]
    assert properties["id"].startswith("finding-") and properties["sxv"] == "SXV-008"
    assert properties["title"] and properties["originalSeverity"] == "critical"
    assert properties["effectiveSeverity"] == "critical" and properties["evidence"]
    assert properties["cwe"] == ["CWE-78", "CWE-77"] and properties["tier"] == "T1"
    assert properties["disposition"] == "reported" and properties["reason"]
    assert properties["candidateIds"] and properties["provenance"]
    assert result["partialFingerprints"]
    assert len(run["properties"]["rawCandidates"]) == len(run["properties"]["candidateLinks"]) == 2
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["properties"]["opengrepVersion"] and run["properties"]["rulesetDigest"]
    assert "codeFlows" not in result


def test_suppression_and_demotion_are_serialized_not_redecided(make_package):
    parsed = package(make_package)
    raw = [candidate()]
    result = correlate(parsed, raw)["results"][0]
    for action in ("suppress", "demote"):
        report = report_for(parsed, raw, policy_for(result, action))
        document = build_sarif(parsed, report)
        output, = document["runs"][0]["results"]
        assert output["properties"]["originalSeverity"] == "critical"
        if action == "suppress":
            suppression, = output["suppressions"]
            assert suppression == {"kind": "external", "status": "accepted",
                                    "justification": output["properties"]["reason"]}
        else:
            assert output["level"] == "warning" and "suppressions" not in output
            assert output["properties"]["disposition"] == "corrected"
        validate_sarif(document)


@pytest.mark.parametrize("severity,level", [("critical", "error"), ("high", "error"),
                                            ("medium", "warning"), ("low", "note")])
def test_severity_mapping(make_package, severity, level):
    parsed = package(make_package)
    report = report_for(parsed, [candidate(severity=severity)])
    result, = build_sarif(parsed, report)["runs"][0]["results"]
    assert result["level"] == level and result["properties"]["effectiveSeverity"] == severity


@pytest.mark.parametrize("path,uri", [("dir/run.py", "dir/run.py"),
    ("dir/a b#é.py", "dir/a%20b%23%C3%A9.py"), ("dir/a%20.py", "dir/a%2520.py"),
    (r"dir/a\b.py", "dir/a%5Cb.py"), (r"C:\run.py", "C%3A%5Crun.py"), ("C:run.py", "C%3Arun.py"),
    pytest.param("raw-\udcff/SKILL.md", "raw-%FF/SKILL.md",
                 marks=pytest.mark.skipif(sys.platform != "linux", reason="Linux byte filename"))])
def test_relative_paths_are_uri_encoded(make_package, path, uri):
    if sys.platform == "win32" and ("\\" in path or ":" in path):
        pytest.skip("POSIX filename")
    parsed = parse.parse_package(ingest.build_package(make_package({path: "pass\n"})))
    report = report_for(parsed, [candidate(path=path, line=1)])
    result, = build_sarif(parsed, report)["runs"][0]["results"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == uri


@pytest.mark.parametrize("path", ["../outside.py", "/tmp/file.py", "C:/temp/file.py",
                                "\\\\host\\file"])
def test_unsafe_paths_are_not_emitted_as_source_uris(make_package, path):
    parsed = package(make_package)
    output = build_sarif(parsed, report_for(parsed, [candidate(path=path)]))
    result, = output["runs"][0]["results"]
    assert "locations" not in result
    assert "location-unvalidated" in result["properties"]["limitations"]
    assert result["properties"]["reportedLocation"]["path"] == path


def test_unicode_columns_crlf_and_byte_regions(make_package):
    parsed = package(make_package, "é = 1\r\nos.system('x')\r\n")
    raw = [candidate("text", line=1, column=4, evidence={"engine": "opengrep"}),
           candidate("bytes", line=None, column=None, offset=2, length=3),
           candidate("incomplete", line=1, evidence={"end": {"line": 2}})]
    output = build_sarif(parsed, report_for(parsed, raw))
    assert output["runs"][0]["columnKind"] == "unicodeCodePoints"
    regions = [r["locations"][0]["physicalLocation"].get("region")
               for r in output["runs"][0]["results"]]
    assert None in regions
    assert {"startLine": 1, "startColumn": 3} in regions
    assert {"byteOffset": 2, "byteLength": 3} in regions


def test_supported_code_flow_only_and_order_preserved(make_package):
    class CountedText(str):
        splits = 0
        def split(self, *args, **kwargs):
            self.splits += 1
            return super().split(*args, **kwargs)
    parsed = package(make_package, "source = input()\nos.system(source)\n")
    trace = {"taint_source": loc(1, "source = input()"), "taint_sink": loc(2, "os.system(source)")}
    report = report_for(parsed, [candidate(evidence={"dataflow_trace": trace})])
    parsed.by_rel["run.py"].text = text = CountedText(parsed.by_rel["run.py"].text)
    output = build_sarif(parsed, report)
    assert text.splits == 1
    steps = output["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [step["kinds"] for step in steps] == [["source"], ["sink"]]
    assert [step["executionOrder"] for step in steps] == [0, 1]
    validate_sarif(output)


def test_canonical_output_removes_volatile_engine_ids_and_scan_local_order(make_package):
    parsed = package(make_package)
    first = candidate("a")
    first["finding"]["evidence"]["fingerprint"] = "/tmp/random-one"
    second = candidate("b", analyzer="ir-check")
    old = build_sarif(parsed, report_for(parsed, [first, second]))
    first["candidate_id"] = "new-b"
    second["candidate_id"] = "new-a"
    first["finding"]["evidence"]["fingerprint"] = "/tmp/random-two"
    new = build_sarif(parsed, report_for(parsed, [second, first]))
    assert encode_sarif(old) == encode_sarif(new)
    assert b"/tmp/random" not in encode_sarif(new)


@pytest.mark.parametrize("severity,success", [("low", True), ("high", False)])
def test_coverage_and_check_failure_are_not_clean_or_suppressible(make_package, severity, success):
    parsed = package(make_package)
    raw = [candidate(vector="", rule="analysis-incomplete", severity=severity)]
    output = build_sarif(parsed, report_for(parsed, raw))
    run, = output["runs"]
    assert run["invocations"][0]["executionSuccessful"] is success
    assert run["properties"]["coverage"] == "incomplete"
    assert run["results"][0]["properties"]["disposition"] == "reported"
    assert "suppressions" not in run["results"][0]


@pytest.mark.parametrize("mutation", ["schema", "rule", "candidate", "link", "severity",
    "suppression", "empty-evidence", "forged-evidence", "rule-binding", "duplicates", "primaries",
    "fingerprint"])
def test_schema_and_cross_reference_validation_fail_visibly(make_package, mutation):
    parsed = package(make_package)
    output = build_sarif(parsed, report_for(parsed, [candidate(), candidate("duplicate")]))
    run = output["runs"][0]
    result = run["results"][0]
    if mutation == "schema":
        result["notASarifField"] = True
    elif mutation == "rule":
        result["ruleIndex"] = 999
    elif mutation == "candidate":
        run["properties"]["rawCandidates"].clear()
    elif mutation == "link":
        run["properties"]["candidateLinks"][0]["result_id"] = "absent"
    elif mutation == "severity":
        result["properties"]["originalSeverity"] = "low"
    elif mutation.endswith("evidence"):
        result["properties"]["evidence"] = [] if mutation == "empty-evidence" else [{"fake": True}]
    elif mutation == "rule-binding":
        run["tool"]["driver"]["rules"][0]["id"] = result["ruleId"] = "skill-xray/other"
    elif mutation == "fingerprint":
        result["partialFingerprints"] = dict.fromkeys(result["partialFingerprints"], "0" * 64)
    elif mutation in {"duplicates", "primaries"}:
        for link in run["properties"]["candidateLinks"]:
            link["disposition"] = "duplicate" if mutation == "duplicates" else "reported"
    else:
        result["properties"]["disposition"] = "suppressed"
    with pytest.raises(ValueError):
        validate_sarif(output)


def test_result_without_its_own_candidate_links_is_rejected(make_package):
    parsed = package(make_package)
    output = build_sarif(parsed, report_for(parsed, [candidate()]))
    orphan = deepcopy(output["runs"][0]["results"][0])
    orphan["properties"]["id"] = "fabricated-finding"
    output["runs"][0]["results"].append(orphan)
    with pytest.raises(ValueError):
        validate_sarif(output)


def test_unknown_disposition_is_not_a_valid_final_report(make_package):
    parsed = package(make_package)
    output = build_sarif(parsed, report_for(parsed, [candidate()]))
    output["runs"][0]["results"][0]["properties"]["disposition"] = "disappeared"
    output["runs"][0]["properties"]["candidateLinks"][0]["disposition"] = "disappeared"
    with pytest.raises(ValueError):
        validate_sarif(output)


@pytest.mark.parametrize("gap", ["manifest", "trace", "location"])
def test_run_completeness_uses_final_result_context(make_package, gap):
    parsed = package(make_package)
    item = candidate()
    if gap == "manifest":
        parsed.artifacts = [a for a in parsed.artifacts if a.rel != "SKILL.md"]
        parsed.by_rel.pop("SKILL.md")
    elif gap == "trace":
        item["finding"]["evidence"]["dataflow_trace"] = "unsupported"
    else:
        item["finding"]["line"] = 999
    report = report_for(parsed, [item])
    assert report.correlation["results"][0]["coverage"] == "incomplete"
    run = build_sarif(parsed, report)["runs"][0]
    assert run["properties"]["coverage"] == "incomplete"
    assert run["invocations"][0]["executionSuccessful"]


def test_zero_findings_do_not_erase_capability_context_limitations(make_package):
    parsed = package(make_package, manifest="---\nname: test\nallowed-tools: FutureTool\n---\n")
    report = report_for(parsed, [])
    run = build_sarif(parsed, report)["runs"][0]
    assert run["results"] == []
    assert run["properties"]["coverage"] == "incomplete"
    assert run["properties"]["contextLimitations"] == [
        {"manifest": "SKILL.md", "limitations": ["declaration-capability-unknown"]}]
    assert run["invocations"][0]["executionSuccessful"]


def test_observation_order_does_not_change_canonical_sarif(make_package, monkeypatch):
    scanmod = sys.modules["skill_xray.scan"]
    parsed = package(make_package)
    observations = [{"path": "run.py", "line": line, "capability": "execution",
                     "state": "present", "analyzer": "opengrep"} for line in (1, 2)]
    outputs = []
    for values in (observations, list(reversed(observations))):
        finding = Finding("SXV-008", "command-injection", "high", "run.py", "test", line=2)
        def checks(_parsed, _executable, observations=None, values=values, finding=finding):
            observations.extend(values)
            return [finding]
        monkeypatch.setattr(scanmod, "_collect", checks)
        outputs.append(encode_sarif(build_sarif(parsed, scanmod.scan_report(parsed))))
    assert outputs[0] == outputs[1]


def test_atomic_write_validates_before_replacement(make_package, tmp_path, monkeypatch):
    parsed = package(make_package)
    document = build_sarif(parsed, report_for(parsed, [candidate()]))
    target = tmp_path / "report.sarif"
    target.write_text("previous report")
    invalid = deepcopy(document)
    invalid["version"] = "wrong"
    with pytest.raises(ValueError):
        write_sarif(invalid, target, source_root=Path(parsed.identity))
    assert target.read_text() == "previous report"
    import skill_xray.sarif as sarif
    def fail(*_):
        raise OSError("disk unavailable")
    monkeypatch.setattr(sarif.os, "replace", fail)
    with pytest.raises(OSError):
        write_sarif(document, target, source_root=Path(parsed.identity))
    assert target.read_text() == "previous report"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["pkg", "report.sarif"]


def test_write_rejects_source_overlap_and_is_repeatable(make_package, tmp_path):
    parsed = package(make_package)
    document = build_sarif(parsed, report_for(parsed, [candidate()]))
    root = Path(parsed.identity)
    for target in (root / "SKILL.md", root / "generated.sarif"):
        with pytest.raises(ValueError):
            write_sarif(document, target, source_root=root)
    target = tmp_path / "report.sarif"
    write_sarif(document, target, source_root=root)
    first = target.read_bytes()
    write_sarif(document, target, source_root=root)
    assert first == target.read_bytes() == encode_sarif(document)
    assert json.loads(first)["version"] == "2.1.0"
