"""Generated fence coordinates must map to captured original Markdown source."""

import sys
from copy import deepcopy
from dataclasses import replace

import pytest

from skill_xray import ingest, opengrep_bridge, parse
from skill_xray.capability import build_triads
from skill_xray.correlate import correlate, source_region
from skill_xray.disposition import POLICY_VERSION, apply_dispositions
from skill_xray.findings import FINDING_CAP, cap_findings, dedupe_findings
from skill_xray.opengrep_bridge import findings_from_report, select_executable_code
from skill_xray.sarif import build_sarif, encode_sarif, validate_sarif
from skill_xray.scan import ScanReport


def _fixture(make_package, prefix="   ", command='open("~/.ssh/id_rsa")'):
    if prefix == "list":
        body = '- Read the file:\n\n  ```python\n  ' + command + '\n  ```\n'
    else:
        body = prefix + '```python\n' + prefix + command + '\n' + prefix + '```\n'
    root = make_package({"SKILL.md": '---\nname: test\nallowed-tools: Read\n---\n' + body})
    parsed = parse.parse_package(ingest.build_package(root))
    target, = select_executable_code(parsed)
    line = next(i for i, value in enumerate(target.text.split("\n"), 1) if command in value)
    return parsed, target, line


def _native(line, command, start_col=1):
    return {
        "path": "0000.py", "check_id": "skill-xray.python-credential-read",
        "start": {"line": line, "col": start_col, "offset": 0},
        "end": {"line": line, "col": len(command.encode("utf-8")) + 1, "offset": 20},
        "extra": {"message": "Python code reads a private credential file.",
                  "metadata": {"skill_xray_vector": "SXV-023",
                               "skill_xray_rule": "opengrep-credential-read",
                               "skill_xray_severity": "high"}},
    }


def _document(parsed, finding, *, suppress=False):
    raw = [{"candidate_id": "a", "finding": finding.to_dict(), "analyzer": "opengrep",
            "provenance": "deterministic-check-output", "coverage": "no-reported-gap"}]
    correlation = correlate(parsed, raw)
    policy = None
    if suppress:
        result = correlation["results"][0]
        policy = {"version": POLICY_VERSION, "decisions": [{
            **{key: result[key] for key in ("rule_id", "fingerprint", "context_digest")},
            "path": finding.path, "action": "suppress", "reason": "Reviewed fixture",
        }]}
    triads = build_triads(parsed)
    correlation = apply_dispositions(parsed, correlation, triads, policy=policy)
    report = ScanReport([], raw, triads, [], {}, [], correlation=correlation)
    document = build_sarif(parsed, report)
    validate_sarif(document)
    return document["runs"][0]["results"][0]


@pytest.mark.parametrize("prefix", ["", "   ", "> ", "list"])
@pytest.mark.parametrize("leading", ["", 'label = "é😀"; '])
def test_primary_fence_region_selects_original_source(make_package, prefix, leading):
    call = 'open("~/.ssh/id_rsa")'
    command = leading + call
    parsed, target, line = _fixture(make_package, prefix, command)
    native = _native(line, command, len(leading.encode("utf-8")) + 1)
    original = deepcopy(native)
    finding, = findings_from_report({"results": [native]}, {"0000.py": target}, parsed=parsed)
    result = _document(parsed, finding)
    region = result["locations"][0]["physicalLocation"]["region"]
    source = parsed.by_rel["SKILL.md"].text.split("\n")[line - 1]
    assert source[region["startColumn"] - 1:region["endColumn"] - 1] == call
    assert "location-unvalidated" not in result["properties"]["limitations"]
    assert native == original


@pytest.mark.parametrize("prefix", ["   ", "> ", "list"])
def test_trace_positions_map_to_original_source_and_keep_engine_evidence(make_package, prefix):
    command = 'value = "é😀"; open("~/.ssh/id_rsa")'
    parsed, target, line = _fixture(make_package, prefix, command)
    native = _native(line, command)
    location = {"path": "0000.py", "start": dict(native["start"]), "end": dict(native["end"])}
    trace = {"taint_source": ["CliLoc", [location, command]],
             "intermediate_vars": [{"location": location, "content": command}],
             "taint_sink": ["CliLoc", [location, command]]}
    native["extra"]["dataflow_trace"] = trace
    finding, = findings_from_report({"results": [native]}, {"0000.py": target}, parsed=parsed)
    result = _document(parsed, finding)
    steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
    source = parsed.by_rel["SKILL.md"].text.split("\n")[line - 1]
    for step in steps:
        region = step["location"]["physicalLocation"]["region"]
        assert source[region["startColumn"] - 1:region["endColumn"] - 1] == command
    assert finding.evidence["engine_dataflow_trace"]["taint_source"][1][0]["start"]["col"] == 1
    assert finding.evidence["dataflow_trace"]["taint_source"][1][0]["start"]["col"] > 1


@pytest.mark.parametrize("damage", ["tab", "different-source", "multiline"])
def test_unprovable_fence_mapping_retains_finding_with_explicit_limitations(make_package, damage):
    command = 'open("~/.ssh/id_rsa")'
    parsed, target, line = _fixture(make_package, command=command)
    native = _native(line, command)
    artifact = parsed.by_rel["SKILL.md"]
    if damage == "tab":
        artifact.text = artifact.text.replace("   " + command, "\t" + command)
    elif damage == "different-source":
        artifact.text = artifact.text.replace(command, "pass # " + "x" * len(command))
    else:
        native["end"] = {"line": line + 1, "col": 1}
    location = {"path": "0000.py", "start": dict(native["start"]), "end": dict(native["end"])}
    trace = {"taint_source": ["CliLoc", [location, command]],
             "taint_sink": ["CliLoc", [location, command]]}
    native["extra"]["dataflow_trace"] = trace
    finding, = findings_from_report({"results": [native]}, {"0000.py": target}, parsed=parsed)
    assert finding.vector == "SXV-023"
    assert finding.evidence["location_mapping"] == "unvalidated"
    assert finding.evidence["trace_mapping"] == "unvalidated"
    assert finding.evidence["dataflow_trace"]["taint_source"][1][0]["start"] == native["start"]
    result = _document(parsed, finding, suppress=True)
    assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": line}
    assert {"location-unvalidated", "trace-unvalidated"} <= set(result["properties"]["limitations"])
    assert result["properties"]["coverage"] == "incomplete"
    assert result["properties"]["disposition"] == "reported"
    assert "codeFlows" not in result


def test_file_coordinates_are_unchanged(make_package):
    source = 'label = "é😀"; open("~/.ssh/id_rsa")'
    root = make_package({"run.py": source})
    parsed = parse.parse_package(ingest.build_package(root))
    target, = select_executable_code(parsed)
    native = _native(1, source, len('label = "é😀"; '.encode("utf-8")) + 1)
    finding, = findings_from_report({"results": [native]}, {"0000.py": target}, parsed=parsed)
    assert finding.column == native["start"]["col"]
    assert finding.evidence["start"] == native["start"]
    assert "engine_location" not in finding.evidence
    content, _, _ = source_region(
        parsed.by_rel["run.py"], finding.evidence["start"], finding.evidence["end"])
    assert content == 'open("~/.ssh/id_rsa")'


def test_postfilters_receive_generated_columns_before_reporting_map(make_package, monkeypatch):
    command = 'os.system(input())'
    parsed, target, line = _fixture(make_package, command=command)
    native = _native(line, command)
    native["extra"]["metadata"]["skill_xray_vector"] = "SXV-008"
    checked = []

    def shell_status(tree, line, col):
        checked.append(("shell", line, col))
        return True, False

    def postfilter(extra, name, selected, vector, line, col, trees):
        checked.append(("taint", line, col))
        return False

    monkeypatch.setattr(opengrep_bridge, "_subprocess_shell_status", shell_status)
    monkeypatch.setattr(opengrep_bridge, "_python_definite_false_positive", postfilter)
    finding, = findings_from_report({"results": [native]}, {"0000.py": target}, parsed=parsed)
    assert checked == [("shell", line, 1), ("taint", line, 1)]
    assert finding.column == 4
    assert finding.severity == "high" and finding.vector == "SXV-008"


@pytest.mark.parametrize("prefix,validated", [("", True), ("   ", False)])
def test_multiline_fence_span_requires_exact_original_substring(make_package, prefix, validated):
    lines = ['open(', '    "~/.ssh/id_rsa")']
    body = (prefix + '```python\n' + ''.join(prefix + line + '\n' for line in lines)
            + prefix + '```\n')
    root = make_package({"SKILL.md": '---\nname: test\n---\n' + body})
    parsed = parse.parse_package(ingest.build_package(root))
    target, = select_executable_code(parsed)
    native = _native(5, lines[0])
    native["end"] = {"line": 6, "col": len(lines[1]) + 1}
    finding, = findings_from_report({"results": [native]}, {"0000.py": target}, parsed=parsed)
    assert finding.evidence["location_mapping"] == ("validated" if validated else "unvalidated")
    if validated:
        content, _, _ = source_region(
            parsed.by_rel["SKILL.md"], finding.evidence["start"], finding.evidence["end"])
        assert content == '\n'.join(lines)


def test_fence_sources_split_once_per_target_and_reporting_call(make_package):
    class CountedText(str):
        def __new__(cls, text):
            value = super().__new__(cls, text)
            value.splits = 0
            return value

        def split(self, sep=None, maxsplit=-1):
            if sep == "\n":
                self.splits += 1
            return super().split(sep, maxsplit)

    command = 'open("~/.ssh/id_rsa")'
    files = {}
    for path, prefix in (("SKILL.md", "   "), ("nested/SKILL.md", "> ")):
        files[path] = ('---\nname: test\n---\n' + prefix + '```python\n'
                       + prefix + command + '\n' + prefix + '```\n')
    parsed = parse.parse_package(ingest.build_package(make_package(files)))
    targets, results, captured = {}, [], []
    for index, selected in enumerate(select_executable_code(parsed)):
        name = "%04d.py" % index
        target = replace(selected, text=CountedText(selected.text))
        artifact = parsed.by_rel[target.rel]
        artifact.text = CountedText(artifact.text)
        captured.extend((target.text, artifact.text))
        targets[name] = target
        native = _native(5, command)
        native["path"] = name
        location = {"path": name, "start": native["start"], "end": native["end"]}
        native["extra"]["dataflow_trace"] = {
            "taint_source": ["CliLoc", [location, command]],
            "intermediate_vars": [{"location": location, "content": command}] * 8,
            "taint_sink": ["CliLoc", [location, command]],
        }
        results.extend((native, deepcopy(native)))
    for expected_calls in (1, 2):
        findings = findings_from_report({"results": results}, targets, parsed=parsed)
        assert {finding.path: finding.column for finding in findings} == {
            "SKILL.md": 4, "nested/SKILL.md": 3,
        }
        assert [text.splits for text in captured] == [expected_calls] * 4


@pytest.mark.parametrize("separator", ["; ", ";\t"])
@pytest.mark.parametrize("same_path", [False, True])
def test_unmapped_occurrences_survive_all_deduplication(
        make_package, monkeypatch, separator, same_path):
    first = 'open("~/.ssh/id_rsa")'
    second = first if same_path else 'open("~/.aws/credentials")'
    command = first + separator + second
    parsed, target, line = _fixture(make_package, prefix="", command=command)
    a = _native(line, first)
    b = _native(line, command, len(first + separator) + 1)
    engine = {"results": [b, a, deepcopy(a), deepcopy(b)]}
    original = deepcopy(engine)
    findings = findings_from_report(engine, {"0000.py": target}, parsed=parsed)
    assert len(findings) == 2 and engine == original
    kept = cap_findings(findings * (FINDING_CAP + 1))
    assert kept == findings and dedupe_findings(kept[::-1]) == findings
    scanmod = sys.modules["skill_xray.scan"]
    monkeypatch.setattr(scanmod, "run_checks", lambda *_a, **_kw: kept)
    report = scanmod.scan_report(parsed)
    assert len(scanmod.scan(parsed)) == len(report.findings) == len(report.raw_candidates) == 2
    output = build_sarif(parsed, report)
    validate_sarif(output)
    results = output["runs"][0]["results"]
    assert len(results) == 2
    assert len({r["properties"]["id"] for r in results}) == 2
    assert all(f.vector == "SXV-023" and f.path == "SKILL.md" and f.line == line
               and f.severity == "high" for f in findings)
    if "\t" in separator:
        assert all(f.column is None for f in findings)
        assert {f.evidence["engine_location"]["start"]["col"] for f in findings} == {
            1, len(first + separator) + 1}
        for result in results:
            assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": line}
            assert "location-unvalidated" in result["properties"]["limitations"]
            assert result["properties"]["disposition"] == "reported"
            assert "codeFlows" not in result
    assert encode_sarif(output) == encode_sarif(build_sarif(parsed, scanmod.scan_report(parsed)))


@pytest.mark.parametrize("separator", ["; ", ";\t"])
def test_native_fence_keeps_both_credential_reads(make_package, separator):
    command = 'open("~/.ssh/id_rsa")' + separator + 'open("~/.aws/credentials")'
    parsed, _, line = _fixture(make_package, prefix="", command=command)
    report = sys.modules["skill_xray.scan"].scan_report(parsed)
    raw = [c for c in report.raw_candidates if c["finding"]["vector"] == "SXV-023"]
    assert len(raw) == 2
    output = build_sarif(parsed, report)
    validate_sarif(output)
    results = [r for r in output["runs"][0]["results"] if r["properties"].get("sxv") == "SXV-023"]
    assert len(results) == 2
    assert all(r["properties"]["effectiveSeverity"] == "high" for r in results)
    assert all(c["finding"]["line"] == line and c["finding"]["path"] == "SKILL.md" for c in raw)
    if "\t" in separator:
        assert all(r["locations"][0]["physicalLocation"]["region"] == {"startLine": line}
                   for r in results)
