"""Execution-policy coordination stays a single enforced OpenGrep call."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from skill_xray import checks, ingest, parse
from skill_xray.checks import taint_engine
from skill_xray.findings import Finding


def _parsed(make_package, files):
    root = make_package({"SKILL.md": "---\nname: t\n---\n", **files})
    return parse.parse_package(ingest.build_package(str(root)))


def _runner(results=()):
    def run(command, **_kwargs):
        output = Path(command[command.index("--output") + 1])
        targets = sorted(path.name for path in Path(command[-1]).iterdir())
        output.write_text(json.dumps({
            "results": list(results),
            "errors": [],
            "paths": {"scanned": targets},
        }), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, None, "")

    return run


def _result(path="0000.py", vector="SXV-008"):
    return {
        "check_id": "skill-xray.test",
        "path": path,
        "start": {"line": 1, "col": 1},
        "end": {"line": 1, "col": 5},
        "extra": {
            "message": "matched",
            "severity": "ERROR",
            "metadata": {
                "skill_xray_vector": vector,
                "skill_xray_rule": "opengrep-test",
                "skill_xray_severity": "high",
            },
        },
    }


def test_opengrep_finding_is_returned_without_parallel_engine(make_package):
    findings = taint_engine.check(
        _parsed(make_package, {"run.py": "print('safe')\n"}),
        executable="opengrep",
        opengrep_runner=_runner([_result()]),
    )

    assert [(finding.vector, finding.evidence["engine"]) for finding in findings] == [
        ("SXV-008", "opengrep")
    ]


def test_unexpected_adapter_exception_is_visible(make_package, monkeypatch):
    monkeypatch.setattr(taint_engine, "opengrep_check", lambda *_args, **_kwargs: 1 / 0)

    findings = taint_engine.check(_parsed(make_package, {"run.py": "pass\n"}))

    assert [(finding.rule, finding.severity) for finding in findings] == [
        ("opengrep-internal-error", "high")
    ]


def test_lane_notes_are_retained_once(make_package):
    note = Finding(
        vector="", rule="analysis-incomplete", severity="high", path="SKILL.md",
        message="unparseable grant",
    )
    findings = taint_engine.check(
        _parsed(make_package, {"run.py": "pass\n"}),
        executable="opengrep",
        opengrep_runner=_runner(),
        lane_notes=(note,),
    )

    assert findings.count(note) == 1


def test_failed_shared_lane_is_not_rebuilt(monkeypatch):
    seen = []

    def opengrep(_parsed, **options):
        seen.append(options["code_units"])
        return []

    monkeypatch.setattr(checks, "build_code_lane", lambda _parsed: 1 / 0)
    monkeypatch.setattr(checks, "_CHECKS", (taint_engine.check,))
    monkeypatch.setattr(taint_engine, "opengrep_check", opengrep)

    findings = checks.run_checks(object())

    assert seen == [()]
    assert [(finding.rule, finding.severity) for finding in findings] == [
        ("check-error", "high")
    ]
