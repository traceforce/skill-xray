"""Contract tests for manifest truth and unsafe metadata (SXV-033/034)."""

from __future__ import annotations

import pytest

from skill_xray import ingest, parse
from skill_xray.checks import run_checks


def _manifest(grants="allowed-tools: Read"):
    return "---\nname: demo\n%s\n---\nbody\n" % grants


def _run(make_package, files):
    package = ingest.build_package(str(make_package(files)))
    parsed = parse.parse_package(package)
    return run_checks(parsed)


@pytest.mark.parametrize(("path", "source", "capability", "line"), [
    ("run.py", "import subprocess\nsubprocess.run(['echo', 'ok'])\n", "execution", 2),
    ("run.py", "import requests\nrequests.get('https://example.invalid')\n", "network", 2),
    ("run.sh", "#!/bin/sh\ncurl https://example.invalid/data -o out\n", "network", 2),
])
def test_observed_capability_under_restrictive_manifest_reports_sxv033(
    make_package, path, source, capability, line,
):
    findings = _run(make_package, {"SKILL.md": _manifest(), path: source})
    hit = next(f for f in findings if f.vector == "SXV-033"
               and f.evidence["understated_capability"] == capability)

    assert (hit.rule, hit.severity, hit.path, hit.line) == (
        "permission-understatement", "high", path, line,
    )
    assert hit.evidence["manifest"] == "SKILL.md"
    assert hit.evidence["declared_tools"] == ["Read"]
    assert hit.evidence["engine"] == "opengrep"


@pytest.mark.parametrize(("source", "declared"), [
    ("import subprocess\nsubprocess.run(['echo'])\n", "allowed-tools: Bash"),
    ("import requests\nrequests.get('https://example.invalid')\n", "allowed-tools: WebFetch"),
])
def test_honestly_declared_capability_does_not_report_sxv033(
    make_package, source, declared,
):
    findings = _run(make_package, {"SKILL.md": _manifest(declared), "run.py": source})
    assert all(f.vector != "SXV-033" for f in findings)


def test_absent_allowed_tools_makes_no_understatement_claim(make_package):
    findings = _run(make_package, {
        "SKILL.md": "---\nname: demo\n---\nbody\n",
        "run.py": "import subprocess\nsubprocess.run(['echo'])\n",
    })
    assert all(f.vector != "SXV-033" for f in findings)


def test_nearest_manifest_governs_nested_script(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest("allowed-tools: Bash"),
        "nested/SKILL.md": _manifest("allowed-tools: Read"),
        "nested/run.py": "import subprocess\nsubprocess.run(['echo'])\n",
    })
    hit = next(f for f in findings if f.vector == "SXV-033")
    assert hit.evidence["manifest"] == "nested/SKILL.md"


@pytest.mark.parametrize("source", [
    "# subprocess.run(['echo'])\nprint('ok')\n",
    '"""requests.get(\"https://example.invalid\")"""\nprint("ok")\n',
    "def fetch(url):\n    return url\nfetch('local')\n",
])
def test_comments_docstrings_and_local_helpers_are_not_observed_capabilities(
    make_package, source,
):
    findings = _run(make_package, {"SKILL.md": _manifest(), "run.py": source})
    assert all(f.vector != "SXV-033" for f in findings)


def test_shell_comment_and_quoted_example_are_not_network_capability(make_package):
    source = "# curl https://example.invalid\necho 'wget https://example.invalid'\n"
    findings = _run(make_package, {"SKILL.md": _manifest(), "run.sh": source})
    assert all(f.vector != "SXV-033" for f in findings)


@pytest.mark.parametrize("source", [
    ("class Fake:\n    def run(self, value): return value\n"
     "subprocess = Fake()\nsubprocess.run('x')\n"),
    ("class Fake:\n    def get(self, value): return value\n"
     "requests = Fake()\nrequests.get('local')\n"),
])
def test_shadowed_library_names_do_not_prove_capability(make_package, source):
    findings = _run(make_package, {"SKILL.md": _manifest(), "run.py": source})
    assert all(f.vector != "SXV-033" for f in findings)


@pytest.mark.parametrize(("source", "capability"), [
    ("import subprocess as sp\nsp.run(['echo'])\n", "execution"),
    ("from requests import get\nget('https://example.invalid')\n", "network"),
])
def test_import_aliases_preserve_capability_detection(make_package, source, capability):
    findings = _run(make_package, {"SKILL.md": _manifest(), "run.py": source})
    assert any(f.vector == "SXV-033"
               and f.evidence["understated_capability"] == capability for f in findings)


def test_narrow_network_grant_does_not_hide_unrelated_execution(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest("allowed-tools: Bash(curl:*)"),
        "run.py": "import subprocess\nsubprocess.run(['echo'])\n",
    })
    assert any(f.vector == "SXV-033"
               and f.evidence["understated_capability"] == "execution" for f in findings)


def test_space_separated_curl_grant_declares_observed_network(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest("allowed-tools: Bash(curl:*) Bash(jq:*)")
        + "\n```bash\ncurl https://example.invalid\n```\n",
    })
    assert not any(f.vector == "SXV-033" for f in findings)


@pytest.mark.parametrize("grant", [
    "allowed-tools: Bash(python -c:*)",
    "allowed-tools: Bash(sudo:*)",
    "allowed-tools: Bash(*)",
    "allowed-tools: Bash(npx:*)",
    "allowed-tools: Bash(pip:*)",
    "allowed-tools: Bash(env:*)",
    "allowed-tools: Bash(xargs:*)",
])
def test_declared_broad_execution_suppresses_execution_mismatch(make_package, grant):
    findings = _run(make_package, {
        "SKILL.md": _manifest(grant),
        "run.py": "import subprocess\nsubprocess.run(['echo'])\n",
    })
    assert not any(f.vector == "SXV-033"
                   and f.evidence["understated_capability"] == "execution" for f in findings)


def test_shell_ifs_network_command_is_observed_without_matching_quoted_text(make_package):
    source = "wget$IFS-qO-$IFS'https://example.invalid/data'>out\n"
    findings = _run(make_package, {"SKILL.md": _manifest(), "run.sh": source})
    assert any(f.vector == "SXV-033"
               and f.evidence["understated_capability"] == "network" for f in findings)


@pytest.mark.parametrize("source", [
    "import requests\nrequests.Session().get('https://example.invalid')\n",
    "import httpx\nclient = httpx.Client()\nclient.get('https://example.invalid')\n",
])
def test_instantiated_http_clients_are_observed(make_package, source):
    findings = _run(make_package, {"SKILL.md": _manifest(), "run.py": source})
    assert any(f.vector == "SXV-033"
               and f.evidence["understated_capability"] == "network" for f in findings)


def test_rebound_http_client_constructor_does_not_prove_network(make_package):
    source = """import httpx
class Fake:
    def get(self, value): return value
httpx.Client = Fake
httpx.Client().get('local')
"""
    findings = _run(make_package, {"SKILL.md": _manifest(), "run.py": source})
    assert all(f.vector != "SXV-033" for f in findings)


def test_client_created_before_constructor_rebinding_still_proves_network(make_package):
    source = """import httpx
client = httpx.Client()
httpx.Client = object
client.get('https://example.invalid')
"""
    findings = _run(make_package, {"SKILL.md": _manifest(), "run.py": source})
    assert any(f.vector == "SXV-033"
               and f.evidence["understated_capability"] == "network" for f in findings)


@pytest.mark.parametrize("tool", ["chmod", "chown"])
def test_file_permission_grant_does_not_declare_process_execution(make_package, tool):
    findings = _run(make_package, {
        "SKILL.md": _manifest("allowed-tools: Bash(%s:*)" % tool),
        "run.py": "import subprocess\nsubprocess.run(['echo'])\n",
    })
    assert any(f.vector == "SXV-033"
               and f.evidence["understated_capability"] == "execution" for f in findings)


def test_capability_declaration_checks_every_command_segment(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest(
            "allowed-tools: Bash(echo ok && curl example.invalid && npx tool:*)",
        ),
        "run.py": (
            "import requests, subprocess\n"
            "requests.get('https://example.invalid')\n"
            "subprocess.run(['echo'])\n"
        ),
    })
    assert not [finding for finding in findings if finding.vector == "SXV-033"]


def test_network_only_chain_does_not_declare_process_execution(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest(
            "allowed-tools: Bash(echo ok && curl https://example.invalid:*)",
        ),
        "run.py": "import subprocess\nsubprocess.run(['echo'])\n",
    })
    assert any(finding.vector == "SXV-033"
               and finding.evidence["understated_capability"] == "execution"
               for finding in findings)


def test_malformed_declaration_does_not_invent_understatement(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest("allowed-tools: [Read, {Bash: true}]"),
        "run.py": "import subprocess\nsubprocess.run(['echo'])\n",
    })
    assert all(f.vector != "SXV-033" for f in findings)
    assert any(f.evidence.get("reason") == "grants_unparsed_shape" for f in findings)
    assert any(
        f.rule == "analysis-incomplete"
        and f.severity == "high"
        and f.path == "run.py"
        and f.evidence.get("reason") == "capability-declaration-unparsed"
        for f in findings
    )


def test_invalid_frontmatter_with_observed_capability_fails_high(make_package):
    manifest = "---\nname: [broken\nallowed-tools: Read\n---\nbody\n"
    findings = _run(make_package, {
        "SKILL.md": manifest,
        "run.py": "import subprocess\nsubprocess.run(['echo'])\n",
    })
    assert all(f.vector != "SXV-033" for f in findings)
    assert any(
        f.rule == "analysis-incomplete"
        and f.severity == "high"
        and f.path == "run.py"
        and f.evidence.get("reason") == "capability-declaration-unparsed"
        for f in findings
    )


def test_opengrep_capability_finding_exposes_exact_column(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest(),
        "run.py": "import os\nvalue = 1; os.system('echo ok')\n",
    })
    hit = next(f for f in findings if f.vector == "SXV-033")
    assert hit.column == hit.evidence["start"]["col"]


def test_file_capability_validation_reuses_ir_ast(make_package, monkeypatch):
    package = ingest.build_package(str(make_package({
        "SKILL.md": _manifest(),
        "run.py": "import subprocess\nsubprocess.run(['echo'])\n",
    })))
    parsed = parse.parse_package(package)

    def reject_reparse(_source):
        raise AssertionError("file AST was parsed twice")

    monkeypatch.setattr("skill_xray.opengrep_bridge.parse_python", reject_reparse)
    findings = run_checks(parsed)
    assert any(f.vector == "SXV-033" for f in findings)


@pytest.mark.parametrize("source", [
    "import os\nos.execvp('tool', ['tool'])\n",
    "import os\nos.posix_spawnp('tool', ['tool'], {})\n",
])
def test_process_replacement_is_observed_execution(make_package, source):
    findings = _run(make_package, {
        "SKILL.md": _manifest(),
        "run.py": source,
    })
    assert any(
        f.vector == "SXV-033"
        and f.evidence["understated_capability"] == "execution"
        for f in findings
    )


def test_process_replacement_import_alias_is_observed(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest(),
        "run.py": "from os import execvp as launch\nlaunch('tool', ['tool'])\n",
    })
    assert any(f.vector == "SXV-033" for f in findings)


def test_shadowed_process_replacement_api_is_not_observed(make_package):
    source = (
        "class Fake:\n"
        "    def execvp(self, *args): return args\n"
        "os = Fake()\n"
        "os.execvp('tool', ['tool'])\n"
    )
    findings = _run(make_package, {"SKILL.md": _manifest(), "run.py": source})
    assert all(f.vector != "SXV-033" for f in findings)


def test_spawn_process_creation_is_observed_execution(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest(),
        "run.py": "import os\nos.spawnvp(os.P_WAIT, 'tool', ['tool'])\n",
    })
    assert any(f.vector == "SXV-033"
               and f.evidence["understated_capability"] == "execution" for f in findings)


def test_shadowed_spawn_api_is_not_observed(make_package):
    source = (
        "class Fake:\n"
        "    def spawnvp(self, *args): return args\n"
        "os = Fake()\n"
        "os.spawnvp(0, 'tool', ['tool'])\n"
    )
    findings = _run(make_package, {"SKILL.md": _manifest(), "run.py": source})
    assert all(f.vector != "SXV-033" for f in findings)


def test_command_lookup_grant_does_not_declare_execution(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest("allowed-tools: Bash(command -v tool)"),
        "run.py": "import subprocess\nsubprocess.run(['echo', 'ok'])\n",
    })
    assert any(f.vector == "SXV-033"
               and f.evidence["understated_capability"] == "execution" for f in findings)


def test_denied_execution_grant_is_not_declared(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest("allowed-tools: Bash\ndisallowed-tools: Bash"),
        "run.py": "import subprocess\nsubprocess.run(['echo', 'ok'])\n",
    })
    assert any(f.vector == "SXV-033"
               and f.evidence["understated_capability"] == "execution" for f in findings)


def test_denied_network_grant_is_not_declared(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest("allowed-tools: WebFetch\ndisallowed-tools: WebFetch"),
        "run.py": "import requests\nrequests.get('https://example.invalid')\n",
    })
    assert any(f.vector == "SXV-033"
               and f.evidence["understated_capability"] == "network" for f in findings)


def test_unrelated_denial_leaves_grant_effective(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest("allowed-tools: Bash\ndisallowed-tools: WebFetch"),
        "run.py": "import subprocess\nsubprocess.run(['echo', 'ok'])\n",
    })
    assert all(f.vector != "SXV-033" for f in findings)


def test_final_same_line_constructor_reassignment_wins(make_package):
    source = (
        "import httpx\n"
        "class Fake:\n"
        "    def get(self, *a): return None\n"
        "client = httpx.Client(); client = Fake()\n"
        "client.get('https://example.invalid')\n"
    )
    findings = _run(make_package, {"SKILL.md": _manifest(), "run.py": source})
    assert all(not (f.vector == "SXV-033"
                    and f.evidence.get("understated_capability") == "network")
               for f in findings)


def test_unsupported_language_remains_explicitly_incomplete(make_package):
    findings = _run(make_package, {
        "SKILL.md": _manifest(),
        "run.ps1": "Invoke-WebRequest https://example.invalid\n",
    })
    assert all(f.vector != "SXV-033" for f in findings)
    assert any(f.rule == "analysis-incomplete" and f.path == "run.ps1" for f in findings)


@pytest.mark.parametrize(("tag", "expected"), [
    ("!!python/object/apply:os.system", "tag:yaml.org,2002:python/object/apply:os.system"),
    ("!!python/object/new:subprocess.Popen",
     "tag:yaml.org,2002:python/object/new:subprocess.Popen"),
    ("!ruby/object:Gem::Requirement", "!ruby/object:Gem::Requirement"),
    ("!!python/object:example.Payload", "tag:yaml.org,2002:python/object:example.Payload"),
    ("!!python/name:os.system", "tag:yaml.org,2002:python/name:os.system"),
    ("!!python/module:os", "tag:yaml.org,2002:python/module:os"),
    ("!ruby/hash:Example", "!ruby/hash:Example"),
])
def test_unsafe_object_tag_reports_exact_parser_location(make_package, tag, expected):
    manifest = "---\nname: demo\npayload: %s [echo]\n---\nbody\n" % tag
    hit = next(f for f in _run(make_package, {"SKILL.md": manifest})
               if f.vector == "SXV-034")

    assert (hit.rule, hit.severity, hit.path, hit.line, hit.column) == (
        "unsafe-yaml-tag", "critical", "SKILL.md", 3, 10,
    )
    assert hit.evidence["tag"] == expected


def test_known_java_gadget_tag_reports_but_custom_namespace_does_not(make_package):
    dangerous = (_manifest().replace("---\nbody", "loader: !!javax.script.ScriptEngineManager []\n"
                                      "---\nbody"))
    benign = (_manifest().replace("---\nbody", "value: !!com.example.Value ordinary\n"
                                   "---\nbody"))
    assert any(f.vector == "SXV-034" for f in _run(make_package, {
        "SKILL.md": dangerous,
    }))
    assert all(f.vector != "SXV-034" for f in _run(make_package, {
        "SKILL.md": benign,
    }))


def test_python_object_prefix_lookalike_is_not_a_constructor_tag(make_package):
    manifest = "---\nname: demo\nvalue: !!python/objective ordinary\n---\nbody\n"
    findings = _run(make_package, {"SKILL.md": manifest})
    assert all(f.vector != "SXV-034" for f in findings)


@pytest.mark.parametrize("text", [
    "---\nname: demo\nnote: '!!python/object/apply:os.system'\n---\nbody\n",
    "---\nname: demo\n# !!python/object/apply:os.system\n---\nbody\n",
    "---\nname: demo\n---\nMention !!python/object/apply:os.system in prose.\n",
])
def test_unsafe_tag_lookalikes_outside_yaml_tag_tokens_do_not_report(make_package, text):
    findings = _run(make_package, {"SKILL.md": text})
    assert all(f.vector != "SXV-034" for f in findings)


def test_unterminated_frontmatter_is_incomplete_not_asserted_unsafe(make_package):
    text = "---\nname: demo\npayload: !!python/object/apply:os.system [echo]\n"
    findings = _run(make_package, {"SKILL.md": text})
    assert all(f.vector != "SXV-034" for f in findings)
    assert any(f.rule == "coverage-note" and f.path == "SKILL.md" for f in findings)
