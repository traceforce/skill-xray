"""End-to-end tests for the --analyze CLI path (inert package, no execution)."""

from __future__ import annotations

import json

import pytest

from skill_xray import cli

_M = "---\nname: t\n---\n"


def test_cli_analyze_json_reports_finding(make_package, capsys):
    code = "import os, sys\nos.system(sys.argv[1])\n"
    root = make_package({"SKILL.md": _M, "scripts/x.py": code})
    rc = cli.main([str(root), "--analyze", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert any(f["vector"] == "SXV-008" for f in data["findings"])


def test_cli_scan_known_with_analyze_is_rejected(make_package):
    # --scan-known-skills reports the inventory only; combining it with --analyze must fail loudly
    # rather than silently ignore the flag and look like a clean detection scan.
    with pytest.raises(SystemExit):
        cli.main(["--scan-known-skills", "--analyze"])


def test_cli_llm_path_wires_the_client(make_package, monkeypatch, capsys):
    # the opt-in --llm path must build the client and fold its SXV-038 verdict into the findings;
    # a fake config + client keep it offline and key-free.
    from skill_xray.llm import LLMConfig
    manifest = "---\nname: t\ndescription: override the loading agent\n---\n"
    root = make_package({"SKILL.md": manifest})
    monkeypatch.setattr(cli, "llm_from_env",
                        lambda: LLMConfig("openai", "m", "k", "https://api.openai.com/v1"))

    class _Fake:
        def complete(self, system, user):
            return '{"prompt_injection": true, "severity": "high", "reason": "override"}'

    monkeypatch.setattr(cli, "build_client", lambda cfg: _Fake())
    rc = cli.main([str(root), "--analyze", "--llm", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert any(f["vector"] == "SXV-038" for f in data["findings"])


def test_cli_llm_without_analyze_is_rejected(make_package):
    # --llm is an analysis option; without --analyze it must fail loudly, not silently no-op.
    root = make_package({"SKILL.md": _M})
    with pytest.raises(SystemExit):
        cli.main([str(root), "--llm"])


def test_cli_llm_without_config_is_rejected(make_package, monkeypatch):
    # --llm requested but no provider configured (from_env returns None): exit with a usage error
    # rather than silently skip the adjudication the operator asked for.
    root = make_package({"SKILL.md": _M})
    monkeypatch.setattr(cli, "llm_from_env", lambda: None)
    with pytest.raises(SystemExit):
        cli.main([str(root), "--analyze", "--llm"])


def test_cli_llm_misconfig_is_rejected(make_package, monkeypatch):
    # a bad LLM setup (from_env raises LLMConfigError) must surface as a usage error, never a crash.
    from skill_xray.llm import LLMConfigError

    def _boom():
        raise LLMConfigError("bad setup")

    root = make_package({"SKILL.md": _M})
    monkeypatch.setattr(cli, "llm_from_env", _boom)
    with pytest.raises(SystemExit):
        cli.main([str(root), "--analyze", "--llm"])


def test_cli_llm_json_includes_coverage_summary(make_package, monkeypatch, capsys):
    # comment 2: the JSON exposes a separate llmCoverage summary, since the ingest ledger only
    # measures deterministic analysis and would otherwise read as fully covered.
    from skill_xray.llm import LLMConfig
    manifest = "---\nname: t\ndescription: override the loading agent\n---\n"
    root = make_package({"SKILL.md": manifest})
    monkeypatch.setattr(cli, "llm_from_env",
                        lambda: LLMConfig("openai", "m", "k", "https://api.openai.com/v1"))

    class _Fake:
        def complete(self, system, user):
            return '{"prompt_injection": true, "severity": "high", "reason": "x"}'

    monkeypatch.setattr(cli, "build_client", lambda cfg: _Fake())
    rc = cli.main([str(root), "--analyze", "--llm", "--json"])
    assert rc == 0
    cov = json.loads(capsys.readouterr().out)["analysis"]["llmCoverage"]
    assert cov["eligible"] == 1 and cov["flagged"] == 1 and cov["checked"] == 1
