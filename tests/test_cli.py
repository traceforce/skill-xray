"""CLI smoke tests: the ingest command inventories a package and never executes it."""

from __future__ import annotations

import json

import pytest

from skill_xray import cli, ingest


def test_cli_reports_inventory_and_ledger(make_package, capsys):
    root = make_package({
        "SKILL.md": "---\nname: t\n---\nbody\n",
        "scripts/run.py": "print(1)\n",
        "assets/logo.png": b"\x89PNG\r\n",
    })
    rc = cli.main([str(root), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "identity" in out          # injective install key, restored after refactor
    rels = {a["rel"]: a for a in out["artifacts"]}
    assert rels["scripts/run.py"]["read"] is True
    assert rels["assets/logo.png"]["read"] is False
    assert out["ledger"]["artifactsSeen"] == 3


def test_cli_rejects_a_non_directory(capsys, tmp_path):
    missing = tmp_path / "nope"
    assert cli.main([str(missing)]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_cli_requires_a_target_or_the_flag(capsys):
    # no package and no --scan-known-skills is a usage error
    with pytest.raises(SystemExit):
        cli.main([])
    assert "scan-known-skills" in capsys.readouterr().err


def test_cli_scan_known_skills(make_package, monkeypatch, capsys):
    root = make_package({"SKILL.md": "---\nname: t\n---\n"}, name="disc")
    monkeypatch.setattr(ingest, "KNOWN_SKILL_ROOTS", (str(root.parent),))
    rc = cli.main(["--scan-known-skills", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert any(p["package"] == "disc" for p in out)


def test_cli_scan_known_skills_flags_identity(make_package, monkeypatch, capsys):
    # the auto-scan surfaces identity files inline, without pointing at a package
    root = make_package({"SKILL.md": "---\nname: t\n---\n", "CLAUDE.md": "x"}, name="idpkg")
    monkeypatch.setattr(ingest, "KNOWN_SKILL_ROOTS", (str(root.parent),))
    assert cli.main(["--scan-known-skills"]) == 0
    assert "identity=1" in capsys.readouterr().out


def test_text_output_escapes_control_chars(make_package, capsys):
    # a member name carrying an escape/newline must not forge or hide inventory
    # lines in the human-readable output -- the one thing this tool must prevent.
    pkg = ingest.build_package(str(make_package({"SKILL.md": "---\nname: t\n---\n"})))
    pkg.artifacts[0].rel = "evil\x1b[2K\n  read  FAKE.md"
    cli._print_one(pkg, ingest.build_ledger(pkg))
    out = capsys.readouterr().out
    assert "\x1b" not in out          # raw escape neutralised
    assert "\\x1b" in out             # shown in escaped form instead


def test_scan_known_skills_rejects_a_package_arg(capsys):
    with pytest.raises(SystemExit):
        cli.main(["somepkg", "--scan-known-skills"])
    assert "no package argument" in capsys.readouterr().err


def test_scan_known_escapes_control_chars_in_discovered_path(make_package, monkeypatch, capsys):
    # a package dir whose NAME carries an escape must not rewrite the scan output;
    # _scan_known prints the discovered path and must route it through _display.
    try:
        root = make_package({"SKILL.md": "---\nname: t\n---\n"}, name="ev\x1bil")
    except OSError:
        pytest.skip("control chars in a directory name are not permitted on this host")
    monkeypatch.setattr(ingest, "KNOWN_SKILL_ROOTS", (str(root.parent),))
    assert cli.main(["--scan-known-skills"]) == 0
    assert "\x1b" not in capsys.readouterr().out


def test_error_path_escapes_control_chars(capsys):
    # the package arg is echoed to stderr on failure; a control char must not be
    # able to forge or hide lines there either.
    assert cli.main(["/nonexistent/ev\x1bil"]) == 2
    assert "\x1b" not in capsys.readouterr().err
