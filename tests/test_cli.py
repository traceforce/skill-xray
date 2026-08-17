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
