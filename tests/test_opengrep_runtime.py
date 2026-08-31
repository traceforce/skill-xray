"""Pinned OpenGrep runtime contract tests."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest

from skill_xray import cli
from skill_xray import opengrep_runtime as runtime
from skill_xray.findings import Finding


class _Response:
    def __init__(self, data: bytes):
        self._stream = io.BytesIO(data)
        self.headers = {"Content-Length": str(len(data))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, size=-1):
        return self._stream.read(size)


def test_platform_assets_are_pinned():
    assert runtime.platform_asset("Windows", "AMD64").name.endswith(".exe")
    assert runtime.platform_asset("Linux", "arm64").name == "opengrep_manylinux_aarch64"
    assert runtime.platform_asset("Darwin", "x86_64").size == 48_310_144
    with pytest.raises(runtime.OpenGrepRuntimeError):
        runtime.platform_asset("Plan9", "mips")


def test_verify_rejects_wrong_size_or_digest(tmp_path: Path):
    candidate = tmp_path / "opengrep"
    candidate.write_bytes(b"wrong")
    asset = runtime.OpenGrepAsset("test", 5, "0" * 64)
    with pytest.raises(runtime.OpenGrepRuntimeError):
        runtime.verify_executable(candidate, asset)


def test_verified_binary_digest_is_cached_by_file_identity(tmp_path: Path, monkeypatch):
    candidate = tmp_path / "opengrep"
    candidate.write_bytes(b"valid")
    asset = runtime.OpenGrepAsset(
        "test", 5, hashlib.sha256(b"valid").hexdigest()
    )
    runtime._digest_cached.cache_clear()
    calls = []
    original = runtime._digest

    def counted(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(runtime, "_digest", counted)
    runtime.verify_executable(candidate, asset)
    runtime.verify_executable(candidate, asset)
    assert len(calls) == 1


def test_install_is_atomic_and_verified(tmp_path: Path, monkeypatch):
    payload = b"verified-opengrep"
    asset = runtime.OpenGrepAsset(
        "opengrep-test", len(payload), hashlib.sha256(payload).hexdigest()
    )
    monkeypatch.setattr(runtime, "platform_asset", lambda: asset)
    monkeypatch.setattr(runtime.platform, "system", lambda: "Linux")

    requested = []

    def opener(request, timeout):
        requested.append((request.full_url, timeout))
        return _Response(payload)

    installed = runtime.install_opengrep(tmp_path, opener=opener, timeout=3)
    assert installed.read_bytes() == payload
    assert requested == [(asset.url, 3)]
    assert not list(tmp_path.glob(".opengrep-*"))


def test_install_rejects_unverified_payload(tmp_path: Path, monkeypatch):
    asset = runtime.OpenGrepAsset("opengrep-test", 4, hashlib.sha256(b"good").hexdigest())
    monkeypatch.setattr(runtime, "platform_asset", lambda: asset)
    monkeypatch.setattr(runtime.platform, "system", lambda: "Linux")
    with pytest.raises(runtime.OpenGrepRuntimeError):
        runtime.install_opengrep(tmp_path, opener=lambda *_args, **_kwargs: _Response(b"evil"))
    assert not list(tmp_path.glob(".opengrep-*"))


def test_resolve_prefers_explicit_and_requires_verification(monkeypatch, tmp_path: Path):
    candidate = tmp_path / "opengrep"
    candidate.write_bytes(b"x")
    seen = []

    def verify(path, asset=None):
        seen.append((Path(path), asset))
        return Path(path)

    monkeypatch.setattr(runtime, "verify_executable", verify)
    assert runtime.resolve_opengrep(candidate) == candidate
    assert seen == [(candidate, None)]


def test_cli_installs_pinned_runtime(monkeypatch, capsys, tmp_path: Path):
    installed = tmp_path / "opengrep"
    monkeypatch.setattr(cli, "install_opengrep", lambda: installed)
    assert cli.main(["--install-opengrep"]) == 0
    output = capsys.readouterr().out
    assert runtime.VERSION in output and installed.name in output


def test_cli_install_rejects_unrelated_options(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--install-opengrep", "--json"])
    assert "standalone action" in capsys.readouterr().err


def test_cli_install_failure_is_explicit(monkeypatch, capsys):
    def fail():
        raise runtime.OpenGrepRuntimeError("verification failed")

    monkeypatch.setattr(cli, "install_opengrep", fail)
    assert cli.main(["--install-opengrep"]) == 2
    assert "verification failed" in capsys.readouterr().err


def test_cli_rejects_explicit_binary_without_analysis(capsys):
    with pytest.raises(SystemExit):
        cli.main(["package", "--opengrep-bin", "opengrep"])
    assert "--opengrep-bin requires --analyze" in capsys.readouterr().err


def test_cli_forwards_explicit_binary(make_package, monkeypatch, capsys):
    root = make_package({"run.py": "pass\n"})
    received = {}

    def scan(parsed, **options):
        received.update(options)
        return []

    monkeypatch.setattr(cli, "scan", scan)
    assert cli.main([
        str(root), "--analyze", "--json", "--opengrep-bin", "pinned-opengrep",
    ]) == 0
    output = capsys.readouterr().out
    assert received == {"opengrep_executable": "pinned-opengrep"}
    assert '"opengrepVersion": "1.29.0"' in output
    assert "taintEngine" not in output


def test_cli_defaults_to_the_single_enforced_policy(make_package, monkeypatch, capsys):
    root = make_package({"run.py": "pass\n"})
    received = {}

    def scan(parsed, **options):
        received.update(options)
        return []

    monkeypatch.setattr(cli, "scan", scan)
    assert cli.main([str(root), "--analyze", "--json"]) == 0
    output = capsys.readouterr().out
    assert received == {"opengrep_executable": None}
    assert '"opengrepVersion": "1.29.0"' in output
    assert "taintEngine" not in output


def test_cli_returns_nonzero_after_reporting_incomplete_analysis(
    make_package, monkeypatch, capsys,
):
    root = make_package({"run.py": "pass\n"})
    gap = Finding(
        vector="", rule="opengrep-unavailable", severity="high", path="run.py",
        message="OpenGrep is unavailable",
    )
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: [gap])

    assert cli.main([str(root), "--analyze", "--json"]) == 2
    assert '"rule": "opengrep-unavailable"' in capsys.readouterr().out


def test_cli_security_findings_keep_report_only_exit_semantics(
    make_package, monkeypatch, capsys,
):
    root = make_package({"run.py": "pass\n"})
    finding = Finding(
        vector="SXV-008", rule="test", severity="critical", path="run.py",
        message="command injection",
    )
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: [finding])

    assert cli.main([str(root), "--analyze", "--json"]) == 0
    assert '"vector": "SXV-008"' in capsys.readouterr().out
