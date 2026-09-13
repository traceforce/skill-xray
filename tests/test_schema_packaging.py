"""Prepared upstream data must not turn into an incomplete or online-only release."""

import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ASSET = Path("src/skill_xray/schemas/sarif-schema-2.1.0.json")
EXPECTED = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"


@pytest.fixture
def schema():
    spec = importlib.util.spec_from_file_location(
        "schema_preparation", ROOT / "dev/prepare_sarif_schema.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def official():
    data = (ROOT / ASSET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXPECTED
    return data


def test_verified_cache_prepares_exact_bytes_without_network(
        schema, official, tmp_path, monkeypatch):
    cache = tmp_path / "cache.json"
    cache.write_bytes(official)
    monkeypatch.setattr(schema.subprocess, "run", lambda *_a, **_k: pytest.fail("network"))
    target = schema.prepare(tmp_path / "checkout", cache)
    assert target == tmp_path / "checkout" / ASSET and target.read_bytes() == official
    cache.unlink()
    assert schema.prepare(tmp_path / "checkout", cache) == target


@pytest.mark.parametrize("data", [b"{}", b"x" * (256 * 1024 + 1)], ids=["digest", "oversized"])
def test_bad_cache_never_becomes_a_release_asset(schema, data, tmp_path, monkeypatch):
    cache = tmp_path / "cache.json"
    cache.write_bytes(data)
    monkeypatch.setattr(schema.subprocess, "run", lambda *_a, **_k: pytest.fail("network"))
    with pytest.raises(ValueError):
        schema.prepare(tmp_path / "checkout", cache)
    assert cache.read_bytes() == data and not (tmp_path / "checkout" / ASSET).exists()


def test_missing_cache_uses_bounded_worker(schema, official, tmp_path, monkeypatch):
    calls = []

    def fetch(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout=official)

    monkeypatch.setattr(schema.subprocess, "run", fetch)
    cache = tmp_path / "cache.json"
    assert schema.prepare(tmp_path / "checkout", cache).read_bytes() == official
    assert cache.read_bytes() == official and len(calls) == 1
    args, options = calls[0]
    assert args[0] == sys.executable and args[-1] == "--download"
    assert options["timeout"] == 30 and options["check"] is True


@pytest.mark.parametrize("failure", ["timeout", "unavailable", "bad-response"])
def test_failed_download_leaves_no_asset(schema, tmp_path, monkeypatch, failure):
    def fetch(args, **_kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 30)
        if failure == "unavailable":
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0, stdout=b"not the pinned schema")

    monkeypatch.setattr(schema.subprocess, "run", fetch)
    cache = tmp_path / "cache.json"
    with pytest.raises((ValueError, subprocess.SubprocessError)):
        schema.prepare(tmp_path / "checkout", cache)
    assert not cache.exists() and not (tmp_path / "checkout" / ASSET).exists()


def test_download_checks_url_size_and_digest(schema, official, monkeypatch):
    class Response(io.BytesIO):
        def read(self, size=-1):
            assert size == 256 * 1024 + 1
            return super().read(size)

    class Opener:
        def open(self, url, timeout):
            assert url == schema.URL and url.startswith("https://docs.oasis-open.org/")
            assert timeout == 10
            return Response(official)

    monkeypatch.setattr(schema, "build_opener", lambda *_: Opener())
    assert schema.download() == official


def test_redirects_are_not_followed(schema):
    with pytest.raises(ValueError, match="redirect"):
        schema.NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://127.0.0.1")


def test_symlink_cache_is_rejected(schema, official, tmp_path):
    source, cache = tmp_path / "source.json", tmp_path / "cache.json"
    source.write_bytes(official)
    try:
        cache.symlink_to(source)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError):
        schema.prepare(tmp_path / "checkout", cache)
    assert source.read_bytes() == official


def test_failed_replacement_preserves_old_file(schema, official, tmp_path, monkeypatch):
    target = tmp_path / "schema.json"
    target.write_bytes(b"old file")

    def fail(*_args):
        raise OSError("disk unavailable")

    monkeypatch.setattr(schema.os, "replace", fail)
    with pytest.raises(OSError):
        schema.atomic_write(target, official)
    assert target.read_bytes() == b"old file" and list(tmp_path.iterdir()) == [target]


@pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions")
def test_prepared_public_schema_is_readable_by_package_users(schema, official, tmp_path):
    target = tmp_path / "schema.json"
    schema.atomic_write(target, official)
    assert target.stat().st_mode & 0o444 == 0o444


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE", "setup.py", "MANIFEST.in"):
        if (ROOT / name).exists():
            shutil.copy2(ROOT / name, root / name)
    shutil.copytree(ROOT / "src", root / "src", ignore=shutil.ignore_patterns(
        "*.egg-info", "__pycache__"))
    (root / "dev").mkdir()
    helper = ROOT / "dev/prepare_sarif_schema.py"
    if helper.exists():
        shutil.copy2(helper, root / "dev" / helper.name)
    return root


def build(root, kind):
    # Release builds must never acquire network access, even on a cache miss.
    code = ("import sys\n"
            "def deny(event, args):\n"
            "    if event in ('socket.connect', 'socket.getaddrinfo'):\n"
            "        raise RuntimeError('network forbidden during build')\n"
            "sys.addaudithook(deny)\n"
            "from setuptools import build_meta\n"
            "build_meta.build_%s('dist')\n" % kind)
    return subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True,
                          text=True, timeout=60, env=dict(os.environ, PIP_NO_INDEX="1"))


@pytest.mark.parametrize("kind", ["wheel", "sdist", "editable"])
@pytest.mark.parametrize("state", ["missing", "tampered"])
def test_build_rejects_missing_or_tampered_schema(checkout, kind, state):
    asset = checkout / ASSET
    if state == "missing":
        asset.unlink()
    else:
        asset.write_bytes(b"{}")
    result = build(checkout, kind)
    assert result.returncode != 0, "Build accepted a missing or tampered schema"
    assert "prepare_sarif_schema.py" in result.stderr
    assert not list((checkout / "dist").glob("*"))


def test_wheel_and_sdist_preserve_schema_and_rules_offline(checkout, official, tmp_path):
    for kind in ("wheel", "sdist", "editable"):
        result = build(checkout, kind)
        assert result.returncode == 0, result.stderr
    wheel, = [p for p in (checkout / "dist").glob("*.whl") if "editable" not in p.name]
    with zipfile.ZipFile(wheel) as archive:
        assert archive.read(str(ASSET.relative_to("src")).replace("\\", "/")) == official
        assert archive.read("skill_xray/rules/opengrep-phase1.yml")
    sdist, = (checkout / "dist").glob("*.tar.gz")
    unpacked = tmp_path / "unpacked"
    with tarfile.open(sdist) as archive:
        archive.extractall(unpacked, filter="data")
    root, = unpacked.iterdir()
    assert (root / ASSET).read_bytes() == official
    assert (root / "dev/prepare_sarif_schema.py").is_file()
    result = build(root, "wheel")
    assert result.returncode == 0, result.stderr
    for artifact in (wheel, sdist):
        installed = tmp_path / ("installed-wheel" if artifact == wheel else "installed-sdist")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "--no-index",
            "--no-deps", "--no-build-isolation", "--no-compile", "--target", str(installed),
            str(artifact)], cwd=tmp_path, capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        assert (installed / ASSET.relative_to("src")).read_bytes() == official
        assert (installed / "skill_xray/rules/opengrep-phase1.yml").is_file()
