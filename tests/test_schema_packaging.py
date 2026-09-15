"""Vendored upstream data must survive offline builds without a downloader."""

import hashlib
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
def official():
    data = (ROOT / ASSET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXPECTED
    return data


def test_schema_needs_no_preparation_command(official):
    assert official
    assert not (ROOT / "dev/prepare_sarif_schema.py").exists()
    for name in ("README.md", ".github/workflows/ci.yml"):
        assert "prepare_sarif_schema.py" not in (ROOT / name).read_text(encoding="utf-8")
    assert "/" + ASSET.as_posix() not in (ROOT / ".gitignore").read_text(encoding="utf-8")


def test_git_checkout_preserves_pinned_bytes_with_autocrlf(official, tmp_path):
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    attributes = ROOT / ".gitattributes"
    if attributes.exists():
        shutil.copy2(attributes, tmp_path / ".gitattributes")
    target = tmp_path / ASSET
    target.parent.mkdir(parents=True)
    target.write_bytes(official)
    command = ["git", "-C", str(tmp_path), "-c", "core.autocrlf=true"]
    subprocess.run(command + ["add", "."], check=True, capture_output=True)
    target.unlink()
    subprocess.run(command + ["checkout-index", "--all", "--force"], check=True)
    assert target.read_bytes() == official


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE", "setup.py", "MANIFEST.in"):
        if (ROOT / name).exists():
            shutil.copy2(ROOT / name, root / name)
    shutil.copytree(ROOT / "src", root / "src", ignore=shutil.ignore_patterns(
        "*.egg-info", "__pycache__"))
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
    assert "Restore the vendored SARIF schema from a trusted checkout" in result.stderr
    assert not list((checkout / "dist").glob("*"))


def test_wheel_and_sdist_preserve_schema_and_rules_offline(checkout, official, tmp_path):
    for kind in ("wheel", "sdist", "editable"):
        result = build(checkout, kind)
        assert result.returncode == 0, result.stderr
    wheel, = [p for p in (checkout / "dist").glob("*.whl") if "editable" not in p.name]
    with zipfile.ZipFile(wheel) as archive:
        assert archive.read(str(ASSET.relative_to("src")).replace("\\", "/")) == official
        assert archive.read("skill_xray/rules/opengrep-phase1.yml")
        assert archive.read("skill_xray/schemas/README.md") == (
            ROOT / ASSET.parent / "README.md").read_bytes()
    sdist, = (checkout / "dist").glob("*.tar.gz")
    unpacked = tmp_path / "unpacked"
    with tarfile.open(sdist) as archive:
        archive.extractall(unpacked, filter="data")
    root, = unpacked.iterdir()
    assert (root / ASSET).read_bytes() == official
    assert not (root / "dev/prepare_sarif_schema.py").exists()
    assert (root / ASSET.parent / "README.md").read_bytes() == (
        ROOT / ASSET.parent / "README.md").read_bytes()
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
        assert (installed / "skill_xray/schemas/README.md").read_bytes() == (
            ROOT / ASSET.parent / "README.md").read_bytes()
