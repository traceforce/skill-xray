"""Input resolver tests. Directory, file and zip run fully offline; the URL and
git safety checks are tested without touching the network."""

from __future__ import annotations

import os
import zipfile

import pytest

from skill_xray import build_package, resolve
from skill_xray.resolve import (
    IngestLimitExceededError,
    UnsafeInputError,
    resolved_input,
)


# --- directory + single file ------------------------------------------------
def test_directory_is_used_in_place(make_package):
    root = make_package({"SKILL.md": "---\nname: t\n---\n"})
    with resolved_input(str(root)) as r:
        assert r.kind == "directory"
        assert r.root == str(root)


def test_single_file_is_wrapped_into_a_package(tmp_path):
    f = tmp_path / "SKILL.md"
    f.write_text("---\nname: t\n---\n", encoding="utf-8")
    with resolved_input(str(f)) as r:
        assert r.kind == "file"
        pkg = build_package(r.root)
        assert any(a.rel == "SKILL.md" for a in pkg.artifacts)


def test_single_file_temp_dir_is_removed_on_exit(tmp_path):
    f = tmp_path / "SKILL.md"
    f.write_text("---\nname: t\n---\n", encoding="utf-8")
    with resolved_input(str(f)) as r:
        root = r.root
        assert os.path.isdir(root)
    assert not os.path.exists(root)      # the temp dir must not leak


def test_missing_target_is_a_clear_error():
    with pytest.raises(UnsafeInputError):
        with resolved_input("/no/such/target/xyz"):
            pass


def test_local_dir_named_dot_git_is_treated_as_directory(make_package):
    # a local path is resolved before the git heuristic, so foo.git on disk is a dir
    root = make_package({"SKILL.md": "---\nname: t\n---\n"}, name="foo.git")
    with resolved_input(str(root)) as r:
        assert r.kind == "directory"


# --- zip: happy path + the safety caps --------------------------------------
def _zip(path, members):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)


def test_zip_is_extracted_and_walkable(tmp_path):
    z = tmp_path / "skill.zip"
    _zip(z, {"SKILL.md": "---\nname: t\n---\n", "scripts/run.py": "print(1)\n"})
    with resolved_input(str(z)) as r:
        assert r.kind == "zip"
        pkg = build_package(r.root)
        rels = {a.rel for a in pkg.artifacts}
        assert "SKILL.md" in rels and "scripts/run.py" in rels


def test_zip_member_count_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(resolve, "INGEST_MAX_ZIP_MEMBERS", 2)
    z = tmp_path / "many.zip"
    _zip(z, {"a": "1", "b": "2", "c": "3"})
    with pytest.raises(IngestLimitExceededError):
        with resolved_input(str(z)):
            pass


def test_zip_uncompressed_byte_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(resolve, "INGEST_MAX_BYTES", 1000)
    z = tmp_path / "big.zip"
    _zip(z, {"SKILL.md": "x" * 5000})
    with pytest.raises(IngestLimitExceededError):
        with resolved_input(str(z)):
            pass


def test_zip_slip_is_rejected(tmp_path):
    z = tmp_path / "slip.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../escape.txt", "pwned")
    with pytest.raises(UnsafeInputError):
        with resolved_input(str(z)):
            pass


def test_zip_symlink_member_is_rejected(tmp_path):
    z = tmp_path / "link.zip"
    with zipfile.ZipFile(z, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 & 0xFFFF) << 16   # S_IFLNK
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(UnsafeInputError):
        with resolved_input(str(z)):
            pass


def test_zip_degenerate_member_does_not_crash(tmp_path):
    z = tmp_path / "deg.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("SKILL.md", "---\nname: t\n---\n")
        zf.writestr(zipfile.ZipInfo("."), "")   # maps to the extract root; skipped
    with resolved_input(str(z)) as r:
        assert r.kind == "zip"


# --- URL SSRF guard (no network) --------------------------------------------
@pytest.mark.parametrize("url", [
    "http://127.0.0.1/x", "http://localhost/x", "https://10.0.0.5/x",
    "http://169.254.169.254/latest/meta-data", "http://[::1]/x",
    "http://100.64.0.1/x",   # CGNAT: not is_private, but not public either
])
def test_url_ssrf_blocks_non_public(url):
    with pytest.raises(UnsafeInputError):
        resolve._check_url_host(url)


def test_url_rejects_non_http_scheme():
    with pytest.raises(UnsafeInputError):
        resolve._check_url_host("ftp://example.com/x")


def test_url_invalid_port_is_refused():
    with pytest.raises(UnsafeInputError):
        resolve._check_url_host("http://example.com:99999/x")


def test_url_public_host_passes_the_check(monkeypatch):
    # a host resolving to a public IP passes; no connection is made
    monkeypatch.setattr(resolve.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    resolve._check_url_host("https://example.com/skill.zip")


def test_url_download_pins_and_caps_size(monkeypatch):
    monkeypatch.setattr(resolve, "INGEST_MAX_BYTES", 1000)
    monkeypatch.setattr(resolve, "_check_url_host",
                        lambda url: ("https", "example.com", 443, "/x", "93.184.216.34"))

    class _Resp:
        status = 200

        def __init__(self):
            self._sent = False

        def read(self, n):
            if self._sent:
                return b""
            self._sent = True
            return b"x" * 5000

    class _Conn:
        def request(self, *a, **k):
            pass

        def getresponse(self):
            return _Resp()

        def close(self):
            pass

    monkeypatch.setattr(resolve, "_pinned_connection", lambda *a: _Conn())
    with pytest.raises(IngestLimitExceededError):
        with resolved_input("https://example.com/big.bin"):
            pass


# --- git guard (https only + SSRF; no clone) --------------------------------
def test_git_requires_https(monkeypatch):
    monkeypatch.setattr(resolve, "_check_url_host", lambda url: None)   # skip network
    resolve._check_git_remote("https://github.com/u/r.git")            # ok
    for bad in ["git@github.com:u/r.git", "git://host/r.git", "ssh://h/r.git",
                "http://h/r.git", "/local/path/repo.git", "repo.git"]:
        with pytest.raises(UnsafeInputError):
            resolve._check_git_remote(bad)


def test_git_ssrf_blocks_internal_host(monkeypatch):
    monkeypatch.setattr(resolve.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))])
    with pytest.raises(UnsafeInputError):
        resolve._check_git_remote("https://internal.example.com/r.git")


def test_git_missing_binary_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(resolve, "_check_git_remote", lambda url: None)

    def _boom(*a, **k):
        raise FileNotFoundError()
    monkeypatch.setattr(resolve.subprocess, "run", _boom)
    with pytest.raises(UnsafeInputError):
        resolve._git_clone("https://github.com/u/r.git")
