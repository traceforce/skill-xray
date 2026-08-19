"""Input resolver tests. Directory, file and zip run fully offline; the URL and
git safety checks are tested without touching the network."""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
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


def test_single_file_symlink_is_refused(tmp_path):
    # a single-file input that is a symlink to a sensitive file must not have its
    # target content copied into the package.
    secret = tmp_path / "secret"
    secret.write_text("SENSITIVE", encoding="utf-8")
    link = tmp_path / "SKILL.md"
    try:
        os.symlink(str(secret), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this host")
    with pytest.raises(UnsafeInputError):
        with resolved_input(str(link)):
            pass


def test_single_file_symlink_to_zip_is_refused(tmp_path):
    # a symlink to a zip must be refused before extraction; otherwise a symlinked
    # single-file input pulls the target's contents in via the zip path.
    z = tmp_path / "real.zip"
    _zip(z, {"SKILL.md": "---\nname: t\n---\n"})
    link = tmp_path / "link.zip"
    try:
        os.symlink(str(z), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this host")
    with pytest.raises(UnsafeInputError):
        with resolved_input(str(link)):
            pass


def test_single_file_size_cap_is_enforced(tmp_path, monkeypatch):
    # an oversized single-file input is refused during the bounded copy, not copied
    # whole (a pre-copy size check alone would be TOCTOU-bypassable).
    monkeypatch.setattr(resolve, "INGEST_MAX_BYTES", 100)
    f = tmp_path / "big.txt"
    f.write_bytes(b"x" * 5000)
    with pytest.raises(IngestLimitExceededError):
        with resolved_input(str(f)):
            pass


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
    "https://127.0.0.1/x", "https://localhost/x", "https://10.0.0.5/x",
    "https://169.254.169.254/latest/meta-data", "https://[::1]/x",
    "https://100.64.0.1/x",   # CGNAT: not is_private, but not public either
])
def test_url_ssrf_blocks_non_public(url):
    with pytest.raises(UnsafeInputError):
        resolve._check_url_host(url)


def test_url_rejects_non_https_scheme():
    # https only: cleartext http is refused like ftp, matching the git adapter.
    for bad in ("ftp://example.com/x", "http://example.com/x"):
        with pytest.raises(UnsafeInputError):
            resolve._check_url_host(bad)


def test_url_invalid_port_is_refused():
    with pytest.raises(UnsafeInputError):
        resolve._check_url_host("https://example.com:99999/x")


def test_url_with_embedded_credentials_is_refused():
    # userinfo would leak creds in error output and enable host confusion.
    with pytest.raises(UnsafeInputError):
        resolve._check_url_host("https://user:pass@example.com/x")


def test_malformed_url_error_does_not_echo_the_url():
    # a malformed URL can carry a token in its path/query; the error must not echo it.
    with pytest.raises(UnsafeInputError) as ei:
        resolve._check_url_host("https://[::1/secret-token")
    assert "secret-token" not in str(ei.value)


def test_url_public_host_passes_the_check(monkeypatch):
    # a host resolving to a public IP passes; no connection is made
    monkeypatch.setattr(resolve.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    resolve._check_url_host("https://example.com/skill.zip")


def test_url_download_pins_and_caps_size(monkeypatch):
    monkeypatch.setattr(resolve, "INGEST_MAX_BYTES", 1000)
    monkeypatch.setattr(resolve, "_check_url_host",
                        lambda url: ("example.com", 443, "/x", "93.184.216.34"))

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

    monkeypatch.setattr(resolve, "_PinnedHTTPSConnection", lambda *a: _Conn())
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


def test_git_clone_success_from_local_repo(tmp_path, monkeypatch):
    # The clone SUCCESS path, offline: clone from a local repo using only the git
    # binary (no network). The https/SSRF guard is bypassed like the other git
    # tests; this exercises the real subprocess clone + _enforce_tree_size + return.
    if shutil.which("git") is None:
        pytest.skip("git binary not available")
    src = tmp_path / "src"
    src.mkdir()
    (src / "SKILL.md").write_text("---\nname: t\n---\n", encoding="utf-8")
    genv = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e",
                GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e")
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "init"]):
        subprocess.run(["git", *args], cwd=str(src), check=True, capture_output=True, env=genv)
    monkeypatch.setattr(resolve, "_check_git_remote", lambda url: None)   # skip https/SSRF
    root, name = resolve._git_clone(str(src))
    try:
        assert os.path.isfile(os.path.join(root, "SKILL.md"))   # clone produced the tree
    finally:
        resolve._rmtree(root)


def test_git_clone_strips_uppercase_git_suffix(tmp_path, monkeypatch):
    # _looks_like_git accepts .GIT case-insensitively, so the resolved name must
    # strip the suffix case-insensitively too (not leave "myrepo.GIT").
    if shutil.which("git") is None:
        pytest.skip("git binary not available")
    src = tmp_path / "myrepo.GIT"
    src.mkdir()
    (src / "SKILL.md").write_text("---\nname: t\n---\n", encoding="utf-8")
    genv = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e",
                GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e")
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "init"]):
        subprocess.run(["git", *args], cwd=str(src), check=True, capture_output=True, env=genv)
    monkeypatch.setattr(resolve, "_check_git_remote", lambda url: None)
    root, name = resolve._git_clone(str(src))
    try:
        assert name == "myrepo"       # .GIT stripped case-insensitively
    finally:
        resolve._rmtree(root)


# --- fail-closed contract for local + malformed inputs ----------------------
def test_malformed_zip_fails_closed(tmp_path):
    # 'a' as a file then 'a/b' as its child raises FileExistsError during extract;
    # it must surface as UnsafeInputError (exit 2) like the URL path, not a raw
    # traceback (exit 1).
    z = tmp_path / "bad.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a", "i am a file")
        zf.writestr("a/b", "child under a file")
    with pytest.raises(UnsafeInputError):
        with resolved_input(str(z)):
            pass


def test_malformed_url_fails_closed():
    # an unterminated IPv6 literal makes urlparse raise ValueError; it must be
    # caught and reported as UnsafeInputError, not escape as a traceback.
    with pytest.raises(UnsafeInputError):
        resolve._check_url_host("https://[::1/x")


def test_scheme_matching_is_case_insensitive():
    assert resolve._looks_like_url("HTTPS://example.com/x")
    assert not resolve._looks_like_url("HTTP://example.com/x")   # https only now
    assert resolve._looks_like_git("https://host/REPO.GIT")


@pytest.mark.parametrize("addr", [
    "::ffff:169.254.169.254",   # IPv4-mapped cloud metadata
    "64:ff9b::a9fe:a9fe",       # NAT64-embedded 169.254.169.254 (is_global at v6 level)
])
def test_url_ssrf_blocks_embedded_ipv4(monkeypatch, addr):
    monkeypatch.setattr(resolve.socket, "getaddrinfo",
                        lambda *a, **k: [(10, 1, 6, "", (addr, 443, 0, 0))])
    with pytest.raises(UnsafeInputError):
        resolve._check_url_host("https://sneaky.example.com/x")


def test_non_zip_tarball_is_refused(tmp_path):
    # a tarball copied in as one opaque asset would report a false 100% coverage.
    member = tmp_path / "SKILL.md"
    member.write_text("---\nname: t\n---\n", encoding="utf-8")
    t = tmp_path / "skill.tar.gz"
    with tarfile.open(t, "w:gz") as tf:
        tf.add(str(member), arcname="SKILL.md")
    with pytest.raises(UnsafeInputError):
        with resolved_input(str(t)):
            pass


def test_unknown_archive_extension_is_refused(tmp_path):
    f = tmp_path / "skill.7z"
    f.write_bytes(b"7z\xbc\xaf\x27\x1c not a real archive")
    with pytest.raises(UnsafeInputError):
        with resolved_input(str(f)):
            pass


def test_url_redirect_is_refused(monkeypatch):
    monkeypatch.setattr(resolve, "_check_url_host",
                        lambda url: ("example.com", 443, "/x", "93.184.216.34"))

    class _Resp:
        status = 302

        def read(self, n):
            return b""

    class _Conn:
        def request(self, *a, **k):
            pass

        def getresponse(self):
            return _Resp()

        def close(self):
            pass

    monkeypatch.setattr(resolve, "_PinnedHTTPSConnection", lambda *a: _Conn())
    with pytest.raises(UnsafeInputError):
        with resolved_input("https://example.com/x"):
            pass


def test_enforce_tree_size_caps_a_large_clone(tmp_path, monkeypatch):
    monkeypatch.setattr(resolve, "INGEST_MAX_BYTES", 10)
    (tmp_path / "big").write_bytes(b"x" * 100)
    with pytest.raises(IngestLimitExceededError):
        resolve._enforce_tree_size(str(tmp_path))


def test_enforce_tree_size_allows_a_small_clone(tmp_path):
    (tmp_path / "small").write_bytes(b"x" * 5)
    resolve._enforce_tree_size(str(tmp_path))   # under the cap: no raise


def test_resolved_namedtuple_is_exported():
    from skill_xray import Resolved
    assert Resolved._fields == ("root", "name", "kind")
