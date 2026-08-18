"""Tests for the package walker.

The package is not trusted, so the walker does not read outside its directory
and cannot be made to hang or run out of memory. Every file it does not read is
recorded in the ledger.
"""

from __future__ import annotations

import os
import stat
import subprocess
import unicodedata

import pytest

from skill_xray import ingest


# --- which directory entries are unsafe to open -----------------------------
# Tested on synthetic st_mode so the cases that cannot be created in a test on
# every host (FIFO, device, socket) are still covered everywhere.
@pytest.mark.parametrize(
    "mode,expected",
    [
        (stat.S_IFREG | 0o644, None),
        (stat.S_IFLNK | 0o777, "symlink"),
        (stat.S_IFIFO | 0o644, "not_regular_file"),
        (stat.S_IFSOCK | 0o644, "not_regular_file"),
        (stat.S_IFBLK | 0o644, "not_regular_file"),
        (stat.S_IFCHR | 0o644, "not_regular_file"),
        (stat.S_IFDIR | 0o755, "not_regular_file"),
    ],
)
def test_reject_special(mode, expected):
    assert ingest._reject_special(mode) == expected


# --- size cap ---------------------------------------------------------------
def test_oversized_file_is_skipped_not_read(make_package):
    big = b"x" * (ingest.MAX_FILE_BYTES + 1)
    root = make_package({"SKILL.md": "---\nname: t\n---\n", "scripts/big.py": big})
    pkg = ingest.build_package(str(root))
    art = next(a for a in pkg.artifacts if a.rel == "scripts/big.py")
    assert art.text is None
    assert art.exception == "too_large"
    assert any(
        e["reasonCode"] == "too_large" and e["path"] == "scripts/big.py"
        for e in pkg.ledger_exceptions
    )


def test_file_at_the_cap_is_read(make_package):
    at_cap = b"# " + b"x" * (ingest.MAX_FILE_BYTES - 2)
    root = make_package({"SKILL.md": "---\nname: t\n---\n", "scripts/ok.py": at_cap})
    pkg = ingest.build_package(str(root))
    art = next(a for a in pkg.artifacts if a.rel == "scripts/ok.py")
    assert art.exception is None
    assert art.text is not None


def test_read_text_reports_bytes_actually_read(make_package):
    # the memory budget must be charged for bytes read from the fd, not a
    # pre-read lstat size a TOCTOU swap could understate.
    root = make_package({"SKILL.md": "---\nname: t\n---\n", "a.md": "hello"})
    text, exc, nbytes = ingest.read_text(os.path.join(str(root), "a.md"))
    assert exc is None and text == "hello" and nbytes == 5


# --- file-count cap ---------------------------------------------------------
def test_file_count_cap_truncates_and_records(make_package, monkeypatch):
    monkeypatch.setattr(ingest, "MAX_FILES", 3)
    files = {"SKILL.md": "---\nname: t\n---\n"}
    for i in range(5):
        files["scripts/f%d.py" % i] = "x = 1\n"
    root = make_package(files)
    pkg = ingest.build_package(str(root))
    assert len(pkg.artifacts) == 3
    assert any(e["reasonCode"] == "walk_truncated" for e in pkg.ledger_exceptions)


# --- symlinks ---------------------------------------------------------------
def _symlink_or_skip(src, dst, is_dir=False):
    try:
        os.symlink(src, dst, target_is_directory=is_dir)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this host")


def test_symlinked_file_is_not_read(make_package, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("SENSITIVE", encoding="utf-8")
    root = make_package({"SKILL.md": "---\nname: t\n---\n"})
    _symlink_or_skip(str(outside), str(root / "leak.md"))
    pkg = ingest.build_package(str(root))
    # the symlink never becomes a readable artifact, and the skip is recorded
    assert [a for a in pkg.artifacts if a.rel == "leak.md"] == []
    assert any(
        e["reasonCode"] == "symlink" and e["path"] == "leak.md"
        for e in pkg.ledger_exceptions
    )


def test_symlinked_directory_is_not_traversed(make_package, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.py").write_text("import os\n", encoding="utf-8")
    root = make_package({"SKILL.md": "---\nname: t\n---\n"})
    _symlink_or_skip(str(outside), str(root / "linkdir"), is_dir=True)
    pkg = ingest.build_package(str(root))
    assert not any("evil.py" in a.rel for a in pkg.artifacts)


def _junction_or_skip(link, target):
    """An NTFS junction via `mklink /J` needs no admin and is not an os.path.islink."""
    if os.name != "nt":
        pytest.skip("junctions are Windows-only")
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("mklink /J unavailable: %s" % (r.stderr or r.stdout).strip())


def test_junction_directory_does_not_escape_the_package(make_package, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.md").write_text("root:x:0:0:SECRET-OUTSIDE", encoding="utf-8")
    root = make_package({"SKILL.md": "---\nname: t\n---\n"})
    _junction_or_skip(root / "escape", outside)
    pkg = ingest.build_package(str(root))
    # the outside file is never read into an artifact ...
    assert not any("SECRET-OUTSIDE" in (a.text or "") for a in pkg.artifacts)
    assert not any(a.rel.startswith("escape/") for a in pkg.artifacts)
    # ... and the junction is logged, not silently pruned
    assert any(e["reasonCode"] == "reparse_point" and e["path"] == "escape"
               for e in pkg.ledger_exceptions)


def test_reparse_dir_is_pruned_and_logged(make_package, monkeypatch):
    # A real NTFS junction can only be made on Windows, so simulate the OS
    # reporting one. This proves the prune-and-log branch on any host; the test
    # above proves the actual escape is stopped on Windows.
    root = make_package({
        "SKILL.md": "---\nname: t\n---\n",
        "escape/secret.py": "x = 1\n",
    })
    target = os.path.abspath(str(root / "escape"))
    real_isjunction = os.path.isjunction
    monkeypatch.setattr(os.path, "isjunction",
                        lambda p: os.path.abspath(p) == target or real_isjunction(p))
    pkg = ingest.build_package(str(root))
    assert any(e["reasonCode"] == "reparse_point" and e["path"] == "escape"
               for e in pkg.ledger_exceptions)
    assert not any(a.rel.startswith("escape/") for a in pkg.artifacts)


def test_excluded_dir_is_logged_not_silent(make_package):
    root = make_package({
        "SKILL.md": "---\nname: t\n---\n",
        ".git/config": "x",
        "node_modules/pkg/index.js": "y",
    })
    pkg = ingest.build_package(str(root))
    reasons = {(e["reasonCode"], e["path"]) for e in pkg.ledger_exceptions}
    assert ("excluded_dir", ".git") in reasons
    assert ("excluded_dir", "node_modules") in reasons
    assert not any(a.rel.startswith((".git/", "node_modules/")) for a in pkg.artifacts)


def test_unreadable_directory_is_logged_not_silent(make_package):
    # chmod(0) does not restrict directory traversal on Windows, and root can read
    # anything on POSIX, so the "cannot enter" condition can't be created there.
    if os.name == "nt":
        pytest.skip("chmod(0) does not restrict directory traversal on Windows")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root bypasses directory permissions")
    root = make_package({"SKILL.md": "---\nname: t\n---\n"})
    locked = root / "locked"
    locked.mkdir()
    (locked / "secret.py").write_text("x = 1\n", encoding="utf-8")
    os.chmod(locked, 0)
    try:
        pkg = ingest.build_package(str(root))
    finally:
        os.chmod(locked, 0o755)  # restore so tmp cleanup can delete it
    # a subtree we could not enter is recorded, not silently dropped
    assert any(e["reasonCode"].startswith("walk_error") for e in pkg.ledger_exceptions)
    assert not any(a.rel.startswith("locked/") for a in pkg.artifacts)


def test_undecodable_files_are_charged_against_the_budget(make_package, monkeypatch):
    # a package cannot read past the aggregate budget by shipping files that fail
    # to decode: the bytes read are charged even when decoding fails.
    monkeypatch.setattr(ingest, "AGGREGATE_MAX_BYTES", 2000)
    bad = bytes([0x81, 0x8D, 0x90]) * 400        # 1200 bytes, undecodable, no NUL
    files = {"SKILL.md": "---\nname: t\n---\n"}
    for i in range(4):
        files["f%d.md" % i] = bad
    root = make_package(files)
    pkg = ingest.build_package(str(root))
    assert any(e["reasonCode"] == "total_budget_exhausted" for e in pkg.ledger_exceptions)


def test_aggregate_byte_budget_bounds_memory(make_package, monkeypatch):
    monkeypatch.setattr(ingest, "AGGREGATE_MAX_BYTES", 2000)
    files = {"SKILL.md": "---\nname: t\n---\n"}
    for i in range(6):
        files["scripts/f%d.py" % i] = "x" * 1000
    root = make_package(files)
    pkg = ingest.build_package(str(root))
    # once the budget is hit, remaining bodies are skipped and logged
    assert any(e["reasonCode"] == "total_budget_exhausted" for e in pkg.ledger_exceptions)
    # retained text stays near the budget, not the full 6000+ chars
    total = sum(len(a.text or "") for a in pkg.artifacts)
    assert total <= ingest.AGGREGATE_MAX_BYTES + 1000


# --- inventory + ledger happy path ------------------------------------------
def test_normal_package_is_inventoried_with_a_clean_ledger(make_package):
    root = make_package(
        {"SKILL.md": "---\nname: t\nallowed-tools: Bash(curl:*)\n---\nbody\n"}
    )
    pkg = ingest.build_package(str(root))
    assert [a.rel for a in pkg.artifacts] == ["SKILL.md"]
    assert pkg.ledger_exceptions == []
    ledger = ingest.build_ledger(pkg)
    assert ledger["artifactsSeen"] == 1
    assert ledger["artifactsAnalyzed"] == 1
    assert ledger["coveragePercent"] == 100.0


def test_filenames_are_recorded_in_nfc(make_package):
    # macOS hands back NFD-decomposed filenames; Linux preserves the bytes. Create
    # an NFD name and assert the ledger records the NFC form, so normalization is
    # proven without a Mac.
    nfd = "cafe\u0301.md"          # c a f e + combining acute (NFD)
    root = make_package({nfd: "hi\n"})
    pkg = ingest.build_package(str(root))
    rels = [a.rel for a in pkg.artifacts]
    assert all(r == unicodedata.normalize("NFC", r) for r in rels)
    assert "caf\u00e9.md" in rels   # the NFD input surfaced as its NFC form


def test_discover_finds_packages_under_roots(tmp_path):
    # two skill packages, one nested, plus a non-skill dir that must be ignored
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "SKILL.md").write_text("---\nname: a\n---\n", encoding="utf-8")
    (tmp_path / "group" / "b").mkdir(parents=True)
    (tmp_path / "group" / "b" / "SKILL.md").write_text("---\nname: b\n---\n", encoding="utf-8")
    (tmp_path / "notaskill").mkdir()
    (tmp_path / "notaskill" / "README.md").write_text("hi", encoding="utf-8")
    found = ingest.discover_skill_packages([str(tmp_path)])
    assert len(found) == 2
    assert any(os.path.basename(p) == "a" for p in found)
    assert any(os.path.basename(p) == "b" for p in found)


def test_discover_skips_missing_roots():
    # a root that does not exist is silently skipped, not an error
    assert ingest.discover_skill_packages(["/no/such/skills/root/xyz"]) == []


def test_shipped_bytecode_is_inventoried_not_dropped(make_package):
    # a .pyc whose .py source is absent runs the same but is invisible to a
    # source-only scan, so it must be inventoried and surfaced, not swallowed.
    root = make_package({
        "SKILL.md": "---\nname: t\n---\n",
        "scripts/mod.cpython-313.pyc": b"\xcb\r\r\n\x00\x00payload",
    })
    pkg = ingest.build_package(str(root))
    pyc = [a for a in pkg.artifacts if a.rel == "scripts/mod.cpython-313.pyc"]
    assert pyc, "the .pyc was silently dropped"
    assert pyc[0].kind == "python_bytecode"
    assert pyc[0].role == "compiled"
    assert pyc[0].exception == "shipped_bytecode"
    assert pyc[0].text is None
    ledger = ingest.build_ledger(pkg)
    assert "scripts/mod.cpython-313.pyc" in ledger["shippedBytecode"]
    # text coverage stays honest (SKILL.md read) while the bytecode is surfaced
    assert ledger["coveragePercent"] == 100.0


def test_pyc_inside_pycache_is_seen_not_excluded(make_package):
    # __pycache__ is no longer a blanket exclusion; the bytecode inside is seen.
    root = make_package({
        "SKILL.md": "---\nname: t\n---\n",
        "scripts/__pycache__/util.cpython-313.pyc": b"\xcb\r\r\n\x00bytes",
    })
    pkg = ingest.build_package(str(root))
    assert not any(e["reasonCode"] == "excluded_dir" and e["path"].endswith("__pycache__")
                   for e in pkg.ledger_exceptions)
    ledger = ingest.build_ledger(pkg)
    assert any(p.endswith("util.cpython-313.pyc") for p in ledger["shippedBytecode"])


def test_agent_identity_files_are_first_class(make_package):
    # identity/memory files are the persistence write-target, so they must be a
    # distinct class a downstream check can find, not folded into generic docs.
    identity = ["CLAUDE.md", "AGENTS.md", "GEMINI.md", "SOUL.md", "MEMORY.md",
                "IDENTITY.md", ".cursorrules", "copilot-instructions.md",
                "references/AGENTS.md"]
    files = {"SKILL.md": "---\nname: t\n---\n", "README.md": "docs"}
    for n in identity:
        files[n] = "marker"
    pkg = ingest.build_package(str(make_package(files)))
    by_rel = {a.rel: a for a in pkg.artifacts}
    for rel in identity:
        assert by_rel[rel].kind == "agent_identity", rel
        assert by_rel[rel].role == "identity", rel
        assert by_rel[rel].text is not None, rel          # read, not skipped
    # a doc and the manifest are not swept into the identity class
    assert by_rel["README.md"].role == "documentation"
    assert by_rel["SKILL.md"].kind == "skill_manifest"


def test_agent_identity_match_is_case_insensitive(make_package):
    root = make_package({"SKILL.md": "---\nname: t\n---\n",
                         "claude.md": "x", "Agents.MD": "y"})
    kinds = {a.rel: a.kind for a in ingest.build_package(str(root)).artifacts}
    assert kinds["claude.md"] == "agent_identity"
    assert kinds["Agents.MD"] == "agent_identity"


def test_binary_asset_is_ledgered_not_counted_against_coverage(make_package):
    root = make_package({
        "SKILL.md": "---\nname: t\n---\n",
        "assets/logo.png": b"\x89PNG\r\n\x1a\n\x00\x00",
    })
    pkg = ingest.build_package(str(root))
    ledger = ingest.build_ledger(pkg)
    # the icon is inventoried and skipped, but the denominator excludes it so a
    # package that ships a logo still reports full coverage of its text.
    assert ledger["artifactsNotInspectable"] == 1
    assert ledger["coveragePercent"] == 100.0
    assert any(e["reasonCode"] == "binary_content" and e["path"] == "assets/logo.png"
               for e in pkg.ledger_exceptions)


# --- a skipped file lowers coverage -----------------------------------------
def test_symlinked_away_manifest_lowers_coverage(make_package, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("SECRET-OUTSIDE", encoding="utf-8")
    root = make_package({"notes.md": "just docs\n"})
    _symlink_or_skip(str(outside), str(root / "SKILL.md"))
    pkg = ingest.build_package(str(root))
    ledger = ingest.build_ledger(pkg)
    # the symlink skip is counted, so the scan is NOT a clean 100%
    assert ledger["artifactsFailedRead"] >= 1
    assert ledger["coveragePercent"] < 100.0


def test_nul_in_script_counts_as_failed_read_not_binary(make_package):
    # a script the walker could not read (NUL early in the buffer) must lower
    # coverage, not be excused as a binary asset the way an icon is.
    root = make_package({
        "SKILL.md": "---\nname: t\n---\n",
        "scripts/x.py": b"print(1)\x00payload",
    })
    pkg = ingest.build_package(str(root))
    ledger = ingest.build_ledger(pkg)
    assert ledger["artifactsNotInspectable"] == 0
    assert ledger["artifactsFailedRead"] == 1
    assert ledger["coveragePercent"] < 100.0


def test_all_binary_package_reports_full_coverage_not_zero(make_package):
    root = make_package({"assets/a.png": b"\x89PNG\r\n", "assets/b.ico": b"\x00\x01"})
    pkg = ingest.build_package(str(root))
    ledger = ingest.build_ledger(pkg)
    # nothing inspectable to fail on -> covered, not a 0% failure
    assert ledger["inspectableDenominator"] == 0
    assert ledger["coveragePercent"] == 100.0


def test_excluded_dir_does_not_lower_coverage(make_package):
    root = make_package({
        "SKILL.md": "---\nname: t\n---\nbody\n",
        ".git/config": "x",
    })
    pkg = ingest.build_package(str(root))
    ledger = ingest.build_ledger(pkg)
    # an excluded cache dir is benign; it is logged but does not penalise coverage
    assert ledger["coveragePercent"] == 100.0
    assert any(e["reasonCode"] == "excluded_dir" and e["path"] == ".git"
               for e in pkg.ledger_exceptions)
