"""Checks for the Python side of the parity harness (run with PYTHONPATH=<oracle>/src)."""

import hashlib
import json

import msb_materialize
import pytest
import pytest_dump_corpus

parse = pytest.importorskip("skill_xray.parse")
py_dump_ir = pytest.importorskip("py_dump_ir")

IR_FIELDS = sorted("""rel kind text_sha256 raw_sha256 frontmatter frontmatter_keys
    frontmatter_key_lines frontmatter_end_line unsafe_yaml_tags grants fences fence_spans code_spans
    prose_spans reference_spans paragraph_spans links fallback_links html_comments html_prose
    html_uninspectable has_html has_uninspectable_html preprocessing preprocessing_counts config
    manifest_kind deps diagnostics refs""".split())


def test_slug_is_short_stable_and_collision_free():
    a = pytest_dump_corpus.slug("tests/test_x.py::test_y[\u00e9]")
    b = pytest_dump_corpus.slug("tests/test_x.py::test_y[\u00e0]")
    assert a != b and a.startswith("test_x.py_test_y-") and len(a) <= 89
    assert pytest_dump_corpus.slug("tests/test_x.py::test_y[\u00e9]") == a


def test_package_dir_matches_msb_run_scan_one():
    bid = "ASB04/000 018:" + "x" * 50
    stem = ("ASB04_000_018_" + "x" * 50)[:40]
    assert msb_materialize.package_dir(bid) == \
        stem + "-" + hashlib.sha1(bid.encode("utf-8")).hexdigest()[:10]
    assert msb_materialize.package_dir("ASB04_000018") == "ASB04_000018-" + \
        hashlib.sha1(b"ASB04_000018").hexdigest()[:10]


def test_measure_counts_regular_files_only(tmp_path):
    (tmp_path / "pkg" / "a").mkdir(parents=True)
    (tmp_path / "pkg" / "SKILL.md").write_bytes(b"12345")
    (tmp_path / "pkg" / "a" / "b.py").write_bytes(b"xy")
    assert pytest_dump_corpus.measure(str(tmp_path / "pkg")) == (2, 7)
    pytest_dump_corpus.copy_tree(str(tmp_path / "pkg"), str(tmp_path / "copy"))
    assert (tmp_path / "copy" / "a" / "b.py").read_bytes() == b"xy"


def test_dump_ir_covers_every_field_and_tags_config(tmp_path):
    root = tmp_path / "pkg"
    (root / "scripts").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: t\nallowed-tools: Bash(ls *)\n---\n# T\n\n[doc](README.md)\n\n"
        "```bash\nls\n```\n",
        encoding="utf-8", newline="")
    (root / "README.md").write_text("readme\n", encoding="utf-8")
    (root / "scripts" / "a.py").write_text("def f(:\n", encoding="utf-8")
    (root / "hooks.json").write_text('{"n": 1, "f": 1.5, "b": true, "l": [null, "s"]}',
                                     encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\ndependencies = ['requests==2.0']\n",
                                         encoding="utf-8")
    (root / "package.json").write_text("{not json", encoding="utf-8")
    docs = {d["rel"]: d for d in py_dump_ir.dump(str(root))}
    assert set(docs) == {"SKILL.md", "README.md", "scripts/a.py", "hooks.json", "pyproject.toml",
                         "package.json"}
    for d in docs.values():
        assert sorted(d) == IR_FIELDS
        json.dumps(d, sort_keys=True, default=py_dump_ir._default)
    skill = docs["SKILL.md"]
    assert skill["frontmatter_keys"] == ["name", "allowed-tools"]
    assert skill["grants"][0]["tool"] == "Bash" and skill["fences"][0]["info"] == "bash"
    assert skill["refs"] == [{"from": "SKILL.md", "to": "README.md", "line": 7}]
    assert docs["scripts/a.py"]["diagnostics"] == [["python_syntax_error", "line 1"]]
    assert docs["package.json"]["diagnostics"] == [["config_parse_error", True]]
    assert docs["hooks.json"]["config"] == ["dict", {
        "n": ["int", 1], "f": ["float", 1.5], "b": ["bool", True],
        "l": ["list", [["NoneType", None], ["str", "s"]]]}]
    assert docs["pyproject.toml"]["deps"][0]["pinned"] is True
    assert docs["README.md"]["text_sha256"] == hashlib.sha256(b"readme\n").hexdigest()
