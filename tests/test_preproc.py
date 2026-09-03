"""Contract tests for load-time preprocessing findings (SXV-001/002)."""

from __future__ import annotations

import time

import pytest

from skill_xray import ingest, parse
from skill_xray.checks import preproc, run_checks
from skill_xray.findings import FINDING_CAP, dedupe_findings, findings_to_dicts


def _findings(make_package, body):
    package = ingest.build_package(str(make_package({"SKILL.md": body})))
    parsed = parse.parse_package(package)
    return preproc.check(parsed)


def _package_findings(make_package, files):
    package = ingest.build_package(str(make_package(files)))
    parsed = parse.parse_package(package)
    return preproc.check(parsed)


def test_inline_preprocessing_reports_exact_location_and_evidence(make_package):
    findings = _findings(make_package, "---\nname: demo\n---\nintro\nrun !`whoami` now\n")

    assert len(findings) == 1
    finding = findings[0]
    assert (finding.vector, finding.rule, finding.severity, finding.path, finding.line) == (
        "SXV-001", "preproc-inline-bang", "critical", "SKILL.md", 5)
    assert finding.evidence["command_text"] == "whoami"
    assert finding.evidence["column"] == 5
    assert finding.evidence["fence_state"] == "outside"


def test_preprocessing_check_is_registered(make_package):
    package = ingest.build_package(str(make_package({
        "SKILL.md": "---\nname: demo\n---\n!`id`\n",
    })))
    findings = run_checks(parse.parse_package(package))
    assert any(f.vector == "SXV-001" for f in findings)


def test_repeated_inline_preprocessing_preserves_each_column(make_package):
    findings = _findings(make_package, "---\nname: demo\n---\n!`id` then !`id`\n")

    assert [(f.line, f.evidence["column"]) for f in findings] == [(4, 1), (4, 12)]
    assert [f.column for f in findings] == [1, 12]
    assert all(f.offset is None for f in findings)
    assert len(dedupe_findings(findings)) == 2


def test_inline_evidence_preserves_command_whitespace(make_package):
    [finding] = _findings(make_package, "---\nname: demo\n---\n!`  printf x  `\n")
    assert finding.evidence["command_text"] == "  printf x  "


def test_preprocessing_in_loaded_document_is_detected(make_package):
    package = ingest.build_package(str(make_package({
        "SKILL.md": "---\nname: demo\n---\nSee [README](README.md).\n",
        "README.md": "setup !`whoami`\n",
    })))

    findings = [
        f for f in preproc.check(parse.parse_package(package)) if f.vector == "SXV-001"
    ]
    assert [(f.path, f.line, f.evidence["column"]) for f in findings] == [
        ("README.md", 1, 7)
    ]


@pytest.mark.parametrize("identity", ["AGENTS.md", "CLAUDE.md", ".cursorrules"])
def test_preprocessing_in_loaded_identity_is_detected(make_package, identity):
    findings = _package_findings(make_package, {
        "SKILL.md": "---\nname: demo\n---\n# Demo\n",
        identity: "run !`whoami` now\n",
    })
    assert [(f.vector, f.path, f.line, f.column) for f in findings] == [
        ("SXV-001", identity, 1, 5),
    ]


@pytest.mark.parametrize("document", [
    "README.md", "CHANGELOG.md", "LICENSE.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md",
])
def test_unreferenced_document_preprocessing_is_inert(make_package, document):
    findings = _package_findings(make_package, {
        "SKILL.md": "---\nname: demo\n---\n# Demo\n",
        document: "documented example !`whoami`\n",
    })
    assert findings == []


def test_inline_preprocessing_in_frontmatter_uses_raw_file_location(make_package):
    findings = _findings(
        make_package, "---\nname: demo\ndescription: run !`whoami`\n---\n# Demo\n")
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-001", 3, 18)]


@pytest.mark.parametrize("prefix", ["x", "=", "\\", "\u200b"])
def test_non_boundary_inline_preprocessing_is_a_decoy(make_package, prefix):
    assert _findings(make_package, f"---\nname: demo\n---\n{prefix}!`whoami`\n") == []


def test_inline_preprocessing_uses_normalized_crlf_location(make_package):
    findings = _findings(
        make_package, "---\r\nname: demo\r\n---\r\ntext\r\n  !`id`\r\n")

    assert len(findings) == 1
    assert findings[0].line == 5
    assert findings[0].column == 3
    assert findings[0].offset is None
    assert findings[0].evidence["column"] == 3


@pytest.mark.parametrize("space", ["\u00a0", "\u2003"])
def test_unicode_whitespace_is_a_live_boundary(make_package, space):
    findings = _findings(make_package, "---\nname: demo\n---\n%s!`id`\n" % space)
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-001", 4, 2)]


@pytest.mark.parametrize("body", [
    "```bash\n!`id`\n```\n",
    "~~~bash\n!`id`\n~~~\n",
    "Example: `` !`id` ``\n",
])
def test_inline_preprocessing_inside_code_examples_is_inert(make_package, body):
    assert _findings(make_package, "---\nname: demo\n---\n" + body) == []


def test_unmatched_multibacktick_run_cannot_suppress_later_preprocessing(make_package):
    body = "Unmatched documentation marker: ``\n!`id`\n"
    findings = _findings(make_package, "---\nname: demo\n---\n" + body)
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-001", 5, 1)]


def test_code_span_delimiters_in_other_list_items_cannot_suppress_preprocessing(
    make_package,
):
    body = "- ``\n- !`id`\n- ``\n"
    findings = _findings(make_package, "---\nname: demo\n---\n" + body)
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-001", 5, 3)]


def test_table_cell_preprocessing_example_is_inert(make_package):
    body = "| behavior | example |\n| --- | --- |\n| does not execute | !`id` |\n"
    assert _findings(make_package, "---\nname: demo\n---\n" + body) == []


def test_one_column_table_preprocessing_example_is_inert(make_package):
    body = "| example |\n| --- |\n| !`id` |\n"
    assert _findings(make_package, "---\nname: demo\n---\n" + body) == []


def test_escaped_pipe_prose_cannot_suppress_live_preprocessing(make_package):
    body = "heading \\| text\n--- | ---\nrun | !`id`\n"
    findings = _findings(make_package, "---\nname: demo\n---\n" + body)
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-001", 6, 7)]


def test_table_classification_is_linear_on_hostile_divider_input():
    lines = ["| --- | --- |"] * 8000
    started = time.perf_counter()
    parse._table_lines(lines)
    assert time.perf_counter() - started < 1.0


def test_pipe_prose_before_table_remains_executable(make_package):
    body = "run | !`id`\n| behavior | example |\n| --- | --- |\n| inert | text |\n"
    findings = _findings(make_package, "---\nname: demo\n---\n" + body)
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-001", 4, 7)]


def test_indented_code_block_preprocessing_is_inert(make_package):
    body = "    !`id`\n\nnext paragraph\n"
    assert _findings(make_package, "---\nname: demo\n---\n" + body) == []


def test_tab_indented_code_block_preprocessing_is_inert(make_package):
    assert _findings(make_package, "---\nname: demo\n---\n\t!`id`\n") == []


@pytest.mark.parametrize("body", [
    "- Run the required setup:\n    !`id`\n",
    "  - Nested setup:\n      !`id`\n",
])
def test_list_continuation_preprocessing_remains_executable(make_package, body):
    findings = _findings(make_package, "---\nname: demo\n---\n" + body)
    assert [(f.vector, f.evidence["command_text"]) for f in findings] == [
        ("SXV-001", "id"),
    ]


def test_indented_code_cannot_crowd_real_preprocessing_out_of_cap(make_package):
    examples = "\n\n".join("    !`example-%d`" % i for i in range(FINDING_CAP))
    body = examples + "\n\n!`real-command`\n"
    findings = _findings(make_package, "---\nname: demo\n---\n" + body)
    assert [(f.vector, f.evidence["command_text"]) for f in findings] == [
        ("SXV-001", "real-command"),
    ]


def test_bang_fence_reports_nonempty_commands(make_package):
    findings = _findings(
        make_package, "---\nname: demo\n---\n```!sh\necho first\nid\n```\n")

    assert len(findings) == 1
    finding = findings[0]
    assert (finding.vector, finding.rule, finding.severity, finding.path, finding.line) == (
        "SXV-002", "preproc-fenced-bang", "critical", "SKILL.md", 4)
    assert finding.evidence["command_text"] == ["echo first", "id"]
    assert finding.evidence["fence_info"] == "!sh"
    assert finding.evidence["block_line_count"] == 2


def test_bang_fence_preserves_indentation_and_internal_blank_lines(make_package):
    body = "```!python\nif True:\n    print('x')\n\nprint('done')\n```\n"
    [finding] = _findings(make_package, "---\nname: demo\n---\n" + body)
    assert finding.evidence["command_text"] == [
        "if True:", "    print('x')", "", "print('done')",
    ]


def test_blockquoted_bang_fence_reports_source_column(make_package):
    body = "> ```!sh\n> id\n> ```\n"
    findings = _findings(make_package, "---\nname: demo\n---\n" + body)
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-002", 4, 3)]


def test_unicode_separator_does_not_shift_bang_fence_column(make_package):
    body = "text\u2028still one source line\n  ```!sh\n  id\n  ```\n"
    findings = _findings(make_package, "---\nname: demo\n---\n" + body)
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-002", 5, 3)]


@pytest.mark.parametrize(("opener", "column"), [
    ("```!sh extra", 1),
    ("   ```!sh", 4),
    ("~~~!bash extra", 1),
])
def test_bang_fence_variants_preserve_opener_location(make_package, opener, column):
    findings = _findings(make_package, "---\nname: demo\n---\n%s\nid\n" % opener)
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-002", 4, column)]


def test_tilde_bang_fence_is_executable(make_package):
    findings = _findings(make_package, "---\nname: demo\n---\n~~~!bash\nid\n~~~\n")
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-002", 4, 1)]


def test_indented_bang_fence_preserves_opener_column(make_package):
    findings = _findings(
        make_package, "---\nname: demo\n---\n  ```!\n  id\n  ```\n")

    assert len(findings) == 1
    assert findings[0].column == 3
    assert findings[0].evidence["column"] == 3


@pytest.mark.parametrize("body", [
    "```bash\necho example\n```\n",
    "```!sh\n\n```\n",
    "prose showing `!command` as documentation\n",
])
def test_non_executable_examples_do_not_report(make_package, body):
    assert _findings(make_package, "---\nname: demo\n---\n" + body) == []


def test_multiple_preprocessing_forms_are_independent(make_package):
    findings = _findings(
        make_package,
        "---\nname: demo\n---\n!`id`\n```!\necho live\n```\n",
    )

    assert [(f.vector, f.line) for f in findings] == [("SXV-001", 4), ("SXV-002", 5)]


def test_preprocessing_findings_are_capped_with_visible_note(make_package):
    body = "---\nname: demo\n---\n" + "\n".join(
        "!`command-%d`" % index for index in range(FINDING_CAP + 3)
    )
    package = ingest.build_package(str(make_package({"SKILL.md": body})))
    findings = preproc.check(parse.parse_package(package))

    assert len([f for f in findings if f.vector == "SXV-001"]) == FINDING_CAP
    notes = [f for f in findings if f.rule == "findings-capped" and f.path == "SKILL.md"]
    assert len(notes) == 1
    assert "3 more SXV-001 findings" in notes[0].message


def test_frontmatter_and_body_share_one_inline_cap(make_package):
    frontmatter = "\n".join(
        "field%d: run !`front-%d`" % (index, index) for index in range(FINDING_CAP)
    )
    body = "\n".join("!`body-%d`" % index for index in range(FINDING_CAP))
    package = ingest.build_package(str(make_package({
        "SKILL.md": "---\n%s\n---\n%s\n" % (frontmatter, body),
    })))
    parsed = parse.parse_package(package)
    findings = preproc.check(parsed)

    inline = [f for f in findings if f.vector == "SXV-001"]
    assert len(inline) == FINDING_CAP
    assert all(f.evidence["command_text"].startswith("front-") for f in inline)
    assert any(f.rule == "findings-capped" and "25 more SXV-001" in f.message
               for f in findings)


def test_frontmatter_decoys_cannot_crowd_out_live_body_preprocessing(make_package):
    decoys = "\n".join("field%d: x!`decoy-%d`" % (i, i) for i in range(FINDING_CAP))
    findings = _findings(
        make_package, "---\n%s\n---\n!`real-command`\n" % decoys,
    )
    assert [(f.vector, f.evidence["command_text"]) for f in findings] == [
        ("SXV-001", "real-command"),
    ]


def test_frontmatter_yaml_scalar_is_not_suppressed_as_markdown_example(make_package):
    body = "---\nname: demo\ndescription: |\n  ```bash\n  !`id`\n  ```\n---\nbody\n"
    findings = _findings(make_package, body)
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-001", 5, 3)]


def test_fenced_preprocessing_ir_and_findings_are_capped(make_package):
    fences = "".join("```!sh\necho %d\n```\n" % i for i in range(FINDING_CAP + 3))
    package = ingest.build_package(str(make_package({
        "SKILL.md": "---\nname: demo\n---\n" + fences,
    })))
    parsed = parse.parse_package(package)
    findings = preproc.check(parsed)

    assert len([t for t in parsed.by_rel["SKILL.md"].preprocessing if t.kind == "fenced"]) \
        == FINDING_CAP
    assert len([f for f in findings if f.vector == "SXV-002"]) == FINDING_CAP
    assert any(f.rule == "findings-capped" and "3 more SXV-002" in f.message
               for f in findings)


def test_inline_preprocessing_survives_markdown_parser_failure(make_package, monkeypatch):
    def fail_parse(*_args, **_kwargs):
        raise MemoryError

    monkeypatch.setattr(parse._MD, "parse", fail_parse)
    findings = _findings(make_package, "---\nname: demo\n---\nrun !`id`\n")
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-001", 4, 5)]


def test_frontmatter_preprocessing_survives_markdown_parser_failure(
    make_package, monkeypatch,
):
    monkeypatch.setattr(parse._MD, "parse", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        MemoryError,
    ))
    body = "---\nname: demo\ndescription: |\n  ```bash\n  !`id`\n  ```\n---\nbody\n"
    findings = _findings(make_package, body)
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-001", 5, 3)]


def test_fenced_preprocessing_survives_markdown_parser_failure(make_package, monkeypatch):
    monkeypatch.setattr(parse._MD, "parse", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        MemoryError,
    ))
    body = "---\nname: demo\n---\n```!sh\nid\n```\n"
    findings = _findings(make_package, body)
    assert [(f.vector, f.line, f.column) for f in findings] == [("SXV-002", 4, 1)]


def test_preprocessing_ir_and_evidence_are_bounded(make_package):
    commands = "\n".join("!`%s-%d`" % ("x" * 1000, index) for index in range(100))
    package = ingest.build_package(str(make_package({
        "SKILL.md": "---\nname: demo\n---\n" + commands + "\n",
    })))
    parsed = parse.parse_package(package)
    artifact = parsed.by_rel["SKILL.md"]
    findings = [f for f in preproc.check(parsed) if f.vector == "SXV-001"]

    assert len(artifact.preprocessing) == FINDING_CAP
    assert len(findings) == FINDING_CAP
    assert all(len(f.evidence["command_text"]) <= 400 for f in findings)
    assert all(len(f.evidence["selector"]) < 100 for f in findings)
    assert all(f.evidence["truncated"] is True for f in findings)


def test_preprocessing_finding_serialization_keeps_location_contract(make_package):
    [finding] = _findings(make_package, "---\nname: demo\n---\nrun !`id`\n")
    [serialized] = findings_to_dicts([finding])
    assert (serialized["vector"], serialized["path"], serialized["line"],
            serialized["column"], serialized["evidence"]["command_text"]) == (
        "SXV-001", "SKILL.md", 4, 5, "id",
    )


def test_parser_and_output_caps_share_one_contract():
    assert parse.MAX_PREPROC_TOKENS == FINDING_CAP


def test_empty_preprocessing_constructs_do_not_create_cap_notes(make_package):
    inline = "\n".join("!`   `" for _ in range(FINDING_CAP + 3))
    fenced = "".join("```!sh\n\n```\n" for _ in range(FINDING_CAP + 3))
    package = ingest.build_package(str(make_package({
        "SKILL.md": "---\nname: demo\n---\n" + inline + "\n" + fenced,
    })))
    findings = preproc.check(parse.parse_package(package))
    assert not any(f.vector in {"SXV-001", "SXV-002"} or f.rule == "findings-capped"
                   for f in findings)
