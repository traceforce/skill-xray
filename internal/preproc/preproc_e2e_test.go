package preproc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// The tests/test_preproc.py literals run through the real pipeline, as _findings and
// _package_findings do there. The fallback-path cases (_MD.parse monkeypatch) are parse's
// (parse.md §6); test_preprocessing_check_is_registered is ported in internal/checks.

const fm = "---\nname: demo\n---\n"

func parsed(t *testing.T, files map[string]string) *parse.Package {
	return parse.Parse(ingest.BuildPackage(testutil.MakePackage(t, files)))
}

func run(t *testing.T, files map[string]string) []findings.Finding { return Check(parsed(t, files)) }

func skill(t *testing.T, body string) []findings.Finding {
	return run(t, map[string]string{"SKILL.md": body})
}

type e2eCase struct {
	name  string
	files map[string]string
	want  []loc
}

func TestE2ELocations(t *testing.T) {
	cases := []e2eCase{
		// test_inline_preprocessing_reports_exact_location_and_evidence (location half)
		{"exact_location", map[string]string{"SKILL.md": fm + "intro\nrun !`whoami` now\n"}, []loc{{"SXV-001", "SKILL.md", 5, 5}}},
		// test_preprocessing_in_loaded_document_is_detected
		{"loaded_document", map[string]string{"SKILL.md": fm + "See [README](README.md).\n", "README.md": "setup !`whoami`\n"},
			[]loc{{"SXV-001", "README.md", 1, 7}}},
		// test_inline_preprocessing_in_frontmatter_uses_raw_file_location
		{"frontmatter_location", map[string]string{"SKILL.md": "---\nname: demo\ndescription: run !`whoami`\n---\n# Demo\n"}, []loc{{"SXV-001", "SKILL.md", 3, 18}}},
		// test_inline_preprocessing_uses_normalized_crlf_location
		{"crlf", map[string]string{"SKILL.md": "---\r\nname: demo\r\n---\r\ntext\r\n  !`id`\r\n"}, []loc{{"SXV-001", "SKILL.md", 5, 3}}},
		// test_unmatched_multibacktick_run_cannot_suppress_later_preprocessing
		{"unmatched_run", map[string]string{"SKILL.md": fm + "`` open\n!`id`\n"}, []loc{{"SXV-001", "SKILL.md", 5, 1}}},
		// test_bang_fence_reports_nonempty_commands (location half)
		{"bang_fence", map[string]string{"SKILL.md": fm + "```!sh\necho first\nid\n```\n"}, []loc{{"SXV-002", "SKILL.md", 4, 1}}},
		// test_blockquoted_bang_fence_reports_source_column
		{"blockquoted_fence", map[string]string{"SKILL.md": fm + "> ```!sh\n> id\n> ```\n"}, []loc{{"SXV-002", "SKILL.md", 4, 3}}},
		// test_unicode_separator_does_not_shift_bang_fence_column
		{"u2028_fence", map[string]string{"SKILL.md": fm + "text still one source line\n  ```!sh\n  id\n  ```\n"}, []loc{{"SXV-002", "SKILL.md", 5, 3}}},
		// test_tilde_bang_fence_is_executable
		{"tilde_fence", map[string]string{"SKILL.md": fm + "~~~!bash\nid\n~~~\n"}, []loc{{"SXV-002", "SKILL.md", 4, 1}}},
		// test_indented_bang_fence_preserves_opener_column
		{"indented_fence", map[string]string{"SKILL.md": fm + "  ```!\n  id\n  ```\n"}, []loc{{"SXV-002", "SKILL.md", 4, 3}}},
		// test_multiple_preprocessing_forms_are_independent
		{"both_forms", map[string]string{"SKILL.md": fm + "!`id`\n```!\necho live\n```\n"}, []loc{{"SXV-001", "SKILL.md", 4, 1}, {"SXV-002", "SKILL.md", 5, 1}}},
		// test_frontmatter_yaml_scalar_is_not_suppressed_as_markdown_example
		{"yaml_scalar_fence", map[string]string{"SKILL.md": "---\nname: demo\ndescription: |\n  ```bash\n  !`id`\n  ```\n---\nbody\n"}, []loc{{"SXV-001", "SKILL.md", 5, 3}}},
		// test_disposition.py::test_ir_unicode_column_is_not_an_opengrep_byte_column
		{"emoji_column", map[string]string{"SKILL.md": "---\nname: test\n---\n😀 !`echo test`\n"}, []loc{{"SXV-001", "SKILL.md", 4, 3}}},
	}
	// test_preprocessing_in_loaded_identity_is_detected
	for _, identity := range []string{"AGENTS.md", "CLAUDE.md", ".cursorrules"} {
		cases = append(cases, e2eCase{"identity_" + identity, map[string]string{"SKILL.md": fm + "# Demo\n", identity: "run !`whoami` now\n"}, []loc{{"SXV-001", identity, 1, 5}}})
	}
	// test_unicode_whitespace_is_a_live_boundary
	for _, space := range []string{" ", " "} {
		cases = append(cases, e2eCase{fmt.Sprintf("space_%U", []rune(space)[0]), map[string]string{"SKILL.md": fm + space + "!`id`\n"}, []loc{{"SXV-001", "SKILL.md", 4, 2}}})
	}
	// test_bang_fence_variants_preserve_opener_location
	for opener, column := range map[string]int{"```!sh extra": 1, "   ```!sh": 4, "~~~!bash extra": 1} {
		cases = append(cases, e2eCase{"opener_" + opener, map[string]string{"SKILL.md": fm + opener + "\nid\n"}, []loc{{"SXV-002", "SKILL.md", 4, column}}})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { assert.Equal(t, c.want, locs(run(t, c.files))) })
	}
}

func TestE2EInert(t *testing.T) {
	files := map[string]map[string]string{}
	// test_unreferenced_document_preprocessing_is_inert
	for _, document := range []string{"README.md", "CHANGELOG.md", "LICENSE.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md"} {
		files["unreferenced_"+document] = map[string]string{"SKILL.md": fm + "# Demo\n", document: "documented example !`whoami`\n"}
	}
	// test_non_boundary_inline_preprocessing_is_a_decoy
	for _, prefix := range []string{"x", "=", "\\", "\u200b"} {
		files["decoy_"+prefix] = map[string]string{"SKILL.md": fm + prefix + "!`whoami`\n"}
	}
	// test_inline_preprocessing_inside_code_examples_is_inert
	// test_non_executable_examples_do_not_report
	for i, body := range []string{
		"```bash\n!`id`\n```\n", "~~~bash\n!`id`\n~~~\n", "Example: `` !`id` ``\n",
		"```bash\necho example\n```\n", "```!sh\n\n```\n", "prose showing `!command` as documentation\n",
	} {
		files[fmt.Sprintf("example_%d", i)] = map[string]string{"SKILL.md": fm + body}
	}
	// test_empty_preprocessing_constructs_do_not_create_cap_notes
	files["empty_constructs"] = map[string]string{"SKILL.md": fm +
		strings.Repeat("!`   `\n", findings.Cap+3) + strings.Repeat("```!sh\n\n```\n", findings.Cap+3)}
	for name, f := range files {
		t.Run(name, func(t *testing.T) { assert.Empty(t, run(t, f)) })
	}
}

// test_inline_preprocessing_reports_exact_location_and_evidence
// test_repeated_inline_preprocessing_preserves_each_column
// test_inline_evidence_preserves_command_whitespace
// test_preprocessing_finding_serialization_keeps_location_contract
func TestE2EInlineEvidence(t *testing.T) {
	fs := skill(t, fm+"intro\nrun !`whoami` now\n")
	require.Len(t, fs, 1)
	assert.Equal(t, []any{"SXV-001", "preproc-inline-bang", "critical", "SKILL.md", 5},
		[]any{fs[0].Vector, fs[0].Rule, fs[0].Severity, fs[0].Path, *fs[0].Line})
	assert.Equal(t, map[string]any{"command_text": "whoami", "column": 5, "fence_state": "outside"},
		map[string]any{"command_text": fs[0].Evidence["command_text"], "column": fs[0].Evidence["column"], "fence_state": fs[0].Evidence["fence_state"]})

	fs = skill(t, fm+"!`id` then !`id`\n")
	assert.Equal(t, []loc{{"SXV-001", "SKILL.md", 4, 1}, {"SXV-001", "SKILL.md", 4, 12}}, locs(fs))
	for _, f := range fs {
		assert.Nil(t, f.Offset)
	}
	assert.Len(t, findings.Dedupe(fs), 2)

	fs = skill(t, fm+"!`  printf x  `\n")
	require.Len(t, fs, 1)
	assert.Equal(t, "  printf x  ", fs[0].Evidence["command_text"])

	fs = skill(t, fm+"run !`id`\n")
	require.Len(t, fs, 1)
	d := fs[0].ToMap()
	assert.Equal(t, []any{"SXV-001", "SKILL.md", 4, 5, "id"},
		[]any{d["vector"], d["path"], d["line"], d["column"], d["evidence"].(map[string]any)["command_text"]})
}

// test_bang_fence_reports_nonempty_commands
// test_bang_fence_preserves_indentation_and_internal_blank_lines
func TestE2EFencedEvidence(t *testing.T) {
	fs := skill(t, fm+"```!sh\necho first\nid\n```\n")
	require.Len(t, fs, 1)
	assert.Equal(t, []string{"echo first", "id"}, fs[0].Evidence["command_text"])
	assert.Equal(t, "!sh", fs[0].Evidence["fence_info"])
	assert.Equal(t, 2, fs[0].Evidence["block_line_count"])

	fs = skill(t, fm+"```!python\nif True:\n    print('x')\n\nprint('done')\n```\n")
	require.Len(t, fs, 1)
	assert.Equal(t, []string{"if True:", "    print('x')", "", "print('done')"}, fs[0].Evidence["command_text"])
}

func capNotes(fs []findings.Finding, contains string) (n int) {
	for _, f := range fs {
		if f.Rule == "findings-capped" && f.Path == "SKILL.md" && strings.Contains(f.Message, contains) {
			n++
		}
	}
	return n
}

// test_preprocessing_findings_are_capped_with_visible_note
// test_frontmatter_and_body_share_one_inline_cap
// test_frontmatter_decoys_cannot_crowd_out_live_body_preprocessing
// test_fenced_preprocessing_ir_and_findings_are_capped
// test_preprocessing_ir_and_evidence_are_bounded
func TestE2ECaps(t *testing.T) {
	var lines []string
	for i := range findings.Cap + 3 {
		lines = append(lines, fmt.Sprintf("!`command-%d`", i))
	}
	fs := skill(t, fm+strings.Join(lines, "\n"))
	assert.Len(t, testutil.ByVector(fs, "SXV-001"), findings.Cap)
	assert.Equal(t, 1, capNotes(fs, "3 more SXV-001 findings"))

	var front, body []string
	for i := range findings.Cap {
		front = append(front, fmt.Sprintf("field%d: run !`front-%d`", i, i))
		body = append(body, fmt.Sprintf("!`body-%d`", i))
	}
	fs = skill(t, fmt.Sprintf("---\n%s\n---\n%s\n", strings.Join(front, "\n"), strings.Join(body, "\n")))
	inline := testutil.ByVector(fs, "SXV-001")
	assert.Len(t, inline, findings.Cap)
	for _, f := range inline {
		assert.True(t, strings.HasPrefix(f.Evidence["command_text"].(string), "front-"))
	}
	assert.Equal(t, 1, capNotes(fs, "25 more SXV-001"))

	var decoys []string
	for i := range findings.Cap {
		decoys = append(decoys, fmt.Sprintf("field%d: x!`decoy-%d`", i, i))
	}
	fs = skill(t, fmt.Sprintf("---\n%s\n---\n!`real-command`\n", strings.Join(decoys, "\n")))
	require.Len(t, fs, 1)
	assert.Equal(t, []any{"SXV-001", "real-command"}, []any{fs[0].Vector, fs[0].Evidence["command_text"]})

	var fences strings.Builder
	for i := range findings.Cap + 3 {
		fmt.Fprintf(&fences, "```!sh\necho %d\n```\n", i)
	}
	p := parsed(t, map[string]string{"SKILL.md": fm + fences.String()})
	kept := 0
	for _, tok := range p.ByRel["SKILL.md"].Preprocessing {
		if tok.Kind == "fenced" {
			kept++
		}
	}
	assert.Equal(t, findings.Cap, kept)
	fs = Check(p)
	assert.Len(t, testutil.ByVector(fs, "SXV-002"), findings.Cap)
	assert.Equal(t, 1, capNotes(fs, "3 more SXV-002"))

	var commands []string
	for i := range 100 {
		commands = append(commands, fmt.Sprintf("!`%s-%d`", strings.Repeat("x", 1000), i))
	}
	p = parsed(t, map[string]string{"SKILL.md": fm + strings.Join(commands, "\n") + "\n"})
	assert.Len(t, p.ByRel["SKILL.md"].Preprocessing, findings.Cap)
	fs = testutil.ByVector(Check(p), "SXV-001")
	assert.Len(t, fs, findings.Cap)
	for _, f := range fs {
		assert.LessOrEqual(t, len(f.Evidence["command_text"].(string)), 400)
		assert.Less(t, len(f.Evidence["selector"].(string)), 100)
		assert.Equal(t, true, f.Evidence["truncated"])
	}
}

// test_parser_and_output_caps_share_one_contract
func TestParserAndOutputCapsShareOneContract(t *testing.T) {
	assert.Equal(t, findings.Cap, parse.MaxPreprocTokens)
}
