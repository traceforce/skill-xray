package preproc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// The IR below is what parse.Parse yields for the tests/test_preproc.py packages cited on each
// case (token lines, columns and counts verified on the oracle); preproc_e2e_test.go runs the
// same literals through the real pipeline.

func pkg(refs []parse.Ref, arts ...*parse.Artifact) *parse.Package {
	p := &parse.Package{Artifacts: arts, ByRel: map[string]*parse.Artifact{}, Refs: refs}
	for _, a := range arts {
		p.ByRel[a.Rel] = a
	}
	return p
}

func manifest(rel string, toks ...parse.Preproc) *parse.Artifact {
	return &parse.Artifact{Rel: rel, Kind: "skill_manifest", Preprocessing: toks}
}

func inline(code string, line, column int, runs bool) parse.Preproc {
	return parse.Preproc{Kind: "inline", Code: code, Line: line, Column: column, Runs: runs}
}

func fenced(code, info string, line, column int) parse.Preproc {
	return parse.Preproc{Kind: "fenced", Code: code, Line: line, Column: column, Runs: true, Info: info}
}

type loc struct {
	vector, path string
	line, column int
}

func locs(fs []findings.Finding) []loc {
	out := []loc{}
	for _, f := range fs {
		out = append(out, loc{f.Vector, f.Path, *f.Line, *f.Column})
	}
	return out
}

// test_preproc.py::test_inline_preprocessing_reports_exact_location_and_evidence
// test_preproc.py::test_preprocessing_finding_serialization_keeps_location_contract
func TestInlineFindingLocationAndEvidence(t *testing.T) {
	fs := Check(pkg(nil, manifest("SKILL.md", inline("whoami", 5, 5, true))))
	require.Len(t, fs, 1)
	f := fs[0]
	assert.Equal(t, findings.Finding{
		Vector: "SXV-001", Rule: "preproc-inline-bang", Severity: "critical", Path: "SKILL.md",
		Line: findings.Int(5), Column: findings.Int(5),
		Message: "inline preprocessing executes `whoami` while loading the skill, before its instructions are evaluated",
		Evidence: map[string]any{
			"command_text": "whoami", "command_length": 6,
			"command_sha256": "f25297859cf0a70af5c053a5464a5fa647a35ceee1d91397331903846d79ffc1",
			"truncated":      false, "column": 5, "fence_state": "outside", "selector": "inline-bang:f25297859cf0",
		},
	}, f)
	d := f.ToMap()
	assert.Equal(t, []any{"SXV-001", "SKILL.md", 5, 5, "whoami"},
		[]any{d["vector"], d["path"], d["line"], d["column"], d["evidence"].(map[string]any)["command_text"]})
}

// test_preproc.py::test_repeated_inline_preprocessing_preserves_each_column
func TestRepeatedInlinePreservesEachColumn(t *testing.T) {
	fs := Check(pkg(nil, manifest("SKILL.md", inline("id", 4, 1, true), inline("id", 4, 12, true))))
	assert.Equal(t, []loc{{"SXV-001", "SKILL.md", 4, 1}, {"SXV-001", "SKILL.md", 4, 12}}, locs(fs))
	for _, f := range fs {
		assert.Nil(t, f.Offset)
	}
	assert.Len(t, findings.Dedupe(fs), 2)
}

// test_preproc.py::test_inline_evidence_preserves_command_whitespace
func TestInlineEvidencePreservesWhitespace(t *testing.T) {
	fs := Check(pkg(nil, manifest("SKILL.md", inline("  printf x  ", 4, 1, true))))
	require.Len(t, fs, 1)
	assert.Equal(t, "  printf x  ", fs[0].Evidence["command_text"])
}

// test_preproc.py::test_preprocessing_in_loaded_document_is_detected
// test_preproc.py::test_preprocessing_in_loaded_identity_is_detected
// test_preproc.py::test_unreferenced_document_preprocessing_is_inert
func TestOnlyLoadedArtifactsAreChecked(t *testing.T) {
	readme := &parse.Artifact{Rel: "README.md", Kind: "doc", Preprocessing: []parse.Preproc{inline("whoami", 1, 7, true)}}
	linked := pkg([]parse.Ref{{From: "SKILL.md", To: "README.md", Line: 4}}, readme, manifest("SKILL.md"))
	assert.Equal(t, []loc{{"SXV-001", "README.md", 1, 7}}, locs(Check(linked)))

	for _, identity := range []string{"AGENTS.md", "CLAUDE.md", ".cursorrules"} {
		id := &parse.Artifact{Rel: identity, Kind: "agent_identity", Preprocessing: []parse.Preproc{inline("whoami", 1, 5, true)}}
		assert.Equal(t, []loc{{"SXV-001", identity, 1, 5}}, locs(Check(pkg(nil, id, manifest("SKILL.md")))), identity)
	}

	for _, document := range []string{"README.md", "CHANGELOG.md", "LICENSE.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md"} {
		doc := &parse.Artifact{Rel: document, Kind: "doc", Preprocessing: []parse.Preproc{inline("whoami", 1, 20, true)}}
		assert.Empty(t, Check(pkg(nil, doc, manifest("SKILL.md"))), document)
	}

	// A ref into a non-liftable kind (script) or from an unloaded doc does not load anything.
	script := &parse.Artifact{Rel: "x.py", Kind: "script_python", Preprocessing: []parse.Preproc{inline("whoami", 1, 1, true)}}
	chain := pkg([]parse.Ref{{From: "SKILL.md", To: "x.py"}, {From: "other.md", To: "README.md"}}, readme, script, manifest("SKILL.md"))
	assert.Empty(t, Check(chain))
}

// test_preproc.py::test_bang_fence_reports_nonempty_commands
func TestFencedFindingEvidence(t *testing.T) {
	fs := Check(pkg(nil, manifest("SKILL.md", fenced("echo first\nid\n", "!sh", 4, 1))))
	require.Len(t, fs, 1)
	assert.Equal(t, findings.Finding{
		Vector: "SXV-002", Rule: "preproc-fenced-bang", Severity: "critical", Path: "SKILL.md",
		Line: findings.Int(4), Column: findings.Int(1),
		Message: "bang-tagged fenced preprocessing executes 2 command line(s) while loading the skill",
		Evidence: map[string]any{
			"command_text": []string{"echo first", "id"}, "command_length": 13,
			"command_sha256": "e89c9bca06d791d88517dd461fb573d9541c3acdd95ddbfb79e30d590917a627",
			"truncated":      false, "column": 1, "fence_info": "!sh", "block_line_count": 2,
			"selector": "fenced-bang:e89c9bca06d7",
		},
	}, fs[0])
}

// test_preproc.py::test_bang_fence_preserves_indentation_and_internal_blank_lines
func TestFencedFindingKeepsIndentAndBlankLines(t *testing.T) {
	fs := Check(pkg(nil, manifest("SKILL.md", fenced("if True:\n    print('x')\n\nprint('done')\n", "!python", 4, 1))))
	require.Len(t, fs, 1)
	assert.Equal(t, []string{"if True:", "    print('x')", "", "print('done')"}, fs[0].Evidence["command_text"])
	assert.Equal(t, 3, fs[0].Evidence["block_line_count"])
}

// test_preproc.py::test_non_executable_examples_do_not_report
// test_preproc.py::test_non_boundary_inline_preprocessing_is_a_decoy
func TestBlankAndDecoyTokensDoNotReport(t *testing.T) {
	fs := Check(pkg(nil, manifest("SKILL.md",
		fenced("\n", "!sh", 4, 1), inline("   ", 8, 1, true), inline("whoami", 9, 2, false),
		parse.Preproc{Kind: "other", Code: "x", Runs: true})))
	assert.Empty(t, fs)
}

// test_preproc.py::test_multiple_preprocessing_forms_are_independent
func TestInlineAndFencedSortedByLine(t *testing.T) {
	fs := Check(pkg(nil, manifest("SKILL.md", fenced("echo live\n", "!", 5, 1), inline("id", 4, 1, true))))
	assert.Equal(t, []loc{{"SXV-001", "SKILL.md", 4, 1}, {"SXV-002", "SKILL.md", 5, 1}}, locs(fs))
}

// test_preproc.py::test_preprocessing_findings_are_capped_with_visible_note
// test_preproc.py::test_fenced_preprocessing_ir_and_findings_are_capped
// test_preproc.py::test_frontmatter_and_body_share_one_inline_cap
func TestCapNotes(t *testing.T) {
	var toks []parse.Preproc
	for i := range findings.Cap {
		toks = append(toks, inline(fmt.Sprintf("command-%d", i), 4+i, 1, true))
	}
	a := manifest("SKILL.md", toks...)
	a.PreprocessingCounts = parse.PreprocCounts{Inline: findings.Cap + 3}
	fs := Check(pkg(nil, a))
	assert.Len(t, testutil.ByVector(fs, "SXV-001"), findings.Cap)
	notes := testutil.ByVector(fs, "")
	require.Len(t, notes, 1)
	assert.Equal(t, findings.Finding{Rule: "findings-capped", Severity: "low", Path: "SKILL.md",
		Message: "3 more SXV-001 findings in SKILL.md were suppressed (cap 25 per file)"}, notes[0])

	a.PreprocessingCounts = parse.PreprocCounts{Inline: 50, Fenced: 28}
	var msgs []string
	for _, f := range testutil.ByVector(Check(pkg(nil, a)), "") {
		msgs = append(msgs, f.Message)
	}
	assert.Equal(t, []string{
		"25 more SXV-001 findings in SKILL.md were suppressed (cap 25 per file)",
		"3 more SXV-002 findings in SKILL.md were suppressed (cap 25 per file)",
	}, msgs)
}

// test_preproc.py::test_empty_preprocessing_constructs_do_not_create_cap_notes
func TestBlankTokensCreateNoFindingsOrNotes(t *testing.T) {
	var toks []parse.Preproc
	for i := range findings.Cap + 3 {
		toks = append(toks, inline("   ", 4+i, 1, true), fenced("\n", "!sh", 40+3*i, 1))
	}
	assert.Empty(t, Check(pkg(nil, manifest("SKILL.md", toks...))))
}

// test_preproc.py::test_preprocessing_ir_and_evidence_are_bounded
func TestEvidenceIsBoundedOnCodePoints(t *testing.T) {
	long := strings.Repeat("x", 1000) + "-0"
	wide := strings.Repeat("é", 401)
	fs := Check(pkg(nil, manifest("SKILL.md", inline(long, 4, 1, true), fenced(wide+"\n"+wide+"\n", "!sh", 5, 1))))
	require.Len(t, fs, 2)
	assert.Equal(t, strings.Repeat("x", 400), fs[0].Evidence["command_text"])
	assert.Equal(t, 1002, fs[0].Evidence["command_length"])
	assert.Equal(t, true, fs[0].Evidence["truncated"])
	assert.Equal(t, "inline-bang:70213190c10b", fs[0].Evidence["selector"])
	assert.Equal(t, "inline preprocessing executes `"+strings.Repeat("x", 160)+"` while loading the skill, before its instructions are evaluated", fs[0].Message)
	assert.Equal(t, []string{strings.Repeat("é", 400)}, fs[1].Evidence["command_text"])
	assert.Equal(t, 803, fs[1].Evidence["command_length"])
	assert.Equal(t, true, fs[1].Evidence["truncated"])
}
