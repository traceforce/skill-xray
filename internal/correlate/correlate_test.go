package correlate

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// Fixtures are tests/test_correlate.py::SOURCE, package, candidate, loc.
const source = "import os, sys\nos.system(sys.argv[1])\n"

func pkg(t *testing.T, files map[string]string) *parse.Package {
	return parse.Parse(ingest.BuildPackage(testutil.MakePackage(t, files)))
}

func pkgWith(t *testing.T, src, manifest string) *parse.Package {
	return pkg(t, map[string]string{"SKILL.md": manifest, "run.py": src})
}

func simple(t *testing.T, src string) *parse.Package {
	return pkgWith(t, src, "---\nname: test\n---\n")
}

type mod = func(*findings.Finding)

func cand(cid, analyzer string, mods ...mod) Candidate {
	f := findings.Finding{Vector: "SXV-008", Rule: "command-injection", Severity: "critical", Path: "run.py",
		Line: findings.Int(2), Column: findings.Int(1), Message: "Input reaches a shell",
		Evidence: map[string]any{"engine": analyzer, "command": "os.system(sys.argv[1])"}}
	for _, m := range mods {
		m(&f)
	}
	return Candidate{CandidateID: cid, Finding: f.ToMap(), Analyzer: analyzer,
		Provenance: "deterministic-check-output", Coverage: "no-reported-gap"}
}

func ev(m map[string]any) mod   { return func(f *findings.Finding) { f.Evidence = m } }
func line(n int) mod            { return func(f *findings.Finding) { f.Line = findings.Int(n) } }
func message(s string) mod      { return func(f *findings.Finding) { f.Message = s } }
func vector(v, rule string) mod { return func(f *findings.Finding) { f.Vector, f.Rule = v, rule } }

// loc is the test's trace step; the end column counts code points as Python len() does.
func loc(line any, text, path string) []any {
	return []any{"CliLoc", []any{map[string]any{"path": path,
		"start": map[string]any{"line": line, "col": 1},
		"end":   map[string]any{"line": line, "col": utf8.RuneCountInString(text) + 1}}, text}}
}

func correlated(t *testing.T, p *parse.Package, raw ...Candidate) *Correlation {
	t.Helper()
	c, err := Correlate(p, raw)
	require.NoError(t, err)
	return c
}

func analyzers(r *Result) []string {
	out := []string{}
	for _, p := range r.Provenance {
		out = append(out, p.Analyzer)
	}
	return out
}

// test_duplicates_preserve_candidates_evidence_and_provenance
func TestDuplicatesPreserveCandidatesEvidenceAndProvenance(t *testing.T) {
	raw := []Candidate{cand("a", "opengrep"), cand("b", "opengrep"), cand("c", "other-engine")}
	original := copyCandidates(raw)
	report := correlated(t, simple(t, source), raw...)
	assert.Equal(t, original, raw)
	assert.Equal(t, original, report.RawCandidates)
	require.Len(t, report.Results, 1)
	assert.Len(t, report.Links, 3)
	r := report.Results[0]
	assert.Equal(t, "skill-xray/command-injection", r.RuleID)
	assert.NotEqual(t, "SXV-008", r.ID)
	assert.Len(t, r.Fingerprint, 64)
	assert.Equal(t, []string{"a", "b", "c"}, r.CandidateIDs)
	assert.ElementsMatch(t, []string{"opengrep", "other-engine"}, analyzers(r))
	assert.Len(t, r.Evidence, 2)
	dispositions := []string{}
	for _, l := range report.Links {
		assert.Equal(t, r.ID, l.ResultID)
		assert.NotEmpty(t, l.Reason)
		dispositions = append(dispositions, l.Disposition)
	}
	assert.Equal(t, []string{"reported", "duplicate", "duplicate"}, dispositions)
	clear(report.RawCandidates[0].Finding["evidence"].(map[string]any))
	assert.Equal(t, original, raw)
}

// test_distinct_security_evidence_or_occurrences_do_not_merge (11 rows)
func TestDistinctSecurityEvidenceOrOccurrencesDoNotMerge(t *testing.T) {
	cases := map[string]mod{
		"command":  ev(map[string]any{"command": "curl https://attacker.invalid"}),
		"source":   ev(map[string]any{"source": "~/.ssh/id_rsa"}),
		"sink":     ev(map[string]any{"sink": "/etc/cron.d/start"}),
		"endpoint": ev(map[string]any{"endpoint": "https://attacker.invalid"}),
		"line":     line(1),
		"column":   func(f *findings.Finding) { f.Column = findings.Int(2) },
		"offset":   func(f *findings.Finding) { f.Offset = findings.Int(1) },
		"length":   func(f *findings.Finding) { f.Length = findings.Int(2) },
		"severity": func(f *findings.Finding) { f.Severity = "high" },
		"vector":   func(f *findings.Finding) { f.Vector = "SXV-019" },
		"rule":     func(f *findings.Finding) { f.Rule = "other-rule" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			report := correlated(t, simple(t, source), cand("a", "opengrep"), cand("b", "opengrep", change))
			require.Len(t, report.Results, 2)
			assert.NotEqual(t, report.Results[0].ID, report.Results[1].ID)
			assert.Len(t, report.Links, 2)
		})
	}
}

// test_blank_lines_and_install_path_do_not_change_identity (3 newline styles)
func TestBlankLinesAndInstallPathDoNotChangeIdentity(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n", "\r"} {
		t.Run(pytext.Repr(newline), func(t *testing.T) {
			old := correlated(t, simple(t, source), cand("c0", "opengrep")).Results[0]
			src := strings.ReplaceAll("\n\n"+source, "\n", newline)
			cur := correlated(t, simple(t, src), cand("c0", "opengrep", line(4))).Results[0]
			assert.Equal(t, [2]string{old.ID, old.Fingerprint}, [2]string{cur.ID, cur.Fingerprint})
			assert.NotEqual(t, old.ContextDigest, cur.ContextDigest)
		})
	}
}

// test_changed_security_context_invalidates_decision_identity (6 rows)
func TestChangedSecurityContextInvalidatesDecisionIdentity(t *testing.T) {
	for _, change := range []string{"https://approved.invalid", "https://attacker.invalid", "~/.ssh/id_rsa",
		"~/.aws/credentials", "/etc/cron.d/evil", "C:/Users/me/Startup/run.cmd"} {
		t.Run(change, func(t *testing.T) {
			original := correlated(t, simple(t, source), cand("c0", "opengrep")).Results[0]
			changed := correlated(t, simple(t, source+"destination = "+pytext.Repr(change)+"\n"), cand("c0", "opengrep")).Results[0]
			assert.Equal(t, original.Fingerprint, changed.Fingerprint)
			assert.NotEqual(t, original.ContextDigest, changed.ContextDigest)
		})
	}
}

// test_repeated_identical_calls_remain_distinct_after_line_shift
func TestRepeatedIdenticalCallsRemainDistinctAfterLineShift(t *testing.T) {
	src := source + strings.Split(source, "\n")[1] + "\n"
	old := correlated(t, simple(t, src), cand("a", "opengrep"), cand("b", "opengrep", line(3))).Results
	cur := correlated(t, simple(t, "\n\n"+src), cand("a", "opengrep", line(4)), cand("b", "opengrep", line(5))).Results
	require.Len(t, old, 2)
	assert.NotEqual(t, old[0].Fingerprint, old[1].Fingerprint)
	assert.Equal(t, []string{old[0].ID, old[1].ID}, []string{cur[0].ID, cur[1].ID})
}

// test_permuted_candidates_do_not_change_correlation
func TestPermutedCandidatesDoNotChangeCorrelation(t *testing.T) {
	p := simple(t, source)
	raw := []Candidate{cand("c", "opengrep"), cand("b", "opengrep", line(1)), cand("a", "opengrep")}
	first := correlated(t, p, raw...)
	second := correlated(t, p, raw[2], raw[1], raw[0])
	assert.Equal(t, first.Results, second.Results)
	assert.Equal(t, first.Links, second.Links)
}

// test_engine_fingerprints_are_not_finding_identity
func TestEngineFingerprintsAreNotFindingIdentity(t *testing.T) {
	p := simple(t, source)
	raw := cand("c0", "opengrep")
	raw.Finding["evidence"].(map[string]any)["fingerprint"] = "/tmp/engine-one/random"
	first := correlated(t, p, raw)
	raw.Finding["evidence"].(map[string]any)["fingerprint"] = "/tmp/engine-two/random"
	second := correlated(t, p, raw)
	assert.Equal(t, first.Results, second.Results)
	assert.NotEqual(t, first.RawCandidates, second.RawCandidates)
}

// test_equivalent_analyzer_wording_merges_without_losing_messages
func TestEquivalentAnalyzerWordingMergesWithoutLosingMessages(t *testing.T) {
	p := simple(t, source)
	raw := []Candidate{cand("a", "opengrep"),
		cand("b", "other-engine", message("An untrusted argument reaches command execution"))}
	report := correlated(t, p, raw...)
	require.Len(t, report.Results, 1)
	r := report.Results[0]
	assert.Equal(t, []string{"a", "b"}, r.CandidateIDs)
	assert.Equal(t, raw, report.RawCandidates)
	assert.NotEqual(t, report.RawCandidates[0].Finding["message"], report.RawCandidates[1].Finding["message"])
	assert.ElementsMatch(t, []string{"opengrep", "other-engine"}, analyzers(r))
	assert.Equal(t, correlated(t, p, raw[0]).Results[0].Fingerprint, r.Fingerprint)
	reversed := correlated(t, p, raw[1], raw[0])
	assert.Equal(t, report.Results, reversed.Results)
	assert.Equal(t, report.Links, reversed.Links)
}

// test_uncertain_or_diagnostic_messages_remain_separate (4 rows)
func TestUncertainOrDiagnosticMessagesRemainSeparate(t *testing.T) {
	cases := map[string]mod{
		"check-error": vector("", "check-error"),
		"no-evidence": ev(map[string]any{}),
		"absent-path": func(f *findings.Finding) { f.Path = "absent.py" },
		"no-line":     func(f *findings.Finding) { f.Line = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			raw := []Candidate{cand("a", "opengrep", message("First distinct detail"), change),
				cand("b", "opengrep", message("Second distinct detail"), change)}
			report := correlated(t, simple(t, source), raw...)
			assert.Len(t, report.Results, 2)
			assert.Equal(t, raw, report.RawCandidates)
		})
	}
}

// test_real_trace_is_preserved_without_stitching_findings
func TestRealTraceIsPreservedWithoutStitchingFindings(t *testing.T) {
	src := "source = input()\nos.system(source)\n"
	trace := map[string]any{"taint_source": loc(1, "source = input()", "run.py"),
		"intermediate_vars": []any{}, "taint_sink": loc(2, "os.system(source)", "run.py")}
	raw := cand("c0", "opengrep", ev(map[string]any{"engine": "opengrep", "dataflow_trace": trace}))
	r := correlated(t, simple(t, src), raw).Results[0]
	assert.Equal(t, trace, r.Evidence[0]["dataflow_trace"])
	require.Len(t, r.CodeFlow, 2)
	assert.Equal(t, []string{"source", "sink"}, []string{r.CodeFlow[0].Role, r.CodeFlow[1].Role})
	assert.Equal(t, []string{"run.py", "run.py"}, []string{r.CodeFlow[0].Path, r.CodeFlow[1].Path})
	assert.Empty(t, r.Limitations)
	unrelated := correlated(t, simple(t, source), cand("read", "opengrep", vector("SXV-023", "command-injection")),
		cand("network", "opengrep", vector("SXV-024", "command-injection")))
	require.Len(t, unrelated.Results, 2)
	for _, r := range unrelated.Results {
		assert.Empty(t, r.CodeFlow)
	}
}

// test_malformed_or_unsupported_trace_retains_evidence_without_flow (8 rows)
func TestMalformedOrUnsupportedTraceRetainsEvidenceWithoutFlow(t *testing.T) {
	cases := map[string]any{
		"none": nil, "string": "bad", "list": []any{},
		"bare-source":       map[string]any{"taint_source": []any{"source"}},
		"outside-path":      map[string]any{"taint_source": loc(1, "source", "../outside.py"), "taint_sink": loc(2, "sink", "run.py")},
		"bool-line":         map[string]any{"taint_source": loc(true, "source", "run.py"), "taint_sink": loc(2, "sink", "run.py")},
		"line-out-of-range": map[string]any{"taint_source": loc(1, "source", "run.py"), "taint_sink": loc(999, "sink", "run.py")},
		"intermediate-string": map[string]any{"taint_source": loc(1, "source", "run.py"), "taint_sink": loc(2, "sink", "run.py"),
			"intermediate_vars": "unsupported"},
	}
	for name, trace := range cases {
		t.Run(name, func(t *testing.T) {
			raw := cand("c0", "opengrep", ev(map[string]any{"engine": "opengrep", "dataflow_trace": trace}))
			report := correlated(t, simple(t, source), raw)
			require.Len(t, report.Results, 1)
			r := report.Results[0]
			assert.Empty(t, r.CodeFlow)
			assert.Contains(t, r.Limitations, "trace-unvalidated")
			assert.Equal(t, raw, report.RawCandidates[0])
			assert.Equal(t, trace, r.Evidence[0]["dataflow_trace"])
		})
	}
}

// test_governing_manifest_changes_context_but_not_evidence_identity
func TestGoverningManifestChangesContextButNotEvidenceIdentity(t *testing.T) {
	old := correlated(t, simple(t, source), cand("c0", "opengrep")).Results[0]
	cur := correlated(t, pkgWith(t, source, "---\nname: test\nallowed-tools: Bash\n---\n"), cand("c0", "opengrep")).Results[0]
	require.NotNil(t, old.Manifest)
	require.NotNil(t, cur.Manifest)
	assert.Equal(t, "SKILL.md", *old.Manifest)
	assert.Equal(t, "SKILL.md", *cur.Manifest)
	assert.Equal(t, old.Fingerprint, cur.Fingerprint)
	assert.NotEqual(t, old.ContextDigest, cur.ContextDigest)
}

// test_missing_source_and_coverage_records_are_retained
func TestMissingSourceAndCoverageRecordsAreRetained(t *testing.T) {
	report := correlated(t, simple(t, source),
		cand("c0", "opengrep", func(f *findings.Finding) { f.Path = "absent.py" }),
		cand("gap", "opengrep", vector("", "check-error"), func(f *findings.Finding) { f.Path, f.Line, f.Evidence = "", nil, nil }))
	assert.Len(t, report.Results, 2)
	assert.Len(t, report.Links, 2)
	unavailable, operational := false, false
	for _, r := range report.Results {
		unavailable = unavailable || assert.ObjectsAreEqual([]string{"source-unavailable"}, r.Limitations)
		operational = operational || str(r.Finding, "vector") == ""
	}
	assert.True(t, unavailable)
	assert.True(t, operational)
}

// test_duplicate_candidate_ids_fail_visibly
func TestDuplicateCandidateIDsFailVisibly(t *testing.T) {
	_, err := Correlate(simple(t, source), []Candidate{cand("c0", "opengrep"), cand("c0", "opengrep")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "candidate")
}

// test_malformed_evidence_position_retains_candidate (5 rows)
func TestMalformedEvidencePositionRetainsCandidate(t *testing.T) {
	cases := map[string]any{"none": nil, "list": []any{}, "string": "unknown",
		"bool-line": map[string]any{"line": true}, "out-of-range": map[string]any{"line": 999}}
	for name, end := range cases {
		t.Run(name, func(t *testing.T) {
			raw := cand("c0", "opengrep", ev(map[string]any{"end": end}))
			report := correlated(t, simple(t, source), raw)
			assert.Equal(t, []Candidate{raw}, report.RawCandidates)
			assert.Equal(t, []string{"c0"}, report.Results[0].CandidateIDs)
		})
	}
}

// test_binary_evidence_identity_and_byte_occurrences
func TestBinaryEvidenceIdentityAndByteOccurrences(t *testing.T) {
	scan := func(data string, offset int) *Result {
		p := pkg(t, map[string]string{"payload.bin": data})
		raw := cand("c0", "opengrep", vector("SXV-037", "trailing-bytes"), func(f *findings.Finding) {
			f.Path, f.Line, f.Column, f.Evidence = "payload.bin", nil, nil, nil
			f.Offset, f.Length = findings.Int(offset), findings.Int(4)
		})
		return correlated(t, p, raw).Results[0]
	}
	first := scan("headEVIL", 4)
	assert.Equal(t, first.Fingerprint, scan("paddingheadEVIL", 11).Fingerprint)
	assert.NotEqual(t, first.ContextDigest, scan("headSAFE", 4).ContextDigest)
}

// testdata/canonical.jsonl: correlate.canonical and digest over the objects correlate hashes,
// recorded by tools/parity/gen_correlate_golden.py on the oracle (core.md R2).
func TestCanonicalGolden(t *testing.T) {
	f, err := os.Open("testdata/canonical.jsonl")
	require.NoError(t, err)
	defer f.Close()
	rows := 0
	for sc := bufio.NewScanner(f); sc.Scan(); rows++ {
		var row struct {
			Value             any
			Canonical, Digest string
		}
		dec := json.NewDecoder(strings.NewReader(sc.Text()))
		dec.UseNumber()
		require.NoError(t, dec.Decode(&row))
		value := pytext.Intify(row.Value)
		assert.Equal(t, row.Canonical, pytext.Canonical(value))
		assert.Equal(t, row.Digest, digest(value))
	}
	assert.GreaterOrEqual(t, rows, 50)
}
