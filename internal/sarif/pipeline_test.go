package sarif

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/capability"
	"github.com/traceforce/skill-xray/internal/codelane"
	"github.com/traceforce/skill-xray/internal/correlate"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/opengrep"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/scan"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// tests/test_fence_locations.py, the SARIF half: _fixture, _native, _document.

const call = `open("~/.ssh/id_rsa")`

// fenceFixture is _fixture: one Python fence in SKILL.md, the lifted unit and the command's line.
func fenceFixture(t *testing.T, prefix, command string) (*parse.Package, opengrep.Selected, int) {
	t.Helper()
	var text string
	if prefix == "list" {
		text = "- Read the file:\n\n  ```python\n  " + command + "\n  ```\n"
	} else {
		text = prefix + "```python\n" + prefix + command + "\n" + prefix + "```\n"
	}
	p := parsePkg(t, map[string]string{"SKILL.md": "---\nname: test\nallowed-tools: Read\n---\n" + text})
	units, _ := codelane.Build(p)
	selected := opengrep.Select(p, units, []string{"python", "shell"})
	require.Len(t, selected, 1)
	line := 1 + slices.IndexFunc(strings.Split(selected[0].Text, "\n"), func(v string) bool { return strings.Contains(v, command) })
	return p, selected[0], line
}

// native is _native: one engine result on the lifted unit; columns are bytes.
func native(line int, command string, startCol int) map[string]any {
	return map[string]any{"path": "0000.py", "check_id": "skill-xray.python-credential-read",
		"start": map[string]any{"line": line, "col": startCol, "offset": 0},
		"end":   map[string]any{"line": line, "col": len(command) + 1, "offset": 20},
		"extra": map[string]any{"message": "Python code reads a private credential file.",
			"metadata": map[string]any{"skill_xray_vector": "SXV-023", "skill_xray_rule": "opengrep-credential-read",
				"skill_xray_severity": "high"}}}
}

func fromReport(t *testing.T, p *parse.Package, target opengrep.Selected, natives ...map[string]any) []findings.Finding {
	t.Helper()
	list := []any{}
	for _, n := range natives {
		list = append(list, n)
	}
	return opengrep.FindingsFromReport(map[string]any{"results": list, "errors": []any{}},
		map[string]opengrep.Selected{"0000.py": target}, p, nil, nil)
}

func traceOf(location map[string]any, command string, intermediate bool) map[string]any {
	step := []any{"CliLoc", []any{location, command}}
	trace := map[string]any{"taint_source": step, "taint_sink": step}
	if intermediate {
		trace["intermediate_vars"] = []any{map[string]any{"location": location, "content": command}}
	}
	return trace
}

// sarifResult is _document: the single validated SARIF result of one engine finding.
func sarifResult(t *testing.T, p *parse.Package, f findings.Finding, suppress bool) map[string]any {
	t.Helper()
	raw := candidates(correlate.Candidate{CandidateID: "a", Finding: f.ToMap(), Analyzer: "opengrep",
		Provenance: "deterministic-check-output", Coverage: "no-reported-gap"})
	c, err := correlate.Correlate(p, raw)
	require.NoError(t, err)
	var policy map[string]any
	if suppress {
		policy = policyFor(c.Results[0], "suppress")
	}
	triads := capability.Build(p, nil, nil)
	c, err = correlate.ApplyDispositions(p, c, triads, policy, nil)
	require.NoError(t, err)
	doc := build(t, p, &scan.ScanReport{RawCandidates: raw, Triads: triads, Correlation: c})
	require.NoError(t, Validate(doc))
	return only(t, doc)
}

// slice is Python source[a:b] on code points.
func slice(s string, a, b int) string { return string([]rune(s)[a:b]) }

func sourceLine(p *parse.Package, line int) string {
	return strings.Split(*p.ByRel["SKILL.md"].Text, "\n")[line-1]
}

// test_primary_fence_region_selects_original_source (4 x 2 rows)
func TestPrimaryFenceRegionSelectsOriginalSource(t *testing.T) {
	for _, prefix := range []string{"", "   ", "> ", "list"} {
		for _, leading := range []string{"", `label = "é😀"; `} {
			command := leading + call
			p, target, line := fenceFixture(t, prefix, command)
			n := native(line, command, len(leading)+1)
			original := canon(n)
			fs := fromReport(t, p, target, n)
			require.Len(t, fs, 1)
			result := sarifResult(t, p, fs[0], false)
			reg := m(regionOf(result))
			assert.Equal(t, call, slice(sourceLine(p, line), reg["startColumn"].(int)-1, reg["endColumn"].(int)-1), prefix+leading)
			assert.NotContains(t, l(props(result)["limitations"]), "location-unvalidated")
			assert.Equal(t, original, canon(n))
		}
	}
}

// test_trace_positions_map_to_original_source_and_keep_engine_evidence (3 rows)
func TestTracePositionsMapToOriginalSourceAndKeepEngineEvidence(t *testing.T) {
	for _, prefix := range []string{"   ", "> ", "list"} {
		command := `value = "é😀"; ` + call
		p, target, line := fenceFixture(t, prefix, command)
		n := native(line, command, 1)
		location := map[string]any{"path": "0000.py", "start": maps.Clone(m(n["start"])), "end": maps.Clone(m(n["end"]))}
		m(n["extra"])["dataflow_trace"] = traceOf(location, command, true)
		fs := fromReport(t, p, target, n)
		require.Len(t, fs, 1)
		result := sarifResult(t, p, fs[0], false)
		steps := l(m(l(m(l(result["codeFlows"])[0])["threadFlows"])[0])["locations"])
		require.NotEmpty(t, steps)
		for _, step := range steps {
			reg := m(m(m(step)["location"].(map[string]any)["physicalLocation"])["region"])
			assert.Equal(t, command, slice(sourceLine(p, line), reg["startColumn"].(int)-1, reg["endColumn"].(int)-1), prefix)
		}
		startCol := func(trace any) int {
			return m(m(l(l(m(trace)["taint_source"])[1])[0])["start"])["col"].(int)
		}
		assert.Equal(t, 1, startCol(fs[0].Evidence["engine_dataflow_trace"]))
		assert.Greater(t, startCol(fs[0].Evidence["dataflow_trace"]), 1)
	}
}

// test_unprovable_fence_mapping_retains_finding_with_explicit_limitations (3 rows)
func TestUnprovableFenceMappingRetainsFindingWithExplicitLimitations(t *testing.T) {
	for _, damage := range []string{"tab", "different-source", "multiline"} {
		p, target, line := fenceFixture(t, "   ", call)
		n := native(line, call, 1)
		artifact := p.ByRel["SKILL.md"]
		switch damage {
		case "tab":
			text := strings.Replace(*artifact.Text, "   "+call, "\t"+call, 1)
			artifact.Text = &text
		case "different-source":
			text := strings.Replace(*artifact.Text, call, "pass # "+strings.Repeat("x", len(call)), 1)
			artifact.Text = &text
		default:
			n["end"] = map[string]any{"line": line + 1, "col": 1}
		}
		location := map[string]any{"path": "0000.py", "start": maps.Clone(m(n["start"])), "end": maps.Clone(m(n["end"]))}
		m(n["extra"])["dataflow_trace"] = traceOf(location, call, false)
		fs := fromReport(t, p, target, n)
		require.Len(t, fs, 1)
		f := fs[0]
		assert.Equal(t, "SXV-023", f.Vector)
		assert.Equal(t, "unvalidated", f.Evidence["location_mapping"])
		assert.Equal(t, "unvalidated", f.Evidence["trace_mapping"])
		assert.Equal(t, canon(n["start"]), canon(m(l(l(m(f.Evidence["dataflow_trace"])["taint_source"])[1])[0])["start"]))
		result := sarifResult(t, p, f, true)
		assert.Equal(t, fmt.Sprintf(`{"startLine":%d}`, line), canon(regionOf(result)))
		assert.Subset(t, l(props(result)["limitations"]), []any{"location-unvalidated", "trace-unvalidated"})
		assert.Equal(t, "incomplete", props(result)["coverage"])
		assert.Equal(t, "reported", props(result)["disposition"])
		assert.NotContains(t, result, "codeFlows")
	}
}

// deterministic is scan_report over fixed findings and observations with the LLM lane off (the
// checks seam is scan's).
func deterministic(t *testing.T, p *parse.Package, raw []findings.Finding, observations []map[string]any) *scan.ScanReport {
	t.Helper()
	cs := correlate.Candidates(raw)
	triads := capability.Build(p, observations, raw)
	c, err := correlate.Correlate(p, cs)
	require.NoError(t, err)
	c, err = correlate.ApplyDispositions(p, c, triads, nil, nil)
	require.NoError(t, err)
	return &scan.ScanReport{Findings: findings.Dedupe(raw), RawCandidates: cs, Triads: triads, Correlation: c}
}

// test_unmapped_occurrences_survive_all_deduplication (2 x 2 rows)
func TestUnmappedOccurrencesSurviveAllDeduplication(t *testing.T) {
	for _, separator := range []string{"; ", ";\t"} {
		for _, samePath := range []bool{false, true} {
			second := `open("~/.aws/credentials")`
			if samePath {
				second = call
			}
			command := call + separator + second
			p, target, line := fenceFixture(t, "", command)
			a, b := native(line, call, 1), native(line, command, len(call+separator)+1)
			engine := []map[string]any{b, a, pytext.DeepCopy(a).(map[string]any), pytext.DeepCopy(b).(map[string]any)}
			original := canon(engine)
			fs := fromReport(t, p, target, engine...)
			require.Len(t, fs, 2)
			assert.Equal(t, original, canon(engine))
			repeated := []findings.Finding{}
			for range findings.Cap + 1 {
				repeated = append(repeated, fs...)
			}
			kept := findings.CapFindings(repeated)
			assert.Equal(t, fs, kept)
			reversed := slices.Clone(kept)
			slices.Reverse(reversed)
			assert.Equal(t, fs, findings.Dedupe(reversed))
			report := deterministic(t, p, kept, nil)
			assert.Len(t, report.Findings, 2)
			assert.Len(t, report.RawCandidates, 2)
			output := build(t, p, report)
			require.NoError(t, Validate(output))
			rs := results(output)
			require.Len(t, rs, 2)
			assert.NotEqual(t, props(m(rs[0]))["id"], props(m(rs[1]))["id"])
			for _, f := range fs {
				assert.Equal(t, "SXV-023", f.Vector)
				assert.Equal(t, "SKILL.md", f.Path)
				assert.Equal(t, line, *f.Line)
				assert.Equal(t, "high", f.Severity)
			}
			if strings.Contains(separator, "\t") {
				cols := []any{}
				for _, f := range fs {
					assert.Nil(t, f.Column)
					cols = append(cols, m(m(f.Evidence["engine_location"])["start"])["col"])
				}
				assert.ElementsMatch(t, []any{1, len(call+separator) + 1}, cols)
				for _, r := range rs {
					assert.Equal(t, fmt.Sprintf(`{"startLine":%d}`, line), canon(regionOf(m(r))))
					assert.Contains(t, l(props(m(r))["limitations"]), "location-unvalidated")
					assert.Equal(t, "reported", props(m(r))["disposition"])
					assert.NotContains(t, m(r), "codeFlows")
				}
			}
			assert.Equal(t, encode(t, output), encode(t, build(t, p, deterministic(t, p, kept, nil))))
		}
	}
}

func requireOpengrep(t *testing.T) string {
	t.Helper()
	exe, err := opengrep.Resolve("")
	if err != nil {
		t.Skip("pinned OpenGrep binary absent: " + err.Error())
	}
	return exe
}

// test_native_fence_keeps_both_credential_reads (2 rows; live OpenGrep)
func TestNativeFenceKeepsBothCredentialReads(t *testing.T) {
	exe := requireOpengrep(t)
	for _, separator := range []string{"; ", ";\t"} {
		p, _, line := fenceFixture(t, "", call+separator+`open("~/.aws/credentials")`)
		report, err := scan.Report(p, scan.Options{OpengrepExe: exe})
		require.NoError(t, err)
		raw := []correlate.Candidate{}
		for _, c := range report.RawCandidates {
			if c.Finding["vector"] == "SXV-023" {
				raw = append(raw, c)
			}
		}
		require.Len(t, raw, 2)
		output := build(t, p, report)
		require.NoError(t, Validate(output))
		rs := []map[string]any{}
		for _, r := range results(output) {
			if props(m(r))["sxv"] == "SXV-023" {
				rs = append(rs, m(r))
			}
		}
		require.Len(t, rs, 2)
		for _, r := range rs {
			assert.Equal(t, "high", props(r)["effectiveSeverity"])
			if strings.Contains(separator, "\t") {
				assert.Equal(t, fmt.Sprintf(`{"startLine":%d}`, line), canon(regionOf(r)))
			}
		}
		for _, c := range raw {
			assert.Equal(t, line, c.Finding["line"])
			assert.Equal(t, "SKILL.md", c.Finding["path"])
		}
	}
}

// stable is a finding's ToMap without the run-scoped OpenGrep fingerprint.
func stable(f findings.Finding) string {
	d := f.ToMap()
	if ev, _ := d["evidence"].(map[string]any); ev["engine"] == any("opengrep") {
		ev = maps.Clone(ev)
		delete(ev, "fingerprint")
		d["evidence"] = ev
	}
	return canon(d)
}

// test_sarif_integration.py::test_native_sarif_accounts_for_every_candidate (6 rows; live OpenGrep)
func TestNativeSARIFAccountsForEveryCandidate(t *testing.T) {
	exe := requireOpengrep(t)
	for _, name := range slices.Sorted(maps.Keys(testutil.Microcorpus)) {
		t.Run(name, func(t *testing.T) {
			outputs := [][]byte{}
			var p *parse.Package
			var report *scan.ScanReport
			var output map[string]any
			for range 2 {
				p = parsePkg(t, testutil.Microcorpus[name])
				var err error
				report, err = scan.Report(p, scan.Options{OpengrepExe: exe})
				require.NoError(t, err)
				output = build(t, p, report)
				outputs = append(outputs, encode(t, output))
			}
			assert.Equal(t, outputs[0], outputs[1])
			want, got := []string{}, []string{}
			for _, f := range report.Findings {
				want = append(want, stable(f))
			}
			for _, f := range scan.Scan(p, nil, exe) {
				got = append(got, stable(f))
			}
			assert.Equal(t, want, got)
			raw, links := l(runProps(output)["rawCandidates"]), l(runProps(output)["candidateLinks"])
			assert.Len(t, raw, len(report.RawCandidates))
			assert.Len(t, links, len(report.RawCandidates))
			ids := func(items []any) []string {
				out := []string{}
				for _, item := range items {
					out = append(out, m(item)["candidate_id"].(string))
				}
				slices.Sort(out)
				return out
			}
			assert.Equal(t, ids(raw), ids(links))
			for _, r := range results(output) {
				assert.Equal(t, "reported", props(m(r))["disposition"])
			}
			assert.Empty(t, report.ContextErrors)
		})
	}
}
