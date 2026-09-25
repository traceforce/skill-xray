package opengrep

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "go.yaml.in/yaml/v3"

	"github.com/traceforce/skill-xray/internal/codelane"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

const manifest = "---\nname: t\n---\n"

func parsed(t *testing.T, files map[string]string) *parse.Package {
	return parse.Parse(ingest.BuildPackage(testutil.MakePackage(t, files)))
}

type runner = func(ctx context.Context, argv []string, dir string, env []string, stderr *os.File) (int, error)

func arg(argv []string, flag string) string { return argv[slices.Index(argv, flag)+1] }

// targetNames lists the temporary targets directory (the last argv element), sorted.
func targetNames(argv []string) []string {
	entries, _ := os.ReadDir(argv[len(argv)-1])
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func writeReport(t *testing.T, argv []string, report string) {
	t.Helper()
	require.NoError(t, os.WriteFile(arg(argv, "--output"), []byte(report), 0o644))
}

// fakeRunner is tests/test_taint_engine.py::_runner: it writes a report listing every target
// as scanned and returns exit 0.
func fakeRunner(t *testing.T, results ...map[string]any) runner {
	return func(_ context.Context, argv []string, _ string, _ []string, _ *os.File) (int, error) {
		scanned := []any{}
		for _, n := range targetNames(argv) {
			scanned = append(scanned, n)
		}
		rep := report(results...)
		rep["paths"] = map[string]any{"scanned": scanned}
		data, _ := json.Marshal(rep)
		writeReport(t, argv, string(data))
		return 0, nil
	}
}

// result is tests/test_opengrep_bridge.py::_result.
func result(path string, line int, vector string) map[string]any {
	return map[string]any{
		"check_id": "skill-xray.python-local-command-injection",
		"path":     path,
		"start":    map[string]any{"line": line, "col": 1, "offset": 10},
		"end":      map[string]any{"line": line, "col": 20, "offset": 29},
		"extra": map[string]any{
			"message":  "Untrusted local input reaches a Python command-execution sink.",
			"severity": "ERROR",
			"metadata": map[string]any{
				"skill_xray_vector":   vector,
				"skill_xray_rule":     "opengrep-python-command-injection",
				"skill_xray_severity": "critical",
			},
			"fingerprint":    "stable-id",
			"dataflow_trace": map[string]any{"taint_source": []any{"source"}},
		},
	}
}

func rules(fs []findings.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

// tests/test_opengrep_bridge.py::test_selects_real_python_files
func TestSelectsRealPythonFiles(t *testing.T) {
	p := parsed(t, map[string]string{"run.py": "import os\nos.system(input())\n"})
	assert.Equal(t, []Selected{{"run.py", "import os\nos.system(input())\n", "file", ".py"}}, Select(p, nil, []string{"python"}))
}

// tests/test_opengrep_bridge.py::test_selects_shell_only_when_requested
func TestSelectsShellOnlyWhenRequested(t *testing.T) {
	p := parsed(t, map[string]string{"run.sh": "echo ok\n", "run.py": "print(1)\n"})
	assert.Equal(t, []Selected{{"run.sh", "echo ok\n", "file", ".sh"}}, Select(p, nil, []string{"shell"}))
}

// tests/test_opengrep_bridge.py::test_bash_engine_does_not_receive_other_shell_dialects
func TestBashEngineDoesNotReceiveOtherShellDialects(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": "```bash\necho bash\n```\n```fish\necho fish\n```\n```powershell\nWrite-Output pwsh\n```\n"})
	selected := Select(p, nil, []string{"shell"})
	require.Len(t, selected, 1)
	assert.Contains(t, selected[0].Text, "echo bash")
}

// tests/test_opengrep_bridge.py::test_supported_shell_fences_share_one_line_mapped_target
func TestSupportedShellFencesShareOneLineMappedTarget(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": "```bash\necho bash\n```\n```sh\necho sh\n```\n"})
	selected := Select(p, nil, []string{"shell"})
	require.Len(t, selected, 1)
	var lines []string
	for _, l := range strings.Split(selected[0].Text, "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	assert.Equal(t, []string{"echo bash", "echo sh"}, lines)
}

// tests/test_opengrep_bridge.py::test_lifts_python_fences_independent_of_attacker_controlled_grants
func TestLiftsPythonFencesIndependentOfAttackerControlledGrants(t *testing.T) {
	allowed := parsed(t, map[string]string{
		"SKILL.md":  "---\nname: x\nallowed-tools: Bash\n---\n```python\nimport os\nos.system(input())\n```\n",
		"README.md": "```python\nexec(input())\n```\n",
	})
	selected := Select(allowed, nil, []string{"python"})
	require.Len(t, selected, 1)
	assert.Equal(t, "SKILL.md", selected[0].Rel)
	assert.Equal(t, "fence", selected[0].Origin)
	assert.Equal(t, "import os", strings.Split(selected[0].Text, "\n")[5])
	denied := parsed(t, map[string]string{"SKILL.md": "---\nname: x\nallowed-tools: Read\n---\n```python\nexec(input())\n```\n"})
	selected = Select(denied, nil, []string{"python"})
	require.Len(t, selected, 1)
	assert.Contains(t, selected[0].Text, "exec(input())")
}

// tests/test_opengrep_bridge.py::test_nested_manifest_cannot_suppress_fence_analysis
func TestNestedManifestCannotSuppressFenceAnalysis(t *testing.T) {
	p := parsed(t, map[string]string{
		"SKILL.md":        "---\nname: root\nallowed-tools: Bash\n---\n",
		"nested/SKILL.md": "---\nname: child\nallowed-tools: Read\n---\n",
		"nested/task.md":  "```python\nexec(input())\n```\n",
	})
	selected := Select(p, nil, []string{"python"})
	require.Len(t, selected, 1)
	assert.Contains(t, selected[0].Text, "exec(input())")
}

// tests/test_opengrep_bridge.py::test_check_invokes_argument_list_and_converts_json
func TestCheckInvokesArgumentListAndConvertsJSON(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "leak")
	p := parsed(t, map[string]string{"run.py": "import os\nos.system(input())\n"})
	var argv, env []string
	var dir, stderrName string
	fs := run(p, Options{Executable: "opengrep", Runner: func(ctx context.Context, a []string, d string, e []string, stderr *os.File) (int, error) {
		argv, env, dir, stderrName = a, e, d, stderr.Name()
		return fakeRunner(t, result("0000.py", 2, "SXV-008"))(ctx, a, d, e, stderr)
	}})
	require.NotEmpty(t, fs)
	assert.Equal(t, "SXV-008", fs[0].Vector)
	assert.Equal(t, "run.py", fs[0].Path)
	assert.Equal(t, []string{"opengrep", "scan"}, argv[:2])
	for _, flag := range []string{"--json", "--dataflow-traces", "--disable-nosem", "--disable-version-check",
		"--no-git-ignore", "--jobs=1", "--max-memory=512", "--max-target-bytes=5242880",
		"--max-match-per-file=1000", "--timeout=5", "--timeout-threshold=1"} {
		assert.Contains(t, argv, flag)
	}
	assert.Equal(t, filepath.Join(dir, "opengrep-report.json"), arg(argv, "--output"))
	assert.Equal(t, filepath.Join(dir, "rules.yml"), arg(argv, "--config"))
	assert.Equal(t, filepath.Join(dir, "targets"), argv[len(argv)-1])
	assert.Equal(t, filepath.Join(dir, "opengrep-stderr.txt"), stderrName)
	assert.True(t, strings.HasPrefix(filepath.Base(dir), "skill-xray-opengrep-"))
	assert.NoDirExists(t, dir, "temporary tree is removed")
	vars := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		vars[k] = v
	}
	assert.NotContains(t, vars, "AWS_SECRET_ACCESS_KEY")
	under := func(path string) bool { return strings.HasPrefix(path, vars["HOME"]+string(os.PathSeparator)) }
	assert.True(t, under(vars["XDG_CONFIG_HOME"]))
	assert.True(t, under(vars["SEMGREP_SETTINGS_FILE"]))
	assert.Equal(t, filepath.Join(dir, "engine-tmp"), vars["TMPDIR"])
	if runtime.GOOS == "windows" {
		assert.Equal(t, os.Getenv("USERPROFILE"), vars["USERPROFILE"])
		assert.True(t, under(vars["APPDATA"]))
		assert.True(t, under(vars["LOCALAPPDATA"]))
		assert.True(t, strings.HasSuffix(vars["SEMGREP_LOG_FILE"], "engine.log"))
	}
}

// tests/test_opengrep_bridge.py::test_relative_rule_path_is_resolved_before_temporary_cwd
func TestRelativeRulePathIsResolvedBeforeTemporaryCwd(t *testing.T) {
	p := parsed(t, map[string]string{"run.py": "pass\n"})
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "rules.yml"), []byte("rules: []\n"), 0o644))
	t.Chdir(tmp)
	var config, root, text string
	fs := run(p, Options{Executable: "opengrep", Rules: "rules.yml", Runner: func(ctx context.Context, argv []string, d string, e []string, stderr *os.File) (int, error) {
		config, root = arg(argv, "--config"), d
		b, err := os.ReadFile(config)
		require.NoError(t, err)
		text = string(b)
		return fakeRunner(t)(ctx, argv, d, e, stderr)
	}})
	assert.Equal(t, []findings.Finding{}, fs)
	// the engine reads a copy at the engine root, never the file at its own path
	assert.True(t, filepath.IsAbs(config))
	assert.Equal(t, filepath.Join(root, "rules.yml"), config)
	assert.NotEqual(t, filepath.Join(tmp, "rules.yml"), config)
	assert.Equal(t, "rules: []\n", text)
	assert.Equal(t, []string{"opengrep-rules-unavailable"}, rules(run(p, Options{Executable: "opengrep", Rules: "missing.yml", Runner: fakeRunner(t)})))
}

// tests/test_opengrep_bridge.py::test_skipped_selected_target_is_not_clean
func TestSkippedSelectedTargetIsNotClean(t *testing.T) {
	p := parsed(t, map[string]string{"run.py": "exec(input())\n"})
	fs := run(p, Options{Executable: "opengrep", Runner: func(_ context.Context, argv []string, _ string, _ []string, _ *os.File) (int, error) {
		writeReport(t, argv, `{"results": [], "errors": [], "paths": {"scanned": []}}`)
		return 0, nil
	}})
	assert.Equal(t, []string{"opengrep-analysis-incomplete"}, rules(fs))
	assert.Equal(t, "run.py", fs[0].Path)
	assert.Equal(t, "OpenGrep skipped 1 selected code target(s); the candidate result is incomplete.", fs[0].Message)
	fs = run(p, Options{Executable: "opengrep", Runner: func(_ context.Context, argv []string, _ string, _ []string, _ *os.File) (int, error) {
		writeReport(t, argv, `{"results": [], "errors": []}`)
		return 0, nil
	}})
	assert.Equal(t, []string{"opengrep-invalid-output"}, rules(fs))
	assert.Equal(t, "OpenGrep did not report which selected targets it scanned.", fs[0].Message)
}

// tests/test_opengrep_bridge.py::test_missing_engine_timeout_and_invalid_json_are_not_clean
func TestMissingEngineTimeoutAndInvalidJSONAreNotClean(t *testing.T) {
	p := parsed(t, map[string]string{"run.py": "exec(input())\n"})
	// resolve_opengrep -> None: no explicit binary, empty env override, an empty cache, nothing on PATH.
	t.Setenv(envBinary, "")
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")
	fs := run(p, Options{})
	require.Equal(t, []string{"opengrep-unavailable"}, rules(fs))
	assert.Equal(t, "high", fs[0].Severity)
	bogus := filepath.Join(t.TempDir(), "opengrep")
	require.NoError(t, os.WriteFile(bogus, []byte("x"), 0o644))
	assert.Equal(t, []string{"opengrep-unverified"}, rules(run(p, Options{Executable: bogus})))

	timeoutRunner := func(ctx context.Context, _ []string, _ string, _ []string, _ *os.File) (int, error) {
		return -1, context.DeadlineExceeded
	}
	fs = run(p, Options{Executable: "opengrep", Runner: timeoutRunner})
	assert.Equal(t, []string{"opengrep-timeout"}, rules(fs))

	invalidRunner := func(_ context.Context, argv []string, _ string, _ []string, _ *os.File) (int, error) {
		writeReport(t, argv, "not-json")
		return 0, nil
	}
	fs = run(p, Options{Executable: "opengrep", Runner: invalidRunner})
	assert.Equal(t, []string{"opengrep-invalid-output"}, rules(fs))
	assert.Equal(t, "OpenGrep completed without returning valid JSON.", fs[0].Message)

	scalarRunner := func(_ context.Context, argv []string, _ string, _ []string, _ *os.File) (int, error) {
		writeReport(t, argv, "[1]")
		return 0, nil
	}
	fs = run(p, Options{Executable: "opengrep", Runner: scalarRunner})
	assert.Equal(t, "OpenGrep returned an unexpected JSON document.", fs[0].Message)

	failing := func(_ context.Context, _ []string, _ string, _ []string, stderr *os.File) (int, error) {
		stderr.WriteString("  boom  ")
		return 3, nil
	}
	fs = run(p, Options{Executable: "opengrep", Runner: failing})
	assert.Equal(t, []string{"opengrep-execution-error"}, rules(fs))
	assert.Equal(t, "OpenGrep exited with status 3: boom", fs[0].Message)

	// A binary that cannot start through the real runner.
	fs = run(p, Options{Executable: filepath.Join(t.TempDir(), "no-such-opengrep"), Runner: nil})
	assert.Equal(t, []string{"opengrep-unverified"}, rules(fs))
	status, err := execRunner(context.Background(), []string{filepath.Join(t.TempDir(), "no-such-opengrep")}, t.TempDir(), nil, nil)
	assert.Equal(t, 0, status)
	assert.Error(t, err)
	assert.Equal(t, "OpenGrep could not start: FileNotFoundError", couldNotStart(p, err)[0].Message)
}

// tests/test_opengrep_bridge.py::test_missing_and_oversized_reports_are_not_clean
func TestMissingAndOversizedReportsAreNotClean(t *testing.T) {
	p := parsed(t, map[string]string{"run.py": "exec(input())\n"})
	noReport := func(context.Context, []string, string, []string, *os.File) (int, error) { return 0, nil }
	fs := run(p, Options{Executable: "opengrep", Runner: noReport})
	assert.Equal(t, []string{"opengrep-invalid-output"}, rules(fs))
	assert.Equal(t, "OpenGrep completed without producing its JSON report.", fs[0].Message)

	testutil.Swap(t, &maxReportBytes, 3)
	oversized := func(_ context.Context, argv []string, _ string, _ []string, _ *os.File) (int, error) {
		writeReport(t, argv, "1234")
		return 0, nil
	}
	fs = run(p, Options{Executable: "opengrep", Runner: oversized})
	assert.Equal(t, []string{"opengrep-output-limit"}, rules(fs))
	assert.Equal(t, "OpenGrep's JSON report exceeded the 3-byte limit.", fs[0].Message)
}

// Report numbers are int when integral and float64 otherwise, never json.Number.
func TestDecodeReportNormalisesNumbers(t *testing.T) {
	v, err := decodeReport([]byte(`{"a": 1, "b": 1.0, "c": [2, 3e2, 99999999999999999999], "d": true}`))
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"a": 1, "b": 1.0, "c": []any{2, 300.0, 1e20}, "d": true}, v)
	_, err = decodeReport([]byte(`{} trailing`))
	assert.Error(t, err)
	assert.Equal(t, "0000.py", targetName(`C:\Temp\scan\0000.py`))
	assert.Equal(t, "", targetName(nil))
}

// tests/test_opengrep_bridge.py::test_bundled_rules_are_valid_yaml_and_mapped
func TestBundledRulesAreValidYAMLAndMapped(t *testing.T) {
	var doc struct {
		Rules []struct {
			ID        string         `yaml:"id"`
			Languages []string       `yaml:"languages"`
			Metadata  map[string]any `yaml:"metadata"`
		} `yaml:"rules"`
	}
	require.NoError(t, yaml.Unmarshal(Rules, &doc))
	ids, vectors, capabilities := map[string]bool{}, map[string]bool{}, map[string]bool{}
	python, bash := 0, 0
	for _, r := range doc.Rules {
		ids[r.ID] = true
		assert.NotContains(t, r.ID, "poc")
		switch {
		case slices.Equal(r.Languages, []string{"python"}):
			python++
		case slices.Equal(r.Languages, []string{"bash"}):
			bash++
		}
		vectors[r.Metadata["skill_xray_vector"].(string)] = true
		if c, ok := r.Metadata["skill_xray_capability"]; ok {
			capabilities[c.(string)] = true
		}
	}
	assert.Len(t, doc.Rules, 73)
	assert.Len(t, ids, 73)
	assert.Equal(t, 28, python)
	assert.Equal(t, 35, bash)
	assert.Equal(t, map[string]bool{"SXV-005": true, "SXV-008": true, "SXV-009": true, "SXV-010": true, "SXV-018": true,
		"SXV-019": true, "SXV-020": true, "SXV-021": true, "SXV-022": true, "SXV-023": true, "SXV-024": true,
		"SXV-025": true, "SXV-026": true, "SXV-032": true, "SXV-033": true, "SXV-039": true, "SXV-040": true}, vectors)
	assert.Equal(t, map[string]bool{"execution": true, "network": true}, capabilities)
}

// tests/test_taint_engine.py::_result
func taintResult(path, vector string) map[string]any {
	return map[string]any{
		"check_id": "skill-xray.test", "path": path,
		"start": map[string]any{"line": 1, "col": 1}, "end": map[string]any{"line": 1, "col": 5},
		"extra": map[string]any{"message": "matched", "severity": "ERROR",
			"metadata": map[string]any{"skill_xray_vector": vector, "skill_xray_rule": "opengrep-test", "skill_xray_severity": "high"}},
	}
}

// tests/test_taint_engine.py::test_one_process_receives_python_and_supported_shell
func TestOneProcessReceivesPythonAndSupportedShell(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": manifest, "run.py": "pass\n", "run.sh": "echo ok\n"})
	var calls []map[string]bool
	Check(p, Options{Executable: "opengrep", Runner: func(ctx context.Context, argv []string, d string, e []string, stderr *os.File) (int, error) {
		suffixes := map[string]bool{}
		for _, n := range targetNames(argv) {
			suffixes[filepath.Ext(n)] = true
		}
		calls = append(calls, suffixes)
		return fakeRunner(t)(ctx, argv, d, e, stderr)
	}})
	assert.Equal(t, []map[string]bool{{".py": true, ".sh": true}}, calls)
}

// tests/test_taint_engine.py::test_opengrep_finding_is_returned_without_parallel_engine
func TestOpengrepFindingIsReturnedWithoutParallelEngine(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": manifest, "run.py": "print('safe')\n"})
	fs := Check(p, Options{Executable: "opengrep", Runner: fakeRunner(t, taintResult("0000.py", "SXV-008"))})
	require.Len(t, fs, 1)
	assert.Equal(t, "SXV-008", fs[0].Vector)
	assert.Equal(t, "opengrep", fs[0].Evidence["engine"])
}

// tests/test_taint_engine.py::test_unexpected_adapter_exception_is_visible
func TestUnexpectedAdapterExceptionIsVisible(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": manifest, "run.py": "pass\n"})
	fs := Check(p, Options{Executable: "opengrep", Runner: func(context.Context, []string, string, []string, *os.File) (int, error) {
		var zero int
		return 1 / zero, nil
	}})
	require.Len(t, fs, 1)
	assert.Equal(t, "opengrep-internal-error", fs[0].Rule)
	assert.Equal(t, "high", fs[0].Severity)
	assert.Equal(t, "OpenGrep analysis failed unexpectedly: RuntimeError", fs[0].Message)
	assert.Equal(t, map[string]any{"engine": "opengrep"}, fs[0].Evidence)
}

// tests/test_taint_engine.py::test_lane_notes_are_retained_once
func TestLaneNotesAreRetainedOnce(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": manifest, "run.py": "pass\n"})
	note := findings.Finding{Rule: "analysis-incomplete", Severity: "high", Path: "SKILL.md", Message: "unparseable grant"}
	fs := Check(p, Options{Executable: "opengrep", Runner: fakeRunner(t), LaneNotes: []findings.Finding{note}})
	count := 0
	for _, f := range fs {
		if assert.ObjectsAreEqual(note, f) {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

// tests/test_taint_engine.py::test_failed_shared_lane_is_not_rebuilt: an empty non-nil unit
// list selects nothing and never starts the engine.
func TestFailedSharedLaneIsNotRebuilt(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": manifest, "run.py": "pass\n"})
	started := false
	fs := Check(p, Options{Units: []codelane.Unit{}, Runner: func(context.Context, []string, string, []string, *os.File) (int, error) {
		started = true
		return 0, nil
	}})
	assert.Equal(t, []findings.Finding{}, fs)
	assert.False(t, started)
}

// contractCase is one row of either contract fixture.
type contractCase struct {
	Name   string   `json:"name"`
	Code   string   `json:"code"`
	Vector *string  `json:"vector"`
	Count  int      `json:"count"`
	Ext    string   `json:"ext"`
	Source string   `json:"source"`
	Expect []string `json:"expect"`
}

func contract(t *testing.T, name string) []contractCase {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	require.NoError(t, err)
	defer f.Close()
	var cases []contractCase
	for sc := bufio.NewScanner(f); sc.Scan(); {
		var c contractCase
		require.NoError(t, json.Unmarshal(sc.Bytes(), &c))
		cases = append(cases, c)
	}
	return cases
}

// tests/test_opengrep_parity.py::test_frozen_python_contract_has_expected_shape
func TestFrozenPythonContractHasExpectedShape(t *testing.T) {
	cases := contract(t, "opengrep_python_contract.jsonl")
	positives, names := 0, map[string]bool{}
	for _, c := range cases {
		if c.Vector != nil {
			positives++
		}
		names[c.Name] = true
	}
	// Dynamic indexes and explicit dynamic shell settings retain taint unless proven safe.
	assert.Equal(t, [3]int{258, 135, 123}, [3]int{len(cases), positives, len(cases) - positives})
	assert.Len(t, names, len(cases))
}

// tests/test_opengrep_shell_parity.py::test_shell_contract_has_unique_shell_only_cases
func TestShellContractHasUniqueShellOnlyCases(t *testing.T) {
	cases := contract(t, "opengrep_shell_contract.jsonl")
	assert.Len(t, cases, 91)
	names := map[string]bool{}
	for _, c := range cases {
		names[c.Name] = true
		assert.Contains(t, []string{"", "sh"}, c.Ext)
	}
	assert.Len(t, names, len(cases))
}

// A package-level engine gap is anchored to the manifest, so every result has a location.
func TestPackageGapIsAnchoredToTheManifest(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": "---\nname: x\n---\n", "run.py": "exec(input())\n"})
	bogus := filepath.Join(t.TempDir(), "opengrep")
	require.NoError(t, os.WriteFile(bogus, []byte("x"), 0o644))
	fs := run(p, Options{Executable: bogus})
	require.Equal(t, []string{"opengrep-unverified"}, rules(fs))
	assert.Equal(t, "SKILL.md", fs[0].Path)
	assert.Equal(t, "SKILL.md", couldNotStart(p, os.ErrNotExist)[0].Path, "every package-level failure is anchored")
}
