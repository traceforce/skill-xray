package opengrep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pyast"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// Ports of tests/test_opengrep_bridge.py, tests/test_fence_locations.py and
// tests/test_capability.py at the findings_from_report boundary, plus the recorded OpenGrep
// reports of the frozen contracts (testdata/record_contract.py).

// taintFlow is _taint_result; sourceLine 0 leaves the trace alone.
func taintFlow(line int, vector, command string, sourceLine int) map[string]any {
	r := result("0000.py", line, vector)
	extra := r["extra"].(map[string]any)
	extra["metavars"] = map[string]any{"$COMMAND": map[string]any{"abstract_content": command}}
	if sourceLine != 0 {
		extra["dataflow_trace"] = map[string]any{"taint_source": []any{"CliLoc", []any{map[string]any{
			"path":  "0000.py",
			"start": map[string]any{"line": sourceLine, "col": 1},
			"end":   map[string]any{"line": sourceLine, "col": 2},
		}, "source"}}}
	}
	return r
}

func report(results ...map[string]any) map[string]any {
	list := make([]any, 0, len(results))
	for _, r := range results {
		list = append(list, r)
	}
	return map[string]any{"results": list, "errors": []any{}}
}

func file(rel, text string) map[string]Selected {
	return map[string]Selected{"0000.py": {rel, text, "file", ".py"}}
}

func vectors(fs []findings.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Vector)
	}
	return out
}

func ruleSet(fs []findings.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		out[f.Rule] = true
	}
	return out
}

// asJSON round-trips through the to_dict JSON shape so both sides compare as decoded values.
func asJSON(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	var out any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

func TestReportMapsTemporaryPathToOriginalLocation(t *testing.T) {
	r := result("0000.py", 3, "SXV-008")
	r["check_id"] = "C.Users.local.rules.skill-xray.python-local-command-injection"
	r["extra"].(map[string]any)["dataflow_trace"] = map[string]any{"taint_source": []any{map[string]any{"path": `C:\Temp\scan\0000.py`}}}
	targets := map[string]Selected{"0000.py": {"SKILL.md", "\n\nexec(input())", "fence", ".py"}}
	fs := FindingsFromReport(map[string]any{"results": []any{r}, "errors": []any{}}, targets, nil, nil, nil)
	require.Len(t, fs, 1)
	f := fs[0]
	assert.Equal(t, []any{"SXV-008", "opengrep-python-command-injection", "SKILL.md", 3}, []any{f.Vector, f.Rule, f.Path, *f.Line})
	assert.Equal(t, "fence", f.Evidence["origin"])
	assert.Equal(t, "stable-id", f.Evidence["fingerprint"])
	assert.Equal(t, "skill-xray.python-local-command-injection", f.Evidence["engine_rule"])
	trace := f.Evidence["dataflow_trace"].(map[string]any)
	assert.Equal(t, "SKILL.md", trace["taint_source"].([]any)[0].(map[string]any)["path"])
}

func TestUnmappedRuleAndEngineErrorAreVisible(t *testing.T) {
	rep := map[string]any{
		"results": []any{result("0000.py", 3, "SXV-999")},
		"errors":  []any{map[string]any{"path": "0000.py", "message": "parse failed"}},
	}
	fs := FindingsFromReport(rep, file("run.py", "pass"), nil, nil, nil)
	assert.Equal(t, map[string]bool{"opengrep-unmapped-rule": true, "opengrep-analysis-error": true}, ruleSet(fs))
	for _, f := range fs {
		assert.Equal(t, "run.py", f.Path)
	}
}

func TestRejectOnlyPostfilterWorkIsBoundedPerTarget(t *testing.T) {
	calls, shellCalls := 0, 0
	testutil.Swap(t, &pythonDefiniteFalsePositive, func(map[string]any, string, Selected, string, int, int, map[string]*pyast.Module) bool {
		calls++
		return false
	})
	testutil.Swap(t, &subprocessShellStatus, func(*pyast.Module, int, int) (tri, bool) {
		shellCalls++
		return triTrue, false
	})
	var results []map[string]any
	for line := 1; line <= 1000; line++ {
		results = append(results, result("0000.py", line, "SXV-008"))
	}
	fs := FindingsFromReport(report(results...), file("run.py", strings.Repeat("pass\n", 1000)), nil, nil, nil)
	assert.Equal(t, maxPostfiltersPerTarget, calls)
	assert.Equal(t, maxPostfiltersPerTarget, shellCalls)
	assert.Len(t, fs, 1000)
	assert.True(t, slices.ContainsFunc(fs, func(f findings.Finding) bool {
		return f.Evidence["postfilter"] == "retained-after-validation-budget"
	}))
}

var taintSources = []struct{ vector, source string }{
	{"SXV-008", "os.getenv('CFG')"},
	{"SXV-018", "requests.get('https://example.invalid').text"},
}

func TestPythonImportShadowFiltersKnownOpengrepScopeOvertaint(t *testing.T) {
	for _, c := range taintSources {
		text := fmt.Sprintf("import os, subprocess, requests\ncfg = %s\ndef run():\n"+
			"    from mypkg import safe_cfg as cfg\n    subprocess.call(cfg, shell=True)\n", c.source)
		assert.Empty(t, FindingsFromReport(report(taintFlow(5, c.vector, "cfg", 2)), file("run.py", text), nil, nil, nil), c.vector)
	}
}

func TestPythonImportInOtherScopeDoesNotHideFinding(t *testing.T) {
	text := "import os, subprocess\ncfg = os.getenv('CFG')\ndef unrelated():\n" +
		"    from mypkg import safe_cfg as cfg\ndef run():\n    pass\nsubprocess.call(cfg, shell=True)\n"
	fs := FindingsFromReport(report(taintFlow(7, "SXV-008", "cfg", 2)), file("run.py", text), nil, nil, nil)
	assert.Equal(t, []string{"SXV-008"}, vectors(fs))
}

func TestPythonLocalTaintAfterImportIsNotHidden(t *testing.T) {
	for _, c := range taintSources {
		text := fmt.Sprintf("import os, subprocess, requests\ndef run():\n    from mypkg import safe_cfg as cfg\n"+
			"    cfg = %s\n    subprocess.call(cfg, shell=True)\n", c.source)
		fs := FindingsFromReport(report(taintFlow(5, c.vector, "cfg", 4)), file("run.py", text), nil, nil, nil)
		assert.Equal(t, []string{c.vector}, vectors(fs), c.vector)
	}
}

func TestPythonReboundSinkIsFiltered(t *testing.T) {
	for _, c := range []struct{ vector, source string }{{"SXV-008", "sys.argv[1]"}, taintSources[1]} {
		for _, shadow := range []string{"function", "object"} {
			text := fmt.Sprintf("import sys, requests\nfrom os import system\ndef system(command):\n    pass\nsystem(%s)\n", c.source)
			line := 5
			if shadow == "object" {
				text = fmt.Sprintf("import os, sys, requests\nclass Safe:\n    def system(self, command):\n        pass\nos = Safe()\nos.system(%s)\n", c.source)
				line = 6
			}
			assert.Empty(t, FindingsFromReport(report(taintFlow(line, c.vector, c.source, 0)), file("run.py", text), nil, nil, nil), c.vector+" "+shadow)
		}
	}
}

func TestPythonBareAnnotationDoesNotShadowImportedSink(t *testing.T) {
	fs := FindingsFromReport(report(taintFlow(3, "SXV-008", "sys.argv[1]", 0)),
		file("run.py", "import os, sys\nos: object\nos.system(sys.argv[1])\n"), nil, nil, nil)
	assert.Equal(t, []string{"SXV-008"}, vectors(fs))
}

func TestPythonReboundBuiltinSinkIsFiltered(t *testing.T) {
	for _, text := range []string{"exec = print\nexec(input())\n", "def eval(value):\n    print(value)\neval(input())\n"} {
		line := strings.Count(text, "\n")
		assert.Empty(t, FindingsFromReport(report(taintFlow(line, "SXV-008", "input()", 0)), file("run.py", text), nil, nil, nil), text)
	}
}

func TestPythonDeletedOrBareAnnotatedBuiltinSinkIsNotFiltered(t *testing.T) {
	for _, text := range []string{"exec = print\ndel exec\nexec(input())\n", "exec: object\nexec(input())\n"} {
		line := 2
		if strings.Contains(text, "del") {
			line = 3
		}
		fs := FindingsFromReport(report(taintFlow(line, "SXV-008", "input()", 0)), file("run.py", text), nil, nil, nil)
		assert.Equal(t, []string{"SXV-008"}, vectors(fs), text)
	}
}

func TestPythonExplicitGlobalCommandIsNotFiltered(t *testing.T) {
	for _, c := range taintSources {
		text := fmt.Sprintf("import os, subprocess, requests\ncfg = %s\ndef run():\n    global cfg\n    from safe import cfg\n"+
			"    subprocess.call(cfg, shell=True)\n", c.source)
		fs := FindingsFromReport(report(taintFlow(6, c.vector, "cfg", 2)), file("run.py", text), nil, nil, nil)
		assert.Equal(t, []string{c.vector}, vectors(fs), c.vector)
	}
}

func TestPythonFutureSinkRebindingDoesNotHideFinding(t *testing.T) {
	for _, c := range []struct{ vector, source string }{{"SXV-008", "sys.argv[1]"}, taintSources[1]} {
		text := fmt.Sprintf("import os, sys, requests\nos.system(%s)\nos = object()\n", c.source)
		fs := FindingsFromReport(report(taintFlow(2, c.vector, c.source, 0)), file("run.py", text), nil, nil, nil)
		assert.Equal(t, []string{c.vector}, vectors(fs), c.vector)
	}
}

func TestPythonFutureCommandImportDoesNotHideFinding(t *testing.T) {
	text := "import os, subprocess\ncfg = os.getenv('CFG')\ndef run():\n    subprocess.call(cfg, shell=True)\n    from safe import cfg\n"
	fs := FindingsFromReport(report(taintFlow(4, "SXV-008", "cfg", 2)), file("run.py", text), nil, nil, nil)
	assert.Equal(t, []string{"SXV-008"}, vectors(fs))
}

func TestPythonRealSinkAliasIsNotFiltered(t *testing.T) {
	for _, c := range []struct{ prefix, call string }{
		{"import os as operating_system", "operating_system.system"},
		{"from os import system as launch", "launch"},
	} {
		text := fmt.Sprintf("%s\nimport sys\n%s(sys.argv[1])\n", c.prefix, c.call)
		fs := FindingsFromReport(report(taintFlow(3, "SXV-008", "sys.argv[1]", 0)), file("run.py", text), nil, nil, nil)
		assert.Equal(t, []string{"SXV-008"}, vectors(fs), c.call)
	}
}

func TestFinallyReturnOnlySuppressesTheCalledDefinition(t *testing.T) {
	for _, c := range []struct {
		text     string
		sinkLine int
		retained bool
	}{
		{"import os\ndef identity(value):\n    try:\n        return value\n    finally:\n        return 'safe'\nos.system(identity(input()))\n", 7, false},
		{"import os\ndef identity(value):\n    try:\n        return value\n    finally:\n        return 'safe'\ndef outer():\n" +
			"    def identity(value):\n        return value\n    os.system(identity(input()))\nouter()\n", 10, true},
	} {
		fs := FindingsFromReport(report(taintFlow(c.sinkLine, "SXV-008", "identity(input())", c.sinkLine)), file("run.py", c.text), nil, nil, nil)
		assert.Equal(t, c.retained, len(fs) > 0, c.text)
	}
}

func TestSelfAssignmentRespectsPythonLexicalScope(t *testing.T) {
	for _, c := range []struct {
		local      bool
		sourceLine int
		retained   bool
	}{{false, 5, true}, {true, 6, false}} {
		nested := "run = run\nrun(input())\n"
		if c.local {
			nested = "def outer():\n    run = run\n    run(input())\nouter()\n"
		}
		r := taintFlow(3, "SXV-008", "value", c.sourceLine)
		if c.local {
			trace := r["extra"].(map[string]any)["dataflow_trace"].(map[string]any)
			trace["taint_source"].([]any)[1].([]any)[0].(map[string]any)["start"].(map[string]any)["col"] = 9
		}
		fs := FindingsFromReport(report(r), file("run.py", "import os\ndef run(value):\n    os.system(value)\n"+nested), nil, nil, nil)
		assert.Equal(t, c.retained, len(fs) > 0, nested)
	}
}

func TestSubprocessShellBooleanExpression(t *testing.T) {
	for _, c := range []struct {
		shell    string
		retained bool
	}{{"False or True", true}, {"True and True", true}, {"True and False", false}, {"False", false}} {
		text := fmt.Sprintf("import subprocess\nsubprocess.run(input(), shell=%s)\n", c.shell)
		fs := FindingsFromReport(report(taintFlow(2, "SXV-008", "input()", 2)), file("run.py", text), nil, nil, nil)
		assert.Equal(t, c.retained, len(fs) > 0, c.shell)
	}
}

func TestExplicitDynamicSubprocessShellRetainsVector(t *testing.T) {
	text := "import subprocess\nflag = unknown()\nsubprocess.run(input(), shell=flag)\n"
	fs := FindingsFromReport(report(taintFlow(3, "SXV-008", "input()", 3)), file("run.py", text), nil, nil, nil)
	require.Len(t, fs, 1)
	assert.Equal(t, []string{"SXV-008", "opengrep-python-command-injection"}, []string{fs[0].Vector, fs[0].Rule})
	assert.Equal(t, "dynamic-explicit-shell-retained", fs[0].Evidence["shell_validation"])
}

func TestUnresolvedSubprocessKwargsIsFailVisibleWithoutFalseVector(t *testing.T) {
	text := "import subprocess\nsubprocess.run(input(), **options())\n"
	fs := FindingsFromReport(report(taintFlow(2, "SXV-008", "input()", 2)), file("run.py", text), nil, nil, nil)
	require.Len(t, fs, 1)
	assert.Equal(t, []string{"", "analysis-incomplete", "high"}, []string{fs[0].Vector, fs[0].Rule, fs[0].Severity})
	assert.Equal(t, "dynamic-subprocess-kwargs", fs[0].Evidence["reason"])
}

func budgetFindings(statement string) []findings.Finding {
	text := "import subprocess\n" + strings.Repeat(statement+"\n", 33)
	var results []map[string]any
	for line := 2; line < 35; line++ {
		results = append(results, taintFlow(line, "SXV-008", "input()", line))
	}
	return FindingsFromReport(report(results...), file("run.py", text), nil, nil, nil)
}

func TestDynamicShellPolicyIsInvariantAcrossPostfilterBudget(t *testing.T) {
	fs := budgetFindings("subprocess.run(input(), shell=unknown())")
	require.Len(t, fs, 33)
	for i, f := range fs {
		assert.Equal(t, "SXV-008", f.Vector)
		if i < 32 {
			assert.Equal(t, "dynamic-explicit-shell-retained", f.Evidence["shell_validation"])
		}
	}
	assert.Equal(t, "retained-after-validation-budget", fs[32].Evidence["postfilter"])
}

func TestProvenFalseShellIsRejectedUntilValidationBudget(t *testing.T) {
	fs := budgetFindings("subprocess.run(input(), shell=False)")
	require.Len(t, fs, 1)
	assert.Equal(t, 34, *fs[0].Line)
	assert.Equal(t, "SXV-008", fs[0].Vector)
	assert.Equal(t, "retained-after-validation-budget", fs[0].Evidence["postfilter"])
}

func TestOpaqueKwargsIsGapUntilValidationBudgetThenRetained(t *testing.T) {
	fs := budgetFindings("subprocess.run(input(), **options())")
	var gaps, retained []findings.Finding
	for _, f := range fs {
		if f.Vector == "" {
			gaps = append(gaps, f)
		} else {
			retained = append(retained, f)
		}
	}
	require.Len(t, gaps, 32)
	for _, g := range gaps {
		assert.Equal(t, "dynamic-subprocess-kwargs", g.Evidence["reason"])
	}
	require.Len(t, retained, 1)
	assert.Equal(t, 34, *retained[0].Line)
	assert.Equal(t, "retained-after-validation-budget", retained[0].Evidence["postfilter"])
}

type flowCase struct {
	text                 string
	sourceLine, sinkLine int
}

func checkFlows(t *testing.T, cases []flowCase, want []string) {
	t.Helper()
	for _, c := range cases {
		fs := FindingsFromReport(report(taintFlow(c.sinkLine, "SXV-008", "cmd", c.sourceLine)), file("run.py", c.text), nil, nil, nil)
		assert.Equal(t, want, vectors(fs), c.text)
	}
}

func TestPythonMutuallyExclusiveBranchFlowIsFiltered(t *testing.T) {
	checkFlows(t, []flowCase{
		{"import os, sys\ncmd = 'safe'\nif mode:\n    cmd = sys.argv[1]\nelse:\n    os.system(cmd)\n", 4, 6},
		{"import os, sys\ncmd = 'safe'\nmatch mode:\n    case 1:\n        cmd = sys.argv[1]\n    case 2:\n        os.system(cmd)\n", 5, 7},
	}, []string{})
}

func TestPythonSameBranchFlowIsRetained(t *testing.T) {
	checkFlows(t, []flowCase{
		{"import os, sys\nif mode:\n    cmd = sys.argv[1]\n    os.system(cmd)\n", 3, 4},
		{"import os, sys\nmatch mode:\n    case 1:\n        cmd = sys.argv[1]\n        os.system(cmd)\n", 4, 5},
	}, []string{"SXV-008"})
}

func TestPythonBranchToPostJoinFlowIsRetained(t *testing.T) {
	checkFlows(t, []flowCase{
		{"import os, sys\nif mode:\n    cmd = sys.argv[1]\nos.system(cmd)\n", 3, 4},
		{"import os, sys\nmatch mode:\n    case 1:\n        cmd = sys.argv[1]\nos.system(cmd)\n", 4, 5},
	}, []string{"SXV-008"})
}

func TestPythonDifferentLoopIterationsAreNotFiltered(t *testing.T) {
	checkFlows(t, []flowCase{
		{"import os, sys\ncmd = 'safe'\nfor mode in modes:\n    if mode:\n        cmd = sys.argv[1]\n    else:\n        os.system(cmd)\n", 5, 7},
		{"import os, sys\ncmd = 'safe'\nwhile ready():\n    match mode:\n        case 1:\n            cmd = sys.argv[1]\n        case 2:\n            os.system(cmd)\n", 5, 7},
	}, []string{"SXV-008"})
}

func TestPythonTargetIsParsedOncePerReport(t *testing.T) {
	parses := 0
	testutil.Swap(t, &parsePython, func(src string) *pyast.Module {
		parses++
		m, _ := pyast.Parse(src)
		return m
	})
	FindingsFromReport(report(result("0000.py", 2, "SXV-008"), result("0000.py", 3, "SXV-008")),
		file("run.py", "import os\nos.system(input())\nos.system(input())\n"), nil, nil, nil)
	assert.Equal(t, 1, parses)
}

func TestMalformedExtraIsNotABridgeCrash(t *testing.T) {
	r := result("0000.py", 3, "SXV-008")
	r["extra"] = "invalid"
	fs := FindingsFromReport(report(r), file("run.py", "pass\n"), nil, nil, nil)
	assert.Equal(t, []string{"opengrep-unmapped-rule"}, []string{fs[0].Rule})
	assert.Len(t, fs, 1)
}

func TestMalformedReportShapeIsNotClean(t *testing.T) {
	fs := FindingsFromReport(map[string]any{"results": nil, "errors": []any{}}, map[string]Selected{}, nil, nil, nil)
	require.Len(t, fs, 1)
	assert.Equal(t, "opengrep-invalid-output", fs[0].Rule)
}

func TestMalformedErrorsShapeDoesNotDiscardValidResult(t *testing.T) {
	fs := FindingsFromReport(map[string]any{"results": []any{result("0000.py", 3, "SXV-008")}, "errors": nil},
		file("run.py", "\n\npass\n"), nil, nil, nil)
	assert.Equal(t, map[string]bool{"opengrep-invalid-output": true, "opengrep-python-command-injection": true}, ruleSet(fs))
}

func TestMalformedReportEntryIsNotClean(t *testing.T) {
	for _, field := range []string{"results", "errors"} {
		rep := map[string]any{"results": []any{}, "errors": []any{}}
		rep[field] = []any{1}
		fs := FindingsFromReport(rep, map[string]Selected{}, nil, nil, nil)
		require.Len(t, fs, 1, field)
		assert.Equal(t, "opengrep-invalid-output", fs[0].Rule)
	}
}

func TestMalformedMetavarsAreReportedAndNotRetained(t *testing.T) {
	for _, metavars := range []any{"invalid", map[string]any{"$PATH": []any{}}, map[string]any{"$PATH": map[string]any{"abstract_content": []any{}}}} {
		r := result("0000.py", 3, "SXV-008")
		r["extra"].(map[string]any)["metavars"] = metavars
		fs := FindingsFromReport(report(r), file("run.py", "\n\npass\n"), nil, nil, nil)
		assert.Equal(t, map[string]bool{"opengrep-invalid-output": true, "opengrep-python-command-injection": true}, ruleSet(fs))
		i := slices.IndexFunc(fs, func(f findings.Finding) bool { return f.Vector != "" })
		require.GreaterOrEqual(t, i, 0)
		assert.NotContains(t, fs[i].Evidence, "metavars")
	}
}

func TestPythonParameterLaunderedThroughLocalIsRetained(t *testing.T) {
	for _, c := range []struct {
		body, command        string
		sourceLine, sinkLine int
	}{
		// control: the parameter reaches the sink unchanged (retained before and after).
		{"import os, sys\ndef run_it(user_input):\n    os.system(user_input)\nrun_it(sys.argv[1])\n", "user_input", 4, 3},
		// regression: the parameter is laundered through a local before the sink.
		{"import os, sys\ndef run_it(user_input):\n    command = user_input\n    os.system(command)\nrun_it(sys.argv[1])\n", "command", 5, 4},
	} {
		fs := FindingsFromReport(report(taintFlow(c.sinkLine, "SXV-008", c.command, c.sourceLine)), file("run.py", c.body), nil, nil, nil)
		assert.Equal(t, []string{"SXV-008"}, vectors(fs), c.command)
	}
}

func TestPythonAsyncEntrypointDriverIsRetained(t *testing.T) {
	for _, driver := range []string{"asyncio.run(main())", "asyncio.create_task(main())", "asyncio.ensure_future(main())"} {
		body := "import asyncio, os\nasync def main():\n    os.system(input())\n" + driver + "\n"
		fs := FindingsFromReport(report(taintFlow(3, "SXV-008", "input()", 3)), file("run.py", body), nil, nil, nil)
		assert.Equal(t, []string{"SXV-008"}, vectors(fs), driver)
	}
}

func TestPythonTrulyUnawaitedAsyncCallIsStillFiltered(t *testing.T) {
	body := "import asyncio, os\nasync def main():\n    os.system(input())\nmain()\n"
	assert.Empty(t, FindingsFromReport(report(taintFlow(3, "SXV-008", "input()", 3)), file("run.py", body), nil, nil, nil))
}

func TestMalformedMetadataDoesNotDiscardValidSiblingResult(t *testing.T) {
	valid := result("0000.py", 3, "SXV-008")
	malformed := result("0001.py", 3, "SXV-008")
	malformed["extra"].(map[string]any)["metadata"].(map[string]any)["skill_xray_vector"] = map[string]any{}
	targets := map[string]Selected{
		"0000.py": {"valid.py", "\n\npass\n", "file", ".py"},
		"0001.py": {"invalid.py", "\n\npass\n", "file", ".py"},
	}
	fs := FindingsFromReport(report(valid, malformed), targets, nil, nil, nil)
	got := map[[2]string]bool{}
	for _, f := range fs {
		got[[2]string{f.Vector, f.Rule}] = true
	}
	assert.Equal(t, map[[2]string]bool{{"SXV-008", "opengrep-python-command-injection"}: true, {"", "opengrep-unmapped-rule"}: true}, got)
}

func TestInvalidResultLocationIsFailVisible(t *testing.T) {
	for _, start := range []map[string]any{{}, {"line": nil}, {"line": "3"}, {"line": 0}, {"line": -1}, {"line": true}, {"line": 999}} {
		r := result("0000.py", 3, "SXV-008")
		r["start"] = start
		fs := FindingsFromReport(report(r), file("run.py", "\n\npass\n"), nil, nil, nil)
		require.Len(t, fs, 1, fmt.Sprint(start))
		assert.Equal(t, []string{"", "opengrep-invalid-output", "high"}, []string{fs[0].Vector, fs[0].Rule, fs[0].Severity})
	}
}

func TestMalformedResultColumnDoesNotCrashSorting(t *testing.T) {
	good := result("0000.py", 2, "SXV-008")
	bad := result("0000.py", 3, "SXV-008")
	bad["start"].(map[string]any)["col"] = "not-an-int"
	fs := FindingsFromReport(report(good, bad), file("run.py", "\n\n\npass\n"), nil, nil, nil)
	assert.Equal(t, map[string]bool{"opengrep-python-command-injection": true}, ruleSet(fs))
	assert.Len(t, fs, 2)
}

func TestEngineErrorRedactsLocalPaths(t *testing.T) {
	rep := map[string]any{"results": []any{}, "errors": []any{map[string]any{"path": "0000.py", "message": "/tmp/private/0000.py failed"}}}
	fs := FindingsFromReport(rep, file("run.py", "pass"), nil, []string{"/tmp/private"}, nil)
	require.Len(t, fs, 1)
	assert.NotContains(t, fs[0].Message, "/tmp/private")
	assert.Contains(t, fs[0].Message, "<local>/0000.py failed")
}

func TestAllBoundedEngineErrorsRemainVisible(t *testing.T) {
	targets := map[string]Selected{}
	var errs []any
	for i := 0; i < 25; i++ {
		name := fmt.Sprintf("%04d.py", i)
		targets[name] = Selected{fmt.Sprintf("run-%d.py", i), "pass", "file", ".py"}
		errs = append(errs, map[string]any{"path": name, "message": "parse failed"})
	}
	assert.Len(t, FindingsFromReport(map[string]any{"results": []any{}, "errors": errs}, targets, nil, nil, nil), 25)
}

// ---- tests/test_fence_locations.py (bridge boundary) --------------------------------------------

// fixture is _fixture: one Python fence under a container prefix; returns the package, the
// lone selected target and the generated line holding command.
func fixture(t *testing.T, prefix, command string) (*parse.Package, Selected, int) {
	t.Helper()
	body := prefix + "```python\n" + prefix + command + "\n" + prefix + "```\n"
	if prefix == "list" {
		body = "- Read the file:\n\n  ```python\n  " + command + "\n  ```\n"
	}
	p := parsed(t, map[string]string{"SKILL.md": "---\nname: test\nallowed-tools: Read\n---\n" + body})
	selected := Select(p, nil, []string{"python"})
	require.Len(t, selected, 1)
	line := 1 + slices.IndexFunc(strings.Split(selected[0].Text, "\n"), func(l string) bool { return strings.Contains(l, command) })
	return p, selected[0], line
}

// native is _native: a credential-read result whose end column is the command's byte length.
func native(line int, command string, startCol int) map[string]any {
	return map[string]any{
		"path": "0000.py", "check_id": "skill-xray.python-credential-read",
		"start": map[string]any{"line": line, "col": startCol, "offset": 0},
		"end":   map[string]any{"line": line, "col": len(command) + 1, "offset": 20},
		"extra": map[string]any{"message": "Python code reads a private credential file.",
			"metadata": map[string]any{"skill_xray_vector": "SXV-023", "skill_xray_rule": "opengrep-credential-read", "skill_xray_severity": "high"}},
	}
}

func one(t *testing.T, rep map[string]any, targets map[string]Selected, p *parse.Package) findings.Finding {
	t.Helper()
	fs := FindingsFromReport(rep, targets, p, nil, nil)
	require.Len(t, fs, 1)
	return fs[0]
}

// span is the bytes of line between the evidence's start and end columns.
func span(text string, line int, loc map[string]any) string {
	source := strings.Split(text, "\n")[line-1]
	start := loc["start"].(map[string]any)["col"].(int)
	end := loc["end"].(map[string]any)["col"].(int)
	return source[start-1 : end-1]
}

func TestPrimaryFenceRegionSelectsOriginalSource(t *testing.T) {
	call := `open("~/.ssh/id_rsa")`
	for _, prefix := range []string{"", "   ", "> ", "list"} {
		for _, leading := range []string{"", `label = "é😀"; `} {
			command := leading + call
			p, target, line := fixture(t, prefix, command)
			nat := native(line, command, len(leading)+1)
			original := pytext.DeepCopy(nat)
			f := one(t, map[string]any{"results": []any{nat}}, map[string]Selected{"0000.py": target}, p)
			assert.Equal(t, "validated", f.Evidence["location_mapping"], prefix+leading)
			assert.Equal(t, call, span(*p.ByRel["SKILL.md"].Text, line, f.Evidence), prefix+leading)
			assert.Equal(t, original, nat)
		}
	}
}

func TestTracePositionsMapToOriginalSourceAndKeepEngineEvidence(t *testing.T) {
	command := `value = "é😀"; open("~/.ssh/id_rsa")`
	for _, prefix := range []string{"   ", "> ", "list"} {
		p, target, line := fixture(t, prefix, command)
		nat := native(line, command, 1)
		loc := func() map[string]any {
			return map[string]any{"path": "0000.py", "start": pytext.DeepCopy(nat["start"]), "end": pytext.DeepCopy(nat["end"])}
		}
		nat["extra"].(map[string]any)["dataflow_trace"] = map[string]any{
			"taint_source":      []any{"CliLoc", []any{loc(), command}},
			"intermediate_vars": []any{map[string]any{"location": loc(), "content": command}},
			"taint_sink":        []any{"CliLoc", []any{loc(), command}},
		}
		f := one(t, map[string]any{"results": []any{nat}}, map[string]Selected{"0000.py": target}, p)
		trace := f.Evidence["dataflow_trace"].(map[string]any)
		source := *p.ByRel["SKILL.md"].Text
		for _, step := range []map[string]any{
			trace["taint_source"].([]any)[1].([]any)[0].(map[string]any),
			trace["intermediate_vars"].([]any)[0].(map[string]any)["location"].(map[string]any),
			trace["taint_sink"].([]any)[1].([]any)[0].(map[string]any),
		} {
			assert.Equal(t, command, span(source, line, step), prefix)
		}
		engine := f.Evidence["engine_dataflow_trace"].(map[string]any)
		assert.Equal(t, 1, engine["taint_source"].([]any)[1].([]any)[0].(map[string]any)["start"].(map[string]any)["col"])
		assert.Greater(t, trace["taint_source"].([]any)[1].([]any)[0].(map[string]any)["start"].(map[string]any)["col"].(int), 1)
	}
}

func TestUnprovableFenceMappingRetainsFindingWithExplicitLimitations(t *testing.T) {
	command := `open("~/.ssh/id_rsa")`
	for _, damage := range []string{"tab", "different-source", "multiline"} {
		p, target, line := fixture(t, "   ", command)
		nat := native(line, command, 1)
		artifact := p.ByRel["SKILL.md"]
		switch damage {
		case "tab":
			*artifact.Text = strings.ReplaceAll(*artifact.Text, "   "+command, "\t"+command)
		case "different-source":
			*artifact.Text = strings.ReplaceAll(*artifact.Text, command, "pass # "+strings.Repeat("x", len(command)))
		default:
			nat["end"] = map[string]any{"line": line + 1, "col": 1}
		}
		loc := map[string]any{"path": "0000.py", "start": pytext.DeepCopy(nat["start"]), "end": pytext.DeepCopy(nat["end"])}
		nat["extra"].(map[string]any)["dataflow_trace"] = map[string]any{
			"taint_source": []any{"CliLoc", []any{loc, command}},
			"taint_sink":   []any{"CliLoc", []any{loc, command}},
		}
		f := one(t, map[string]any{"results": []any{nat}}, map[string]Selected{"0000.py": target}, p)
		assert.Equal(t, "SXV-023", f.Vector, damage)
		assert.Equal(t, "unvalidated", f.Evidence["location_mapping"], damage)
		assert.Equal(t, "unvalidated", f.Evidence["trace_mapping"], damage)
		assert.Nil(t, f.Column, damage)
		mapped := f.Evidence["dataflow_trace"].(map[string]any)["taint_source"].([]any)[1].([]any)[0].(map[string]any)
		assert.Equal(t, nat["start"], mapped["start"], damage)
		assert.Equal(t, nat["start"], f.Evidence["engine_location"].(map[string]any)["start"], damage)
	}
}

func TestFileCoordinatesAreUnchanged(t *testing.T) {
	source := `label = "é😀"; open("~/.ssh/id_rsa")`
	p := parsed(t, map[string]string{"run.py": source})
	selected := Select(p, nil, []string{"python"})
	require.Len(t, selected, 1)
	nat := native(1, source, len(`label = "é😀"; `)+1)
	f := one(t, map[string]any{"results": []any{nat}}, map[string]Selected{"0000.py": selected[0]}, p)
	assert.Equal(t, nat["start"].(map[string]any)["col"], *f.Column)
	assert.Equal(t, nat["start"], f.Evidence["start"])
	assert.NotContains(t, f.Evidence, "engine_location")
	assert.Equal(t, `open("~/.ssh/id_rsa")`, span(source, 1, f.Evidence))
}

func TestPostfiltersReceiveGeneratedColumnsBeforeReportingMap(t *testing.T) {
	command := "os.system(input())"
	p, target, line := fixture(t, "   ", command)
	nat := native(line, command, 1)
	nat["extra"].(map[string]any)["metadata"].(map[string]any)["skill_xray_vector"] = "SXV-008"
	var checked [][3]any
	testutil.Swap(t, &subprocessShellStatus, func(_ *pyast.Module, line, col int) (tri, bool) {
		checked = append(checked, [3]any{"shell", line, col})
		return triTrue, false
	})
	testutil.Swap(t, &pythonDefiniteFalsePositive, func(_ map[string]any, _ string, _ Selected, _ string, line, col int, _ map[string]*pyast.Module) bool {
		checked = append(checked, [3]any{"taint", line, col})
		return false
	})
	f := one(t, map[string]any{"results": []any{nat}}, map[string]Selected{"0000.py": target}, p)
	assert.Equal(t, [][3]any{{"shell", line, 1}, {"taint", line, 1}}, checked)
	assert.Equal(t, 4, *f.Column)
	assert.Equal(t, []string{"high", "SXV-008"}, []string{f.Severity, f.Vector})
}

func TestMultilineFenceSpanRequiresExactOriginalSubstring(t *testing.T) {
	lines := []string{"open(", `    "~/.ssh/id_rsa")`}
	for _, c := range []struct {
		prefix    string
		validated bool
	}{{"", true}, {"   ", false}} {
		body := c.prefix + "```python\n" + c.prefix + lines[0] + "\n" + c.prefix + lines[1] + "\n" + c.prefix + "```\n"
		p := parsed(t, map[string]string{"SKILL.md": "---\nname: test\n---\n" + body})
		selected := Select(p, nil, []string{"python"})
		require.Len(t, selected, 1)
		nat := native(5, lines[0], 1)
		nat["end"] = map[string]any{"line": 6, "col": len(lines[1]) + 1}
		f := one(t, map[string]any{"results": []any{nat}}, map[string]Selected{"0000.py": selected[0]}, p)
		want := "unvalidated"
		if c.validated {
			want = "validated"
		}
		assert.Equal(t, want, f.Evidence["location_mapping"], c.prefix)
		if c.validated {
			source := strings.Split(*p.ByRel["SKILL.md"].Text, "\n")
			assert.Equal(t, map[string]any{"line": 5, "col": 1}, f.Evidence["start"])
			assert.Equal(t, map[string]any{"line": 6, "col": len(lines[1]) + 1}, f.Evidence["end"])
			assert.Equal(t, lines[1], source[5])
		}
	}
}

func TestUnmappedOccurrencesSurviveAllDeduplication(t *testing.T) {
	first := `open("~/.ssh/id_rsa")`
	for _, separator := range []string{"; ", ";\t"} {
		for _, samePath := range []bool{false, true} {
			second := `open("~/.aws/credentials")`
			if samePath {
				second = first
			}
			command := first + separator + second
			p, target, line := fixture(t, "", command)
			a := native(line, first, 1)
			b := native(line, command, len(first+separator)+1)
			engine := map[string]any{"results": []any{b, a, pytext.DeepCopy(a), pytext.DeepCopy(b)}}
			original := pytext.DeepCopy(engine)
			fs := FindingsFromReport(engine, map[string]Selected{"0000.py": target}, p, nil, nil)
			require.Len(t, fs, 2, separator)
			assert.Equal(t, original, engine)
			kept := findings.CapFindings(slices.Repeat(fs, findings.Cap+1))
			assert.Equal(t, fs, kept)
			reversed := slices.Clone(kept)
			slices.Reverse(reversed)
			assert.Equal(t, fs, findings.Dedupe(reversed))
			cols := map[int]bool{}
			for _, f := range fs {
				assert.Equal(t, []any{"SXV-023", "SKILL.md", line, "high"}, []any{f.Vector, f.Path, *f.Line, f.Severity})
				if strings.Contains(separator, "\t") {
					assert.Nil(t, f.Column)
					cols[f.Evidence["engine_location"].(map[string]any)["start"].(map[string]any)["col"].(int)] = true
				}
			}
			if strings.Contains(separator, "\t") {
				assert.Equal(t, map[int]bool{1: true, len(first+separator) + 1: true}, cols)
			}
		}
	}
}

// ---- tests/test_capability.py (bridge boundary) --------------------------------------------------

func skillManifest(grants string) string {
	return fmt.Sprintf("---\nname: test\ndescription: ''\n%s\n---\n", grants)
}

// capabilityResult is tests/test_capability.py::_result.
func capabilityResult(capability string, line int) map[string]any {
	return map[string]any{
		"check_id": "test-capability", "path": "0000.py",
		"start": map[string]any{"line": line, "col": 1}, "end": map[string]any{"line": line, "col": 12},
		"extra": map[string]any{"metadata": map[string]any{
			"skill_xray_vector": "SXV-033", "skill_xray_rule": "permission-understatement",
			"skill_xray_severity": "high", "skill_xray_capability": capability,
		}},
	}
}

func TestCollectsValidObservationsWithoutChangingFindings(t *testing.T) {
	code := "import requests\nrequests.get('https://example.invalid')\n"
	for _, grants := range []string{"allowed-tools: WebFetch", "", "allowed-tools: Read"} {
		p := parsed(t, map[string]string{"SKILL.md": skillManifest(grants), "run.py": code})
		rep := report(capabilityResult("network", 2))
		before := FindingsFromReport(rep, file("run.py", code), p, nil, nil)
		var observations []map[string]any
		after := FindingsFromReport(rep, file("run.py", code), p, nil, &observations)
		assert.Equal(t, asJSON(t, before), asJSON(t, after), grants)
		require.Len(t, observations, 1, grants)
		hit := observations[0]
		assert.Equal(t, []any{"run.py", 2, 1, "present"}, []any{hit["path"], hit["line"], hit["column"], hit["state"]}, grants)
	}
}

func TestShadowedRequestsIsNotAnObservation(t *testing.T) {
	code := "class Fake:\n    def get(self, url): pass\nrequests = Fake()\nrequests.get('x')\n"
	p := parsed(t, map[string]string{"SKILL.md": skillManifest(""), "run.py": code})
	var observations []map[string]any
	FindingsFromReport(map[string]any{"results": []any{capabilityResult("network", 4)}}, file("run.py", code), p, nil, &observations)
	for _, hit := range observations {
		assert.NotEqual(t, "present", hit["state"])
	}
}

func TestObservationBudgetCannotStealUnderstatementBudget(t *testing.T) {
	code := "import requests, subprocess\nrequests.get('https://example.invalid')\nsubprocess.run(['echo'])\n"
	p := parsed(t, map[string]string{"SKILL.md": skillManifest("allowed-tools: WebFetch"), "run.py": code})
	results := []any{}
	for i := 0; i < 40; i++ {
		results = append(results, capabilityResult("network", 2))
	}
	rep := map[string]any{"results": append(results, capabilityResult("execution", 3))}
	before := FindingsFromReport(rep, file("run.py", code), p, nil, nil)
	var observations []map[string]any
	after := FindingsFromReport(rep, file("run.py", code), p, nil, &observations)
	assert.Equal(t, asJSON(t, before), asJSON(t, after))
	assert.True(t, slices.ContainsFunc(after, func(f findings.Finding) bool { return f.Evidence["understated_capability"] == "execution" }))
	assert.True(t, slices.ContainsFunc(observations, func(hit map[string]any) bool { return hit["reason"] == "validation-budget" }))
}

func TestMissingManifestAndFailedAstStayUnknown(t *testing.T) {
	p := parsed(t, map[string]string{"run.py": "import requests\nrequests.get('x')\n"})
	p.ByRel["run.py"].PyTree = nil
	var observations []map[string]any
	FindingsFromReport(map[string]any{"results": []any{capabilityResult("network", 2)}},
		file("run.py", *p.ByRel["run.py"].Text), p, nil, &observations)
	require.Len(t, observations, 1)
	assert.Equal(t, "unknown", observations[0]["state"])
	assert.Equal(t, "observation-unvalidated", observations[0]["reason"])
}

func TestOptionalValidatorFailurePreservesExistingFindings(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": skillManifest("allowed-tools: WebFetch"), "run.py": "import requests\nrequests.get('x')\n"})
	targets := file("run.py", *p.ByRel["run.py"].Text)
	other := capabilityResult("network", 2)
	metadata := other["extra"].(map[string]any)["metadata"].(map[string]any)
	metadata["skill_xray_vector"], metadata["skill_xray_rule"] = "SXV-039", "persistence"
	delete(metadata, "skill_xray_capability")
	rep := map[string]any{"results": []any{other, capabilityResult("network", 2)}}
	before := FindingsFromReport(rep, targets, p, nil, nil)
	testutil.Swap(t, &networkCapabilityIsInvalid, func(*pyast.Module, int, int) bool { panic("validator unavailable") })
	var observations []map[string]any
	after := FindingsFromReport(rep, targets, p, nil, &observations)
	assert.Equal(t, before, after)
	assert.NotEmpty(t, before)
	require.Len(t, observations, 1)
	assert.Equal(t, "unknown", observations[0]["state"])
	assert.Equal(t, "validation-error", observations[0]["reason"])
}

func TestDenialScopePreservesValidatedObservations(t *testing.T) {
	for _, c := range []struct {
		capability, denial string
		understated        bool
	}{
		{"execution", "Bash(rm:*)", false}, {"execution", "Bash(python:*)", false},
		{"execution", "Bash(curl:*)", false}, {"execution", "Bash", true},
		{"network", "WebFetch(domain:*)", true},
		{"network", "WebFetch(domain:example.invalid)", false},
	} {
		code := "import requests\nrequests.get('https://example.invalid')\n"
		if c.capability == "execution" {
			code = "import subprocess\nsubprocess.run(['echo', 'ok'])\n"
		}
		p := parsed(t, map[string]string{"SKILL.md": skillManifest("disallowed-tools: " + c.denial), "run.py": code})
		var observations []map[string]any
		fs := FindingsFromReport(map[string]any{"results": []any{capabilityResult(c.capability, 2)}}, file("run.py", code), p, nil, &observations)
		understated := slices.ContainsFunc(fs, func(f findings.Finding) bool { return f.Vector == "SXV-033" })
		assert.Equal(t, c.understated, understated, c.denial)
		require.Len(t, observations, 1, c.denial)
		assert.Equal(t, "present", observations[0]["state"], c.denial)
		if c.understated {
			assert.Equal(t, []any{"run.py", 2, "high"}, []any{fs[0].Path, *fs[0].Line, fs[0].Severity}, c.denial)
			assert.Equal(t, c.capability, fs[0].Evidence["understated_capability"], c.denial)
		}
	}
}

// ---- recorded OpenGrep reports (testdata/record_contract.py) ------------------------------------

type recorded struct {
	Files     map[string]string `json:"files"`
	Languages []string          `json:"languages"`
	Targets   map[string]struct {
		Rel, Origin, Suffix string
	} `json:"targets"`
	Report   json.RawMessage `json:"report"`
	Findings []any           `json:"findings"`
}

// replay rebuilds a recorded package, replays its OpenGrep report through the Go bridge exactly
// as run does, and asserts the findings equal the oracle's; it returns them for contract checks.
// record loads testdata/<name>.recorded.json, or skips the test when it was never recorded.
func record(t *testing.T, name string) recorded {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name+".recorded.json"))
	if err != nil {
		t.Skipf("%s not recorded (testdata/record_contract.py): %v", name, err)
	}
	var rec recorded
	require.NoError(t, json.Unmarshal(data, &rec))
	return rec
}

func replay(t *testing.T, name string) []findings.Finding {
	t.Helper()
	rec := record(t, name)
	p := parsed(t, rec.Files)
	targets := map[string]Selected{}
	for i, s := range Select(p, nil, rec.Languages) {
		targets[fmt.Sprintf("%04d%s", i, s.Suffix)] = s
	}
	require.Len(t, targets, len(rec.Targets))
	for name, want := range rec.Targets {
		assert.Equal(t, [3]string{want.Rel, want.Origin, want.Suffix}, [3]string{targets[name].Rel, targets[name].Origin, targets[name].Suffix}, name)
	}
	doc, err := decodeReport(rec.Report)
	require.NoError(t, err)
	rep := doc.(map[string]any)
	fs := FindingsFromReport(rep, targets, p, []string{"<temporary>", "<rules>", "<temporary>\\targets"}, nil)
	fs = findings.CapFindings(append(fs, coverageFromReport(rep, targets)...))
	assert.Equal(t, rec.Findings, asJSON(t, fs), name)
	return fs
}

// tests/test_opengrep_parity.py::test_live_opengrep_matches_frozen_python_contract, replayed.
func TestRecordedPythonContractMatchesFrozenContract(t *testing.T) {
	_, want, wantGaps := contractExpectations(t)
	fs := replay(t, "python_contract")
	assert.Equal(t, want, counts(fs))
	assert.Equal(t, wantGaps, gapReasons(fs))
}

// tests/test_opengrep_shell_parity.py::test_live_opengrep_matches_shell_contract_exactly, replayed.
func TestRecordedShellContractMatchesExactly(t *testing.T) {
	rows := contract(t, "opengrep_shell_contract.jsonl")
	require.Len(t, rows, 91)
	fs := replay(t, "shell_contract")
	expected := map[[2]string]int{}
	for i, c := range rows {
		ext := ""
		if c.Ext != "" {
			ext = ".sh"
		}
		path := fmt.Sprintf("%03d_%s%s", i, c.Name, ext)
		for _, v := range c.Expect {
			expected[[2]string{path, v}]++
		}
	}
	actual := map[[2]string]int{}
	for _, f := range fs {
		assert.NotEmpty(t, f.Vector, f.Rule)
		actual[[2]string{f.Path, f.Vector}]++
	}
	assert.Equal(t, expected, actual)
}

// tests/test_opengrep_parity.py::test_live_opengrep_keeps_three_nonliteral_positive_contracts, replayed.
func TestRecordedFenceContractKeepsThreeNonliteralPositives(t *testing.T) {
	assertThreeNonliteralPositives(t, replay(t, "fence_contract"))
}

// tests/test_opengrep_bridge.py::test_real_opengrep_phase1_matrix_when_available, replayed.
func TestRecordedPhase1Matrix(t *testing.T) {
	assert.Equal(t, phase1Expected, vectorsByPath(replay(t, "phase1_matrix")))
}
