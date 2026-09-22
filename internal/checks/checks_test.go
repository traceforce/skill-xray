package checks

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/codelane"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

func parsed(t *testing.T, files map[string]string) *parse.Package {
	return parse.Parse(ingest.BuildPackage(testutil.MakePackage(t, files)))
}

// run is tests/test_metadata.py::_run: run_checks over a built package.
func run(t *testing.T, files map[string]string) []findings.Finding {
	return Run(parsed(t, files), "", nil)
}

// The registry runs the checks in the Python scanner's _CHECKS order; the module names are
// the ones a check-error message prints.
func TestRegistryIsThePythonOrder(t *testing.T) {
	want := []string{"skill_xray.analyze", "skill_xray.checks.coverage", "skill_xray.checks.grants",
		"skill_xray.checks.hooks", "skill_xray.checks.instruction_exfil", "skill_xray.checks.metadata",
		"skill_xray.checks.obfuscation", "skill_xray.checks.persistence", "skill_xray.checks.preproc",
		"skill_xray.checks.supply_chain", "skill_xray.checks.taint_engine"}
	var got []string
	for _, c := range registry {
		got = append(got, c.module)
	}
	assert.Equal(t, want, got)
	assert.Nil(t, registry[len(registry)-1].fn, "taint_engine is dispatched by Run with the code lane")
}

// tests/test_preproc.py::test_preprocessing_check_is_registered
func TestPreprocessingCheckIsRegistered(t *testing.T) {
	fs := run(t, map[string]string{"SKILL.md": "---\nname: demo\n---\n!`id`\n"})
	assert.True(t, slices.ContainsFunc(fs, func(f findings.Finding) bool { return f.Vector == "SXV-001" }))
}

// tests/test_coverage.py::test_registered_check_failure_is_high_severity
func TestRegisteredCheckFailureIsHighSeverity(t *testing.T) {
	testutil.Swap(t, &registry, []check{{"tests.failing", func(*parse.Package) []findings.Finding { panic("boom") }}})
	fs := Run(&parse.Package{}, "", nil)
	require.Len(t, fs, 1)
	assert.Equal(t, findings.Finding{Rule: "check-error", Severity: "high", Message: "check tests.failing failed: string"}, fs[0])
}

// tests/test_capability.py::test_collector_reaches_bridge_without_new_engine_run
func TestCollectorReachesBridgeWithoutNewEngineRun(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": "---\nname: test\ndescription: ''\n\n---\n", "run.py": "print(1)\n"})
	var calls []*parse.Package
	testutil.Swap(t, &taint, func(p *parse.Package, _ string, _ []codelane.Unit, _ []findings.Finding, observations *[]map[string]any) []findings.Finding {
		calls = append(calls, p)
		*observations = append(*observations, map[string]any{"path": "run.py", "capability": "execution", "state": "present"})
		return nil
	})
	observations := []map[string]any{}
	Run(p, "", &observations)
	assert.Equal(t, []*parse.Package{p}, calls)
	assert.Len(t, observations, 1)
}
