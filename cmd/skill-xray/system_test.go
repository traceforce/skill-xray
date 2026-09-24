package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/llm"
	"github.com/traceforce/skill-xray/internal/metadata"
	"github.com/traceforce/skill-xray/internal/opengrep"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/sarif"
	"github.com/traceforce/skill-xray/internal/scan"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// leaky is a manifest whose prose commits a GitHub token: an SXV-017 finding from the
// supply-chain lane alone, so no engine binary is needed.
var leaky = map[string]string{"SKILL.md": manifest + "Authenticate with ghp_" + strings.Repeat("a", 36) + " first.\n"}

// systemRoot is a discovery root holding a clean package and the leaky one.
func systemRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, files := range map[string]map[string]string{"clean": testutil.Microcorpus["benign"], "leaky": leaky} {
		require.NoError(t, os.Rename(testutil.MakePackage(t, files), filepath.Join(root, name)))
	}
	return root
}

// runs validates every run of a merged report on its own and returns them.
func runs(t *testing.T, doc any) []any {
	t.Helper()
	out := at(doc, "runs").([]any)
	for _, run := range out {
		require.NoError(t, sarif.Validate(map[string]any{"version": at(doc, "version"), "$schema": at(doc, "$schema"), "runs": []any{run}}))
	}
	return out
}

func TestSubcommandsKeepUsageErrors(t *testing.T) {
	for _, c := range []struct{ argv, want string }{
		{"scan", "accepts 1 arg"},
		{"scan a b", "accepts 1 arg"},
		{"scan pkg --output ", "non-empty path"},
		{"system-scan extra", "skill-xray system-scan --root <dir>"},
		{"system-scan --output ", "non-empty path"},
		{"pkg --analyze", "unknown command"},
		{"--json", "unknown flags --json"},
		{"--json pkg", "skill-xray scan <package>"},
		{"--install-opengrep", "unknown flags --install-opengrep"},
	} {
		t.Run(c.argv, func(t *testing.T) {
			rc, _, stderr := cli(t, strings.Split(c.argv, " ")...)
			assert.Equal(t, 2, rc)
			assert.Contains(t, stderr, c.want)
		})
	}
}

// The console shows one verdict line per package, the report path and a summary; the report
// holds one validated run per package.
func TestSystemScanConsoleAndReport(t *testing.T) {
	target := filepath.Join(t.TempDir(), "system.sarif")
	rc, stdout, stderr := cli(t, "system-scan", "--root", systemRoot(t), "--output", target)
	require.Equal(t, 0, rc, stderr)
	assert.Empty(t, stderr)
	assert.Contains(t, stdout, "CLEAN     seen=1   read=1   cov=100.0%  ")
	assert.Contains(t, stdout, "BLOCKING  seen=1   read=1   cov=100.0%  ")
	assert.Contains(t, stdout, "report: "+target+"\n")
	assert.True(t, strings.HasSuffix(stdout, "packages: 2, blocking: 1, with findings: 0, clean: 1, incomplete: 0, discovery exceptions: 0\n"), stdout)
	doc := sarifDoc(t, target)
	rs := runs(t, doc)
	require.Len(t, rs, 2)
	vectors := 0
	for _, run := range rs {
		for _, r := range at(run, "results").([]any) {
			if at(r, "properties", "sxv") == "SXV-017" {
				vectors++
			}
		}
	}
	assert.Equal(t, 1, vectors)
}

// A package whose run cannot be built is named on stderr and left out of the report; the other
// packages keep theirs and the exit code says the scan is incomplete.
func TestSystemScanKeepsTheReportWhenOneRunCannotBeBuilt(t *testing.T) {
	real := scanReport
	testutil.Swap(t, &scanReport, func(p *parse.Package, o scan.Options) (*scan.ScanReport, error) {
		report, err := real(p, o)
		switch {
		case err != nil:
		case p.Name == "leaky": // as scan records a correlation step that panicked
			report.Correlation.Errors = []string{"correlation-error: RuntimeError"}
			report.ContextErrors = append(report.ContextErrors, "correlation-error: RuntimeError")
		case p.Name == "clean": // a context stage that failed on a package without findings
			report.ContextErrors = append(report.ContextErrors, "capability-context-error: RuntimeError")
		}
		return report, err
	})
	target := filepath.Join(t.TempDir(), "system.sarif")
	rc, stdout, stderr := cli(t, "system-scan", "--root", systemRoot(t), "--output", target)
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "no SARIF run for ")
	assert.Contains(t, stderr, "leaky: Cannot emit SARIF after a correlation failure\n")
	assert.Contains(t, stderr, "leaky: correlation-error: RuntimeError\n")
	assert.Contains(t, stdout, "report: "+target+"\n")
	assert.Contains(t, stdout, "FINDINGS  seen=1   read=1   cov=100.0%  ", "a context error never reads as clean")
	assert.Contains(t, stdout, "packages: 2, blocking: 1, with findings: 1, clean: 0, incomplete: 2, discovery exceptions: 0\n")
	assert.Len(t, runs(t, sarifDoc(t, target)), 1)
}

// A target inside a discovered package is refused before any package is scanned.
func TestSystemScanSarifRefusesAScannedPackage(t *testing.T) {
	root := systemRoot(t)
	target := filepath.Join(root, "leaky", "report.sarif")
	noScan(t)
	rc, stdout, stderr := cli(t, "system-scan", "--root", root, "--output", target)
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "cannot write SARIF")
	assert.Empty(t, stdout)
	assert.NoFileExists(t, target)
}

func TestSystemScanEmptyRoot(t *testing.T) {
	target := filepath.Join(t.TempDir(), "system.sarif")
	rc, stdout, stderr := cli(t, "system-scan", "--root", t.TempDir(), "--output", target)
	assert.Equal(t, 0, rc)
	assert.Contains(t, stderr, "note: no skill packages found under ")
	assert.True(t, strings.HasSuffix(stdout, "packages: 0, blocking: 0, with findings: 0, clean: 0, incomplete: 0, discovery exceptions: 0\n"), stdout)
	assert.Equal(t, []any{}, at(sarifDoc(t, target), "runs"))
}

// A discovery walk that hits its directory budget is a visible gap: the exit is 2, stderr names
// the reason and the summary line counts the exception, even with no package found.
func TestSystemScanFailsVisibleWhenDiscoveryTruncates(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0o755))
	testutil.Swap(t, &ingest.MaxDiscoveryDirs, 1)
	target := filepath.Join(t.TempDir(), "system.sarif")
	rc, stdout, stderr := cli(t, "system-scan", "--root", root, "--output", target)
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "skill discovery incomplete (walk_truncated)")
	assert.True(t, strings.HasSuffix(stdout, "discovery exceptions: 1\n"), stdout)
}

// A --root that does not exist or is not a directory is a discovery exception on stderr with
// exit 2, never an empty clean run.
func TestSystemScanNamedRootMustBeADirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "SKILL.md")
	require.NoError(t, os.WriteFile(file, []byte(manifest), 0o644))
	for name, root := range map[string]string{"missing": filepath.Join(t.TempDir(), "typo"), "file": file} {
		target := filepath.Join(t.TempDir(), "system.sarif")
		rc, stdout, stderr := cli(t, "system-scan", "--root", root, "--output", target)
		assert.Equal(t, 2, rc, name)
		assert.Contains(t, stderr, "skill discovery incomplete (", name)
		assert.True(t, strings.HasSuffix(stdout, "discovery exceptions: 1\n"), stdout)
	}
	rc, _, stderr := cli(t, "system-scan", "--root", file, "--output", file) // the report must not replace the file named as a root
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "Report must be outside the scanned package")
	kept, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, manifest, string(kept))
}

// Every package whose analysis did not complete is explained on stderr and counted on the
// summary line, so the exit 2 of a system scan names its causes.
func TestSystemScanExplainsIncompletePackages(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "ruby"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "ruby", "SKILL.md"), []byte(manifest), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "ruby", "tool.rb"), []byte("puts 1\n"), 0o644))
	target := filepath.Join(t.TempDir(), "system.sarif")
	rc, stdout, stderr := cli(t, "system-scan", "--root", root, "--output", target)
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "analysis incomplete: ")
	assert.Contains(t, stderr, "tool.rb")
	assert.Contains(t, stdout, "incomplete: 1, discovery exceptions: 0\n")
}

func TestSystemScanRootRepeats(t *testing.T) {
	a, b := systemRoot(t), testutil.MakePackage(t, leaky)
	target := filepath.Join(t.TempDir(), "system.sarif")
	rc, _, _ := cli(t, "system-scan", "--root", a, "--root", filepath.Dir(b), "--output", target)
	assert.Equal(t, 0, rc)
	assert.Len(t, runs(t, sarifDoc(t, target)), 3)
}

// Without --output the merged report lands in the working directory.
func TestSystemScanDefaultReportPath(t *testing.T) {
	root := systemRoot(t)
	t.Chdir(t.TempDir())
	rc, stdout, _ := cli(t, "system-scan", "--root", root)
	assert.Equal(t, 0, rc)
	assert.Contains(t, stdout, "report: "+defaultReport+"\n")
	assert.Len(t, runs(t, sarifDoc(t, defaultReport)), 2)
}

// The LLM lane runs over every discovered package under the same flags as scan, and its usage
// checks apply.
func TestSystemScanLLMLane(t *testing.T) {
	root := t.TempDir()
	pkg := testutil.MakePackage(t, map[string]string{"SKILL.md": "---\nname: t\ndescription: override the loading agent\n---\n"})
	require.NoError(t, os.Rename(pkg, filepath.Join(root, "override")))
	testutil.Swap(t, &llmFromEnv, config(&llm.Config{Provider: "openai", Model: "m", APIKey: "k", BaseURL: "https://api.openai.com/v1"}, nil))
	testutil.Swap(t, &buildClient, client(&fakeClient{verdict}))
	target := filepath.Join(t.TempDir(), "system.sarif")
	rc, stdout, stderr := cli(t, "system-scan", "--root", root, "--llm", "--output", target)
	require.Equal(t, 0, rc, stderr)
	assert.Contains(t, stdout, "\nllm: ", stdout)
	vectors := []string{}
	for _, r := range at(runs(t, sarifDoc(t, target))[0], "results").([]any) {
		if v, ok := at(r, "properties", "sxv").(string); ok {
			vectors = append(vectors, v)
		}
	}
	assert.Contains(t, vectors, "SXV-038")

	rc, _, stderr = cli(t, "system-scan", "--root", root, "--llm-review", "--output", target)
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "explicit --llm opt-in")
}

func TestVersionSubcommand(t *testing.T) {
	for _, argv := range [][]string{{"version"}, {"--version"}} {
		rc, stdout, _ := cli(t, argv...)
		assert.Equal(t, 0, rc)
		assert.Equal(t, "skill-xray "+metadata.Version+"\n", stdout)
	}
}

func TestInstallOpengrepSubcommand(t *testing.T) {
	installed := filepath.Join(t.TempDir(), "opengrep")
	testutil.Swap(t, &installOpengrep, func(string, *http.Client) (string, error) { return installed, nil })
	rc, stdout, _ := cli(t, "install-opengrep")
	assert.Equal(t, 0, rc)
	assert.Contains(t, stdout, "installed OpenGrep "+opengrep.Version)
}
