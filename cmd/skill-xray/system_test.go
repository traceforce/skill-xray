package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/metadata"
	"github.com/traceforce/skill-xray/internal/opengrep"
	"github.com/traceforce/skill-xray/internal/sarif"
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

// byPackage indexes the system-scan JSON packages by name.
func byPackage(doc any) map[string]any {
	out := map[string]any{}
	for _, p := range at(doc, "packages").([]any) {
		out[at(p, "package").(string)] = p
	}
	return out
}

func TestRootLegacyFormStillAnalyzes(t *testing.T) {
	root := testutil.MakePackage(t, leaky)
	rc, stdout, _ := cli(t, root, "--analyze", "--json")
	assert.Equal(t, 0, rc)
	assert.True(t, hasVector(decode(t, stdout), "SXV-017"))
}

func TestScanSubcommandMatchesLegacyForm(t *testing.T) {
	root := testutil.MakePackage(t, leaky)
	for _, flags := range [][]string{{"--json"}, {"--analyze", "--json"}, {"--analyze"}} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			rc, legacy, _ := cli(t, append([]string{root}, flags...)...)
			rcScan, scan, _ := cli(t, append([]string{"scan", root}, flags...)...)
			assert.Equal(t, rc, rcScan)
			assert.Equal(t, legacy, scan)
			assert.NotEmpty(t, legacy)
		})
	}
}

func TestSubcommandsKeepUsageErrors(t *testing.T) {
	for _, c := range []struct{ argv, want string }{
		{"scan --scan-known-skills pkg", "no package argument"},
		{"scan pkg --sarif x", "--sarif requires --analyze"},
		{"scan", "scan-known-skills"},
		{"system-scan extra", "unknown command"},
		{"system-scan --sarif ", "non-empty path"},
	} {
		t.Run(c.argv, func(t *testing.T) {
			rc, _, stderr := cli(t, strings.Split(c.argv, " ")...)
			assert.Equal(t, 2, rc)
			assert.Contains(t, stderr, c.want)
		})
	}
}

func TestSystemScanJSONReportsVerdicts(t *testing.T) {
	rc, stdout, stderr := cli(t, "system-scan", "--root", systemRoot(t), "--json")
	assert.Equal(t, 0, rc)
	assert.Empty(t, stderr)
	doc := decode(t, stdout)
	assert.Equal(t, "system-scan-v1", at(doc, "schema_version"))
	assert.Len(t, at(doc, "discovery", "paths"), 2)
	pkgs := byPackage(doc)
	for _, c := range []struct{ name, verdict string }{{"clean", "CLEAN"}, {"leaky", "BLOCKING"}} {
		require.Contains(t, pkgs, c.name)
		assert.Equal(t, c.verdict, at(pkgs[c.name], "verdict"))
		assert.Equal(t, opengrep.Version, at(pkgs[c.name], "analysis", "opengrepVersion"))
		assert.Equal(t, json.Number("1"), at(pkgs[c.name], "ledger", "artifactsSeen"))
	}
	assert.True(t, hasVector(pkgs["leaky"], "SXV-017"))
	assert.Equal(t, []any{}, at(pkgs["clean"], "findings"))
	assert.Equal(t, map[string]any{"packages": json.Number("2"), "blocking": json.Number("1"),
		"withFindings": json.Number("0"), "clean": json.Number("1")}, at(doc, "summary"))
}

func TestSystemScanTextOutput(t *testing.T) {
	rc, stdout, _ := cli(t, "system-scan", "--root", systemRoot(t))
	assert.Equal(t, 0, rc)
	assert.Contains(t, stdout, "CLEAN     seen=1   analyzed=1   cov=100.0%  ")
	assert.Contains(t, stdout, "BLOCKING  seen=1   analyzed=1   cov=100.0%  ")
	assert.Contains(t, stdout, "committed-credential")
	assert.True(t, strings.HasSuffix(stdout, "packages: 2, blocking: 1, with findings: 0, clean: 1, discovery exceptions: 0\n"))
}

func TestSystemScanSarifHoldsOneRunPerPackage(t *testing.T) {
	root := systemRoot(t)
	target := filepath.Join(t.TempDir(), "system.sarif")
	rc, _, stderr := cli(t, "system-scan", "--root", root, "--sarif", target)
	require.Equal(t, 0, rc, stderr)
	doc := sarifDoc(t, target)
	runs := at(doc, "runs").([]any)
	require.Len(t, runs, 2)
	results := 0
	for _, run := range runs {
		require.NoError(t, sarif.Validate(map[string]any{"version": at(doc, "version"), "$schema": at(doc, "$schema"), "runs": []any{run}}))
		results += len(at(run, "results").([]any))
	}
	assert.Equal(t, 1, results)
}

func TestSystemScanSarifRefusesAScannedPackage(t *testing.T) {
	root := systemRoot(t)
	target := filepath.Join(root, "leaky", "report.sarif")
	rc, _, stderr := cli(t, "system-scan", "--root", root, "--sarif", target)
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "cannot write SARIF")
	assert.NoFileExists(t, target)
}

func TestSystemScanEmptyRoot(t *testing.T) {
	rc, stdout, stderr := cli(t, "system-scan", "--root", t.TempDir(), "--json")
	assert.Equal(t, 0, rc)
	assert.Empty(t, stderr)
	doc := decode(t, stdout)
	assert.Equal(t, []any{}, at(doc, "packages"))
	assert.Equal(t, json.Number("0"), at(doc, "summary", "packages"))
}

func TestSystemScanRootRepeats(t *testing.T) {
	a, b := systemRoot(t), testutil.MakePackage(t, leaky)
	rc, stdout, _ := cli(t, "system-scan", "--root", a, "--root", filepath.Dir(b), "--json")
	assert.Equal(t, 0, rc)
	doc := decode(t, stdout)
	assert.Len(t, at(doc, "packages"), 3)
	assert.Equal(t, []any{a, filepath.Dir(b)}, at(doc, "roots"))
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
