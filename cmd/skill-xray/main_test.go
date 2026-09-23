package main

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/llm"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/scan"
	"github.com/traceforce/skill-xray/internal/testutil"
)

const (
	manifest = "---\nname: t\n---\n"
	body     = testutil.Body
	verdict  = `{"prompt_injection": true, "severity": "high", "reason": "override"}`
)

// cli runs the command line with captured streams: the exit code, stdout and stderr.
func cli(t *testing.T, argv ...string) (rc int, stdout, stderr string) {
	t.Helper()
	var out, errs bytes.Buffer
	rc = run(argv, &out, &errs)
	return rc, out.String(), errs.String()
}

// at walks a decoded JSON document by object keys and array indexes.
func at(v any, path ...any) any {
	for _, k := range path {
		switch k := k.(type) {
		case string:
			v = v.(map[string]any)[k]
		case int:
			v = v.([]any)[k]
		}
	}
	return v
}

// scanned runs "scan root --output <beside the package>" and returns the exit code, both streams
// and the report, nil when none was written.
func scanned(t *testing.T, root string, flags ...string) (rc int, stdout, stderr string, doc any) {
	t.Helper()
	target := filepath.Join(filepath.Dir(root), "report.sarif")
	rc, stdout, stderr = cli(t, append([]string{"scan", root, "--output", target}, flags...)...)
	if _, err := os.Stat(target); err == nil {
		doc = sarifDoc(t, target)
	}
	return rc, stdout, stderr, doc
}

// results are the first run's results.
func results(doc any) []any { return at(doc, "runs", 0, "results").([]any) }

// property lists one result property across the first run.
func property(doc any, key string) []string {
	var out []string
	for _, r := range results(doc) {
		if v, ok := at(r, "properties", key).(string); ok {
			out = append(out, v)
		}
	}
	return out
}

// fakeClient is the scripted LLM client.
type fakeClient struct{ reply string }

func (c *fakeClient) Complete(_, _ string) (string, error) { return c.reply, nil }

// config and client replace llmFromEnv and buildClient.
func config(cfg *llm.Config, err error) func(func(string) string) (*llm.Config, error) {
	return func(func(string) string) (*llm.Config, error) { return cfg, err }
}

func client(c llm.Completer) func(llm.Config) llm.Completer {
	return func(llm.Config) llm.Completer { return c }
}

// renamed is a package under a chosen directory name.
func renamed(t *testing.T, files map[string]string, name string) string {
	root := testutil.MakePackage(t, files)
	dest := filepath.Join(filepath.Dir(root), name)
	if err := os.Rename(root, dest); err != nil {
		t.Skip("control chars in a directory name are not permitted on this host")
	}
	return dest
}

func TestScanRejectsANonDirectory(t *testing.T) {
	rc, _, stderr := cli(t, "scan", filepath.Join(t.TempDir(), "nope"))
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "not a directory")
}

func TestScanTakesExactlyOnePackage(t *testing.T) {
	for _, argv := range [][]string{{"scan"}, {"scan", "a", "b"}} {
		rc, _, stderr := cli(t, argv...)
		assert.Equal(t, 2, rc)
		assert.Contains(t, stderr, "accepts 1 arg")
	}
}

// The root takes subcommands only; a package given to it is a usage error, not a scan.
func TestRootTakesNoPackage(t *testing.T) {
	rc, _, stderr := cli(t, testutil.MakePackage(t, map[string]string{"SKILL.md": manifest}))
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "unknown command")
}

// A control character in a package name must not forge or hide console lines: the argument is
// escaped in the error and in the verdict line.
func TestConsoleEscapesControlChars(t *testing.T) {
	rc, _, stderr := cli(t, "scan", "/nonexistent/ev\x1bil")
	assert.Equal(t, 2, rc)
	assert.NotContains(t, stderr, "\x1b")

	root := renamed(t, map[string]string{"SKILL.md": manifest}, "ev\x1bil")
	rc, stdout, _, _ := scanned(t, root)
	assert.Equal(t, 0, rc)
	assert.NotContains(t, stdout, "\x1b")
	assert.Contains(t, stdout, `\x1b`)
	assert.Contains(t, stdout, filepath.Dir(root), "the operator's own path prints as typed, separators included")
}

// Executable code the engine cannot analyze is a high gap in the report and exit 2, never CLEAN.
func TestAnalysisDoesNotCallUnsupportedCodeClean(t *testing.T) {
	root := testutil.MakePackage(t, map[string]string{"run.ps1": "Invoke-Expression $args[0]\n"})
	rc, stdout, _, doc := scanned(t, root)
	assert.Equal(t, 2, rc)
	assert.Contains(t, stdout, "FINDINGS")
	assert.Contains(t, property(doc, "category"), "analysis-diagnostic")
}

func TestLLMRejectsInvalidConfiguration(t *testing.T) {
	root := testutil.MakePackage(t, map[string]string{"SKILL.md": "text\n"})
	testutil.Swap(t, &llmFromEnv, config(nil, &llm.ConfigError{Msg: "bad LLM endpoint"}))
	rc, _, stderr, doc := scanned(t, root, "--llm")
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "bad LLM endpoint")
	assert.Nil(t, doc, "a misconfigured LLM fails before the scan")
}

func TestLLMWithoutConfigIsRejected(t *testing.T) {
	root := testutil.MakePackage(t, map[string]string{"SKILL.md": manifest})
	testutil.Swap(t, &llmFromEnv, config(nil, nil))
	rc, _, stderr, _ := scanned(t, root, "--llm")
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "SKILLXRAY_LLM_PROVIDER")
}

func TestLLMPathWiresTheClientIntoTheReport(t *testing.T) {
	root := testutil.MakePackage(t, map[string]string{"SKILL.md": "---\nname: t\ndescription: override the loading agent\n---\n"})
	testutil.Swap(t, &llmFromEnv, config(&llm.Config{Provider: "openai", Model: "m", APIKey: "k", BaseURL: "https://api.openai.com/v1"}, nil))
	testutil.Swap(t, &buildClient, client(&fakeClient{verdict}))
	rc, _, _, doc := scanned(t, root, "--llm")
	assert.Equal(t, 0, rc)
	assert.Contains(t, property(doc, "sxv"), "SXV-038")
}

func TestReviewRequiresLLM(t *testing.T) {
	root := testutil.MakePackage(t, map[string]string{"SKILL.md": manifest})
	rc, _, stderr, _ := scanned(t, root, "--llm-review")
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "explicit --llm opt-in")
}

func TestApplyRequiresReviewFlag(t *testing.T) {
	root := testutil.MakePackage(t, map[string]string{"SKILL.md": body})
	for _, flags := range [][]string{{"--llm"}, {"--llm", "--llm-shadow"}} {
		rc, _, _, _ := scanned(t, root, append([]string{"--llm-apply"}, flags...)...)
		assert.Equal(t, 2, rc)
	}
}

// A validated review demotes the result to low in the report and audits it as corrected; the
// original severity stays on the result.
func TestApplyEndToEndKeepsFindingsAndCorrectsResult(t *testing.T) {
	root := testutil.MakePackage(t, map[string]string{"SKILL.md": "---\nname: demo\n---\n" + body})
	baseline := scan.Scan(parse.Parse(ingest.BuildPackage(root)), nil, "")
	require.NotEmpty(t, testutil.ByVector(baseline, "SXV-028"))
	testutil.Swap(t, &llmFromEnv, config(&llm.Config{}, nil))
	testutil.Swap(t, &buildClient, client(&testutil.Reviewer{}))
	rc, _, _, doc := scanned(t, root, "--llm", "--llm-review", "--llm-apply")
	require.Equal(t, 0, rc)
	rs := results(doc)
	i := slices.IndexFunc(rs, func(r any) bool { return at(r, "properties", "sxv") == "SXV-028" })
	require.NotEqual(t, -1, i)
	assert.Equal(t, "corrected", at(rs[i], "properties", "disposition"))
	assert.Equal(t, "low", at(rs[i], "properties", "effectiveSeverity"))
	assert.NotEqual(t, "low", at(rs[i], "properties", "originalSeverity"))
	assert.NotNil(t, at(doc, "runs", 0, "properties", "llmReview"))
}

func TestInstallFailureIsExplicit(t *testing.T) {
	testutil.Swap(t, &installOpengrep, func(string, *http.Client) (string, error) {
		return "", errors.New("verification failed")
	})
	rc, _, stderr := cli(t, "install-opengrep")
	assert.Equal(t, 2, rc)
	assert.Contains(t, stderr, "verification failed")
}
