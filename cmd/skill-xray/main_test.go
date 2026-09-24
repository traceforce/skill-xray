package main

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
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

// failingClient is a provider that refuses every request.
type failingClient struct{ err error }

func (c *failingClient) Complete(_, _ string) (string, error) { return "", c.err }

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
	assert.Contains(t, stderr, "skill-xray scan <package>", "the retired root form points at scan")
}

// An empty directory is not called clean in silence: the verdict line shows seen=0 and stderr
// says no files were found; a directory with files but no SKILL.md says nothing was evaluated
// as a manifest.
func TestEmptyPackageIsNoted(t *testing.T) {
	rc, stdout, stderr, _ := scanned(t, t.TempDir())
	assert.Equal(t, 0, rc)
	assert.Contains(t, stdout, "seen=0")
	assert.Contains(t, stderr, "note: no files found under ")
	_, _, stderr, _ = scanned(t, testutil.MakePackage(t, map[string]string{"notes.txt": "just notes\n"}))
	assert.Contains(t, stderr, "note: no SKILL.md found under ")
	_, _, stderr, _ = scanned(t, testutil.MakePackage(t, map[string]string{"SKILL.md": manifest}))
	assert.NotContains(t, stderr, "note:")
}

// A control character in a package name must not forge or hide console lines: the argument is
// escaped in the error and in the verdict line.
func TestConsoleEscapesLineSeparators(t *testing.T) {
	assert.Equal(t, `a\u2028b\u2029c\x1bd`, console("a\u2028b\u2029c\x1bd"))
}

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

	root = renamed(t, map[string]string{"SKILL.md": manifest}, "ev\u0085il") // a C1 control
	rc, stdout, _, _ = scanned(t, root)
	assert.Equal(t, 0, rc)
	assert.NotContains(t, stdout, "\u0085")
	assert.Contains(t, stdout, `\x85`)
}

// Executable code the engine cannot analyze is a high gap in the report and exit 2, never CLEAN.
func TestAnalysisDoesNotCallUnsupportedCodeClean(t *testing.T) {
	root := testutil.MakePackage(t, map[string]string{"run.ps1": "Invoke-Expression $args[0]\n"})
	rc, stdout, stderr, doc := scanned(t, root)
	assert.Equal(t, 2, rc)
	assert.Contains(t, stdout, "FINDINGS")
	assert.Contains(t, property(doc, "category"), "analysis-diagnostic")
	assert.Contains(t, stderr, "analysis incomplete: ", "the exit 2 is explained")
	assert.Contains(t, stderr, "run.ps1")
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
	rc, stdout, _, doc := scanned(t, root, "--llm")
	assert.Equal(t, 0, rc)
	assert.Contains(t, property(doc, "sxv"), "SXV-038")
	usage := at(doc, "runs", 0, "properties", "llmUsage").(map[string]any) // the report records that the lane ran
	assert.Equal(t, true, usage["advisoryEnabled"])
	assert.GreaterOrEqual(t, usage["calls"].(float64), 1.0)
	assert.Contains(t, stdout, "\nllm: ", "the console states what the lane did")
	assert.NotContains(t, stdout, "llm: 0 model call")
	assert.Contains(t, stdout, "semantic check (SXV-038) ran")
}

// A failing provider is named on the console and in the report with its sanitised reason, so a
// run whose every call failed cannot pass for a clean one.
// A skill text over the model's size cap is only partly checked; the console says so instead of
// reporting the semantic check as run over everything.
func TestLLMPartialCoverageIsOnTheConsole(t *testing.T) {
	root := testutil.MakePackage(t, map[string]string{"SKILL.md": "---\nname: t\ndescription: long\n---\n" + strings.Repeat("word ", 5000)})
	testutil.Swap(t, &llmFromEnv, config(&llm.Config{Provider: "openai", Model: "m", APIKey: "k", BaseURL: "https://api.openai.com/v1"}, nil))
	testutil.Swap(t, &buildClient, client(&fakeClient{verdict}))
	_, stdout, _, doc := scanned(t, root, "--llm")
	assert.Contains(t, stdout, "1 file not read whole by the model (size or budget), see the report", stdout)
	assert.Contains(t, property(doc, "category"), "analysis-diagnostic")
}

// One llm-budget note stands for the file it names and every later one; the console counts them all.
func TestLLMBudgetNoteCountsEveryUncheckedFile(t *testing.T) {
	var s llmSummary
	s.add(&scan.ScanReport{LLMUsage: map[string]any{"advisory_enabled": true, "calls": 1},
		Findings: []findings.Finding{{Rule: "llm-budget", Evidence: map[string]any{"unchecked": 3}}, {Rule: "llm-truncated"}}})
	assert.Equal(t, 4, s.partial)
	var b strings.Builder
	s.line(&b)
	assert.Contains(t, b.String(), "4 files not read whole by the model")
}

func TestLLMFailureReasonIsReported(t *testing.T) {
	root := testutil.MakePackage(t, map[string]string{"SKILL.md": "---\nname: t\ndescription: override the loading agent\n---\n"})
	testutil.Swap(t, &llmFromEnv, config(&llm.Config{Provider: "openai", Model: "m", APIKey: "k", BaseURL: "https://api.openai.com/v1"}, nil))
	testutil.Swap(t, &buildClient, client(&failingClient{&llm.Error{Kind: llm.Transport, Msg: "LLM endpoint returned HTTP 401"}}))
	rc, stdout, _, doc := scanned(t, root, "--llm")
	assert.Equal(t, 0, rc)
	assert.Contains(t, stdout, "1 failed (LLM endpoint returned HTTP 401)", stdout)
	assert.Contains(t, stdout, "provider unavailable", stdout)
	assert.Equal(t, "LLM endpoint returned HTTP 401", at(doc, "runs", 0, "properties", "llmUsage", "failureReason"))
	testutil.Swap(t, &buildClient, client(&failingClient{&llm.Error{Kind: llm.Transport, Msg: "token=do-not-echo"}})) // a wrapped client's own text never reaches the report
	_, stdout, _, doc = scanned(t, root, "--llm")
	assert.NotContains(t, stdout, "do-not-echo")
	assert.Equal(t, "LLMError", at(doc, "runs", 0, "properties", "llmUsage", "failureReason"))
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
	rc, stdout, _, doc := scanned(t, root, "--llm", "--llm-review", "--llm-apply")
	require.Equal(t, 0, rc)
	assert.Contains(t, stdout, "semantic check (SXV-038) skipped in review mode", stdout)
	assert.Contains(t, stdout, "reviews sent", stdout)
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
