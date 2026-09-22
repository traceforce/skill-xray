package scan

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// prefixRules are the failure-path rules whose message embeds a Python exception class name;
// they and context_errors are compared up to the last ": " (00-overview section 7).
var prefixRules = map[string]bool{"check-error": true, "analyzer-error": true, "opengrep-execution-error": true,
	"opengrep-internal-error": true, "llm-error": true, "llm-unavailable": true}

// normalizeFinding drops the OpenGrep run fingerprint (it hashes the temporary scan directory
// and never matches across runs) and reduces failure-path messages to their prefix.
func normalizeFinding(f map[string]any) {
	if ev, _ := f["evidence"].(map[string]any); ev["engine"] == any("opengrep") {
		delete(ev, "fingerprint")
	}
	if rule, _ := f["rule"].(string); prefixRules[rule] {
		f["message"] = testutil.MessagePrefix(fmt.Sprint(f["message"]))
	}
}

// normalizeDoc applies the harness's --json rules to {"findings", "enrichment"} and reports
// whether the OpenGrep lane failed anywhere in it.
func normalizeDoc(doc map[string]any) (failed bool) {
	enrichment, _ := doc["enrichment"].(map[string]any)
	correlation, _ := enrichment["correlation"].(map[string]any)
	for _, list := range []any{doc["findings"], enrichment["raw_candidates"], correlation["raw_candidates"]} {
		items, _ := list.([]any)
		for _, item := range items {
			f, _ := item.(map[string]any)
			if inner, ok := f["finding"].(map[string]any); ok {
				f = inner
			}
			normalizeFinding(f)
			failed = failed || testutil.LaneFailed(f)
		}
	}
	if errs, ok := enrichment["context_errors"].([]any); ok {
		for i, e := range errs {
			errs[i] = testutil.MessagePrefix(fmt.Sprint(e))
		}
	}
	return failed
}

// TestCorpusParity is the parity gate over the whole Go pipeline: for the first 100 cached
// Python CLI runs (corpus-cache, sorted by key) whose package still exists, ingest -> parse ->
// Report in deterministic mode must reproduce the cached findings, raw candidates, triads,
// correlation (results, links, dispositions) and context errors. A divergent package's py.json
// and a go.json in the CLI shape are written under corpus/scan-parity/<package>/ for
// `go run ./tools/parity attribute`.
func TestCorpusParity(t *testing.T) {
	if testing.Short() {
		t.Skip("runs OpenGrep on 100 packages")
	}
	exe := requireOpengrep(t)
	identical, divergent, skipped := 0, 0, 0
	for _, cached := range testutil.CachedRuns(t) {
		if identical+divergent == 100 {
			break
		}
		py := testutil.ReadJSON(t, filepath.Join(cached.Dir, "py.json"))
		report, err := Report(parse.Parse(ingest.BuildPackage(cached.Package)), Options{OpengrepExe: exe})
		require.NoError(t, err, cached.Package)
		enrichment := report.ToMap()
		gov := map[string]any{"findings": enrichment["findings"], "enrichment": enrichment}
		delete(enrichment, "findings")
		cli := map[string]any{"findings": py["findings"], "enrichment": py["enrichment"]}
		full := maps.Clone(py) // the CLI document with the scan-owned halves replaced, for attribute
		full["findings"], full["enrichment"] = gov["findings"], gov["enrichment"]
		out, err := json.Marshal(full)
		require.NoError(t, err)
		if normalizeDoc(cli) || normalizeDoc(gov) ||
			slices.ContainsFunc(report.Findings, func(f findings.Finding) bool { return testutil.PresenceOnlyDiagnostic(f.ToMap()) }) {
			skipped++
			continue
		}
		d := testutil.FirstDiff("", cli, gov)
		if d == "" {
			identical++
			continue
		}
		divergent++
		dir := filepath.Join("..", "..", "corpus", "scan-parity", filepath.Base(cached.Dir))
		require.NoError(t, os.MkdirAll(dir, 0o755))
		src, err := os.ReadFile(filepath.Join(cached.Dir, "py.json"))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "py.json"), src, 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "go.json"), out, 0o644))
		if divergent <= 10 {
			t.Errorf("%s\n  py != go at %s", cached.Package, d)
		}
	}
	t.Logf("scan corpus parity (ingest -> parse -> Report, deterministic): %d identical, %d divergent, %d skipped for an OpenGrep lane failure or a presence-only diagnostic",
		identical, divergent, skipped)
}
