package correlate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/capability"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// reshape decodes the generic document from into the typed to through its json tags; numbers
// arrive as json.Number for the caller's intify.
// ponytail: Marshal writes an integral float64 as an int; no oracle finding or triad carries a float.
func reshape(t *testing.T, from, to any) {
	data, err := json.Marshal(from)
	require.NoError(t, err)
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	require.NoError(t, dec.Decode(to))
}

type cachedRun struct {
	pkg        string
	enrichment map[string]any
	raw        []any
}

// cachedRuns is every cached Python run whose package directory still exists, with its enrichment
// document and raw candidates decoded.
func cachedRuns(t *testing.T) []cachedRun {
	var runs []cachedRun
	for _, cached := range testutil.CachedRuns(t) {
		doc := testutil.ReadJSON(t, filepath.Join(cached.Dir, "py.json"))
		enrichment, _ := doc["enrichment"].(map[string]any)
		raw, _ := enrichment["raw_candidates"].([]any)
		runs = append(runs, cachedRun{cached.Package, enrichment, raw})
	}
	return runs
}

// tally compares one replayed correlation document with the cached one, reporting the first ten
// divergences.
func tally(t *testing.T, pkg string, want, got map[string]any, identical, divergent *int) {
	if d := testutil.FirstDiff("correlation", want, got); d != "" {
		*divergent++
		if *divergent <= 10 {
			t.Errorf("%s\n  py != go at %s", pkg, d)
		}
		return
	}
	*identical++
}

// knownDigestReasons are the evidence reasons under which tools/parity/known_divergences.json
// accepts the two digests: presence-only parse diagnostics whose detail text feeds them
// (00-overview section 7, parse R6).
func knownDigestReasons(t *testing.T) map[string]bool {
	data, err := os.ReadFile(filepath.Join("..", "..", "tools", "parity", "known_divergences.json"))
	require.NoError(t, err)
	var entries []struct {
		Where string
		When  []map[string]string
	}
	require.NoError(t, json.Unmarshal(data, &entries))
	out := map[string]bool{}
	for _, e := range entries {
		if strings.HasSuffix(e.Where, "_digest") {
			for _, w := range e.When {
				out[w["reason"]] = true
			}
		}
	}
	return out
}

// dropKnownDigests removes package.content_digest and results[*].context_digest from both
// correlation documents when a raw candidate carries one of the reasons, and reports whether it did.
func dropKnownDigests(reasons map[string]bool, raw []any, docs ...map[string]any) bool {
	if !slices.ContainsFunc(raw, func(c any) bool {
		f, _ := c.(map[string]any)["finding"].(map[string]any)
		ev, _ := f["evidence"].(map[string]any)
		return reasons[fmt.Sprint(ev["reason"])]
	}) {
		return false
	}
	for _, doc := range docs {
		pkg, _ := doc["package"].(map[string]any)
		delete(pkg, "content_digest")
		results, _ := doc["results"].([]any)
		for _, r := range results {
			m, _ := r.(map[string]any)
			delete(m, "context_digest")
		}
	}
	return true
}

// TestCorpusParity is the scan-less parity gate for correlate and disposition: every cached
// Python run is replayed through parse -> Correlate -> ApplyDispositions on the Python
// candidates, triads and context errors, and the whole correlation document is compared with
// the cached one, minus the two digests the harness accepts in a diagnosed package.
func TestCorpusParity(t *testing.T) {
	identical, accepted, divergent := 0, 0, 0
	reasons := knownDigestReasons(t)
	for _, run := range cachedRuns(t) {
		p := parse.Parse(ingest.BuildPackage(run.pkg))
		var cands []Candidate
		reshape(t, run.raw, &cands)
		for i := range cands {
			pytext.Intify(cands[i].Finding)
		}
		got, err := Correlate(p, cands)
		require.NoError(t, err, run.pkg)
		var triads map[string]*capability.Triad
		reshape(t, run.enrichment["triads"], &triads)
		for _, tr := range triads {
			for _, e := range tr.Evidence {
				pytext.Intify(e) // line numbers stay int, so triadMap's canonical sort matches the oracle
			}
		}
		var errs []string
		reshape(t, run.enrichment["context_errors"], &errs)
		got, err = ApplyDispositions(p, got, triads, nil, errs)
		require.NoError(t, err, run.pkg)
		want, gotDoc := run.enrichment["correlation"].(map[string]any), got.ToMap()
		counter := &identical
		if dropKnownDigests(reasons, run.raw, want, gotDoc) {
			counter = &accepted
		}
		tally(t, run.pkg, want, gotDoc, counter, &divergent)
	}
	t.Logf("correlate+disposition corpus parity: %d identical, %d identical outside the known digest divergence, %d divergent",
		identical, accepted, divergent)
}
