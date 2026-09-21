package correlate

import (
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/capability"
	"github.com/traceforce/skill-xray/internal/checks"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/opengrep"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// stripRunFingerprints drops the OpenGrep engine fingerprint from the raw candidates: it depends on
// where the rule file lives relative to the scan cwd (the oracle loads its installed copy, Go a copy
// under the temp root), so the two sides never agree; the oracle excludes it from result identity.
func stripRunFingerprints(correlation map[string]any) {
	raw, _ := correlation["raw_candidates"].([]any)
	for _, c := range raw {
		finding, _ := c.(map[string]any)["finding"].(map[string]any)
		if ev, _ := finding["evidence"].(map[string]any); ev["engine"] == any("opengrep") {
			delete(ev, "fingerprint")
		}
	}
}

// TestPipelineParity is the parity gate over the Go pipeline itself: for the first 30 cached
// Python runs with OpenGrep-backed candidates, parse -> checks.Run -> Candidates -> Correlate ->
// capability.Build -> ApplyDispositions must reproduce the cached candidate ids, findings and
// dispositions. It runs the pinned OpenGrep binary once per package.
func TestPipelineParity(t *testing.T) {
	exe := opengrep.CachedExecutable("")
	if _, err := os.Stat(exe); err != nil {
		t.Skip("pinned OpenGrep binary absent: " + exe)
	}
	if testing.Short() {
		t.Skip("runs OpenGrep on 30 packages (about three minutes)")
	}
	identical, divergent, skipped := 0, 0, 0
	for _, run := range cachedRuns(t) {
		if identical+divergent == 30 {
			break
		}
		if !slices.ContainsFunc(run.raw, func(c any) bool { return c.(map[string]any)["analyzer"] == any("opengrep") }) {
			continue
		}
		p := parse.Parse(ingest.BuildPackage(run.pkg))
		var observations []map[string]any
		emitted := checks.Run(p, exe, &observations)
		// A lane failure (opengrep-timeout, opengrep-internal-error, ...) is timing-dependent and
		// compared by prefix only (00-overview section 7); such a package has no comparable taint
		// evidence on either side.
		if slices.ContainsFunc(run.raw, func(c any) bool { return testutil.LaneFailed(c.(map[string]any)["finding"].(map[string]any)) }) ||
			slices.ContainsFunc(emitted, func(f findings.Finding) bool { return testutil.LaneFailed(f.ToMap()) }) {
			skipped++
			continue
		}
		got, err := Correlate(p, Candidates(emitted))
		require.NoError(t, err, run.pkg)
		got, err = ApplyDispositions(p, got, capability.Build(p, observations, emitted), nil, nil)
		require.NoError(t, err, run.pkg)
		want, gotDoc := run.enrichment["correlation"].(map[string]any), got.ToMap()
		stripRunFingerprints(want)
		stripRunFingerprints(gotDoc)
		tally(t, run.pkg, want, gotDoc, &identical, &divergent)
	}
	t.Logf("pipeline parity (parse -> checks.Run -> correlate, OpenGrep-backed packages): %d identical, %d divergent, %d skipped for an OpenGrep lane failure",
		identical, divergent, skipped)
}
