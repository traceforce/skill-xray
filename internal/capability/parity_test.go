package capability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
)

func readJSON(path string, v any) bool {
	data, err := os.ReadFile(path)
	return err == nil && json.Unmarshal(data, v) == nil
}

// Triad parity over corpus-cache/*/py.json, the cached full Python CLI output (tools/parity
// run). Build gets the oracle's own inputs: the raw candidates' findings as coverage and the
// OpenGrep observations replayed from the cached triads' evidence (every entry with an analyzer
// other than the preproc-ir ones Build derives itself), so a difference is capability.py's
// logic and nothing upstream. Skips when the cache is absent.
func TestCorpusParity(t *testing.T) {
	metas, _ := filepath.Glob(filepath.Join("..", "..", "corpus-cache", "*", "meta.json"))
	if len(metas) == 0 {
		t.Skip("corpus-cache absent (go run ./tools/parity run)")
	}
	identical, divergent, skipped := 0, 0, 0
	for _, metaPath := range metas {
		var meta struct{ Package string }
		var doc struct {
			Enrichment struct {
				RawCandidates []struct{ Finding findings.Finding } `json:"raw_candidates"`
				Triads        map[string]map[string]any            `json:"triads"`
			} `json:"enrichment"`
		}
		if !readJSON(metaPath, &meta) || !readJSON(filepath.Join(filepath.Dir(metaPath), "py.json"), &doc) ||
			doc.Enrichment.Triads == nil {
			skipped++
			continue
		}
		if _, err := os.Stat(meta.Package); err != nil {
			skipped++
			continue
		}
		coverage := make([]findings.Finding, 0, len(doc.Enrichment.RawCandidates))
		for _, c := range doc.Enrichment.RawCandidates {
			coverage = append(coverage, c.Finding)
		}
		var observations []map[string]any
		for _, tr := range doc.Enrichment.Triads {
			evidence, _ := tr["evidence"].([]any)
			for _, e := range evidence {
				if hit, _ := e.(map[string]any); hit["analyzer"] != nil && hit["analyzer"] != "preproc-ir" {
					observations = append(observations, hit)
				}
			}
		}
		got := Build(parse.Parse(ingest.BuildPackage(meta.Package)), observations, coverage)
		var gotJSON map[string]map[string]any
		data, _ := json.Marshal(got)
		json.Unmarshal(data, &gotJSON)
		if reflect.DeepEqual(gotJSON, doc.Enrichment.Triads) {
			identical++
			continue
		}
		divergent++
		if divergent <= 10 {
			py, _ := json.Marshal(doc.Enrichment.Triads)
			t.Errorf("%s: triads differ\n  py %s\n  go %s", meta.Package, py, data)
		}
	}
	t.Logf("capability corpus parity: %d cached packages, %d identical, %d divergent, %d skipped",
		len(metas), identical, divergent, skipped)
}
