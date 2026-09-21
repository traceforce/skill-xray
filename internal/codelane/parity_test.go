package codelane

// Corpus parity for build_code_lane: Build against the oracle's build_code_lane over
// corpus/pytest and corpus/msb-test, units and notes compared as JSON. The Python side
// (tools/parity/py_dump_findings.py code_lane) encodes each unit as a finding (rule "code-unit",
// its fields under evidence), and this test encodes the Go Unit the same way so both flow through
// testutil.CheckParity unchanged.

import (
	"testing"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

func TestCodeLaneParity(t *testing.T) {
	testutil.CheckParity(t, "code_lane", func(dir string) []findings.Finding {
		units, notes := Build(parse.Parse(ingest.BuildPackage(dir)))
		out := make([]findings.Finding, 0, len(units)+len(notes))
		for _, u := range units {
			var dialect any // "" is Python None -> JSON null
			if u.Dialect != "" {
				dialect = u.Dialect
			}
			out = append(out, findings.Finding{Rule: "code-unit", Path: u.Rel, Evidence: map[string]any{
				"kind": u.Kind, "origin": u.Origin, "dialect": dialect, "text": u.Text}})
		}
		return append(out, notes...)
	})
}
