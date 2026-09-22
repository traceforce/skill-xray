package supplychain

import (
	"testing"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// Corpus parity against skill_xray.checks.supply_chain.
func TestCorpusParity(t *testing.T) {
	testutil.CheckParity(t, "supply_chain", func(dir string) []findings.Finding {
		return Check(parse.Parse(ingest.BuildPackage(dir)))
	})
}
