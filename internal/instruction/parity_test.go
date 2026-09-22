package instruction

import (
	"testing"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// Corpus parity for instruction_exfil: Check against the oracle's check over
// corpus/pytest and corpus/msb-test, findings compared as JSON.
func TestCorpusParity(t *testing.T) {
	testutil.CheckParity(t, "instruction_exfil", func(dir string) []findings.Finding {
		return Check(parse.Parse(ingest.BuildPackage(dir)))
	})
}
