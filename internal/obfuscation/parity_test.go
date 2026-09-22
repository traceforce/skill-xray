package obfuscation

import (
	"testing"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// Corpus parity against skill_xray.checks.obfuscation over corpus/pytest and corpus/msb-test.
func TestCorpusParity(t *testing.T) {
	testutil.CheckParity(t, "obfuscation", func(dir string) []findings.Finding {
		return Check(parse.Parse(ingest.BuildPackage(dir)))
	})
}
