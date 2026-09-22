package forensics

import (
	"testing"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// Corpus parity against skill_xray.analyze.analyze_package.
func TestCorpusParity(t *testing.T) {
	testutil.CheckParity(t, "analyze", func(dir string) []findings.Finding {
		return AnalyzePackage(parse.Parse(ingest.BuildPackage(dir)))
	})
}
