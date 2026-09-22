// Package lane fuzzes one lane's Check over a package on disk. It imports parse, which testutil
// cannot (parse's own tests import testutil).
package lane

import (
	"testing"
	"time"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// Fuzz writes layout from data under root, ingests and parses the package and runs check over
// it, failing on a parse_crash, a recovered panic or a hang.
func Fuzz(t testing.TB, root string, layout []string, data []byte, check func(*parse.Package) []findings.Finding) {
	testutil.FuzzFiles(t, root, layout, data)
	defer testutil.Hang(t, time.Now(), len(data))
	p := parse.Parse(ingest.BuildPackage(root))
	NoParseCrash(t, p)
	testutil.NoRecoveredPanic(t, check(p))
}

// NoParseCrash fails on parse_crash, the diagnostic a swallowed parser panic becomes.
func NoParseCrash(t testing.TB, p *parse.Package) {
	for _, e := range p.LedgerExceptions {
		if e.ReasonCode == "parse_crash" {
			t.Fatalf("parse_crash on %s: %s", e.Path, *e.Detail)
		}
	}
}
