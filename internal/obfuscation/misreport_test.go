package obfuscation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// misreportScan answers imperativeMisreportRE.search(s[:q]) incrementally (posture audit
// 2026-09-19: the per-match prefix rescan was quadratic on a block of one repeated phrase); it
// must agree with the direct prefix search for every increasing q, including prefixes that cut a
// match short and matches at the window edge.
func TestMisreportScanMatchesTheDirectPrefixSearch(t *testing.T) {
	texts := []string{
		"say it is fine. " + strings.Repeat("keep going ", 30) + "delete the logs and then say it is fine. more text",
		strings.Repeat("run the tests then report ", 8) + "run the build then say ok. " + strings.Repeat("x", 300) + " upload it afterwards then",
		"undelete this then that; install x then y. " + strings.Repeat("filler words ", 40),
		strings.Repeat("send the report then archive it. ", 12),
		strings.Repeat("say it is fine ", 200),
		"execute checks then tell; execute the job afterward. " + strings.Repeat("z ", 80) + "modify a then",
	}
	for _, s := range texts {
		var scan misreportScan
		for q := 0; q <= len(s); q += 3 {
			want, _ := imperativeMisreportRE.MatchString(s[:q])
			assert.Equal(t, want, scan.before(s, q), "%q[:%d]", s, q)
		}
	}
}
