package instruction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// indexRunes replaces the per-call prefix scans of runeIdx/byteIdx/cutRunes/sliceRunes inside
// the exfil lane (posture audit 2026-09-19: O(n²) on a sentence of thousands of verbs); it must
// agree with them at every offset, including a cut inside a multi-byte rune and out-of-range
// code points.
func TestRuneIndexMatchesTheScanningHelpers(t *testing.T) {
	for _, s := range []string{"", "plain ascii text", "naïve café — señor 日本語 ✓ end", "🙂x🙂"} {
		x := indexRunes(s)
		for b := 0; b <= len(s); b++ {
			assert.Equal(t, runeIdx(s, b), x.rune(b), "%q rune(%d)", s, b)
		}
		for r := -1; r <= len(s)+2; r++ {
			assert.Equal(t, byteIdx(s, r), x.byte(r), "%q byte(%d)", s, r)
			assert.Equal(t, cutRunes(s, r), x.cut(r), "%q cut(%d)", s, r)
			for hi := r; hi <= len(s)+2; hi++ {
				lo, hi := max(0, r), max(0, hi)
				assert.Equal(t, sliceRunes(s, lo, hi), x.slice(lo, hi), "%q slice(%d,%d)", s, lo, hi)
			}
		}
	}
}

// The article guard on a delivery verb reads the last six bytes of the prefix; that window must
// decide exactly what the whole prefix did.
func TestArticleWindowMatchesThePrefix(t *testing.T) {
	for _, s := range []string{"the send", "bathe send", "each send it", "x the  send", "sénd the send",
		"a send", "an send", "your send", "then send", "this send", "éthe send", "the\tsend"} {
		for q := 0; q <= len(s); q++ {
			assert.Equal(t, exfilArticleRE.MatchString(s[:q]), exfilArticleRE.MatchString(s[max(0, q-6):q]), "%q[:%d]", s, q)
		}
	}
}
