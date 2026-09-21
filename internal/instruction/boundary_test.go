package instruction

// RE2's \b is ASCII, so a keyword next to a non-ASCII letter matches \bword\b in
// RE2 where Python's Unicode \b does not. findAll re-checks the boundary the pattern opens with.

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindAllUnicodeWordBoundary(t *testing.T) {
	all := func(m []int) bool { return true }

	// A pattern that opens with \b: the leading-boundary re-check applies.
	lead := regexp.MustCompile(`(?i)\bsend\b`)
	for _, c := range []struct {
		name string
		s    string
		want int
	}{
		{"ascii boundary matches", "send it now", 1},
		{"end-of-string boundary", "please send", 1},
		{"non-word neighbour matches", "re-send it", 1},                    // '-' is non-word in both
		{"preceding non-ascii letter is a word char", "ésend it", 0},       // Python \b Unicode: no boundary
		{"following non-ascii letter still matches at start", "send é", 1}, // leading boundary holds
		{"mid-word does not match", "unsendable", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, len(findAll(lead, c.s, all)), c.s)
		})
	}

	// A pattern that does NOT open with \b (leading '.') is untouched by the re-check, so a
	// non-ASCII neighbour before it does not suppress the match.
	noLead := regexp.MustCompile(`(?i)\.env\b`)
	require.Equal(t, 1, len(findAll(noLead, "é.env is present", all)))
	require.Equal(t, 1, len(findAll(noLead, "read .env now", all)))

	// The resume-after-reject case: rejecting a candidate must not surface an overlapping
	// mid-word match at the resumed substring start (RE2 would see a false string-start \b).
	rejectFirst := func(m []int) bool { return m[0] != 0 }
	require.Equal(t, 0, len(findAll(lead, "send", rejectFirst)))
}
