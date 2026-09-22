package pyast

// The posture audit's fuzz crashers (2026-09-19): sources CPython 3.13 refuses or parses in
// microseconds that hung the port or exhausted its memory. Each must now finish well inside a
// second with CPython's exact message, line and offset.

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func timed(t *testing.T, src string) (*Module, error) {
	t.Helper()
	start := time.Now()
	m, err := Parse(src)
	assert.Less(t, time.Since(start), 2*time.Second, "Parse(%.40q) took too long", src)
	return m, err
}

func TestMalformedFStringFailsInsteadOfLooping(t *testing.T) {
	// strings() once appended fstring()'s nil result and re-peeked the same FSTRING_START
	// forever, growing a slice at about 1 GB/s until the process died.
	for _, c := range []struct {
		src, msg string
		offset   int
	}{
		{"f'{`}'\n", "f-string: expecting a valid expression after '{'", 4},
		{"f'{f'{f'{1}'`'}'\n", "f-string: expecting '=', or '!', or ':', or '}'", 13},
		{"f'{}'\n", "f-string: valid expression required before '}'", 4},
		{"f'{1 ?}'\n", "f-string: expecting '=', or '!', or ':', or '}'", 6},
	} {
		_, err := timed(t, c.src)
		require.Error(t, err, c.src)
		se := err.(*SyntaxError)
		assert.Equal(t, []any{"SyntaxError", c.msg, 1, c.offset}, []any{se.Kind, se.Msg, se.Line, se.Offset}, c.src)
	}
}

func TestNestedGroupsParseInLinearTime(t *testing.T) {
	// Only expression() was memoised. The star_targets attempt on an assignment's right-hand
	// side re-descended each parenthesis twice (2^depth: 60 of them never returned) and the
	// invalid_* second pass re-descended each bracket about six times (12 of them: hours).
	m, err := timed(t, "x = "+strings.Repeat("(", 60)+"1"+strings.Repeat(")", 60)+"\n")
	require.NoError(t, err)
	assert.Equal(t, 3, Depth(m)) // Module, Assign, Constant: parentheses leave no node
	for _, c := range []struct {
		src, msg string
		offset   int
	}{
		{strings.Repeat("[", 12) + "E(\n", "'(' was never closed", 14},
		{strings.Repeat("[", 12) + "E($\n", "invalid syntax", 15},
		{strings.Repeat("[", 8) + "E($\n", "invalid syntax", 11},
	} {
		_, err := timed(t, c.src)
		require.Error(t, err, c.src)
		se := err.(*SyntaxError)
		assert.Equal(t, []any{"SyntaxError", c.msg, 1, c.offset}, []any{se.Kind, se.Msg, se.Line, se.Offset}, c.src)
	}
}
