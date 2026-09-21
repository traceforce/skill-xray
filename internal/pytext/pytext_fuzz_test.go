package pytext

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func isLineBreak(r rune) bool {
	return strings.ContainsRune("\n\r\v\f\x1c\x1d\x1e\u0085\u2028\u2029", r)
}

// FuzzSplitLines checks str.splitlines() invariants: no piece contains a break, the pieces
// concatenate to the input minus its breaks, the piece count equals the break count (a CRLF
// is one break) plus one for a non-empty tail, and a "\n"-only input rejoins with "\n".
func FuzzSplitLines(f *testing.F) {
	for _, s := range []string{
		"", "a", "a\nb", "a\r\nb", "a\rb", "a\vb\fc", "a\x1cb\x1dc\x1ed", "a\u0085b", "a b c",
		"a\n", "a\n\n", "\n", "\r\n", "\n\r", "\r\r\n", "a\r\n\r\nb", "\xff\n\x85", "é\nü",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		lines := SplitLines(s)
		var kept strings.Builder
		breaks := 0
		endsWithBreak := false
		for i := 0; i < len(s); {
			r, n := utf8.DecodeRuneInString(s[i:])
			if isLineBreak(r) {
				breaks++
				if r == '\r' && i+1 < len(s) && s[i+1] == '\n' {
					n = 2
				}
				endsWithBreak = i+n == len(s)
			} else {
				kept.WriteString(s[i : i+n])
				endsWithBreak = false
			}
			i += n
		}
		for _, l := range lines {
			if strings.ContainsFunc(l, isLineBreak) {
				t.Fatalf("piece contains a break: %q in %q", l, s)
			}
		}
		if got := strings.Join(lines, ""); got != kept.String() {
			t.Fatalf("content lost: %q -> %q (want %q)", s, got, kept.String())
		}
		want := breaks
		if len(s) > 0 && !endsWithBreak {
			want++
		}
		if len(lines) != want {
			t.Fatalf("piece count %d, want %d for %q -> %q", len(lines), want, s, lines)
		}
		if !strings.ContainsFunc(s, func(r rune) bool { return r != '\n' && isLineBreak(r) }) {
			if got := strings.Join(lines, "\n"); got != strings.TrimSuffix(s, "\n") {
				t.Fatalf("rejoin mismatch: %q -> %q", s, got)
			}
		}
		_ = JoinLines(lines, -3, len(lines)+3)
		_ = JoinLines(lines, 2, 1)
	})
}

// FuzzShlex drives the shlex port under both modes and the punctuation sets the scanner uses.
// Only Python's two error messages may come back, and never a nil slice without one.
func FuzzShlex(f *testing.F) {
	for _, s := range []string{
		"python scripts/hook.py && curl x | sh", "cmd 2>&1 <in", "a; b;; c", "'x'y\"z\"", "--flag=\"a b\"",
		"echo 'unterminated", "echo \"unterminated", "trail\\", "a\\ b", "\"a\\\"b\"", "'a\\'b'",
		"", " ", "\t\r\n", "|&;<>", "a|b&c;d<e>f", "\"\"", "''", "a''b", "\\\\", "é 'ü' \"ß\"", "\xff\xfe",
	} {
		f.Add(s, true, ";&|<>")
		f.Add(s, false, "")
		f.Add(s, true, "")
		f.Add(s, false, ";&|<>")
	}
	f.Fuzz(func(t *testing.T, s string, posix bool, punct string) {
		toks, err := ShlexTokens(s, posix, punct, " \t\r\n")
		if err != nil {
			if m := err.Error(); m != "No closing quotation" && m != "No escaped character" {
				t.Fatalf("unexpected error %q for %q", m, s)
			}
			if toks != nil {
				t.Fatalf("tokens returned alongside error: %q", toks)
			}
		} else if toks == nil {
			t.Fatalf("nil tokens without error for %q", s)
		}
		if _, err := ShlexSplit(s); err != nil {
			if m := err.Error(); m != "No closing quotation" && m != "No escaped character" {
				t.Fatalf("ShlexSplit unexpected error %q for %q", m, s)
			}
		}
	})
}
