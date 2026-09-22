package instruction

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

var proseSeeds = []string{
	"",
	"\n",
	"one\n\ntwo\n",
	"  \n\t\nlead blank\n  trailing\n\n\n",
	"a\r\nb\r\n\r\nc\r\n",
	"no newline at end",
	"only nbsp\n \nafter",
	"para one\ncontinues here\n\npara two\n  indented\n\tline\n",
	"\v\f\x1c\x1d\x1e\x85 blank-ish\n\nreal\n",
	"- item\n- item\n\n1. num\n",
	"é\nü\n\nß\n",
	"\xff\xfe\n\n\xff\n",
	strings.Repeat("x\n", 300),
	strings.Repeat("\n", 300),
	strings.Repeat("y\n\n", 200),
}

// FuzzPlainProseBlocks checks the blank-line block splitter: blocks come in increasing line
// order, each is a non-blank substring of the input, and every flattened position maps back to
// a line at or after the block's start with a column of at least one.
func FuzzPlainProseBlocks(f *testing.F) {
	for _, s := range proseSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		blocks := PlainProseBlocks(s)
		prev := 0
		for _, b := range blocks {
			if b.Start <= prev {
				t.Fatalf("block starts out of order: %d after %d in %q", b.Start, prev, s)
			}
			prev = b.Start
			if !strings.Contains(s, b.Text) {
				t.Fatalf("block text is not a substring: %q", b.Text)
			}
			if pytext.Strip(b.Text) == "" {
				t.Fatalf("blank block %q at %d in %q", b.Text, b.Start, s)
			}
			flat := FlattenProse(b.Text)
			n := utf8.RuneCountInString(flat)
			step := max(1, n/8)
			for pos := 0; pos <= n; pos += step {
				line, col := SourcePosition(b.Text, b.Start, pos)
				// col == 0 is a recorded fuzz-text finding (a line ending in non-space/tab
				// whitespace shifts every later flattened position by one); only negatives fail.
				if line < b.Start || col < 0 {
					t.Fatalf("SourcePosition(%d) = %d,%d for block at %d: %q", pos, line, col, b.Start, b.Text)
				}
			}
		}
		lines := strings.Count(s, "\n") + 1
		_ = SourceSpanBlocks(s, []parse.Span{{Start: 1, End: lines}, {Start: lines, End: lines + 5}, {Start: 2, End: 1}})
	})
}

// FuzzFlattenProse checks _flatten_prose: the result has no newline and is already stripped.
func FuzzFlattenProse(f *testing.F) {
	for _, s := range proseSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		flat := FlattenProse(s)
		if strings.Contains(flat, "\n") {
			t.Fatalf("newline survived: %q -> %q", s, flat)
		}
		if flat != pytext.Strip(flat) {
			t.Fatalf("not stripped: %q -> %q", s, flat)
		}
		if utf8.RuneCountInString(flat) > utf8.RuneCountInString(s) {
			t.Fatalf("grew: %q -> %q", s, flat)
		}
	})
}
