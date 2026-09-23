package pyast

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdata/xid.json and the inline expectations below were recorded from CPython 3.13.2
// (ast.parse error class, message, lineno, offset).

func tokenizeAll(src string) ([]Token, *SyntaxError) {
	t := newTokenizer(src, false)
	var toks []Token
	for {
		tok, err := t.next()
		if err != nil {
			return toks, err
		}
		toks = append(toks, tok)
		if tok.Kind == ENDMARKER {
			return toks, nil
		}
	}
}

func TestTokenizerErrors(t *testing.T) {
	indent := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(strings.Repeat(" ", i) + "if 1:\n")
		}
		return b.String() + strings.Repeat(" ", n) + "pass\n"
	}
	cases := []struct {
		src, kind, msg string
		line, offset   int
	}{
		{"\ufeffx=1\n", "SyntaxError", "invalid non-printable character U+FEFF", 1, 1},
		{"if 1:\n        x\n    y\n", "IndentationError", "unindent does not match any outer indentation level", 3, 6},
		{"if 1:\n        x\n    y", "IndentationError", "unindent does not match any outer indentation level", 3, 6},
		{"if 1:\n\tx\n        y\n", "TabError", "inconsistent use of tabs and spaces in indentation", 3, 1},
		{"if 1:\n        x\n\ty\n", "TabError", "inconsistent use of tabs and spaces in indentation", 3, 1},
		{indent(100), "IndentationError", "too many levels of indentation", 101, 1},
		{strings.Repeat("(", 201) + "1" + strings.Repeat(")", 201) + "\n", "SyntaxError", "too many nested parentheses", 1, 201},
		{"f'{" + strings.Repeat("(", 200) + "x" + strings.Repeat(")", 200) + "}'\n", "SyntaxError", "too many nested parentheses", 1, 203},
		{")\n", "SyntaxError", "unmatched ')'", 1, 1},
		{"(]\n", "SyntaxError", "closing parenthesis ']' does not match opening parenthesis '('", 1, 2},
		{"(\n]\n", "SyntaxError", "closing parenthesis ']' does not match opening parenthesis '(' on line 1", 2, 1},
		{"f(1,\n", "SyntaxError", "'(' was never closed", 1, 2},
		{"x = 1\ny = (1,\n  2\n", "SyntaxError", "'(' was never closed", 2, 5},
		{"é = (1,\n", "SyntaxError", "'(' was never closed", 1, 5},
		{"x = (1 + \\", "SyntaxError", "'(' was never closed", 1, 5},
		{"x \\", "SyntaxError", "unexpected EOF while parsing", 1, 4},
		{"\\", "SyntaxError", "unexpected EOF while parsing", 1, 2},
		{"a\\ b\n", "SyntaxError", "unexpected character after line continuation character", 1, 3},
		{"é\\ b\n", "SyntaxError", "unexpected character after line continuation character", 1, 3},
		{"x = \x01\n", "SyntaxError", "invalid non-printable character U+0001", 1, 5},
		{"0777\n", "SyntaxError", "leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers", 1, 1},
		{"09\n", "SyntaxError", "leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers", 1, 1},
		{"0b2\n", "SyntaxError", "invalid digit '2' in binary literal", 1, 3},
		{"0o8\n", "SyntaxError", "invalid digit '8' in octal literal", 1, 3},
		{"0o78\n", "SyntaxError", "invalid digit '8' in octal literal", 1, 4},
		{"0b12\n", "SyntaxError", "invalid digit '2' in binary literal", 1, 4},
		{"1__2\n", "SyntaxError", "invalid decimal literal", 1, 2},
		{"1_\n", "SyntaxError", "invalid decimal literal", 1, 2},
		{"0_\n", "SyntaxError", "invalid decimal literal", 1, 2},
		{"1.e\n", "SyntaxError", "invalid decimal literal", 1, 2},
		{"1e+\n", "SyntaxError", "invalid decimal literal", 1, 3},
		{"1_j\n", "SyntaxError", "invalid decimal literal", 1, 2},
		{"1x\n", "SyntaxError", "invalid decimal literal", 1, 1},
		{"1.5x\n", "SyntaxError", "invalid decimal literal", 1, 3},
		{"1e5x\n", "SyntaxError", "invalid decimal literal", 1, 3},
		{"1jx\n", "SyntaxError", "invalid imaginary literal", 1, 2},
		{"0b\n", "SyntaxError", "invalid binary literal", 1, 2},
		{"0b_\n", "SyntaxError", "invalid binary literal", 1, 3},
		{"0x\n", "SyntaxError", "invalid hexadecimal literal", 1, 2},
		{"0xg\n", "SyntaxError", "invalid hexadecimal literal", 1, 2},
		{"0x1g\n", "SyntaxError", "invalid hexadecimal literal", 1, 3},
		{"1e_5\n", "SyntaxError", "invalid decimal literal", 1, 1},
		{"1_e5\n", "SyntaxError", "invalid decimal literal", 1, 2},
		{"1i\n", "SyntaxError", "invalid decimal literal", 1, 1},
		{"1not_in\n", "SyntaxError", "invalid decimal literal", 1, 1},
		{"1e\n", "SyntaxError", "invalid decimal literal", 1, 1},
		{"1_000_\n", "SyntaxError", "invalid decimal literal", 1, 6},
		{"x = 'abc\n", "SyntaxError", "unterminated string literal (detected at line 1)", 1, 5},
		{"x = 'abc\\'\n", "SyntaxError", "unterminated string literal (detected at line 1); perhaps you escaped the end quote?", 1, 5},
		{"é = 'abc\n", "SyntaxError", "unterminated string literal (detected at line 1)", 1, 5},
		{"'''abc\n", "SyntaxError", "unterminated triple-quoted string literal (detected at line 1)", 1, 1},
		{"x = 1\n'''abc\nd\n", "SyntaxError", "unterminated triple-quoted string literal (detected at line 3)", 2, 1},
		{"'a\rb'\n", "SyntaxError", "unterminated string literal (detected at line 1)", 1, 1},
		{"'\n", "SyntaxError", "unterminated string literal (detected at line 1)", 1, 1},
		{"f'}'\n", "SyntaxError", "f-string: single '}' is not allowed", 1, 3},
		{"f'{x}}'\n", "SyntaxError", "f-string: single '}' is not allowed", 1, 6},
		{"f'\\}'\n", "SyntaxError", "f-string: single '}' is not allowed", 1, 4},
		{"f'{'\n", "SyntaxError", "f-string: expecting '}'", 1, 4},
		{"f'{x'\n", "SyntaxError", "f-string: expecting '}'", 1, 5},
		{"f'{(x'\n", "SyntaxError", "f-string: expecting '}'", 1, 6},
		{"f'{x:{y:{z:{w}}}}'\n", "SyntaxError", "f-string: expressions nested too deeply", 1, 11},
		{"f'abc\n", "SyntaxError", "unterminated f-string literal (detected at line 1)", 1, 1},
		{"f'{abc\n", "SyntaxError", "'{' was never closed", 1, 3},
		{"f'{x # c }'\n", "SyntaxError", "'{' was never closed", 1, 3},
		{"f'{x:{{}}'\n", "SyntaxError", "'{' was never closed", 1, 3},
		{"f'''abc\n", "SyntaxError", "unterminated triple-quoted f-string literal (detected at line 1)", 1, 1},
		{"x=1\nf'''abc\nd\n", "SyntaxError", "unterminated triple-quoted f-string literal (detected at line 3)", 2, 1},
		{"f'{)}'\n", "SyntaxError", "f-string: unmatched ')'", 1, 4},
		{"f'{]}'\n", "SyntaxError", "f-string: unmatched ']'", 1, 4},
		{"f'{(]}'\n", "SyntaxError", "closing parenthesis ']' does not match opening parenthesis '('", 1, 5},
		{"f'{(}'\n", "SyntaxError", "closing parenthesis '}' does not match opening parenthesis '('", 1, 5},
		{"f'{x\\n}'\n", "SyntaxError", "unexpected character after line continuation character", 1, 6},
		{"x\u00b2 = 1\n", "SyntaxError", "invalid character '²' (U+00B2)", 1, 2},
		{"x\u00b2y = 1\n", "SyntaxError", "invalid character '²' (U+00B2)", 1, 2},
		{"\u00a0x = 1\n", "SyntaxError", "invalid non-printable character U+00A0", 1, 1},
		{"a\u200b = 1\n", "SyntaxError", "invalid non-printable character U+200B", 1, 2},
		{"a\u037a = 1\n", "SyntaxError", "invalid character 'ͺ' (U+037A)", 1, 2},
		{"x = 1\u2028y = 2\n", "SyntaxError", "invalid non-printable character U+2028", 1, 6},
		{"x\u0085 = 1\n", "SyntaxError", "invalid non-printable character U+0085", 1, 2},
		{"x = 😀\n", "SyntaxError", "invalid character '😀' (U+1F600)", 1, 5},
		{"x = \u201cabc\u201d\n", "SyntaxError", "invalid character '“' (U+201C)", 1, 5},
		{"\u0661x = 1\n", "SyntaxError", "invalid character '١' (U+0661)", 1, 1},
		{"\u0e33x = 1\n", "SyntaxError", "invalid character 'ำ' (U+0E33)", 1, 1},
		{"x \u00d7 y\n", "SyntaxError", "invalid character '×' (U+00D7)", 1, 3},
		{"1\u00b2\n", "SyntaxError", "invalid character '²' (U+00B2)", 1, 2},
	}
	for _, c := range cases {
		_, err := tokenizeAll(c.src)
		if assert.NotNil(t, err, "%q", c.src) {
			assert.Equal(t, &SyntaxError{Kind: c.kind, Msg: c.msg, Line: c.line, Offset: c.offset}, err, "%q", c.src)
		}
	}
	// Refused by the parser, not the tokenizer.
	for _, src := range []string{"$\n", "x ?\n", "`x`\n", "!\n", "1 <> 2\n", "x = ..\n", "1if x else 2\n", "[0x1for x in y]\n",
		"1or 2\n", "1é\n", "00\n", "0_0\n", "0e1\n", "01.5\n", "0x_1\n", "09.9\n", "0777j\n", "0777e1\n", "5.\n", ".5\n",
		"f'{}'\n", "f'{x!}'\n", "f'{x!z}'\n", "f'{x! r}'\n", "f'{lambda x: x}'\n", "b'é'\n", "ur'x'\n", "bu'x'\n", "fb'x'\n",
		"f'\\N{DASH}'\n", "x = 1 + \\\n\ny\n", "x = 1 + \\\n# c\n2\n", "\u2118 = 1\n", "\U0001d518 = 1\n", "a\u200c = 1\n",
		"x = a *** b\n", "x ->= 1\n", "  x=1\n", "def f():\n  x\n    y\n", ""} {
		_, err := tokenizeAll(src)
		assert.Nil(t, err, "%q", src)
	}
}

func TestTokenizerPositions(t *testing.T) {
	tok := func(kind TokenKind, s string, l, c, el, ec int) Token {
		return Token{Kind: kind, Str: s, Lineno: l, Col: c, EndLineno: el, EndCol: ec}
	}
	strip := func(toks []Token) []Token { // compare positions only
		out := make([]Token, len(toks))
		for i, tk := range toks {
			tk.Level, tk.Cur, tk.Meta = 0, 0, ""
			out[i] = tk
		}
		return out
	}
	got, err := tokenizeAll("x = 1 + # c\n")
	require.Nil(t, err)
	assert.Equal(t, []Token{tok(NAME, "x", 1, 0, 1, 1), tok(OP, "=", 1, 2, 1, 3), tok(NUMBER, "1", 1, 4, 1, 5), tok(OP, "+", 1, 6, 1, 7),
		tok(NEWLINE, "# c", 1, 8, 1, 12), tok(ENDMARKER, "", 1, -1, 1, -1)}, strip(got), "a NEWLINE after a comment starts at the '#' and carries those bytes, as pegen's does")

	got, err = tokenizeAll("if 1:\n    x")
	require.Nil(t, err)
	assert.Equal(t, []Token{tok(NAME, "if", 1, 0, 1, 2), tok(NUMBER, "1", 1, 3, 1, 4), tok(OP, ":", 1, 4, 1, 5), tok(NEWLINE, "", 1, 5, 1, 6),
		tok(INDENT, "", 2, -1, 2, -1), tok(NAME, "x", 2, 4, 2, 5), tok(NEWLINE, "", 2, 5, 2, 6), tok(DEDENT, "", 2, -1, 2, -1),
		tok(ENDMARKER, "", 2, -1, 2, -1)}, strip(got))
	assert.Equal(t, 4, got[4].Cur, "INDENT: cursor after the indentation")
	assert.Equal(t, 6, got[7].Cur, "DEDENT at EOF: cursor at the end of the buffer")

	got, err = tokenizeAll("x = '''a\nb''' + \"é\"\n")
	require.Nil(t, err)
	assert.Equal(t, tok(STRING, "'''a\nb'''", 1, 4, 2, 4), strip(got[2:3])[0], "multi-line string: start on its first line, end on its last")
	assert.Equal(t, tok(STRING, "\"é\"", 2, 7, 2, 11), strip(got[4:5])[0], "byte columns")

	got, err = tokenizeAll("(f'{x}')\n")
	require.Nil(t, err)
	var levels []int
	for _, tk := range got {
		levels = append(levels, tk.Level)
	}
	assert.Equal(t, []int{1, 1, 2, 2, 1, 1, 0, 0, 0}, levels, "Level is the depth after the token")

	got, err = tokenizeAll("f'a{{b}}c{x=!r:>5}{ y = }'\n")
	require.Nil(t, err)
	var kinds []string
	for _, tk := range got {
		kinds = append(kinds, fmt.Sprintf("%s:%s:%s", tk.Kind, tk.Str, tk.Meta))
	}
	assert.Equal(t, []string{"FSTRING_START:f':", "FSTRING_MIDDLE:a{:", "FSTRING_MIDDLE:b}:", "FSTRING_MIDDLE:c:", "OP:{:", "NAME:x:", "OP:=:",
		"OP:!:x=", "NAME:r:", "OP:::x=", "FSTRING_MIDDLE:>5:", "OP:}:x=!r:>5", "OP:{:", "NAME:y:", "OP:=:", "OP:}: y = ", "FSTRING_END:':",
		"NEWLINE::", "ENDMARKER::"}, kinds)
	assert.Equal(t, 1, got[1].EndCol-got[1].Col-len(got[1].Str), "'{{': the token ends after the second brace")

	got, err = tokenizeAll("f'''{x # c\n=}'''\n")
	require.Nil(t, err)
	assert.Equal(t, "x \n=", got[4].Meta, "comments are cut from the debug text")

	got, err = tokenizeAll("")
	require.Nil(t, err)
	assert.Equal(t, []Token{tok(ENDMARKER, "", 0, -1, 0, -1)}, strip(got))
}

func TestXidTables(t *testing.T) {
	var golden struct{ Start, Continue [][2]rune }
	f, err := os.ReadFile(filepath.Join("testdata", "xid.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(f, &golden))
	set := func(ranges [][2]rune) map[rune]bool {
		m := map[rune]bool{}
		for _, r := range ranges {
			for cp := r[0]; cp <= r[1]; cp++ {
				m[cp] = true
			}
		}
		return m
	}
	start, cont := set(golden.Start), set(golden.Continue)
	var bad []rune
	for cp := rune(0); cp <= 0x10FFFF; cp++ {
		if (isXidStart(cp) || cp == '_') != start[cp] || isXidContinue(cp) != cont[cp] {
			bad = append(bad, cp)
		}
	}
	// Unicode 15.1 (the oracle) added CJK Extension I; Go's tables are 15.0.
	for _, cp := range bad {
		assert.True(t, 0x2EBF0 <= cp && cp <= 0x2EE5D, "U+%04X: Go %v/%v, CPython %v/%v", cp, isXidStart(cp), isXidContinue(cp), start[cp], cont[cp])
	}
	t.Logf("xid: %d code points differ, all in CJK Extension I", len(bad))
}
