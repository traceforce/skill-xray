package pyast

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/pytext"
)

// The tokenizer is CPython 3.13.2 Parser/lexer/lexer.c driven over a string buffer the way
// ast.parse(str) drives it (_PyTokenizer_FromUTF8: newlines translated, no BOM or cookie
// handling, encoding fixed to UTF-8). Token positions are what pegen's Token carries; with
// extra=true it is the tokenize module's stream instead (COMMENT and NL tokens, INDENT/DEDENT
// spans, no identifier or number-tail validation, lenient closing brackets), which is what the
// corpus goldens hold. Errors are formatted as ast.parse raises them, including the ones
// pegen's _Pypegen_tokenizer_error builds from tok->done.

const (
	maxIndent       = 100 // MAXINDENT: the 100th indentation level is refused
	maxLevel        = 200 // MAXLEVEL: nested parentheses
	maxFstringLevel = 150 // MAXFSTRINGLEVEL
	maxExprNesting  = 3   // MAX_EXPR_NESTING: replacement fields inside format specs
	tabSize         = 8
)

const eof = -1

// tok->done states that reach pegen as an ERRORTOKEN without a message of their own.
const (
	eOK = iota
	eEOF
	eError
	eDedent
	eTabSpace
	eTooDeep
	eLineCont
)

type tokMode struct {
	fstring            bool // TOK_FSTRING_MODE; false is TOK_REGULAR_MODE
	quote              int
	quoteSize          int
	raw                bool
	start              int // f_string_start: index of the FSTRING_START token
	multiLineStart     int // f_string_multi_line_start
	lineno             int // f_string_line_start
	curlyDepth         int // curly_bracket_depth
	exprStartDepth     int // curly_bracket_expr_start_depth; -1 outside a replacement field
	inFormatSpec       bool
	debug              bool // f_string_debug: a '=' was seen in the expression
	exprStart, exprEnd int  // last_expr_buffer: source after '{' up to the closing '}', '!' or ':'; -1 unset
}

type tokenizer struct {
	src                         string // newline-translated source ending in '\n' (or empty)
	cur, inp, lineStart         int    // tok->cur, tok->inp (end of the current line), tok->line_start
	lineno                      int
	start                       int // tok->start
	firstLineno, multiLineStart int
	done                        int
	err                         *SyntaxError
	meta                        string // metadata for the token being emitted (set_fstring_expr)
	extra                       bool   // tok_extra_tokens
	atbol, commentNewline       bool
	indent, pendin              int
	indstack, altindstack       [maxIndent]int
	level                       int
	parenstack                  [maxLevel]int
	parenLineno, parenCol       [maxLevel]int
	modes                       []tokMode // tok_mode_stack; modes[0] is the regular mode
}

// newTokenizer applies translate_newlines(exec_input=1) and starts at the beginning of a line.
func newTokenizer(src string, extra bool) *tokenizer {
	src = strings.ReplaceAll(strings.ReplaceAll(src, "\r\n", "\n"), "\r", "\n")
	if src != "" && !strings.HasSuffix(src, "\n") {
		src += "\n"
	}
	return &tokenizer{src: src, atbol: true, extra: extra, modes: []tokMode{{}}}
}

func (t *tokenizer) mode() *tokMode { return &t.modes[len(t.modes)-1] }

func (t *tokenizer) insideFstring() bool { return len(t.modes) > 1 }

// nextc is tok_nextc with tok_underflow_string: one byte, or eof after the buffer.
func (t *tokenizer) nextc() int {
	for {
		if t.cur != t.inp {
			c := int(t.src[t.cur])
			t.cur++
			return c
		}
		if t.done != eOK {
			return eof
		}
		if t.inp >= len(t.src) {
			t.done = eEOF
			return eof
		}
		end := strings.IndexByte(t.src[t.inp:], '\n')
		if end < 0 {
			end = len(t.src)
		} else {
			end += t.inp + 1
		}
		t.lineStart = t.cur
		t.lineno++
		t.inp = end
	}
}

func (t *tokenizer) backup(c int) {
	if c != eof {
		t.cur--
	}
}

// next returns the next token, or the SyntaxError ast.parse would raise at this point. After
// an error every call returns that error again.
func (t *tokenizer) next() (Token, *SyntaxError) {
	if t.err != nil {
		return Token{}, t.err
	}
	if m := t.mode(); m.fstring {
		return t.fstringMode(m)
	}
	return t.normalMode()
}

// emit is token_setup plus the position rules of pegen (or, with extra, of Python-tokenize.c).
// pStart < 0 is a NULL start: INDENT, DEDENT and ENDMARKER in parser mode.
func (t *tokenizer) emit(kind TokenKind, pStart, pEnd int) (Token, *SyntaxError) {
	tok := Token{Kind: kind, Lineno: t.lineno, EndLineno: t.lineno, Level: t.level, Cur: t.cur - t.lineStart, Meta: t.meta}
	t.meta = ""
	ls := t.lineStart
	if kind == STRING || kind == FSTRING_MIDDLE {
		tok.Lineno, ls = t.firstLineno, t.multiLineStart
	}
	if pStart < 0 {
		tok.Col, tok.EndCol = -1, -1
		return tok, nil
	}
	tok.Str, tok.Col, tok.EndCol = t.src[pStart:pEnd], pStart-ls, t.cur-t.lineStart
	if t.extra {
		tok.EndCol = pEnd - t.lineStart
		if kind == NEWLINE {
			tok.EndCol++
		}
	}
	return tok, nil
}

// syntaxError is _PyTokenizer_syntaxerror: the offset is the character count from the line
// start to cur.
func (t *tokenizer) syntaxError(format string, args ...any) *SyntaxError {
	return t.fail("SyntaxError", fmt.Sprintf(format, args...), t.lineno, utf8.RuneCountInString(t.src[t.lineStart:t.cur]))
}

func (t *tokenizer) fail(kind, msg string, line, offset int) *SyntaxError {
	t.done = eError
	t.err = &SyntaxError{Kind: kind, Msg: msg, Line: line, Offset: offset}
	return t.err
}

// doneError builds the error pegen raises for tok->done when the tokenizer set no message
// (_Pypegen_tokenizer_error, raise_unclosed_parentheses_error, _PyPegen_raise_error). done
// keeps its code, so the parser can tell these from tokenizer-formatted errors (done ==
// eError): in _PyPegen_tokenize_full_source_to_check_for_errors only the latter, and an eEOF
// with an unclosed bracket opened before the error line, replace a generic "invalid syntax".
func (t *tokenizer) doneError() (Token, *SyntaxError) {
	if t.err != nil {
		return Token{}, t.err
	}
	code := t.done
	defer func() { t.done = code }()
	line, col := t.src[t.lineStart:t.inp], t.cur-t.lineStart
	switch t.done {
	case eEOF:
		if t.level > 0 {
			n := t.level - 1
			return Token{}, t.fail("SyntaxError", fmt.Sprintf("'%c' was never closed", t.parenstack[n]),
				t.parenLineno[n], charOffset(t.lineText(t.parenLineno[n]), t.parenCol[n]+1))
		}
		return Token{}, t.fail("SyntaxError", "unexpected EOF while parsing", t.lineno, charOffset(line, col))
	case eDedent:
		return Token{}, t.fail("IndentationError", "unindent does not match any outer indentation level", t.lineno, charOffset(line, col))
	case eTabSpace:
		return Token{}, t.fail("TabError", "inconsistent use of tabs and spaces in indentation", t.lineno, 1)
	case eTooDeep:
		return Token{}, t.fail("IndentationError", "too many levels of indentation", t.lineno, 1)
	case eLineCont:
		return Token{}, t.fail("SyntaxError", "unexpected character after line continuation character", t.lineno, charOffset(line, col))
	}
	panic(fmt.Sprintf("pyast: tokenizer done=%d without an error", t.done))
}

// lineText is the text of a 1-based line including its '\n' (error path only; max guards
// the lineno-0 ENDMARKER of empty source).
func (t *tokenizer) lineText(lineno int) string {
	return strings.SplitAfter(t.src, "\n")[max(lineno, 1)-1]
}

// charOffset is _PyPegen_byte_offset_to_character_offset: the number of characters in the
// first off bytes of line (a cut inside a character counts as one, one past the end counts
// the terminating NUL).
func charOffset(line string, off int) int {
	if off > len(line)+1 {
		off = len(line) + 1
	}
	n := 0
	for i := 0; i < off && i < len(line); n++ {
		_, size := utf8.DecodeRuneInString(line[i:])
		i += size
	}
	if off == len(line)+1 {
		n++
	}
	return n
}

func isDigit(c int) bool  { return '0' <= c && c <= '9' }
func isXDigit(c int) bool { return isDigit(c) || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F') }
func isPotentialIdentifierStart(c int) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '_' || c >= 128
}
func isPotentialIdentifierChar(c int) bool { return isPotentialIdentifierStart(c) || isDigit(c) }

func isTwoCharOp(a, b int) bool {
	switch string([]byte{byte(a), byte(b)}) { // #nosec G115 -- a and b are nextc results, a byte or eof (-1); eof wraps to 0xFF, which no case string contains, so an eof operand matches nothing
	case "!=", "%=", "&=", "**", "*=", "+=", "-=", "->", "//", "/=", ":=", "<<", "<=", "<>", "==", ">=", ">>", "@=", "^=", "|=":
		return b != eof
	}
	return false
}

func isThreeCharOp(a, b, c int) bool {
	switch string([]byte{byte(a), byte(b), byte(c)}) { // #nosec G115 -- a, b and c are nextc results, a byte or eof (-1); eof wraps to 0xFF, which no case string contains, so an eof operand matches nothing
	case "**=", "//=", "<<=", ">>=":
		return c != eof
	}
	return false
}

// XID_Start and XID_Continue from Go's Unicode 15.0 tables: ID_Start/ID_Continue (UAX #31)
// minus the NFKC-closure exclusions of DerivedCoreProperties.txt, plus the four Other_ID_Continue
// code points Unicode 15.1 (the oracle's tables) added.
func xidExcluded(r rune) bool {
	switch r {
	case 0x037A, 0x309B, 0x309C, 0xFDFA, 0xFDFB, 0xFE70, 0xFE72, 0xFE74, 0xFE76, 0xFE78, 0xFE7A, 0xFE7C, 0xFE7E:
		return true
	}
	return 0xFC5E <= r && r <= 0xFC63
}

func isXidStart(r rune) bool {
	return !xidExcluded(r) && r != 0x0E33 && r != 0x0EB3 && r != 0xFF9E && r != 0xFF9F &&
		(unicode.IsLetter(r) || unicode.Is(unicode.Nl, r) || unicode.Is(unicode.Other_ID_Start, r)) &&
		!unicode.Is(unicode.Pattern_Syntax, r) && !unicode.Is(unicode.Pattern_White_Space, r)
}

func isXidContinue(r rune) bool {
	switch r {
	case 0x0E33, 0x0EB3, 0xFF9E, 0xFF9F, 0x200C, 0x200D, 0x30FB, 0xFF65:
		return true
	}
	return !xidExcluded(r) && (isXidStart(r) || unicode.In(r, unicode.Mn, unicode.Mc, unicode.Nd, unicode.Pc, unicode.Other_ID_Continue)) &&
		!unicode.Is(unicode.Pattern_Syntax, r) && !unicode.Is(unicode.Pattern_White_Space, r)
}

// verifyIdentifier is lexer.c verify_identifier over the token at start..cur.
func (t *tokenizer) verifyIdentifier() bool {
	if t.extra {
		return true
	}
	s := t.src[t.start:t.cur]
	for i, r := range s {
		ok := isXidContinue(r)
		if i == 0 {
			ok = r == '_' || isXidStart(r)
		}
		if ok {
			continue
		}
		_, width := utf8.DecodeRuneInString(s[i:]) // RuneError is one byte here, not RuneLen's three
		t.cur = t.start + i + width
		if pytext.IsPrintable(string(r)) {
			t.syntaxError("invalid character '%c' (U+%04X)", r, r)
		} else {
			t.syntaxError("invalid non-printable character U+%04X", r)
		}
		return false
	}
	return true
}

// lookahead is lexer.c lookahead: true when test follows and is not continued by an
// identifier character; the cursor is restored.
func (t *tokenizer) lookahead(test string) bool {
	n, res := 0, false
	for {
		c := t.nextc()
		if n == len(test) {
			res = !isPotentialIdentifierChar(c)
		} else if c == int(test[n]) {
			n++
			continue
		}
		t.backup(c)
		for n > 0 {
			n--
			t.backup(int(test[n]))
		}
		return res
	}
}

// verifyEndOfNumber is lexer.c verify_end_of_number; the SyntaxWarning branch (a keyword right
// after the literal) is a no-op because the oracle suppresses SyntaxWarning.
func (t *tokenizer) verifyEndOfNumber(c int, kind string) bool {
	if t.extra {
		return true
	}
	r := false
	switch c {
	case 'a':
		r = t.lookahead("nd")
	case 'e':
		r = t.lookahead("lse")
	case 'f':
		r = t.lookahead("or")
	case 'i':
		c2 := t.nextc()
		r = c2 == 'f' || c2 == 'n' || c2 == 's'
		t.backup(c2)
	case 'o':
		r = t.lookahead("r")
	case 'n':
		r = t.lookahead("ot")
	}
	if !r && c < 128 && isPotentialIdentifierChar(c) {
		t.backup(c)
		t.syntaxError("invalid %s literal", kind)
		return false
	}
	return true
}

// decimalTail is tok_decimal_tail: the char after the digits, 0 on error.
func (t *tokenizer) decimalTail() int {
	for {
		c := t.nextc()
		for isDigit(c) {
			c = t.nextc()
		}
		if c != '_' {
			return c
		}
		if c = t.nextc(); !isDigit(c) {
			t.backup(c)
			t.syntaxError("invalid decimal literal")
			return 0
		}
	}
}

// number scans a numeric literal whose first digit c has been consumed.
func (t *tokenizer) number(c int) (Token, *SyntaxError) {
	if c != '0' {
		if c = t.decimalTail(); c == 0 {
			return Token{}, t.err
		}
		if c == '.' {
			return t.fraction(t.nextc())
		}
		return t.exponentOrEnd(c)
	}
	switch c = t.nextc(); c {
	case 'x', 'X':
		return t.radix(isXDigit, "hexadecimal")
	case 'o', 'O':
		return t.radix(func(c int) bool { return '0' <= c && c < '8' }, "octal")
	case 'b', 'B':
		return t.radix(func(c int) bool { return c == '0' || c == '1' }, "binary")
	}
	nonzero := false
	for {
		if c == '_' {
			if c = t.nextc(); !isDigit(c) {
				t.backup(c)
				return Token{}, t.syntaxError("invalid decimal literal")
			}
		}
		if c != '0' {
			break
		}
		c = t.nextc()
	}
	if isDigit(c) {
		nonzero = true
		if c = t.decimalTail(); c == 0 {
			return Token{}, t.err
		}
	}
	switch {
	case c == '.':
		return t.fraction(t.nextc())
	case c == 'e' || c == 'E':
		return t.exponentOrEnd(c)
	case c == 'j' || c == 'J':
		return t.imaginaryOrEnd(c)
	case nonzero && !t.extra:
		t.backup(c)
		// syntaxerror_known_range: a byte column, used as it is.
		return Token{}, t.fail("SyntaxError", "leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers",
			t.lineno, t.start+1-t.lineStart)
	}
	if !t.verifyEndOfNumber(c, "decimal") {
		return Token{}, t.err
	}
	t.backup(c)
	return t.emit(NUMBER, t.start, t.cur)
}

// radix scans the digits after 0x, 0o or 0b (ok tells the digits of the base).
func (t *tokenizer) radix(ok func(int) bool, kind string) (Token, *SyntaxError) {
	badDigit := func(c int) bool { return kind != "hexadecimal" && isDigit(c) }
	c := t.nextc()
	for {
		if c == '_' {
			c = t.nextc()
		}
		if !ok(c) {
			if badDigit(c) {
				return Token{}, t.syntaxError("invalid digit '%c' in %s literal", c, kind)
			}
			t.backup(c)
			return Token{}, t.syntaxError("invalid %s literal", kind)
		}
		for ok(c) {
			c = t.nextc()
		}
		if c != '_' {
			break
		}
	}
	if badDigit(c) {
		return Token{}, t.syntaxError("invalid digit '%c' in %s literal", c, kind)
	}
	if !t.verifyEndOfNumber(c, kind) {
		return Token{}, t.err
	}
	t.backup(c)
	return t.emit(NUMBER, t.start, t.cur)
}

// fraction continues after '.', c being the char after it.
func (t *tokenizer) fraction(c int) (Token, *SyntaxError) {
	if isDigit(c) {
		if c = t.decimalTail(); c == 0 {
			return Token{}, t.err
		}
	}
	return t.exponentOrEnd(c)
}

func (t *tokenizer) exponentOrEnd(c int) (Token, *SyntaxError) {
	if c == 'e' || c == 'E' {
		e := c
		c = t.nextc()
		if c == '+' || c == '-' {
			if c = t.nextc(); !isDigit(c) {
				t.backup(c)
				return Token{}, t.syntaxError("invalid decimal literal")
			}
		} else if !isDigit(c) {
			t.backup(c)
			if !t.verifyEndOfNumber(e, "decimal") {
				return Token{}, t.err
			}
			t.backup(e)
			return t.emit(NUMBER, t.start, t.cur)
		}
		if c = t.decimalTail(); c == 0 {
			return Token{}, t.err
		}
	}
	return t.imaginaryOrEnd(c)
}

func (t *tokenizer) imaginaryOrEnd(c int) (Token, *SyntaxError) {
	if c == 'j' || c == 'J' {
		c = t.nextc()
		if !t.verifyEndOfNumber(c, "imaginary") {
			return Token{}, t.err
		}
	} else if !t.verifyEndOfNumber(c, "decimal") {
		return Token{}, t.err
	}
	t.backup(c)
	return t.emit(NUMBER, t.start, t.cur)
}

// continuationLine is tok_continuation_line: -1 with done set on error, else the (backed up)
// first char of the next line.
func (t *tokenizer) continuationLine() int {
	c := t.nextc()
	if c == '\r' {
		c = t.nextc()
	}
	if c != '\n' {
		t.done = eLineCont
		return -1
	}
	if c = t.nextc(); c == eof {
		t.done = eEOF
		t.cur = t.inp
		return -1
	}
	t.backup(c)
	return c
}

// doneAt ends the line with the given tok->done code and raises its pegen error.
func (t *tokenizer) doneAt(code int) (Token, *SyntaxError) {
	t.done = code
	t.cur = t.inp
	return t.doneError()
}

// updateFstringExpr is _PyLexer_update_fstring_expr over the whole-buffer string tokenizer.
func (t *tokenizer) updateFstringExpr(c int) {
	m := t.mode()
	switch c {
	case '{':
		m.exprStart, m.exprEnd = t.cur, -1
	case '}', '!':
		m.exprEnd = t.start
	case ':':
		if m.exprEnd == -1 {
			m.exprEnd = t.start
		}
	}
}

var fstringComment = regexp.MustCompile(`#[^\n]*`)

// setFstringExpr is set_fstring_expr: the debug text of a '{...=' field with '#' comments cut
// (the newline after each comment stays).
func (t *tokenizer) setFstringExpr() {
	if m := t.mode(); m.debug && m.exprStart >= 0 && m.exprEnd >= m.exprStart {
		t.meta = fstringComment.ReplaceAllString(t.src[m.exprStart:m.exprEnd], "")
	}
}

func (t *tokenizer) normalMode() (Token, *SyntaxError) {
	var c int
	var blankline bool
nextline:
	blankline = false

	if t.atbol {
		col, altcol, contLineCol := 0, 0, 0
		t.atbol = false
	indentation:
		for {
			c = t.nextc()
			switch c {
			case ' ':
				col++
				altcol++
			case '\t':
				col = (col/tabSize + 1) * tabSize
				altcol++
			case '\f':
				col, altcol = 0, 0
			case '\\':
				// Indentation cannot be split over physical lines: the first backslash wins.
				if contLineCol == 0 {
					contLineCol = col
				}
				if c = t.continuationLine(); c == -1 {
					return t.doneError()
				}
			default:
				break indentation
			}
		}
		t.backup(c)
		if c == '#' || c == '\n' || c == '\r' {
			blankline = true // whitespace/comment-only line: not a NEWLINE, no indentation change
		}
		if !blankline && t.level == 0 {
			if contLineCol != 0 {
				col, altcol = contLineCol, contLineCol
			}
			switch {
			case col == t.indstack[t.indent]:
				if altcol != t.altindstack[t.indent] {
					return t.doneAt(eTabSpace)
				}
			case col > t.indstack[t.indent]:
				if t.indent+1 >= maxIndent {
					return t.doneAt(eTooDeep)
				}
				if altcol <= t.altindstack[t.indent] {
					return t.doneAt(eTabSpace)
				}
				t.pendin++
				t.indent++
				t.indstack[t.indent] = col
				t.altindstack[t.indent] = altcol
			default:
				for t.indent > 0 && col < t.indstack[t.indent] {
					t.pendin--
					t.indent--
				}
				if col != t.indstack[t.indent] {
					return t.doneAt(eDedent)
				}
				if altcol != t.altindstack[t.indent] {
					return t.doneAt(eTabSpace)
				}
			}
		}
	}

	if t.pendin != 0 {
		if t.pendin < 0 {
			t.pendin++
			if t.extra {
				return t.emit(DEDENT, t.cur, t.cur)
			}
			return t.emit(DEDENT, -1, -1)
		}
		t.pendin--
		if t.extra {
			return t.emit(INDENT, t.lineStart, t.cur)
		}
		return t.emit(INDENT, -1, -1)
	}

again:
	for c = t.nextc(); c == ' ' || c == '\t' || c == '\f'; c = t.nextc() {
	}
	t.start = t.cur - 1

	if c == '#' {
		for c != eof && c != '\n' && c != '\r' {
			c = t.nextc()
		}
		if t.extra {
			t.backup(c) // leave the newline or EOF
			t.commentNewline = blankline
			return t.emit(COMMENT, t.start, t.cur)
		}
	}

	if c == eof {
		if t.level > 0 || t.done != eEOF {
			return t.doneError()
		}
		return t.emit(ENDMARKER, -1, -1)
	}

	if isPotentialIdentifierStart(c) {
		sawB, sawR, sawU, sawF := false, false, false, false
	prefix:
		for {
			switch {
			case !(sawB || sawU || sawF) && (c == 'b' || c == 'B'):
				sawB = true
			case !(sawB || sawU || sawR || sawF) && (c == 'u' || c == 'U'):
				sawU = true
			case !(sawR || sawU) && (c == 'r' || c == 'R'):
				sawR = true
			case !(sawF || sawB || sawU) && (c == 'f' || c == 'F'):
				sawF = true
			default:
				break prefix
			}
			c = t.nextc()
			if c == '"' || c == '\'' {
				if sawF {
					goto fstringQuote
				}
				goto letterQuote
			}
		}
		nonascii := false
		for isPotentialIdentifierChar(c) {
			if c >= 128 {
				nonascii = true
			}
			c = t.nextc()
		}
		t.backup(c)
		if nonascii && !t.verifyIdentifier() {
			return Token{}, t.err
		}
		return t.emit(NAME, t.start, t.cur)
	}

	if c == '\n' {
		t.atbol = true
		if blankline || t.level > 0 {
			if t.extra {
				t.commentNewline = false
				return t.emit(NL, t.start, t.cur)
			}
			goto nextline
		}
		if t.commentNewline && t.extra {
			t.commentNewline = false
			return t.emit(NL, t.start, t.cur)
		}
		return t.emit(NEWLINE, t.start, t.cur-1) // the '\n' is left out of the string
	}

	if c == '.' {
		c = t.nextc()
		if isDigit(c) {
			return t.fraction(c)
		}
		if c == '.' {
			if c = t.nextc(); c == '.' {
				return t.emit(OP, t.start, t.cur)
			}
			t.backup(c)
			t.backup('.')
		} else {
			t.backup(c)
		}
		return t.emit(OP, t.start, t.cur)
	}

	if isDigit(c) {
		return t.number(c)
	}

letterQuote:
	if c == '\'' || c == '"' {
		quote := c
		quoteSize, endQuoteSize := 1, 0
		hasEscapedQuote := false
		t.firstLineno = t.lineno
		t.multiLineStart = t.lineStart
		c = t.nextc()
		if c == quote {
			if c = t.nextc(); c == quote {
				quoteSize = 3
			} else {
				endQuoteSize = 1 // empty string
			}
		}
		if c != quote {
			t.backup(c)
		}
		for endQuoteSize != quoteSize {
			c = t.nextc()
			if c == eof || (quoteSize == 1 && c == '\n') {
				// Report from the opening quote.
				t.cur = t.start + 1
				t.lineStart = t.multiLineStart
				start := t.lineno
				t.lineno = t.firstLineno
				if t.insideFstring() {
					if m := t.mode(); m.quote == quote && m.quoteSize == quoteSize {
						return Token{}, t.syntaxError("f-string: expecting '}'")
					}
				}
				if quoteSize == 3 {
					return Token{}, t.syntaxError("unterminated triple-quoted string literal (detected at line %d)", start)
				}
				if hasEscapedQuote {
					return Token{}, t.syntaxError("unterminated string literal (detected at line %d); perhaps you escaped the end quote?", start)
				}
				return Token{}, t.syntaxError("unterminated string literal (detected at line %d)", start)
			}
			if c == quote {
				endQuoteSize++
				continue
			}
			endQuoteSize = 0
			if c == '\\' {
				if c = t.nextc(); c == quote {
					hasEscapedQuote = true
				}
				if c == '\r' {
					t.nextc()
				}
			}
		}
		return t.emit(STRING, t.start, t.cur)
	}

fstringQuote:
	if (c == '\'' || c == '"') && (t.src[t.start]|0x20 == 'f' || t.src[t.start]|0x20 == 'r') {
		quote, quoteSize := c, 1
		t.firstLineno = t.lineno
		t.multiLineStart = t.lineStart
		// The line still holds its '\n', so two more quotes never cross a line.
		if q := t.src[t.cur:]; len(q) >= 2 && q[0] == byte(quote) && q[1] == byte(quote) { // #nosec G115 -- quote is the quote character checked at the string start
			t.cur += 2
			quoteSize = 3
		}
		if len(t.modes) >= maxFstringLevel {
			return Token{}, t.syntaxError("too many nested f-strings")
		}
		raw := t.src[t.start]|0x20 == 'r' || t.src[t.start+1]|0x20 == 'r'
		t.modes = append(t.modes, tokMode{fstring: true, quote: quote, quoteSize: quoteSize, raw: raw,
			start: t.start, multiLineStart: t.lineStart, lineno: t.lineno, exprStartDepth: -1, exprStart: -1, exprEnd: -1})
		return t.emit(FSTRING_START, t.start, t.cur)
	}

	if c == '\\' {
		if c = t.continuationLine(); c == -1 {
			return t.doneError()
		}
		goto again
	}

	if (c == ':' || c == '}' || c == '!' || c == '{') && t.insideFstring() && t.mode().exprStartDepth >= 0 {
		m := t.mode()
		// Runs before the '{' below increments the depth, so level 0 needs adjusting by hand.
		cursor := m.curlyDepth
		if c != '{' {
			cursor--
		}
		if cursor == 0 || (cursor == 1 && (m.debug || m.inFormatSpec)) {
			t.updateFstringExpr(c)
			if c != '{' {
				t.setFstringExpr()
			}
		}
		if c == ':' && cursor == m.exprStartDepth {
			m.fstring = true
			m.inFormatSpec = true
			return t.emit(OP, t.start, t.cur)
		}
	}

	if c2 := t.nextc(); isTwoCharOp(c, c2) {
		if c3 := t.nextc(); !isThreeCharOp(c, c2, c3) {
			t.backup(c3)
		}
		return t.emit(OP, t.start, t.cur)
	} else {
		t.backup(c2)
	}

	switch c {
	case '(', '[', '{':
		if t.level >= maxLevel {
			return Token{}, t.syntaxError("too many nested parentheses")
		}
		t.parenstack[t.level], t.parenLineno[t.level], t.parenCol[t.level] = c, t.lineno, t.start-t.lineStart
		t.level++
		if t.insideFstring() {
			t.mode().curlyDepth++
		}
	case ')', ']', '}':
		if t.insideFstring() && t.mode().curlyDepth == 0 && c == '}' {
			return Token{}, t.syntaxError("f-string: single '}' is not allowed")
		}
		if !t.extra && t.level == 0 {
			return Token{}, t.syntaxError("unmatched '%c'", c)
		}
		if t.level > 0 {
			t.level--
			opening := t.parenstack[t.level]
			if !t.extra && !((opening == '(' && c == ')') || (opening == '[' && c == ']') || (opening == '{' && c == '}')) {
				if m := t.mode(); t.insideFstring() && opening == '{' && m.curlyDepth-1 == m.exprStartDepth {
					return Token{}, t.syntaxError("f-string: unmatched '%c'", c)
				}
				if t.parenLineno[t.level] != t.lineno {
					return Token{}, t.syntaxError("closing parenthesis '%c' does not match opening parenthesis '%c' on line %d", c, opening, t.parenLineno[t.level])
				}
				return Token{}, t.syntaxError("closing parenthesis '%c' does not match opening parenthesis '%c'", c, opening)
			}
		}
		if t.insideFstring() {
			m := t.mode()
			m.curlyDepth--
			if m.curlyDepth < 0 {
				return Token{}, t.syntaxError("f-string: unmatched '%c'", c)
			}
			if c == '}' && m.curlyDepth == m.exprStartDepth {
				m.exprStartDepth--
				m.fstring = true
				m.inFormatSpec = false
				m.debug = false
			}
		}
	}

	if !pytext.IsPrintable(string(rune(c))) { // #nosec G115 -- c is a nextc result, a byte or eof
		return Token{}, t.syntaxError("invalid non-printable character U+%04X", c)
	}
	if c == '=' && t.insideFstring() && t.mode().exprStartDepth >= 0 {
		t.mode().debug = true
	}
	return t.emit(OP, t.start, t.cur)
}

func (t *tokenizer) fstringMode(m *tokMode) (Token, *SyntaxError) {
	endQuoteSize := 0
	unicodeEscape := false
	t.start = t.cur
	t.firstLineno = t.lineno

	// A replacement field starts here: hand over to the normal mode. Every entry leaves cur
	// before the line's '\n', so peeking at src needs no nextc line advance.
	if rest := t.src[t.cur:]; strings.HasPrefix(rest, "{") && !strings.HasPrefix(rest, "{{") {
		m.exprStartDepth++
		if m.exprStartDepth >= maxExprNesting {
			return Token{}, t.syntaxError("f-string: expressions nested too deeply")
		}
		m.fstring = false
		return t.normalMode()
	}

	// The closing quotes?
	if q := strings.Repeat(string(rune(m.quote)), m.quoteSize); strings.HasPrefix(t.src[t.cur:], q) { // #nosec G115 -- m.quote is the quote character checked at the f-string start
		t.cur += m.quoteSize
		t.modes = t.modes[:len(t.modes)-1]
		return t.emit(FSTRING_END, t.start, t.cur)
	}

	t.multiLineStart = t.lineStart
	for endQuoteSize != m.quoteSize {
		c := t.nextc()
		inFormatSpec := m.inFormatSpec && m.exprStartDepth >= 0
		if c == eof || (m.quoteSize == 1 && c == '\n') {
			if inFormatSpec && c == '\n' {
				// The format spec ends with the line.
				t.backup(c)
				m.fstring = false
				m.inFormatSpec = false
				return t.emit(FSTRING_MIDDLE, t.start, t.cur)
			}
			t.cur = m.start + 1
			t.lineStart = m.multiLineStart
			start := t.lineno
			t.lineno = m.lineno
			if m.quoteSize == 3 {
				return Token{}, t.syntaxError("unterminated triple-quoted f-string literal (detected at line %d)", start)
			}
			return Token{}, t.syntaxError("unterminated f-string literal (detected at line %d)", start)
		}
		if c == m.quote {
			endQuoteSize++
			continue
		}
		endQuoteSize = 0
		switch c {
		case '{':
			t.updateFstringExpr(c)
			peek := t.nextc()
			if peek != '{' || inFormatSpec {
				t.backup(peek)
				t.backup(c)
				m.exprStartDepth++
				if m.exprStartDepth >= maxExprNesting {
					return Token{}, t.syntaxError("f-string: expressions nested too deeply")
				}
				m.fstring = false
				m.inFormatSpec = false
				return t.emit(FSTRING_MIDDLE, t.start, t.cur)
			}
			return t.emit(FSTRING_MIDDLE, t.start, t.cur-1) // '{{': one brace kept
		case '}':
			if unicodeEscape {
				return t.emit(FSTRING_MIDDLE, t.start, t.cur)
			}
			peek := t.nextc()
			if peek == '}' && !inFormatSpec && m.curlyDepth == 0 {
				return t.emit(FSTRING_MIDDLE, t.start, t.cur-1) // '}}': one brace kept
			}
			t.backup(peek)
			t.backup(c)
			m.fstring = false
			m.inFormatSpec = false
			return t.emit(FSTRING_MIDDLE, t.start, t.cur)
		case '\\':
			peek := t.nextc()
			if peek == '\r' {
				peek = t.nextc()
			}
			if peek == '{' || peek == '}' {
				t.backup(peek) // "\{" is a literal backslash before a field (SyntaxWarning only)
				continue
			}
			if !m.raw && peek == 'N' {
				if peek = t.nextc(); peek == '{' {
					unicodeEscape = true // \N{NAME}: the braces are not a field
				} else {
					t.backup(peek)
				}
			}
		}
	}
	t.cur -= m.quoteSize // leave the quotes for FSTRING_END
	return t.emit(FSTRING_MIDDLE, t.start, t.cur)
}
