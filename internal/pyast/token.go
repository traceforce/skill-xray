package pyast

import "fmt"

// TokenKind is the CPython token type the parser dispatches on. Keywords are NAME tokens
// (the parser checks Str), operators and delimiters are OP tokens keyed by Str.
type TokenKind int

const (
	ENDMARKER TokenKind = iota
	NAME
	NUMBER
	STRING
	NEWLINE
	INDENT
	DEDENT
	OP
	FSTRING_START
	FSTRING_MIDDLE
	FSTRING_END
	COMMENT // tokenize-module stream only (extra tokens)
	NL
)

var kindNames = [...]string{"ENDMARKER", "NAME", "NUMBER", "STRING", "NEWLINE", "INDENT", "DEDENT", "OP", "FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END", "COMMENT", "NL"}

func (k TokenKind) String() string { return kindNames[k] }

// Token is one lexical token with CPython's positions: 1-based lines and 0-based UTF-8
// byte columns. INDENT, DEDENT and ENDMARKER carry Col == -1 like CPython's start-less
// tokens; for them Cur is the tokenizer's byte position within Lineno (tok->cur -
// line_start), which is what CPython reports when an error lands on such a token.
type Token struct {
	Kind                           TokenKind
	Str                            string // source text of the token (FSTRING_MIDDLE: the literal text with one brace of a doubled pair dropped)
	Lineno, Col, EndLineno, EndCol int
	Level                          int // parenthesis nesting depth at the token
	Cur                            int
	Meta                           string // f-string debug text: the source from '{' to this '}', '!' or ':' when the field has '='
}

// SyntaxError is what Parse returns for refused input. Kind is the Python exception class
// name: SyntaxError, IndentationError, TabError, RecursionError or MemoryError. Line is
// 1-based and Offset is the 1-based character offset within that line, both 0 when Python
// reports None.
type SyntaxError struct {
	Kind   string
	Msg    string
	Line   int
	Offset int
}

func (e *SyntaxError) Error() string {
	if e.Line == 0 {
		return e.Kind + ": " + e.Msg
	}
	return fmt.Sprintf("%s: %s (line %d, offset %d)", e.Kind, e.Msg, e.Line, e.Offset)
}
