package pyast

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// recursionCeiling is the AST depth at which CPython 3.13.2 (Windows x64, default limits)
// raises "maximum recursion depth exceeded during ast construction" while converting the C
// AST to Python objects; measured on +, -, not, attribute, subscript, call and conditional
// chains (all fail at node depth 2998, Module being depth 1). Singletons are not counted.
// ponytail: build-dependent; pinned only by the contract corpus (bomb.py refused, deep.py
// accepted). Re-measure if the oracle's CPython build changes.
const recursionCeiling = 2998

// Parse is ast.parse(src) for a str source in "exec" mode. The error is always a
// *SyntaxError whose Kind names the Python exception class.
func Parse(src string) (*Module, error) {
	if strings.IndexByte(src, 0) >= 0 {
		return nil, &SyntaxError{Kind: "SyntaxError", Msg: "source code string cannot contain null bytes"}
	}
	p := &parser{t: newTokenizer(src), memo: map[memoKey]memoEntry{}}
	m, err := p.run()
	if err != nil {
		return nil, err
	}
	// ast2obj recursion: every node except the singletons, the root counting as 1.
	if depth(m, false)+1 >= recursionCeiling {
		return nil, &SyntaxError{Kind: "RecursionError", Msg: "maximum recursion depth exceeded during ast construction"}
	}
	return m, nil
}

type memoEntry struct {
	node Expr
	end  int
}

// rule names a memoised grammar rule: pegen's (memo) rules and its left-recursive ones, whose
// memo is what keeps nested alternatives (tuple/group/genexp, the star_atom parens, the
// invalid_* second pass) linear instead of doubling per nesting level.
type rule uint8

const (
	rExpression rule = iota
	rStarExpression
	rDisjunction
	rConjunction
	rInversion
	rBitwiseOr
	rBitwiseXor
	rBitwiseAnd
	rShiftExpr
	rSum
	rTerm
	rFactor
	rAwaitPrimary
	rPrimary
	rStrings
	rStarTarget
	rTargetWithStarAtom
	rDelTarget
	rTPrimary
)

type memoKey struct {
	rule rule
	pos  int
}

type parser struct {
	t       *tokenizer
	toks    []Token // tokens fetched so far
	tokErr  *SyntaxError
	pos     int  // p->mark
	fill    int  // p->fill: one past the furthest token fetched
	invalid bool // p->call_invalid_rules
	memo    map[memoKey]memoEntry
	depth   int
}

// bail carries a raised SyntaxError up through the recursive descent.
type bail struct{ err *SyntaxError }

func (p *parser) run() (m *Module, err *SyntaxError) {
	defer func() {
		if r := recover(); r != nil {
			b, ok := r.(bail)
			if !ok {
				panic(r)
			}
			m, err = nil, b.err
		}
	}()
	m = p.file()
	if m != nil {
		return m, nil
	}
	// First pass failed without a raised error: remember the furthest token, run the
	// second pass with the invalid_* rules (fill keeps growing, as pegen's does), and fall
	// back to the generic message.
	last := p.toks[p.fill-1]
	p.pos, p.invalid, p.memo = 0, true, map[memoKey]memoEntry{}
	p.file()
	if last.Kind == INDENT {
		return nil, p.errorAtToken("IndentationError", &last, "unexpected indent")
	}
	if last.Kind == DEDENT {
		return nil, p.errorAtToken("IndentationError", &last, "unexpected unindent")
	}
	generic := p.errorKnownLocation("SyntaxError", &last, "invalid syntax")
	// _PyPegen_tokenize_full_source_to_check_for_errors: a later error the tokenizer itself
	// raised wins; the tok->done codes pegen turns into errors do not, except an unclosed
	// bracket at EOF opened before the error line.
	for p.tokErr == nil && p.toks[len(p.toks)-1].Kind != ENDMARKER {
		p.fetch()
	}
	if e := p.tokErr; e != nil {
		if strings.HasSuffix(e.Msg, "was never closed") {
			if last.Lineno > e.Line {
				return nil, e
			}
		} else if !doneCodeMessages[e.Msg] {
			return nil, e
		}
	}
	return nil, generic
}

// doneCodeMessages are the errors pegen builds from tok->done (E_DEDENT, E_TABSPACE,
// E_TOODEEP, E_LINECONT, E_EOF) rather than the tokenizer raising them itself.
var doneCodeMessages = map[string]bool{
	"unindent does not match any outer indentation level":    true,
	"inconsistent use of tabs and spaces in indentation":     true,
	"too many levels of indentation":                         true,
	"unexpected character after line continuation character": true,
	"unexpected EOF while parsing":                           true,
}

// fetch pulls one more token from the tokenizer, recording its error instead of a token.
func (p *parser) fetch() {
	tok, err := p.t.next()
	if err != nil {
		if err.Msg == "unexpected character after line continuation character" {
			err = p.lineContError(err)
		}
		p.tokErr = err
		return
	}
	p.toks = append(p.toks, tok)
}

// lineContError re-anchors E_LINECONT the way pegen measures it: from tok->buf, which a
// backslash continuation leaves at the first line of the continued chain, so the offset
// counts every continued line before the error line.
// ponytail: a multi-line string token ending on the previous line holds buf back the same
// way; no corpus input has that shape, so only backslash chains are followed.
func (p *parser) lineContError(err *SyntaxError) *SyntaxError {
	offset := err.Offset
	for l := err.Line - 1; l >= 1; l-- {
		text := strings.TrimSuffix(p.t.lineText(l), "\n")
		if !strings.HasSuffix(text, "\\") {
			break
		}
		offset += utf8.RuneCountInString(text) + 1
	}
	return &SyntaxError{Kind: err.Kind, Msg: err.Msg, Line: err.Line, Offset: offset}
}

// tok fetches token i, growing fill; reading past a tokenizer error raises that error.
func (p *parser) tok(i int) *Token {
	for i >= len(p.toks) {
		if p.tokErr != nil {
			panic(bail{p.tokErr})
		}
		if len(p.toks) > 0 && p.toks[len(p.toks)-1].Kind == ENDMARKER {
			i = len(p.toks) - 1
			break
		}
		p.fetch()
	}
	if i+1 > p.fill {
		p.fill = i + 1
	}
	return &p.toks[i]
}

func (p *parser) peek() *Token { return p.tok(p.pos) }

func (p *parser) peekAt(n int) *Token { return p.tok(p.pos + n) }

func (p *parser) advance() *Token {
	t := p.tok(p.pos)
	p.pos++
	return t
}

var hardKeywords = map[string]bool{"False": true, "None": true, "True": true, "and": true, "as": true, "assert": true, "async": true, "await": true, "break": true, "class": true, "continue": true, "def": true, "del": true, "elif": true, "else": true, "except": true, "finally": true, "for": true, "from": true, "global": true, "if": true, "import": true, "in": true, "is": true, "lambda": true, "nonlocal": true, "not": true, "or": true, "pass": true, "raise": true, "return": true, "try": true, "while": true, "with": true, "yield": true}

var softKeywords = map[string]bool{"match": true, "case": true, "type": true, "_": true}

func (p *parser) atOp(s string) bool {
	t := p.peek()
	return t.Kind == OP && t.Str == s
}

func (p *parser) atKw(s string) bool {
	t := p.peek()
	return t.Kind == NAME && t.Str == s
}

func (p *parser) atKind(k TokenKind) bool { return p.peek().Kind == k }

// isName reports a NAME token that is not a hard keyword.
func (p *parser) isName(t *Token) bool { return t.Kind == NAME && !hardKeywords[t.Str] }

func (p *parser) expectOp(s string) *Token {
	if p.atOp(s) {
		return p.advance()
	}
	return nil
}

func (p *parser) expectKw(s string) *Token {
	if p.atKw(s) {
		return p.advance()
	}
	return nil
}

// forced is the grammar's &&'x': a missing token raises immediately, in both passes.
func (p *parser) forced(s string) *Token {
	if t := p.expectOp(s); t != nil {
		return t
	}
	t := p.peek()
	panic(bail{p.errorAtToken("SyntaxError", t, fmt.Sprintf("expected '%s'", s))})
}

// name consumes a NAME that is not a hard keyword and returns it as a Load Name.
func (p *parser) name() *Name {
	t := p.peek()
	if !p.isName(t) {
		return nil
	}
	p.pos++
	return &Name{Pos: tokPos(t), Id: identifier(t.Str), Ctx: LoadCtx}
}

func tokPos(t *Token) Pos { return Pos{t.Lineno, t.Col, t.EndLineno, t.EndCol} }

// span is the grammar's EXTRA: from the start token to the last non-whitespace token consumed.
func (p *parser) span(start *Token) Pos {
	for i := p.pos - 1; i >= 0; i-- {
		t := &p.toks[i]
		if t.Kind != ENDMARKER && t.Kind != NEWLINE && t.Kind != INDENT && t.Kind != DEDENT {
			return Pos{start.Lineno, start.Col, t.EndLineno, t.EndCol}
		}
	}
	return Pos{start.Lineno, start.Col, start.EndLineno, start.EndCol}
}

// posOf is the `_attributes` block of a positioned node (every node except Module and the
// singletons embeds Pos).
func posOf(n Node) Pos { return n.(interface{ pos() Pos }).pos() }

func (x Pos) pos() Pos { return x }

// errorAtToken is _PyPegen_raise_error's location for a token: its start column, or the
// tokenizer cursor for the start-less INDENT/DEDENT/ENDMARKER tokens.
func (p *parser) errorAtToken(kind string, t *Token, msg string) *SyntaxError {
	line := p.t.lineText(t.Lineno)
	if t.Col == -1 {
		return &SyntaxError{Kind: kind, Msg: msg, Line: t.Lineno, Offset: charOffset(line, t.Cur)}
	}
	return &SyntaxError{Kind: kind, Msg: msg, Line: t.Lineno, Offset: charOffset(line, t.Col+1)}
}

// errorKnownLocation is RAISE_SYNTAX_ERROR_KNOWN_LOCATION on a token: col_offset + 1, which
// makes a start-less token (col -1) report offset 0.
func (p *parser) errorKnownLocation(kind string, t *Token, msg string) *SyntaxError {
	if t.Col == -1 {
		return &SyntaxError{Kind: kind, Msg: msg, Line: t.Lineno, Offset: 0}
	}
	return &SyntaxError{Kind: kind, Msg: msg, Line: t.Lineno, Offset: charOffset(p.t.lineText(t.Lineno), t.Col+1)}
}

// raiseAt is RAISE_SYNTAX_ERROR_KNOWN_LOCATION / KNOWN_RANGE / STARTING_FROM on a node.
func (p *parser) raiseAt(n Node, msg string) {
	q := posOf(n)
	p.raiseAtCol(q.Lineno, q.ColOffset, msg)
}

// raiseAtCol is RAISE_ERROR_KNOWN_LOCATION with an explicit 0-based byte column.
func (p *parser) raiseAtCol(lineno, col int, msg string) {
	panic(bail{&SyntaxError{Kind: "SyntaxError", Msg: msg, Line: lineno, Offset: charOffset(p.t.lineText(lineno), col+1)}})
}

func (p *parser) raiseAtTok(t *Token, msg string) {
	panic(bail{p.errorKnownLocation("SyntaxError", t, msg)})
}

// raiseLast is RAISE_SYNTAX_ERROR: located at the furthest token fetched so far.
func (p *parser) raiseLast(kind, msg string) {
	panic(bail{p.errorAtToken(kind, &p.toks[p.fill-1], msg)})
}

// raiseNext is RAISE_SYNTAX_ERROR_ON_NEXT_TOKEN.
func (p *parser) raiseNext(msg string) {
	panic(bail{p.errorAtToken("SyntaxError", p.peek(), msg)})
}

// ---- statements ----

func (p *parser) file() *Module {
	body := p.statements()
	if !p.atKind(ENDMARKER) {
		return nil
	}
	if body == nil {
		body = []Stmt{}
	}
	return &Module{Body: body}
}

func (p *parser) statements() []Stmt {
	var out []Stmt
	for {
		s := p.statement()
		if s == nil {
			return out
		}
		out = append(out, s...)
	}
}

func (p *parser) statement() []Stmt {
	if s := p.compoundStmt(); s != nil {
		return []Stmt{s}
	}
	return p.simpleStmts()
}

func (p *parser) simpleStmts() []Stmt {
	mark := p.pos
	s := p.simpleStmt()
	if s == nil {
		p.pos = mark
		return nil
	}
	stmts := []Stmt{s}
	for p.atOp(";") {
		save := p.pos
		p.pos++
		s2 := p.simpleStmt()
		if s2 == nil {
			p.pos = save
			break
		}
		stmts = append(stmts, s2)
	}
	p.expectOp(";")
	if !p.atKind(NEWLINE) {
		p.pos = mark
		return nil
	}
	p.pos++
	return stmts
}

func (p *parser) simpleStmt() Stmt {
	mark := p.pos
	if s := p.assignment(); s != nil {
		return s
	}
	p.pos = mark
	if p.atKw("type") {
		if s := p.typeAlias(); s != nil {
			return s
		}
		p.pos = mark
	}
	start := p.peek()
	if e := p.starExpressions(); e != nil {
		return &ExprStmt{Pos: p.span(start), Value: e}
	}
	p.pos = mark
	t := p.peek()
	if t.Kind != NAME {
		return nil
	}
	switch t.Str {
	case "return":
		p.pos++
		v := p.starExpressions()
		return &Return{Pos: p.span(t), Value: v}
	case "import", "from":
		return p.importStmt()
	case "raise":
		p.pos++
		if e := p.expression(); e != nil {
			var cause Expr
			if p.atKw("from") {
				save := p.pos
				p.pos++
				if cause = p.expression(); cause == nil {
					p.pos = save
				}
			}
			return &Raise{Pos: p.span(t), Exc: e, Cause: cause}
		}
		p.pos = mark + 1
		return &Raise{Pos: p.span(t)}
	case "pass":
		p.pos++
		return &Pass{Pos: tokPos(t)}
	case "del":
		return p.delStmt()
	case "yield":
		if y := p.yieldExpr(); y != nil {
			return &ExprStmt{Pos: p.span(t), Value: y}
		}
		return nil
	case "assert":
		p.pos++
		test := p.expression()
		if test == nil {
			p.pos = mark
			return nil
		}
		var msg Expr
		if p.atOp(",") {
			save := p.pos
			p.pos++
			if msg = p.expression(); msg == nil {
				p.pos = save
			}
		}
		return &Assert{Pos: p.span(t), Test: test, Msg: msg}
	case "break":
		p.pos++
		return &Break{Pos: tokPos(t)}
	case "continue":
		p.pos++
		return &Continue{Pos: tokPos(t)}
	case "global", "nonlocal":
		p.pos++
		var names []string
		for {
			n := p.name()
			if n == nil {
				p.pos = mark
				return nil
			}
			names = append(names, n.Id)
			if !p.atOp(",") {
				break
			}
			p.pos++
		}
		if t.Str == "global" {
			return &Global{Pos: p.span(t), Names: names}
		}
		return &Nonlocal{Pos: p.span(t), Names: names}
	}
	return nil
}

func (p *parser) assignment() Stmt {
	mark := p.pos
	start := p.peek()
	// NAME ':' expression ['=' annotated_rhs]
	if n := p.name(); n != nil {
		if p.expectOp(":") != nil {
			if ann := p.expression(); ann != nil {
				val := p.optAnnotatedRhs()
				n.Ctx = storeCtx
				return &AnnAssign{Pos: p.span(start), Target: n, Annotation: ann, Value: val, Simple: 1}
			}
		}
		p.pos = mark
	}
	// ('(' single_target ')' | single_subscript_attribute_target) ':' expression ['=' annotated_rhs]
	var tgt Expr
	if p.expectOp("(") != nil {
		if t := p.singleTarget(); t != nil && p.expectOp(")") != nil {
			tgt = t
		} else {
			p.pos = mark
		}
	}
	if tgt == nil {
		tgt = p.tTarget(storeCtx)
	}
	if tgt != nil && p.expectOp(":") != nil {
		if ann := p.expression(); ann != nil {
			val := p.optAnnotatedRhs()
			return &AnnAssign{Pos: p.span(start), Target: tgt, Annotation: ann, Value: val, Simple: 0}
		}
	}
	p.pos = mark
	// (star_targets '=')+ (yield_expr | star_expressions) !'='
	var targets []Expr
	for {
		save := p.pos
		t := p.starTargets()
		if t == nil || p.expectOp("=") == nil {
			p.pos = save
			break
		}
		targets = append(targets, t)
	}
	if len(targets) > 0 {
		val := p.yieldExpr()
		if val == nil {
			val = p.starExpressions()
		}
		if val != nil && !p.atOp("=") {
			return &Assign{Pos: p.span(start), Targets: targets, Value: val}
		}
	}
	p.pos = mark
	// single_target augassign ~ (yield_expr | star_expressions)
	if t := p.singleTarget(); t != nil {
		if op := p.augassign(); op != nil {
			val := p.yieldExpr()
			if val == nil {
				val = p.starExpressions()
			}
			if val == nil {
				p.pos = mark
				return nil // cut
			}
			return &AugAssign{Pos: p.span(start), Target: t, Op: op, Value: val}
		}
	}
	p.pos = mark
	if p.invalid {
		p.invalidAssignment()
		p.pos = mark
	}
	return nil
}

func (p *parser) optAnnotatedRhs() Expr {
	if !p.atOp("=") {
		return nil
	}
	save := p.pos
	p.pos++
	v := p.annotatedRhs()
	if v == nil {
		p.pos = save
	}
	return v
}

func (p *parser) annotatedRhs() Expr {
	if y := p.yieldExpr(); y != nil {
		return y
	}
	return p.starExpressions()
}

var augOps = map[string]Operator{"+=": &Add{}, "-=": &Sub{}, "*=": &Mult{}, "@=": &MatMult{}, "/=": &Div{}, "%=": &Mod{}, "&=": &BitAnd{}, "|=": &BitOr{}, "^=": &BitXor{}, "<<=": &LShift{}, ">>=": &RShift{}, "**=": &Pow{}, "//=": &FloorDiv{}}

func (p *parser) augassign() Operator {
	t := p.peek()
	if t.Kind == OP {
		if op, ok := augOps[t.Str]; ok {
			p.pos++
			return op
		}
	}
	return nil
}

func (p *parser) typeAlias() Stmt {
	start := p.advance() // "type"
	n := p.name()
	if n == nil {
		return nil
	}
	params := p.optTypeParams()
	if p.expectOp("=") == nil {
		return nil
	}
	v := p.expression()
	if v == nil {
		return nil
	}
	n.Ctx = storeCtx
	return &TypeAlias{Pos: p.span(start), Name: n, TypeParams: params, Value: v}
}

func (p *parser) delStmt() Stmt {
	mark := p.pos
	start := p.advance() // 'del'
	if targets := p.delTargets(); targets != nil && (p.atOp(";") || p.atKind(NEWLINE)) {
		return &Delete{Pos: p.span(start), Targets: targets}
	}
	p.pos = mark
	if p.invalid {
		// invalid_del_stmt: 'del' star_expressions
		p.pos++
		if e := p.starExpressions(); e != nil {
			p.raiseInvalidTarget(e, kindDel)
		}
		p.pos = mark
	}
	return nil
}

func (p *parser) importStmt() Stmt {
	mark := p.pos
	start := p.peek()
	if p.invalid {
		p.invalidImport()
		p.pos = mark
	}
	if p.expectKw("import") != nil {
		var names []*Alias
		for {
			a := p.dottedAsName()
			if a == nil {
				p.pos = mark
				return nil
			}
			names = append(names, a)
			if p.expectOp(",") == nil {
				break
			}
		}
		return &Import{Pos: p.span(start), Names: names}
	}
	if p.expectKw("from") == nil {
		return nil
	}
	level := 0
	for {
		if p.atOp(".") {
			level++
		} else if p.atOp("...") {
			level += 3
		} else {
			break
		}
		p.pos++
	}
	module := ""
	if level == 0 || p.isName(p.peek()) {
		module = p.dottedName()
		if module == "" {
			p.pos = mark
			return nil
		}
	}
	if p.expectKw("import") == nil {
		p.pos = mark
		return nil
	}
	names := p.importFromTargets()
	if names == nil {
		p.pos = mark
		return nil
	}
	return &ImportFrom{Pos: p.span(start), Module: module, Names: names, Level: level}
}

func (p *parser) importFromTargets() []*Alias {
	mark := p.pos
	if p.expectOp("(") != nil {
		if names := p.importFromAsNames(); names != nil {
			p.expectOp(",")
			if p.expectOp(")") != nil {
				return names
			}
		}
		p.pos = mark
	}
	if names := p.importFromAsNames(); names != nil && !p.atOp(",") {
		return names
	}
	p.pos = mark
	if t := p.expectOp("*"); t != nil {
		return []*Alias{{Pos: tokPos(t), Name: "*"}}
	}
	if p.invalid {
		p.invalidImportFromTargets()
		p.pos = mark
	}
	return nil
}

func (p *parser) importFromAsNames() []*Alias {
	mark := p.pos
	var names []*Alias
	for {
		start := p.peek()
		n := p.name()
		if n == nil {
			break
		}
		a := &Alias{Name: n.Id}
		if p.atKw("as") {
			save := p.pos
			p.pos++
			if as := p.name(); as != nil {
				a.Asname = as.Id
			} else {
				p.pos = save
			}
		}
		a.Pos = p.span(start)
		names = append(names, a)
		if !p.atOp(",") {
			return names
		}
		save := p.pos
		p.pos++
		if !p.isName(p.peek()) {
			p.pos = save
			return names
		}
	}
	if len(names) == 0 {
		p.pos = mark
		return nil
	}
	return names
}

func (p *parser) dottedAsName() *Alias {
	start := p.peek()
	dn := p.dottedName()
	if dn == "" {
		return nil
	}
	a := &Alias{Name: dn}
	if p.atKw("as") {
		save := p.pos
		p.pos++
		if as := p.name(); as != nil {
			a.Asname = as.Id
		} else {
			p.pos = save
		}
	}
	a.Pos = p.span(start)
	return a
}

// dottedName parses NAME ('.' NAME)* into "a.b.c"; "" when there is no name.
func (p *parser) dottedName() string {
	n := p.name()
	if n == nil {
		return ""
	}
	parts := []string{n.Id}
	for p.atOp(".") {
		save := p.pos
		p.pos++
		m := p.name()
		if m == nil {
			p.pos = save
			break
		}
		parts = append(parts, m.Id)
	}
	return strings.Join(parts, ".")
}

// ---- compound statements ----

func (p *parser) compoundStmt() Stmt {
	t := p.peek()
	if t.Kind == OP && t.Str == "@" {
		return p.decorated()
	}
	if t.Kind != NAME {
		return nil
	}
	switch t.Str {
	case "def":
		return p.functionDef(nil)
	case "if":
		return p.ifStmt("if")
	case "class":
		return p.classDef(nil)
	case "with":
		return p.withStmt()
	case "for":
		return p.forStmt()
	case "try":
		return p.tryStmt()
	case "while":
		return p.whileStmt()
	case "async":
		switch p.peekAt(1).Str {
		case "def":
			return p.functionDef(nil)
		case "with":
			return p.withStmt()
		case "for":
			return p.forStmt()
		}
		return nil
	case "match":
		return p.matchStmt()
	}
	return nil
}

func (p *parser) decorated() Stmt {
	mark := p.pos
	var decos []Expr
	for p.atOp("@") {
		save := p.pos
		p.pos++
		e := p.namedExpression()
		if e == nil || !p.atKind(NEWLINE) {
			p.pos = save
			break
		}
		p.pos++
		decos = append(decos, e)
	}
	if len(decos) == 0 {
		p.pos = mark
		return nil
	}
	var s Stmt
	if p.atKw("class") {
		s = p.classDef(decos)
	} else {
		s = p.functionDef(decos)
	}
	if s == nil {
		p.pos = mark
	}
	return s
}

// block: NEWLINE INDENT statements DEDENT | simple_stmts | invalid_block
func (p *parser) block() []Stmt {
	mark := p.pos
	if p.atKind(NEWLINE) {
		p.pos++
		if p.atKind(INDENT) {
			p.pos++
			body := p.statements()
			if body != nil && p.atKind(DEDENT) {
				p.pos++
				return body
			}
		}
		p.pos = mark
	}
	if s := p.simpleStmts(); s != nil {
		return s
	}
	p.pos = mark
	if p.invalid && p.atKind(NEWLINE) {
		p.pos++
		if !p.atKind(INDENT) {
			p.raiseLast("IndentationError", "expected an indented block")
		}
		p.pos = mark
	}
	return nil
}

func (p *parser) functionDef(decos []Expr) Stmt {
	mark := p.pos
	start := p.peek()
	if p.invalid {
		p.invalidDefRaw()
		p.pos = mark
	}
	async := p.expectKw("async") != nil
	if p.expectKw("def") == nil {
		p.pos = mark
		return nil
	}
	n := p.name()
	if n == nil {
		p.pos = mark
		return nil
	}
	tparams := p.optTypeParams()
	if p.expectOp("(") == nil {
		p.pos = mark
		return nil
	}
	args := p.params()
	if p.expectOp(")") == nil {
		p.pos = mark
		return nil
	}
	var returns Expr
	if p.atOp("->") {
		save := p.pos
		p.pos++
		if returns = p.expression(); returns == nil {
			p.pos = save
		}
	}
	if p.expectOp(":") == nil {
		p.pos = mark
		return nil
	}
	body := p.block()
	if body == nil {
		p.pos = mark
		return nil
	}
	if args == nil {
		args = &Arguments{}
	}
	if async {
		return &AsyncFunctionDef{Pos: p.span(start), Name: n.Id, Args: args, Body: body, DecoratorList: decos, Returns: returns, TypeParams: tparams}
	}
	return &FunctionDef{Pos: p.span(start), Name: n.Id, Args: args, Body: body, DecoratorList: decos, Returns: returns, TypeParams: tparams}
}

func (p *parser) classDef(decos []Expr) Stmt {
	mark := p.pos
	start := p.peek()
	if p.invalid {
		p.invalidClassDefRaw()
		p.pos = mark
	}
	if p.expectKw("class") == nil {
		return nil
	}
	n := p.name()
	if n == nil {
		p.pos = mark
		return nil
	}
	tparams := p.optTypeParams()
	var bases []Expr
	var keywords []*Keyword
	if p.atOp("(") {
		save := p.pos
		p.pos++
		bases, keywords = p.arguments()
		if p.expectOp(")") == nil {
			p.pos = save
			bases, keywords = nil, nil
		}
	}
	if p.expectOp(":") == nil {
		p.pos = mark
		return nil
	}
	body := p.block()
	if body == nil {
		p.pos = mark
		return nil
	}
	return &ClassDef{Pos: p.span(start), Name: n.Id, Bases: bases, Keywords: keywords, Body: body, DecoratorList: decos, TypeParams: tparams}
}

// ifStmt parses if_stmt (kw "if") and elif_stmt (kw "elif"), which differ only in the keyword.
func (p *parser) ifStmt(kw string) Stmt {
	mark := p.pos
	start := p.peek()
	if p.invalid {
		p.invalidIfStmt(kw)
		p.pos = mark
	}
	p.pos++ // 'if' / 'elif'
	test := p.namedExpression()
	if test == nil || p.expectOp(":") == nil {
		p.pos = mark
		return nil
	}
	body := p.block()
	if body == nil {
		p.pos = mark
		return nil
	}
	var orelse []Stmt
	if p.atKw("elif") {
		if e := p.ifStmt("elif"); e != nil {
			orelse = []Stmt{e}
		} else {
			p.pos = mark
			return nil
		}
	} else {
		orelse = p.elseBlock()
	}
	return &If{Pos: p.span(start), Test: test, Body: body, Orelse: orelse}
}

// elseBlock: 'else' &&':' block (nil when there is no else).
func (p *parser) elseBlock() []Stmt {
	if !p.atKw("else") {
		return nil
	}
	mark := p.pos
	if p.invalid {
		p.invalidElseStmt()
		p.pos = mark
	}
	p.pos++
	p.forced(":")
	body := p.block()
	if body == nil {
		p.pos = mark
	}
	return body
}

func (p *parser) whileStmt() Stmt {
	mark := p.pos
	start := p.peek()
	if p.invalid {
		p.invalidWhileStmt()
		p.pos = mark
	}
	p.pos++
	test := p.namedExpression()
	if test == nil || p.expectOp(":") == nil {
		p.pos = mark
		return nil
	}
	body := p.block()
	if body == nil {
		p.pos = mark
		return nil
	}
	orelse := p.elseBlock()
	return &While{Pos: p.span(start), Test: test, Body: body, Orelse: orelse}
}

func (p *parser) forStmt() Stmt {
	mark := p.pos
	start := p.peek()
	if p.invalid {
		p.invalidForStmt()
		p.pos = mark
	}
	async := p.expectKw("async") != nil
	if p.expectKw("for") == nil {
		p.pos = mark
		return nil
	}
	target := p.starTargets()
	if target == nil || p.expectKw("in") == nil {
		p.pos = mark
		if p.invalid {
			p.invalidForTarget()
			p.pos = mark
		}
		return nil
	}
	// cut
	iter := p.starExpressions()
	if iter == nil || p.expectOp(":") == nil {
		p.pos = mark
		return nil
	}
	body := p.block()
	if body == nil {
		p.pos = mark
		return nil
	}
	orelse := p.elseBlock()
	if async {
		return &AsyncFor{Pos: p.span(start), Target: target, Iter: iter, Body: body, Orelse: orelse}
	}
	return &For{Pos: p.span(start), Target: target, Iter: iter, Body: body, Orelse: orelse}
}

func (p *parser) withStmt() Stmt {
	mark := p.pos
	start := p.peek()
	if p.invalid {
		p.invalidWithStmtIndent()
		p.pos = mark
	}
	async := p.expectKw("async") != nil
	if p.expectKw("with") == nil {
		p.pos = mark
		return nil
	}
	var items []*WithItem
	// 'with' '(' ','.with_item+ ','? ')' ':' block
	if p.atOp("(") {
		save := p.pos
		p.pos++
		items = p.withItems()
		if items != nil {
			p.expectOp(",")
			if p.expectOp(")") == nil || !p.atOp(":") {
				items = nil
			}
		}
		if items == nil {
			p.pos = save
		}
	}
	if items == nil {
		items = p.withItems()
	}
	if items == nil || p.expectOp(":") == nil {
		p.pos = mark
		if p.invalid {
			p.invalidWithStmt()
			p.pos = mark
		}
		return nil
	}
	body := p.block()
	if body == nil {
		p.pos = mark
		return nil
	}
	if async {
		return &AsyncWith{Pos: p.span(start), Items: items, Body: body}
	}
	return &With{Pos: p.span(start), Items: items, Body: body}
}

func (p *parser) withItems() []*WithItem {
	var items []*WithItem
	for {
		it := p.withItem()
		if it == nil {
			return items
		}
		items = append(items, it)
		if !p.atOp(",") {
			return items
		}
		save := p.pos
		p.pos++
		if p.atOp(")") {
			p.pos = save
			return items
		}
	}
}

func (p *parser) withItem() *WithItem {
	mark := p.pos
	e := p.expression()
	if e == nil {
		return nil
	}
	if p.atKw("as") {
		p.pos++
		if t := p.starTarget(); t != nil && (p.atOp(",") || p.atOp(")") || p.atOp(":")) {
			return &WithItem{ContextExpr: e, OptionalVars: t}
		}
		p.pos = mark
		if p.invalid {
			p.invalidWithItem()
			p.pos = mark
		}
		e = p.expression()
	}
	return &WithItem{ContextExpr: e}
}

func (p *parser) tryStmt() Stmt {
	mark := p.pos
	start := p.peek()
	if p.invalid {
		p.invalidTryStmt()
		p.pos = mark
	}
	p.pos++ // 'try'
	p.forced(":")
	body := p.block()
	if body == nil {
		p.pos = mark
		return nil
	}
	if p.atKw("finally") {
		if fin := p.finallyBlock(); fin != nil {
			return &Try{Pos: p.span(start), Body: body, Finalbody: fin}
		}
		p.pos = mark
		return nil
	}
	star := p.atKw("except") && p.peekAt(1).Kind == OP && p.peekAt(1).Str == "*"
	var handlers []*ExceptHandler
	for p.atKw("except") {
		h := p.exceptBlock(star)
		if h == nil {
			break
		}
		handlers = append(handlers, h)
	}
	if len(handlers) == 0 {
		p.pos = mark
		return nil
	}
	orelse := p.elseBlock()
	var fin []Stmt
	if p.atKw("finally") {
		fin = p.finallyBlock()
	}
	if star {
		return &TryStar{Pos: p.span(start), Body: body, Handlers: handlers, Orelse: orelse, Finalbody: fin}
	}
	return &Try{Pos: p.span(start), Body: body, Handlers: handlers, Orelse: orelse, Finalbody: fin}
}

func (p *parser) exceptBlock(star bool) *ExceptHandler {
	mark := p.pos
	start := p.peek()
	if p.invalid {
		p.invalidExceptStmtIndent(star)
		p.pos = mark
	}
	p.pos++ // 'except'
	if star {
		if p.expectOp("*") == nil {
			p.pos = mark
			return nil
		}
	}
	var typ Expr
	name := ""
	if !p.atOp(":") || star {
		typ = p.expression()
		if typ == nil {
			p.pos = mark
			if p.invalid {
				p.invalidExceptStmt()
				p.pos = mark
			}
			return nil
		}
		if p.atKw("as") {
			save := p.pos
			p.pos++
			if n := p.name(); n != nil {
				name = n.Id
			} else {
				p.pos = save
			}
		}
	}
	if p.expectOp(":") == nil {
		p.pos = mark
		if p.invalid {
			p.invalidExceptStmt()
			p.pos = mark
		}
		return nil
	}
	body := p.block()
	if body == nil {
		p.pos = mark
		return nil
	}
	return &ExceptHandler{Pos: p.span(start), Type: typ, Name: name, Body: body}
}

func (p *parser) finallyBlock() []Stmt {
	mark := p.pos
	if p.invalid {
		p.invalidFinallyStmt()
		p.pos = mark
	}
	p.pos++ // 'finally'
	p.forced(":")
	body := p.block()
	if body == nil {
		p.pos = mark
	}
	return body
}

// identifier is _PyPegen_new_identifier: non-ASCII names are NFKC-normalised.
func identifier(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return norm.NFKC.String(s)
		}
	}
	return s
}
