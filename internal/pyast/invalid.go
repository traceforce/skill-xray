package pyast

import "fmt"

// The invalid_* rules of python.gram: they run only in the second parser pass and either
// raise CPython's specific message or match nothing. Each restores nothing itself; callers
// reset the mark.

type targetKind int

const (
	kindStar targetKind = iota
	kindDel
	kindFor
)

// exprName is _PyPegen_get_expr_name.
func exprName(e Expr) string {
	switch n := e.(type) {
	case *Attribute:
		return "attribute"
	case *Subscript:
		return "subscript"
	case *Starred:
		return "starred"
	case *Name:
		return "name"
	case *List:
		return "list"
	case *Tuple:
		return "tuple"
	case *Lambda:
		return "lambda"
	case *Call:
		return "function call"
	case *BoolOp, *BinOp, *UnaryOp:
		return "expression"
	case *GeneratorExp:
		return "generator expression"
	case *Yield, *YieldFrom:
		return "yield expression"
	case *Await:
		return "await expression"
	case *ListComp:
		return "list comprehension"
	case *SetComp:
		return "set comprehension"
	case *DictComp:
		return "dict comprehension"
	case *Dict:
		return "dict literal"
	case *Set:
		return "set display"
	case *JoinedStr, *FormattedValue:
		return "f-string expression"
	case *Constant:
		switch v := n.Value.(type) {
		case nil:
			return "None"
		case bool:
			if v {
				return "True"
			}
			return "False"
		case EllipsisValue:
			return "ellipsis"
		}
		return "literal"
	case *Compare:
		return "comparison"
	case *IfExp:
		return "conditional expression"
	case *NamedExpr:
		return "named expression"
	}
	return "expression"
}

// invalidTarget is _PyPegen_get_invalid_target.
func invalidTarget(e Expr, kind targetKind) Expr {
	switch n := e.(type) {
	case nil:
		return nil
	case *List:
		for _, x := range n.Elts {
			if c := invalidTarget(x, kind); c != nil {
				return c
			}
		}
		return nil
	case *Tuple:
		for _, x := range n.Elts {
			if c := invalidTarget(x, kind); c != nil {
				return c
			}
		}
		return nil
	case *Starred:
		if kind == kindDel {
			return e
		}
		return invalidTarget(n.Value, kind)
	case *Compare:
		if kind == kindFor {
			if _, in := n.Ops[0].(*In); in {
				return invalidTarget(n.Left, kind)
			}
			return nil
		}
		return e
	case *Name, *Subscript, *Attribute:
		return nil
	}
	return e
}

// raiseInvalidTarget is RAISE_SYNTAX_ERROR_INVALID_TARGET: a raise when the expression
// holds an invalid target, otherwise the alternative merely fails.
func (p *parser) raiseInvalidTarget(e Expr, kind targetKind) {
	if t := invalidTarget(e, kind); t != nil {
		verb := "assign to"
		if kind == kindDel {
			verb = "delete"
		}
		p.raiseAt(t, fmt.Sprintf("cannot %s %s", verb, exprName(t)))
	}
}

func (p *parser) indentationError(kw *Token, what string) {
	panic(bail{p.errorAtToken("IndentationError", &p.toks[p.fill-1], fmt.Sprintf("expected an indented block after %s on line %d", what, kw.Lineno))})
}

// colonNewlineNoIndent matches ':' NEWLINE !INDENT after a statement header.
func (p *parser) colonNewlineNoIndent() bool {
	return p.expectOp(":") != nil && p.atKind(NEWLINE) && p.peekAt(1).Kind != INDENT
}

func (p *parser) invalidAssignment() {
	mark := p.pos
	// invalid_ann_assign_target ':' expression
	if a := p.invalidAnnAssignTarget(); a != nil && p.expectOp(":") != nil && p.expression() != nil {
		p.raiseAt(a, fmt.Sprintf("only single target (not %s) can be annotated", exprName(a)))
	}
	p.pos = mark
	// star_named_expression ',' star_named_expressions* ':' expression
	if a := p.starNamedExpression(); a != nil && p.expectOp(",") != nil {
		p.starNamedExpressions()
		if p.expectOp(":") != nil && p.expression() != nil {
			p.raiseAt(a, "only single target (not tuple) can be annotated")
		}
	}
	p.pos = mark
	// expression ':' expression
	if a := p.expression(); a != nil && p.expectOp(":") != nil && p.expression() != nil {
		p.raiseAt(a, "illegal target for annotation")
	}
	p.pos = mark
	// (star_targets '=')* star_expressions '=' ; (star_targets '=')* yield_expr '='
	for {
		save := p.pos
		if t := p.starTargets(); t == nil || p.expectOp("=") == nil {
			p.pos = save
			break
		}
	}
	after := p.pos
	if a := p.starExpressions(); a != nil && p.atOp("=") {
		p.raiseInvalidTarget(a, kindStar)
	}
	p.pos = after
	if a := p.yieldExpr(); a != nil && p.atOp("=") {
		p.raiseAt(a, "assignment to yield expression not possible")
	}
	p.pos = mark
	// star_expressions augassign annotated_rhs
	if a := p.starExpressions(); a != nil && p.augassign() != nil && p.annotatedRhs() != nil {
		p.raiseAt(a, fmt.Sprintf("'%s' is an illegal expression for augmented assignment", exprName(a)))
	}
	p.pos = mark
}

// invalid_ann_assign_target: list | tuple | '(' invalid_ann_assign_target ')'
func (p *parser) invalidAnnAssignTarget() Expr {
	mark := p.pos
	if p.atOp("[") {
		return p.list()
	}
	if p.atOp("(") {
		if t := p.tuple(); t != nil {
			return t
		}
		p.pos = mark + 1
		if inner := p.invalidAnnAssignTarget(); inner != nil && p.expectOp(")") != nil {
			return inner
		}
		p.pos = mark
	}
	return nil
}

func isLegacyStmt(e Expr) bool {
	n, ok := e.(*Name)
	return ok && (n.Id == "print" || n.Id == "exec")
}

func (p *parser) invalidExpression() {
	mark := p.pos
	t0 := p.peek()
	nameString := p.isName(t0) && p.peekAt(1).Kind == STRING
	soft := t0.Kind == NAME && softKeywords[t0.Str]
	if !nameString && !soft {
		if a := p.disjunction(); a != nil {
			if b := p.expressionWithoutInvalid(); b != nil {
				if !isLegacyStmt(a) && p.toks[p.pos-1].Level != 0 {
					p.raiseAt(a, "invalid syntax. Perhaps you forgot a comma?")
				}
			}
		}
	}
	p.pos = mark
	if a := p.disjunction(); a != nil && p.expectKw("if") != nil {
		if p.disjunction() != nil && !p.atKw("else") && !p.atOp(":") {
			p.raiseAt(a, "expected 'else' after 'if' expression")
		}
	}
	p.pos = mark
	if a := p.expectKw("lambda"); a != nil {
		p.lambdaParams()
		if p.atOp(":") && p.peekAt(1).Kind == FSTRING_MIDDLE {
			p.raiseAtTok(a, "f-string: lambda expressions are not allowed without parentheses")
		}
	}
	p.pos = mark
}

func (p *parser) invalidLegacyExpression() {
	mark := p.pos
	if a := p.name(); a != nil && !p.atOp("(") {
		if p.starExpressions() != nil && isLegacyStmt(a) {
			p.raiseAt(a, fmt.Sprintf("Missing parentheses in call to '%s'. Did you mean %s(...)?", a.Id, a.Id))
		}
	}
	p.pos = mark
}

func (p *parser) invalidNamedExpression() {
	mark := p.pos
	if a := p.expression(); a != nil && p.expectOp(":=") != nil && p.expression() != nil {
		p.raiseAt(a, fmt.Sprintf("cannot use assignment expressions with %s", exprName(a)))
	}
	p.pos = mark
	if a := p.name(); a != nil && p.expectOp("=") != nil {
		if p.bitwiseOr() != nil && !p.atOp("=") && !p.atOp(":=") {
			p.raiseAt(a, "invalid syntax. Maybe you meant '==' or ':=' instead of '='?")
		}
	}
	p.pos = mark
	// !(list|tuple|genexp|'True'|'None'|'False') bitwise_or '=' bitwise_or !('='|':=')
	excluded := false
	switch t := p.peek(); {
	case t.Kind == NAME && (t.Str == "True" || t.Str == "None" || t.Str == "False"):
		excluded = true
	case t.Kind == OP && t.Str == "[":
		excluded = p.list() != nil
	case t.Kind == OP && t.Str == "(":
		excluded = p.tuple() != nil
		if !excluded {
			p.pos = mark
			excluded = p.genexp() != nil
		}
	}
	p.pos = mark
	if !excluded {
		if a := p.bitwiseOr(); a != nil && p.expectOp("=") != nil {
			if p.bitwiseOr() != nil && !p.atOp("=") && !p.atOp(":=") {
				p.raiseAt(a, fmt.Sprintf("cannot assign to %s here. Maybe you meant '==' instead of '='?", exprName(a)))
			}
		}
	}
	p.pos = mark
}

func (p *parser) invalidComprehension() {
	mark := p.pos
	open := p.advance() // '[' | '(' | '{'
	if a := p.starredExpression(); a != nil && p.forIfClauses() != nil {
		p.raiseAt(a, "iterable unpacking cannot be used in comprehension")
	}
	p.pos = mark + 1
	if open.Str == "[" || open.Str == "{" {
		if a := p.starNamedExpression(); a != nil {
			if comma := p.expectOp(","); comma != nil {
				save := p.pos
				if b := p.starNamedExpressions(); b != nil && p.forIfClauses() != nil {
					p.raiseAt(a, "did you forget parentheses around the comprehension target?")
				}
				p.pos = save
				if p.forIfClauses() != nil {
					p.raiseAt(a, "did you forget parentheses around the comprehension target?")
				}
			}
		}
	}
	p.pos = mark
}

func (p *parser) invalidDictComprehension() {
	mark := p.pos
	p.pos++ // '{'
	if a := p.expectOp("**"); a != nil && p.bitwiseOr() != nil && p.forIfClauses() != nil && p.atOp("}") {
		p.raiseAtTok(a, "dict unpacking cannot be used in dict comprehension")
	}
	p.pos = mark
}

// slashNoDefault / slashWithDefault as used by the invalid_parameters rules.
func (p *parser) slashNoDefault(lambda bool) bool {
	mark := p.pos
	n := 0
	for p.paramNoDefault(lambda, false) != nil {
		n++
	}
	if n > 0 && p.expectOp("/") != nil && p.paramEnd(lambda) {
		return true
	}
	p.pos = mark
	return false
}

func (p *parser) slashWithDefault(lambda bool) bool {
	mark := p.pos
	for p.paramNoDefault(lambda, false) != nil {
	}
	n := 0
	for a, _ := p.paramWithDefault(lambda); a != nil; a, _ = p.paramWithDefault(lambda) {
		n++
	}
	if n > 0 && p.expectOp("/") != nil && p.paramEnd(lambda) {
		return true
	}
	p.pos = mark
	return false
}

func (p *parser) invalidParameters(lambda bool) {
	mark := p.pos
	// "/" ','
	if a := p.expectOp("/"); a != nil && p.atOp(",") {
		p.raiseAtTok(a, "at least one argument must precede /")
	}
	p.pos = mark
	// (slash_no_default | slash_with_default) param_maybe_default* '/'
	if p.slashNoDefault(lambda) || p.slashWithDefault(lambda) {
		p.skipParamMaybeDefaults(lambda)
		if a := p.expectOp("/"); a != nil {
			p.raiseAtTok(a, "/ may appear only once")
		}
	}
	p.pos = mark
	// slash_no_default? param_no_default* invalid_parameters_helper param_no_default
	p.slashNoDefault(lambda)
	for p.paramNoDefault(lambda, false) != nil {
	}
	helper := p.slashWithDefault(lambda)
	if !helper {
		for a, _ := p.paramWithDefault(lambda); a != nil; a, _ = p.paramWithDefault(lambda) {
			helper = true
		}
	}
	if helper {
		if a := p.paramNoDefault(lambda, false); a != nil {
			p.raiseAt(a, "parameter without a default follows parameter with a default")
		}
	}
	p.pos = mark
	// param_no_default* '(' param_no_default+ ','? ')'
	for p.paramNoDefault(lambda, false) != nil {
	}
	if a := p.expectOp("("); a != nil {
		n := 0
		if lambda {
			for p.name() != nil {
				n++
				if p.expectOp(",") == nil {
					break
				}
			}
		} else {
			for p.paramNoDefault(lambda, false) != nil {
				n++
			}
			p.expectOp(",")
		}
		if n > 0 && p.atOp(")") {
			if lambda {
				p.raiseAtTok(a, "Lambda expression parameters cannot be parenthesized")
			}
			p.raiseAtTok(a, "Function parameters cannot be parenthesized")
		}
	}
	p.pos = mark
	// (slash_no_default | slash_with_default)? param_maybe_default* '*' (',' | param_no_default) param_maybe_default* '/'
	if !p.slashNoDefault(lambda) {
		p.slashWithDefault(lambda)
	}
	p.skipParamMaybeDefaults(lambda)
	if p.expectOp("*") != nil && (p.expectOp(",") != nil || p.paramNoDefault(lambda, false) != nil) {
		p.skipParamMaybeDefaults(lambda)
		if a := p.expectOp("/"); a != nil {
			p.raiseAtTok(a, "/ must be ahead of *")
		}
	}
	p.pos = mark
	// param_maybe_default+ '/' '*'
	if p.skipParamMaybeDefaults(lambda) > 0 && p.expectOp("/") != nil {
		if a := p.expectOp("*"); a != nil {
			p.raiseAtTok(a, "expected comma between / and *")
		}
	}
	p.pos = mark
}

// skipParamMaybeDefaults consumes param_maybe_default* and returns how many it matched.
func (p *parser) skipParamMaybeDefaults(lambda bool) (n int) {
	for _, _, ok := p.paramMaybeDefault(lambda); ok; _, _, ok = p.paramMaybeDefault(lambda) {
		n++
	}
	return n
}

func (p *parser) invalidDefault() {
	if a := p.peek(); a.Kind == OP && a.Str == "=" {
		if n := p.peekAt(1); n.Kind == OP && (n.Str == ")" || n.Str == ",") {
			p.raiseAtTok(a, "expected default value expression")
		}
	}
}

func (p *parser) invalidStarEtc(lambda bool) {
	mark := p.pos
	close := closer(lambda)
	if a := p.expectOp("*"); a != nil {
		if p.atOp(close) {
			p.raiseAtTok(a, "named arguments must follow bare *")
		}
		if p.expectOp(",") != nil && (p.atOp(close) || p.atOp("**")) {
			p.raiseAtTok(a, "named arguments must follow bare *")
		}
	}
	p.pos = mark
	if p.expectOp("*") != nil && p.param(lambda, false) != nil {
		if a := p.expectOp("="); a != nil {
			p.raiseAtTok(a, "var-positional argument cannot have default value")
		}
	}
	p.pos = mark
	if p.expectOp("*") != nil && (p.paramNoDefault(lambda, false) != nil || p.expectOp(",") != nil) {
		p.skipParamMaybeDefaults(lambda)
		if a := p.expectOp("*"); a != nil && (p.paramNoDefault(lambda, false) != nil || p.atOp(",")) {
			p.raiseAtTok(a, "* argument may appear only once")
		}
	}
	p.pos = mark
}

func (p *parser) invalidKwds(lambda bool) {
	mark := p.pos
	if p.expectOp("**") != nil && p.param(lambda, false) != nil {
		if a := p.expectOp("="); a != nil {
			p.raiseAtTok(a, "var-keyword argument cannot have default value")
		}
		if p.expectOp(",") != nil {
			if a := p.param(lambda, false); a != nil {
				p.raiseAt(a, "arguments cannot follow var-keyword argument")
			}
			if t := p.peek(); t.Kind == OP && (t.Str == "*" || t.Str == "**" || t.Str == "/") {
				p.raiseAtTok(t, "arguments cannot follow var-keyword argument")
			}
		}
	}
	p.pos = mark
}

func (p *parser) invalidWithItem() {
	mark := p.pos
	if p.expression() != nil && p.expectKw("as") != nil {
		if a := p.expression(); a != nil && (p.atOp(",") || p.atOp(")") || p.atOp(":")) {
			p.raiseInvalidTarget(a, kindStar)
		}
	}
	p.pos = mark
}

func (p *parser) invalidForTarget() {
	mark := p.pos
	p.expectKw("async")
	if p.expectKw("for") != nil {
		if a := p.starExpressions(); a != nil {
			p.raiseInvalidTarget(a, kindFor)
		}
	}
	p.pos = mark
}

func (p *parser) invalidGroup() {
	mark := p.pos
	p.pos++ // '('
	if a := p.starredExpression(); a != nil && p.atOp(")") {
		p.raiseAt(a, "cannot use starred expression here")
	}
	p.pos = mark + 1
	if a := p.expectOp("**"); a != nil && p.expression() != nil && p.atOp(")") {
		p.raiseAtTok(a, "cannot use double starred expression here")
	}
	p.pos = mark
}

func (p *parser) invalidImport() {
	mark := p.pos
	if a := p.expectKw("import"); a != nil {
		if p.atKind(NEWLINE) {
			p.raiseAtTok(p.peek(), "Expected one or more names after 'import'")
		}
		for p.dottedName() != "" {
			if p.expectOp(",") == nil {
				break
			}
		}
		if p.expectKw("from") != nil && p.dottedName() != "" {
			p.raiseAtTok(a, "Did you mean to use 'from ... import ...' instead?")
		}
	}
	p.pos = mark
}

func (p *parser) invalidImportFromTargets() {
	mark := p.pos
	if p.importFromAsNames() != nil && p.expectOp(",") != nil && p.atKind(NEWLINE) {
		p.raiseLast("SyntaxError", "trailing comma not allowed without surrounding parentheses")
	}
	p.pos = mark
	if p.atKind(NEWLINE) {
		p.raiseAtTok(p.peek(), "Expected one or more names after 'import'")
	}
	p.pos = mark
}

// withHeader matches ','.(expression ['as' star_target])+ or the parenthesised form and
// returns true when it consumed something.
func (p *parser) withHeader() bool {
	mark := p.pos
	if p.expectOp("(") != nil {
		n := 0
		for {
			if p.expressions() == nil {
				break
			}
			n++
			if p.atKw("as") {
				p.pos++
				if p.starTarget() == nil {
					n = 0
					break
				}
			}
			if p.expectOp(",") == nil {
				break
			}
		}
		if n > 0 && p.expectOp(")") != nil {
			return true
		}
		p.pos = mark
	}
	n := 0
	for {
		if p.expression() == nil {
			break
		}
		n++
		if p.atKw("as") {
			p.pos++
			if p.starTarget() == nil {
				p.pos = mark
				return false
			}
		}
		if p.expectOp(",") == nil {
			break
		}
	}
	if n == 0 {
		p.pos = mark
	}
	return n > 0
}

func (p *parser) invalidWithStmt() {
	mark := p.pos
	p.expectKw("async")
	if p.expectKw("with") != nil && p.withHeader() && p.atKind(NEWLINE) {
		p.raiseLast("SyntaxError", "expected ':'")
	}
	p.pos = mark
}

func (p *parser) invalidWithStmtIndent() {
	mark := p.pos
	p.expectKw("async")
	if a := p.expectKw("with"); a != nil && p.withHeader() && p.colonNewlineNoIndent() {
		p.indentationError(a, "'with' statement")
	}
	p.pos = mark
}

func (p *parser) invalidTryStmt() {
	mark := p.pos
	a := p.advance() // 'try'
	if p.colonNewlineNoIndent() {
		p.indentationError(a, "'try' statement")
	}
	p.pos = mark + 1
	if p.expectOp(":") != nil && p.block() != nil && !p.atKw("except") && !p.atKw("finally") {
		p.raiseLast("SyntaxError", "expected 'except' or 'finally' block")
	}
	p.pos = mark + 1
	if p.expectOp(":") != nil && p.block() != nil {
		save := p.pos
		// except_block+ then 'except' '*'
		n := 0
		for p.atKw("except") && p.peekAt(1).Str != "*" {
			if p.exceptBlock(false) == nil {
				break
			}
			n++
		}
		if n > 0 {
			if e := p.expectKw("except"); e != nil {
				if s := p.expectOp("*"); s != nil && p.expression() != nil {
					if p.expectKw("as") != nil {
						p.name()
					}
					if p.atOp(":") {
						p.raiseAtTok(e, "cannot have both 'except' and 'except*' on the same 'try'")
					}
				}
			}
		}
		p.pos = save
		n = 0
		for p.atKw("except") && p.peekAt(1).Str == "*" {
			if p.exceptBlock(true) == nil {
				break
			}
			n++
		}
		if n > 0 {
			if e := p.expectKw("except"); e != nil {
				if p.expression() != nil && p.expectKw("as") != nil {
					p.name()
				}
				if p.atOp(":") {
					p.raiseAtTok(e, "cannot have both 'except' and 'except*' on the same 'try'")
				}
			}
		}
	}
	p.pos = mark
}

func (p *parser) invalidExceptStmt() {
	mark := p.pos
	p.pos++ // 'except'
	star := p.expectOp("*") != nil
	if e := p.expression(); e != nil {
		if p.expectOp(",") != nil && p.expressions() != nil {
			if p.expectKw("as") != nil {
				p.name()
			}
			if p.atOp(":") {
				p.raiseAt(e, "multiple exception types must be parenthesized")
			}
		}
	}
	p.pos = mark + 1
	if star {
		p.pos++
	}
	if p.expression() != nil {
		if p.expectKw("as") != nil {
			p.name()
		}
		if p.atKind(NEWLINE) {
			p.raiseLast("SyntaxError", "expected ':'")
		}
	}
	p.pos = mark + 1
	if p.atKind(NEWLINE) {
		p.raiseLast("SyntaxError", "expected ':'")
	}
	if p.expectOp("*") != nil && (p.atKind(NEWLINE) || p.atOp(":")) {
		p.raiseLast("SyntaxError", "expected one or more exception types")
	}
	p.pos = mark
}

func (p *parser) invalidFinallyStmt() {
	mark := p.pos
	a := p.advance()
	if p.colonNewlineNoIndent() {
		p.indentationError(a, "'finally' statement")
	}
	p.pos = mark
}

func (p *parser) invalidExceptStmtIndent(star bool) {
	mark := p.pos
	a := p.advance() // 'except'
	if star {
		if p.expectOp("*") != nil && p.expression() != nil {
			if p.expectKw("as") != nil {
				p.name()
			}
			if p.colonNewlineNoIndent() {
				p.indentationError(a, "'except*' statement")
			}
		}
		p.pos = mark
		return
	}
	if p.expression() != nil {
		if p.expectKw("as") != nil {
			p.name()
		}
		if p.colonNewlineNoIndent() {
			p.indentationError(a, "'except' statement")
		}
	}
	p.pos = mark + 1
	if p.colonNewlineNoIndent() {
		p.indentationError(a, "'except' statement")
	}
	p.pos = mark
}

func (p *parser) invalidMatchStmt() {
	mark := p.pos
	a := p.advance() // "match"
	if p.subjectExpr() != nil {
		if p.atKind(NEWLINE) {
			p.raiseLast("SyntaxError", "expected ':'")
		}
		if p.colonNewlineNoIndent() {
			p.indentationError(a, "'match' statement")
		}
	}
	p.pos = mark
}

func (p *parser) invalidCaseBlock() {
	mark := p.pos
	a := p.advance() // "case"
	if p.patterns() != nil {
		if p.expectKw("if") != nil {
			p.namedExpression()
		}
		if p.atKind(NEWLINE) {
			p.raiseLast("SyntaxError", "expected ':'")
		}
		if p.colonNewlineNoIndent() {
			p.indentationError(a, "'case' statement")
		}
	}
	p.pos = mark
}

func (p *parser) invalidAsPattern() {
	mark := p.pos
	if p.orPattern() != nil && p.expectKw("as") != nil {
		if a := p.peek(); a.Kind == NAME && a.Str == "_" {
			p.raiseAtTok(a, "cannot use '_' as a target")
		}
		if !p.isName(p.peek()) {
			if a := p.expression(); a != nil {
				p.raiseAt(a, "invalid pattern target")
			}
		}
	}
	p.pos = mark
}

func (p *parser) invalidClassPattern() {
	mark := p.pos
	if p.nameOrAttr() != nil && p.expectOp("(") != nil {
		// [positional_patterns ','] keyword_patterns ',' positional_patterns
		save := p.pos
		if p.pattern() != nil {
			for p.expectOp(",") != nil && p.pattern() != nil {
			}
		}
		if p.pos == save || !p.atOp(",") {
			p.pos = save
		}
		kw := 0
		for {
			s := p.pos
			if p.name() != nil && p.expectOp("=") != nil && p.pattern() != nil {
				kw++
				if p.expectOp(",") == nil {
					break
				}
				continue
			}
			p.pos = s
			break
		}
		if kw > 0 {
			if first := p.pattern(); first != nil {
				p.raiseAt(first, "positional patterns follow keyword patterns")
			}
		}
	}
	p.pos = mark
}

func (p *parser) invalidIfStmt(kw string) {
	mark := p.pos
	a := p.advance()
	if p.namedExpression() != nil {
		if p.atKind(NEWLINE) {
			p.raiseLast("SyntaxError", "expected ':'")
		}
		if p.colonNewlineNoIndent() {
			p.indentationError(a, "'"+kw+"' statement")
		}
	}
	p.pos = mark
}

func (p *parser) invalidElseStmt() {
	mark := p.pos
	a := p.advance()
	if p.colonNewlineNoIndent() {
		p.indentationError(a, "'else' statement")
	}
	p.pos = mark
}

func (p *parser) invalidWhileStmt() {
	mark := p.pos
	a := p.advance()
	if p.namedExpression() != nil {
		if p.atKind(NEWLINE) {
			p.raiseLast("SyntaxError", "expected ':'")
		}
		if p.colonNewlineNoIndent() {
			p.indentationError(a, "'while' statement")
		}
	}
	p.pos = mark
}

func (p *parser) invalidForStmt() {
	mark := p.pos
	p.expectKw("async")
	if a := p.expectKw("for"); a != nil {
		if p.starTargets() != nil && p.expectKw("in") != nil && p.starExpressions() != nil {
			if p.atKind(NEWLINE) {
				p.raiseLast("SyntaxError", "expected ':'")
			}
			if p.colonNewlineNoIndent() {
				p.indentationError(a, "'for' statement")
			}
		}
	}
	p.pos = mark
}

func (p *parser) invalidDefRaw() {
	mark := p.pos
	p.expectKw("async")
	a := p.expectKw("def")
	if a == nil {
		p.pos = mark
		return
	}
	if p.name() != nil {
		p.optTypeParams()
		save := p.pos
		if p.expectOp("(") != nil {
			p.params()
			if p.expectOp(")") != nil {
				if p.expectOp("->") != nil {
					p.expression()
				}
				if p.colonNewlineNoIndent() {
					p.indentationError(a, "function definition")
				}
			}
		}
		// ['async'] 'def' NAME [type_params] &&'(' [params] ')' ['->' expression] &&':' [func_type_comment] block
		p.pos = save
		p.forced("(")
		p.params()
		if p.expectOp(")") != nil {
			if p.expectOp("->") != nil {
				p.expression()
			}
			p.forced(":")
		}
	}
	p.pos = mark
}

func (p *parser) invalidClassDefRaw() {
	mark := p.pos
	a := p.advance() // 'class'
	if p.name() != nil {
		p.optTypeParams()
		if p.expectOp("(") != nil {
			p.arguments()
			if p.expectOp(")") == nil {
				p.pos = mark
				return
			}
		}
		if p.atKind(NEWLINE) {
			p.raiseLast("SyntaxError", "expected ':'")
		}
		if p.colonNewlineNoIndent() {
			p.indentationError(a, "class definition")
		}
	}
	p.pos = mark
}

// invalidDoubleStarredKvpairs runs after '{' has been consumed.
func (p *parser) invalidDoubleStarredKvpairs() {
	mark := p.pos
	// ','.double_starred_kvpair+ ',' invalid_kvpair
	n := 0
	for {
		save := p.pos
		if _, _, ok := p.doubleStarredKvpair(); !ok {
			p.pos = save
			break
		}
		n++
		if p.expectOp(",") == nil {
			break
		}
	}
	if n > 0 && p.toks[p.pos-1].Str == "," {
		p.invalidKvpair()
	}
	p.pos = mark
	if p.expression() != nil && p.expectOp(":") != nil {
		if a := p.expectOp("*"); a != nil && p.bitwiseOr() != nil {
			p.raiseAtTok(a, "cannot use a starred expression in a dictionary value")
		}
		if p.atOp("}") || p.atOp(",") {
			p.raiseAtTok(&p.toks[p.pos-1], "expression expected after dictionary key and ':'")
		}
	}
	p.pos = mark
}

func (p *parser) invalidKvpair() {
	mark := p.pos
	if a := p.expression(); a != nil {
		if !p.atOp(":") {
			q := posOf(a)
			p.raiseAtCol(q.Lineno, q.EndColOffset-1, "':' expected after dictionary key")
		}
		colon := p.advance()
		if s := p.expectOp("*"); s != nil && p.bitwiseOr() != nil {
			p.raiseAtTok(s, "cannot use a starred expression in a dictionary value")
		}
		p.pos = mark
		p.expression()
		p.pos++
		if p.atOp("}") || p.atOp(",") {
			p.raiseAtTok(colon, "expression expected after dictionary key and ':'")
		}
	}
	p.pos = mark
}

func (p *parser) invalidStarredExpressionUnpacking() {
	mark := p.pos
	if a := p.expectOp("*"); a != nil && p.expression() != nil && p.expectOp("=") != nil && p.expression() != nil {
		p.raiseAtTok(a, "cannot assign to iterable argument unpacking")
	}
	p.pos = mark
}

func (p *parser) invalidArguments() {
	mark := p.pos
	// ((positional+ ',' kwargs) | kwargs) ',' ','.(starred_expression !'=')+
	consumed := false
	if e := p.positionalArg(); e != nil {
		for p.atOp(",") {
			save := p.pos
			p.pos++
			if p.positionalArg() == nil {
				p.pos = save
				break
			}
		}
		if p.expectOp(",") != nil {
			if _, _, ok := p.kwargs(); ok {
				consumed = true
			}
		}
	}
	if !consumed {
		p.pos = mark
		if _, _, ok := p.kwargs(); ok {
			consumed = true
		}
	}
	if consumed {
		if a := p.expectOp(","); a != nil {
			if s := p.starredExpression(); s != nil && !p.atOp("=") {
				p.raiseAtTok(a, "iterable argument unpacking follows keyword argument unpacking")
			}
		}
	}
	p.pos = mark
	// expression for_if_clauses ',' [args | expression for_if_clauses]
	if a := p.expression(); a != nil {
		if p.forIfClauses() != nil && p.atOp(",") {
			p.raiseAt(a, "Generator expression must be parenthesized")
		}
	}
	p.pos = mark
	// NAME '=' expression for_if_clauses
	if a := p.name(); a != nil && p.expectOp("=") != nil && p.expression() != nil && p.forIfClauses() != nil {
		p.raiseAt(a, "invalid syntax. Maybe you meant '==' or ':=' instead of '='?")
	}
	p.pos = mark
	// (args ',')? NAME '=' &(',' | ')')
	if _, _, ok := p.args(); ok {
		if p.expectOp(",") == nil {
			p.pos = mark
		}
	} else {
		p.pos = mark
	}
	if a := p.name(); a != nil && p.expectOp("=") != nil && (p.atOp(",") || p.atOp(")")) {
		p.raiseAt(a, "expected argument value expression")
	}
	p.pos = mark
	// args for_if_clauses (_PyPegen_nonparen_genexp_in_call)
	if args, _, ok := p.args(); ok {
		if p.forIfClauses() != nil && len(args) > 1 {
			p.raiseAt(args[len(args)-1], "Generator expression must be parenthesized")
		}
	}
	p.pos = mark
	// args ',' expression for_if_clauses
	if _, _, ok := p.args(); ok && p.expectOp(",") != nil {
		if a := p.expression(); a != nil && p.forIfClauses() != nil {
			p.raiseAt(a, "Generator expression must be parenthesized")
		}
	}
	p.pos = mark
	// args ',' args
	if _, kws, ok := p.args(); ok && p.expectOp(",") != nil {
		if _, _, ok2 := p.args(); ok2 {
			msg := "positional argument follows keyword argument"
			for _, k := range kws {
				if k.Arg == "" {
					msg = "positional argument follows keyword argument unpacking"
				}
			}
			p.raiseLast("SyntaxError", msg)
		}
	}
	p.pos = mark
}

func (p *parser) invalidKwarg() {
	mark := p.pos
	if t := p.peek(); t.Kind == NAME && (t.Str == "True" || t.Str == "False" || t.Str == "None") {
		p.pos++
		if p.atOp("=") {
			p.raiseAtTok(t, "cannot assign to "+t.Str)
		}
	}
	p.pos = mark
	if a := p.name(); a != nil && p.expectOp("=") != nil && p.expression() != nil && p.forIfClauses() != nil {
		p.raiseAt(a, "invalid syntax. Maybe you meant '==' or ':=' instead of '='?")
	}
	p.pos = mark
	nameEq := p.isName(p.peek())
	if nameEq {
		n := p.peekAt(1)
		nameEq = n.Kind == OP && n.Str == "="
	}
	if !nameEq {
		if a := p.expression(); a != nil && p.atOp("=") {
			p.raiseAt(a, "expression cannot contain assignment, perhaps you meant \"==\"?")
		}
	}
	p.pos = mark
	if a := p.expectOp("**"); a != nil && p.expression() != nil && p.expectOp("=") != nil && p.expression() != nil {
		p.raiseAtTok(a, "cannot assign to keyword argument unpacking")
	}
	p.pos = mark
}

func (p *parser) invalidReplacementField() {
	mark := p.pos
	p.pos++ // '{'
	if t := p.peek(); t.Kind == OP {
		switch t.Str {
		case "=", "!", ":", "}":
			p.raiseAtTok(t, "f-string: valid expression required before '"+t.Str+"'")
		}
	}
	if p.annotatedRhs() == nil {
		p.raiseNext("f-string: expecting a valid expression after '{'")
	}
	if !(p.atOp("=") || p.atOp("!") || p.atOp(":") || p.atOp("}")) {
		p.raiseNext("f-string: expecting '=', or '!', or ':', or '}'")
	}
	if p.expectOp("=") != nil && !(p.atOp("!") || p.atOp(":") || p.atOp("}")) {
		p.raiseNext("f-string: expecting '!', or ':', or '}'")
	}
	if p.expectOp("!") != nil {
		if p.atOp(":") || p.atOp("}") {
			p.raiseNext("f-string: missing conversion character")
		}
		if !p.isName(p.peek()) {
			p.raiseNext("f-string: invalid conversion character")
		}
		p.pos++
	}
	if !(p.atOp(":") || p.atOp("}")) {
		p.raiseNext("f-string: expecting ':' or '}'")
	}
	if p.expectOp(":") != nil {
		for {
			if p.atKind(FSTRING_MIDDLE) {
				p.pos++
				continue
			}
			if p.atOp("{") {
				if p.fstringReplacementField() == nil {
					break
				}
				continue
			}
			break
		}
		if !p.atOp("}") {
			p.raiseNext("f-string: expecting '}', or format specs")
		}
	}
	if !p.atOp("}") {
		p.raiseNext("f-string: expecting '}'")
	}
	p.pos = mark
}

func (p *parser) invalidArithmetic() {
	mark := p.pos
	if p.sum() != nil {
		if t := p.peek(); t.Kind == OP && (t.Str == "+" || t.Str == "-" || t.Str == "*" || t.Str == "/" || t.Str == "%" || t.Str == "//" || t.Str == "@") {
			p.pos++
			if a := p.expectKw("not"); a != nil && p.inversion() != nil {
				p.raiseAtTok(a, "'not' after an operator must be parenthesized")
			}
		}
	}
	p.pos = mark
}

func (p *parser) invalidFactor() {
	mark := p.pos
	if t := p.peek(); t.Kind == OP && (t.Str == "+" || t.Str == "-" || t.Str == "~") {
		p.pos++
		if a := p.expectKw("not"); a != nil && p.factor() != nil {
			p.raiseAtTok(a, "'not' after an operator must be parenthesized")
		}
	}
	p.pos = mark
}
