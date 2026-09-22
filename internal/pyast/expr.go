package pyast

import (
	"strings"
)

// maxStack is pegen's MAXSTACK: rule nesting beyond it is "Parser stack overflowed".
const maxStack = 6000

func (p *parser) enter() {
	p.depth++
	if p.depth > maxStack {
		panic(bail{&SyntaxError{Kind: "MemoryError", Msg: "Parser stack overflowed - Python source too complex to parse"}})
	}
}

func (p *parser) leave() { p.depth-- }

// ---- expressions ----

// tupleOf parses `item (',' item)* [',']`: a lone item is returned as is, more become a Tuple.
// It is expressions, star_expressions and star_targets.
func (p *parser) tupleOf(item func() Expr, ctx ExprContext) Expr {
	start := p.peek()
	e := item()
	if e == nil {
		return nil
	}
	if !p.atOp(",") {
		return e
	}
	elts := []Expr{e}
	for p.atOp(",") {
		save := p.pos
		p.pos++
		x := item()
		if x == nil {
			p.pos = save + 1 // trailing comma consumed
			break
		}
		elts = append(elts, x)
	}
	return &Tuple{Pos: p.span(start), Elts: elts, Ctx: ctx}
}

// expressions: expression (',' expression)+ [','] | expression ',' | expression
func (p *parser) expressions() Expr { return p.tupleOf(p.expression, LoadCtx) }

// memoized is pegen's memo: one result per (rule, position), the cursor left where that parse
// ended, or reset when it failed. Rules that enter() do so in their body, so the stack depth
// pegen's MAXSTACK measures is unchanged.
func (p *parser) memoized(r rule, body func(*parser) Expr) Expr {
	key := memoKey{r, p.pos}
	if m, ok := p.memo[key]; ok {
		p.pos = m.end
		return m.node
	}
	start := p.pos
	e := body(p)
	if e == nil {
		p.pos = start
	}
	p.memo[key] = memoEntry{e, p.pos}
	return e
}

// expression (memo): invalid_expression | invalid_legacy_expression |
// disjunction 'if' disjunction 'else' expression | disjunction | lambdef
func (p *parser) expression() Expr {
	return p.memoized(rExpression, func(p *parser) Expr { p.enter(); defer p.leave(); return p.expressionRaw() })
}

func (p *parser) expressionRaw() Expr {
	mark := p.pos
	if p.invalid {
		p.invalidExpression()
		p.pos = mark
		p.invalidLegacyExpression()
		p.pos = mark
	}
	start := p.peek()
	if d := p.disjunction(); d != nil {
		if p.atKw("if") {
			save := p.pos
			p.pos++
			if test := p.disjunction(); test != nil && p.expectKw("else") != nil {
				if orelse := p.expression(); orelse != nil {
					return &IfExp{Pos: p.span(start), Test: test, Body: d, Orelse: orelse}
				}
			}
			p.pos = save
		}
		return d
	}
	p.pos = mark
	return p.lambdef()
}

// expressionWithoutInvalid is expression with the invalid_* rules disabled.
func (p *parser) expressionWithoutInvalid() Expr {
	saved := p.invalid
	p.invalid = false
	defer func() { p.invalid = saved }()
	mark := p.pos
	e := p.expressionRaw()
	if e == nil {
		p.pos = mark
	}
	return e
}

func (p *parser) yieldExpr() Expr {
	if !p.atKw("yield") {
		return nil
	}
	start := p.advance()
	if p.atKw("from") {
		save := p.pos
		p.pos++
		if e := p.expression(); e != nil {
			return &YieldFrom{Pos: p.span(start), Value: e}
		}
		p.pos = save
	}
	v := p.starExpressions()
	return &Yield{Pos: p.span(start), Value: v}
}

// star_expressions: star_expression (',' star_expression)+ [','] | star_expression ',' | star_expression
func (p *parser) starExpressions() Expr { return p.tupleOf(p.starExpression, LoadCtx) }

// starOr parses `'*' bitwise_or | next`: star_expression and star_named_expression.
func (p *parser) starOr(next func() Expr) Expr {
	if p.atOp("*") {
		start := p.advance()
		if e := p.bitwiseOr(); e != nil {
			return &Starred{Pos: p.span(start), Value: e, Ctx: LoadCtx}
		}
		p.pos--
		return nil
	}
	return next()
}

// star_expression (memo)
func (p *parser) starExpression() Expr {
	return p.memoized(rStarExpression, (*parser).starExpressionRaw)
}

func (p *parser) starExpressionRaw() Expr { return p.starOr(p.expression) }

// star_named_expressions: ','.star_named_expression+ [',']
func (p *parser) starNamedExpressions() []Expr {
	var out []Expr
	for {
		e := p.starNamedExpression()
		if e == nil {
			return out
		}
		out = append(out, e)
		if !p.atOp(",") {
			return out
		}
		p.pos++
	}
}

func (p *parser) starNamedExpression() Expr { return p.starOr(p.namedExpression) }

// assignment_expression: NAME ':=' ~ expression
func (p *parser) assignmentExpression() Expr {
	mark := p.pos
	start := p.peek()
	if n := p.name(); n != nil && p.expectOp(":=") != nil {
		if v := p.expression(); v != nil {
			n.Ctx = storeCtx
			return &NamedExpr{Pos: p.span(start), Target: n, Value: v}
		}
		p.pos = mark
		return nil
	}
	p.pos = mark
	return nil
}

// named_expression: assignment_expression | invalid_named_expression | expression !':='
func (p *parser) namedExpression() Expr {
	mark := p.pos
	if e := p.assignmentExpression(); e != nil {
		return e
	}
	if p.invalid {
		p.invalidNamedExpression()
		p.pos = mark
	}
	e := p.expression()
	if e != nil && p.atOp(":=") {
		p.pos = mark
		return nil
	}
	return e
}

// boolLevel parses `next (kw next)*` into one BoolOp: disjunction and conjunction.
func (p *parser) boolLevel(kw string, next func() Expr, op BoolOperator) Expr {
	p.enter()
	defer p.leave()
	start := p.peek()
	a := next()
	if a == nil {
		return nil
	}
	values := []Expr{a}
	for p.atKw(kw) {
		save := p.pos
		p.pos++
		c := next()
		if c == nil {
			p.pos = save
			break
		}
		values = append(values, c)
	}
	if len(values) == 1 {
		return a
	}
	return &BoolOp{Pos: p.span(start), Op: op, Values: values}
}

// disjunction (memo), conjunction (memo), inversion (memo)
func (p *parser) disjunction() Expr { return p.memoized(rDisjunction, (*parser).disjunctionRaw) }

func (p *parser) disjunctionRaw() Expr { return p.boolLevel("or", p.conjunction, &Or{}) }

func (p *parser) conjunction() Expr { return p.memoized(rConjunction, (*parser).conjunctionRaw) }

func (p *parser) conjunctionRaw() Expr { return p.boolLevel("and", p.inversion, &And{}) }

func (p *parser) inversion() Expr { return p.memoized(rInversion, (*parser).inversionRaw) }

func (p *parser) inversionRaw() Expr {
	p.enter()
	defer p.leave()
	if p.atKw("not") {
		start := p.advance()
		if e := p.inversion(); e != nil {
			return &UnaryOp{Pos: p.span(start), Op: &Not{}, Operand: e}
		}
		p.pos--
		return nil
	}
	return p.comparison()
}

// Operator singletons, shared across trees like CPython's.
var cmpOps = map[string]CmpOp{"==": &Eq{}, "!=": &NotEq{}, "<=": &LtE{}, "<": &Lt{}, ">=": &GtE{}, ">": &Gt{}}

func (p *parser) comparison() Expr {
	p.enter()
	defer p.leave()
	start := p.peek()
	left := p.bitwiseOr()
	if left == nil {
		return nil
	}
	var ops []CmpOp
	var comps []Expr
	for {
		save := p.pos
		var op CmpOp
		t := p.peek()
		switch {
		case t.Kind == OP && cmpOps[t.Str] != nil:
			op = cmpOps[t.Str]
			p.pos++
		case t.Kind == NAME && t.Str == "not":
			p.pos++
			if p.expectKw("in") == nil {
				p.pos = save
			} else {
				op = &NotIn{}
			}
		case t.Kind == NAME && t.Str == "in":
			p.pos++
			op = &In{}
		case t.Kind == NAME && t.Str == "is":
			p.pos++
			if p.expectKw("not") != nil {
				op = &IsNot{}
			} else {
				op = &Is{}
			}
		}
		if op == nil {
			break
		}
		right := p.bitwiseOr()
		if right == nil {
			p.pos = save
			break
		}
		ops = append(ops, op)
		comps = append(comps, right)
	}
	if len(ops) == 0 {
		return left
	}
	return &Compare{Pos: p.span(start), Left: left, Ops: ops, Comparators: comps}
}

// binaryLevel parses a left-associative level: next (op next)*.
func (p *parser) binaryLevel(next func() Expr, ops map[string]Operator) Expr {
	p.enter()
	defer p.leave()
	start := p.peek()
	left := next()
	if left == nil {
		return nil
	}
	for {
		t := p.peek()
		if t.Kind != OP || ops[t.Str] == nil {
			return left
		}
		save := p.pos
		p.pos++
		right := next()
		if right == nil {
			p.pos = save
			return left
		}
		left = &BinOp{Pos: p.span(start), Left: left, Op: ops[t.Str], Right: right}
	}
}

var (
	orOps    = map[string]Operator{"|": &BitOr{}}
	xorOps   = map[string]Operator{"^": &BitXor{}}
	andOps   = map[string]Operator{"&": &BitAnd{}}
	shiftOps = map[string]Operator{"<<": &LShift{}, ">>": &RShift{}}
	sumOps   = map[string]Operator{"+": &Add{}, "-": &Sub{}}
	termOps  = map[string]Operator{"*": &Mult{}, "/": &Div{}, "//": &FloorDiv{}, "%": &Mod{}, "@": &MatMult{}}
)

// The binary levels are left-recursive in the grammar, which pegen memoises.
func (p *parser) bitwiseOr() Expr     { return p.memoized(rBitwiseOr, (*parser).bitwiseOrRaw) }
func (p *parser) bitwiseOrRaw() Expr  { return p.binaryLevel(p.bitwiseXor, orOps) }
func (p *parser) bitwiseXor() Expr    { return p.memoized(rBitwiseXor, (*parser).bitwiseXorRaw) }
func (p *parser) bitwiseXorRaw() Expr { return p.binaryLevel(p.bitwiseAnd, xorOps) }
func (p *parser) bitwiseAnd() Expr    { return p.memoized(rBitwiseAnd, (*parser).bitwiseAndRaw) }
func (p *parser) bitwiseAndRaw() Expr { return p.binaryLevel(p.shiftExpr, andOps) }

func (p *parser) shiftExpr() Expr { return p.memoized(rShiftExpr, (*parser).shiftExprRaw) }

func (p *parser) shiftExprRaw() Expr {
	if p.invalid {
		mark := p.pos
		p.invalidArithmetic()
		p.pos = mark
	}
	return p.binaryLevel(p.sum, shiftOps)
}

func (p *parser) sum() Expr    { return p.memoized(rSum, (*parser).sumRaw) }
func (p *parser) sumRaw() Expr { return p.binaryLevel(p.term, sumOps) }

func (p *parser) term() Expr { return p.memoized(rTerm, (*parser).termRaw) }

func (p *parser) termRaw() Expr {
	if p.invalid {
		mark := p.pos
		p.invalidFactor()
		p.pos = mark
	}
	return p.binaryLevel(p.factor, termOps)
}

// factor (memo)
func (p *parser) factor() Expr { return p.memoized(rFactor, (*parser).factorRaw) }

func (p *parser) factorRaw() Expr {
	p.enter()
	defer p.leave()
	t := p.peek()
	if t.Kind == OP && (t.Str == "+" || t.Str == "-" || t.Str == "~") {
		p.pos++
		if e := p.factor(); e != nil {
			var op UnaryOperator
			switch t.Str {
			case "+":
				op = &UAdd{}
			case "-":
				op = &USub{}
			default:
				op = &Invert{}
			}
			return &UnaryOp{Pos: p.span(t), Op: op, Operand: e}
		}
		p.pos--
		return nil
	}
	return p.power()
}

func (p *parser) power() Expr {
	p.enter()
	defer p.leave()
	start := p.peek()
	a := p.awaitPrimary()
	if a == nil {
		return nil
	}
	if p.atOp("**") {
		save := p.pos
		p.pos++
		if b := p.factor(); b != nil {
			return &BinOp{Pos: p.span(start), Left: a, Op: &Pow{}, Right: b}
		}
		p.pos = save
	}
	return a
}

// await_primary (memo)
func (p *parser) awaitPrimary() Expr { return p.memoized(rAwaitPrimary, (*parser).awaitPrimaryRaw) }

func (p *parser) awaitPrimaryRaw() Expr {
	p.enter()
	defer p.leave()
	if p.atKw("await") {
		start := p.advance()
		if e := p.primary(); e != nil {
			return &Await{Pos: p.span(start), Value: e}
		}
		p.pos--
		return nil
	}
	return p.primary()
}

// primary: primary '.' NAME | primary genexp | primary '(' [arguments] ')' | primary '[' slices ']' | atom
// (left-recursive, memoised)
func (p *parser) primary() Expr { return p.memoized(rPrimary, (*parser).primaryRaw) }

func (p *parser) primaryRaw() Expr {
	p.enter()
	defer p.leave()
	start := p.peek()
	e := p.atom()
	if e == nil {
		return nil
	}
	for {
		save := p.pos
		switch {
		case p.atOp("."):
			p.pos++
			if n := p.name(); n != nil {
				e = &Attribute{Pos: p.span(start), Value: e, Attr: n.Id, Ctx: LoadCtx}
				continue
			}
		case p.atOp("("):
			if g := p.genexp(); g != nil {
				e = &Call{Pos: p.span(start), Func: e, Args: []Expr{g}}
				continue
			}
			p.pos = save + 1
			args, kws := p.arguments()
			if p.expectOp(")") != nil {
				e = &Call{Pos: p.span(start), Func: e, Args: args, Keywords: kws}
				continue
			}
		case p.atOp("["):
			p.pos++
			if s := p.slices(); s != nil && p.expectOp("]") != nil {
				e = &Subscript{Pos: p.span(start), Value: e, Slice: s, Ctx: LoadCtx}
				continue
			}
		}
		p.pos = save
		return e
	}
}

// slices: slice !',' | ','.(slice | starred_expression)+ [',']
func (p *parser) slices() Expr {
	start := p.peek()
	mark := p.pos
	first := p.slice()
	if first != nil && !p.atOp(",") {
		return first
	}
	p.pos = mark
	var elts []Expr
	for {
		e := p.slice()
		if e == nil {
			e = p.starredExpression()
		}
		if e == nil {
			break
		}
		elts = append(elts, e)
		if !p.atOp(",") {
			break
		}
		p.pos++
	}
	if len(elts) == 0 {
		p.pos = mark
		return nil
	}
	return &Tuple{Pos: p.span(start), Elts: elts, Ctx: LoadCtx}
}

// slice: [expression] ':' [expression] [':' [expression]] | named_expression
func (p *parser) slice() Expr {
	start := p.peek()
	mark := p.pos
	lower := p.expression()
	if p.atOp(":") {
		p.pos++
		upper := p.expression()
		var step Expr
		if p.atOp(":") {
			p.pos++
			step = p.expression()
		}
		return &Slice{Pos: p.span(start), Lower: lower, Upper: upper, Step: step}
	}
	p.pos = mark
	return p.namedExpression()
}

func (p *parser) atom() Expr {
	p.enter()
	defer p.leave()
	t := p.peek()
	switch t.Kind {
	case NAME:
		switch t.Str {
		case "True":
			p.pos++
			return &Constant{Pos: tokPos(t), Value: true}
		case "False":
			p.pos++
			return &Constant{Pos: tokPos(t), Value: false}
		case "None":
			p.pos++
			return &Constant{Pos: tokPos(t), Value: nil}
		}
		if n := p.name(); n != nil {
			return n
		}
		return nil
	case STRING, FSTRING_START:
		return p.strings()
	case NUMBER:
		p.pos++
		return &Constant{Pos: tokPos(t), Value: parseNumber(t.Str)}
	case OP:
		switch t.Str {
		case "(":
			if e := p.tuple(); e != nil {
				return e
			}
			if e := p.group(); e != nil {
				return e
			}
			return p.genexp()
		case "[":
			if e := p.list(); e != nil {
				return e
			}
			return p.listcomp()
		case "{":
			if e := p.dict(); e != nil {
				return e
			}
			if e := p.set(); e != nil {
				return e
			}
			if e := p.dictcomp(); e != nil {
				return e
			}
			return p.setcomp()
		case "...":
			p.pos++
			return &Constant{Pos: tokPos(t), Value: ellipsis}
		}
	}
	return nil
}

// group: '(' (yield_expr | named_expression) ')' | invalid_group
func (p *parser) group() Expr {
	mark := p.pos
	p.pos++
	e := p.yieldExpr()
	if e == nil {
		e = p.namedExpression()
	}
	if e != nil && p.expectOp(")") != nil {
		return e
	}
	p.pos = mark
	if p.invalid {
		p.invalidGroup()
		p.pos = mark
	}
	return nil
}

// tuple: '(' [star_named_expression ',' [star_named_expressions]] ')'
func (p *parser) tuple() Expr {
	mark := p.pos
	start := p.advance()
	var elts []Expr
	if first := p.starNamedExpression(); first != nil {
		if p.expectOp(",") == nil {
			p.pos = mark
			return nil
		}
		elts = append([]Expr{first}, p.starNamedExpressions()...)
	}
	if p.expectOp(")") == nil {
		p.pos = mark
		return nil
	}
	if elts == nil {
		elts = []Expr{}
	}
	return &Tuple{Pos: p.span(start), Elts: elts, Ctx: LoadCtx}
}

func (p *parser) list() Expr {
	mark := p.pos
	start := p.advance()
	elts := p.starNamedExpressions()
	if p.expectOp("]") == nil {
		p.pos = mark
		return nil
	}
	if elts == nil {
		elts = []Expr{}
	}
	return &List{Pos: p.span(start), Elts: elts, Ctx: LoadCtx}
}

func (p *parser) set() Expr {
	mark := p.pos
	start := p.advance()
	elts := p.starNamedExpressions()
	if elts == nil || p.expectOp("}") == nil {
		p.pos = mark
		return nil
	}
	return &Set{Pos: p.span(start), Elts: elts}
}

// dict: '{' [double_starred_kvpairs] '}' | '{' invalid_double_starred_kvpairs '}'
func (p *parser) dict() Expr {
	mark := p.pos
	start := p.advance()
	keys, values, ok := p.doubleStarredKvpairs()
	if ok && p.expectOp("}") != nil {
		return &Dict{Pos: p.span(start), Keys: keys, Values: values}
	}
	p.pos = mark
	if p.invalid {
		p.pos++
		p.invalidDoubleStarredKvpairs()
		p.pos = mark
	}
	return nil
}

// doubleStarredKvpairs parses ','.double_starred_kvpair+ [','] (possibly empty).
func (p *parser) doubleStarredKvpairs() (keys, values []Expr, ok bool) {
	keys, values = []Expr{}, []Expr{}
	for {
		save := p.pos
		k, v, ok := p.doubleStarredKvpair()
		if !ok {
			p.pos = save
			return keys, values, true
		}
		keys = append(keys, k)
		values = append(values, v)
		if !p.atOp(",") {
			return keys, values, true
		}
		p.pos++
	}
}

func (p *parser) doubleStarredKvpair() (Expr, Expr, bool) {
	if p.atOp("**") {
		p.pos++
		if v := p.bitwiseOr(); v != nil {
			return nil, v, true
		}
		return nil, nil, false
	}
	return p.kvpair()
}

func (p *parser) kvpair() (Expr, Expr, bool) {
	k := p.expression()
	if k == nil || p.expectOp(":") == nil {
		return nil, nil, false
	}
	v := p.expression()
	if v == nil {
		return nil, nil, false
	}
	return k, v, true
}

// for_if_clauses: for_if_clause+
func (p *parser) forIfClauses() []*Comprehension {
	var out []*Comprehension
	for {
		c := p.forIfClause()
		if c == nil {
			return out
		}
		out = append(out, c)
	}
}

func (p *parser) forIfClause() *Comprehension {
	mark := p.pos
	isAsync := 0
	if p.atKw("async") && p.peekAt(1).Str == "for" {
		p.pos++
		isAsync = 1
	}
	if p.expectKw("for") == nil {
		p.pos = mark
		return nil
	}
	target := p.starTargets()
	if target != nil && p.expectKw("in") != nil {
		// cut
		iter := p.disjunction()
		if iter == nil {
			p.pos = mark
			return nil
		}
		var ifs []Expr
		for p.atKw("if") {
			save := p.pos
			p.pos++
			cond := p.disjunction()
			if cond == nil {
				p.pos = save
				break
			}
			ifs = append(ifs, cond)
		}
		return &Comprehension{Target: target, Iter: iter, Ifs: ifs, IsAsync: isAsync}
	}
	// 'async'? 'for' (bitwise_or (',' bitwise_or)* [',']) !'in'
	p.pos = mark
	if p.atKw("async") {
		p.pos++
	}
	p.pos++ // 'for'
	if e := p.bitwiseOr(); e != nil {
		for p.atOp(",") {
			save := p.pos
			p.pos++
			if p.bitwiseOr() == nil {
				p.pos = save + 1
				break
			}
		}
		if !p.atKw("in") {
			p.raiseLast("SyntaxError", "'in' expected after for-loop variables")
		}
	}
	p.pos = mark
	if p.invalid {
		p.invalidForTarget()
		p.pos = mark
	}
	return nil
}

// comp parses `open named_expression for_if_clauses close | invalid_comprehension` with the
// opener at the cursor: listcomp and setcomp.
func (p *parser) comp(close string, mk func(Pos, Expr, []*Comprehension) Expr) Expr {
	mark := p.pos
	start := p.advance()
	if elt := p.namedExpression(); elt != nil {
		if gens := p.forIfClauses(); gens != nil && p.expectOp(close) != nil {
			return mk(p.span(start), elt, gens)
		}
	}
	p.pos = mark
	if p.invalid {
		p.invalidComprehension()
		p.pos = mark
	}
	return nil
}

func (p *parser) listcomp() Expr {
	return p.comp("]", func(pos Pos, elt Expr, gens []*Comprehension) Expr {
		return &ListComp{Pos: pos, Elt: elt, Generators: gens}
	})
}

func (p *parser) setcomp() Expr {
	return p.comp("}", func(pos Pos, elt Expr, gens []*Comprehension) Expr {
		return &SetComp{Pos: pos, Elt: elt, Generators: gens}
	})
}

// genexp: '(' (assignment_expression | expression !':=') for_if_clauses ')' | invalid_comprehension
func (p *parser) genexp() Expr {
	mark := p.pos
	start := p.advance()
	elt := p.assignmentExpression()
	if elt == nil {
		elt = p.expression()
		if elt != nil && p.atOp(":=") {
			elt = nil
		}
	}
	if elt != nil {
		if gens := p.forIfClauses(); gens != nil && p.expectOp(")") != nil {
			return &GeneratorExp{Pos: p.span(start), Elt: elt, Generators: gens}
		}
	}
	p.pos = mark
	if p.invalid {
		p.invalidComprehension()
		p.pos = mark
	}
	return nil
}

func (p *parser) dictcomp() Expr {
	mark := p.pos
	start := p.advance()
	if k, v, ok := p.kvpair(); ok {
		if gens := p.forIfClauses(); gens != nil && p.expectOp("}") != nil {
			return &DictComp{Pos: p.span(start), Key: k, Value: v, Generators: gens}
		}
	}
	p.pos = mark
	if p.invalid {
		p.invalidDictComprehension()
		p.pos = mark
	}
	return nil
}

// ---- calls ----

// arguments (memo): args [','] &')' | invalid_arguments. Returns nil slices when absent.
func (p *parser) arguments() ([]Expr, []*Keyword) {
	mark := p.pos
	if args, kws, ok := p.args(); ok {
		p.expectOp(",")
		if p.atOp(")") {
			return args, kws
		}
	}
	p.pos = mark
	if p.invalid {
		p.invalidArguments()
		p.pos = mark
	}
	return nil, nil
}

// positionalArg is (starred_expression | (assignment_expression | expression !':=') !'=')
func (p *parser) positionalArg() Expr {
	mark := p.pos
	if e := p.starredExpression(); e != nil {
		return e
	}
	p.pos = mark
	e := p.assignmentExpression()
	if e == nil {
		e = p.expression()
		if e != nil && p.atOp(":=") {
			p.pos = mark
			return nil
		}
	}
	if e == nil || p.atOp("=") {
		p.pos = mark
		return nil
	}
	return e
}

func (p *parser) args() (args []Expr, kws []*Keyword, ok bool) {
	mark := p.pos
	if e := p.positionalArg(); e != nil {
		args = append(args, e)
		for p.atOp(",") {
			save := p.pos
			p.pos++
			next := p.positionalArg()
			if next == nil {
				p.pos = save
				break
			}
			args = append(args, next)
		}
	}
	if len(args) > 0 {
		if p.atOp(",") {
			save := p.pos
			p.pos++
			if a, k, ok := p.kwargs(); ok {
				args, kws = append(args, a...), k
			} else {
				p.pos = save
			}
		}
		return args, kws, true
	}
	p.pos = mark
	if args, kws, ok = p.kwargs(); !ok {
		p.pos = mark
	}
	return args, kws, ok
}

// kwargs: ','.kwarg_or_starred+ ',' ','.kwarg_or_double_starred+ | ','.kwarg_or_starred+ | ','.kwarg_or_double_starred+
// The *Starred items are returned as args, the *Keyword items as kws.
func (p *parser) kwargs() (args []Expr, kws []*Keyword, ok bool) {
	mark := p.pos
	items := p.gather(func() Node { return p.kwargOrStarred() })
	if items != nil {
		if p.atOp(",") {
			save := p.pos
			p.pos++
			if second := p.gather(func() Node { return p.kwargOrDoubleStarred() }); second != nil {
				items = append(items, second...)
			} else {
				p.pos = save
			}
		}
	} else {
		p.pos = mark
		if items = p.gather(func() Node { return p.kwargOrDoubleStarred() }); items == nil {
			p.pos = mark
			return nil, nil, false
		}
	}
	for _, x := range items {
		if s, isStar := x.(*Starred); isStar {
			args = append(args, s)
		} else {
			kws = append(kws, x.(*Keyword))
		}
	}
	return args, kws, true
}

// gather parses ','.item+ leaving a trailing comma unconsumed.
func (p *parser) gather(item func() Node) []Node {
	var out []Node
	for {
		save := p.pos
		x := item()
		if x == nil {
			p.pos = save
			if len(out) > 0 {
				p.pos = save - 1 // give the comma back
			}
			return out
		}
		out = append(out, x)
		if !p.atOp(",") {
			return out
		}
		p.pos++
	}
}

func (p *parser) keywordArg() *Keyword {
	mark := p.pos
	start := p.peek()
	if n := p.name(); n != nil && p.expectOp("=") != nil {
		if v := p.expression(); v != nil {
			return &Keyword{Pos: p.span(start), Arg: n.Id, Value: v}
		}
	}
	p.pos = mark
	return nil
}

func (p *parser) kwargOrStarred() Node {
	mark := p.pos
	if p.invalid {
		p.invalidKwarg()
		p.pos = mark
	}
	if k := p.keywordArg(); k != nil {
		return k
	}
	if s := p.starredExpression(); s != nil {
		return s
	}
	return nil
}

func (p *parser) kwargOrDoubleStarred() Node {
	mark := p.pos
	if p.invalid {
		p.invalidKwarg()
		p.pos = mark
	}
	if k := p.keywordArg(); k != nil {
		return k
	}
	if p.atOp("**") {
		start := p.advance()
		if v := p.expression(); v != nil {
			return &Keyword{Pos: p.span(start), Value: v}
		}
		p.pos = mark
	}
	return nil
}

// starred_expression: invalid_starred_expression_unpacking | '*' expression | invalid_starred_expression
func (p *parser) starredExpression() Expr {
	if !p.atOp("*") {
		return nil
	}
	mark := p.pos
	if p.invalid {
		p.invalidStarredExpressionUnpacking()
		p.pos = mark
	}
	start := p.advance()
	if e := p.expression(); e != nil {
		return &Starred{Pos: p.span(start), Value: e, Ctx: LoadCtx}
	}
	if p.invalid {
		p.raiseLast("SyntaxError", "Invalid star expression")
	}
	p.pos = mark
	return nil
}

// ---- lambda ----

func (p *parser) lambdef() Expr {
	if !p.atKw("lambda") {
		return nil
	}
	p.enter()
	defer p.leave()
	mark := p.pos
	start := p.advance()
	args := p.lambdaParams()
	if p.expectOp(":") == nil {
		p.pos = mark
		return nil
	}
	body := p.expression()
	if body == nil {
		p.pos = mark
		return nil
	}
	if args == nil {
		args = &Arguments{}
	}
	return &Lambda{Pos: p.span(start), Args: args, Body: body}
}

func (p *parser) lambdaParams() *Arguments {
	mark := p.pos
	if p.invalid {
		p.invalidParameters(true)
		p.pos = mark
	}
	return p.parameters(true)
}

// ---- parameters ----

func (p *parser) params() *Arguments {
	mark := p.pos
	if p.invalid {
		p.invalidParameters(false)
		p.pos = mark
	}
	return p.parameters(false)
}

// closer is what ends the parameter list: ')' for def, ':' for lambda.
func closer(lambda bool) string {
	if lambda {
		return ":"
	}
	return ")"
}

// param: NAME [annotation]; lambda params have no annotation. star allows a starred
// annotation (only after '*').
func (p *parser) param(lambda, star bool) *Arg {
	start := p.peek()
	n := p.name()
	if n == nil {
		return nil
	}
	a := &Arg{Arg: n.Id}
	if !lambda && p.atOp(":") {
		save := p.pos
		p.pos++
		var ann Expr
		if star {
			ann = p.starExpression()
		} else {
			ann = p.expression()
		}
		if ann == nil {
			p.pos = save
		} else {
			a.Annotation = ann
		}
	}
	a.Pos = p.span(start)
	return a
}

// paramEnd consumes ',' or checks for the closer.
func (p *parser) paramEnd(lambda bool) bool {
	if p.expectOp(",") != nil {
		return true
	}
	return p.atOp(closer(lambda))
}

func (p *parser) paramNoDefault(lambda, star bool) *Arg {
	mark := p.pos
	if a := p.param(lambda, star); a != nil && p.paramEnd(lambda) {
		return a
	}
	p.pos = mark
	return nil
}

func (p *parser) defaultValue() Expr {
	if !p.atOp("=") {
		return nil
	}
	mark := p.pos
	p.pos++
	if e := p.expression(); e != nil {
		return e
	}
	p.pos = mark
	if p.invalid {
		p.invalidDefault()
		p.pos = mark
	}
	return nil
}

func (p *parser) paramWithDefault(lambda bool) (*Arg, Expr) {
	mark := p.pos
	if a, d, ok := p.paramMaybeDefault(lambda); ok && d != nil {
		return a, d
	}
	p.pos = mark
	return nil, nil
}

func (p *parser) paramMaybeDefault(lambda bool) (*Arg, Expr, bool) {
	mark := p.pos
	if a := p.param(lambda, false); a != nil {
		d := p.defaultValue()
		if p.paramEnd(lambda) {
			return a, d, true
		}
	}
	p.pos = mark
	return nil, nil, false
}

// parameters implements the five `parameters` alternatives by parsing the shared shape:
// no-default params, optional '/', default params, then star_etc.
func (p *parser) parameters(lambda bool) *Arguments {
	mark := p.pos
	args := &Arguments{}
	// slash_no_default: param_no_default+ '/' (',' | &')')
	// slash_with_default: param_no_default* param_with_default+ '/' (',' | &')')
	var noDefault []*Arg
	for {
		a := p.paramNoDefault(lambda, false)
		if a == nil {
			break
		}
		noDefault = append(noDefault, a)
	}
	var withDefault []*Arg
	var defaults []Expr
	for {
		a, d := p.paramWithDefault(lambda)
		if a == nil {
			break
		}
		withDefault = append(withDefault, a)
		defaults = append(defaults, d)
	}
	slashPos := p.pos
	if len(noDefault)+len(withDefault) > 0 && p.atOp("/") {
		p.pos++
		if p.paramEnd(lambda) {
			args.Posonlyargs = append(noDefault, withDefault...)
			args.Defaults = defaults
			noDefault, withDefault, defaults = nil, nil, nil
			if len(args.Defaults) == 0 {
				// slash_no_default: param_no_default* param_with_default* may follow
				for {
					a := p.paramNoDefault(lambda, false)
					if a == nil {
						break
					}
					noDefault = append(noDefault, a)
				}
			}
			for {
				a, d := p.paramWithDefault(lambda)
				if a == nil {
					break
				}
				withDefault = append(withDefault, a)
				defaults = append(defaults, d)
			}
		} else {
			p.pos = slashPos
		}
	}
	args.Args = append(noDefault, withDefault...)
	args.Defaults = append(args.Defaults, defaults...)
	if !p.starEtc(args, lambda) && len(args.Posonlyargs)+len(args.Args) == 0 {
		p.pos = mark
		return nil
	}
	return args
}

// starEtc: '*' param_no_default param_maybe_default* [kwds] | '*' param_no_default_star_annotation ... |
// '*' ',' param_maybe_default+ [kwds] | kwds
func (p *parser) starEtc(args *Arguments, lambda bool) bool {
	mark := p.pos
	if p.invalid {
		p.invalidStarEtc(lambda)
		p.pos = mark
	}
	if p.atOp("*") {
		p.pos++
		if p.atOp(",") {
			p.pos++
			n := 0
			for {
				a, d, ok := p.paramMaybeDefault(lambda)
				if !ok {
					break
				}
				args.Kwonlyargs = append(args.Kwonlyargs, a)
				args.KwDefaults = append(args.KwDefaults, d)
				n++
			}
			if n == 0 {
				p.pos = mark
				return false
			}
		} else {
			v := p.paramNoDefault(lambda, true)
			if v == nil {
				p.pos = mark
				return false
			}
			args.Vararg = v
			for {
				a, d, ok := p.paramMaybeDefault(lambda)
				if !ok {
					break
				}
				args.Kwonlyargs = append(args.Kwonlyargs, a)
				args.KwDefaults = append(args.KwDefaults, d)
			}
		}
		p.kwds(args, lambda)
		return true
	}
	return p.kwds(args, lambda)
}

func (p *parser) kwds(args *Arguments, lambda bool) bool {
	mark := p.pos
	if p.invalid {
		p.invalidKwds(lambda)
		p.pos = mark
	}
	if p.atOp("**") {
		p.pos++
		if a := p.paramNoDefault(lambda, false); a != nil {
			args.Kwarg = a
			return true
		}
		p.pos = mark
	}
	return false
}

// ---- strings ----

// strings (memo): (fstring|string)+ then _PyPegen_concatenate_strings.
func (p *parser) strings() Expr { return p.memoized(rStrings, (*parser).stringsRaw) }

func (p *parser) stringsRaw() Expr {
	start := p.peek()
	var parts []Expr
	for {
		t := p.peek()
		switch t.Kind {
		case STRING:
			p.pos++
			v, kind, err := decodeStringLiteral(t.Str)
			if err != nil {
				p.raiseAtTok(t, err.Error())
			}
			parts = append(parts, &Constant{Pos: tokPos(t), Value: v, Kind: kind})
			continue
		case FSTRING_START:
			// A failed fstring leaves the cursor on its FSTRING_START: the repetition ends
			// there, as pegen's does, instead of appending nil and re-peeking the same token.
			if f := p.fstring(); f != nil {
				parts = append(parts, f)
				continue
			}
		}
		break
	}
	if parts == nil {
		return nil
	}
	return p.concatenateStrings(parts, p.span(start))
}

func (p *parser) concatenateStrings(parts []Expr, pos Pos) Expr {
	fstringFound, unicodeFound, bytesFound := false, false, false
	for _, e := range parts {
		switch n := e.(type) {
		case *Constant:
			if _, ok := n.Value.([]byte); ok {
				bytesFound = true
			} else {
				unicodeFound = true
			}
		default:
			fstringFound = true
		}
	}
	if (unicodeFound || fstringFound) && bytesFound {
		p.raiseLast("SyntaxError", "cannot mix bytes and nonbytes literals")
	}
	if bytesFound {
		var b []byte
		for _, e := range parts {
			b = append(b, e.(*Constant).Value.([]byte)...)
		}
		return &Constant{Pos: pos, Value: b, Kind: parts[0].(*Constant).Kind}
	}
	if !fstringFound && len(parts) == 1 {
		return parts[0]
	}
	var flat []Expr
	for _, e := range parts {
		if j, ok := e.(*JoinedStr); ok {
			flat = append(flat, j.Values...)
		} else {
			flat = append(flat, e)
		}
	}
	values := []Expr{}
	for i := 0; i < len(flat); i++ {
		e := flat[i]
		if c, ok := e.(*Constant); ok {
			if i+1 < len(flat) {
				if _, next := flat[i+1].(*Constant); next {
					var sb strings.Builder
					first, last := c, c
					j := i
					for ; j < len(flat); j++ {
						cc, ok := flat[j].(*Constant)
						if !ok {
							break
						}
						sb.WriteString(cc.Value.(string))
						last = cc
					}
					i = j - 1
					c = &Constant{Pos: Pos{first.Lineno, first.ColOffset, last.EndLineno, last.EndColOffset}, Value: sb.String(), Kind: first.Kind}
					e = c
				}
			}
			if fstringFound && c.Value.(string) == "" {
				continue
			}
		}
		values = append(values, e)
	}
	if !fstringFound {
		return values[0]
	}
	return &JoinedStr{Pos: pos, Values: values}
}

// fstring: FSTRING_START fstring_middle* FSTRING_END, then _PyPegen_joined_str.
func (p *parser) fstring() Expr {
	mark := p.pos
	start := p.advance()
	raw := strings.ContainsAny(start.Str, "rR")
	var values []Expr
	for {
		t := p.peek()
		if t.Kind == FSTRING_MIDDLE {
			p.pos++
			values = append(values, &Constant{Pos: tokPos(t), Value: t.Str})
			continue
		}
		if t.Kind == OP && t.Str == "{" {
			f := p.fstringReplacementField()
			if f == nil {
				p.pos = mark
				return nil
			}
			values = append(values, f)
			continue
		}
		break
	}
	end := p.peek()
	if end.Kind != FSTRING_END {
		p.pos = mark
		return nil
	}
	p.pos++
	out := []Expr{}
	for _, v := range values {
		switch n := v.(type) {
		case *Constant:
			s := n.Value.(string)
			if s == "{{" || s == "}}" {
				s = s[:1]
			}
			if !raw && strings.IndexByte(s, '\\') >= 0 {
				d, err := decodeUnicodeEscapes(s)
				if err != nil {
					p.raiseLast("SyntaxError", "(unicode error) "+err.Error())
				}
				s = d
			}
			if s == "" {
				continue
			}
			out = append(out, &Constant{Pos: n.Pos, Value: s})
		case *JoinedStr: // debug field: Constant + FormattedValue
			out = append(out, n.Values...)
		default:
			out = append(out, v)
		}
	}
	return &JoinedStr{Pos: Pos{start.Lineno, start.Col, end.EndLineno, end.EndCol}, Values: out}
}

// fstringReplacementField: '{' annotated_rhs '='? [fstring_conversion] [fstring_full_format_spec] '}'
// (with _PyPegen_formatted_value's debug-text handling) | invalid_replacement_field
func (p *parser) fstringReplacementField() Expr {
	mark := p.pos
	open := p.advance()
	if e := p.annotatedRhs(); e != nil {
		var debug *Token
		if p.atOp("=") {
			debug = p.advance()
		}
		var convTok, convName *Token
		ok := true
		if p.atOp("!") {
			convTok = p.advance()
			if p.isName(p.peek()) {
				convName = p.advance()
				if convName.Lineno != convTok.Lineno || convName.Col != convTok.EndCol {
					p.raiseAtTok(convTok, "f-string: conversion type must come right after the exclamanation mark")
				}
			} else {
				ok = false
			}
		}
		var format *JoinedStr
		var formatTok *Token
		if ok && p.atOp(":") {
			formatTok = p.peek()
			format = p.fstringFullFormatSpec()
		}
		if ok && p.atOp("}") {
			closeTok := p.advance()
			conversion := -1
			if convName != nil {
				c := convName.Str
				if len(c) != 1 || (c != "s" && c != "r" && c != "a") {
					p.raiseAtTok(convName, "f-string: invalid conversion character '"+c+"': expected 's', 'r', or 'a'")
				}
				conversion = int(c[0])
			} else if debug != nil && format == nil {
				conversion = 'r'
			}
			var fs Expr
			if format != nil {
				fs = format
			}
			fv := &FormattedValue{Pos: Pos{open.Lineno, open.Col, closeTok.EndLineno, closeTok.EndCol}, Value: e, Conversion: conversion, FormatSpec: fs}
			if debug == nil {
				return fv
			}
			endLine, endCol, meta := closeTok.EndLineno, closeTok.EndCol, closeTok.Meta
			if convName != nil {
				endLine, endCol, meta = convName.Lineno, convName.Col, convTok.Meta
			} else if format != nil {
				endLine, endCol, meta = formatTok.Lineno, formatTok.Col+1, formatTok.Meta
			}
			text := &Constant{Pos: Pos{open.Lineno, open.Col + 1, endLine, endCol - 1}, Value: meta}
			return &JoinedStr{Pos: Pos{open.Lineno, open.Col, endLine, endCol}, Values: []Expr{text, fv}}
		}
	}
	p.pos = mark
	if p.invalid {
		p.invalidReplacementField()
		p.pos = mark
	}
	return nil
}

// fstring_full_format_spec: ':' fstring_format_spec* with _PyPegen_setup_full_format_spec.
func (p *parser) fstringFullFormatSpec() *JoinedStr {
	colon := p.advance()
	var spec []Expr
	for {
		t := p.peek()
		if t.Kind == FSTRING_MIDDLE {
			p.pos++
			d, err := decodeUnicodeEscapes(t.Str)
			if err != nil {
				p.raiseLast("SyntaxError", "(unicode error) "+err.Error())
			}
			spec = append(spec, &Constant{Pos: tokPos(t), Value: d})
			continue
		}
		if t.Kind == OP && t.Str == "{" {
			f := p.fstringReplacementField()
			if f == nil {
				break
			}
			spec = append(spec, f)
			continue
		}
		break
	}
	pos := p.span(colon)
	nonEmpty := []Expr{}
	for _, e := range spec {
		if c, ok := e.(*Constant); ok && c.Value.(string) == "" {
			continue
		}
		nonEmpty = append(nonEmpty, e)
	}
	if len(nonEmpty) == 0 { // concatenateStrings indexes values[0]
		return &JoinedStr{Pos: pos, Values: nonEmpty}
	}
	res := p.concatenateStrings(nonEmpty, pos)
	if j, ok := res.(*JoinedStr); ok {
		return j
	}
	return &JoinedStr{Pos: pos, Values: []Expr{res}}
}

// ---- targets ----

// star_targets: star_target !',' | star_target (',' star_target)* [',']
func (p *parser) starTargets() Expr { return p.tupleOf(p.starTarget, storeCtx) }

// star_target (memo): '*' (!'*' star_target) | target_with_star_atom
func (p *parser) starTarget() Expr { return p.memoized(rStarTarget, (*parser).starTargetRaw) }

func (p *parser) starTargetRaw() Expr {
	if p.atOp("*") {
		start := p.advance()
		if !p.atOp("*") {
			if t := p.starTarget(); t != nil {
				return &Starred{Pos: p.span(start), Value: setCtx(t, storeCtx), Ctx: storeCtx}
			}
		}
		p.pos--
		return nil
	}
	return p.targetWithStarAtom()
}

// tTarget: t_primary '.' NAME !t_lookahead | t_primary '[' slices ']' !t_lookahead, in the
// given context; the head shared by target_with_star_atom, single_subscript_attribute_target
// and del_target. On failure the cursor is back at the start.
func (p *parser) tTarget(ctx ExprContext) Expr {
	mark := p.pos
	start := p.peek()
	if prim := p.tPrimary(); prim != nil {
		if p.atOp(".") {
			p.pos++
			if n := p.name(); n != nil && !p.atTLookahead() {
				return &Attribute{Pos: p.span(start), Value: prim, Attr: n.Id, Ctx: ctx}
			}
		} else if p.atOp("[") {
			p.pos++
			if s := p.slices(); s != nil && p.expectOp("]") != nil && !p.atTLookahead() {
				return &Subscript{Pos: p.span(start), Value: prim, Slice: s, Ctx: ctx}
			}
		}
	}
	p.pos = mark
	return nil
}

// target_with_star_atom (memo): t_primary '.' NAME !t_lookahead | t_primary '[' slices ']' !t_lookahead | star_atom
func (p *parser) targetWithStarAtom() Expr {
	return p.memoized(rTargetWithStarAtom, (*parser).targetWithStarAtomRaw)
}

func (p *parser) targetWithStarAtomRaw() Expr {
	if t := p.tTarget(storeCtx); t != nil {
		return t
	}
	return p.starAtom()
}

func (p *parser) atTLookahead() bool {
	t := p.peek()
	return t.Kind == OP && (t.Str == "(" || t.Str == "[" || t.Str == ".")
}

// star_atom: NAME | '(' target_with_star_atom ')' | '(' [star_targets_tuple_seq] ')' | '[' [star_targets_list_seq] ']'
func (p *parser) starAtom() Expr {
	mark := p.pos
	start := p.peek()
	if n := p.name(); n != nil {
		n.Ctx = storeCtx
		return n
	}
	if p.atOp("(") {
		p.pos++
		if t := p.targetWithStarAtom(); t != nil && p.expectOp(")") != nil {
			return setCtx(t, storeCtx)
		}
		p.pos = mark + 1
		elts := []Expr{}
		if first := p.starTarget(); first != nil {
			if p.expectOp(",") == nil {
				p.pos = mark
				return nil
			}
			elts = append(elts, first)
			for {
				t := p.starTarget()
				if t == nil {
					break
				}
				elts = append(elts, t)
				if p.expectOp(",") == nil {
					break
				}
			}
		}
		if p.expectOp(")") != nil {
			return &Tuple{Pos: p.span(start), Elts: elts, Ctx: storeCtx}
		}
		p.pos = mark
		return nil
	}
	if p.atOp("[") {
		p.pos++
		elts := []Expr{}
		for {
			t := p.starTarget()
			if t == nil {
				break
			}
			elts = append(elts, t)
			if p.expectOp(",") == nil {
				break
			}
		}
		if p.expectOp("]") != nil {
			return &List{Pos: p.span(start), Elts: elts, Ctx: storeCtx}
		}
		p.pos = mark
	}
	return nil
}

// single_target: single_subscript_attribute_target | NAME | '(' single_target ')'
func (p *parser) singleTarget() Expr {
	mark := p.pos
	if t := p.tTarget(storeCtx); t != nil {
		return t
	}
	if n := p.name(); n != nil {
		n.Ctx = storeCtx
		return n
	}
	if p.atOp("(") {
		p.pos++
		if t := p.singleTarget(); t != nil && p.expectOp(")") != nil {
			return t
		}
		p.pos = mark
	}
	return nil
}

// t_primary: (t_primary '.' NAME | t_primary '[' slices ']' | t_primary genexp | t_primary '(' [arguments] ')' | atom) &t_lookahead
// (left-recursive, memoised)
func (p *parser) tPrimary() Expr { return p.memoized(rTPrimary, (*parser).tPrimaryRaw) }

func (p *parser) tPrimaryRaw() Expr {
	mark := p.pos
	start := p.peek()
	e := p.atom()
	if e == nil || !p.atTLookahead() {
		p.pos = mark
		return nil
	}
	for {
		save := p.pos
		var next Expr
		switch {
		case p.atOp("."):
			p.pos++
			if n := p.name(); n != nil {
				next = &Attribute{Pos: p.span(start), Value: e, Attr: n.Id, Ctx: LoadCtx}
			}
		case p.atOp("["):
			p.pos++
			if s := p.slices(); s != nil && p.expectOp("]") != nil {
				next = &Subscript{Pos: p.span(start), Value: e, Slice: s, Ctx: LoadCtx}
			}
		case p.atOp("("):
			if g := p.genexp(); g != nil {
				next = &Call{Pos: p.span(start), Func: e, Args: []Expr{g}}
			} else {
				p.pos = save + 1
				args, kws := p.arguments()
				if p.expectOp(")") != nil {
					next = &Call{Pos: p.span(start), Func: e, Args: args, Keywords: kws}
				}
			}
		}
		if next == nil || !p.atTLookahead() {
			p.pos = save
			return e
		}
		e = next
	}
}

// del_targets: ','.del_target+ [',']
func (p *parser) delTargets() []Expr {
	var out []Expr
	for {
		t := p.delTarget()
		if t == nil {
			return out
		}
		out = append(out, t)
		if p.expectOp(",") == nil {
			return out
		}
	}
}

// del_target (memo): t_primary '.' NAME !t_lookahead | t_primary '[' slices ']' !t_lookahead | del_t_atom
func (p *parser) delTarget() Expr { return p.memoized(rDelTarget, (*parser).delTargetRaw) }

func (p *parser) delTargetRaw() Expr {
	mark := p.pos
	start := p.peek()
	if t := p.tTarget(delCtx); t != nil {
		return t
	}
	// del_t_atom: NAME | '(' del_target ')' | '(' [del_targets] ')' | '[' [del_targets] ']'
	if n := p.name(); n != nil {
		n.Ctx = delCtx
		return n
	}
	if p.atOp("(") {
		p.pos++
		if t := p.delTarget(); t != nil && p.expectOp(")") != nil {
			return setCtx(t, delCtx)
		}
		p.pos = mark + 1
		elts := p.delTargets()
		if p.expectOp(")") != nil {
			if elts == nil {
				elts = []Expr{}
			}
			return &Tuple{Pos: p.span(start), Elts: elts, Ctx: delCtx}
		}
		p.pos = mark
		return nil
	}
	if p.atOp("[") {
		p.pos++
		elts := p.delTargets()
		if p.expectOp("]") != nil {
			if elts == nil {
				elts = []Expr{}
			}
			return &List{Pos: p.span(start), Elts: elts, Ctx: delCtx}
		}
		p.pos = mark
	}
	return nil
}

// setCtx is _PyPegen_set_expr_context, applied in place.
func setCtx(e Expr, ctx ExprContext) Expr {
	switch n := e.(type) {
	case *Name:
		n.Ctx = ctx
	case *Attribute:
		n.Ctx = ctx
	case *Subscript:
		n.Ctx = ctx
	case *Starred:
		n.Ctx = ctx
		setCtx(n.Value, ctx)
	case *List:
		n.Ctx = ctx
		for _, x := range n.Elts {
			setCtx(x, ctx)
		}
	case *Tuple:
		n.Ctx = ctx
		for _, x := range n.Elts {
			setCtx(x, ctx)
		}
	}
	return e
}
