package pyast

// ---- match statement ----

// match_stmt: "match" subject_expr ':' NEWLINE INDENT case_block+ DEDENT | invalid_match_stmt
func (p *parser) matchStmt() Stmt {
	mark := p.pos
	start := p.advance() // "match"
	subject := p.subjectExpr()
	if subject != nil && p.expectOp(":") != nil && p.atKind(NEWLINE) {
		p.pos++
		if p.atKind(INDENT) {
			p.pos++
			var cases []*MatchCase
			for p.atKw("case") {
				c := p.caseBlock()
				if c == nil {
					break
				}
				cases = append(cases, c)
			}
			if len(cases) > 0 && p.atKind(DEDENT) {
				p.pos++
				return &Match{Pos: p.span(start), Subject: subject, Cases: cases}
			}
		}
	}
	p.pos = mark
	if p.invalid {
		p.invalidMatchStmt()
		p.pos = mark
	}
	return nil
}

// subject_expr: star_named_expression ',' star_named_expressions? | named_expression
func (p *parser) subjectExpr() Expr {
	mark := p.pos
	start := p.peek()
	if first := p.starNamedExpression(); first != nil && p.expectOp(",") != nil {
		elts := append([]Expr{first}, p.starNamedExpressions()...)
		return &Tuple{Pos: p.span(start), Elts: elts, Ctx: LoadCtx}
	}
	p.pos = mark
	return p.namedExpression()
}

// case_block: invalid_case_block | "case" patterns guard? ':' block
func (p *parser) caseBlock() *MatchCase {
	mark := p.pos
	if p.invalid {
		p.invalidCaseBlock()
		p.pos = mark
	}
	p.pos++ // "case"
	pat := p.patterns()
	if pat == nil {
		p.pos = mark
		return nil
	}
	var guard Expr
	if p.atKw("if") {
		save := p.pos
		p.pos++
		if guard = p.namedExpression(); guard == nil {
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
	return &MatchCase{Pattern: pat, Guard: guard, Body: body}
}

// patterns: open_sequence_pattern | pattern
func (p *parser) patterns() Pattern {
	mark := p.pos
	start := p.peek()
	if seq := p.openSequencePattern(); seq != nil {
		return &MatchSequence{Pos: p.span(start), Patterns: seq}
	}
	p.pos = mark
	return p.pattern()
}

// pattern: as_pattern | or_pattern
func (p *parser) pattern() Pattern {
	mark := p.pos
	start := p.peek()
	or := p.orPattern()
	if or == nil {
		return nil
	}
	if p.atKw("as") {
		save := p.pos
		p.pos++
		if target := p.patternCaptureTarget(); target != nil {
			return &MatchAs{Pos: p.span(start), Pattern: or, Name: target.Id}
		}
		p.pos = mark
		if p.invalid {
			p.invalidAsPattern()
			p.pos = mark
		}
		p.pos = save
	}
	return or
}

// or_pattern: '|'.closed_pattern+
func (p *parser) orPattern() Pattern {
	start := p.peek()
	first := p.closedPattern()
	if first == nil {
		return nil
	}
	pats := []Pattern{first}
	for p.atOp("|") {
		save := p.pos
		p.pos++
		c := p.closedPattern()
		if c == nil {
			p.pos = save
			break
		}
		pats = append(pats, c)
	}
	if len(pats) == 1 {
		return first
	}
	return &MatchOr{Pos: p.span(start), Patterns: pats}
}

// closed_pattern: literal_pattern | capture_pattern | wildcard_pattern | value_pattern |
// group_pattern | sequence_pattern | mapping_pattern | class_pattern
func (p *parser) closedPattern() Pattern {
	mark := p.pos
	start := p.peek()
	if v := p.literalPattern(); v != nil {
		return v
	}
	p.pos = mark
	if p.atKw("_") {
		p.pos++
		return &MatchAs{Pos: tokPos(start)}
	}
	if t := p.patternCaptureTarget(); t != nil {
		return &MatchAs{Pos: tokPos(start), Name: t.Id}
	}
	p.pos = mark
	if attr := p.attr(); attr != nil && !p.atOp(".") && !p.atOp("(") && !p.atOp("=") {
		return &MatchValue{Pos: p.span(start), Value: attr}
	}
	p.pos = mark
	if p.atOp("(") {
		p.pos++
		if inner := p.pattern(); inner != nil && p.expectOp(")") != nil {
			return inner
		}
		p.pos = mark + 1
		seq := p.openSequencePattern()
		if p.expectOp(")") != nil {
			if seq == nil {
				seq = []Pattern{}
			}
			return &MatchSequence{Pos: p.span(start), Patterns: seq}
		}
		p.pos = mark
		return nil
	}
	if p.atOp("[") {
		p.pos++
		seq := p.maybeSequencePattern()
		if p.expectOp("]") != nil {
			if seq == nil {
				seq = []Pattern{}
			}
			return &MatchSequence{Pos: p.span(start), Patterns: seq}
		}
		p.pos = mark
		return nil
	}
	if p.atOp("{") {
		return p.mappingPattern()
	}
	return p.classPattern()
}

// literal_pattern: signed_number !('+' | '-') | complex_number | strings | 'None' | 'True' | 'False'
func (p *parser) literalPattern() Pattern {
	mark := p.pos
	start := p.peek()
	if v := p.literalExpr(); v != nil {
		if c, ok := v.(*Constant); ok && (c.Value == nil || c.Value == true || c.Value == false) {
			return &MatchSingleton{Pos: c.Pos, Value: c.Value}
		}
		return &MatchValue{Pos: p.span(start), Value: v}
	}
	p.pos = mark
	return nil
}

// literalExpr: signed_number !('+' | '-') | complex_number | strings | 'None' | 'True' | 'False'
func (p *parser) literalExpr() Expr {
	mark := p.pos
	t := p.peek()
	if t.Kind == NAME {
		switch t.Str {
		case "None":
			p.pos++
			return &Constant{Pos: tokPos(t), Value: nil}
		case "True":
			p.pos++
			return &Constant{Pos: tokPos(t), Value: true}
		case "False":
			p.pos++
			return &Constant{Pos: tokPos(t), Value: false}
		}
		return nil
	}
	if t.Kind == STRING || t.Kind == FSTRING_START {
		return p.strings()
	}
	// signed_number !('+' | '-')
	if num := p.signedNumber(); num != nil {
		if !p.atOp("+") && !p.atOp("-") {
			return num
		}
		// complex_number: signed_real_number ('+' | '-') imaginary_number
		p.pos = mark
		real := p.signedNumber()
		if c, ok := realOf(real); ok {
			if _, isComplex := c.Value.(complex128); isComplex {
				p.raiseAt(c, "real number required in complex literal")
			}
		}
		var op Operator
		if p.atOp("+") {
			op = &Add{}
		} else {
			op = &Sub{}
		}
		p.pos++
		imagTok := p.peek()
		if imagTok.Kind != NUMBER {
			p.pos = mark
			return nil
		}
		p.pos++
		imag := &Constant{Pos: tokPos(imagTok), Value: parseNumber(imagTok.Str)}
		if _, isComplex := imag.Value.(complex128); !isComplex {
			p.raiseAt(imag, "imaginary number required in complex literal")
		}
		return &BinOp{Pos: p.span(t), Left: real, Op: op, Right: imag}
	}
	p.pos = mark
	return nil
}

func realOf(e Expr) (*Constant, bool) {
	switch n := e.(type) {
	case *Constant:
		return n, true
	case *UnaryOp:
		return realOf(n.Operand)
	}
	return nil, false
}

// signed_number: NUMBER | '-' NUMBER
func (p *parser) signedNumber() Expr {
	start := p.peek()
	if p.atOp("-") {
		p.pos++
		t := p.peek()
		if t.Kind != NUMBER {
			p.pos--
			return nil
		}
		p.pos++
		return &UnaryOp{Pos: p.span(start), Op: &USub{}, Operand: &Constant{Pos: tokPos(t), Value: parseNumber(t.Str)}}
	}
	if start.Kind == NUMBER {
		p.pos++
		return &Constant{Pos: tokPos(start), Value: parseNumber(start.Str)}
	}
	return nil
}

// pattern_capture_target: !"_" NAME !('.' | '(' | '=')
func (p *parser) patternCaptureTarget() *Name {
	mark := p.pos
	if p.atKw("_") {
		return nil
	}
	n := p.name()
	if n == nil {
		return nil
	}
	if p.atOp(".") || p.atOp("(") || p.atOp("=") {
		p.pos = mark
		return nil
	}
	n.Ctx = storeCtx
	return n
}

// attr: name_or_attr '.' NAME; nameOrAttr is NAME ('.' NAME)*.
func (p *parser) attr() Expr {
	mark := p.pos
	e := p.nameOrAttr()
	if _, ok := e.(*Attribute); !ok {
		p.pos = mark
		return nil
	}
	return e
}

func (p *parser) nameOrAttr() Expr {
	start := p.peek()
	n := p.name()
	if n == nil {
		return nil
	}
	var e Expr = n
	for p.atOp(".") {
		save := p.pos
		p.pos++
		m := p.name()
		if m == nil {
			p.pos = save
			break
		}
		e = &Attribute{Pos: p.span(start), Value: e, Attr: m.Id, Ctx: LoadCtx}
	}
	return e
}

// open_sequence_pattern: maybe_star_pattern ',' maybe_sequence_pattern?
func (p *parser) openSequencePattern() []Pattern {
	mark := p.pos
	first := p.maybeStarPattern()
	if first == nil || p.expectOp(",") == nil {
		p.pos = mark
		return nil
	}
	rest := p.maybeSequencePattern()
	return append([]Pattern{first}, rest...)
}

// maybe_sequence_pattern: ','.maybe_star_pattern+ ','?
func (p *parser) maybeSequencePattern() []Pattern {
	var out []Pattern
	for {
		pat := p.maybeStarPattern()
		if pat == nil {
			return out
		}
		out = append(out, pat)
		if p.expectOp(",") == nil {
			return out
		}
	}
}

func (p *parser) maybeStarPattern() Pattern {
	if p.atOp("*") {
		start := p.advance()
		if p.atKw("_") {
			p.pos++
			return &MatchStar{Pos: p.span(start)}
		}
		if t := p.patternCaptureTarget(); t != nil {
			return &MatchStar{Pos: p.span(start), Name: t.Id}
		}
		p.pos--
		return nil
	}
	return p.pattern()
}

// mapping_pattern: '{' '}' | '{' double_star_pattern ','? '}' | '{' items_pattern ',' double_star_pattern ','? '}' | '{' items_pattern ','? '}'
func (p *parser) mappingPattern() Pattern {
	mark := p.pos
	start := p.advance()
	m := &MatchMapping{}
	if p.expectOp("}") != nil {
		m.Pos = p.span(start)
		return m
	}
	for {
		if p.atOp("**") {
			p.pos++
			t := p.patternCaptureTarget()
			if t == nil {
				p.pos = mark
				return nil
			}
			m.Rest = t.Id
			p.expectOp(",")
			break
		}
		save := p.pos
		k := p.literalExpr()
		if k == nil {
			p.pos = save
			k = p.attr()
		}
		if k == nil || p.expectOp(":") == nil {
			p.pos = mark
			return nil
		}
		v := p.pattern()
		if v == nil {
			p.pos = mark
			return nil
		}
		m.Keys = append(m.Keys, k)
		m.Patterns = append(m.Patterns, v)
		if p.expectOp(",") == nil {
			break
		}
	}
	if p.expectOp("}") == nil {
		p.pos = mark
		return nil
	}
	m.Pos = p.span(start)
	return m
}

// class_pattern: name_or_attr '(' [positional_patterns [',' keyword_patterns]] ','? ')' | invalid_class_pattern
func (p *parser) classPattern() Pattern {
	mark := p.pos
	start := p.peek()
	cls := p.nameOrAttr()
	if cls == nil || p.expectOp("(") == nil {
		p.pos = mark
		return nil
	}
	m := &MatchClass{Cls: cls}
	for !p.atOp(")") {
		save := p.pos
		if n := p.name(); n != nil && p.expectOp("=") != nil {
			v := p.pattern()
			if v == nil {
				p.pos = mark
				return nil
			}
			m.KwdAttrs = append(m.KwdAttrs, n.Id)
			m.KwdPatterns = append(m.KwdPatterns, v)
		} else {
			p.pos = save
			if len(m.KwdAttrs) > 0 {
				p.pos = mark
				if p.invalid {
					p.invalidClassPattern()
					p.pos = mark
				}
				return nil
			}
			v := p.pattern()
			if v == nil {
				p.pos = mark
				return nil
			}
			m.Patterns = append(m.Patterns, v)
		}
		if p.expectOp(",") == nil {
			break
		}
	}
	if p.expectOp(")") == nil {
		p.pos = mark
		return nil
	}
	m.Pos = p.span(start)
	return m
}

// ---- type parameters (PEP 695) ----

// optTypeParams parses [type_params]: '[' type_param_seq ']' | invalid_type_params
func (p *parser) optTypeParams() []TypeParam {
	if !p.atOp("[") {
		return nil
	}
	mark := p.pos
	if p.invalid {
		p.pos++
		if t := p.peek(); t.Kind == OP && t.Str == "]" {
			p.raiseAtTok(t, "Type parameter list cannot be empty")
		}
		p.pos = mark
	}
	p.pos++
	var params []TypeParam
	for {
		tp := p.typeParam()
		if tp == nil {
			break
		}
		params = append(params, tp)
		if p.expectOp(",") == nil {
			break
		}
	}
	if params == nil || p.expectOp("]") == nil {
		p.pos = mark
		return nil
	}
	return params
}

// type_param: NAME [type_param_bound] [type_param_default] | invalid_type_param | '*' NAME [type_param_starred_default] | '**' NAME [type_param_default]
func (p *parser) typeParam() TypeParam {
	mark := p.pos
	start := p.peek()
	if n := p.name(); n != nil {
		var bound, def Expr
		if p.atOp(":") {
			save := p.pos
			p.pos++
			if bound = p.expression(); bound == nil {
				p.pos = save
			}
		}
		if p.atOp("=") {
			save := p.pos
			p.pos++
			if def = p.expression(); def == nil {
				p.pos = save
			}
		}
		return &TypeVar{Pos: p.span(start), Name: n.Id, Bound: bound, DefaultValue: def}
	}
	if p.atOp("*") || p.atOp("**") {
		star := p.advance()
		n := p.name()
		if n == nil {
			p.pos = mark
			return nil
		}
		if p.invalid && p.atOp(":") {
			colon := p.advance()
			if e := p.expression(); e != nil {
				kind := "TypeVarTuple"
				if star.Str == "**" {
					kind = "ParamSpec"
				}
				what := "bound"
				if _, ok := e.(*Tuple); ok {
					what = "constraints"
				}
				p.raiseAtTok(colon, "cannot use "+what+" with "+kind)
			}
			p.pos = mark + 2
		}
		var def Expr
		if p.atOp("=") {
			save := p.pos
			p.pos++
			if star.Str == "*" {
				def = p.starExpression()
			} else {
				def = p.expression()
			}
			if def == nil {
				p.pos = save
			}
		}
		if star.Str == "*" {
			return &TypeVarTuple{Pos: p.span(start), Name: n.Id, DefaultValue: def}
		}
		return &ParamSpec{Pos: p.span(start), Name: n.Id, DefaultValue: def}
	}
	return nil
}
