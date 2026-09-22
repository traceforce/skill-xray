// Package pyast parses Python 3.13 source into CPython's AST node set (Parser/Python.asdl)
// with CPython's positions, acceptance limits and SyntaxError messages, so that internal/parse and
// the code checks see exactly what the oracle's `ast.parse` sees.
package pyast

import (
	"iter"
	"reflect"
	"slices"
	"strings"
	"sync"
	"unicode"
)

// Node is any AST node, including the expr_context / operator singletons.
type Node interface{ node() }

// Expr, Stmt, Pattern and TypeParam are the ASDL sum types the parser distinguishes.
type (
	Expr interface {
		Node
		expr()
	}
	Stmt interface {
		Node
		stmt()
	}
	Pattern interface {
		Node
		pattern()
	}
	TypeParam interface {
		Node
		typeParam()
	}
	ExprContext interface {
		Node
		ctx()
	}
	Operator interface {
		Node
		operator()
	}
	BoolOperator interface {
		Node
		boolOp()
	}
	UnaryOperator interface {
		Node
		unaryOp()
	}
	CmpOp interface {
		Node
		cmpOp()
	}
)

// Pos is the `_attributes` block: 1-based lines, 0-based UTF-8 byte columns.
type Pos struct{ Lineno, ColOffset, EndLineno, EndColOffset int }

// EllipsisValue is the Constant value of `...`.
type EllipsisValue struct{}

// ellipsis is the singleton value stored in Constant for `...`.
var ellipsis = EllipsisValue{}

// Module is the root; it has no position. type_ignores is never populated by ast.parse
// without type_comments=True, so the field is not modelled (Dump omits empty lists anyway).
type Module struct {
	Body []Stmt
}

// Statements.
type (
	FunctionDef struct {
		Pos
		Name          string
		Args          *Arguments
		Body          []Stmt
		DecoratorList []Expr
		Returns       Expr
		TypeComment   string
		TypeParams    []TypeParam
	}
	AsyncFunctionDef struct {
		Pos
		Name          string
		Args          *Arguments
		Body          []Stmt
		DecoratorList []Expr
		Returns       Expr
		TypeComment   string
		TypeParams    []TypeParam
	}
	ClassDef struct {
		Pos
		Name          string
		Bases         []Expr
		Keywords      []*Keyword
		Body          []Stmt
		DecoratorList []Expr
		TypeParams    []TypeParam
	}
	Return struct {
		Pos
		Value Expr
	}
	Delete struct {
		Pos
		Targets []Expr
	}
	Assign struct {
		Pos
		Targets     []Expr
		Value       Expr
		TypeComment string
	}
	TypeAlias struct {
		Pos
		Name       Expr
		TypeParams []TypeParam
		Value      Expr
	}
	AugAssign struct {
		Pos
		Target Expr
		Op     Operator
		Value  Expr
	}
	AnnAssign struct {
		Pos
		Target     Expr
		Annotation Expr
		Value      Expr
		Simple     int
	}
	For struct {
		Pos
		Target      Expr
		Iter        Expr
		Body        []Stmt
		Orelse      []Stmt
		TypeComment string
	}
	AsyncFor struct {
		Pos
		Target      Expr
		Iter        Expr
		Body        []Stmt
		Orelse      []Stmt
		TypeComment string
	}
	While struct {
		Pos
		Test   Expr
		Body   []Stmt
		Orelse []Stmt
	}
	If struct {
		Pos
		Test   Expr
		Body   []Stmt
		Orelse []Stmt
	}
	With struct {
		Pos
		Items       []*WithItem
		Body        []Stmt
		TypeComment string
	}
	AsyncWith struct {
		Pos
		Items       []*WithItem
		Body        []Stmt
		TypeComment string
	}
	Match struct {
		Pos
		Subject Expr
		Cases   []*MatchCase
	}
	Raise struct {
		Pos
		Exc   Expr
		Cause Expr
	}
	Try struct {
		Pos
		Body      []Stmt
		Handlers  []*ExceptHandler
		Orelse    []Stmt
		Finalbody []Stmt
	}
	TryStar struct {
		Pos
		Body      []Stmt
		Handlers  []*ExceptHandler
		Orelse    []Stmt
		Finalbody []Stmt
	}
	Assert struct {
		Pos
		Test Expr
		Msg  Expr
	}
	Import struct {
		Pos
		Names []*Alias
	}
	ImportFrom struct {
		Pos
		Module string
		Names  []*Alias
		Level  int
	}
	Global struct {
		Pos
		Names []string
	}
	Nonlocal struct {
		Pos
		Names []string
	}
	ExprStmt struct { // Python `Expr`
		Pos
		Value Expr
	}
	Pass     struct{ Pos }
	Break    struct{ Pos }
	Continue struct{ Pos }
)

// Expressions.
type (
	BoolOp struct {
		Pos
		Op     BoolOperator
		Values []Expr
	}
	NamedExpr struct {
		Pos
		Target Expr
		Value  Expr
	}
	BinOp struct {
		Pos
		Left  Expr
		Op    Operator
		Right Expr
	}
	UnaryOp struct {
		Pos
		Op      UnaryOperator
		Operand Expr
	}
	Lambda struct {
		Pos
		Args *Arguments
		Body Expr
	}
	IfExp struct {
		Pos
		Test   Expr
		Body   Expr
		Orelse Expr
	}
	Dict struct {
		Pos
		Keys   []Expr // nil entry == `**x`
		Values []Expr
	}
	Set struct {
		Pos
		Elts []Expr
	}
	ListComp struct {
		Pos
		Elt        Expr
		Generators []*Comprehension
	}
	SetComp struct {
		Pos
		Elt        Expr
		Generators []*Comprehension
	}
	DictComp struct {
		Pos
		Key        Expr
		Value      Expr
		Generators []*Comprehension
	}
	GeneratorExp struct {
		Pos
		Elt        Expr
		Generators []*Comprehension
	}
	Await struct {
		Pos
		Value Expr
	}
	Yield struct {
		Pos
		Value Expr
	}
	YieldFrom struct {
		Pos
		Value Expr
	}
	Compare struct {
		Pos
		Left        Expr
		Ops         []CmpOp
		Comparators []Expr
	}
	Call struct {
		Pos
		Func     Expr
		Args     []Expr
		Keywords []*Keyword
	}
	FormattedValue struct {
		Pos
		Value      Expr
		Conversion int
		FormatSpec Expr
	}
	JoinedStr struct {
		Pos
		Values []Expr
	}
	// Constant.Value is nil (None), bool, int64, *big.Int, float64, complex128, string,
	// []byte or ellipsis.
	Constant struct {
		Pos
		Value any
		Kind  string
	}
	Attribute struct {
		Pos
		Value Expr
		Attr  string
		Ctx   ExprContext
	}
	Subscript struct {
		Pos
		Value Expr
		Slice Expr
		Ctx   ExprContext
	}
	Starred struct {
		Pos
		Value Expr
		Ctx   ExprContext
	}
	Name struct {
		Pos
		Id  string
		Ctx ExprContext
	}
	List struct {
		Pos
		Elts []Expr
		Ctx  ExprContext
	}
	Tuple struct {
		Pos
		Elts []Expr
		Ctx  ExprContext
	}
	Slice struct {
		Pos
		Lower Expr
		Upper Expr
		Step  Expr
	}
)

// Auxiliary nodes.
type (
	Comprehension struct {
		Target  Expr
		Iter    Expr
		Ifs     []Expr
		IsAsync int
	}
	ExceptHandler struct {
		Pos
		Type Expr
		Name string
		Body []Stmt
	}
	Arguments struct {
		Posonlyargs []*Arg
		Args        []*Arg
		Vararg      *Arg
		Kwonlyargs  []*Arg
		KwDefaults  []Expr // nil entry == no default
		Kwarg       *Arg
		Defaults    []Expr
	}
	Arg struct {
		Pos
		Arg         string
		Annotation  Expr
		TypeComment string
	}
	Keyword struct {
		Pos
		Arg   string // "" == `**value`
		Value Expr
	}
	Alias struct {
		Pos
		Name   string
		Asname string
	}
	WithItem struct {
		ContextExpr  Expr
		OptionalVars Expr
	}
	MatchCase struct {
		Pattern Pattern
		Guard   Expr
		Body    []Stmt
	}
)

// Patterns.
type (
	MatchValue struct {
		Pos
		Value Expr
	}
	MatchSingleton struct {
		Pos
		Value any
	}
	MatchSequence struct {
		Pos
		Patterns []Pattern
	}
	MatchMapping struct {
		Pos
		Keys     []Expr
		Patterns []Pattern
		Rest     string
	}
	MatchClass struct {
		Pos
		Cls         Expr
		Patterns    []Pattern
		KwdAttrs    []string
		KwdPatterns []Pattern
	}
	MatchStar struct {
		Pos
		Name string
	}
	MatchAs struct {
		Pos
		Pattern Pattern
		Name    string
	}
	MatchOr struct {
		Pos
		Patterns []Pattern
	}
)

// Type parameters (PEP 695).
type (
	TypeVar struct {
		Pos
		Name         string
		Bound        Expr
		DefaultValue Expr
	}
	ParamSpec struct {
		Pos
		Name         string
		DefaultValue Expr
	}
	TypeVarTuple struct {
		Pos
		Name         string
		DefaultValue Expr
	}
)

// Singletons: each embeds the marker of its sum type, which carries node() and the sum method.
type (
	ctxMark      struct{}
	boolOpMark   struct{}
	operatorMark struct{}
	unaryOpMark  struct{}
	cmpOpMark    struct{}

	Load  struct{ ctxMark }
	Store struct{ ctxMark }
	Del   struct{ ctxMark }

	And struct{ boolOpMark }
	Or  struct{ boolOpMark }

	Add      struct{ operatorMark }
	Sub      struct{ operatorMark }
	Mult     struct{ operatorMark }
	MatMult  struct{ operatorMark }
	Div      struct{ operatorMark }
	Mod      struct{ operatorMark }
	Pow      struct{ operatorMark }
	LShift   struct{ operatorMark }
	RShift   struct{ operatorMark }
	BitOr    struct{ operatorMark }
	BitXor   struct{ operatorMark }
	BitAnd   struct{ operatorMark }
	FloorDiv struct{ operatorMark }

	Invert struct{ unaryOpMark }
	Not    struct{ unaryOpMark }
	UAdd   struct{ unaryOpMark }
	USub   struct{ unaryOpMark }

	Eq    struct{ cmpOpMark }
	NotEq struct{ cmpOpMark }
	Lt    struct{ cmpOpMark }
	LtE   struct{ cmpOpMark }
	Gt    struct{ cmpOpMark }
	GtE   struct{ cmpOpMark }
	Is    struct{ cmpOpMark }
	IsNot struct{ cmpOpMark }
	In    struct{ cmpOpMark }
	NotIn struct{ cmpOpMark }
)

// node() is promoted from Pos to every positioned node and from the markers to the singletons.
func (Pos) node()            {}
func (ctxMark) node()        {}
func (boolOpMark) node()     {}
func (operatorMark) node()   {}
func (unaryOpMark) node()    {}
func (cmpOpMark) node()      {}
func (*Module) node()        {}
func (*Comprehension) node() {}
func (*Arguments) node()     {}
func (*WithItem) node()      {}
func (*MatchCase) node()     {}

func (ctxMark) ctx()           {}
func (boolOpMark) boolOp()     {}
func (operatorMark) operator() {}
func (unaryOpMark) unaryOp()   {}
func (cmpOpMark) cmpOp()       {}

func (*FunctionDef) stmt()      {}
func (*AsyncFunctionDef) stmt() {}
func (*ClassDef) stmt()         {}
func (*Return) stmt()           {}
func (*Delete) stmt()           {}
func (*Assign) stmt()           {}
func (*TypeAlias) stmt()        {}
func (*AugAssign) stmt()        {}
func (*AnnAssign) stmt()        {}
func (*For) stmt()              {}
func (*AsyncFor) stmt()         {}
func (*While) stmt()            {}
func (*If) stmt()               {}
func (*With) stmt()             {}
func (*AsyncWith) stmt()        {}
func (*Match) stmt()            {}
func (*Raise) stmt()            {}
func (*Try) stmt()              {}
func (*TryStar) stmt()          {}
func (*Assert) stmt()           {}
func (*Import) stmt()           {}
func (*ImportFrom) stmt()       {}
func (*Global) stmt()           {}
func (*Nonlocal) stmt()         {}
func (*ExprStmt) stmt()         {}
func (*Pass) stmt()             {}
func (*Break) stmt()            {}
func (*Continue) stmt()         {}

func (*BoolOp) expr()         {}
func (*NamedExpr) expr()      {}
func (*BinOp) expr()          {}
func (*UnaryOp) expr()        {}
func (*Lambda) expr()         {}
func (*IfExp) expr()          {}
func (*Dict) expr()           {}
func (*Set) expr()            {}
func (*ListComp) expr()       {}
func (*SetComp) expr()        {}
func (*DictComp) expr()       {}
func (*GeneratorExp) expr()   {}
func (*Await) expr()          {}
func (*Yield) expr()          {}
func (*YieldFrom) expr()      {}
func (*Compare) expr()        {}
func (*Call) expr()           {}
func (*FormattedValue) expr() {}
func (*JoinedStr) expr()      {}
func (*Constant) expr()       {}
func (*Attribute) expr()      {}
func (*Subscript) expr()      {}
func (*Starred) expr()        {}
func (*Name) expr()           {}
func (*List) expr()           {}
func (*Tuple) expr()          {}
func (*Slice) expr()          {}

func (*MatchValue) pattern()     {}
func (*MatchSingleton) pattern() {}
func (*MatchSequence) pattern()  {}
func (*MatchMapping) pattern()   {}
func (*MatchClass) pattern()     {}
func (*MatchStar) pattern()      {}
func (*MatchAs) pattern()        {}
func (*MatchOr) pattern()        {}

func (*TypeVar) typeParam()      {}
func (*ParamSpec) typeParam()    {}
func (*TypeVarTuple) typeParam() {}

// The singletons, shared like CPython's.
var (
	LoadCtx  ExprContext = &Load{}
	storeCtx ExprContext = &Store{}
	delCtx   ExprContext = &Del{}
)

// plan is the reflected `_fields` layout of one node type: field indexes in declaration
// order, the Python field names, and whether the struct carries the `_attributes` block.
type plan struct {
	class  string
	fields []int
	names  []string
	hasPos bool
}

var plans sync.Map // reflect.Type -> *plan

var pyClassName = map[string]string{
	"ExprStmt": "Expr", "Arguments": "arguments", "Arg": "arg", "Keyword": "keyword",
	"Alias": "alias", "WithItem": "withitem", "MatchCase": "match_case", "Comprehension": "comprehension",
}

func planOf(t reflect.Type) *plan {
	if p, ok := plans.Load(t); ok {
		return p.(*plan)
	}
	p := &plan{class: t.Name()}
	if n, ok := pyClassName[p.class]; ok {
		p.class = n
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			p.hasPos = p.hasPos || f.Type == reflect.TypeFor[Pos]()
			continue
		}
		p.fields = append(p.fields, i)
		p.names = append(p.names, snake(f.Name))
	}
	plans.Store(t, p)
	return p
}

func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

var nodeType = reflect.TypeFor[Node]()

// IterChildNodes is ast.iter_child_nodes: node-valued fields and the nodes inside list
// fields, in `_fields` order, skipping None (the expr_context and operator singletons are
// nodes and are yielded).
func IterChildNodes(n Node) []Node {
	v := reflect.ValueOf(n).Elem()
	p := planOf(v.Type())
	var out []Node
	for _, i := range p.fields {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Interface, reflect.Pointer:
			if !f.IsNil() {
				if c, ok := f.Interface().(Node); ok {
					out = append(out, c)
				}
			}
		case reflect.Slice:
			if f.Type().Elem().Implements(nodeType) {
				for j := 0; j < f.Len(); j++ {
					e := f.Index(j)
					if !e.IsNil() {
						out = append(out, e.Interface().(Node))
					}
				}
			}
		}
	}
	return out
}

// Walk is ast.walk: breadth-first, FIFO queue seeded with the root.
func Walk(n Node) iter.Seq[Node] {
	return func(yield func(Node) bool) {
		queue := []Node{n}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if !yield(cur) {
				return
			}
			queue = append(queue, IterChildNodes(cur)...)
		}
	}
}

// Depth is the nesting depth parse._parse_python measures: the root is 0 and every
// ast.iter_child_nodes child (singletons included) is one deeper; iterative.
func Depth(n Node) int { return depth(n, true) }

func depth(n Node, singletons bool) int {
	type item struct {
		n Node
		d int
	}
	stack := []item{{n, 0}}
	deepest := 0
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		deepest = max(deepest, it.d)
		for _, c := range IterChildNodes(it.n) {
			if !singletons && isSingleton(c) {
				continue
			}
			stack = append(stack, item{c, it.d + 1})
		}
	}
	return deepest
}

// isSingleton reports the expr_context, operator, boolop, unaryop and cmpop leaves.
func isSingleton(n Node) bool {
	switch n.(type) {
	case ExprContext, Operator, BoolOperator, UnaryOperator, CmpOp:
		return true
	}
	return false
}

// Dotted is _pyast.dotted: "a.b.c" for a Name/Attribute chain, "" otherwise.
func Dotted(n Node) string {
	var parts []string
	for {
		a, ok := n.(*Attribute)
		if !ok {
			break
		}
		parts = append(parts, a.Attr)
		n = a.Value
	}
	name, ok := n.(*Name)
	if !ok {
		return ""
	}
	parts = append(parts, name.Id)
	slices.Reverse(parts)
	return strings.Join(parts, ".")
}
