package opengrep

import (
	"bytes"
	"cmp"
	"math"
	"math/big"
	"reflect"
	"slices"
	"strings"

	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pyast"
	"github.com/traceforce/skill-xray/internal/pytext"
)

var pyTaintVectors = pytext.Set("SXV-008", "SXV-018", "SXV-019")

var pySinks = pytext.Set(
	"os.system", "os.popen", "subprocess.run", "subprocess.call",
	"os.execl", "os.execle", "os.execlp", "os.execlpe", "os.execv", "os.execve",
	"os.execvp", "os.execvpe", "os.posix_spawn", "os.posix_spawnp",
	"os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
	"os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
	"subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
	"subprocess.getoutput", "subprocess.getstatusoutput",
)

var pyBuiltinSinks = pytext.Set("eval", "exec")

func canonicalSink(name string) bool {
	return pySinks[name] || name == "builtins.eval" || name == "builtins.exec"
}

// marker is one of the three identity-compared sentinels (_UNKNOWN, _SOURCE_MARKER, _OTHER_MARKER).
type marker struct{ name string }

var (
	unknown      = &marker{"unknown"}
	sourceMarker = &marker{"source"}
	otherMarker  = &marker{"other"}
)

// tri is a Python bool | None.
type tri int8

const (
	triFalse tri = iota
	triTrue
	triNone
)

func triOf(b bool) tri {
	if b {
		return triTrue
	}
	return triFalse
}

// parsePython is _pyast.parse with every parser failure mapped to None; a test counts calls.
var parsePython = func(src string) *pyast.Module {
	m, err := pyast.Parse(src)
	if err != nil {
		return nil
	}
	return m
}

// ---- node helpers ---------------------------------------------------------------------------

var posType = reflect.TypeFor[pyast.Pos]()

// posOf is the `_attributes` block of a positioned node; ok is false for Module, arguments,
// comprehension, withitem, match_case and the singletons (Python raises AttributeError).
func posOf(n pyast.Node) (pyast.Pos, bool) {
	v := reflect.ValueOf(n)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return pyast.Pos{}, false
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct || v.NumField() == 0 || v.Type().Field(0).Type != posType {
		return pyast.Pos{}, false
	}
	return v.Field(0).Interface().(pyast.Pos), true
}

// endLine is `node.end_lineno or node.lineno`.
func endLine(p pyast.Pos) int { return cmp.Or(p.EndLineno, p.Lineno) }

// inLines is `node.lineno <= line <= (node.end_lineno or node.lineno)`.
func inLines(n pyast.Node, line int) bool {
	p, ok := posOf(n)
	return ok && p.Lineno <= line && line <= endLine(p)
}

func isFunctionScope(n pyast.Node) bool {
	switch n.(type) {
	case *pyast.FunctionDef, *pyast.AsyncFunctionDef, *pyast.Lambda:
		return true
	}
	return false
}

func isComprehensionScope(n pyast.Node) bool {
	switch n.(type) {
	case *pyast.ListComp, *pyast.SetComp, *pyast.DictComp, *pyast.GeneratorExp:
		return true
	}
	return false
}

func isScope(n pyast.Node) bool {
	_, class := n.(*pyast.ClassDef)
	return class || isFunctionScope(n) || isComprehensionScope(n)
}

func isDef(n pyast.Node) bool {
	switch n.(type) {
	case *pyast.FunctionDef, *pyast.AsyncFunctionDef:
		return true
	}
	return false
}

// bodyOf is `getattr(scope, "body", ())` when that is a statement list.
func bodyOf(n pyast.Node) []pyast.Stmt {
	switch x := n.(type) {
	case *pyast.Module:
		return x.Body
	case *pyast.FunctionDef:
		return x.Body
	case *pyast.AsyncFunctionDef:
		return x.Body
	case *pyast.ClassDef:
		return x.Body
	}
	return nil
}

func argsOf(n pyast.Node) *pyast.Arguments {
	switch x := n.(type) {
	case *pyast.FunctionDef:
		return x.Args
	case *pyast.AsyncFunctionDef:
		return x.Args
	case *pyast.Lambda:
		return x.Args
	}
	return nil
}

// params lists every parameter of a function scope (posonly, args, kwonly, *args, **kwargs).
func params(a *pyast.Arguments) []*pyast.Arg {
	if a == nil {
		return nil
	}
	out := slices.Concat(a.Posonlyargs, a.Args, a.Kwonlyargs)
	for _, extra := range []*pyast.Arg{a.Vararg, a.Kwarg} {
		if extra != nil {
			out = append(out, extra)
		}
	}
	return out
}

func generatorsOf(n pyast.Node) []*pyast.Comprehension {
	switch x := n.(type) {
	case *pyast.ListComp:
		return x.Generators
	case *pyast.SetComp:
		return x.Generators
	case *pyast.DictComp:
		return x.Generators
	case *pyast.GeneratorExp:
		return x.Generators
	}
	return nil
}

// defName is `.name` of a def, async def or class; "" otherwise.
func defName(n pyast.Node) string {
	switch x := n.(type) {
	case *pyast.FunctionDef:
		return x.Name
	case *pyast.AsyncFunctionDef:
		return x.Name
	case *pyast.ClassDef:
		return x.Name
	}
	return ""
}

func decoratorsOf(n pyast.Node) []pyast.Expr {
	switch x := n.(type) {
	case *pyast.FunctionDef:
		return x.DecoratorList
	case *pyast.AsyncFunctionDef:
		return x.DecoratorList
	}
	return nil
}

func isStore(ctx pyast.ExprContext) bool { _, ok := ctx.(*pyast.Store); return ok }
func isDel(ctx pyast.ExprContext) bool   { _, ok := ctx.(*pyast.Del); return ok }

// cutDot is raw.partition("."): rest is "" or the "."-prefixed tail.
func cutDot(raw string) (name, rest string) {
	name, _, _ = strings.Cut(raw, ".")
	return name, raw[len(name):]
}

// containsPosition is _contains_position; col 0 is Python None.
func containsPosition(n pyast.Node, line, col int) bool {
	p, ok := posOf(n)
	if !ok || !(p.Lineno <= line && line <= endLine(p)) {
		return false
	}
	if col < 1 {
		return true
	}
	point := col - 1
	end := cmp.Or(p.EndColOffset, point)
	return (line != p.Lineno || point >= p.ColOffset) && (line != p.EndLineno || point <= end)
}

// before is _before: the node ends before (line, col); col 0 is None.
func before(n pyast.Node, line, col int) bool {
	p, ok := posOf(n)
	if !ok {
		return false
	}
	end := endLine(p)
	return end < line || (end == line && col != 0 && p.EndColOffset < col)
}

// scopeChain is _scope_chain: the module plus every scope containing the position, sorted by
// (lineno, -end_lineno), minus classes that enclose a later function scope.
func scopeChain(tree *pyast.Module, line, col int) []pyast.Node {
	var scopes []pyast.Node
	for n := range pyast.Walk(tree) {
		if isScope(n) && containsPosition(n, line, col) {
			scopes = append(scopes, n)
		}
	}
	slices.SortStableFunc(scopes, func(a, b pyast.Node) int {
		pa, _ := posOf(a)
		pb, _ := posOf(b)
		return cmp.Or(cmp.Compare(pa.Lineno, pb.Lineno), cmp.Compare(-pa.EndLineno, -pb.EndLineno))
	})
	out := []pyast.Node{tree}
	for i, s := range scopes {
		if _, class := s.(*pyast.ClassDef); class && slices.ContainsFunc(scopes[i+1:], isFunctionScope) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// scopeNodes is _scope_nodes: a LIFO walk of the scope that does not enter nested scopes.
func scopeNodes(scope pyast.Node) []pyast.Node {
	stack := pyast.IterChildNodes(scope)
	var out []pyast.Node
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		out = append(out, n)
		if !isScope(n) {
			stack = append(stack, pyast.IterChildNodes(n)...)
		}
	}
	return out
}

// ---- bindings -------------------------------------------------------------------------------

// binding is the ("import"|"sink"|"other"|"delete", origin) pair; kind "" is None.
type binding struct{ kind, origin string }

func (b binding) ok() bool { return b.kind != "" }

func importBinding(n pyast.Node, name string) binding {
	switch x := n.(type) {
	case *pyast.Import:
		for _, a := range slices.Backward(x.Names) {
			first, _, _ := strings.Cut(a.Name, ".")
			if cmp.Or(a.Asname, first) == name {
				if a.Asname != "" {
					return binding{"import", a.Name}
				}
				return binding{"import", first}
			}
		}
	case *pyast.ImportFrom:
		for _, a := range slices.Backward(x.Names) {
			if a.Name != "*" && cmp.Or(a.Asname, a.Name) == name {
				origin := a.Name
				if x.Module != "" {
					origin = x.Module + "." + a.Name
				}
				return binding{"import", strings.Repeat(".", x.Level) + origin}
			}
		}
	}
	return binding{}
}

func targetBinds(n pyast.Node, name string) bool {
	switch x := n.(type) {
	case *pyast.Name:
		return x.Id == name
	case *pyast.Tuple:
		return slices.ContainsFunc(x.Elts, func(e pyast.Expr) bool { return targetBinds(e, name) })
	case *pyast.List:
		return slices.ContainsFunc(x.Elts, func(e pyast.Expr) bool { return targetBinds(e, name) })
	case *pyast.Starred:
		return targetBinds(x.Value, name)
	}
	return false
}

func anyBinds(targets []pyast.Expr, name string) bool {
	return slices.ContainsFunc(targets, func(t pyast.Expr) bool { return targetBinds(t, name) })
}

func statementBinding(n pyast.Node, name string) binding {
	if b := importBinding(n, name); b.ok() {
		return b
	}
	if def := defName(n); def != "" {
		if def == name {
			return binding{"other", ""}
		}
		return binding{}
	}
	var targets []pyast.Expr
	switch x := n.(type) {
	case *pyast.Assign:
		if anyBinds(x.Targets, name) {
			if sink := pyast.Dotted(x.Value); pySinks[sink] {
				return binding{"sink", sink}
			}
		}
		targets = x.Targets
	case *pyast.AnnAssign:
		if x.Value != nil {
			targets = []pyast.Expr{x.Target}
		}
	case *pyast.AugAssign:
		targets = []pyast.Expr{x.Target}
	case *pyast.Delete:
		if anyBinds(x.Targets, name) {
			return binding{"delete", ""}
		}
		return binding{}
	}
	if anyBinds(targets, name) {
		return binding{"other", ""}
	}
	return binding{}
}

// assignTargets is (targets, value) of an Assign or AnnAssign; ok false for other statements.
func assignTargets(n pyast.Node) (targets []pyast.Expr, value pyast.Expr, ok bool) {
	switch x := n.(type) {
	case *pyast.Assign:
		return x.Targets, x.Value, true
	case *pyast.AnnAssign:
		return []pyast.Expr{x.Target}, x.Value, true
	}
	return nil, nil, false
}

func preservesNameBinding(n pyast.Node, name string) bool {
	targets, value, ok := assignTargets(n)
	return ok && value != nil && pyast.Dotted(value) == name && anyBinds(targets, name)
}

func lastBinding(scope pyast.Node, name string, line, col int) binding {
	var b binding
	if args := argsOf(scope); args != nil && slices.ContainsFunc(params(args), func(a *pyast.Arg) bool { return a.Arg == name }) {
		b = binding{"other", ""}
	}
	if slices.ContainsFunc(generatorsOf(scope), func(g *pyast.Comprehension) bool { return targetBinds(g.Target, name) }) {
		b = binding{"other", ""}
	}
	for _, st := range bodyOf(scope) {
		if before(st, line, col) && !preservesNameBinding(st, name) {
			if sb := statementBinding(st, name); sb.ok() {
				b = sb
			}
		}
	}
	return b
}

func bindingAt(scopes []pyast.Node, name string, line, col int) binding {
	for _, scope := range slices.Backward(scopes) {
		if b := lastBinding(scope, name, line, col); b.ok() {
			return b
		}
	}
	return binding{}
}

func starImportsSink(n pyast.Node, name string, line, col int) bool {
	imp, ok := n.(*pyast.ImportFrom)
	if !ok || !before(n, line, col) {
		return false
	}
	star := slices.ContainsFunc(imp.Names, func(a *pyast.Alias) bool { return a.Name == "*" })
	return star && canonicalSink(imp.Module+"."+name)
}

func hasSinkImport(scopes []pyast.Node, name, suffix string, line, col int) bool {
	if b := bindingAt(scopes, name, line, col); b.ok() {
		return b.kind == "sink" || b.kind == "import" && canonicalSink(b.origin+suffix)
	}
	for _, scope := range slices.Backward(scopes) {
		for _, st := range bodyOf(scope) {
			if starImportsSink(st, name, line, col) {
				return true
			}
		}
	}
	return false
}

func wasSinkImported(scopes []pyast.Node, name, suffix string, line, col int) bool {
	for _, scope := range scopes {
		for _, st := range bodyOf(scope) {
			switch st.(type) {
			case *pyast.Import, *pyast.ImportFrom:
			default:
				continue
			}
			if !before(st, line, col) {
				continue
			}
			if b := importBinding(st, name); b.ok() && canonicalSink(b.origin+suffix) {
				return true
			}
			if starImportsSink(st, name, line, col) {
				return true
			}
		}
	}
	return false
}

// targetPath is _target_path: the dotted path an Attribute or Subscript target rebinds.
func targetPath(t pyast.Expr) string {
	switch x := t.(type) {
	case *pyast.Attribute:
		return pyast.Dotted(x)
	case *pyast.Subscript:
		return pyast.Dotted(x.Value)
	}
	return ""
}

func assignedExpression(scopes []pyast.Node, name string, line, col int) (pyast.Expr, pyast.Stmt) {
	for _, scope := range slices.Backward(scopes) {
		for _, st := range slices.Backward(bodyOf(scope)) {
			if !before(st, line, col) {
				continue
			}
			if targets, value, ok := assignTargets(st); ok && value != nil && anyBinds(targets, name) {
				return value, st
			}
		}
	}
	return nil, nil
}

func callableIdentity(scopes []pyast.Node, raw string, line, col int, seen []string) string {
	if slices.Contains(seen, raw) || len(seen) >= 16 {
		return ""
	}
	name, rest := cutDot(raw)
	b := bindingAt(scopes, name, line, col)
	if b.kind == "import" || b.kind == "sink" {
		return b.origin + rest
	}
	if value, st := assignedExpression(scopes, name, line, col); st != nil {
		p, _ := posOf(st)
		path := pyast.Dotted(value)
		seen = append(slices.Clone(seen), raw)
		switch {
		case path == name:
			return callableIdentity(scopes, raw, p.Lineno, p.ColOffset+1, seen)
		case path != "":
			if base := callableIdentity(scopes, path, p.Lineno, p.ColOffset+1, seen); base != "" {
				return base + rest
			}
		}
		return ""
	}
	if !b.ok() && (pyBuiltinSinks[name] || name == "input" || name == "raw_input" || name == "print") {
		return "builtins." + raw
	}
	return ""
}

func isLiteralShape(e pyast.Expr) bool {
	switch e.(type) {
	case *pyast.Lambda, *pyast.Constant, *pyast.Dict, *pyast.List, *pyast.Set, *pyast.Tuple:
		return true
	}
	return false
}

func qualifiedRebound(scopes []pyast.Node, raw string, line, col int, unknownIsRebound bool) bool {
	for _, scope := range scopes {
		for _, st := range bodyOf(scope) {
			if !before(st, line, col) {
				continue
			}
			var targets []pyast.Expr
			var value pyast.Expr
			switch x := st.(type) {
			case *pyast.Assign:
				targets, value = x.Targets, x.Value
			case *pyast.AnnAssign:
				targets, value = []pyast.Expr{x.Target}, x.Value
			case *pyast.AugAssign:
				targets = []pyast.Expr{x.Target}
			case *pyast.Delete:
				targets = x.Targets
			default:
				continue
			}
			if raw == "" || !slices.ContainsFunc(targets, func(t pyast.Expr) bool { return targetPath(t) == raw }) {
				continue
			}
			if value == nil {
				return true
			}
			p, _ := posOf(st)
			expected := callableIdentity(scopes, raw, p.Lineno, p.ColOffset+1, nil)
			actual := ""
			if path := pyast.Dotted(value); path != "" {
				actual = callableIdentity(scopes, path, p.Lineno, p.ColOffset+1, nil)
			}
			if expected != "" && actual == expected {
				continue
			}
			if actual != "" || isLiteralShape(value) {
				return true
			}
			// Unknown assignments are not proof that the source or sink disappeared.
			return unknownIsRebound
		}
	}
	return false
}

func sinkIsShadowed(tree *pyast.Module, line, col int) bool {
	scopes := scopeChain(tree, line, col)
	for _, n := range scopeNodes(scopes[len(scopes)-1]) {
		c, ok := n.(*pyast.Call)
		if !ok || !containsPosition(c, line, col) {
			continue
		}
		call := pyast.Dotted(c.Func)
		if call == "" {
			continue
		}
		name, suffix := cutDot(call)
		builtin := suffix == "" && pyBuiltinSinks[name]
		b := bindingAt(scopes, name, line, col)
		importedSink := hasSinkImport(scopes, name, suffix, line, col)
		if !builtin && !importedSink {
			if canonicalSink(call) || wasSinkImported(scopes, name, suffix, line, col) {
				return true
			}
			continue
		}
		if builtin && b.ok() && !(b.kind == "delete" || b.kind == "import" && b.origin == "builtins."+name) {
			return true
		}
		if !builtin && b.ok() && !(b.kind == "sink" || b.kind == "import" && canonicalSink(b.origin+suffix)) {
			return true
		}
		canonical := call
		switch {
		case builtin:
			canonical = "builtins." + name
		case b.kind == "import":
			canonical = b.origin + suffix
		}
		if qualifiedRebound(scopes, call, line, col, false) || canonical != call && qualifiedRebound(scopes, canonical, line, col, false) {
			return true
		}
	}
	return false
}

// ---- Python literal values -----------------------------------------------------------------
//
// Values are nil, bool, int64, *big.Int, float64, complex128, string, []byte,
// pyast.EllipsisValue, []any (list), pyast.TupleValue, pyast.SetValue, *pyDict, or a *marker.

// pyDict is a Python dict over literal values: insertion-ordered, keys compared as Python does.
type pyDict struct{ keys, values []any }

func (d *pyDict) index(k any) int {
	return slices.IndexFunc(d.keys, func(key any) bool { return pyEqual(key, k) })
}

func (d *pyDict) get(k any) (any, bool) {
	if i := d.index(k); i >= 0 {
		return d.values[i], true
	}
	return nil, false
}

func (d *pyDict) set(k, v any) {
	if i := d.index(k); i >= 0 {
		d.values[i] = v
		return
	}
	d.keys, d.values = append(d.keys, k), append(d.values, v)
}

func (d *pyDict) clone() *pyDict {
	return &pyDict{slices.Clone(d.keys), slices.Clone(d.values)}
}

// merged is {**a, **b} (and a | b).
func merged(a, b *pyDict) *pyDict {
	out := a.clone()
	for i, k := range b.keys {
		out.set(k, b.values[i])
	}
	return out
}

func hashable(v any) bool {
	switch x := v.(type) {
	case []any, pyast.SetValue, *pyDict:
		return false
	case pyast.TupleValue:
		return !slices.ContainsFunc(x, func(e any) bool { return !hashable(e) })
	}
	return true
}

func isNumber(v any) bool {
	switch v.(type) {
	case bool, int64, *big.Int, float64, complex128:
		return true
	}
	return false
}

// asReal is the exact value of a real number; ok false for complex and NaN.
func asReal(v any) (*big.Float, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return big.NewFloat(1), true
		}
		return big.NewFloat(0), true
	case int64:
		return new(big.Float).SetInt64(x), true
	case *big.Int:
		return new(big.Float).SetInt(x), true
	case float64:
		if math.IsNaN(x) {
			return nil, false
		}
		return big.NewFloat(x), true
	}
	return nil, false
}

func asComplex(v any) (complex128, bool) {
	if c, ok := v.(complex128); ok {
		return c, true
	}
	r, ok := asReal(v)
	if !ok {
		return 0, false
	}
	f, _ := r.Float64()
	return complex(f, 0), true
}

// pyEqual is Python ==: numbers across types, structural containers, identity for markers.
func pyEqual(a, b any) bool {
	if isNumber(a) && isNumber(b) {
		if _, ca := a.(complex128); ca {
			return complexEqual(a, b)
		}
		if _, cb := b.(complex128); cb {
			return complexEqual(a, b)
		}
		x, okx := asReal(a)
		y, oky := asReal(b)
		return okx && oky && x.Cmp(y) == 0
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []byte:
		y, ok := b.([]byte)
		return ok && bytes.Equal(x, y)
	case pyast.EllipsisValue:
		_, ok := b.(pyast.EllipsisValue)
		return ok
	case []any:
		y, ok := b.([]any)
		return ok && slices.EqualFunc(x, y, pyEqual)
	case pyast.TupleValue:
		y, ok := b.(pyast.TupleValue)
		return ok && slices.EqualFunc(x, y, pyEqual)
	case pyast.SetValue:
		y, ok := b.(pyast.SetValue)
		return ok && len(x) == len(y) && !slices.ContainsFunc(x, func(e any) bool { return !containsEqual(y, e) })
	case *pyDict:
		y, ok := b.(*pyDict)
		if !ok || len(x.keys) != len(y.keys) {
			return false
		}
		for i, k := range x.keys {
			if v, found := y.get(k); !found || !pyEqual(x.values[i], v) {
				return false
			}
		}
		return true
	case *marker:
		y, ok := b.(*marker)
		return ok && x == y
	}
	return false
}

func complexEqual(a, b any) bool {
	x, okx := asComplex(a)
	y, oky := asComplex(b)
	return okx && oky && x == y
}

func containsEqual(items []any, v any) bool {
	return slices.ContainsFunc(items, func(e any) bool { return pyEqual(e, v) })
}

// literalTruthy is bool(v) over literal-eval values; pytext.Truthy is the JSON-value one.
func literalTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int64:
		return x != 0
	case *big.Int:
		return x.Sign() != 0
	case float64:
		return x != 0
	case complex128:
		return x != 0
	case string:
		return x != ""
	case []byte:
		return len(x) > 0
	case []any:
		return len(x) > 0
	case pyast.TupleValue:
		return len(x) > 0
	case pyast.SetValue:
		return len(x) > 0
	case *pyDict:
		return len(x.keys) > 0
	}
	return true
}

// pyIs is `a is b`.
// ponytail: identity is modelled as same-type equality for scalars and never-identical for
// containers; the bridge only compares literals, and CPython's small-int and string interning
// is not reproduced.
func pyIs(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if x, ok := a.(*marker); ok {
		return b == any(x)
	}
	switch a.(type) {
	case []any, pyast.TupleValue, pyast.SetValue, *pyDict:
		return false
	}
	return reflect.TypeOf(a) == reflect.TypeOf(b) && pyEqual(a, b)
}

// pyOrder is a < b (strict) or a <= b; ok false is TypeError.
func pyOrder(a, b any, strict bool) (bool, bool) {
	less := func(c int) bool { return c < 0 || !strict && c == 0 }
	if isNumber(a) && isNumber(b) {
		x, okx := asReal(a)
		y, oky := asReal(b)
		return okx && oky && less(x.Cmp(y)), okx && oky
	}
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && less(strings.Compare(x, y)), ok
	case []byte:
		y, ok := b.([]byte)
		return ok && less(bytes.Compare(x, y)), ok
	case []any:
		if y, ok := b.([]any); ok {
			return seqOrder(x, y, strict)
		}
	case pyast.TupleValue:
		if y, ok := b.(pyast.TupleValue); ok {
			return seqOrder(x, y, strict)
		}
	case pyast.SetValue:
		if y, ok := b.(pyast.SetValue); ok {
			return isSubset(x, y) && (!strict || len(x) < len(y)), true
		}
	}
	return false, false
}

// seqOrder orders two sequences: the first unequal pair decides, else the lengths do.
func seqOrder(a, b []any, strict bool) (bool, bool) {
	for i := 0; i < len(a) && i < len(b); i++ {
		if !pyEqual(a[i], b[i]) {
			return pyOrder(a[i], b[i], strict)
		}
	}
	return len(a) < len(b) || !strict && len(a) == len(b), true
}

func isSubset(a, b pyast.SetValue) bool {
	return !slices.ContainsFunc(a, func(e any) bool { return !containsEqual(b, e) })
}

// pyIn is `a in b`.
func pyIn(a, b any) (bool, bool) {
	switch c := b.(type) {
	case string:
		s, ok := a.(string)
		return ok && strings.Contains(c, s), ok
	case []byte:
		switch x := a.(type) {
		case []byte:
			return bytes.Contains(c, x), true
		case int64:
			if 0 <= x && x <= 255 {
				return bytes.IndexByte(c, byte(x)) >= 0, true
			}
		}
		return false, false
	case []any:
		return containsEqual(c, a), true
	case pyast.TupleValue:
		return containsEqual(c, a), true
	case pyast.SetValue:
		return hashable(a) && containsEqual(c, a), hashable(a)
	case *pyDict:
		if !hashable(a) {
			return false, false
		}
		_, found := c.get(a)
		return found, true
	}
	return false, false
}

// compareOp evaluates one comparison operator; ok false is TypeError.
func compareOp(op pyast.CmpOp, a, b any) (bool, bool) {
	switch op.(type) {
	case *pyast.Eq:
		return pyEqual(a, b), true
	case *pyast.NotEq:
		return !pyEqual(a, b), true
	case *pyast.Is:
		return pyIs(a, b), true
	case *pyast.IsNot:
		return !pyIs(a, b), true
	case *pyast.Lt:
		return pyOrder(a, b, true)
	case *pyast.LtE:
		return pyOrder(a, b, false)
	case *pyast.Gt:
		return pyOrder(b, a, true)
	case *pyast.GtE:
		return pyOrder(b, a, false)
	case *pyast.In:
		return pyIn(a, b)
	case *pyast.NotIn:
		r, ok := pyIn(a, b)
		return !r, ok
	}
	return false, false
}

// seqIndex resolves a Python index into a sequence of length n; ok false is IndexError or
// TypeError.
func seqIndex(key any, n int) (int, bool) {
	var i int64
	switch k := key.(type) {
	case bool:
		if k {
			i = 1
		}
	case int64:
		i = k
	default:
		return 0, false
	}
	if i < 0 {
		i += int64(n)
	}
	return int(i), 0 <= i && i < int64(n)
}

// pySubscript is owner[key]; ok false where Python raises KeyError, IndexError or TypeError.
func pySubscript(owner, key any) (any, bool) {
	switch o := owner.(type) {
	case *pyDict:
		if !hashable(key) {
			return nil, false
		}
		return o.get(key)
	case []any:
		if i, ok := seqIndex(key, len(o)); ok {
			return o[i], true
		}
	case pyast.TupleValue:
		if i, ok := seqIndex(key, len(o)); ok {
			return o[i], true
		}
	case string:
		runes := []rune(o)
		if i, ok := seqIndex(key, len(runes)); ok {
			return string(runes[i]), true
		}
	case []byte:
		if i, ok := seqIndex(key, len(o)); ok {
			return int64(o[i]), true
		}
	}
	return nil, false
}

// toDict is dict(v): a copy of a dict, or the pairs of an iterable of 2-sequences.
// ponytail: str/bytes elements of length 2 are not accepted as pairs.
func toDict(v any) (*pyDict, bool) {
	var items []any
	switch x := v.(type) {
	case *pyDict:
		return x.clone(), true
	case []any:
		items = x
	case pyast.TupleValue:
		items = x
	case pyast.SetValue:
		items = x
	case string:
		return &pyDict{}, x == ""
	case []byte:
		return &pyDict{}, len(x) == 0
	default:
		return nil, false
	}
	d := &pyDict{}
	for _, item := range items {
		var pair []any
		switch p := item.(type) {
		case []any:
			pair = p
		case pyast.TupleValue:
			pair = p
		}
		if len(pair) != 2 || !hashable(pair[0]) {
			return nil, false
		}
		d.set(pair[0], pair[1])
	}
	return d, true
}

// toSet is set(items): TypeError (ok false) on an unhashable member, equal members kept once.
func toSet(items []any) (pyast.SetValue, bool) {
	set := pyast.SetValue{}
	for _, e := range items {
		if !hashable(e) {
			return nil, false
		}
		if !containsEqual(set, e) {
			set = append(set, e)
		}
	}
	return set, true
}

// fromLiteral converts pyast.LiteralEval output into the value model, applying Python key
// equality and hashability (TypeError is ok false).
func fromLiteral(v any) (any, bool) {
	convert := func(items []any) ([]any, bool) {
		out := make([]any, len(items))
		for i, e := range items {
			var ok bool
			if out[i], ok = fromLiteral(e); !ok {
				return nil, false
			}
		}
		return out, true
	}
	switch x := v.(type) {
	case pyast.DictValue:
		keys, ok := convert(x.Keys)
		if !ok {
			return nil, false
		}
		values, ok := convert(x.Values)
		if !ok {
			return nil, false
		}
		d := &pyDict{}
		for i, k := range keys {
			if !hashable(k) {
				return nil, false
			}
			d.set(k, values[i])
		}
		return d, true
	case []any:
		return convert(x)
	case pyast.TupleValue:
		items, ok := convert(x)
		return pyast.TupleValue(items), ok
	case pyast.SetValue:
		items, ok := convert(x)
		if !ok {
			return nil, false
		}
		return toSet(items)
	}
	return v, true
}

// literalEval is ast.literal_eval; ok false is ValueError or TypeError.
func literalEval(n pyast.Node) (any, bool) {
	if n == nil {
		return nil, false
	}
	v, ok := pyast.LiteralEval(n)
	if !ok {
		return nil, false
	}
	return fromLiteral(v)
}

// ---- the static evaluator (_static_value and friends) ----------------------------------------

func valueOf(values map[string]any, name string) any {
	if v, ok := values[name]; ok {
		return v
	}
	return unknown
}

func staticValue(n pyast.Expr, values map[string]any) any {
	switch x := n.(type) {
	case nil:
		return unknown
	case *pyast.Name:
		return valueOf(values, x.Id)
	case *pyast.Dict:
		d := &pyDict{}
		keys := make([]any, len(x.Keys))
		items := make([]any, len(x.Values))
		for i := range x.Keys {
			keys[i] = staticValue(x.Keys[i], values)
			items[i] = staticValue(x.Values[i], values)
			if keys[i] == unknown || items[i] == unknown {
				return unknown
			}
		}
		for i, k := range keys {
			if !hashable(k) {
				return unknown
			}
			d.set(k, items[i])
		}
		return d
	case *pyast.List, *pyast.Tuple, *pyast.Set:
		var elts []pyast.Expr
		switch c := x.(type) {
		case *pyast.List:
			elts = c.Elts
		case *pyast.Tuple:
			elts = c.Elts
		case *pyast.Set:
			elts = c.Elts
		}
		items := make([]any, 0, len(elts))
		for _, e := range elts {
			v := staticValue(e, values)
			if v == unknown {
				return unknown
			}
			items = append(items, v)
		}
		switch x.(type) {
		case *pyast.Tuple:
			return pyast.TupleValue(items)
		case *pyast.Set:
			if set, ok := toSet(items); ok {
				return set
			}
			return unknown
		}
		return items
	case *pyast.UnaryOp:
		if _, not := x.Op.(*pyast.Not); not {
			if v := staticValue(x.Operand, values); v != unknown {
				return !literalTruthy(v)
			}
			return unknown
		}
	case *pyast.BoolOp:
		_, and := x.Op.(*pyast.And)
		result := staticValue(x.Values[0], values)
		for _, item := range x.Values[1:] {
			if result == unknown {
				return unknown
			}
			if and && !literalTruthy(result) || !and && literalTruthy(result) {
				return result
			}
			result = staticValue(item, values)
		}
		return result
	case *pyast.Compare:
		left := staticValue(x.Left, values)
		if left == unknown {
			return unknown
		}
		rights := make([]any, len(x.Comparators))
		for i, c := range x.Comparators {
			if rights[i] = staticValue(c, values); rights[i] == unknown {
				return unknown
			}
		}
		for i, op := range x.Ops {
			r, ok := compareOp(op, left, rights[i])
			if !ok {
				return unknown
			}
			if !r {
				return false
			}
			left = rights[i]
		}
		return true
	case *pyast.BinOp:
		if _, or := x.Op.(*pyast.BitOr); or {
			left, okl := staticValue(x.Left, values).(*pyDict)
			right, okr := staticValue(x.Right, values).(*pyDict)
			if okl && okr {
				return merged(left, right)
			}
			return unknown
		}
	case *pyast.Subscript:
		owner, key := staticValue(x.Value, values), staticValue(x.Slice, values)
		if owner == unknown || key == unknown {
			return unknown
		}
		if v, ok := pySubscript(owner, key); ok {
			return v
		}
		return unknown
	case *pyast.Call:
		return staticCall(x, values)
	}
	if v, ok := literalEval(n); ok {
		return v
	}
	return unknown
}

// staticCall handles dict(...) and mapping.get(...); everything else is unknown.
func staticCall(x *pyast.Call, values map[string]any) any {
	if pyast.Dotted(x.Func) == "dict" {
		// values.get("dict", None) is not _UNKNOWN: absent or any non-unknown value proceeds.
		if v, shadowed := values["dict"]; !shadowed || v != unknown {
			if len(x.Args) > 1 || slices.ContainsFunc(x.Keywords, func(k *pyast.Keyword) bool { return k.Arg == "" }) {
				return unknown
			}
			result := &pyDict{}
			if len(x.Args) == 1 {
				d, ok := toDict(staticValue(x.Args[0], values))
				if !ok {
					return unknown
				}
				result = d
			}
			for _, k := range x.Keywords {
				v := staticValue(k.Value, values)
				if v == unknown {
					return unknown
				}
				result.set(k.Arg, v)
			}
			return result
		}
	}
	if attr, ok := x.Func.(*pyast.Attribute); ok && attr.Attr == "get" {
		if len(x.Args) < 1 || len(x.Args) > 2 || len(x.Keywords) > 0 {
			return unknown
		}
		owner, isDict := staticValue(attr.Value, values).(*pyDict)
		key := staticValue(x.Args[0], values)
		var dflt any
		if len(x.Args) > 1 {
			dflt = staticValue(x.Args[1], values)
		}
		if !isDict || key == unknown || len(x.Args) > 1 && dflt == unknown || !hashable(key) {
			// ponytail: an unhashable key raises TypeError out of the oracle; here it is unknown.
			return unknown
		}
		if v, found := owner.get(key); found {
			return v
		}
		return dflt
	}
	return unknown
}

func assignStatic(target pyast.Expr, value any, values map[string]any) {
	switch t := target.(type) {
	case *pyast.Name:
		values[t.Id] = value
	case *pyast.Subscript:
		owner, ok := t.Value.(*pyast.Name)
		if !ok {
			return
		}
		key := staticValue(t.Slice, values)
		item, isDict := valueOf(values, owner.Id).(*pyDict)
		if isDict && key != unknown && value != unknown && hashable(key) {
			// ponytail: an unhashable key raises TypeError out of the oracle; here it is unknown.
			item = item.clone()
			item.set(key, value)
			values[owner.Id] = item
			return
		}
		values[owner.Id] = unknown
	}
}

func applyStatic(st pyast.Stmt, values map[string]any) {
	if name := defName(st); name != "" {
		values[name] = unknown
		return
	}
	switch x := st.(type) {
	case *pyast.Assign:
		value := staticValue(x.Value, values)
		for _, t := range x.Targets {
			assignStatic(t, value, values)
		}
	case *pyast.AnnAssign:
		if x.Value != nil {
			assignStatic(x.Target, staticValue(x.Value, values), values)
		}
	case *pyast.AugAssign:
		name, ok := x.Target.(*pyast.Name)
		if !ok {
			return
		}
		left, okl := valueOf(values, name.Id).(*pyDict)
		right, okr := staticValue(x.Value, values).(*pyDict)
		if _, or := x.Op.(*pyast.BitOr); or && okl && okr {
			values[name.Id] = merged(left, right)
		} else {
			values[name.Id] = unknown
		}
	case *pyast.Import:
		for _, a := range x.Names {
			first, _, _ := strings.Cut(a.Name, ".")
			values[cmp.Or(a.Asname, first)] = unknown
		}
	case *pyast.ImportFrom:
		for _, a := range x.Names {
			first, _, _ := strings.Cut(a.Name, ".")
			values[cmp.Or(a.Asname, first)] = unknown
		}
	case *pyast.ExprStmt:
		call, ok := x.Value.(*pyast.Call)
		if !ok {
			return
		}
		attr, ok := call.Func.(*pyast.Attribute)
		if !ok || attr.Attr != "update" {
			return
		}
		owner, ok := attr.Value.(*pyast.Name)
		if !ok {
			return
		}
		current, isDict := valueOf(values, owner.Id).(*pyDict)
		synthetic := &pyast.Call{Func: &pyast.Name{Id: "dict", Ctx: pyast.LoadCtx}, Args: call.Args, Keywords: call.Keywords}
		additions, isAdded := staticValue(synthetic, values).(*pyDict)
		if isDict && isAdded {
			values[owner.Id] = merged(current, additions)
		} else {
			values[owner.Id] = unknown
		}
	}
}

func staticValuesAt(tree *pyast.Module, line, col int) map[string]any {
	values := map[string]any{}
	scopes := scopeChain(tree, line, col)
	for i, scope := range scopes {
		if args := argsOf(scope); args != nil {
			for _, a := range params(args) {
				values[a.Arg] = unknown
			}
		} else {
			for _, g := range generatorsOf(scope) {
				for n := range pyast.Walk(g.Target) {
					if name, ok := n.(*pyast.Name); ok {
						values[name.Id] = unknown
					}
				}
			}
		}
		limit := line
		if i+1 < len(scopes) {
			p, _ := posOf(scopes[i+1])
			limit = p.Lineno
		}
		for _, st := range bodyOf(scope) {
			if before(st, limit, col) {
				applyStatic(st, values)
			}
		}
	}
	return values
}

var runLike = pytext.Set("run", "call", "check_call", "check_output", "Popen")

// subprocessShellStatus is _subprocess_shell_status: whether the subprocess call at the
// position runs through a shell (None when a keyword argument could not be resolved) and
// whether `shell=` was written explicitly. A test swaps it.
var subprocessShellStatus = func(tree *pyast.Module, line, col int) (tri, bool) {
	scopes := scopeChain(tree, line, col)
	values := staticValuesAt(tree, line, col)
	for n := range pyast.Walk(scopes[len(scopes)-1]) {
		c, ok := n.(*pyast.Call)
		if !ok || !containsPosition(c, line, col) {
			continue
		}
		call := pyast.Dotted(c.Func)
		if call == "" {
			continue
		}
		name, suffix := cutDot(call)
		if !hasSinkImport(scopes, name, suffix, line, col) || !pySinks[name+suffix] && !runLike[suffix[strings.LastIndex(suffix, ".")+1:]] {
			continue
		}
		if i := slices.IndexFunc(c.Keywords, func(k *pyast.Keyword) bool { return k.Arg == "shell" }); i >= 0 {
			shell := c.Keywords[i]
			if sub, ok := shell.Value.(*pyast.Subscript); ok {
				owner, key := staticValue(sub.Value, values), staticValue(sub.Slice, values)
				if owner != unknown && key != unknown {
					if _, found := pySubscript(owner, key); !found {
						return triFalse, true
					}
				}
			}
			v := staticValue(shell.Value, values)
			if v == unknown {
				return triNone, true
			}
			return triOf(literalTruthy(v)), true
		}
		var mappings []any
		for _, k := range c.Keywords {
			if k.Arg == "" {
				mappings = append(mappings, staticValue(k.Value, values))
			}
		}
		if len(mappings) > 0 {
			if slices.Contains(mappings, any(unknown)) {
				return triNone, false
			}
			for _, m := range mappings {
				if d, ok := m.(*pyDict); ok {
					if v, found := d.get("shell"); found && literalTruthy(v) {
						return triTrue, false
					}
				}
			}
			return triFalse, false
		}
		return triTrue, false
	}
	return triTrue, false
}

var allowedNetworkCalls = pytext.Set(
	"requests.delete", "requests.get", "requests.head", "requests.options",
	"requests.patch", "requests.post", "requests.put", "requests.request",
	"httpx.delete", "httpx.get", "httpx.head", "httpx.options", "httpx.patch",
	"httpx.post", "httpx.put", "httpx.request", "httpx.stream",
	"urllib.request.urlopen", "urllib.request.urlretrieve",
	"socket.create_connection",
)

var networkClients = pytext.Set("httpx.AsyncClient", "httpx.Client", "requests.Session")

var networkMethods = pytext.Set("delete", "get", "head", "options", "patch", "post", "put", "request")

// networkCapabilityIsInvalid is _network_capability_is_invalid: reject a network-looking call
// unless its root is still bound to a known import. A test swaps it.
var networkCapabilityIsInvalid = func(tree *pyast.Module, line, col int) bool {
	scopes := scopeChain(tree, line, col)
	canonical := func(raw string, atLine, atCol int) string {
		name, rest := cutDot(raw)
		b := bindingAt(scopes, name, atLine, atCol)
		if b.kind != "import" {
			return ""
		}
		return b.origin + rest
	}
	assignedConstructor := func(name string) (string, int, int, bool) {
		for _, scope := range slices.Backward(scopes) {
			for _, st := range slices.Backward(bodyOf(scope)) {
				targets, value, ok := assignTargets(st)
				if !ok || !before(st, line, col) {
					continue
				}
				if !slices.ContainsFunc(targets, func(t pyast.Expr) bool { return pyast.Dotted(t) == name }) {
					continue
				}
				if pyast.Dotted(value) == name {
					continue
				}
				call, ok := value.(*pyast.Call)
				if !ok {
					return "", 0, 0, false
				}
				p, _ := posOf(st)
				return pyast.Dotted(call.Func), p.Lineno, p.ColOffset + 1, true
			}
		}
		if !strings.Contains(name, ".") {
			return "", 0, 0, false
		}
		var assignments []pyast.Node
		for n := range pyast.Walk(tree) {
			if targets, _, ok := assignTargets(n); ok && slices.ContainsFunc(targets, func(t pyast.Expr) bool { return pyast.Dotted(t) == name }) {
				assignments = append(assignments, n)
			}
		}
		if len(assignments) != 1 {
			return "", 0, 0, false
		}
		_, value, _ := assignTargets(assignments[0])
		call, ok := value.(*pyast.Call)
		if !ok {
			return "", 0, 0, false
		}
		p, _ := posOf(assignments[0])
		return pyast.Dotted(call.Func), p.Lineno, p.ColOffset + 1, true
	}
	for n := range pyast.Walk(scopes[len(scopes)-1]) {
		c, ok := n.(*pyast.Call)
		if !ok || !containsPosition(c, line, col) {
			continue
		}
		raw := pyast.Dotted(c.Func)
		resolved := ""
		if raw != "" {
			resolved = canonical(raw, line, col)
		}
		if allowedNetworkCalls[resolved] && !qualifiedRebound(scopes, raw, line, col, true) &&
			!(resolved != raw && qualifiedRebound(scopes, resolved, line, col, true)) {
			return false
		}
		attr, ok := c.Func.(*pyast.Attribute)
		if !ok {
			continue
		}
		constructor, constructorLine, constructorCol := "", line, col
		if inner, ok := attr.Value.(*pyast.Call); ok {
			constructor = pyast.Dotted(inner.Func)
		} else if owner := pyast.Dotted(attr.Value); owner != "" {
			if name, l, col, found := assignedConstructor(owner); found {
				constructor, constructorLine, constructorCol = name, l, col
			}
		}
		resolvedConstructor := ""
		if constructor != "" {
			resolvedConstructor = canonical(constructor, constructorLine, constructorCol)
		}
		if networkClients[resolvedConstructor] &&
			(networkMethods[attr.Attr] || attr.Attr == "stream" && (resolvedConstructor == "httpx.AsyncClient" || resolvedConstructor == "httpx.Client")) &&
			!qualifiedRebound(scopes, constructor, constructorLine, constructorCol, true) &&
			!qualifiedRebound(scopes, raw, line, col, true) &&
			!(resolvedConstructor != constructor && qualifiedRebound(scopes, resolvedConstructor, constructorLine, constructorCol, true)) {
			return false
		}
	}
	return true
}

// validatedCapability is _validated_capability: None when no tree is available, False when
// the observed call is shadowed (execution) or not a known network client (network).
func validatedCapability(target Selected, name, capability string, line, col int, p *parse.Package, trees map[string]*pyast.Module) tri {
	if target.Suffix != ".py" {
		return triTrue
	}
	if _, seen := trees[name]; !seen {
		var artifact *parse.Artifact
		if target.Origin == "file" && p != nil {
			artifact = p.ByRel[target.Rel]
		}
		if artifact != nil {
			trees[name] = artifact.PyTree
		} else {
			trees[name] = parsePython(target.Text)
		}
	}
	tree := trees[name]
	if tree == nil {
		return triNone
	}
	return triOf(!(capability == "execution" && sinkIsShadowed(tree, line, col) ||
		capability == "network" && networkCapabilityIsInvalid(tree, line, col)))
}
