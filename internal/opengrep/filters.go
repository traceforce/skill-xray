package opengrep

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/traceforce/skill-xray/internal/pyast"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// identifierRE is re.fullmatch(r"[A-Za-z_]\w*", ...) with Python's Unicode \w.
var identifierRE = regexp.MustCompile(`^[A-Za-z_][\pL\pN_]*$`)

// parents is _parents: child -> parent over ast.walk.
func parents(tree *pyast.Module) map[pyast.Node]pyast.Node {
	out := map[pyast.Node]pyast.Node{}
	for parent := range pyast.Walk(tree) {
		for _, child := range pyast.IterChildNodes(parent) {
			out[child] = parent
		}
	}
	return out
}

// functionAt is _function_at: the innermost (shortest) def containing line.
func functionAt(tree *pyast.Module, line int) pyast.Node {
	var best pyast.Node
	bestSpan := 0
	for n := range pyast.Walk(tree) {
		if !isDef(n) || !inLines(n, line) {
			continue
		}
		p, _ := posOf(n)
		if best == nil || p.EndLineno-p.Lineno < bestSpan {
			best, bestSpan = n, p.EndLineno-p.Lineno
		}
	}
	return best
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(s, p) })
}

// sourceExpression is _source_expression: the expression reads a known taint source.
func sourceExpression(n pyast.Node) bool {
	for item := range pyast.Walk(n) {
		call := ""
		if c, ok := item.(*pyast.Call); ok {
			call = pyast.Dotted(c.Func)
		}
		value := pyast.Dotted(item)
		if call == "input" || call == "raw_input" || call == "os.getenv" ||
			call != "" && hasAnyPrefix(call, "requests.", "httpx.", "urllib.request.urlopen") ||
			value != "" && hasAnyPrefix(value, "sys.argv", "sys.stdin", "os.environ") {
			return true
		}
	}
	return false
}

// argumentMarker is _argument_marker: SOURCE/OTHER, or a container of markers.
func argumentMarker(n pyast.Node) any {
	switch x := n.(type) {
	case *pyast.Dict:
		d := &pyDict{}
		for i := range x.Keys {
			key, ok := literalEval(x.Keys[i])
			if !ok || !hashable(key) {
				return unknown
			}
			d.set(key, argumentMarker(x.Values[i]))
		}
		return d
	case *pyast.List:
		out := make([]any, len(x.Elts))
		for i, e := range x.Elts {
			out[i] = argumentMarker(e)
		}
		return out
	case *pyast.Tuple:
		out := make(pyast.TupleValue, len(x.Elts))
		for i, e := range x.Elts {
			out[i] = argumentMarker(e)
		}
		return out
	}
	if sourceExpression(n) {
		return sourceMarker
	}
	return otherMarker
}

// param kinds, in inspect.Parameter order.
const (
	posOnly = iota
	posOrKw
	varPos
	kwOnly
	varKw
)

type param struct {
	name       string
	kind       int
	hasDefault bool
}

// signatureOf is _signature: the inspect.Signature of a def; boundMethod drops parameter 0.
func signatureOf(fn pyast.Node, boundMethod bool) []param {
	a := argsOf(fn)
	positional := slices.Concat(a.Posonlyargs, a.Args)
	var out []param
	for i, arg := range positional {
		if boundMethod && i == 0 {
			continue
		}
		kind := posOrKw
		if i < len(a.Posonlyargs) {
			kind = posOnly
		}
		out = append(out, param{arg.Arg, kind, i >= len(positional)-len(a.Defaults)})
	}
	if a.Vararg != nil {
		out = append(out, param{a.Vararg.Arg, varPos, false})
	}
	for i, arg := range a.Kwonlyargs {
		out = append(out, param{arg.Arg, kwOnly, a.KwDefaults[i] != nil})
	}
	if a.Kwarg != nil {
		out = append(out, param{a.Kwarg.Arg, varKw, false})
	}
	return out
}

// bind is inspect.Signature._bind (CPython 3.13); ok false is its TypeError. Parameters with
// defaults that were not supplied are absent from the result (bind, not apply_defaults).
func bind(params []param, positional []any, keywords map[string]any) (map[string]any, bool) {
	kwargs := maps.Clone(keywords)
	arguments := map[string]any{}
	pi, ai := 0, 0
	var parametersEx []param
	for {
		if ai >= len(positional) {
			if pi >= len(params) {
				break
			}
			p := params[pi]
			pi++
			_, inKwargs := kwargs[p.name]
			if p.kind == varPos {
				break
			} else if inKwargs {
				if p.kind == posOnly {
					if !p.hasDefault {
						return nil, false
					}
					continue // raised once no **kwargs turns up
				}
				parametersEx = []param{p}
				break
			} else if p.kind == varKw || p.hasDefault {
				parametersEx = []param{p}
				break
			}
			return nil, false // missing a required argument
		}
		argVal := positional[ai]
		ai++
		if pi >= len(params) {
			return nil, false // too many positional arguments
		}
		p := params[pi]
		pi++
		if p.kind == varKw || p.kind == kwOnly {
			return nil, false
		}
		if p.kind == varPos {
			values := pyast.TupleValue{argVal}
			arguments[p.name] = append(values, positional[ai:]...)
			break
		}
		if _, inKwargs := kwargs[p.name]; inKwargs && p.kind != posOnly {
			return nil, false // multiple values
		}
		arguments[p.name] = argVal
	}
	kwargsParam := ""
	hasKwargs := false
	for _, p := range slices.Concat(parametersEx, params[pi:]) {
		if p.kind == varKw {
			kwargsParam, hasKwargs = p.name, true
			continue
		}
		if p.kind == varPos {
			continue
		}
		v, ok := kwargs[p.name]
		if !ok {
			if !p.hasDefault {
				return nil, false
			}
			continue
		}
		delete(kwargs, p.name)
		if p.kind == posOnly {
			return nil, false
		}
		arguments[p.name] = v
	}
	if len(kwargs) > 0 {
		if !hasKwargs {
			return nil, false
		}
		d := &pyDict{}
		for _, k := range slices.Sorted(maps.Keys(kwargs)) {
			d.set(k, kwargs[k])
		}
		arguments[kwargsParam] = d
	}
	return arguments, true
}

// callArguments is _call_arguments: the markers a call supplies. status is argsOK, argsNone
// (an unresolvable splat) or argsInvalid (a duplicate keyword).
const (
	argsOK = iota
	argsNone
	argsInvalid
)

func callArguments(call *pyast.Call) (positional []any, keywords map[string]any, status int) {
	positional = []any{}
	for _, a := range call.Args {
		if s, ok := a.(*pyast.Starred); ok {
			var elts []pyast.Expr
			switch v := s.Value.(type) {
			case *pyast.List:
				elts = v.Elts
			case *pyast.Tuple:
				elts = v.Elts
			default:
				return nil, nil, argsNone
			}
			for _, e := range elts {
				positional = append(positional, argumentMarker(e))
			}
			continue
		}
		positional = append(positional, argumentMarker(a))
	}
	keywords = map[string]any{}
	for _, k := range call.Keywords {
		if k.Arg != "" {
			if _, dup := keywords[k.Arg]; dup {
				return nil, nil, argsInvalid
			}
			keywords[k.Arg] = argumentMarker(k.Value)
			continue
		}
		d, ok := k.Value.(*pyast.Dict)
		if !ok {
			return nil, nil, argsNone
		}
		for i := range d.Keys {
			name, ok := literalEval(d.Keys[i])
			if !ok {
				return nil, nil, argsNone
			}
			s, isStr := name.(string)
			if _, dup := keywords[s]; !isStr || dup {
				return nil, nil, argsInvalid
			}
			keywords[s] = argumentMarker(d.Values[i])
		}
	}
	return positional, keywords, argsOK
}

// sinkArgument is _sink_argument: the argument the first sink call on line executes.
func sinkArgument(fn pyast.Node, line int) pyast.Expr {
	for n := range pyast.Walk(fn) {
		c, ok := n.(*pyast.Call)
		if !ok || !inLines(c, line) {
			continue
		}
		if call := pyast.Dotted(c.Func); pySinks[call] || pyBuiltinSinks[call] {
			if i := slices.IndexFunc(c.Keywords, func(k *pyast.Keyword) bool { return k.Arg == "args" }); i >= 0 {
				return c.Keywords[i].Value
			}
			if len(c.Args) > 0 {
				return c.Args[0]
			}
			return nil
		}
	}
	return nil
}

// containsMarker is the `contains` closure of _bound_marker.
func containsMarker(v, expected any) bool {
	switch x := v.(type) {
	case *marker:
		return x == expected
	case *pyDict:
		return slices.ContainsFunc(x.values, func(e any) bool { return containsMarker(e, expected) })
	case []any:
		return slices.ContainsFunc(x, func(e any) bool { return containsMarker(e, expected) })
	case pyast.TupleValue:
		return slices.ContainsFunc(x, func(e any) bool { return containsMarker(e, expected) })
	}
	return false
}

// boundMarker is _bound_marker: the marker bound to the sink expression.
func boundMarker(expr pyast.Expr, arguments map[string]any) any {
	switch x := expr.(type) {
	case *pyast.Name:
		if v, ok := arguments[x.Id]; ok {
			return v
		}
		return unknown
	case *pyast.Subscript:
		if owner, ok := x.Value.(*pyast.Name); ok {
			key, ok := literalEval(x.Slice)
			if !ok {
				return unknown
			}
			if v, found := pySubscript(arguments[owner.Id], key); found {
				return v
			}
			return unknown
		}
	}
	var markers []any
	for n := range pyast.Walk(expr) {
		if name, ok := n.(*pyast.Name); ok {
			if v, bound := arguments[name.Id]; bound {
				markers = append(markers, v)
			}
		}
	}
	switch {
	case slices.ContainsFunc(markers, func(m any) bool { return containsMarker(m, sourceMarker) }):
		return sourceMarker
	case len(markers) > 0:
		return otherMarker
	}
	return unknown
}

// resolveAlias is _resolve_alias: follow bare `Name = Name` copies inside the function back to
// the ultimate name.
func resolveAlias(fn pyast.Node, expr pyast.Expr, line int) pyast.Expr {
	seen := map[string]bool{}
	for {
		name, ok := expr.(*pyast.Name)
		if !ok || seen[name.Id] {
			return expr
		}
		seen[name.Id] = true
		var latest *pyast.Assign
		for _, n := range scopeNodes(fn) {
			a, ok := n.(*pyast.Assign)
			if !ok || len(a.Targets) != 1 {
				continue
			}
			target, ok := a.Targets[0].(*pyast.Name)
			if ok && target.Id == name.Id && endLine(a.Pos) < line && (latest == nil || a.Lineno > latest.Lineno) {
				latest = a
			}
		}
		if latest == nil {
			return expr
		}
		value, ok := latest.Value.(*pyast.Name)
		if !ok {
			return expr
		}
		expr, line = value, latest.Lineno
	}
}

// directScope is _direct_scope: the module or def a definition sits in directly.
func directScope(def pyast.Node, par map[pyast.Node]pyast.Node) pyast.Node {
	switch parent := par[def]; parent.(type) {
	case *pyast.Module, *pyast.FunctionDef, *pyast.AsyncFunctionDef:
		return parent
	}
	return nil
}

// scopeBindsName is _scope_binds_name: the scope rebinds name locally (never through
// global/nonlocal).
func scopeBindsName(scope pyast.Node, name string) bool {
	nodes := scopeNodes(scope)
	for _, n := range nodes {
		switch x := n.(type) {
		case *pyast.Global:
			if slices.Contains(x.Names, name) {
				return false
			}
		case *pyast.Nonlocal:
			if slices.Contains(x.Names, name) {
				return false
			}
		}
	}
	for _, n := range nodes {
		bound := ""
		switch x := n.(type) {
		case *pyast.Arg:
			bound = x.Arg
		case *pyast.Name:
			if isStore(x.Ctx) || isDel(x.Ctx) {
				bound = x.Id
			}
		case *pyast.ExceptHandler:
			bound = x.Name
		case *pyast.MatchAs:
			bound = x.Name
		case *pyast.MatchStar:
			bound = x.Name
		case *pyast.MatchMapping:
			bound = x.Rest
		default:
			bound = defName(n)
		}
		if bound == name || importBinding(n, name).ok() {
			return true
		}
	}
	return false
}

// definitionVisible is _definition_visible: walking up from the call, no scope rebinds the
// definition's name before its direct scope, and the latest definition of that name before the
// call in the direct scope is def itself.
func definitionVisible(def pyast.Node, call *pyast.Call, par map[pyast.Node]pyast.Node) bool {
	scope := directScope(def, par)
	if scope == nil {
		return false
	}
	name := defName(def)
	var node pyast.Node = call
	crossed, reached := false, false
	for {
		parent, ok := par[node]
		if !ok {
			break
		}
		node = parent
		if node == scope {
			reached = true
			break
		}
		if isScope(node) {
			_, class := node.(*pyast.ClassDef)
			if !(class && crossed) && scopeBindsName(node, name) {
				return false
			}
			crossed = crossed || isFunctionScope(node)
		}
	}
	if !reached {
		return false
	}
	var current pyast.Node
	for _, st := range bodyOf(scope) {
		if !before(st, call.Lineno, call.ColOffset+1) {
			continue
		}
		if stName := defName(st); stName != "" {
			if stName == name {
				current = st
			}
		} else if statementBinding(st, name).ok() && !preservesNameBinding(st, name) {
			current = nil
		}
	}
	return current == def
}

// methodCallOwner is _method_call_owner: the class of an inline `Owner().method(...)` call.
func methodCallOwner(fn pyast.Node, call *pyast.Call, par map[pyast.Node]pyast.Node) *pyast.ClassDef {
	owner, ok := par[fn].(*pyast.ClassDef)
	if !ok {
		return nil
	}
	attr, ok := call.Func.(*pyast.Attribute)
	if !ok || attr.Attr != defName(fn) {
		return nil
	}
	inner, ok := attr.Value.(*pyast.Call)
	if !ok {
		return nil
	}
	if name, ok := inner.Func.(*pyast.Name); !ok || name.Id != owner.Name {
		return nil
	}
	return owner
}

// callFlowIsImpossible is _call_flow_is_impossible: every visible call of the sink's function
// at the source position binds the sink argument to a non-source marker. sourceLine 0 is None.
func callFlowIsImpossible(tree *pyast.Module, sourceLine, sinkLine, sourceCol int) bool {
	if sourceLine == 0 {
		return false
	}
	fn := functionAt(tree, sinkLine)
	if fn == nil {
		return false
	}
	par := parents(tree)
	var calls []*pyast.Call
	for n := range pyast.Walk(tree) {
		c, ok := n.(*pyast.Call)
		if !ok || !containsPosition(c, sourceLine, sourceCol) {
			continue
		}
		if name, ok := c.Func.(*pyast.Name); ok && name.Id == defName(fn) || methodCallOwner(fn, c, par) != nil {
			calls = append(calls, c)
		}
	}
	if len(calls) == 0 {
		return false
	}
	sink := sinkArgument(fn, sinkLine)
	if sink != nil {
		sink = resolveAlias(fn, sink, sinkLine)
	}
	for _, call := range calls {
		owner := methodCallOwner(fn, call, par)
		if owner == nil && !definitionVisible(fn, call, par) {
			continue
		}
		if owner != nil && !definitionVisible(owner, call, par) {
			continue
		}
		positional, keywords, status := callArguments(call)
		if status == argsInvalid {
			continue
		}
		if status == argsNone {
			return false
		}
		bound, ok := bind(signatureOf(fn, owner != nil), positional, keywords)
		if !ok {
			continue
		}
		if sink == nil || boundMarker(sink, bound) == sourceMarker {
			return false
		}
	}
	return true
}

// receiverFlowIsImpossible is _receiver_flow_is_impossible: a self/cls call inside a method
// whose receiver is not the first parameter, is static, or was rebound earlier.
func receiverFlowIsImpossible(tree *pyast.Module, line int) bool {
	fn := functionAt(tree, line)
	if fn == nil {
		return false
	}
	par := parents(tree)
	if _, inClass := par[fn].(*pyast.ClassDef); !inClass {
		return false
	}
	receiver := ""
	for n := range pyast.Walk(fn) {
		c, ok := n.(*pyast.Call)
		if !ok || !inLines(c, line) {
			continue
		}
		if attr, ok := c.Func.(*pyast.Attribute); ok {
			if name, ok := attr.Value.(*pyast.Name); ok && (name.Id == "self" || name.Id == "cls") {
				receiver = name.Id
				break
			}
		}
	}
	if receiver == "" {
		return false
	}
	a := argsOf(fn)
	positional := slices.Concat(a.Posonlyargs, a.Args)
	static := slices.ContainsFunc(decoratorsOf(fn), func(d pyast.Expr) bool { return pyast.Dotted(d) == "staticmethod" })
	if len(positional) == 0 || positional[0].Arg != receiver || static {
		return true
	}
	for _, n := range scopeNodes(fn) {
		p, ok := posOf(n)
		if !ok || p.Lineno >= line {
			continue
		}
		switch x := n.(type) {
		case *pyast.Name:
			if isStore(x.Ctx) && x.Id == receiver {
				return true
			}
		case *pyast.MatchAs:
			if x.Name == receiver {
				return true
			}
		case *pyast.Alias:
			if x.Asname == receiver {
				return true
			}
		}
	}
	return false
}

var asyncDrivers = pytext.Set(
	"run", "create_task", "ensure_future", "run_until_complete",
	"run_coroutine_threadsafe", "gather", "wait", "wait_for", "as_completed",
)

// asyncCallIsExecuted is _async_call_is_executed: the call is awaited or handed to an asyncio
// driver.
func asyncCallIsExecuted(call *pyast.Call, par map[pyast.Node]pyast.Node) bool {
	for n := par[call]; n != nil; n = par[n] {
		if _, await := n.(*pyast.Await); await {
			return true
		}
	}
	parent, ok := par[call].(*pyast.Call)
	if !ok || parent.Func == pyast.Expr(call) {
		return false
	}
	driver := ""
	switch f := parent.Func.(type) {
	case *pyast.Attribute:
		driver = f.Attr
	case *pyast.Name:
		driver = f.Id
	}
	return asyncDrivers[driver]
}

// unawaitedAsyncFlow is _unawaited_async_flow: an async def touching the flow is only ever
// called without being awaited or scheduled. sourceLine 0 is None.
func unawaitedAsyncFlow(tree *pyast.Module, sourceLine, sinkLine, sourceCol, sinkCol int) bool {
	par := parents(tree)
	for n := range pyast.Walk(tree) {
		fn, ok := n.(*pyast.AsyncFunctionDef)
		if !ok {
			continue
		}
		touches := inLines(fn, sinkLine) || sourceLine != 0 && inLines(fn, sourceLine)
		var calls, relevant []*pyast.Call
		for m := range pyast.Walk(tree) {
			c, ok := m.(*pyast.Call)
			if !ok {
				continue
			}
			if name, ok := c.Func.(*pyast.Name); ok && name.Id == fn.Name {
				calls = append(calls, c)
				if sourceLine != 0 && containsPosition(c, sourceLine, sourceCol) || containsPosition(c, sinkLine, sinkCol) {
					relevant = append(relevant, c)
				}
			}
		}
		if touches && len(relevant) == 0 {
			relevant = calls
		}
		if len(relevant) > 0 && !slices.ContainsFunc(relevant, func(c *pyast.Call) bool { return asyncCallIsExecuted(c, par) }) {
			return true
		}
	}
	return false
}

// finallyOverridesFlow is _finally_overrides_flow: the sink line calls a visible function whose
// try/finally returns from the finally block.
func finallyOverridesFlow(tree *pyast.Module, sinkLine int) bool {
	par := parents(tree)
	for fn := range pyast.Walk(tree) {
		if !isDef(fn) {
			continue
		}
		overrides := slices.ContainsFunc(scopeNodes(fn), func(n pyast.Node) bool {
			try, ok := n.(*pyast.Try)
			return ok && slices.ContainsFunc(try.Finalbody, func(s pyast.Stmt) bool { _, ret := s.(*pyast.Return); return ret })
		})
		if !overrides {
			continue
		}
		for n := range pyast.Walk(tree) {
			c, ok := n.(*pyast.Call)
			if !ok {
				continue
			}
			if name, ok := c.Func.(*pyast.Name); ok && name.Id == defName(fn) && inLines(c, sinkLine) && definitionVisible(fn, c, par) {
				return true
			}
		}
	}
	return false
}

// metavar is metavars[name]["abstract_content"] when it is a string.
func metavar(extra map[string]any, name string) (string, bool) {
	metavars, _ := extra["metavars"].(map[string]any)
	match, _ := metavars[name].(map[string]any)
	s, ok := match["abstract_content"].(string)
	return s, ok
}

// assignedAliasIsInvalid is _assigned_alias_is_invalid: the $ALIAS identifier is not bound to a
// sink at the sink position.
func assignedAliasIsInvalid(extra map[string]any, tree *pyast.Module, line, col int) bool {
	name, ok := metavar(extra, "$ALIAS")
	if !ok || !identifierRE.MatchString(name) {
		return false
	}
	return bindingAt(scopeChain(tree, line, col), name, line, col).kind != "sink"
}

// srcSpan is the taint source position of _source_span; line, col and endCol are 0 for None
// (they are 1-based when set) while endLine may be any int, so nil is its None.
type srcSpan struct {
	line, col, endCol int
	endLine           *int
}

func optInt(v any) *int {
	if i, ok := v.(int); ok {
		return &i
	}
	return nil
}

func optCol(v any) int {
	if i, ok := v.(int); ok && i >= 1 {
		return i
	}
	return 0
}

// sourceSpan is _source_span: the dataflow trace's taint_source when it names this target,
// else the $SOURCE metavariable.
func sourceSpan(extra map[string]any, name string, target Selected) srcSpan {
	lines := strings.Count(target.Text, "\n") + 1
	// The trace is used when `kind, payload = trace["taint_source"]; location, _ = payload;
	// location["start"]["line"]; location["end"].get(...); location["path"]` all succeed;
	// any KeyError/TypeError/ValueError in that unpacking falls back to the $SOURCE metavariable.
	trace, _ := extra["dataflow_trace"].(map[string]any)
	if source, ok := trace["taint_source"].([]any); ok && len(source) == 2 {
		if payload, ok := source[1].([]any); ok && len(payload) == 2 {
			if loc, ok := payload[0].(map[string]any); ok {
				start, startOK := loc["start"].(map[string]any)
				lineValue, hasLine := start["line"]
				end, endOK := loc["end"].(map[string]any) // ponytail: a non-dict end raises out of the oracle
				path, hasPath := loc["path"]
				if startOK && hasLine && endOK && hasPath {
					kind, _ := source[0].(string)
					line, isInt := lineValue.(int)
					pathStr, pathOK := path.(string)
					if kind != "CliLoc" || !isInt || line < 1 || line > lines || !pathOK ||
						targetName(pathStr) != name && targetName(pathStr) != targetName(target.Rel) {
						return srcSpan{}
					}
					return srcSpan{line, optCol(start["col"]), optCol(end["col"]), optInt(end["line"])}
				}
			}
		}
	}
	metavars, _ := extra["metavars"].(map[string]any)
	source, _ := metavars["$SOURCE"].(map[string]any)
	start, _ := source["start"].(map[string]any)
	end, _ := source["end"].(map[string]any)
	line, isInt := start["line"].(int)
	if !isInt || line < 1 || line > lines {
		return srcSpan{}
	}
	return srcSpan{line, optCol(start["col"]), optCol(end["col"]), optInt(end["line"])}
}

// canonicalAt is _canonical_at: the import origin of raw, or the builtin for a few names.
func canonicalAt(tree *pyast.Module, raw string, line, col int) string {
	name, rest := cutDot(raw)
	b := bindingAt(scopeChain(tree, line, col), name, line, col)
	if b.kind == "import" {
		return b.origin + rest
	}
	if !b.ok() && (name == "input" || name == "raw_input" || name == "bytes" || name == "bytearray") {
		return "builtins." + raw
	}
	return ""
}

// sourceIdentityIsInvalid is _source_identity_is_invalid: every protected-looking source
// candidate at the source span resolves to something other than the vector's real sources.
func sourceIdentityIsInvalid(tree *pyast.Module, sp srcSpan, vector string) bool {
	if sp.line == 0 {
		return false
	}
	var protected map[string]bool
	var allowed []string
	switch vector {
	case "SXV-008":
		protected = map[string]bool{"input": true, "raw_input": true, "sys": true, "os": true}
		allowed = []string{"builtins.input", "builtins.raw_input", "sys.argv", "sys.stdin", "os.environ", "os.getenv"}
	case "SXV-018":
		protected = map[string]bool{"requests": true, "httpx": true, "urllib": true, "urllib3": true, "urlopen": true}
		allowed = []string{"requests.", "httpx.", "urllib.request.urlopen", "urllib3.PoolManager"}
	default:
		protected = map[string]bool{"base64": true, "binascii": true, "bytes": true, "bytearray": true}
		allowed = []string{"base64.", "binascii.", "builtins.bytes.", "builtins.bytearray."}
	}
	var scopes []pyast.Node
	var candidates []bool
	for n := range pyast.Walk(tree) {
		var value pyast.Expr
		switch x := n.(type) {
		case *pyast.Call:
			value = x.Func
		case *pyast.Subscript:
			value = x.Value
		case *pyast.Attribute:
			value = x
		default:
			continue
		}
		p, _ := posOf(n)
		withinSpan := sp.col != 0 && sp.endLine != nil && sp.endCol != 0 &&
			(p.Lineno > sp.line || p.Lineno == sp.line && p.ColOffset >= sp.col-1) &&
			(endLine(p) < *sp.endLine || endLine(p) == *sp.endLine && p.EndColOffset <= sp.endCol-1)
		if !(withinSpan || sp.endLine == nil && containsPosition(n, sp.line, sp.col)) {
			continue
		}
		raw := pyast.Dotted(value)
		if raw == "" {
			continue
		}
		canonical := canonicalAt(tree, raw, sp.line, p.ColOffset+1)
		head, _, _ := strings.Cut(raw, ".")
		allowedCanonical := canonical != "" && hasAnyPrefix(canonical, allowed...)
		if protected[head] || allowedCanonical {
			if scopes == nil {
				scopes = scopeChain(tree, sp.line, sp.col)
			}
			candidates = append(candidates, allowedCanonical &&
				!qualifiedRebound(scopes, raw, sp.line, sp.col, false) &&
				!(canonical != raw && qualifiedRebound(scopes, canonical, sp.line, sp.col, false)))
		}
	}
	return len(candidates) > 0 && !slices.Contains(candidates, true)
}

// branchAt is _branch_at: the index of the branch whose statements cover line, or -1.
func branchAt(branches [][]pyast.Stmt, line int) int {
	return slices.IndexFunc(branches, func(body []pyast.Stmt) bool {
		return slices.ContainsFunc(body, func(s pyast.Stmt) bool { return inLines(s, line) })
	})
}

// mutuallyExclusiveLines is _mutually_exclusive_lines: the two lines sit in different arms of
// one if/match that no enclosing loop can run twice.
func mutuallyExclusiveLines(tree *pyast.Module, first, second int) bool {
	for n := range pyast.Walk(tree) {
		var branches [][]pyast.Stmt
		switch x := n.(type) {
		case *pyast.If:
			branches = [][]pyast.Stmt{x.Body, x.Orelse}
		case *pyast.Match:
			for _, c := range x.Cases {
				branches = append(branches, c.Body)
			}
		default:
			continue
		}
		left, right := branchAt(branches, first), branchAt(branches, second)
		if left < 0 || right < 0 || left == right {
			continue
		}
		// Different arms can both run on different loop iterations. Without a CFG that
		// proves a single iteration, keep the engine's flow instead of hiding a real one.
		np, _ := posOf(n)
		repeated := false
		for parent := range pyast.Walk(tree) {
			switch parent.(type) {
			case *pyast.For, *pyast.AsyncFor, *pyast.While:
			default:
				continue
			}
			pp, _ := posOf(parent)
			if parent != n && pp.Lineno <= np.Lineno && endLine(np) <= endLine(pp) {
				repeated = true
				break
			}
		}
		if !repeated {
			return true
		}
	}
	return false
}

// commandImportHidesOuterSource is _command_import_hides_outer_source: the $COMMAND name is
// imported inside the sink's function while the source lies outside it.
func commandImportHidesOuterSource(extra map[string]any, name string, target Selected, tree *pyast.Module, line, col int) bool {
	command, ok := metavar(extra, "$COMMAND")
	if !ok || !identifierRE.MatchString(command) {
		return false
	}
	scopes := scopeChain(tree, line, col)
	scope := scopes[len(scopes)-1]
	if !isDef(scope) {
		return false
	}
	for _, n := range scopeNodes(scope) {
		if g, ok := n.(*pyast.Global); ok && slices.Contains(g.Names, command) {
			return false
		}
	}
	source := sourceSpan(extra, name, target).line
	if source == 0 || inLines(scope, source) {
		return false
	}
	return lastBinding(scope, command, line, col).kind == "import"
}

// pythonDefiniteFalsePositive is _python_definite_false_positive: the OR of every filter, for
// Python taint results only. A test swaps it.
var pythonDefiniteFalsePositive = func(extra map[string]any, name string, target Selected, vector string, line, col int, trees map[string]*pyast.Module) bool {
	if !pyTaintVectors[vector] || target.Suffix != ".py" {
		return false
	}
	if _, seen := trees[name]; !seen {
		trees[name] = parsePython(target.Text)
	}
	tree := trees[name]
	if tree == nil {
		return false
	}
	sp := sourceSpan(extra, name, target)
	return sinkIsShadowed(tree, line, col) ||
		sourceIdentityIsInvalid(tree, sp, vector) ||
		assignedAliasIsInvalid(extra, tree, line, col) ||
		callFlowIsImpossible(tree, sp.line, line, sp.col) ||
		receiverFlowIsImpossible(tree, line) ||
		unawaitedAsyncFlow(tree, sp.line, line, sp.col, col) ||
		finallyOverridesFlow(tree, line) ||
		commandImportHidesOuterSource(extra, name, target, tree, line, col) ||
		sp.line != 0 && mutuallyExclusiveLines(tree, sp.line, line)
}
