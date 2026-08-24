"""Python source->sink taint over the IR's ast trees (ported engine_pytaint).

Proves that attacker-controlled bytes reach a command-execution sink through a concrete
assignment chain in a bundled .py script. Two outcomes, split by the SOURCE not the sink:

  - SXV-008 (command injection, CWE-78/77): a LOCAL untrusted input -- argv, an argparse
    namespace, an environment variable, or stdin -- flows into a shell-executing sink.
  - SXV-018 (remote dropper, CWE-494/829): a NETWORK read's bytes flow into an execution
    sink, so the code that runs is not the code that was reviewed.

It fires only with a proven flow (>=2 threadflow steps): a constant command, a list-form
subprocess call without shell, a shlex-quoted argument, or a constant-dict lookup does not
taint. Flow-sensitive over statement order; one level of positional interprocedural
binding; reads the IR's pre-parsed ast, never re-parsing."""

from __future__ import annotations

import ast

from ..findings import Finding

_MAX_DEPTH = 3
# Bound the expression-taint recursion. _taint_of walks nested BinOp/BoolOp/Tuple/... and each
# level adds interpreter frames on top of the statement walker already on the stack, so an
# unbounded nest (a multi-KB `os.system('a'+'a'+...+'a')`) is a RecursionError crash primitive.
# 120 is far deeper than any real command expression yet well under the ~1000 default limit given
# those walker frames, so behaviour below the bound is identical.
_MAX_EXPR_DEPTH = 120

# Sources ---------------------------------------------------------------------
_NETWORK_READS = {
    "urllib.request.urlopen", "urlopen", "urllib.request.urlretrieve", "urlretrieve",
    "urllib.urlopen", "requests.get", "requests.post", "requests.put", "requests.head",
    "requests.request", "httpx.get", "httpx.post", "httpx.request", "urllib3.request",
}

# Propagation -----------------------------------------------------------------
_DECLASSIFIERS = {"quote", "shlex.quote", "list2cmdline"}
_PROPAGATING = {
    "abspath", "realpath", "normpath", "expanduser", "expandvars", "join", "dirname",
    "basename", "strip", "rstrip", "lstrip", "lower", "upper", "decode", "encode",
    "read", "readline", "readlines", "format", "replace", "str", "compile", "loads",
    "read_text",
    # A parsed network response forwards the remote taint: requests.Response.json() and
    # json.loads(<remote>) (loads, above) both hand back attacker-controlled data, so a later
    # index into it must stay tainted (the JSON-mediated dropper the taint engine used to miss).
    "json",
}
_OPENERS = {"open", "io.open", "codecs.open", "pathlib.Path"}

# Sinks -----------------------------------------------------------------------
_OS_SHELL = {"os.system", "os.popen", "system", "popen"}
_EVAL = {"eval", "exec"}
_ALWAYS_SHELL = {"getoutput", "getstatusoutput"}        # subprocess.getoutput: shell always
_SHELL_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}   # only when shell=True


def _dotted(node):
    """Dotted name for a Name/Attribute chain (os.path.join -> 'os.path.join'), else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _leaf(dotted):
    return dotted.rsplit(".", 1)[-1] if dotted else None


class _Taint:
    """A tainted value: its source kind and the ordered threadflow steps that carried it."""

    __slots__ = ("kind", "steps")

    def __init__(self, kind, steps):
        self.kind = kind
        self.steps = steps

    def extend(self, step):
        return _Taint(self.kind, self.steps + [step])


def _step(node, note):
    return {"line": getattr(node, "lineno", 0),
            "col": getattr(node, "col_offset", -1) + 1, "note": note}


class _Analyzer:
    def __init__(self, rel, tree):
        self.rel = rel
        self.tree = tree
        # Interprocedural resolution follows only BARE calls -- a helper nested in the current
        # scope, then a top-level function. Method calls (obj.m()/self.m()) are deliberately
        # NOT resolved: a receiver's runtime type is unknowable statically (self can be rebound
        # by assignment, for/with/except, a match-capture, or import-as -- an unbounded set of
        # forms), and guessing by method name fabricated critical findings on benign code.
        # Sinks INSIDE methods are still analysed directly (analyze() walks every function
        # body); only cross-method argument/return following is given up.
        self.top_funcs = {}
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.top_funcs[stmt.name] = stmt        # last def wins, matching Python
        self._cur_locals = self.top_funcs   # functions a bare call can see in the current scope
        self.const_dicts = set()
        self.flows = []
        for stmt in tree.body:
            # Only an ALL-CONSTANT literal is a declassifying lookup table. A list/dict
            # assembled FROM tainted input and later indexed must NOT declassify the taint.
            if (isinstance(stmt, ast.Assign)
                    and isinstance(stmt.value, (ast.Dict, ast.Set, ast.Tuple, ast.List))
                    and _is_all_const(stmt.value)):
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Name):
                        self.const_dicts.add(tgt.id)

    # -- sources --
    def _source_kind(self, node):
        if isinstance(node, ast.Subscript):
            base = _dotted(node.value)
            if base in ("sys.argv", "argv"):
                return "cli_argv"
            if base in ("os.environ", "environ"):
                return "environment"
        elif isinstance(node, ast.Attribute):
            if _dotted(node) in ("sys.argv", "argv"):
                return "cli_argv"
        elif isinstance(node, ast.Call):
            fn = _dotted(node.func)
            if fn in ("input", "raw_input"):
                return "stdin"
            if fn in ("os.getenv", "os.environ.get", "environ.get"):
                return "environment"
            if fn == "sys.stdin.read":
                return "stdin"
            if fn and fn.endswith(".parse_args"):
                return "cli_argparse"
            if fn in _NETWORK_READS:
                return "network_response"
        return None

    # -- taint propagation --
    def _taint_of(self, node, env, depth=0):
        if node is None:
            return None
        if depth > _MAX_EXPR_DEPTH:
            return None            # bound the walk (see _MAX_EXPR_DEPTH): deeper nesting cannot
                                   # deepen the taint and unbounded recursion here crashes the scan
        kind = self._source_kind(node)
        if kind is not None:
            return _Taint(kind, [_step(node, "source: %s" % kind)])
        if isinstance(node, ast.Name):
            v = env.get(node.id)
            return v if isinstance(v, _Taint) else None   # a per-key dict map is not a scalar taint
        if isinstance(node, ast.Attribute):
            return self._taint_of(node.value, env, depth + 1)
        if isinstance(node, ast.Starred):
            return self._taint_of(node.value, env, depth + 1)   # run(*[argv]) forwards the splat
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name):
                v = env.get(node.value.id)
                if isinstance(v, dict):                  # dict literal tracked per constant key
                    key = _const_key(node.slice)
                    return v.get(key) if key is not None else None
            base = _dotted(node.value)
            if base and base.split(".")[0] in self.const_dicts:
                return None                              # constant-table lookup: declassify
            return self._taint_of(node.value, env, depth + 1)
        if isinstance(node, ast.BinOp):
            return (self._taint_of(node.left, env, depth + 1)
                    or self._taint_of(node.right, env, depth + 1))
        if isinstance(node, ast.BoolOp):
            for v in node.values:
                t = self._taint_of(v, env, depth + 1)
                if t:
                    return t
            return None
        if isinstance(node, ast.IfExp):
            return (self._taint_of(node.body, env, depth + 1)
                    or self._taint_of(node.orelse, env, depth + 1))
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    t = self._taint_of(part.value, env, depth + 1)
                    if t:
                        return t
            return None
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            for el in node.elts:
                t = self._taint_of(el, env, depth + 1)
                if t:
                    return t
            return None
        if isinstance(node, ast.Call):
            return self._taint_of_call(node, env, depth)
        return None

    def _taint_of_call(self, node, env, depth=0):
        fn = _dotted(node.func)
        leaf = _leaf(fn) if fn else getattr(node.func, "attr", None)
        if leaf in _DECLASSIFIERS or fn in _DECLASSIFIERS:
            return None
        if leaf == "get" and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                v = env.get(node.func.value.id)
                if isinstance(v, dict):                  # d.get("const") on a per-key-tracked dict
                    key = _const_key(node.args[0]) if node.args else None
                    return v.get(key) if key is not None else None
            recv = _dotted(node.func.value)
            if recv and recv.split(".")[0] in self.const_dicts:
                return None
        if fn in _OPENERS and node.args:
            t = self._taint_of(node.args[0], env, depth + 1)
            return t.extend(_step(node, "file handle opened on a tainted path")) if t else None
        if leaf in _PROPAGATING:
            candidates = list(node.args) + [kw.value for kw in node.keywords]
            if isinstance(node.func, ast.Attribute):
                candidates.insert(0, node.func.value)
            for c in candidates:
                t = self._taint_of(c, env, depth + 1)
                if t:
                    return t.extend(_step(node, "propagates through %s()" % leaf))
        # A call to a self-defined helper that directly returns an untrusted source
        # launders the taint (def g(): return sys.argv[1]; os.system(g())). Resolved
        # soundly (bare call -> top-level, method -> unambiguous only), never by leaf guess.
        callee = self._resolve_call(node)
        if callee is not None:
            kind = self._returns_source(callee)
            if kind:
                return _Taint(kind, [_step(node, "return value of %s() is a %s source"
                                           % (leaf or fn, kind))])
        return None

    def _dict_keymap(self, node, env):
        """Per-constant-key taint for a dict literal: {key_value: _Taint} for each entry whose
        key is a constant and whose value is tainted. A spread (**x) or a computed key is
        skipped, so only a specific tainted field is recoverable later by d[key] or d.get(key)."""
        out = {}
        for k, v in zip(node.keys, node.values, strict=True):
            if k is None or not isinstance(k, ast.Constant):
                continue
            t = self._taint_of(v, env)
            if t:
                out[k.value] = t.extend(
                    _step(node, "tainted value stored under dict key %r" % (k.value,)))
        return out

    # -- sinks --
    def _sink_of(self, node, env):
        if not isinstance(node, ast.Call):
            return None
        fn = _dotted(node.func)
        leaf = _leaf(fn) if fn else getattr(node.func, "attr", None)
        if fn in _OS_SHELL:
            return self._hit(node.args[0] if node.args else None, env, "os.%s" % leaf)
        if fn in _EVAL:
            return self._hit(node.args[0] if node.args else None, env, fn)
        if leaf in _ALWAYS_SHELL and fn and "subprocess" in fn:
            return self._hit(self._command_expr(node), env, fn)
        if leaf in _SHELL_FUNCS and self._has_shell_true(node):
            return self._hit(self._command_expr(node), env, fn or leaf)
        return None

    @staticmethod
    def _command_expr(node):
        """The command expression of a subprocess call: the first positional arg, or the
        `args=`/`command=` keyword. subprocess.run(args=<tainted>, shell=True) puts the
        command in a keyword, so requiring a positional arg missed a real injection."""
        if node.args:
            return node.args[0]
        for kw in node.keywords:
            if kw.arg in ("args", "command", "cmd"):
                return kw.value
        return None

    @staticmethod
    def _has_shell_true(node):
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    def _hit(self, expr, env, sink_name):
        if expr is None:
            return None
        t = self._taint_of(expr, env)
        return (t, sink_name) if t else None

    def _returns_source(self, funcnode):
        """The source kind a self-defined function returns DIRECTLY (e.g. `return sys.argv[1]`),
        or None. Bounded: it looks only at returns in the function's own scope, not in a
        nested function, so calling such a helper laundering an untrusted value is caught."""
        stack = list(funcnode.body)
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue                        # a nested scope's return is not this function's
            if isinstance(n, ast.Return) and n.value is not None:
                kind = self._source_kind(n.value)
                if kind:
                    return kind
            for field in ("body", "orelse", "finalbody"):
                stack.extend(getattr(n, field, []) or [])
            for h in getattr(n, "handlers", []) or []:
                stack.extend(h.body)
        return None

    def _record(self, node, taint, sink_name):
        steps = taint.steps + [_step(node, "SINK: %s executes the tainted value" % sink_name)]
        if len(steps) < 2:
            return
        self.flows.append({
            "source_kind": taint.kind, "source_line": steps[0]["line"],
            "sink_line": node.lineno, "sink_name": sink_name, "steps": steps,
        })

    # -- traversal --
    def _maybe_descend(self, call, env, stack, depth):
        if depth >= _MAX_DEPTH:
            return
        callee = self._resolve_call(call)
        if callee is None or callee.name in stack:
            return
        # Only bare calls resolve (see _resolve_call), so the callee is a plain function and
        # every positional arg binds its parameter by index -- no implicit self/cls to skip.
        # Positional-only params come FIRST and are bound positionally; dropping them shifted
        # every later positional onto the wrong name (a wrong-param false positive AND a miss).
        params = callee.args.posonlyargs + callee.args.args
        sub_env = {}
        bound = False
        for i, arg in enumerate(call.args):
            if i >= len(params):
                break
            t = self._taint_of(arg, env)
            if t:
                p = params[i].arg
                note = ("interprocedural: argument %d binds parameter %s of %s()"
                        % (i, p, callee.name))
                sub_env[p] = t.extend(_step(call, note))
                bound = True
        # A keyword call arg binds by NAME to a matching parameter, so run(cmd=sys.argv[1]) is
        # followed like run(sys.argv[1]).
        param_names = {p.arg for p in params + callee.args.kwonlyargs}
        for kw in call.keywords:
            if kw.arg is None or kw.arg not in param_names:
                continue
            t = self._taint_of(kw.value, env)
            if t:
                note = ("interprocedural: keyword %s binds parameter %s of %s()"
                        % (kw.arg, kw.arg, callee.name))
                sub_env[kw.arg] = t.extend(_step(call, note))
                bound = True
        if bound:
            self._walk_scoped(callee, dict(sub_env), stack + [callee.name], depth + 1)

    def _walk_stmt(self, stmt, env, stack, depth):
        for call in [n for n in ast.walk(stmt) if isinstance(n, ast.Call)]:
            hit = self._sink_of(call, env)
            if hit:
                self._record(call, hit[0], hit[1])
            self._maybe_descend(call, env, stack, depth)
        if isinstance(stmt, ast.Assign):
            names = []
            for tgt in stmt.targets:
                names.extend(_target_names(tgt))
            # A dict literal with constant keys is tracked per key, so d["cmd"] carries the taint
            # of that key's value while d["safe"] stays clean. Marking the whole dict tainted the
            # moment one value is tainted would flag a constant-key read of the safe field -- the
            # false positive that made JSON/dict-mediated taint too costly to model naively.
            if isinstance(stmt.value, ast.Dict):
                keymap = self._dict_keymap(stmt.value, env)
                for n in names:
                    if keymap:
                        env[n] = keymap
                    else:
                        env.pop(n, None)
                return
            t = self._taint_of(stmt.value, env)
            if t:
                bound = t.extend(_step(stmt, "assignment binds tainted value"))
                for n in names:
                    env[n] = bound
            else:
                for n in names:
                    env.pop(n, None)
            return
        if isinstance(stmt, (ast.AugAssign, ast.AnnAssign)):
            val = getattr(stmt, "value", None)
            if val is not None and isinstance(stmt.target, ast.Name):
                t = self._taint_of(val, env)
                if t:
                    env[stmt.target.id] = t.extend(_step(stmt, "assignment binds tainted value"))
            return
        if isinstance(stmt, ast.With):
            for item in stmt.items:
                t = self._taint_of(item.context_expr, env)
                if t and item.optional_vars is not None:
                    bound = t.extend(_step(stmt, "context manager binds tainted resource"))
                    for n in _target_names(item.optional_vars):
                        env[n] = bound
            self._walk_body(stmt.body, env, stack, depth)
            return
        for attr in ("body", "orelse", "finalbody"):
            block = getattr(stmt, attr, None)
            if block:
                self._walk_body(block, env, stack, depth)
        for handler in getattr(stmt, "handlers", []) or []:
            self._walk_body(handler.body, env, stack, depth)

    def _walk_body(self, body, env, stack, depth):
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue                    # nested scopes are analysed in their own scope
            self._walk_stmt(stmt, env, stack, depth)

    def _resolve_call(self, call):
        """The function a BARE call targets, or None. A bare g() resolves against the current
        scope (a nested helper) then the module top level. A METHOD call obj.m()/self.m() is
        deliberately NOT resolved: a receiver's runtime type is unknowable statically -- self
        alone can be rebound by =, +=, :=, for/with/except, a match-capture or import-as, an
        unbounded set of forms -- so resolving by method name fabricated critical findings on
        benign code. Sinks inside methods are still analysed directly; only cross-method
        argument/return following is given up (a precision-over-recall choice)."""
        func = call.func
        if isinstance(func, ast.Name):
            return self._cur_locals.get(func.id) or self.top_funcs.get(func.id)
        return None

    def _walk_scoped(self, fn, env, stack, depth):
        """Walk one function body with its bare-call scope set: the functions nested directly
        in it (a bare nested call resolves here, then to a top-level function)."""
        prev_locals = self._cur_locals
        self._cur_locals = {n.name: n for n in fn.body
                            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        try:
            self._walk_body(fn.body, env, stack, depth)
        finally:
            self._cur_locals = prev_locals

    def analyze(self):
        self._cur_locals = self.top_funcs
        self._walk_body(self.tree.body, {}, [], 0)          # module scope, shared env
        # EVERY function body -- top-level, methods, nested -- each in a fresh env with its own
        # scope context. Driven from the list, so a same-named function cannot evict another.
        for fn in _all_functions(self.tree):
            self._walk_scoped(fn, {}, [fn.name], 0)
        # dedupe: keep the shortest flow per (source_line, sink_line, sink_name)
        best = {}
        for fl in self.flows:
            key = (fl["source_line"], fl["sink_line"], fl["sink_name"])
            if key not in best or len(fl["steps"]) < len(best[key]["steps"]):
                best[key] = fl
        return [best[k] for k in sorted(best)]


def _target_names(node):
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        out = []
        for el in node.elts:
            out.extend(_target_names(el))
        return out
    return []


def _const_key(node):
    """The literal key of a subscript or .get(), or None. `d["cmd"]` gives "cmd"; a variable
    key gives None, so a dynamic index into a per-key-tracked dict is left clean, not guessed."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, bytes)):
        return node.value
    return None


def _all_functions(tree):
    """Every FunctionDef/AsyncFunctionDef anywhere in the module -- top-level, methods in
    classes, and nested functions -- so each body is analysed in its own scope."""
    return [n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _is_all_const(node):
    """True if a literal is built entirely from constants (no Name/Call/Subscript element),
    so it is a real lookup table and safe to treat as a declassifier."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_all_const(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(k is not None and _is_all_const(k) and _is_all_const(v)
                   for k, v in zip(node.keys, node.values, strict=True))
    return False


def _finding(rel, flow):
    dropper = flow["source_kind"] == "network_response"
    vector = "SXV-018" if dropper else "SXV-008"
    rule = "py-remote-dropper" if dropper else "py-command-injection"
    if dropper:
        msg = ("a bundled script fetches remote content (%s) and executes it via %s: "
               "the code that runs is not the code reviewed"
               % (flow["source_kind"], flow["sink_name"]))
    else:
        msg = ("untrusted input (%s) reaches the shell sink %s through a proven "
               "assignment chain" % (flow["source_kind"], flow["sink_name"]))
    return Finding(
        vector=vector, rule=rule, severity="critical", path=rel, message=msg,
        line=flow["sink_line"],
        evidence={"source_kind": flow["source_kind"], "source_line": flow["source_line"],
                  "sink": flow["sink_name"], "steps": flow["steps"]})


def check(parsed) -> list:
    """Run Python taint over every parsed .py artifact and return SXV-008/018 findings.

    Per-ARTIFACT isolated: a single poisoned script that exhausts the stack or memory records a
    scoped check-error and the scan moves on, so one bad file never drops its siblings' flows."""
    out = []
    for p in parsed.artifacts:
        tree = getattr(p, "py_tree", None)
        if p.kind != "script_python" or not isinstance(tree, ast.Module):
            continue
        try:
            for flow in _Analyzer(p.rel, tree).analyze():
                out.append(_finding(p.rel, flow))
        except Exception as exc:
            # RecursionError and MemoryError are Exception subclasses, so this one handler
            # scopes every failure mode to THIS artifact; silence would read as clean, so the
            # coverage gap is recorded as a low finding on the file that caused it.
            out.append(Finding(
                vector="", rule="check-error", severity="low", path=p.rel,
                message="taint analysis of %s aborted: %s" % (p.rel, type(exc).__name__)))
    return out
