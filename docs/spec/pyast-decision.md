# `internal/pyast`: the Python-AST decision (measured 2026-09-18)

Question (WAVE1 C): code.md §4.1 specifies a hand-written CPython-3.13-exact parser of 3.5-4.5k
lines; the user's rule is libraries first. Decide by measurement between (a)
`github.com/go-python/gpython` parser+ast, (b) tree-sitter-python without cgo, (c) the hand-written
parser.

**Decision: (c), write `internal/pyast`.** No library reproduces CPython's acceptance, and acceptance
is a scanner output here (fence lifting, the high-severity `analysis-incomplete` finding,
`python_syntax_error`). gpython refuses 34.6% of the inputs CPython accepts. The only cgo-free
tree-sitter runtime accepts 303 of the 685 inputs CPython refuses (44%), flips 164 MaliciousSkillBench
records (16 in the test split), emits a tree that is neither CPython's nor upstream tree-sitter's, and
would still need a ~2.2k-line lowering plus an open-ended CPython-strictness rule list. The saving
over the hand-written parser is 1.3-2.3k lines against a 14 MB, 0.x, single-maintainer dependency.
Details, numbers and the fallback plan follow.

## 1. Inputs collected

Every string the oracle hands to `ast.parse` was captured by a pytest plugin that wraps `ast.parse`
(`tools/parity` scratch: `astcap.py`), so the set is exactly what the scanner parses, including the
combined fence sources `code_lane._lift_fences` builds, not a re-derivation from the spec. CPython's
verdict (ok / SyntaxError / IndentationError / RecursionError) was recorded on the same call.

| corpus | how | unique sources | CPython ok | CPython refuses | bytes |
|---|---|---|---|---|---|
| pytest (oracle `tests/`, 3,209 tests: 3,099 passed, 110 skipped, 776 s) | `_parse_python` (.py files): 493; `_pyast.parse` (fences, lifted fences, bridge re-parse): 329; both: 240 | 582 scanner inputs (+74 harness-only: `test_findings._referenced_vectors` and a `sarif.py` import-time parse of the package's own sources) | 573 | 7 SyntaxError, 2 RecursionError (`bomb.py`, twice) | 1.9 MB |
| MSB, all 9,740 records (`skill_text`, falling back to `public_skill_text` as `benchmark/msb_run.py` does), materialised as `SKILL.md`, run through `parse_package` + `build_code_lane` | 10,755 python-classified fences in 2,259 records (test 578, train 1,519, validation 162); 0 `.py` files | 11,351 | 10,675 | 633 SyntaxError, 43 IndentationError | 10.7 MB |
| total | | 12,007 (no sha overlap) | 11,322 | 685 | 12.6 MB |

Syntax the accepted inputs exercise (CPython tags, count of inputs): f-strings 3,257 (format specs
455, PEP 701 multi-line expressions 65, nested quotes 6), non-ASCII 1,160, comprehensions 915,
tabs/backslash continuations 812, async/await 635, decorators 615, annotated assignments 363, lambda
237, bytes 127, starred 74, keyword-only 22, match 17, walrus 16, type params 3, posonly 6, TypeAlias 0.
98 distinct CPython node kinds occur; the 3.13 kinds absent from the corpus are `UAdd`, `TryStar`,
`TypeAlias`, `ParamSpec`, `TypeVarTuple`, `MatchOr`, `MatchSequence`, `MatchSingleton`, `MatchStar`
(and the non-module roots `Interactive`, `Expression`, `FunctionType`, `TypeIgnore`), so those need
synthetic fixtures. CPython AST depth (as `parse._parse_python` counts it, expr_context singletons
included): 11,288 inputs <= 16, 28 <= 32, 5 <= 64, one at 305 (`deep.py`); the 512 ceiling is only
reachable by synthetic input.

## 2. Candidates and parse-success parity

Tool: `tools/pyast-eval` (own `go.mod`; `go build ./... && go vet ./...` clean). It parses every
input with both libraries and joins the CPython verdict; `-probes` runs 62 one-feature programs.
The tool was deleted from the tree after the closing ponytail audit (2026-09-18; `git log --all -- tools/pyast-eval` reaches it); this document keeps its numbers and command lines.

| | (a) gpython v0.2.0 | (b) gotreesitter v0.52.0 + embedded tree-sitter-python |
|---|---|---|
| CPython accepts, library refuses | **3,916 / 11,322 (34.6%)** | **0** |
| CPython refuses, library accepts | 28 / 685 (26 "positional argument follows keyword argument", 2 RecursionError) | **303 / 685 (44%)** |
| total disagreement | 3,944 / 12,007 | 303 / 12,007 (2.5%) |
| wall time, 12.6 MB | 0.5 s (median 0 ms) | 16.6 s (median 1.0 ms, p99 7.6 ms, max 78 ms on 1.2 MB); no timeouts |
| positions | `lineno`, `col_offset` only; column counted in runes | start/end `Point{Row, Column}` per node, **byte** columns; verified equal to CPython on `s = "éé"; x = f(a.b, k=1)`, a decorated `def`, and a parenthesised multi-line `return` |
| binary cost | small | +33.9 MB (all 206 grammars) or +14.3 MB with `-tags grammar_subset,grammar_subset_python` |
| maintenance | last tag v0.2.0 (2022), Python 3.4 grammar | 97 releases, 12 in the last 60 days, one maintainer, ~1,000 files at repo root, CHANGELOG carries an open correctness issue (#1087) with a disabled shortcut; `go 1.22`, deps `x/sync`, `yaml.v3` |

Why gpython refuses (tags on the 3,916 refused inputs): f-strings 3,257, async 635, annotated
assignment 363, `1_000` literals, `@` matmul, `*`/`**` unpacking in calls and dicts (3.5+), posonly
`/`, walrus, match, `except*`, type params, PEP 614 decorators, `\f` form feed. The probes confirm
each individually (`fstring_simple`, `async_def_await`, `annassign`, `walrus`, `posonly_params`,
`match_stmt`, `type_params_pep695`, `type_alias_pep695`, `except_star_pep654`, `parenthesized_with`,
`star_unpack_return`, `unpack_call_kwargs`, `dict_unpack`, `matmul`, `underscore_numeric`,
`decorator_expr_pep614`, `form_feed` all fail). Rejected outright.

Why tree-sitter accepts what CPython refuses (303 inputs; median 3 lines, max 84):

| CPython error | inputs | example |
|---|---|---|
| `invalid syntax`: statements juxtaposed on one line (shell command lines and prose inside ```` ```python ```` fences: `python scripts/x.py <in> [out.md]`) | 218 | parsed as `(identifier) (comparison_operator ...)` with no ERROR node |
| positional argument follows keyword argument | 26 | `create(tenant_id=x, ...)` |
| IndentationError: expected an indented block (def/class/if followed by comments only) | 33 | `(function_definition ... (block))` with an empty block |
| leading zeros in decimal integer literals | 6 | `0001172661-25-003151` |
| IndentationError: unexpected indent | 4 | |
| py2 `print 'x'` (a `print_statement` node exists in the grammar) | 2 | |
| RecursionError (`bomb.py`) | 2 | 3,000-term `+` chain |
| singletons: `expected ':' after dictionary key`, `expected 'except' or 'finally' block`, parameter without default after default, unterminated string / f-string, invalid decimal literal | 12 | |

Probes add TabError (mixed tab/space indentation), `except Exception, e`, `0777`, `ur''`, py2
`exec 'x'`, backtick repr, 201 nested parentheses: all accepted by tree-sitter, all refused by CPython.
Each bucket is a post-check the adapter would have to add, and the list is open: tree-sitter is built
to recover, not to refuse. Five rules cover 287 of 303; the tail is 12 inputs across 6 error kinds
in this corpus alone.

Impact of the 303 on parity (rerun over MSB, matching fence content and lifted sources): **164
records** carry at least one flipped fence: test split 16 (4 benign, 12 malicious), train 134,
validation 14; 218 fences flip at fence level. Each flip changes fence lifting and adds or removes a
high-severity `analysis-incomplete` finding, so `corpus/msb-test` would fail parity on 16 of 1,384
records before any strictness layer is written.

Tree shape: the gotreesitter runtime does not emit `expression_statement` (upstream
tree-sitter-python always does; the runtime's `parser_collapsed_child_policy.go` folds
"public-wrapper/raw-child" pairs, and `parser_result_python.go` / `parser_result_python_recovery.go`
re-shape Python results). `except*` parses as a plain `except_clause` (no `except_group_clause`
symbol in the embedded grammar). So the tree an adapter would consume is specific to this runtime
version, not to tree-sitter-python, and the 12 releases in two months move it.

Option (b) via the official wasm grammar under `wazero` was not built: the web-tree-sitter
`tree-sitter.wasm` is an emscripten build whose imports would have to be re-implemented in Go before a
single parse, and the result is the same CST needing the same lowering and the same strictness layer;
its only gain over gotreesitter would be upstream fidelity, which cannot be measured on this machine
(no cgo binding, no `tree_sitter_python` wheel installed).

## 3. The 181 bridge usages mapped

`opengrep_bridge.py` names 66 distinct `ast.*` attributes (181 uses); `parse.py` uses `ast.parse`
and `ast.iter_child_nodes`; `_pyast.py` uses `ast.parse`, `ast.Attribute`, `ast.Name`. Fields read
(grep of `.func .args .keywords .value(s) .targets .target .id .attr .lineno .col_offset .end_lineno
.end_col_offset .name .names .asname .module .level .elts .keys .op .ops .left .operand .slice
.posonlyargs .kwonlyargs .vararg .kwarg .defaults .kw_defaults .decorator_list .body .orelse
.finalbody .generators .cases .rest .arg .items .kind .ctx`): 55 `.value`, 42 `.lineno`, 40 `.func`,
30 `.args`, 27 `.id`, 18 `.end_lineno`, 13 `.targets`, 10 `.col_offset`, 8 `.keywords`, 6 `.attr`,
5 `.posonlyargs`, 3 `.end_col_offset` (with `or` fallbacks at bridge:223, 299, 514, 587, 739, 940,
980, 1365, 1393, 1414).

| `ast.X` (uses) | gpython v0.2.0 | tree-sitter-python node / fields (all names verified with `pyast-eval -symbols`) | adapter work if (b) |
|---|---|---|---|
| Module (20), stmt (4) | `Module`; `Stmt` interface | `module`; statement nodes | synthesise `Expr` around bare expressions (runtime drops `expression_statement`) |
| walk (19), iter_child_nodes (3) | `ast.Walk` is DFS pre-order, not CPython's BFS `walk`; no `iter_child_nodes` | `Walk` over CST | write both over the synthesised tree (needed in (c) too) |
| Name (22) `.id .ctx` | `Name{Id, Ctx}` | `identifier`; ctx from parent (assignment left, `for` left, `del`, `as` target, pattern) | ctx synthesis |
| Call (20) `.func .args .keywords` | `Call{Func, Args, Keywords, Starargs, Kwargs}` (3.4 shape: `*a` not a `Starred` in `Args`) | `call(function, arguments=argument_list)`; children: expr, `keyword_argument(name,value)`, `list_splat`, `dictionary_splat` | fold splats into `Starred` / `keyword(arg=nil)`; `f(x for x in y)` has `generator_expression` as arguments |
| Assign (11) `.targets .value` | `Assign{Targets, Value}` | `assignment(left, right)`; `a = b = c` nests `assignment` on the right | flatten chains to `targets` |
| AnnAssign (7) `.target .value .annotation` | **absent** | `assignment(left, type, right?)` | split by presence of `type` field; `simple` flag from `left` being a bare identifier |
| AugAssign (3) | `AugAssign` | `augmented_assignment(left, operator, right)` | operator from token text |
| Delete (2) `.targets` | `Delete` | `delete_statement` (`expression_list` or single) | Del ctx |
| FunctionDef (9), AsyncFunctionDef (10) `.name .args .body .decorator_list .lineno .end_lineno` | `FunctionDef`; **no Async** | `function_definition(name, parameters, return_type, body)`; `async` is an anonymous child; `decorated_definition(decorator+, definition)`; `type_parameter` | position of `FunctionDef` is the `def` line (matches CPython 3.8+); decorators lifted from the wrapper |
| ClassDef (9) `.name .body .bases .keywords` | `ClassDef` (with 3.4 `Starargs/Kwargs`) | `class_definition(name, superclasses=argument_list, body)` | bases vs `keyword_argument` split |
| Lambda (2) `.args .body` | `Lambda` | `lambda(parameters=lambda_parameters, body)` | |
| arg (1), arguments `.posonlyargs .args .kwonlyargs .vararg .kwarg .defaults .kw_defaults` | `Arguments` **without `posonlyargs`** | `parameters` children: `identifier`, `default_parameter`, `typed_parameter`, `typed_default_parameter`, `list_splat_pattern`, `dictionary_splat_pattern`, `positional_separator`, `keyword_separator` | rebuild the 7 CPython lists incl. `kw_defaults` `None` slots |
| Import (3), ImportFrom (5), alias (1) `.names .name .asname .module .level` | present | `import_statement` (`dotted_name` / `aliased_import(name, alias)`), `import_from_statement(module_name=dotted_name|relative_import(import_prefix, dotted_name))`, `wildcard_import`, `future_import_statement` | `level` = count of dots in `import_prefix` |
| Global (2), Nonlocal (1) `.names` | present | `global_statement`, `nonlocal_statement` | |
| If (1), For (1), AsyncFor (1), While (1), Try (1) `.body .orelse .finalbody .handlers` | `If For While Try`; **no AsyncFor** | `if_statement(condition, consequence, alternative=elif_clause*|else_clause)`, `for_statement(left, right, body, alternative)`, `while_statement`, `try_statement(body, except_clause*, else_clause?, finally_clause?)` | nest `elif_clause` chain into `orelse`; `TryStar` indistinguishable except by a `*` token child |
| Match (1), MatchAs (2), MatchStar (1), MatchMapping (1) `.cases .pattern .name .rest` | **absent** | `match_statement(subject, body=case_clause*)`, `case_clause(case_pattern+, guard=if_clause, consequence)`; patterns: `as_pattern`, bare `identifier` capture, empty `case_pattern` = `_`, `splat_pattern`, `dict_pattern`, `list_pattern`/`tuple_pattern`, `class_pattern`, `union_pattern` | full pattern lowering (8 kinds) even though the bridge reads 3 |
| ExceptHandler (1) `.name .type .body` | `ExceptHandler{ExprType, Name, Body}` | `except_clause` children: expr, optional `as_pattern`, `block` | |
| Expr (1), Return (1), Await (1) | `ExprStmt`, `Return`; **no Await** | bare expression, `return_statement`, `await` | |
| Attribute (8) `.value .attr` | `Attribute{Value, Attr}` | `attribute(object, attribute)` | |
| Subscript (7) `.value .slice` | `Subscript{Value, Slice: Index|Slice|ExtSlice}` (3.4 wrappers) | `subscript(value, subscript+)`; `slice` | multiple indexes become a `Tuple` (3.9+ shape) |
| Starred (2) | `Starred` | `list_splat` / `list_splat_pattern` | |
| List (7), Tuple (6), Set (3), Dict (4) `.elts .keys .values` | present | `list`, `tuple`, `expression_list`/`pattern_list`/`tuple_pattern` (store side), `set`, `dictionary(pair(key,value)|dictionary_splat)` | `**x` → `keys[i] = None`; parenthesised tuples include the parens (matches CPython 3.8+) |
| ListComp (1), SetComp (1), DictComp (1), GeneratorExp (1) `.generators` | present | `*_comprehension(body, for_in_clause(left, right)+, if_clause*)`, `generator_expression` | `comprehension(target, iter, ifs, is_async)` from `for_in_clause` and its `async` token |
| BoolOp (1) `.values .op`, And (1), Or (1) | `BoolOp` | `boolean_operator(left, operator, right)` nested left | flatten same-operator chains into `values` (CPython shape) |
| BinOp (1) `.left .right .op`, BitOr (2) | `BinOp` | `binary_operator(left, operator, right)` | |
| UnaryOp (1) `.operand`, Not (1) | `UnaryOp` | `unary_operator(operator, argument)`, `not_operator(argument)` | |
| Compare (1) `.left .ops .comparators`, Eq NotEq Lt LtE Gt GtE Is IsNot In NotIn (10) | `Compare` | `comparison_operator` (operands as children, `operators` field; `not in` / `is not` are two tokens) | |
| Constant (1) `.value .kind`, literal_eval (4) | `Num Str Bytes NameConstant Ellipsis` (no `Constant`, no `kind`) | `string(string_start, string_content|escape_sequence|interpolation, string_end)`, `concatenated_string`, `integer`, `float`, `true`, `false`, `none`, `ellipsis` | decode Python literal syntax: prefixes r/b/u/f/rb, `\x \u \U \N{}` and octal escapes, implicit concatenation, `_` digit separators, `0x/0o/0b`, big ints, imaginary; f-strings → `JoinedStr(FormattedValue(value, conversion, format_spec))`; `kind="u"` from `string_start` text. Needed in (c) as well (~300 lines) |
| Load (1), Store (2), Del (1) | present | not nodes | synthesise |
| SetComp/ListComp/... scope tuple `_PY_SCOPES` | | | |

Gaps that decide: gpython lacks 9 of the 66 names (`AsyncFunctionDef`, `AnnAssign`, `Constant`,
`Await`, `AsyncFor`, `Match`, `MatchAs`, `MatchStar`, `MatchMapping`), `posonlyargs`, `end_lineno`,
`end_col_offset`, `kind`, BFS `walk`, and parses a 3.4 grammar; it cannot be adapted, only replaced.
tree-sitter exposes every construct with byte-exact positions, but as a concrete syntax tree: none of
the 66 kinds exists as such, every one is synthesised by the lowering, plus the 32 kinds the bridge
never names but `walk`/`iter_child_nodes`/depth/`literal_eval` traverse (`Pass Break Continue Raise
Assert With AsyncWith withitem Yield YieldFrom IfExp NamedExpr Slice JoinedStr FormattedValue
TypeAlias TypeVar ParamSpec TypeVarTuple MatchValue MatchSingleton MatchSequence MatchClass MatchOr
TryStar` and the operator singletons), because the depth-512 `python_too_complex` diagnostic counts
CPython nodes, not CST nodes.

## 4. Estimates and the recommendation

| | lines of Go (excl. tests) | acceptance parity | positions | dependency |
|---|---|---|---|---|
| (a) gpython | n/a | 34.6% false refusals | no end positions | dead |
| (b) gotreesitter + adapter | lowering of ~98 node kinds ~1,500; literal decoding ~300; CPython strictness rules ~150 for the 5 known buckets (+1 rule per newly found error kind); `Walk`/`IterChildNodes`/`Depth`/`LiteralEval` ~250: **~2,200** | 303/12,007 flips before the rules, residual unknown (tree-sitter recovers by design; 12 singleton error kinds in this corpus alone) | byte-exact (verified) | 14.3 MB with the python-only tag, 0.x, single maintainer, runtime-specific tree shape |
| (c) hand-written | tokenizer (indent stack, PEP 701 f-string modes, numbers, soft keywords) ~900; recursive-descent parser for the 3.13 grammar incl. patterns and type params ~2,000; node types + `Walk`/`IterChildNodes`/`Depth` ~400; literal decoding ~300; `LiteralEval` ~200: **~3,800** (code.md's 3.5-4.5k holds) | refusals fall out of the grammar; proven by the 12,007-input `ast.dump(include_attributes=True)` fixture set this measurement produced (11,322 accepted, 685 refused with CPython's error class) | by construction | none |

Delta: (b) saves roughly 1,300-2,300 lines and costs a 14 MB dependency, an acceptance model that
disagrees with CPython on 2.5% of real inputs (16 test-split MSB records) and can only be patched
rule by rule, and a tree shape owned by a fast-moving 0.x runtime. Under the parity contract
("proven by the harness, never asserted", high-severity finding on every flip) that trade is wrong.
**Write `internal/pyast` (option c)** as code.md §4.1 specifies, with these corrections from the
measurement:

1. Fixtures first: the 12,007 collected inputs (scratch `inputs/{pytest,msb}/<sha>.py` +
   `manifest.jsonl`, regenerable with `astcap.py` and `msb_collect.py`) are the `testdata/pyast`
   corpus; generate `ast.dump(tree, include_attributes=True)` once with CPython 3.13.2 for the 11,322
   accepted inputs and the error class for the 685 refused ones. Add the 62 probe programs.
2. Limits, measured on this CPython 3.13.2/Windows build with `sys.getrecursionlimit() == 1000`:
   nested parentheses/brackets/calls: 200 ok, 201 → `SyntaxError: too many nested parentheses`;
   indentation: 99 levels ok, 100 → `SyntaxError: too many levels of indentation` (a SyntaxError,
   not IndentationError); left-associative chains (`'a'+'a'+…`, `-…-1`, `not …`, `a.b.b…`,
   `a[0][0]…`, `1 if 1 else …`): 2,994-2,995 ok, 2,995-2,996 → `RecursionError: maximum recursion
   depth exceeded during ast construction`; nested `lambda:` 2,983 ok, 2,984 → `MemoryError`. So
   `bomb.py` (3,000 terms) is `python_too_complex` in the oracle (`test_opengrep_parity` asserts it)
   and `deep.py` (300) parses at depth 305. Implement the ceiling as a constant near 2,995 nested
   expression nodes raising the RecursionError-equivalent, `// ponytail:` noting it is
   build-dependent and pinned only by `bomb.py`/`deep.py`; the overview §7 divergence entry stays.
3. `Depth` counts expr_context singletons as children, as `ast.iter_child_nodes` does (the corpus
   maximum outside `deep.py` is 64, so the 512 boundary is exercised only by synthetic tests).
4. Fallback if the parser slips past its slot: gotreesitter with the python-only build tag and the
   lowering in §3, shipped with the five strictness rules (juxtaposed statements on one line without
   `;`, positional-after-keyword, empty `block` after `:`, leading-zero decimal literals,
   `print_statement`/`exec_statement`) and the 164-record MSB delta recorded in
   `known_divergences.json`; measured cost known, not guessed.

## 5. Spec errors found

- code.md §4.1 and §8.2: "`bomb.py` = 3,000 `"a"+"a"+…` parses and is analysed" is wrong; CPython
  3.13 raises `RecursionError` during AST construction at ~2,996 chained terms and
  `tests/test_opengrep_parity.py:284` expects `bomb.py: python_too_complex`. Only `deep.py` (300)
  parses. The parser must stop, not iterate, at that depth.
- code.md §4.1 option (b): "tree-sitter Go bindings — cgo, forbidden" — a pure-Go runtime exists
  (`github.com/odvcencio/gotreesitter`, 206 grammar blobs, external scanners ported); it is rejected
  on measurement (§2), not on cgo.
- code.md §4.1: `MAXINDENT = 100` "indentation levels" produces `SyntaxError("too many levels of
  indentation")`, not `IndentationError`; both map to "not a module", so no behaviour change, but
  the error class recorded in fixtures differs.
- WAVE1 C names the bridge as `checks/opengrep_bridge.py`; the oracle file is
  `src/skill_xray/opengrep_bridge.py` (counts 181/4/3 confirmed).

## 6. Reproduction

```
# capture (scratch): PYTHONPATH=<scratch>/plugin;<oracle>/src ASTCAP_OUT=<dir>
python -m pytest <oracle>/tests -q -p astcap                     # 3,099 passed, 110 skipped, 776 s
python msb_collect.py <msb-snapshot>                             # 9,740 records, 298 s
python features.py <dir>                                         # CPython syntax tags
cd tools/pyast-eval && go build -o pyast-eval.exe . && go vet ./...
./pyast-eval.exe -kinds -inputs <pytest-dir> -inputs <msb-dir> -out results.jsonl   # 12,007 inputs, 17.4 s
./pyast-eval.exe -probes; ./pyast-eval.exe -dump-probes | python probes_cpython.py
./pyast-eval.exe -symbols <names>; ./pyast-eval.exe -sexpr <file>
go build -tags grammar_subset,grammar_subset_python ./tsonly     # 14,259,200 bytes vs 33,896,960
```
