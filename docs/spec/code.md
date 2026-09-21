# Porting specification: group `code`

> **Errata (00-overview).** Read this spec with these substitutions; `00-overview.md` is binding.
> - `ir.*` is `parse.*` (`internal/parse` owns the IR; there is no `internal/ir`). `ManifestIndex` and
>   `GoverningManifest` are exported from `parse`, not `codelane` (codelane calls them).
> - Python `None` is a pointer/nil, never a `HasX` bool: `parse.Artifact.Text *string`, `Grants []Grant`
>   (nil == None), `Deps []Dep` (nil == None), `Diagnostic.Detail *string`, `Dep.Line *int`,
>   `Grant.Pattern *string`; spans are `[]parse.Span{Start, End}`.
> - `internal/pystr` is `internal/pytext` (owned by core; same contents plus `Canonical`, `Dumps`, `Repr`,
>   `Quote`, `OSErrorName`). `codelane.DropHostRE` (`*regexp.Regexp`) is exported; callers use `codelane.DropHostRE.MatchString(host)`.
>   `grants.ExecutionTools` and `grants.NetworkTools map[string]bool` are exported (capability needs them).
> - Observations are `map[string]any` records (keys `path, line, column, capability, state, analyzer, rule,
>   vector, engine_rule, origin, reason?`) and `Options.Observations` is `*[]map[string]any`; the
>   `Observation` struct in §1.4 documents the keys only (00-overview D9).
> - OpenGrep JSON: after the `UseNumber` decode the tree is normalised once (`json.Number` -> `int` when
>   integral and within int64, else `float64`) so evidence never carries `json.Number` (00-overview D7);
>   `isInt` is then the plain `int` assertion shared with core.
> - `supplychain.ReplaceSecrets(text string, repl func(string) string) string` applies every rule's bounded
>   matches in table order; `_redact_source_secrets` and `llm/privacy` both call it.
> - `parse.Package` (the function) is `parse.Parse`; `ingest.Build` is `ingest.BuildPackage`.
> - Toolchain: `go 1.26.0` (risk 5 superseded). `tools/extract_cases.py` lives in `tools/parity/` and reads
>   `skill-xray/` without modifying it.

Source (Python, `skill-xray` main @ 33f057e, 6,249 lines including the 2,165-line rule file):

| Python module | lines | Go package | notes |
|---|---|---|---|
| `checks/code_lane.py` | 322 | `internal/codelane` | code-unit selection, fence lifting, installer idiom, manifest index |
| `checks/grants.py` | 495 | `internal/grants` | SXV-003 / SXV-004 |
| `checks/supply_chain.py` | 368 | `internal/supplychain` | SXV-016 / SXV-017 |
| `checks/taint_engine.py` | 40 | `internal/opengrep` (`Check`) | 20-line wrapper; no package of its own |
| `checks/_pyast.py` | 26 | `internal/pyast` | becomes the whole Python-AST package (see §4.1) |
| `opengrep_bridge.py` | 2,026 | `internal/opengrep` | selection, process boundary, report translation, Python AST post-filters, fence mapping |
| `opengrep_runtime.py` | 192 | `internal/opengrep` (`runtime.go`) | pinned binary discovery / verification / install |
| `rules/opengrep-phase1.yml` | 2,165 | `internal/opengrep/rules/opengrep-phase1.yml` (`//go:embed`) | stays a data file, byte-identical |
| `analyze.py` | 615 | `internal/forensics` | SXV-035 / 036 / 037 byte forensics (`analyze` is not a Go-idiomatic package name) |

Decisions made in this document and not left open: (1) a hand-written pure-Go Python 3.13 parser
(`internal/pyast`) replaces `ast`; (2) zero `regexp2` patterns, both lookaround patterns are rewritten
(§3); (3) OpenGrep JSON is decoded to a generic `any` tree with `json.Number`, not typed structs
(§4.6); (4) the rule file is embedded and written to the scan's temp root at run time (§2.6.14);
(5) Python string and regex semantics live in one small shared package `internal/pytext` used by every
group (§5); (6) pytest inline cases become JSONL tables extracted once by a script, never Go literals
(§6).

Everything below cites the Python line numbers of `src/skill_xray/...` so an implementer can verify
a detail without re-reading the modules.

---

## 1. Public surface

"Public" = imported or attribute-accessed from another module in `src/` or `tests/`. Grep basis:
`checks/__init__.py`, `scan.py`, `cli.py`, `sarif.py`, `correlate.py`, `capability.py`,
`checks/instruction_exfil.py`, `llm/judge.py`, `llm/privacy.py`, and the 21 test files that touch the
group.

### 1.1 Identifier map

| Python | consumers | Go identifier | Go type / signature |
|---|---|---|---|
| `code_lane.CodeUnit` | bridge, checks | `codelane.Unit` | `struct{Rel, Kind, Text, Origin string; Dialect string}` (`Dialect==""` is Python `None`) |
| `code_lane.build_code_lane(parsed)` | `checks/__init__.py:47`, bridge, tests | `codelane.Build(pkg *parse.Package) ([]Unit, []findings.Finding)` | never errors; failures are findings |
| `code_lane.installer_idiom(text)` | bridge:1582, `instruction_exfil.py:45,1433` | `codelane.InstallerIdiom(string) bool` | |
| `code_lane._DROP_HOST_RE` | `instruction_exfil.py:45` | `codelane.DropHostRE.MatchString(host string) bool` | the regexp is exported because the instruction group calls it (`_DROP_HOST_RE.search(host)`) |
| `code_lane._manifest_index(parsed)` | bridge, `correlate.py:11`, `capability.py:9`, `llm/judge.py:9` | `parse.ManifestIndex(pkg) map[string]*parse.Artifact` | key = parent dir ("" for root) |
| `code_lane._governing_manifest(index, rel)` | same | `parse.GoverningManifest(index, rel string) *parse.Artifact` | nil when none |
| `code_lane._SUPPORTED_SHELL_DIALECTS` | bridge:19 | exported map `codelane.SupportedShell map[string]bool` | |
| `grants.check(parsed)` | `checks/__init__.py:28` | `grants.Check(pkg) []findings.Finding` | |
| `grants.effective_grants(g)` | bridge:25, `capability.py:16` | `grants.Effective([]parse.Grant) []parse.Grant` | |
| `grants.declared_capabilities(g)` | bridge, `capability.py:14` | `grants.Declared([]parse.Grant) map[string]bool` | keys ⊆ {"execution","network"} |
| `grants.denied_capabilities(g)` | bridge, `capability.py:15`, `test_grants.py:9` | `grants.Denied([]parse.Grant) map[string]bool` | |
| `grants._EXECUTION_TOOLS`, `grants._NETWORK_TOOLS` | `capability.py:12-13`, `instruction_exfil.py` (own copies) | `grants.ExecutionTools`, `grants.NetworkTools map[string]bool` | P:10-11, copied verbatim |
| `supply_chain.check(parsed)` | `checks/__init__.py:35`, tests | `supplychain.Check(pkg) []findings.Finding` | |
| `supply_chain._SECRET_RULES` | `llm/privacy.py:5` | `supplychain.SecretRules []SecretRule` | `struct{ID string; Pattern *regexp.Regexp; Left, Right bool; Severity string}` (see §3.4 boundary scanner); `supplychain.ReplaceSecrets(text string, repl func(string) string) string` applies every rule's bounded matches in table order (used by `_redact_source_secrets` and `llm/privacy`) |
| `supply_chain._sanitize_source(s)` | `llm/privacy.py:5` | `supplychain.SanitizeSource(string) string` | |
| `supply_chain._redact(s)` (via rules) | privacy indirectly | `supplychain.Redact(string) string` | |
| `taint_engine.check(parsed, *, executable, opengrep_runner, code_units, lane_notes, observations)` | `checks/__init__.py:36,56-63` | `opengrep.Check(pkg, opengrep.Options) []findings.Finding` | see §2.6.11 |
| `opengrep_bridge.SelectedCode` | tests | `opengrep.Selected` | `struct{Rel, Text, Origin, Suffix string}`; `Suffix` default ".py" |
| `opengrep_bridge.select_executable_code(parsed, code_units=None, *, languages=("python",))` | tests | `opengrep.Select(pkg, units []codelane.Unit, languages []string) []Selected` | `units==nil` → build |
| `opengrep_bridge.findings_from_report(report, targets, *, parsed, redactions, observations)` | tests (bridge, fence, capability) | `opengrep.FindingsFromReport(report any, targets map[string]Selected, pkg *parse.Package, redactions []string, obs *[]map[string]any) []findings.Finding` | |
| `opengrep_bridge.check(parsed, *, executable, rules, timeout, runner, code_units, languages, observations)` | taint_engine, tests | `opengrep.Run(pkg, Options) []findings.Finding` | |
| `opengrep_bridge._RULES` | `test_opengrep_bridge.py:16` | `opengrep.Rules []byte` (embedded) | test parses YAML from bytes |
| `opengrep_bridge._MAX_POSTFILTERS_PER_TARGET`, `_MAX_REPORT_BYTES` | tests (monkeypatch) | package vars `maxPostfiltersPerTarget = 32`, `maxReportBytes = 16<<20` | vars, not consts, so tests can lower them |
| `opengrep_runtime.VERSION` | `cli.py:23`, `sarif.py:23` | `opengrep.Version = "1.29.0"` | reaches JSON `analysis.opengrepVersion` and SARIF `runs[0].properties.opengrepVersion` |
| `opengrep_runtime.OpenGrepRuntimeError` | cli, bridge, tests | `opengrep.RuntimeError` (`type RuntimeError struct{Msg string}`; `Error()`) | callers use `errors.As` |
| `opengrep_runtime.OpenGrepAsset` | tests | `opengrep.Asset` | `struct{Name string; Size int64; SHA256 string}`; `URL()` |
| `opengrep_runtime.platform_asset(system, machine)` | tests | `opengrep.PlatformAsset(goos, goarch string) (Asset, error)` | accepts Python spellings too (§2.7.1) |
| `default_cache_dir()`, `cached_executable(dir)` | tests | `opengrep.DefaultCacheDir() string`, `opengrep.CachedExecutable(dir string) string` | |
| `verify_executable(path, asset=None)` | tests, bridge | `opengrep.VerifyExecutable(path string, asset *Asset) (string, error)` | |
| `resolve_opengrep(explicit=None)` | bridge, tests (4 files) | `opengrep.Resolve(explicit string) (string, error)` | `("", nil)` = Python `None` |
| `install_opengrep(cache_dir=None, *, opener, timeout)` | `cli.py:24,156` | `opengrep.Install(cacheDir string, client *http.Client) (string, error)` | `client==nil` → default with 60s timeout |
| `analyze.analyze_package(parsed)` | `checks/__init__.py:8,26` | `forensics.AnalyzePackage(pkg) []findings.Finding` | |
| `analyze.analyze_artifact(rel, kind, text, raw)` | tests | `forensics.AnalyzeArtifact(rel, kind string, hasText bool, raw []byte) []findings.Finding` | Python `text` is only tested for `is not None` (analyze.py:248) |
| `analyze.sniff_magic(raw)` | tests | `forensics.SniffMagic([]byte) string` | `""` = Python `None` |
| `_pyast.parse(source)` | code_lane, bridge | `pyast.Parse(src string) (*pyast.Module, error)` | error kinds §4.1 |
| `_pyast.dotted(node)` | bridge | `pyast.Dotted(n Node) string` | `""` = Python `None` |

Dropped Python ceremony: `__all__`, kwargs plumbing (`**({"observations": ...} if ... else {})` at
`taint_engine.py:351` and `checks/__init__.py:62` becomes a nil pointer), the `opener=urlopen`
injection (Go takes an `*http.Client`), the `runner=subprocess.run` injection becomes an
`Options.Runner` func field (needed by 20+ tests), `id(target)`-keyed caches become caches keyed by
target name.

### 1.2 Data shapes this group reads from the IR (owned by the parse/core groups)

The Go field names are what this spec assumes; the parse spec must provide them (cross-group need).

```
parse.Package    { Artifacts []*Artifact (ingest order); ByRel map[string]*Artifact }
parse.Artifact   { Rel, Kind string
                Text *string                       // nil ⇔ Python .text is None
                Raw []byte                          // nil ⇔ Python .raw is None; bounded by ingest
                Frontmatter map[string]any          // nil ⇔ None
                FrontmatterKeyLines map[string]int  // key -> 1-based line
                Grants []Grant                      // nil ⇔ Python .grants is None; []Grant{} == []
                Markdown *Markdown                  // nil ⇔ None
                PyTree *pyast.Module                // nil ⇔ None
                Deps []Dep                          // nil ⇔ Python .deps is None (parse failure)
                Diagnostics []Diagnostic{Code string; Detail *string} }  // nil ⇔ None
parse.Markdown   { Fences []Fence{Info, Content string; Line int}   // Line = 1-based line of the opening fence (parse.py:764: tok.map[0]+1+offset)
                FenceSpans []Span }                              // (first line 1-based, last line 1-based inclusive) of ``` / ~~~ fences only (parse.py:768-770); indented code blocks are in Fences with Info=="" but NOT in FenceSpans
parse.Grant      { Tool string; Pattern *string; Raw string; Allowed, Broad, Parsed bool }  // parse.py:905-912
parse.Dep        { Name, Specifier, Raw string; Pinned bool; Line *int }  // parse.py:1109-1117 (requirements), 1188-1214 (npm: no line)
```

Artifact kinds this group tests for (ingest.py:295-321 `_classify`): `skill_manifest`, `instruction`,
`doc`, `agent_identity`, `agent_config`, `hooks_config`, `mcp_config`, `plugin_manifest`,
`app_manifest`, `plugin_lock`, `dep_manifest`, `secret_material`, `script_shell`, `script_python`
(and any other `script_*`), `python_bytecode`, `python_extension`, `native_code`, `nested_archive`,
`active_asset`, `asset`, `other`.

### 1.3 Finding (owned by core) — fields this group sets

`findings.Finding{Vector, Rule, Severity, Path, Message string; Line, Column, Offset, Length *int;
Evidence map[string]any}`. `Offset` and `Length` must distinguish 0 from absent (forensics emits
`offset=0`). Evidence values this group writes: `string`, `bool`, `int`, `[]string`, and JSON subtrees
copied from the OpenGrep report (`map[string]any`, `[]any`, `json.Number`, `string`, `bool`, `nil`).
JSON key names are listed per finding in §2; they are identical to Python. Python emits evidence in
insertion order and `cli.py:272` dumps with `indent=2` and no `sort_keys`, so the parity harness must
compare parsed JSON, not text (fingerprints are order-independent: `correlate.py:21` canonicalises
with `sort_keys=True`).

### 1.4 The `Observation` record (bridge:1640-1647 → `capability.build_triads`, core group)

```go
type Observation struct {
    Path string `json:"path"`; Line int `json:"line"`; Column *int `json:"column"`
    Capability string `json:"capability"`; State string `json:"state"` // "present" | "unknown"
    Analyzer string `json:"analyzer"` // "opengrep"
    Rule, Vector, EngineRule, Origin string `json:"rule" ... "engine_rule" "origin"`
    Reason string `json:"reason,omitempty"` // "validation-budget" | "observation-unvalidated" | "validation-error"; only when State=="unknown"
}
```

---

## 2. Behaviour inventory

Conventions: "P:" = Python line. Line numbers reaching findings are always 1-based. `*` marks a place
where a line or column is computed (parity-critical).

### 2.1 `checks/code_lane.py` → `internal/codelane`

**Tables** (P:13-29): `_FENCE_LANG` info-token → (language, dialect): bash→(shell,bash); sh, shell,
console, shell-session, shellsession, shell-script, sh-session→(shell,sh); bash-session→(shell,bash);
zsh, ksh, dash, fish→(shell, same); powershell, pwsh, ps1→(shell,powershell); bat, cmd,
batch→(shell,cmd); python, py, python3, python2, ipython→(python,python). `_SCRIPT_KINDS` =
{script_shell, script_python, script_javascript, script_typescript} (wave 9). `_SUPPORTED_SHELL_DIALECTS` = {bash, sh, dash}.

| function | behaviour | pinned by |
|---|---|---|
| `_parent(rel)` P:41 | text before the last `/`, "" if none | – |
| `_manifest_index(parsed)` P:45 | first `skill_manifest` artifact per parent dir (`setdefault`: first in `parsed.artifacts` order wins) | `test_opengrep_bridge::test_nested_manifest_cannot_suppress_fence_analysis` |
| `_governing_manifest(index, rel)` P:53 | walk `_parent(rel)` upward: dir, parent(dir), … , "" ; return first hit else None | `test_capability::test_nested_manifest_and_ungoverned_observations_do_not_leak` |
| `_fence_lang(info)` P:63 | `info.split()` (Python whitespace split, §5) → first token → first run of `[A-Za-z0-9_+-]+` → lower → table lookup; None if no token / no run / unknown | `test_opengrep_bridge::test_bash_engine_does_not_receive_other_shell_dialects` |
| `_shell_dialect(rel, text)` P:71 | first line lowercased; `^#!.*\b(bash\|sh\|dash\|ksh\|zsh\|fish)\b` group 1; else suffix after the LAST `.` of `rel` (whole `rel`, not basename: "a.d/x" → "d/x"), lowered, mapped {bash,zsh,sh}, default "sh" | `test_coverage::test_unsupported_shell_dialects_are_not_silent[run.zsh]` |
| `_python_is_module(source)` P:80 | `len(source) > MAX_PY_CHARS` (524,288 **code points**, parse.py:44) → True without parsing; else `pyast.Parse` succeeds → True; SyntaxError/ValueError/RecursionError/MemoryError → False | `test_coverage::test_unparseable_python_fence_is_not_clean` (python2 print) |
| `_pad_blocks(blocks)` P:90 * | for each (marker_line, body_lines): pad with "" until `len(lines) == marker_line`, then extend; join "\n". Body line k (0-based) lands on 1-based line `marker_line + 1 + k`. Blocks are appended in fence order; a later block whose marker_line is ≤ current length is appended without padding (its lines then shift; Python does the same) | `test_opengrep_bridge::test_lifts_python_fences...` (`splitlines()[5] == "import os"`), `test_supported_shell_fences_share_one_line_mapped_target` |
| `_lift_fences(fences)` P:99 | per fence: classify; skip None; skip shell with unsupported dialect; `content.split("\n")`, drop one trailing ""; shell lines: `_CONSOLE_PROMPT_RE.sub` replaced by the same number of spaces (length in code points); python: skip when `_python_is_module("\n".join(lines))` is False; group by language in **first-seen order**; per language: `combined = _pad_blocks(blocks)`; emit `(language, "bash" if shell else language, combined)` when shell or combined parses; otherwise one unit per block, each padded alone | `test_opengrep_parity::test_live_opengrep_keeps_three_nonliteral_positive_contracts` (a `from __future__` fence after another python fence still parses under `ast.parse`, so both lift as one combined unit) |
| `_unsupported_shell(rel, dialect, origin, line=None)` P:131 | Finding(vector "", rule `analysis-incomplete`, high, path rel, line, message `"OpenGrep does not support executable %s code." % dialect`, evidence `{"reason":"unsupported_language","language":dialect,"origin":origin}`) | `test_coverage::test_unsupported_shell_dialects_are_not_silent` (3 params) |
| `build_code_lane(parsed)` P:145 | pass 1 over artifacts: kind in `_SCRIPT_KINDS` and text not None → shell dialect from `_shell_dialect` (python: None); unsupported dialect → note (origin "file", line None) and skip; else Unit(rel, kind, text, origin "file", dialect). pass 2 over artifacts with kind in {skill_manifest, instruction, agent_identity} and `markdown.fences` non-empty: for each fence in order: unsupported shell → note with line `marker_line + 1` *; python fence that fails `_python_is_module(content)` → Finding(analysis-incomplete, high, rel, line `marker_line+1` *, `"Python fence could not be parsed, so it was not analysed."`, evidence `{"language": info.split()[0], "origin": "fence"}`); then `_lift_fences` units with kind `"script_"+language`, origin "fence", dialect | `test_coverage::test_unparseable_python_fence_is_not_clean` (line 5), `test_unparsed_allowed_tools_does_not_affect_fence_analysis`, `test_non_execution_grant_cannot_suppress_fences` (grants never gate lifting) |

Ordering guarantee: units are emitted files-first in `parsed.artifacts` order, then per markdown
artifact in artifact order, languages in first-seen order. This order fixes the OpenGrep target
numbering (`%04d`), which fixes which `rel` the `opengrep-analysis-incomplete` note names
(bridge:1838 `missing[0]` sorted by target name).

**`installer_idiom(command_text)`** P:281 (all regexes in §3.1):

1. `text = command_text or ""`; if `_PROCESS_SUB_FETCH_RE` matches the whole text, `text` = group 1
   (the inside of `sh <( ... )`).
2. `fetch = _fetch_text(text)` P:258: scan chars; `\` outside single quotes skips the next char;
   quote toggling for `'`/`"`; an unquoted `|` not followed by `|` ends the fetch (return prefix);
   `||` is skipped; return None if a quote is left open. Bytes vs code points do not matter (all
   delimiters ASCII).
3. False if fetch is None, or `_INSECURE_FLAG_RE` or `_SUBSTITUTION_RE` (`[`$]|[<>]\(`) matches fetch.
4. `tail = text[len(fetch):]`; False if `_INLINE_CODE_CONSUMER_RE` or `_LATER_FETCH_RE` matches tail.
5. `*before, fetch = _COMMAND_SPLIT_RE.split(fetch)` (`\|\||&&|;`); if `before` non-empty and
   (`_LATER_FETCH_RE` matches `";" + ";".join(before)` or any whitespace-split token of any before
   segment fullmatches-as-`match` `_BARE_HOST_RE`) → False.
6. `urls = _ANY_URL_RE.findall(text)` (whole text, not fetch); `len(urls) != 1` → False.
7. `tokens = shlex.split(fetch)` (POSIX mode, §5.6); ValueError → False. `operands = [t.strip("()<>")
   for t in tokens[1:] if not t.startswith("-")]`; `operands.count(urls[0]) != 1` → False; any other
   operand matching `_BARE_HOST_RE` → False.
8. `_INSTALLER_URL_RE.fullmatch(urls[0])` else False; `host = group("host").lower()`,
   `path = group("path") or "/"`.
9. False if host fullmatches `[\d.]+`, or `_DROP_HOST_RE.search(host)`, or `_PLACEHOLDER_HOST_RE.search(host)`.
10. False if `$`, `{` or `%` in path.
11. `bare = path.rstrip("/") == ""`; `path = path.split("?",1)[0].split("#",1)[0]`; return
    `bare or _INSTALLER_PATH_RE.search(path.rstrip("/"))`.

Pinned by `test_installer_idiom::test_installer_idiom_shape` (80 parametrised commands, every one of
them a contract), `test_installer_shaped_fence_is_reported_at_medium`,
`test_dropper_shapes_keep_high_severity` (9), `test_instruction_exfil::test_sxv041_prose_installer_shapes_match_the_code_lane`.

### 2.2 `checks/grants.py` → `internal/grants`

Tables P:10-84 must be copied verbatim (`_EXECUTION_TOOLS`, `_NETWORK_TOOLS`, `_BROAD_COMMANDS`,
`_INSTALLERS` (19 tuples), `_INSTALLER_VALUE_OPTIONS`, `_INTERPRETERS`, `_EVAL_FLAGS`, `_WRAPPERS`,
`_WRAPPER_VALUE_OPTIONS`, `_PRIVILEGE_COMMANDS`, `_NETWORK_COMMANDS` (= listed ∪ installer commands),
`_NETWORK_ONLY_COMMANDS`, `_REMOTE_COMMANDS`, `_GIT_REMOTE_SUBCOMMANDS`, `_NON_EXECUTION_COMMANDS`).

| function | behaviour | pinned by (`tests/test_grants.py::`) |
|---|---|---|
| `_basename(token)` P:87 | strip one pair of identical surrounding quotes (`'` or `"`) when len ≥ 2; `\`→`/`; rstrip `/`; last path segment; lower (§5.2); strip the first matching suffix of `.exe .cmd .bat .com .ps1` | `test_broad_execution_grants_report_sxv004[C:\\tools\\curl.exe]`, `["curl" -fsSL …]`, `test_bare_cmd_grant_is_broad` |
| `_command_tokens(pattern)` P:97 | None → (None, []); strip; drop trailing `:*`; strip; `shlex.shlex(command, posix=False, punctuation_chars=";&|\n")` with `whitespace=" \t\r"`, `whitespace_split=True`, `commenters=""` → `list(lexer)`; ValueError (unclosed quote) → `command.split()` (§5.3) | `test_newline_starts_an_independent_grant_command`, `test_malformed_scalar_grant_is_visible_and_does_not_disable_siblings` |
| `_effective_tokens(tokens)` P:114 | drop leading `NAME=value` tokens (`_ENV_ASSIGNMENT`); while head basename ∈ `_WRAPPERS` (except `command -v/-V` which stops): mark privileged for sudo/doas, drop the wrapper, then drop its options: a token in `_WRAPPER_VALUE_OPTIONS[head]` drops itself and the next token; a token matching `_WRAPPER_ARGUMENT` (`^-\|=\|^\d+(\.\d+)?[smhd]?$`) drops itself; else stop. Returns (remaining, privileged) | `test_env_option_value_is_not_treated_as_executable`, `test_wrapper_option_values_do_not_hide_broad_commands`, `test_command_lookup_variable_is_not_dynamic_execution`, `test_exec_wrapper_exposes_dynamic_command_target` |
| `_segments(tokens)` P:141 | split on tokens made only of chars from `;&|\n` (non-empty); drop empty segments | `test_later_network_segment_sets_network_evidence` |
| `_segment_breadth(tokens)` P:156 | in this order: privileged → `privilege_escalation`; empty effective and head ∈ wrappers → `interpreter_or_downloader`; `effective or tokens`; `head=_basename(effective[0])`; `normalized = _VERSION_SUFFIX.sub("", head) or head`; ∈ {su,sudo} → privilege_escalation; python/py/python3 with `-m`: module `ensurepip` or (`pip` and (len==3 or installer subcommand on `effective[2:]`)) → `package_installer`; `http.server` → interpreter_or_downloader; `_installer_subcommand` hit → package_installer; single installer token → package_installer; `eval` → interpreter_or_downloader; interpreter with `_eval_option` → interpreter_or_downloader; ∈ `_REMOTE_COMMANDS` → …; `git` alone or with remote subcommand → …; `npx` → …; single token ∈ `_BROAD_COMMANDS` → …; else None | `test_broad_execution_grants_report_sxv004` (14), `test_python_installer_modules_are_package_installers`, `test_fixed_python_modules_are_not_misclassified_as_installers`, `test_python_http_server_module_is_network_capable`, `test_bare_delegating_wrapper_is_broad`, `test_versioned_interpreter_network_evidence_is_normalized` |
| `_installer_subcommand(effective, normalized)` P:197 | skip leading `-...` options (value options of `_INSTALLER_VALUE_OPTIONS[normalized]`, compared on the part before `=`, also skip their value); `tail` lowered; first action whose head is `normalized` and whose remaining words prefix-match `tail` → last word of action | `test_installer_global_options_do_not_hide_install`, `test_cargo_global_option_value_does_not_hide_install`, `test_dotnet_mutating_tool_actions_are_broad`, `test_dotnet_tool_list_stays_narrow`, `test_uv_pip_*` |
| `_breadth(tool, pattern, command, tokens)` P:213 | network tools: pattern None or lowered stripped pattern ∈ {`*`,`**`,`:*`,`domain:*`} → `unrestricted_network` else None; non-execution tools → None; pattern None or command ∈ {"", "*", "**"} → `wildcard_all_commands`; else the first present of privilege_escalation, package_installer, interpreter_or_downloader across segments | `test_network_wildcards_are_unrestricted` (7), `test_unrestricted_network_grant_reports_capability_risk` |
| `_reaches_network(tool, pattern, tokens)` P:231 | network tools True; non-exec False; pattern None / no tokens / first token ∈ {"", "*", "**"} → True; any segment whose effective head (version-suffix stripped) ∈ `_NETWORK_COMMANDS` | `test_network_reachability_is_explicit_evidence` (4), `test_installer_grants_record_network_reachability`, `test_git_remote_grants_are_network_capable` |
| `_eval_option(effective, interpreter)` P:246 | scan tokens after the head: lower only for cmd/powershell/pwsh; `--` → None; token ∈ accepted flags → (index, None); POSIX shells and pythons: a `-cluster` containing `c` → (index, suffix after c or None); attached payload `-cPAYLOAD` / `/cPAYLOAD` for accepted prefixes → (index, rest); a token not starting with `-` or `/` → None | `test_attached_eval_payload_reports_both_grant_risks`, `test_shell_clustered_command_option_reports_both_risks`, `test_python_clustered_command_option_reports_both_risks`, `test_python_uppercase_e_option_is_not_eval`, `test_script_arguments_named_eval_are_not_interpreter_options` |
| `_expandable_variable(token)` P:272 | first `_VARIABLE` match whose start is not inside single quotes and not escaped (`_shell_expands_at`) | `test_literal_command_variables_are_not_dynamic`, `test_single_quoted_fragment_in_command_head_is_literal` |
| `_shell_expands_at(token, target)` P:279 | scan `token[:target]` tracking `\`-escape (not inside single quotes), `'` toggles unless in double, `"` toggles unless in single; expands ⇔ not single and not escaped | `test_single_quotes_inside_double_quotes_do_not_hide_substitution` |
| `_dynamic_command_target(tokens)` P:295 | per segment: effective head (version-stripped); `eval` → substitution or variable of the joined payload; interpreter with eval option → payload = attached or the joined tokens after the option index; return substitution (string) or variable (match) | `test_dynamic_interpreter_payload_reports_sxv003` (4), `test_eval_builtin_dynamic_payload_reports_both_risks` |
| `_command_substitution_head(tokens)` P:321 | joined effective tokens; `_expandable_substitution`; keep only if it starts inside the first token (`joined.find(sub) < len(effective[0])`) | `test_wrapped_command_substitution_reports_sxv003`, `test_argument_substitution_is_not_a_dynamic_command_target`, `test_executable_command_substitutions_report_sxv003` (3) |
| `_blanket_grant(g)` P:332 | lowered stripped pattern ∈ {"", `*`, `**`, `:*`} or (network tool and `domain:*`) | – |
| `_denial_covers(denial, grant)` P:338 | same tool, denial not allowed, parsed; blanket denial or equal patterns → True; `denied` ending `:*`: prefix = denied[:-2].rstrip(); candidate = allowed minus `:*`; covered if equal or `candidate.startswith(prefix + " ")` | `test_prefix_denial_closes_narrower_matching_allow`, `test_exact_narrow_denial_closes_matching_allow`, `test_wildcard_denial_closes_same_allowed_tool` |
| `effective_grants(grants)` P:352 | allowed ∧ parsed ∧ no covering denial | `test_capability::test_grants_reuse_parser_and_explicit_states` |
| `_grant_capabilities(grants)` P:363 | execution ⇔ any execution-tool grant with pattern None / command ∈ {"", "*", "**"}, or any segment head (effective or raw, version-stripped) not in `_NON_EXECUTION_COMMANDS`; network ⇔ any `_reaches_network` | `test_denials_do_not_forbid_indirect_or_partially_scoped_capabilities` (11) |
| `declared_capabilities(grants)` P:385 | `_grant_capabilities(effective_grants(grants))` | `test_capability::test_partial_denial_does_not_deny_entire_axis` |
| `denied_capabilities(grants)` P:390 | axes whose tool set intersects the tools of blanket, parsed, disallowed grants | `test_network_denials_survive_both_capability_passes` |
| `_expandable_substitution(value)` P:398 | quote/escape-aware scan for `$( … )` (paren depth, `\`-preceded parens ignored) or `` ` … ` `` (unescaped closing); returns the substring or None | `test_long_command_substitution_is_still_detected`, `test_quoted_command_substitution_is_not_dynamic` |
| `check(parsed)` P:445 | manifests = skill_manifest artifacts sorted by `rel` (byte order); `line = frontmatter_key_lines.get("allowed-tools") or 1` *; skip grants not allowed / empty tool / unparsed / covered by a denial; execution tool with a pattern: `value` from the first segment's `_command_substitution_head`, else `variable` from `_expandable_variable(segment_head[0])` (first segment with an effective head), else `_dynamic_command_target(tokens)`; a variable match → its `group(0)`; emit **SXV-003** `grant-variable-substitution` high, path rel, line, message `` "execution pre-grant `%s` has a dynamic command target (%s)" % (grant.raw, value) ``, evidence `{"grant_text": raw, "variable_name": value, "line": line}`. Then `_breadth`; if any: severity critical for {wildcard_all_commands, privilege_escalation} else high; **SXV-004** `grant-over-broad`, message `` "pre-granted tool `%s` is over-broad (%s)" % (raw, breadth) ``, evidence `{"grant_text", "breadth_class", "line", "reaches_network": bool}`. Return `cap_findings(findings)` | `test_dynamic_execution_head_reports_sxv003` (12), `test_grant_findings_are_capped_with_visible_note` (25 + "3 more SXV-003 findings"), `test_non_manifest_grants_are_out_of_scope`, `test_disallowed_grant_is_never_treated_as_risk` |

Note the order inside `check`: for each grant SXV-003 is appended before SXV-004; `cap_findings`
then sorts (core), so emission order only matters for the cap counters.

### 2.3 `checks/supply_chain.py` → `internal/supplychain`

| function | behaviour | pinned by (`tests/test_supply_chain.py::`) |
|---|---|---|
| `_is_requirements_manifest(base)` P:42 | `base.endswith(".txt") and "requirements" in base` | `test_requirements_variant_is_scanned` |
| `_ecosystem(rel)` P:101 | basename (after `\`→`/`), lowered; `package.json` → "npm" else "PyPI" | `test_package_json_ranges_are_unpinned_exact_is_silent` |
| `_redact(secret)` P:107 | len ≤ 8 → all `*`; else first 4 + `*`×(len−8) + last 4 (code points; matches are ASCII) | `test_credential_is_redacted_never_echoed` |
| `_fence_predicate(markdown)` P:114 | `starts` = span starts; `contains(line)`: `bisect_right(starts, line) - 1` → index ≥ 0 and `line <= spans[index][1]` → Go `sort.Search` for first start > line, minus one | `test_tilde_crlf_and_unclosed_fences_keep_exact_secret_context`, `test_indented_code_does_not_demote_following_prose_secret` |
| `_is_placeholder(rule, token)` P:126 | slack-token and `_SLACK_ZERO_PLACEHOLDER` fullmatch | `test_slack_placeholder_and_prose_are_not_leaks_but_real_token_fires` |
| `_scan_secrets(text, in_fence)` P:130 * | for `lineno, line in enumerate(text.split("\n"), 1)`: for each rule in table order, each `finditer` match: skip `_KNOWN_EXAMPLE` (4 strings, P:83-94) and placeholders; `private-key` sets `pending = (lineno, token, token.replace("-----BEGIN ", "-----END ", 1))`, `saw_encoded=False`, and yields nothing yet; other rules yield `(rule, lineno, token, MEDIUM if in_fence(lineno) else sev)`. After the rules, if `pending` and `lineno > pending[0]`: if the END marker is a substring of the line: yield the private key at its START line (severity MEDIUM if fenced at start line) only when `saw_encoded`; clear pending; elif `len(line.strip()) >= 16` and line.strip() fullmatches `[A-Za-z0-9+/=]+` → `saw_encoded=True`. A second BEGIN before the END overwrites pending (`test_long_private_keys_and_boundary_isolation`: `body + header + footer` yields nothing because the second header resets `saw_encoded`) | `test_each_real_credential_shape_fires`, `test_private_key_header_requires_a_complete_block`, `test_long_private_keys_and_boundary_isolation`, `test_encrypted_and_dsa_private_keys_fire` |
| `_sca_findings(parsed)` P:156 | dep_manifest artifacts with deps not None; skip pinned; npm: skip when `_npm_install_source(specifier)`; PyPI: skip when `_VCS_INSTALL_RE.search(raw)`; `name = _redact_source_secrets(name or "dependency")`; **SXV-016** `unpinned-dependency` low, message `` "Dependency `%s` is declared without an exact version, so the code installed is not the code reviewed." ``, `line=dep.line` (None for npm) *, offset/length None, evidence `{"ecosystem", "package", "pin_state": "unpinned"}` | `test_requirements_unpinned_fires_pinned_is_silent` (line 2), `test_npm_alias_exact_pin_is_silent`, `test_credential_shaped_dependency_names_are_redacted`, `test_pep508_direct_ref_reported_once_not_also_low_unpinned` |
| `_secret_findings(parsed)` P:185 | artifacts with text and kind ≠ asset; `in_fence` only for kinds {skill_manifest, instruction, doc, agent_identity} with markdown; `selected = nsmallest(FINDING_CAP+1, hits, key=(SEVERITY_RANK[sev], lineno))` (stable; Go: collect, `sort.SliceStable`, take 26); first 25 → **SXV-017** `committed-credential`, severity sev, `line=lineno` *, message `` "Credential matching `%s` is committed in the package (%s)." % (rule, redacted) ``, evidence `{"rule", "redacted", "fenced_example": sev == "medium"}`; a 26th hit → one `findings-capped` low note per artifact: `"Additional committed-credential findings were suppressed after the per-file limit of %d." % 25` | `test_committed_credentials_are_capped_per_file`, `test_credential_cap_retains_high_severity_after_fenced_examples` (the HIGH aws hit at line 30 or 1 survives 27 fenced ghp_ examples), `test_agent_identity_fence_demotes_secret`, `test_secret_in_script_is_not_demoted` |
| `_npm_install_source(spec)` P:230 | stripped spec; "" → None; contains `://` → spec; `_NPM_SHORTHAND_RE` / `_NPM_OWNER_REPO_RE` / `_NPM_SCP_RE` match → spec; else None | `test_npm_host_shorthand_and_git_dep_are_install_from_url`, `test_npm_scp_git_source_is_medium_direct_install`, `test_repository_metadata_url_is_not_an_install_source` |
| `_sanitize_source(source)` P:249 | `git+` prefix split off; `urlsplit` (§5.7); when scheme and netloc: `host = hostname or ""` (lowercased, IPv6 brackets stripped), port appended if parseable (`ValueError` → omitted), `urlunsplit((scheme, host, path, "", ""))`, then `_redact_source_secrets`; otherwise strip `#…` then `?…`, replace `scheme://userinfo@` by `scheme://***@` (`(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@`), prefix restored, redact | `test_direct_install_url_credentials_are_redacted`, `test_malformed_direct_url_still_redacts_all_opaque_values` (`[bad` → urlsplit ValueError path), `test_bare_url_does_not_use_credentials_as_dependency_name` |
| `_redact_source_secrets(s)` P:276 | apply every secret rule's `sub(redact)` in table order | `test_direct_install_path_credentials_are_redacted` |
| `_install_finding(rel, name, source, line)` P:282 | **SXV-016** `install-from-url` medium, message `` "Dependency `%s` installs directly from a VCS/URL source (`%s`): the code fetched is not a reviewed, pinned registry release." % (name, safe_source[:120]) `` (120 code points), evidence `{"install_source": safe_source[:200], "pin_state": "vcs_or_url"}`, line * | `test_npm_direct_reference_does_not_invent_a_location` (line None, column None) |
| `_logical_requirement_lines(text)` P:294 * | pip continuation join: a line whose rstrip ends with `\` and does not (after lstrip) start with `#` accumulates `stripped[:-1]`; yields `(first physical line, joined)`; a trailing "" sentinel line flushes | `test_backslash_split_legacy_vcs_url_is_still_install_from_url` (line 1), `test_backslash_comment_does_not_swallow_next_dependency` |
| `_vcs_install_findings(parsed)` P:309 | dep_manifest only. `package.json` with deps: one install finding per dep with an install source (`line=dep.line`, None). Others: `seen=set()`; if requirements manifest with text: per logical line: `line = re.split(r"\s#", raw.strip(), 1)[0].strip()`; skip empty / `#…`; skip `-…` unless `^(?:-e\|--editable)\b`; `_VCS_INSTALL_RE.search(line)` → `src = m.group(0).lstrip("@ ")`, `before = line[:m.start()].strip()`, `name = re.split(r"[\s@<>=!~;\[]", before, 1)[0]` or "dependency" (also when name is `-e`/`--editable`), add `(name, src)` to seen, emit. Then for every parsed dep (requirements AND pyproject): `_VCS_INSTALL_RE.search(dep.raw)` → `src`; emit unless `(dep.name, src) in seen` | `test_pep508_direct_url_reference_fires`, `test_pip_option_line_is_not_a_dependency`, `test_distinct_pyproject_dependencies_sharing_url_are_both_reported`, `test_physical_and_continued_dependencies_sharing_url_are_not_conflated`, `test_pep508_extras_do_not_duplicate_direct_reference` (`requests[socks]` → physical name "requests", parsed name "requests": dedup by seen) |
| `check(parsed)` P:363 | `cap_findings(_sca_findings + _vcs_install_findings) + _secret_findings` (secrets are NOT re-capped here; their own per-artifact cap applies) | `test_dependency_findings_are_capped_per_file` |

### 2.4 `analyze.py` → `internal/forensics`

All integer reads are little-endian unless stated; Python slices clamp silently, Go must clamp
explicitly (`raw[a:min(b,len)]`) wherever the Python code compares a slice that may run past the end
(`_is_pe` P:56 `raw[i:i+2]`, `_is_macho` P:83, `_eocd_candidate` P:320-321 names, `_valid_gif`).

| function | behaviour | pinned by (`tests/test_analyze.py::`) |
|---|---|---|
| `_F(rule, severity, path, message, offset, length, detail)` P:17 | Finding(vector from `{"magic-mismatch": SXV-035, "polyglot": SXV-036, "unreferenced-bytes": SXV-037, "analyzer-error": ""}`, evidence `{"detail": detail}` only when detail is not None) | – |
| `_SIGS` P:22 | signature table sorted by descending magic length (ties keep the listed order: stable sort) | `test_sniff_known_and_unknown` |
| `_is_pe(raw, i)` P:55 | needs `len ≥ i+0x40`, `MZ`, `e_lfanew = u32(i+0x3C) ≥ 0x40`, `off+24 ≤ len`, `PE\0\0` at off, `off+24+u16(off+20) ≤ len` | `test_sniff_rejects_truncated_or_ambiguous_executable_headers`, `test_complete_pe_overlay_is_classified_high` |
| `_is_elf(raw, i)` P:66 | magic, `len ≥ i+7`, class ∈ {1,2}, data ∈ {1,2}, version 1; endian from data byte; header 52/64; `e_type`? no: `u32(i+20) == 1` (e_version) and `e_ehsize == header_size` at offset 40/52 | `test_sniff_rejects_truncated_or_ambiguous_executable_headers` |
| `_is_macho(raw, i)` P:82 | fat: `nfat = u32be(i+4)` in 1..32, `i+8+nfat*20 ≤ len`, cpu = `u32be(i+8) & 0xffffff` ∈ `_MACHO_CPU`; thin: endian by magic, header 28/32, cpu and filetype ∈ 1..11 | `test_sniff_known_and_unknown` (macho), Java `.class` rejection |
| `_first_validated(raw, magic, validator, kind, cap)` P:111 | `k = raw.find(magic, 1)`; loop: validator → `(k, kind)`; next `find(magic, k+1)`; `tries += 1`; at `tries >= cap`: return `_CAPPED` if another occurrence exists else None | `test_decoy_tiling_is_a_capped_anomaly` |
| `_earliest(*c)` P:126 | min offset among tuples (ties: first) | – |
| `_embedded_executable(raw)` P:131 | ELF, PE, then the five Mach-O magics (cap 64 each); earliest, else `_CAPPED` if any capped | `test_generic_png_overlay_does_not_hide_validated_executable` |
| `_is_gzip(raw, i)` P:143 | `len ≥ i+10`, magic, method 8, `(flags & 0xE0) == 0`; stream-decompress with a 1,048,576-byte output cap (produced > cap → False); True only when the member ends (`eof`); any zlib error → False (§4.5) | `test_truncated_gzip_is_not_a_valid_embedded_payload`, `test_embedded_payload_requires_validation_not_bare_magic`, `test_empty_inputs_have_expected_behavior` (`gzip.compress(b"")` is gzip) |
| `_is_7z(raw, i)` P:170 | `len ≥ i+32`, magic, `crc32(raw[i+12:i+32]) == u32(i+8)`, next header off/size/crc, `0 < size ≤ 262144`, bounds, crc match | `test_decoy_tiling_is_a_capped_anomaly` |
| `_embedded_dangerous(raw)` P:190 | executable candidate; `_find_eocd(raw)` dict → `start = eocd - cd_size - cd_offset`, `> 0` → `(start,"zip")`; gzip and 7z via `_first_validated` (cap 64); earliest, else `_CAPPED` if any capped | `test_padded_image_zip_payload_has_exact_high_severity_span` (3 carriers) |
| `sniff_magic(raw)` P:210 | empty → None; first signature that is a prefix and whose validator passes (pe/elf/macho/gzip/sevenzip; zip requires `_find_eocd` to return a dict) | `test_sniff_known_and_unknown`, `test_chance_end_markers_are_clean` |
| `_looks_textual(raw)` P:233 | first 512 bytes; non-empty, no NUL, valid UTF-8 (§5), printable ratio `> 0.85` where printable = 9,10,13 or 32..126 | `test_script_renamed_to_image_is_flagged_as_text` |
| `_declared(kind, ext, text)` P:245 | `_TEXT_KINDS` or `script_*` → "text"; `other` with text → "text"; `asset` → "image"; `active_asset` → "pdf" if ext `.pdf` else "svg"; `nested_archive` → "archive"; compiled kinds → "compiled"; else "other" | `test_declared_formats_reject_contradictory_bytes` |
| `_eocd_candidate(raw, e)` P:269 | 22-byte record, comment fits; disk/cd_disk zero, entries == total; total 0 ⇒ cd_size/cd_offset zero, and a non-empty prefix must be a valid PNG/GIF/JPEG carrier; reject ZIP64 sentinels; walk `total` central entries (`PK\x01\x02`, name_len > 0, disk-number-start 0, local header `PK\x03\x04` within `[archive_start, cd_pos)`, names equal, compressed data inside cd_pos); `pos` must land exactly on `e` | `test_fabricated_central_directory_is_not_a_polyglot`, `test_valid_image_with_empty_zip_is_polyglot`, `test_zip_comment_is_part_of_the_logical_archive_end` |
| `_find_eocd(raw)` P:333 | up to 128 candidates scanning `rfind(b"PK\x05\x06", 0, before)` backwards; dict on first valid; None when exhausted; `_CAPPED` when 128 tried and more remain | `test_decoy_tiling_is_a_capped_anomaly` (140 EOCDs) |
| `_valid_gif(raw)`, `_valid_jpeg(raw)`, `_valid_image_carrier(raw, kind)` P:347-425 | GIF block walk incl. the `while … else: return False` (loop exhausted without `break` → False); JPEG marker walk with SOF/SOS tracking and EOI exactly at end; PNG via `_png_logical_end == len` | `test_malformed_image_prefix_is_not_a_high_polyglot`, `test_prepended_zip_polyglot_fires` |
| `_zip_findings(rel, raw)` P:428 * | `_CAPPED` → medium `unreferenced-bytes` "an unusually large number of ZIP end-record signatures prevented complete validation" (detail "capped", no offset); None with a `PK\x03\x04`/`PK\x05\x06`/`PK\x07\x08` prefix → low, offset 0, length len, "the ZIP structure is malformed or unsupported; trailing bytes could not be verified"; structure mismatch → medium at `offset=e, length=len-e`; prefix bytes: valid image carrier → high `polyglot` `"%d byte(s) precede a valid zip archive: the file is both %s and a zip (prepended-container polyglot)"` offset 0 length archive_start detail pre; else medium polyglot "… but the prefix format is unrecognized"; tail after `logical_end = e + 22 + comment_len`: `payload = sniff_magic(tail)`; if not dangerous, `_embedded_dangerous(tail)` tuple → `(payload_offset, payload)`; if dangerous and `payload_offset`: medium `"%d unreferenced byte(s) precede an appended payload"` at `offset=logical_end, length=payload_offset`; then `"%d byte(s) follow the zip end record (appended overlay%s)"` with `": %s" % payload` only when dangerous, severity high if dangerous else medium, `offset=logical_end+payload_offset`, `length=filesize-start`, detail payload if dangerous | `test_zip_overlay_variants_are_located_and_classified`, `test_valid_zip_after_text_prefix_is_reported`, `test_incomplete_zip_signatures_are_reported` (6) |
| `_png_logical_end(raw)` P:492 | chunk walk with CRC32 over type+data, first chunk IHDR len 13, IDAT seen, IEND len 0 → its end | `test_png_requires_bounded_crc_valid_zero_length_iend` |
| `_png_findings(rel, raw)` P:520 * | malformed → low at `offset 8, length max(0, len-8)`; trailing → `"%d byte(s) follow the PNG IEND chunk (appended overlay%s)"` (`": %s" % ts` when ts truthy), high if dangerous else medium, `offset=logical_end, length=trail, detail=ts` (detail present even when ts is None → evidence `{"detail": None}`? No: `_F` omits the key only when `detail is None`, so a plain overlay has empty evidence) | `test_trailing_bytes_after_png_iend`, `test_malformed_png_fails_closed_not_silent` |
| `_magic_mismatch(rel, declared, ext, detected, raw)` P:538 | text that looks textual → []; compiled: dangerous and not in `_COMPILED_EXT_EXPECT[ext]` → high; executable → high; archive: declared text/image/svg/pdf → high, declared archive with wrong ext → medium; image: declared text/svg/pdf or image with wrong ext → low, declared archive → medium; nothing detected but declared image/archive and textual → medium with detail "text"; message `"declared %s (%s), but bytes are %s" % (declared, ext or "no extension", detail)`, offset 0, length len | `test_executable_masquerades_are_high`, `test_mislabeled_image_is_low_not_high`, `test_all_compiled_declarations_reject_zip_bytes` (5), `test_unrecognized_compiled_formats_are_not_invented_mismatches` (4) |
| `analyze_artifact(rel, kind, text, raw)` P:567 | empty raw → []; `ext = splitext(re.sub(r"\.so(?:\.\d+)+$", ".so", rel.lower()))[1]` (§5.8); mismatch findings; PNG findings when detected png; zip findings when `PK\x05\x06` anywhere or a `PK\x03\x04`/`PK\x07\x08` prefix; for detected images or declared "image": `_embedded_dangerous(raw)`: `_CAPPED` → medium "an unusually large number of embedded archive-header signatures (possible decoy tiling to evade payload detection)" detail "capped"; a hit `(off, kind_)`: drop earlier `unreferenced-bytes`/`polyglot` findings with `offset > off` and detail ∈ {None, "text"}; unless an existing such finding already covers `off` with the same detail, add high `"a %s payload is embedded at offset %d in this image (appended native or archive data)"` at `offset=off, length=len-off, detail=kind_`; any panic/exception → `analyzer-error` high `"byte analysis could not complete: %s" % type(exc).__name__` | `test_generic_png_overlay_does_not_hide_validated_executable`, `test_analyzer_failure_is_recorded_not_raised` |
| `analyze_package(parsed)` P:611 | all artifacts (`getattr(p, "raw", None)`), `dedupe_findings` | `test_findings_are_deterministic_and_severity_ordered`, `test_ingest_retains_raw_reaches_analyzer` |

### 2.5 `checks/_pyast.py` → `internal/pyast` (surface used by this group)

`parse(source)` P:373 = `ast.parse` with SyntaxWarning suppressed (Go: no warnings). `dotted(node)`
P:379: walk `Attribute.value` chain collecting `attr`, end at `Name.id` → "a.b.c"; any other base → None.

The bridge additionally uses these `ast` facilities, which `internal/pyast` must provide with
identical semantics: `ast.walk` (breadth-first, FIFO queue seeded with the root; children in
`_fields` order), `ast.iter_child_nodes` (yields AST-node fields and AST nodes inside list fields, in
`_fields` order, skipping None and non-node values; note `expr_context`/`operator`/`boolop`/`cmpop`
/`unaryop` singletons are AST nodes and are yielded), `lineno`, `col_offset` (UTF-8 **byte** offset,
0-based), `end_lineno`, `end_col_offset` (may be absent → Python `or` fallbacks at bridge:223, 299,
514, 587, 739, 940, 980, 1365, 1393, 1414), `ast.literal_eval(node)` (§4.1), node classes and field
orders listed in §4.1.

### 2.6 `opengrep_bridge.py` → `internal/opengrep`

Constants P:29-52: `_SEVERITY = {ERROR: high, WARNING: medium, INFO: low}`, `_MAX_REPORT_BYTES =
16 MiB`, `_MAX_TARGET_BYTES = 5 MiB`, `_MAX_POSTFILTERS_PER_TARGET = 32`, `_PY_TAINT_VECTORS =
{SXV-008, SXV-018, SXV-019}`, `_PY_SINKS` (27 dotted names: os.system, os.popen, subprocess
run/call/check_call/check_output/Popen/getoutput/getstatusoutput, the 8 `os.exec*`, 2 `os.posix_spawn*`,
8 `os.spawn*`), `_PY_BUILTIN_SINKS = {eval, exec}`,
`_PY_CANONICAL_SINKS = _PY_SINKS ∪ {builtins.eval, builtins.exec}`, scope kinds, four sentinel
objects (`_UNKNOWN`, `_SOURCE_MARKER`, `_OTHER_MARKER`, `_INVALID_CALL`) → Go: unexported singleton
pointer values of a `marker` type, compared by identity.

#### 2.6.1 Selection (P:55-85)

`SelectedCode(rel, text, origin, suffix=".py")`. `_LANGUAGE_KIND = {python: (script_python, .py),
shell: (script_shell, .sh)}`. `select_executable_code`: build units when None; keep units whose kind
is selected; drop shell units with unsupported dialect; map to `SelectedCode(rel, text, origin,
suffix)`. Pinned: `test_selects_real_python_files`, `test_selects_shell_only_when_requested`
(suffix ".sh"), `test_lifts_python_fences_independent_of_attacker_controlled_grants`.

#### 2.6.2 Small helpers

* `_coverage(rule, message, path="", severity="low")` P:88 → Finding(vector "", …).
* `_target_name(raw_path)` P:92: `str(raw or "")`, `\`→`/`, last segment (so `C:\Temp\scan\0000.py` → `0000.py`).
* `_rule_id(raw)` P:96: from the last occurrence of `skill-xray.` to the end, else the whole string
  (`test_report_maps_temporary_path_to_original_location`: `C.Users.local.rules.skill-xray.python-…` → `skill-xray.python-…`).
* `_remap_engine_paths(value, targets)` P:102: deep copy of a JSON tree where every dict key `path`
  with a string value becomes `targets[_target_name(v)].rel` or `_target_name(v)` when unknown.
* `_location(result, target)` P:117 *: `start`/`end` dicts (non-dict → {}); `line = start["line"]`
  must be an int (not bool) in `1..text.count("\n")+1`; else None. Returns `(line, {"start": {"line",
  "col": bounded ≥1, "offset": bounded ≥0}, "end": {"line": ≥1, "col": ≥1, "offset": ≥0}})` with
  non-int/out-of-range values → None (JSON null). Pinned by `test_invalid_result_location_is_fail_visible`
  (7 shapes incl. `True`, `"3"`, `999`), `test_malformed_result_column_does_not_crash_sorting`.

#### 2.6.3 Fence coordinate mapping (P:133-216) — parity-critical column arithmetic *

`_fence_region(target, parsed, start, end, source_cache)`:
1. artifact = `parsed.by_rel[target.rel]` with text, else ValueError.
2. cache per target: `generated = target.text.split("\n")`, `original = artifact.text.split("\n")`
   (the test `test_fence_sources_split_once_per_target_and_reporting_call` pins exactly one split of
   each per `findings_from_report` call → cache keyed by target name, lifetime = one call).
3. for each of start, end: must be dicts with int `line`, int `col`; `1 ≤ line ≤ min(len(generated), len(original))`;
   `encoded = generated[line-1].encode("utf-8")`; `1 ≤ col ≤ len(encoded)+1`;
   char index = `len(encoded[:col-1].decode("utf-8"))` (UnicodeDecodeError is a ValueError → unvalidated).
   Go: `prefix := line[:col-1]`; `utf8.Valid(prefix)` else error; `utf8.RuneCount(prefix)`.
4. `positions[1] < positions[0]` (tuple compare (line, char)) → ValueError.
5. for each line in `first..last`: `source = original[line-1]`, `lifted = generated[line-1]`; require
   `lifted != ""`, no tab in either, `source.endswith(lifted)`; `prefix_len = len(source) - len(lifted)`
   in **code points**.
6. span check: generated span = lines first..last with last cut at `end_char` and first cut from
   `start_char`; original span = same lines cut at `prefixes[-1]+end_char` and from `prefixes[0]+start_char`
   (code-point slices); must be equal lists else ValueError.
7. return `{"start": {"line": first, "col": start["col"] + len(original[first-1][:prefixes[0]].encode())},
   "end": {"line": last, "col": end["col"] + len(original[last-1][:prefixes[-1]].encode())}}`
   — original cols are engine byte col + byte length of the removed container prefix.

`_fence_trace(value, targets, parsed, cache)` P:183: recursive copy; any dict containing `path`,
`start` and `end` keys: target lookup by `_target_name(path)` (unknown → ValueError); for fence
targets `mapped.update(_fence_region(...))`.

`_map_fence_evidence(evidence, target, targets, parsed, trace, cache)` P:200: `evidence["engine_location"] =
deepcopy({start, end})`; try `evidence.update(_fence_region(...))` and `location_mapping = "validated"`,
on ValueError/TypeError/AttributeError `"unvalidated"`; when `trace` truthy: `engine_dataflow_trace =
deepcopy(evidence["dataflow_trace"])`, `dataflow_trace = _remap_engine_paths(_fence_trace(trace,…), targets)`,
`trace_mapping = "validated"` else `"unvalidated"` (the already-remapped `dataflow_trace` stays).

Pinned by `tests/test_fence_locations.py` (all 9 functions / 25 cases): prefixes `""`, `"   "`,
`"> "`, list-item indentation, multi-byte `"é😀"` leading text (`start_col` in bytes),
`different-source`/`tab`/`multiline` damage → unvalidated with `engine_location` retained and
`column=None`; `test_file_coordinates_are_unchanged` (file origin: no mapping, `column == col`).

#### 2.6.4 Scope and binding helpers (P:219-325, 988-1047)

* `_scope_chain(tree, line, col)` P:219: nodes of `_PY_SCOPES` kinds containing `line` (and `col`
  when given, via `_contains_position`), taken in **`ast.walk` order**, then `sort(key=(lineno,
  -(end_lineno or 0)))` (stable); result `[tree] + scopes` minus any `ClassDef` that has a function
  scope after it in the list.
* `_scope_nodes(scope)` P:234: DFS with a LIFO stack seeded with `iter_child_nodes(scope)`, popping
  from the end, yielding each node, descending only into non-scope nodes. Order matters for
  `_scope_binds_name`? No (any), for `_resolve_alias`? No (max lineno). Keep the order anyway.
* `_import_binding(node, name)` P:243: `Import`: reversed aliases; bound = asname or first dotted
  component; returns `("import", alias.name if asname else first component)`. `ImportFrom`: reversed
  aliases, skip `*`; `("import", "."*level + (module + "." + name if module else name))`.
* `_target_binds(node, name)` P:259: Name / Tuple / List / Starred recursion.
* `_statement_binding(node, name)` P:267: import binding; def/class with that name → ("other", None);
  `Assign` binding the name whose value `dotted` ∈ `_PY_SINKS` → ("sink", dotted) else "other";
  `AnnAssign` only with a value; `AugAssign`; `Delete` → ("delete", None).
* `_preserves_name_binding(node, name)` P:291: `x = x` (Assign/AnnAssign with value whose `dotted` equals name and target binds name).
* `_before(node, line, col)` P:298: `end_line < line or (end_line == line and col is not None and (end_col_offset or 0) < col)`.
* `_last_binding(scope, name, line, col)` P:305: function parameters (posonly, args, kwonly, vararg,
  kwarg) → ("other", None); comprehension generator targets → same; then for each body statement
  `_before(...)`: unless it preserves the binding, `binding = _statement_binding(...) or binding`.
  Pinned: `test_python_bare_annotation_does_not_shadow_imported_sink`, `test_python_deleted_or_bare_annotated_builtin_sink_is_not_filtered`.
* `_binding_at(scopes, name, line, col)` P:988: innermost scope with a non-None `_last_binding`.
* `_has_sink_import(scopes, name, suffix, line, col)` P:996: binding → sink, or import whose origin +
  suffix ∈ canonical sinks; no binding → any earlier `from M import *` where `M.name` ∈ canonical sinks.
* `_was_sink_imported(...)` P:1020: any earlier import (any scope, outer first) binding name to a sink, or a star import.
* `_target_path(target)` P:1042: Attribute → dotted; Subscript → dotted(value); else None.
* `_assigned_expression(scopes, name, line, col)` P:1050: innermost scope, latest earlier Assign/AnnAssign binding name → (value, statement).
* `_callable_identity(scopes, raw, line, col, seen)` P:1069: recursion guard `raw in seen or len(seen) >= 16`;
  import/sink binding → origin + rest; assignment chain via `dotted(value)` (self-assignment recurses at
  the statement position); no binding and name ∈ {eval, exec, input, raw_input, print} → "builtins." + raw.
* `_qualified_rebound(scopes, raw, line, col, unknown_is_rebound=False)` P:1097: any earlier
  Assign/AnnAssign/AugAssign/Delete (outer scopes first) whose target path == raw: no value → True;
  identity-preserving reassignment (`expected == actual`) → continue; a resolvable `actual` or a
  Lambda/Constant/Dict/List/Set/Tuple value → True; else `unknown_is_rebound`.

#### 2.6.5 Static value evaluator (P:327-515) — a Python-constant mini-interpreter (§4.1.3)

`_static_value(node, values)`: Name → `values.get(id, UNKNOWN)`; Dict → dict of evaluated keys/values
(any UNKNOWN → UNKNOWN; `**` entries have key None → UNKNOWN; unhashable key → TypeError → UNKNOWN);
List/Tuple/Set constructors (Set with unhashable → UNKNOWN); `not x`; BoolOp with Python
short-circuit truthiness; Compare with chained ops (Eq, NotEq, Is, IsNot, Lt, LtE, Gt, GtE, In, NotIn;
TypeError → UNKNOWN); `BinOp |` of two dicts; Subscript `owner[key]` (KeyError/IndexError/TypeError →
UNKNOWN); Call `dict(...)` when `values.get("dict")` is not UNKNOWN (i.e. `dict` not shadowed
UNKNOWN; `values.get("dict", None)` → None is fine): ≤1 positional, no `**`; `.get(k[, d])` on a dict
value with 1-2 positionals and no keywords; anything else UNKNOWN; fallback `ast.literal_eval`.
`_assign_static`, `_apply_static` (def/class/import → UNKNOWN; `x.update(...)` merges through a
synthetic `dict(...)` call; `|=` on dicts), `_static_values_at(tree, line, col)` (walks the scope chain;
function parameters and comprehension targets become UNKNOWN; statements applied while
`_before(stmt, limit, col)` where `limit` is the next scope's `lineno` or `line`).

`_contains_position(node, line, col)` P:507: line range; `col` not an int or < 1 → True; else
`point = col-1`; `(line != lineno or point >= col_offset) and (line != end_lineno or point <= (end_col_offset or point))`.

`_subprocess_shell_status(tree, line, col)` P:518 → `(shell: bool|None, explicit: bool)`: for Call nodes
in the innermost scope containing the position whose callee `dotted` has an imported sink root and is
either a canonical sink or ends in run/call/check_call/check_output/Popen: `shell=` keyword: Subscript
whose static owner/key exist but lookup raises → `(False, True)`; else `(bool(value) or None if
UNKNOWN, True)`; `**mapping` keywords: any UNKNOWN → `(None, False)`; else `(any dict with truthy
"shell", False)`; no shell/mappings → `(True, False)`; no matching call → `(True, False)`.
Pinned: `test_subprocess_shell_boolean_expression` (4), `test_explicit_dynamic_subprocess_shell_retains_vector`,
`test_unresolved_subprocess_kwargs_is_fail_visible_without_false_vector`, and the frozen contract's
12 expected `dynamic-subprocess-kwargs` gaps (`test_opengrep_parity.py:78-85`: two shadowing cases,
`kwargs-clean-2`, seven `mapping-update-False-*`, two `dict.get` cases) (`test_opengrep_parity::test_live_opengrep_matches_frozen_python_contract`).

#### 2.6.6 Interprocedural and flow filters (P:565-985)

* `_parents(tree)`: child → parent map over `ast.walk`.
* `_function_at(tree, line)`: the FunctionDef/AsyncFunctionDef containing line with the smallest
  `end_lineno - lineno` (`min`: first in walk order on ties).
* `_source_expression(node)` P:590: any sub-node whose call is `input`/`raw_input`/`os.getenv` or
  starts with `requests.`/`httpx.`/`urllib.request.urlopen`, or whose dotted value starts with
  `sys.argv`/`sys.stdin`/`os.environ`.
* `_argument_marker(node)`: Dict → {literal key: marker} (non-literal key → UNKNOWN; unhashable → UNKNOWN);
  List/Tuple → container of markers; else SOURCE/OTHER.
* `_signature(function, bound_method)` P:620 and `bind` (§4.1.4).
* `_call_arguments(call)` P:652: positional (starred only from List/Tuple literals else None),
  keywords (duplicate → `_INVALID_CALL`; `**` only from Dict literals with string literal keys, else None).
* `_sink_argument(function, line)` P:681: the first call on `line` whose callee is a sink: `args=`
  keyword value or first positional.
* `_bound_marker(expr, arguments)` P:694: Name lookup; Subscript with literal key on the bound value;
  otherwise SOURCE if any Name in the expression is bound to a container containing SOURCE, OTHER if
  any Name is bound, UNKNOWN otherwise.
* `_resolve_alias(function, expr, line)` P:724: follow `Name = Name` assignments with `end_lineno < line`, latest wins.
* `_direct_scope`, `_scope_binds_name` (Global/Nonlocal → False; arg, Store/Del Name, def/class,
  ExceptHandler name, MatchAs/MatchStar name, MatchMapping rest, import binding), `_definition_visible`
  (walk up from the call to the defining scope, refusing intermediate scopes that rebind the name;
  then the latest def/class statement before the call with that name must be `function` itself),
  `_method_call_owner` (`Owner().method(...)` inline construction), `_call_flow_is_impossible` P:824
  (every visible call to the function binds the sink argument to a non-SOURCE marker → True),
  `_receiver_flow_is_impossible` P:870 (`self.x()`/`cls.x()` inside a method whose first positional is
  not the receiver, or staticmethod, or the receiver is rebound earlier → True),
  `_async_call_is_executed` / `_unawaited_async_flow` P:904-961 (`_ASYNC_DRIVERS` set),
  `_finally_overrides_flow` P:964 (a visible call on the sink line to a function containing a
  `try/finally` with `return` in `finalbody`), `_source_span` P:1288 (dataflow `taint_source` =
  `["CliLoc", [location, content]]` with path matching the target or its rel; fallback to the
  `$SOURCE` metavar start/end), `_canonical_at`, `_source_identity_is_invalid` P:1340 (per-vector
  protected roots and allowed canonical prefixes; candidates within the source span or containing the
  source position; True when candidates exist and none is valid), `_branch_at`,
  `_mutually_exclusive_lines` P:1398 (If/Match arms; not when the node sits inside a For/AsyncFor/While
  that starts before it), `_command_import_hides_outer_source` P:1423 (`$COMMAND` metavar is an
  identifier, innermost scope is a function without `global command`, source line outside the
  function, and the last binding of command before the sink is an import),
  `_python_definite_false_positive` P:1444 (the OR of all filters, only for `.py` targets and taint vectors).
* `_network_capability_is_invalid(tree, line, col)` P:1179: allowed direct calls (20 dotted names: 8 `requests.*`, 9 `httpx.*`, `urllib.request.urlopen`, `urllib.request.urlretrieve`, `socket.create_connection`) and
  session/client methods on `httpx.AsyncClient`/`httpx.Client`/`requests.Session` constructors,
  resolved through `_binding_at` and `assigned_constructor` (innermost earlier assignment, else the
  single module-wide assignment of a dotted target), each guarded by `_qualified_rebound(...,
  unknown_is_rebound=True)`; True when no call at the position validates.
* `_assigned_alias_is_invalid(extra, tree, line, col)` P:1278: `$ALIAS` metavar identifier whose binding is not "sink".
* `_validated_capability(target, name, capability, line, column, parsed, trees)` P:1482: non-`.py` → True;
  tree from `parsed.by_rel[rel].py_tree` for file origin (may be None → None) or a parse of the text
  (fence origin); None tree → None; execution ⇒ not shadowed sink; network ⇒ not invalid network call.

Pinned by `tests/test_opengrep_bridge.py` lines 201-731 (34 functions / 62 cases) — each test name
states the contract; the implementer must run them all against JSONL tables (§6).

#### 2.6.7 `findings_from_report(report, targets, *, parsed=None, redactions=(), observations=None)` P:1501

Per-call state: `python_trees`, `postfilter_counts`, `capability_postfilter_counts`,
`observation_trees`, `observation_counts`, `fence_sources` (all keyed by target name), `known_vectors
= vector_registry()`, `manifests = _manifest_index(parsed) if parsed else {}`.

1. `results = report.get("results", [])`, `errors = report.get("errors", [])`. `results` not a list →
   return `[opengrep-invalid-output high "OpenGrep returned JSON with an unexpected result shape."]`.
   `errors` not a list → append `"…unexpected error shape."` and treat as []. Any non-dict result →
   append `"OpenGrep returned a malformed result entry."`; any non-dict error → `"…malformed error entry."`.
2. For each dict result: `target_name = _target_name(result["path"])`; unknown target →
   `opengrep-unmapped-target` high `"OpenGrep returned a result for an unknown temporary target."`, continue.
3. `extra` (dict or {}), `metadata` (dict or {}); `vector`, `rule`, `severity`, `capability` from
   `skill_xray_*`. vector not a known registry string or rule not a string → `opengrep-unmapped-rule`
   high, path rel, `` "OpenGrep rule `%s` has no valid Skill Xray mapping." % _rule_id(check_id or "?") ``, continue.
4. severity ∉ {critical, high, medium, low} → `_SEVERITY[extra["severity"].upper()]` default medium.
5. `installer`: rule == `opengrep-shell-fetch-pipe-exec` and severity ∈ {critical, high} and
   `extra["lines"]` is a non-blank string and `installer_idiom(lines)` → severity medium, installer True.
6. `_location` None → `opengrep-invalid-output` high "OpenGrep returned a result with an invalid source location.", continue.
7. `metavars`: present but not a dict, or any key not a string / value not a dict / `abstract_content`
   present but not a string → `"OpenGrep returned malformed metavariable evidence."` and `metavars = None`
   (`malformed_metavars` True).
8. Capability results (`capability is not None`): invalid capability or no `parsed` → `opengrep-unmapped-rule`
   high "OpenGrep capability observation has no valid correlation mapping.", continue. If observations
   collected: `count = observation_counts[target]++`; `valid=None`, `reason="validation-budget"`; when
   `count < 32`: `reason="observation-unvalidated"`, `valid = _validated_capability(...)` unless
   malformed metavars (then None); an exception → `reason="validation-error"`. Append an Observation
   when `valid is not False and count <= 32` with `state = "present" if valid else "unknown"` and
   `reason` only when not valid. Then `manifest = _governing_manifest(manifests, rel)`; None → continue.
   Frontmatter parse error diagnostic → `analysis-incomplete` high, path rel, `"observed %s capability could
   not be compared because the governing frontmatter is invalid"`, evidence `{"phase": "correlation",
   "reason": "capability-declaration-unparsed", "manifest": manifest.rel, "observed_capability": cap}`,
   continue. Neither `allowed-tools` nor `disallowed-tools` key → continue. Malformed-empty values, a
   `grants_unparsed_shape` diagnostic for either key, or any unparsed grant → same finding with message
   `"observed %s capability could not be compared with the malformed governing declaration"`, continue.
   No allowed-tools and capability ∉ denied → continue. capability ∈ declared → continue. For `.py`
   targets: `capability_postfilter_counts[target]++`; ≥ 32 → `analysis-incomplete` high `"observed %s
   capability could not be validated within the per-file budget"`, evidence `{"phase": "correlation",
   "reason": "capability-validation-budget", "observed_capability"}`, continue; `_validated_capability`
   falsy (False or None) → continue. `declared = sorted(tool for effective grants with a tool)`.
9. Python taint post-filter: `python_candidate = vector ∈ taint vectors and suffix == ".py"`;
   `needs_postfilter = candidate and not malformed_metavars`; `count = postfilter_counts[target]++`;
   `postfilter_skipped = count >= 32`. When not skipped: parse once per target (None on failure);
   `(shell_status, explicit) = _subprocess_shell_status(...)` if tree else `(True, False)`;
   `False` → drop; `None and not explicit` → `analysis-incomplete` high, path, **line**, `"A tainted
   subprocess flow uses unresolved keyword arguments; execution eligibility could not be proven."`,
   evidence `{"engine": "opengrep", "reason": "dynamic-subprocess-kwargs", "origin"}`, continue;
   `dynamic_explicit_shell = status is None and explicit`; `_python_definite_false_positive(...)` → drop.
10. Evidence in this insertion order: `engine: "opengrep"`, `engine_rule: _rule_id(check_id)`,
    `origin`, `start`, `end` (from `_location`), `installer_idiom: "https-named-installer"` (if
    installer), `understated_capability`, `manifest`, `declared_tools` (`declared or ["(none)"]`) for
    capability results, `postfilter: "retained-after-validation-budget"` (if skipped),
    `shell_validation: "dynamic-explicit-shell-retained"` (if needs_postfilter and dynamic explicit),
    then for `(extra["fingerprint"], metavars, extra["dataflow_trace"])` when truthy:
    `fingerprint`/`metavars`/`dataflow_trace` = `_remap_engine_paths(value)`. Fence origin →
    `_map_fence_evidence` (adds `engine_location`, `location_mapping`, and possibly
    `engine_dataflow_trace`, `trace_mapping`).
11. Finding(vector, rule, severity, path rel, `line` *, `column = None if location_mapping ==
    "unvalidated" else evidence["start"]["col"]` *, message = `"governing manifest %s does not declare
    observed %s capability" % (manifest.rel, capability)` for capability results, else the own-install
    message (wave 9 errata 6) when `own_path`, else
    `str(extra.get("message") or "OpenGrep detected a tainted flow.")[:800]` (800 code points), evidence).
12. Errors: for each dict error: `target = targets.get(_target_name(error["path"]))`;
    `opengrep-analysis-error` high, path `target.rel` or "", `"OpenGrep could not fully analyze selected
    code: %s" % _scrub(message or type or "unknown error", redactions)[:500]` where `_scrub` replaces
    each redaction string (in the given order) with `<local>`.
13. Return `dedupe_findings(findings)`.

Pinned by: `test_report_maps_temporary_path_to_original_location`, `test_unmapped_rule_and_engine_error_are_visible`,
`test_reject_only_postfilter_work_is_bounded_per_target` (1000 results → exactly 32 validator calls and
32 shell calls, all 1000 findings kept, one carries `postfilter`), `test_dynamic_shell_policy_is_invariant_across_postfilter_budget`,
`test_proven_false_shell_is_rejected_until_validation_budget` (33 results: only line 34 survives),
`test_opaque_kwargs_is_gap_until_validation_budget_then_retained`, `test_malformed_*` (6),
`test_malformed_metadata_does_not_discard_valid_sibling_result`, `test_engine_error_redacts_local_paths`,
`test_all_bounded_engine_errors_remain_visible` (25), `test_python_target_is_parsed_once_per_report`,
`test_capability::*` (observation budget cannot steal understatement budget; validator exception →
observation `unknown`/`validation-error` and findings unchanged; `test_denial_scope_preserves_validated_observations` (6)).

#### 2.6.8 `_coverage_from_report(report, targets)` P:1826

`paths.scanned` missing/not a list → `opengrep-invalid-output` high "OpenGrep did not report which
selected targets it scanned."; `missing = sorted(set(targets) - {_target_name(p) for p in scanned})`;
non-empty → one `opengrep-analysis-incomplete` high at `targets[missing[0]].rel`: `"OpenGrep skipped %d
selected code target(s); the candidate result is incomplete."`. Pinned: `test_skipped_selected_target_is_not_clean`.

#### 2.6.9 `_engine_env(root)` P:1848

Keep only the 26 listed variable names (P:1850-1855; matched on upper-cased names; Go: iterate `os.Environ()`,
split at the first `=`, `strings.ToUpper(key)`), create `root/engine-home{,/cache,/config,/.opengrep}`
and `root/engine-tmp`, set HOME, XDG_CACHE_HOME, XDG_CONFIG_HOME, SEMGREP_SETTINGS_FILE
(`config/settings.yml`), TEMP, TMP, TMPDIR; on Windows additionally `engine-home/AppData/{Roaming,Local}`
→ APPDATA, LOCALAPPDATA, `SEMGREP_LOG_FILE = root/engine.log`, `SEMGREP_VERSION_CACHE_PATH =
root/version-cache`, and USERPROFILE is inherited (it is in the keep list). Pinned by
`test_check_invokes_argument_list_and_converts_json` (asserts `AWS_SECRET_ACCESS_KEY` absent, Windows
paths under HOME).

#### 2.6.10 `check(parsed, *, executable, rules, timeout=45.0, runner, code_units, languages=("python",), observations)` P:1893

1. `selected = select_executable_code(...)`; empty → `[]` (no engine run, no findings).
2. `binary`: if a runner is injected and `executable` is given → use it verbatim (no verification);
   else `resolve_opengrep(executable)`; `OpenGrepRuntimeError` → `[opengrep-unverified high str(exc)]`;
   None → `[opengrep-unavailable high "Executable code was selected, but the OpenGrep binary is unavailable."]`.
3. `rule_path = Path(rules).resolve() if rules else _RULES`; not a file → `opengrep-rules-unavailable` high
   "Executable code was selected, but the local OpenGrep rules are unavailable." (Go: the embedded
   rules are always available; write them to `root/rules.yml` before the run and use that absolute
   path; an explicit `Options.Rules` path is made absolute with `filepath.Abs` **before** changing cwd
   — `test_relative_rule_path_is_resolved_before_temporary_cwd`).
4. Temp dir `skill-xray-opengrep-*`; `targets/` subdir; targets written as `"%04d%s" % (index, suffix)`
   with the text as UTF-8 and `\n` newlines; `targets[name] = item`.
5. argv exactly: `[binary, "scan", "--json", "--dataflow-traces", "--disable-version-check",
   "--disable-nosem", "--no-git-ignore", "--jobs=1", "--max-memory=512", "--max-target-bytes=5242880",
   "--max-match-per-file=1000", "--timeout=5", "--timeout-threshold=1", "--output", <report>,
   "--config", <rules>, <targets dir>]`; cwd = root; env = `_engine_env(root)`; stdout discarded;
   stderr to `root/opengrep-stderr.txt` (first 8192 chars re-read as `captured_stderr`); timeout 45 s;
   no shell; `check=False`. Pinned: `test_check_invokes_argument_list_and_converts_json` (asserts
   `--disable-nosem`, `--disable-version-check`, `--jobs=1`, `--max-memory=512`, `check is False`,
   stdout DEVNULL, stderr not PIPE, no `shell` kwarg).
6. Timeout → `opengrep-timeout` high "OpenGrep exceeded the package analysis deadline."; OSError →
   `opengrep-execution-error` high `"OpenGrep could not start: %s" % type(exc).__name__` (§5.9).
7. Non-zero exit → `opengrep-execution-error` high `"OpenGrep exited with status %d: %s" %
   (returncode, detail[:500])` where detail = `(stderr or stdout or captured_stderr or "no diagnostic
   output").strip()` with `str(root)` → `<temporary>` then `str(rule_path)` → `<rules>`.
8. Report file missing → `opengrep-invalid-output` "OpenGrep completed without producing its JSON report.";
   size > 16 MiB → `opengrep-output-limit` `"OpenGrep's JSON report exceeded the %d-byte limit."`;
   JSON decode error → "OpenGrep completed without returning valid JSON."; not an object →
   "OpenGrep returned an unexpected JSON document."
9. Return `cap_findings(findings_from_report(report, targets, parsed=parsed, redactions=(root,
   rule_path, source_root), observations=observations) + _coverage_from_report(report, targets))`.

Pinned: `test_missing_engine_timeout_and_invalid_json_are_not_clean`,
`test_missing_and_oversized_reports_are_not_clean`, the seven `test_real_opengrep_*` live tests, and
`test_taint_engine::test_one_process_receives_python_and_supported_shell` (one process gets both `.py` and `.sh`).

#### 2.6.11 `checks/taint_engine.py::check` P:333-362 → `opengrep.Check(pkg, Options)`

```go
type Options struct {
    Executable string          // --opengrep-bin / test injection; "" = resolve
    Rules      string          // explicit rule file; "" = embedded
    Timeout    time.Duration   // 0 = 45 s
    Runner     func(ctx context.Context, argv []string, dir string, env []string, stderr *os.File) (exit int, err error) // nil = os/exec
    Units      []codelane.Unit // nil = build now; non-nil empty = nothing selected (run_checks passes () after a failed build: test_taint_engine::test_failed_shared_lane_is_not_rebuilt)
    LaneNotes  []findings.Finding
    Languages  []string        // Run default ("python"); Check always passes ("python","shell")
    Observations *[]map[string]any // nil = do not collect (00-overview D9)
}
```

`Check`: `findings = LaneNotes` (copied once, `test_lane_notes_are_retained_once`); append
`Run(pkg, opts with Languages = python, shell)`; any error or recovered panic from `Run` →
`opengrep-internal-error` high, path "", `"OpenGrep analysis failed unexpectedly: %s"` (§5.9),
evidence `{"engine": "opengrep"}`; return `cap_findings(findings)`. `Run` itself never returns an error
value; the panic recovery exists for the same reason the Python `except Exception` does.

#### 2.6.12 Rule file facts the Go side depends on

63 rules, unique ids, 28 `languages: [python]`, 35 `languages: [bash]`; vectors {SXV-005, 008, 009,
010, 018, 019, 020, 021, 022, 023, 024, 025, 026, 032, 033, 039, 040}; 4 capability rules
(`skill-xray.python-execution-capability`, `python-network-capability`, `shell-execution-capability`,
`shell-network-capability`, vector SXV-033, rule `permission-understatement`, severity medium); no rule
id contains "poc". Pinned by `test_bundled_rules_are_valid_yaml_and_mapped` (Go: `yaml.v3` on the
embedded bytes). The rule file's 409 regexes (30 `pattern-regex`, 187 `metavariable-regex`, the rest
inside `patterns`) run inside OpenGrep, not in Go; 54 of them use lookaround or backreferences and
that is OpenGrep's concern.

### 2.7 `opengrep_runtime.py` → `internal/opengrep/runtime.go`

| function | behaviour | pinned by (`tests/test_opengrep_runtime.py::`) |
|---|---|---|
| `VERSION = "1.29.0"`, `_RELEASE = "https://github.com/opengrep/opengrep/releases/download/v1.29.0"`, `_MAX_DOWNLOAD = 64 MiB`, env `SKILL_XRAY_OPENGREP_BIN` | | `test_cli_forwards_explicit_binary` (`"opengrepVersion": "1.29.0"` in JSON) |
| `_ASSETS` P:37 | (windows,x86_64) `opengrep_windows_x86.exe` 53,536,256 `ee485b31…1025`; (linux,x86_64) `opengrep_manylinux_x86` 46,442,664 `3365ef49…ae13`; (linux,aarch64) `opengrep_manylinux_aarch64` 47,916,824 `db3cda6e…1174`; (darwin,x86_64) `opengrep_osx_x86` 48,310,144 `7173bd70…6508`; (darwin,aarch64) `opengrep_osx_arm64` 47,281,712 `dacc12a2…3438` (copy the full 64-hex digests from P:38-57) | `test_platform_assets_are_pinned` |
| `_platform_key(system, machine)` P:61 | lower; amd64/x64/x86_64 → x86_64; arm64/aarch64 → aarch64. Go: `PlatformAsset(goos, goarch)` must also accept Python spellings (`"Windows"`, `"AMD64"`, `"Darwin"`, `"arm64"`) so the ported test keeps its inputs; unknown → `RuntimeError("OpenGrep v1.29.0 is not pinned for %s/%s")` | same |
| `default_cache_dir()` P:81 | Windows with `LOCALAPPDATA` → that; Darwin → `~/Library/Caches`; else `XDG_CACHE_HOME` or `~/.cache`; + `skill-xray/opengrep/1.29.0` | – |
| `cached_executable(dir)` P:92 | dir or default + `opengrep.exe` (Windows) / `opengrep` | – |
| `verify_executable(path, asset=None)` P:110 | stat failure → `"OpenGrep executable is unavailable: %s"`; not a regular file or size mismatch → `"OpenGrep executable does not match pinned v1.29.0 asset: %s"`; SHA-256 (1 MiB chunks) cached by `(resolved path, size, mtime_ns, ctime_ns, ino, dev)` (LRU 8); digest mismatch → same message; returns the path | `test_verify_rejects_wrong_size_or_digest`, `test_verified_binary_digest_is_cached_by_file_identity` (exactly one digest for two verifications) |
| `resolve_opengrep(explicit=None)` P:137 | explicit or env → verify (errors propagate); else cached path exists → verify; else `shutil.which("opengrep")` → verify; else None | `test_resolve_prefers_explicit_and_requires_verification` |
| `install_opengrep(cache_dir=None, *, opener, timeout=60)` P:148 | asset for this platform; destination exists and verifies → return; mkdir -p; GET `asset.url` with `User-Agent: skill-xray/1.29.0`; `Content-Length` > 64 MiB → `"OpenGrep download exceeds the safety limit"`; stream 1 MiB chunks into `.opengrep-*` temp file in the destination dir, aborting past 64 MiB; verify temp; chmod 0700; `os.replace` → destination; verify again; OSError/ValueError → `"OpenGrep installation failed: %s" % type(exc).__name__`; temp always removed on failure | `test_install_is_atomic_and_verified` (URL + timeout forwarded, no `.opengrep-*` left), `test_install_rejects_unverified_payload` |

CLI wiring (`cli.py:149-161, 176-177, 246, 265`) belongs to core: `--install-opengrep` standalone
action printing `VERSION` and the installed path (exit 0; failure exit 2 with the message on stderr),
`--opengrep-bin PATH` requiring `--analyze`, `analysis.opengrepVersion` in JSON.

---

## 3. Regex inventory

42 regex uses (41 distinct patterns) across the five Python modules. Verdict key: **RE2** = usable
unchanged apart from the mechanical substitutions; **RE2+class** = needs the `pystr` character classes
(§5.1) substituted for `\s`, `\S`, `\w`, `\d`, `\b`; **RE2+scan** = uses the boundary scanner (§3.4).
No pattern needs `dlclark/regexp2` (`regexes_needing_regexp2 = 0`).

Mechanical substitutions: `re.I` → leading `(?i)`; `re.S` → `(?s)`; `\d` → `\p{Nd}` (Python `\d` is
Unicode decimal); `\w` → `[\pL\pN_]`; `\s` → `pytext.Space` (Python `str.isspace` set, §5.1); `\S` →
`pytext.NotSpace`; `\b` → scanner or a consuming one-character class as stated; `.fullmatch(p)` →
`^(?:p)$` (Go `$` is end-of-text only, which is exactly `fullmatch`; Python's bare `$` would also match
before a final `\n`, but none of the group's `$`-anchored patterns is applied to text that can end in
`\n` — every input is a token, a host, a URL path or a trimmed line); `.match` → `^…`; `(?P<name>…)`
unchanged; `finditer` → `FindAllStringIndex(-1)`; `\1` in `re.sub` replacement → `${1}`.

### 3.1 `checks/code_lane.py` (16)

| # | pattern | use | verdict |
|---|---|---|---|
| 1 | `_CONSOLE_PROMPT_RE` `^\s{0,3}\$\s+` P:27 | `.sub` per shell fence line, replacement = spaces of the match's code-point length | RE2+class (`\s` twice) |
| 2 | `[A-Za-z0-9_+-]+` P:67 | `.search` on the first info token | RE2 |
| 3 | `^#!.*\b(bash\|sh\|dash\|ksh\|zsh\|fish)\b` P:73 | `.match` on lowercased first line (no `\n`) | RE2+class: `^#!.*(?:^\|[^\pL\pN_])(bash\|…)(?:[^\pL\pN_]\|$)` is NOT equivalent because `.*` already consumed the boundary char; use `^#!(?:.*[^\pL\pN_])?(bash\|sh\|dash\|ksh\|zsh\|fish)(?:[^\pL\pN_]\|$)` — the `#!` prefix chars are non-word so the empty alternative covers `#!bash`. RE2 leftmost-first with greedy `.*` picks the same (rightmost) group as Python's backtracking |
| 4 | `_INSTALLER_URL_RE` P:202 | `.fullmatch`, groups host/path | RE2+class (`[^\s'"\|;&`)<>]`), `(?i)`, `^…$` |
| 5 | `_INSTALLER_PATH_RE` P:205 | `.search` on the rstripped path | RE2+class (`\w` ×3) |
| 6 | `_DROP_HOST_RE` P:210 | `.search` on host; exported | RE2+class (`\w+` ×2) |
| 7 | `_INSECURE_FLAG_RE` P:221 | `.search` (boolean) | lookbehind `(?<![\w-])` + lookahead `(?![\w-])` → rewrite `(?:^\|[^\pL\pN_-])(?:ALTS)(?:[^\pL\pN_-]\|$)`; existence of a match is preserved because each lookaround is one character wide (§3.4) |
| 8 | `_COMMAND_SPLIT_RE` `\|\|\|&&\|;` P:226 | `.split` | RE2 (`regexp.Split(s, -1)`) |
| 9 | `_LATER_FETCH_RE` P:229 | `.search` (boolean) | two `\b` → `[;&\|](?:[^;&\|\n]*?[^\pL\pN_;&\|\n])?(?:curl\|wget\|aria2c\|https?\|httpie\|fetch)(?:[^\pL\pN_]\|$)`; the leading `[;&\|]` is itself non-word so the optional group covers "immediately after the separator" |
| 10 | `_INLINE_CODE_CONSUMER_RE` P:233 | `.search` (boolean) | three `\b` per alternative → `(?:^\|[^\pL\pN_])(?:python[0-9.]*\|perl\|ruby\|node\|php)(?:S\|[^\|;&\n\pL\pN_][^\|;&\n]{0,39}?S)-[A-Za-z]*[ce](?:[^\pL\pN_]\|$)` with `S` = `pytext.Space` (as a class body inside `[...]`, as a class on its own elsewhere), and the same shape for the shell alternative with `[A-Za-z]*c`. The middle `\b` after the interpreter name requires the next char to be non-word: either the `\s` itself (run of length 0) or the first char of a non-empty `{0,40}?` run, which may itself be whitespace (`python  -c` with two spaces must match, as in Python). RE2's backtracking-equivalent search over `python[0-9.]*` reproduces `python3.x -c` (Python backtracks `[0-9.]*` to `3` so that `.` is the boundary char) |
| 11 | `_BARE_HOST_RE` P:238 | `.match` on tokens | RE2+class (`\S*`, `\d`→`\p{Nd}`, `(?i)`) |
| 12 | `_ANY_URL_RE` P:243 | `.findall` | RE2+class |
| 13 | `_SUBSTITUTION_RE` `[`$]\|[<>]\(` P:248 | `.search` | RE2 |
| 14 | `_PROCESS_SUB_FETCH_RE` P:249 | `.match` with `re.S`, group 1 | RE2+class (`(?s)`, `\s` ×3) |
| 15 | `_PLACEHOLDER_HOST_RE` P:253 | `.search` on host | RE2, `(?i)` |
| 16 | `[\d.]+` P:315 | `.fullmatch` on host | RE2 (`^[\p{Nd}.]+$`; host class is ASCII so `[0-9.]` is also exact) |

### 3.2 `checks/supply_chain.py` (19)

| # | pattern | use | verdict |
|---|---|---|---|
| 17 | aws `\b(?:AKIA\|ASIA)[0-9A-Z]{16}\b` | `finditer` + `sub` | RE2+scan (both `\b`) |
| 18 | github `\b(?:gh[pousr]_[A-Za-z0-9]{36,}\|github_pat_[A-Za-z0-9_]{40,})\b` | same | RE2+scan |
| 19 | slack `\b(?:xox[abeprs]-\d[A-Za-z0-9-]{9,}\|xapp-[0-9]-[A-Za-z0-9-]{10,})\b` | same | RE2+scan, `\d`→`\p{Nd}` |
| 20 | private-key `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----` | same | RE2 |
| 21 | google `(?<![0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])` | same | RE2+scan with the custom boundary class `[0-9A-Za-z_-]` (not `\w`) |
| 22 | stripe `\b(?:sk\|rk)_live_[0-9A-Za-z]{16,}\b` | same | RE2+scan |
| 23 | npm `\bnpm_[A-Za-z0-9]{36}\b` | same | RE2+scan |
| 24 | pypi `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{16,}` | same | RE2+scan (left only) |
| 25 | azure `\b(?:AccountKey\|SharedAccessKey)=[A-Za-z0-9+/]{32,}={0,2}` | same | RE2+scan (left only) |
| 26 | `_SLACK_ZERO_PLACEHOLDER` `^xox[abeprs]-0{10}-0{13}-[A-Za-z0-9-]+$` | `.fullmatch` | RE2 |
| 27 | `_VCS_INSTALL_RE` P:219 | `.search`, `group(0)`, `start()` | RE2+class: `\w`, `\s`, `\S`, `(?i)`; the trailing `\b` after the archive extension becomes a consuming `(?:[^\pL\pN_]\|$)` placed **outside** a capture group so the match extent is unchanged. Because the four alternatives start with disjoint characters (`g/h/s/b`, `@`, whitespace/`=`/start-of-string, `-`) their order is irrelevant to leftmost-first matching, so the archive alternative is moved last: `(?i)((?:git\|hg\|svn\|bzr)\+[\pL\pN_]+://S+\|@s*[a-z][a-z0-9]*(?:\+[a-z0-9]+)?://S+\|(?:-e\|--editable)s+S*://S+)\|((?:^\|s\|=)https?://S+?\.(?:git\|zip\|tar(?:\.(?:gz\|bz2\|xz))?\|tgz\|whl))(?:[^\pL\pN_]\|$)` with `S`/`s` = `pytext.NotSpace`/`pytext.Space`. Go uses `FindStringSubmatchIndex`; the extent is group 1 or group 2, whichever is non-empty; `m.start()` is that group's start. RE2 reproduces Python's lazy `S+?` + greedy optional `\.gz` extents (`a.tar.gz` → `…a.tar.gz`; `a.tar.gzx` → `…a.tar`) |
| 28 | `_NPM_SHORTHAND_RE` `^(?:github\|gitlab\|bitbucket\|gist):` | `.match` | RE2 `(?i)` |
| 29 | `_NPM_OWNER_REPO_RE` `^[A-Za-z0-9][\w.-]*/[\w.-]+(?:#.+)?$` | `.match` | RE2+class (`\w` ×2; `.+` must not cross `\n`: Go `.` also excludes `\n` by default) |
| 30 | `_NPM_SCP_RE` `^git@[^:\s]+:[^\s]+$` | `.match` | RE2+class |
| 31 | `(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@` P:272 | `.sub` → `\1***@` | RE2+class, replacement `${1}***@` |
| 32 | `\s#` P:334 | `.split(maxsplit=1)` | RE2+class, `Split(s, 2)` |
| 33 | `(?:-e\|--editable)\b` P:337 | `.match` (boolean) | `^(?:-e\|--editable)(?:[^\pL\pN_]\|$)` |
| 34 | `[\s@<>=!~;\[]` P:343 | `.split(maxsplit=1)` | RE2+class |
| 35 | `[A-Za-z0-9+/=]+` P:152 | `.fullmatch` | RE2 `^…$` |

### 3.3 `checks/grants.py` (4), `opengrep_bridge.py` (2), `analyze.py` (1)

| # | pattern | use | verdict |
|---|---|---|---|
| 36 | `_VARIABLE` P:12 | `finditer` (start, group 0) | RE2 (`(?i:env)` scoped flags are RE2 syntax; `\d`→`\p{Nd}`) |
| 37 | `_VERSION_SUFFIX` `\d+(?:\.\d+)*$` P:18 | `.sub("")` on a basename | RE2 `\p{Nd}+(?:\.\p{Nd}+)*$` |
| 38 | `_ENV_ASSIGNMENT` `^[A-Za-z_]\w*=` P:19 | `.search` | RE2+class |
| 39 | `_WRAPPER_ARGUMENT` `^-\|=\|^\d+(?:\.\d+)?[smhd]?$` P:20 | `.search` | RE2 `\p{Nd}` |
| 40 | `[A-Za-z_]\w*` bridge P:1282 (`$ALIAS`) | `.fullmatch` | RE2+class `^[A-Za-z_][\pL\pN_]*$` |
| 41 | `[A-Za-z_]\w*` bridge P:1430 (`$COMMAND`) | `.fullmatch` | same pattern object |
| 42 | `\.so(?:\.\d+)+$` analyze P:571 | `.sub(".so")` on the lowered rel | RE2 `\.so(?:\.\p{Nd}+)+$` |

### 3.4 Boundary scanner for `\b`-anchored token patterns (`pytext.FindAllBounded`)

Python's `\b` (str patterns) is Unicode-aware (`\w` = `isalnum() or "_"`), Go's is ASCII. For the nine
secret rules the token itself is ASCII but the neighbours may not be: Python refuses
`éAKIA0123456789ABCDEF` (no boundary between `é` and `A`), ASCII `\b` accepts it. Emulate exactly:
compile the rule without `\b`/lookarounds and anchored with `^`; scan `i` from 0: if the anchored
pattern matches at `s[i:]`, check the left neighbour rune (must not satisfy the boundary class, or
`i == 0`) and the right neighbour rune (must not satisfy the class, or end), where the class is
`pytext.IsWord` for `\b` rules and `[0-9A-Za-z_-]` for the google rule; on success record
`[i, i+len)` and continue at `i+len`; on failure continue at `i+1`. This is exactly `re.finditer`'s
resumption behaviour (a failed candidate at `i` retries at `i+1`; a success resumes after the match).
Left-only rules (pypi, azure) skip the right check. The same helper backs `_redact_source_secrets`
(replace each found span with `Redact(token)`).

### 3.5 Flags where Python `re` and RE2 differ, checked per pattern

* `\b` non-ASCII: patterns 3, 7, 9, 10, 17–19, 21–25, 27, 33 — all handled above; in 3/7/9/10/33 the
  inputs are shell commands and `\w` neighbours can be non-ASCII identifiers or prose.
* `\s`: patterns 1, 4, 10, 11, 12, 14, 27, 30–32, 34 — fence code and requirement lines can contain
  `\v`, `\xa0`, `\x85`, `\u2028`: Python's class includes them, Go's `\s` does not (`[\t\n\f\r ]`) →
  always substitute `pytext.Space`.
* `$` with a trailing newline: none of the anchored patterns is applied to a string that may end in
  `\n` (tokens from shlex cannot contain `\n`; URL/host/path classes exclude whitespace; `line.strip()`).
* `(?i)` on non-ASCII: both engines use simple case folding (Kelvin sign, long s); the group's `(?i)`
  patterns (4, 6, 11, 12, 14, 15, 27, 28, 30, 31) only need to agree on ASCII letters and they do.
* `\d`: 11, 16, 19, 36, 37, 39, 42 → `\p{Nd}` (a basename like `python٣` must have its Unicode digit
  suffix stripped exactly as Python does).

---

## 4. Third-party and stdlib replacements

### 4.1 `ast` (CPython 3.13) → `internal/pyast` (new, pure Go) — the decision

Options considered: (a) `github.com/go-python/gpython/parser` — Python 3.4 grammar, no `end_lineno`/
`end_col_offset`, no `match`, walrus, posonly params, f-strings, type params: rejected, it would change
which fences lift (`_python_is_module`) and every position-based filter; (b) tree-sitter Go bindings —
cgo, forbidden by CLAUDE.md; (c) ANTLR grammars-v4 Python3 → Go target — pure Go but produces a CST
needing a CPython-shaped AST layer of the same size as writing the parser, and the Go target grammar
is not maintained for 3.12+; (d) shelling out to `python` — defeats the port. **Decision: write
`internal/pyast`, a tokenizer + recursive-descent parser for the full Python 3.13 grammar emitting
CPython's AST node set with `lineno`, `col_offset` (UTF-8 bytes), `end_lineno`, `end_col_offset`, plus
`Walk`, `IterChildNodes`, `LiteralEval`, and CPython's acceptance limits.** It is the single largest
work item of the port (estimate 3.5–4.5 k lines incl. tests) and it is shared with the parse group
(`parse.py:1290-1313` builds `py_tree` and the depth-512 `python_too_complex` diagnostic on it).

Acceptance parity requirements (what `_python_is_module` and the parse group's diagnostics see):
`SyntaxError` on any grammar violation, `IndentationError`/`TabError` (tab size 8 consistency check),
NUL byte in source → `ValueError` (both map to "not a module"); CPython limits: `MAXINDENT = 100`
indentation levels, `MAXLEVEL = 200` nested parentheses/brackets/braces ("too many nested
parentheses"), and the parser's recursion ceiling for deeply nested expressions (CPython raises
`RecursionError`/`MemoryError` around ~1,000 nesting depth on 3.13 defaults). Left-associative
chains are iterative (the contract case `bomb.py` = 3,000 `"a"+"a"+…` parses and is analysed;
`deep.py` = 300 `+ 'a'` parses). Implement the three limits as constants with a `// ponytail:` note
that the exact recursion ceiling is CPython-build-dependent and is pinned only by the contract corpus.

Node kinds and `_fields` orders the group depends on (child-yield order = `ast.walk`/BFS order and
`iter_child_nodes` order; copy from CPython 3.13 `Parser/Python.asdl`): `Module(body, type_ignores)`,
`FunctionDef(name, args, body, decorator_list, returns, type_comment, type_params)`, `AsyncFunctionDef`
(same), `ClassDef(name, bases, keywords, body, decorator_list, type_params)`, `Return(value)`,
`Delete(targets)`, `Assign(targets, value, type_comment)`, `AugAssign(target, op, value)`,
`AnnAssign(target, annotation, value, simple)`, `For/AsyncFor(target, iter, body, orelse, type_comment)`,
`While(test, body, orelse)`, `If(test, body, orelse)`, `With/AsyncWith(items, body, type_comment)`,
`Match(subject, cases)`, `Try/TryStar(body, handlers, orelse, finalbody)`, `Import(names)`,
`ImportFrom(module, names, level)`, `Global(names)`, `Nonlocal(names)`, `Expr(value)`,
`BoolOp(op, values)`, `NamedExpr(target, value)`, `BinOp(left, op, right)`, `UnaryOp(op, operand)`,
`Lambda(args, body)`, `IfExp(test, body, orelse)`, `Dict(keys, values)`, `Set(elts)`,
`ListComp/SetComp/GeneratorExp(elt, generators)`, `DictComp(key, value, generators)`, `Await(value)`,
`Yield/YieldFrom(value)`, `Compare(left, ops, comparators)`, `Call(func, args, keywords)`,
`FormattedValue(value, conversion, format_spec)`, `JoinedStr(values)`, `Constant(value, kind)`,
`Attribute(value, attr, ctx)`, `Subscript(value, slice, ctx)`, `Starred(value, ctx)`, `Name(id, ctx)`,
`List/Tuple(elts, ctx)`, `Slice(lower, upper, step)`, `comprehension(target, iter, ifs, is_async)`,
`ExceptHandler(type, name, body)`, `arguments(posonlyargs, args, vararg, kwonlyargs, kw_defaults, kwarg,
defaults)`, `arg(arg, annotation, type_comment)`, `keyword(arg, value)`, `alias(name, asname)`,
`withitem`, `match_case(pattern, guard, body)`, the `Match*` patterns (`MatchAs(pattern, name)`,
`MatchStar(name)`, `MatchMapping(keys, patterns, rest)`, …), and the leaf singletons
(`Load/Store/Del`, operators, `And/Or`, `Not`, comparison ops). `Dict.keys` may contain None (for
`**x`), `arguments.kw_defaults` may contain None; `iter_child_nodes` skips them.

#### 4.1.2 Positions

`col_offset`/`end_col_offset` are byte offsets into the UTF-8 encoding of the line, 0-based; `lineno`
1-based. Multi-line strings end on their last line. Every node the bridge inspects must carry all
four; `Module` has none (Python raises AttributeError for `tree.lineno`, and the bridge never reads it).

#### 4.1.3 `ast.literal_eval` and the constant value model (`pyast.Value`)

`LiteralEval(node)` accepts `Constant` (int — arbitrary precision in CPython; Go: `*big.Int` is
exact, `int64` with overflow → treat as not-literal is the `// ponytail:` corner; choose `int64` +
ponytail note since the values only feed `bool()` and dict keys), float, complex, str, bytes, bool,
None, Ellipsis), `Tuple`/`List`/`Set`/`Dict` of literals (Dict keys must be literals; `**` → ValueError),
`UnaryOp` `+`/`-` on numbers, and `BinOp` `+`/`-` only when combining a real and an imaginary
number; everything else → ValueError. The bridge's `_static_value` needs, on these values: Python
truthiness (`0`, `0.0`, `""`, `b""`, empty containers, `None`, `False` are falsy), `==`/`!=` across
types (never raises; `1 == True`, `1 == 1.0`), ordering (`<` between number types; `str` vs `str`;
list/tuple lexicographic; mixed → TypeError), `is`/`is not` (identity: only meaningful for the same
literal object; in Go treat `is` as `==` for None/bool and small ints, else `==` too — the bridge only
compares constants, `// ponytail:` note), `in` (str substring, container membership; non-container →
TypeError), dict key hashing (int/bool/float/str/bytes/None/tuple-of-hashables; list/dict/set →
TypeError), `dict | dict`, `dict.get`, subscripts on dict/list/tuple/str with negative indices.
Represent with a small tagged union; every TypeError path returns the `UNKNOWN` marker.

#### 4.1.4 `inspect.Signature.bind` (bridge:620-649, 860)

Reimplement CPython's `Signature._bind` for a signature built from `arguments`: parameters in order
POSITIONAL_ONLY (posonlyargs), POSITIONAL_OR_KEYWORD (args), VAR_POSITIONAL, KEYWORD_ONLY,
VAR_KEYWORD; defaults present ⇔ marker `OTHER`; when `bound_method`, drop parameter 0. Bind
`(*positional, **keywords)` following CPython `Lib/inspect.py Signature._bind`: too many positionals
without `*args` → TypeError; a positional-only parameter that was not filled positionally but whose
name appears in the keywords → TypeError ("positional only, but was passed as a keyword"); a keyword
naming a parameter already filled positionally → TypeError ("multiple values") unless the parameter is
positional-only, in which case it flows into `**kwargs` when present and is an "unexpected keyword"
TypeError otherwise; missing required → TypeError; unexpected keyword without `**kwargs` → TypeError.
`bound.arguments` = ordered map name → value with `*args` → tuple of remaining positionals and
`**kwargs` → dict; parameters with defaults that were not supplied are **absent** from
`bound.arguments` (`bind`, not `apply_defaults`) — so `_bound_marker` returns UNKNOWN for them and the
call is treated as "not proven impossible" (`bridge:865`).

### 4.2 `shlex` → `pytext.ShlexSplit(s)` (POSIX) and `pytext.ShlexNonPosix(s, punctuation, whitespace)`

Port CPython 3.13 `Lib/shlex.py` `read_token` verbatim for the two configurations used:
`shlex.split(fetch)` = `posix=True, whitespace_split=True, commenters="", quotes='"'`, `escape='\'`,
`escapedquotes='"'`, `wordchars` irrelevant under whitespace_split; raises "No closing quotation" /
"No escaped character" (both ValueError → Go `error`). `grants._command_tokens` = `posix=False,
punctuation_chars=";&|\n", whitespace=" \t\r", whitespace_split=True, commenters=""`, `wordchars`
= ASCII alnum + `_` + `~-./*?=` minus the punctuation chars; non-POSIX mode keeps quotes inside
tokens, a token starting with a quote ends at the matching quote (`"curl"`), a quote inside a word is
just a character (`foo'$RUNNER'`), runs of punctuation chars are tokens of their own (`&&`, `\n`).
Also used by the parse group (`parse.py:1000` `shlex.split(m.group(2), posix=False)`) — the same
package serves both; that is a third configuration (`posix=False, whitespace_split=False`, default
wordchars, quotes kept) and must be covered by the same state machine.

### 4.3 `urllib.parse.urlsplit/urlunsplit/hostname/port` → `pytext.URLSplit` (hand port, ~50 lines)

`net/url.Parse` is rejected: it accepts/rejects different inputs (percent-encoding validation,
control characters, `[bad` handling differs in details) and lowercases nothing. Port CPython 3.13
`urlsplit`: strip leading C0 controls and spaces, remove `\t\r\n`, scheme = `[A-Za-z][A-Za-z0-9+.-]*`
before the first `:` (lowercased), `//` netloc up to the first of `/?#`, `[`/`]` bracket sanity
(`ValueError("Invalid IPv6 URL")`), `_checknetloc` (NFKC normalisation of a non-ASCII netloc via
`golang.org/x/text/unicode/norm` and rejection when `/?#@:` appear after normalisation), then
`fragment` after `#`, `query` after `?`. `hostname` = netloc after the last `@`, before the port,
brackets stripped, lowercased (§5.2); `port` = digits after the last `:` outside brackets, 0..65535,
else ValueError (→ omitted). `urlunsplit((scheme, host, path, "", ""))` = `scheme + ":" + ("//" +
host if host or scheme in uses_netloc else "") + path` with the leading-slash rule from CPython
(`if netloc or (scheme and scheme in uses_netloc and url[:2] != '//'): if url and url[:1] != '/': url = '/' + url`).

### 4.4 `bisect`, `heapq`

`bisect_right(starts, line)` → `sort.Search(len(starts), func(i) bool { return starts[i] > line })`.
`heapq.nsmallest(n, it, key)` → materialise, `sort.SliceStable` by key, slice to `n` (documented
equivalent of `sorted(...)[:n]`; the Python bound on memory is not a behaviour).

### 4.5 `zlib` → `hash/crc32` and `compress/gzip`

`zlib.crc32` = `crc32.ChecksumIEEE`. `_is_gzip`: `gzip.NewReader(bytes.NewReader(raw[i:]))`,
`Multistream(false)`, read with a `LimitReader` of `_MAX_GZIP_OUTPUT+1` bytes; success ⇔ `io.EOF`
reached (member trailer verified) with ≤ 1,048,576 bytes produced; `ErrChecksum`, `ErrHeader`,
`io.ErrUnexpectedEOF`, any other error → False. Python's `d.eof` after one member ignores trailing
garbage; `Multistream(false)` matches.

### 4.6 `json` → `encoding/json` with `Decoder.UseNumber()` into `any`

The bridge checks `type(x) is int` (bools excluded, floats excluded) and copies `metavars`,
`dataflow_trace` and `fingerprint` verbatim into evidence. Typed structs would drop unknown fields
(changing the JSON output) and cannot express "is this JSON scalar an int". Decode to `any` with `UseNumber`, then normalise the tree once: a `json.Number` whose text has no `.`/`e`/`E` and fits `int64` becomes Go `int`, any other number `float64` (00-overview D7); `isInt(v any)` is then the plain `int` assertion shared with core. Bools are `bool`, never ints. Python `json.loads("1.0")` is a float → invalid line, matching.
Re-encoding evidence: `map[string]any` marshals with sorted keys; Python preserves insertion order —
the parity harness compares parsed JSON (§7), so no ordered map is required. `deepcopy` → a generic
`cloneJSON(any) any`.

### 4.7 `subprocess`, `tempfile`, `os`, `hashlib`, `platform`, `shutil.which`, `urllib.request`

`os/exec` (`exec.CommandContext` with `context.WithTimeout(45s)`, `cmd.Dir = root`, `cmd.Env`,
`cmd.Stdout = nil` (→ /dev/null), `cmd.Stderr = file`, `cmd.WaitDelay = 10s` as in mcp-xray
`taint/opengrep.go:117`); `os.MkdirTemp("", "skill-xray-opengrep-")` + `defer os.RemoveAll`;
`crypto/sha256`; `runtime.GOOS/GOARCH`; `exec.LookPath("opengrep")` (Windows: honours PATHEXT like
`shutil.which`); `net/http` with `User-Agent` header, `Content-Length` check and a streaming 64 MiB cap;
`os.CreateTemp(dir, ".opengrep-*")`, `os.Chmod(0o700)`, `os.Rename`.

### 4.8 Not used by this group

markdown_it, tree_sitter(_bash), ruamel, jsonschema, packaging, tomllib, html, posixpath, ipaddress,
unicodedata (only indirectly through `urlsplit._checknetloc`, §4.3), zipfile/tarfile (the ZIP walk is
hand-written in `analyze.py` and stays hand-written). The group consumes markdown facts only through
the IR: fence `(info, content, opening line)`, fence spans `(first, last)` (§1.2); no bash parse facts
at all (the shell side is OpenGrep's).

---

## 5. Python semantics that do not translate (each use named)

Shared helper package `internal/pytext` (cross-group need; ~150 lines): `Space`/`NotSpace` regex
class strings, `IsSpace(r)`, `IsWord(r)`, `Fields(s)`, `Strip(s)`, `Lower(s)`, `ShlexSplit`,
`ShlexNonPosix`, `URLSplit`, `FindAllBounded`, `Splitext`.

1. **`str.isspace` vs `unicode.IsSpace`** — Python: `\t\n\v\f\r\x1c\x1d\x1e\x1f \x85\xa0\u1680
   \u2000-\u200a\u2028\u2029\u202f\u205f\u3000`; Go's `unicode.IsSpace` lacks `\x1c-\x1f`. Uses:
   `info.split()` (code_lane:64), `t.split()` in `installer_idiom` (code_lane:297), `command.split()`
   fallback (grants:111), `.strip()` on lines/tokens (supply_chain:152, 235, 334, 343; grants:100,
   215, 334, 340-347), `line.strip()` before the base64 fullmatch, and every `\s` in §3.
2. **`str.lower()` vs `strings.ToLower`** — differ for `İ` (U+0130 → `i̇`, two code points, in Python;
   `i` in Go) and final sigma (`Σ` → `ς` at word end in Python). Uses: `_fence_lang` (code_lane:68),
   `_shell_dialect` (72, 76), `host.lower()` (314), `_basename` (grants:90), `.lower()` on tokens
   (grants:169-170, 188, 206, 249), `_ecosystem`/basename (supply_chain:103, 317), `rel.lower()`
   (analyze:571 — reaches the message text via `ext`), `hostname` in `urlsplit`. `pytext.Lower`
   implements the two special cases over `unicode.ToLower`.
3. **`str.split()` (no argument)** → `pytext.Fields` (Python whitespace set, runs collapsed).
   `text.split("\n")` → `strings.Split` (identical incl. trailing empty element).
4. **`len(str)` is code points**: `MAX_PY_CHARS` (code_lane:81), `_redact` (supply_chain:109-111),
   `[:120]`, `[:200]` (288-291), `[:800]` (bridge:1806), `[:500]` (1819, 1989), the 8192-char stderr
   read (1968), `len(source) - len(lifted)` and the slices in `_fence_region` (bridge:154-172).
   Go: `utf8.RuneCountInString`, rune-slice truncation.
5. **`str.encode("utf-8")` on a str that may contain lone surrogates** raises; Go strings cannot hold
   them. Cross-group: the parse/ingest spec must state that `Text` is always valid UTF-8 (ingest decodes
   strictly or leaves `Text == nil`); then `_fence_region`'s UnicodeDecodeError path reduces to
   `utf8.Valid(prefix)` on a byte-split column.
6. **`shlex`** — §4.2.
7. **`urllib.parse`** — §4.3; `unicodedata.normalize("NFKC", …)` only inside `_checknetloc`, via
   `x/text/unicode/norm` (Unicode 15.0 tables vs CPython 3.13's 15.1 — no NFKC change affects the
   `/?#@:` check).
8. **`os.path.splitext`** (analyze:571): last `.` in the basename, but a basename consisting only of
   leading dots plus a name (`.bashrc`, `..x`) has no extension. `filepath.Ext` differs → `pytext.Splitext`.
   Both `ntpath` and `posixpath` treat `/` as a separator for this rel (Python on Windows uses
   `ntpath`, which also splits on `\`; `rel` never contains `\` after ingest).
9. **Exception class names in messages**: `"OpenGrep could not start: %s" % type(exc).__name__`
   (bridge:1978 — FileNotFoundError / PermissionError / OSError), `"OpenGrep analysis failed
   unexpectedly: %s"` (taint_engine:359), `"byte analysis could not complete: %s"` (analyze:608),
   `"OpenGrep installation failed: %s"` (runtime:186), `"check %s failed: %s"` (checks/__init__.py:71,
   core). Go maps: `errors.Is(err, fs.ErrNotExist)` → "FileNotFoundError", `fs.ErrPermission` →
   "PermissionError", other `*exec.Error`/`*fs.PathError` → "OSError"; a recovered panic →
   "RuntimeError". These are failure-path messages; the parity harness compares them by rule, not text (§7).
10. **dict ordering** — `_lift_fences` groups languages in first-seen order (code_lane:120-122): use a
    slice of languages beside the map. Evidence insertion order: irrelevant under parsed-JSON parity.
11. **`sorted` / stability** — `_scope_chain` (bridge:226) stable sort of a BFS-ordered list;
    `min(functions, key=span)` (587) and `min(found, key=offset)` (analyze:128) return the first
    minimum in iteration order → Go: linear scan keeping the first; `sorted(grant.tool …)` (1722) and
    `sorted(manifests, key=rel)` (grants:449) byte order = code-point order for valid UTF-8;
    `sorted(set(targets) - scanned)` (1835); `nsmallest` (§4.4).
12. **`%` formatting** — only `%s`/`%d` with str/int operands in this group (`"%04d%s"`, byte counts,
    cap counts); `fmt.Sprintf` is identical. `str(x)[:800]` of a non-string `message` (bridge:1806)
    would render a Python repr (`{'a': 1}`) — treat a non-string `extra.message` as its JSON encoding
    and flag as a known divergence (OpenGrep always emits a string).
13. **Float formatting** — none reaches output; `printable / len(sample) > 0.85` is a comparison only.
14. **`bool()` truthiness of JSON values** — `if source:` (bridge:1789) skips `""`, `0`, `[]`, `{}`,
    `null`, `false`; Go: `truthy(any)` helper. `str(extra.get("message") or …)` same rule.
15. **`type(x) is int`** — §4.6. `isinstance(x, str)` → `string` type assertion.
16. **Identity-keyed caches** — `id(target)` (bridge:142) → target name.
17. **Python integer semantics in `_static_value`** — §4.1.3.
18. **`bytes.find/rfind` with bounds** — `bytes.Index(raw[from:], m) + from`, `bytes.LastIndex(raw[:before], m)`.
19. **Slicing past the end** — clamp explicitly (§2.4 header).
20. **`html.unescape`, `posixpath.normpath`, `ipaddress`** — not used by this group.

---

## 6. Test port plan

Covering pytest files (functions / collected cases; counts from the AST of each file):

| file | functions | cases | scope for this group | fixtures read |
|---|---|---|---|---|
| `tests/test_analyze.py` | 32 | 46 | all | none on disk: bytes built with `zipfile`, `gzip`, `struct`, `zlib` |
| `tests/test_grants.py` | 73 | 154 | all | none |
| `tests/test_supply_chain.py` | 57 | 57 | all | none |
| `tests/test_taint_engine.py` | 5 | 5 | all | none |
| `tests/test_opengrep_bridge.py` | 59 | 89 | all (7 need the live binary) | `rules/opengrep-phase1.yml` |
| `tests/test_opengrep_parity.py` | 15 | 20 | all (14 live) | `tests/opengrep_python_contract.jsonl` (258 records; 135 positive / 123 clean) |
| `tests/test_opengrep_shell_parity.py` | 2 | 2 | all (1 live) | `tests/opengrep_shell_contract.jsonl` (91 records) |
| `tests/test_opengrep_runtime.py` | 14 | 14 | 9 runtime + 5 CLI (core) | none |
| `tests/test_installer_idiom.py` | 3 | 83 | all | none |
| `tests/test_fence_locations.py` | 9 | 25 | all (3 also exercise correlate/sarif, core/output groups) | none |
| `tests/test_coverage.py` | 17 | 19 | 5 (`build_code_lane`, lines 19-95) | none |
| `tests/test_capability.py` | 22 | — | 8 functions / 15 cases that call `findings_from_report`, `check` or the taint wrapper: `test_collects_valid_observations_without_changing_findings` (3), `test_shadowed_requests_is_not_an_observation`, `test_observation_budget_cannot_steal_understatement_budget`, `test_missing_manifest_and_failed_ast_stay_unknown`, `test_collector_reaches_bridge_without_new_engine_run`, `test_native_network_observation_and_denial_only_regression`, `test_optional_validator_failure_preserves_existing_findings`, `test_denial_scope_preserves_validated_observations` (6) | none |
| `tests/test_cli_analyze.py` | 7 | 7 | 1 (`test_cli_analyze_json_reports_finding`, needs the live binary) | none |
| `tests/test_metadata.py:272`, `tests/test_instruction_exfil.py:1740` | 2 | 2 | 1 each | none |

Total to port for this group: **285 test functions / 520 collected cases** (269 functions / 495 cases
in the ten primary files, plus coverage 5/7, capability 8/15, cli_analyze 1/1, metadata 1/1,
instruction_exfil 1/1). 22 of them execute the pinned OpenGrep binary; they skip when
`opengrep.Resolve("")` returns `""` and fail when `CI` is set (mirror `_live_executable`,
`test_opengrep_parity.py:36-45`).

How the Go tests are written:

* **Contract JSONL fixtures** are copied byte-for-byte to `internal/opengrep/testdata/opengrep_python_contract.jsonl`
  and `opengrep_shell_contract.jsonl` and read by table tests; the shape assertions
  (`(258, 135, 123)`, `91`, unique names, ext ⊆ {"", "sh"}) are kept.
* **Inline pytest cases become JSONL tables**, extracted once by `tools/extract_cases.py` (in
  `port-to-go`, run against the Python repo) into `internal/<pkg>/testdata/<test_file>.jsonl`, one
  record per collected case: `{"name", "files": {rel: text-or-base64}, "args": {...}, "expect": ...}`.
  Where a test asserts a property rather than a value (e.g. "no SXV-003"), the extractor records the
  Python oracle's actual output for that case so the Go test asserts equality; the record keeps the
  pytest node id so a diff names the contract. Never Go literals.
* **Binary forensics inputs** (`_ELF`, `_PE`, `_PNG`, `_GIF`, `_JPEG`, generated zips/gzips) are
  emitted by the extractor as `.bin` files under `internal/forensics/testdata/` with a manifest JSONL
  `{name, rel, kind, has_text, raw_file, expect: [finding dicts]}`.
* **Runner injection** replaces `subprocess.run` monkeypatching: `Options.Runner func(ctx, argv, dir,
  env, stderr) (int, error)`; the fake writes the report file named after `--output` and lists the
  targets dir, exactly like `tests/test_taint_engine.py:_runner`.
* **Monkeypatched internals** (`_python_definite_false_positive`, `_subprocess_shell_status`,
  `_network_capability_is_invalid`, `parse_python`) become package-level function variables in
  `internal/opengrep` (`var pythonDefiniteFalsePositive = …`) swapped by tests; `_MAX_REPORT_BYTES`
  and `_MAX_POSTFILTERS_PER_TARGET` are vars for the same reason.
* `make_package` → `t.TempDir()` + `os.WriteFile` per record (bytes written raw, strings as UTF-8
  with newlines preserved), then the core group's `ingest.BuildPackage` + `parse.Parse`.
* testify `require`/`assert`; every table test names the case in `t.Run`.

---

## 7. Parity hooks

`skill-xray --json` (`cli.py:272-278`) fields this group influences:

* `findings[]` with `vector` ∈ {SXV-003, 004, 016, 017, 035, 036, 037} (direct) and every OpenGrep
  vector {SXV-005, 008, 009, 010, 018, 019, 020, 021, 022, 023, 024, 025, 026, 032, 033, 039, 040};
  `rule` ∈ {grant-variable-substitution, grant-over-broad, unpinned-dependency, install-from-url,
  committed-credential, magic-mismatch, polyglot, unreferenced-bytes, analyzer-error,
  permission-understatement, opengrep-* (the 17 slugs from the rule metadata), analysis-incomplete
  (reasons `unsupported_language`, `dynamic-subprocess-kwargs`, `capability-declaration-unparsed`,
  `capability-validation-budget`, plus the python-fence message), findings-capped, and the coverage
  slugs opengrep-unverified, opengrep-unavailable, opengrep-rules-unavailable, opengrep-timeout,
  opengrep-execution-error, opengrep-invalid-output, opengrep-output-limit, opengrep-unmapped-target,
  opengrep-unmapped-rule, opengrep-analysis-error, opengrep-analysis-incomplete, opengrep-internal-error}.
* per finding: `severity`, `path`, `line`, `column`, `offset`, `length`, `message`, `evidence.*`
  (keys listed in §2), `title`/`cwe`/`tier` (from the registry, core).
* `analysis.opengrepVersion` (= `opengrep.Version`).
* SARIF (output group): `runs[0].properties.opengrepVersion`; per result `region.startLine/startColumn/
  endColumn` derived from `evidence.start/end` and `location_mapping`; `codeFlows` from
  `evidence.dataflow_trace`; `properties.limitations` containing `location-unvalidated` /
  `trace-unvalidated` (`correlate.py:201`); `properties.coverage` from the gap notes; result
  identity via `evidence.engine_location` (`findings.py:175-189 _engine_occurrence`).
* `Observation` records → `capability.build_triads` → SARIF/JSON triad output (core/output).

Attribution rule for `tools/parity`: a diff whose finding `rule` or `vector` is in the lists above,
or whose `evidence` contains `engine == "opengrep"`, `installer_idiom`, `understated_capability`,
`fenced_example`, `pin_state`, `breadth_class`, `variable_name`, or `detail`, belongs to this group.
Message text is compared exactly except for the exception-name messages in §5.9 (compare by rule).

Oracle inputs: `tests/opengrep_python_contract.jsonl`, `tests/opengrep_shell_contract.jsonl`, the
golden fixtures under `tests/`, and the frozen MaliciousSkillBench split
(`benchmark-reports/frozen-dataset/test_final.jsonl`, 1,384 records with `findings[]` of
`{vector, rule, severity, tier, line}` — enough to attribute a group-level regression by rule).

---

## 8. Risks and open questions (each with the recommendation)

1. **Python parser in Go (highest risk).** Every fence-lifting decision and every taint post-filter
   depends on CPython-exact parsing and positions. Recommendation: build `internal/pyast` first, with
   a parity test that compares `ast.dump(tree, include_attributes=True)` produced once by CPython
   3.13 for (a) the 258 contract programs, (b) every Python snippet in the bridge tests, (c) all `.py`
   files and python fences in the golden corpus, stored as `testdata/pyast/*.dump` fixtures; ship the
   scanner without the post-filters only if the parser slips, never with a different parser.
2. **CPython nesting limits** (§4.1). Recommendation: constants 100/200 plus a 1,000-frame recursion
   ceiling; document as `// ponytail:`; the corpus pins `bomb.py`/`deep.py`.
3. **`inspect.Signature.bind` and the constant evaluator** are re-implementations of Python
   semantics (§4.1.3-4.1.4). Recommendation: unit-test them from a JSONL table generated by running
   the Python functions over the argument shapes in the bridge tests; treat every TypeError path as
   UNKNOWN/"skip call" exactly as the Python `except` clauses do.
4. **OpenGrep pin and Windows.** The Python pins v1.29.0 with SHA-256 per platform and needs the
   Windows launcher quirks (`USERPROFILE` inherited, `SEMGREP_LOG_FILE`, `SEMGREP_VERSION_CACHE_PATH`).
   mcp-xray pins v1.22.0 next to the binary with no PATH fallback. Recommendation: keep the Python
   contract (cache dir, env override, PATH fallback, hash verification) because the tests and the
   frozen contracts were produced with 1.29.0; do not adopt mcp-xray's `bin/` layout.
5. **Go toolchain.** `port-to-go/go.mod` says `go 1.26.0` while the machine has 1.24.1 and mcp-xray
   says 1.25.5; nothing in this group needs anything past 1.22 (`min`/`max` builtins, `slices`).
   Recommendation (for core): pin `go 1.24` in go.mod so the local toolchain builds without
   `GOTOOLCHAIN` downloads; raise only if another group needs a newer stdlib.
6. **Dependencies already in go.mod that this group does not need**: `regexp2` (this group: zero
   patterns), `go-pep440-version`, `BurntSushi/toml`, `goldmark`, `mvdan.cc/sh`, `go-sarif`,
   `jsonschema` (other groups). This group adds **no** new module; `golang.org/x/text/unicode/norm` is
   already present via `golang.org/x/text`.
7. **Evidence JSON key order.** Python preserves insertion order; Go maps sort. Recommendation: the
   parity harness compares parsed JSON; if byte-identical output is ever required, core switches
   `Evidence` to an ordered structure — not a concern of this group.
8. **Exception type names in messages** (§5.9). Recommendation: the mapping given there, and
   parity-by-rule for those five rules.
9. **`_python_is_module` size gate counts code points; OpenGrep `--max-target-bytes` counts bytes.**
   Both are reproduced as-is (no divergence); noted so nobody "fixes" one.
10. **Digest cache identity** uses `st_ctime_ns`, `st_ino`, `st_dev` (runtime:122-128), not portable
    in Go without `syscall`. Recommendation: key on `(abs path, size, mtime)`; the only test pins "one
    digest for two verifications of an unchanged file".
11. **Live OpenGrep tests on this machine**: the Windows asset (53,536,256 bytes) must be present in
    `%LOCALAPPDATA%\skill-xray\opengrep\1.29.0\opengrep.exe` or `SKILL_XRAY_OPENGREP_BIN` for the 22
    live tests; the Python contract shows 12 expected `dynamic-subprocess-kwargs` gaps that the Go
    static evaluator must reproduce exactly (`test_live_opengrep_matches_frozen_python_contract`).
12. **Cross-group contract on `Text` validity** (§5.5) and on the IR field names (§1.2) must be
    settled before this group's code is written; both are listed under cross-group needs.

## Wave 9 errata (2026-09-20, oracle `9b7960f`)

1. **JavaScript and TypeScript files are code units.** `_SCRIPT_KINDS` gained `script_javascript` and
   `script_typescript`; `_shell_dialect` returns None for them as for python. `_LANGUAGE_KIND` in the bridge maps
   `javascript -> (script_javascript, .js)` and `typescript -> (script_typescript, .ts)`; `run_opengrep` passes
   `--lang` for all four languages. Fences of these languages are still not lifted. Go: `codelane.scriptKinds`,
   `opengrep.suffixes`, `o.Languages`. `_KEEP_SUFFIX`: a file unit with one of the extensions `.js .mjs .cjs
   .jsx .ts .mts .cts .tsx` keeps it as the engine suffix (Go: `opengrep.keepSuffix` in `Select`).
2. **Antipattern fences (reverted).** Excluding fences near an antipattern label from the code lane was
   built and reverted in review: a planted `# never run this` above a live exfil fence hid its sinks
   from OpenGrep. `build_code_lane` lifts every fence as before; the instruction lane's own
   `_ANTIPATTERN_RE` (SXV-011) is the original six-phrase list. Follow-up design: a `documented` flag on
   the unit that demotes instead of dropping.
3. **Ten JavaScript rules** joined `opengrep-phase1.yml` (73 rules; digest `f39f777a...` with the sinks bound
   to `child_process` through anchored rule blocks, whatever the import form): slugs
   `opengrep-js-remote-execution` (SXV-018), `opengrep-js-command-injection` (SXV-008), `opengrep-reverse-shell`
   (SXV-040), `opengrep-credential-read` (SXV-023), `opengrep-environment-harvest` (SXV-026),
   `opengrep-js-decode-exec` (SXV-019), `opengrep-cloud-metadata` (SXV-021), `opengrep-js-fetch-pipe-exec`
   (SXV-009) and two `permission-understatement` capability observations (SXV-033). The rule-count pin moved
   from 63 to 73.
4. **SXV-017 fixtures under the package's own tests are medium.** `_TEST_PATH_RE` =
   `(?:^|/)(?:tests?|__tests__|spec)/` on `p.rel` (case-insensitive) and `_fixture_call(line, col)`: with
   string literals and comments blanked (`_NOT_CODE_RE`), the innermost `(` still open at the token's
   column is preceded by a callee matching `_FIXTURE_CALLEE_RE` (`assert`, `assert.x`, `expect`, `redact*`,
   `sanitiz*`, `mask*`, `scrub*`). A high hit that satisfies both is emitted as medium with evidence
   `test_fixture: True`; `fenced_example` keeps the pre-demotion value. `_scan_secrets` yields the match
   column for this and the `nsmallest` cap sorts by the reported severity. The path alone is not enough (a
   token a script under `tests/` sends somewhere stays high). Go: `supplychain.testPathRE`, `notCodeRE`,
   `fixtureCalleeRE`, `fixtureCall`.
5. **Registry moves.** SXV-031 tier T2; SXV-032 rules high; the base64 decode flag in the shell rule is `(?i)`.
6. **Own install path (SXV-032 severity).** `own_install_path(command_text, manifest)`: with the governing
   manifest's `name` (a non-empty string), every agent-config path on the matched line must be
   `.(claude|gemini|cursor|codeium|continue)/(plugins/)?(skills|marketplaces)/<name>/...` (the tail stops
   at whitespace, quotes, `<>|;&()` and `${}%`) with no `/..` in it and nothing dynamic right after it
   (`[${}%]|["']?\s*[+.,]`: a variable, template or format hole, or a string joined on): the own paths are
   removed and the remainder must not match `_AGENT_CONFIG_PATH_RE` (the SXV-032 rules' roots). The bridge
   then demotes `opengrep-agent-config-read` from high to medium, adds evidence `own_install_path: true`
   and uses the message "The script reads its own install directory under an agent's configuration
   root.", next to the installer-idiom gate. Go: `codelane.OwnInstallPath`, `agentConfigPathRE`,
   `dynamicTailRE`, `bridge.go`; pins `test_own_install_path_names_this_skill_under_a_skills_root`
   (unit) and `test_real_opengrep_reports_own_install_path_read_at_medium` (live), mirrored in
   `owninstall_test.go` and `live_test.go`.
