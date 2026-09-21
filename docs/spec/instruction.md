# Porting specification: group `instruction`

> **Errata (00-overview).** Read this spec with these substitutions; `00-overview.md` is binding.
> - `parse.Artifact.Text *string` (nil == None) replaces `Text string; HasText bool`; `parse.Grant.Pattern
>   *string` replaces `Pattern string; HasPattern bool`; `findings.Finding.Line/Column` are `*int`
>   (`findings.Int(n)`), never 0-sentinels.
> - Frontmatter keys are strings at every depth (`parse._plain` applies `str(k)` recursively), so
>   `hooks: {SessionStart: [], 7: []}` reaches `_hook_findings` as the key `"7"`, which is an unknown event
>   and therefore `malformed_hook_entry`. `map[string]any` is the only mapping type; the `not isinstance(event,
>   str)` branch is dead in Go as in Python. §1.3 and R8 are corrected accordingly.
> - `internal/pyshlex` is `pytext.ShlexTokens(s, punctuation string, whitespaceSplit bool)` and
>   `pytext.ShlexSplit(s)`; `pyIsSpace`/`pyStrip`/`pySplitlines`/`pyRepr` are `pytext.IsSpace/Strip/SplitLines/
>   Repr`. `internal/pep508` is canonical: `pep508.Parse(s) (Requirement, error)` with
>   `Requirement{Name, URL string; Specifiers []Specifier{Op, Version string}}`.
> - `checks.RunChecks` is `checks.Run`; `codelane.DropHostRE.MatchString(host)` (an exported `*regexp.Regexp`) comes from the code spec;
>   `findings.CapFindings` is canonical. The test helper is `testutil.MakePackage(t, map[string]string) string`
>   followed by `parse.Parse(ingest.BuildPackage(root))`.
> - `FlattenProse`/`SourcePosition` are also consumed by `internal/obfuscation` (00-overview D13).
> - Toolchain: `go 1.26.0` (R15 superseded; the machine's `GOTOOLCHAIN=auto` already holds go1.26.0).

Modules: `src/skill_xray/checks/instruction_exfil.py` (1,900 lines, SXV-027/028/029/030/031/011/041/042/043),
`src/skill_xray/checks/persistence.py` (217 lines, SXV-005), `src/skill_xray/checks/hooks.py` (588 lines,
SXV-006/012/013). 2,705 Python lines, 75 functions, 154 regex patterns (119 + 17 + 18), 20 of which use
lookaround or a backreference; 3 go through `dlclark/regexp2`, the rest are RE2 plus a few lines of Go.

Go package: **one package `internal/instruction`**, three files mirroring the Python modules (`exfil.go`,
`persistence.go`, `hooks.go`) plus `text.go` for the shared Python-string helpers listed in §5. One package,
not three: the modules share the lane-kind set, the same IR reads and the same helpers, and nothing outside
the group imports the internals. Decisions between two Go options are marked **Decision:** with the reason.

Conventions in force: all three checks read the IR only (never the filesystem, never re-parse), every
finding carries the exact message text quoted below, and every offset that reaches output is a 1-based
**code-point** column (see §5.1, the single largest parity trap in this group).

---

## 1. Public surface

### 1.1 What other modules import from this group

| Python import | Importer | Go replacement |
|---|---|---|
| `instruction_exfil.check(parsed)` | `checks/__init__.py` (`_CHECKS` slot 5), `tests/test_instruction_exfil.py`, `tests/test_llm_review_core.py` | `instruction.CheckExfil(pkg *parse.Package) []findings.Finding` |
| `persistence.check(parsed)` | `checks/__init__.py` (slot 8) | `instruction.CheckPersistence(pkg) []findings.Finding` |
| `hooks.check(parsed)` | `checks/__init__.py` (slot 4) | `instruction.CheckHooks(pkg) []findings.Finding` |
| `instruction_exfil._flatten_prose(text, start_line)` | `llm/judge.py` (`_exact_quote`, `_context`) | `instruction.FlattenProse(text string) string` (the `start_line` parameter is `del`eted in Python; drop it) |
| `instruction_exfil._source_position(text, start_line, pos)` | `llm/judge.py` | `instruction.SourcePosition(text string, startLine, posRunes int) (line, col int)` |
| `instruction_exfil._directive_findings(art)` | `tests/test_sarif_release.py` (fixture `directive`, column test at lines 138-149) | unexported `directiveFindings`; the Go SARIF tests call `CheckExfil` and pick the SXV-028 finding (same result: one finding on a one-line SKILL.md) |
| `instruction_exfil._NONHTTP_EGRESS_RE`, `_prose_blocks`, `_html_comments` | `tests/test_instruction_exfil.py` (linearity/memory tests) | unexported; same-package Go tests |
| monkeypatch of `instruction_exfil._directive_findings` | `tests/test_instruction_exfil.py::test_engine_crash_does_not_disable_the_credential_engine` | package-level `var exfilEngines = []func(*parse.Artifact, map[string]*parse.Artifact) []findings.Finding`; the test swaps one entry |

Registration order in core's `RunChecks` must keep the Python `_CHECKS` order (`analyze, coverage, grants,
hooks, instruction_exfil, metadata, obfuscation, persistence, preproc, supply_chain, taint_engine`); the
final `dedupe_findings` sort makes order invisible in output, but `check-error` attribution and the
engine-isolation contract are per slot.

### 1.2 What this group imports (cross-group contract)

| Python | Used for | Go (owned by) |
|---|---|---|
| `findings.Finding` | every finding | `findings.Finding` (core) |
| `findings.cap_findings` | persistence + hooks return value (dedupe → sort → cap 25 per (path, vector-or-rule)) | `findings.CapFindings` (core) |
| `ingest.IDENTITY_FILES` | `_IDENTITY_TARGET` alternation | `ingest.IdentityFiles` (core) |
| `checks.code_lane.installer_idiom(command_text) -> bool` | SXV-041 severity demotion | `codelane.InstallerIdiom(string) bool` (code) |
| `checks.code_lane._DROP_HOST_RE` | SXV-043 telemetry excuse (`.search(host)`) | `codelane.DropHostRE.MatchString(host string) bool` (code) |

### 1.3 IR shapes this group reads (owned by parse/core; field names are the requirement, not the naming)

```go
type Package struct {                 // parse.ParsedPackage
    Artifacts []*Artifact             // ingest walk order; iteration order of every check
    ByRel     map[string]*Artifact
    Refs      []Ref                   // {"from","to","line"} dicts
}
type Ref struct{ From, To string; Line int }

type Artifact struct {                // parse.ParsedArtifact
    Rel, Kind string
    Text      *string                 // nil == Python None; "" is a read empty file (exfil: `p.text is None`;
                                      // persistence: `not artifact.text`; hooks `_local_candidate`: `text is not None`)
    Markdown  *Markdown               // nil when Python .markdown is None (plain .txt lifted docs)
    Frontmatter map[string]any        // nil when None; values plain; keys are str(k) at every depth (parse._plain), so
                                      // map[string]any is the only mapping type hooks will see (00-overview D14)
    FrontmatterKeyLines map[string]int
    FrontmatterEndLine  int           // 0 when None (1-based line of the closing ---)
    Grants    []Grant                 // nil when None
    Config    any                     // decoded JSON/TOML/YAML config; nil when None
    ManifestKind string               // "mcp_servers" | "hooks" | ... | ""
}
type Markdown struct {
    Links             []Link          // (href, label, line)  -- markdown-it links AND presentational <a href>
    FenceSpans        []Span          // ``` / ~~~ fences only, 1-based inclusive line ranges
    CodeSpans         []Span          // fences + indented code blocks
    ProseSpans        []Span          // inline tokens WITHOUT html_inline children (paragraphs, list items,
                                      // headings, table cells); 1-based inclusive
    HTMLComments      []HTMLComment   // (body, line, column) from inspectable HTML blocks/inline
    HTMLProse         []HTMLProse     // (projected text, line): presentational HTML rendered to prose,
                                      // source width preserved, <code>/<pre> content blanked
    HTMLUninspectable []HTMLFragment  // (raw fragment, line, column) for behaviour-bearing HTML
}
type Span struct{ Start, End int }
type Link struct{ Href, Label string; Line int }
type HTMLComment struct{ Body string; Line, Column int }
type HTMLProse struct{ Text string; Line int }
type HTMLFragment struct{ Text string; Line, Column int }

type Grant struct {                   // parse.Grant
    Tool    string
    Pattern *string                   // nil == None; None vs "" matters in _reaches_network
    Raw     string
    Allowed, Broad, Parsed bool
}
```

`findings.Finding` (core) must carry: `Vector, Rule, Severity, Path, Message string; Line, Column *int`
(nil = absent; every line/column this group emits is ≥ 1, wrapped with `findings.Int`), `Evidence map[string]any` (nil/empty = omitted
from JSON). This group never sets `offset`/`length`.

### 1.4 Findings emitted (exact JSON shapes)

Common keys: `vector`, `rule`, `severity`, `path`, `message`, then `line`/`column` when set, then
`evidence` when non-empty; `title`/`cwe`/`tier` are added by the registry (core). `%d` is an int, `%s` a
string unless noted. `[:n]` is a code-point slice.

| vector / rule | severity | line | column | evidence keys (type) | message format |
|---|---|---|---|---|---|
| SXV-027 `hidden-html-comment` | high | comment line | yes | `comment_body` (body[:400]), `line` (int), `column` (int), `selector` (`"hidden-comment:" + sha256(body)[:12]`), `snippet` (one_line[:200]) | `an HTML comment in this instruction file carries a directive to the agent: "%s". A markdown renderer hides it, so a human reviewer sees a clean page while the model still reads it` % one_line[:160] |
| SXV-028 `instruction-override` / SXV-029 `anti-refusal` / SXV-030 `memory-persistence` / SXV-031 `behavior-manipulation` | high / medium / medium / medium | source line | yes | `directive_text` (matched), `rule` (tag), `line`, `col` (ints), `selector` (`tag + ":" + matched.lower()[:50]`), `snippet` (raw[:200]) | `instruction-file directive (%s): "%s". This addresses the model's own behaviour rather than the task` % (tag, matched[:100]) |
| SXV-011 `cred-egress` | critical if proven reach else high | first cred hit line | **no** | `credential_tokens` (list of `{kind, line, text}`), `egress_target` (str), `egress_line` (int), `egress_method` (`"post"`/`"get"`/`"non-http"`), `polarity` (`"positive"`), `reaching_grant` (str), `dotenv_corroboration` (bool), `line`, `col` (ints), `selector` (`"cred-egress:" + "|".join(sorted kinds)`), `snippet` (raw line `.strip()`, untruncated) | `instruction lane directs the agent to read %d credential artifact reference(s) (%s) and send them to %s via %s; positive imperative polarity and %s` % (len(hits), ", ".join(kinds), url, method.upper(), tail) where tail = `the declared grant %s can reach the network` % reaching (proven) or `network reach unproven (fail-open on unrecognized grant %s)` % reaching |
| SXV-041 `remote-instruction-load` | medium if installer idiom else high | n | **no** | `directive_text` (matched), `remote_source` (src), `line` (n), `col` (int, in URL-stripped line), `selector` (`"remote-instruction-load:" + sha256(matched.lower())[:12]`), `snippet` (raw.strip()[:200]), optional `installer_idiom` = `"https-named-installer"` | `instruction lane tells the agent to fetch remote content and follow it as instructions: "%s" (source: %s). The scanner sees the pointer, not the payload -- the real directives load at runtime from a location a reviewer never sees, and the remote side can change after this scan (progressive disclosure)` % (matched[:100], src[:120]) |
| SXV-042 `covert-bundled-script-run` / `coerced-bundled-preflight` | high if strong else medium | artifact line | yes | `directive_text` (≤200), `script`, `cue` (cue[:80]), `cues` (sorted lowercase coercion cues [:6], list of str), `line`, `col`, `selector` (**see quirk §5.7**: `rule + ":" + repr of the tuple (script.lower(), strong)`), `snippet` (raw[:200]) | `` The instructions tell the agent to run the shipped artifact `%s` %s -- a launcher for code that is not reviewed here%s. `` % (script[:80], why, "" if strong else " (single coercion cue: reported, not a verdict)"); why ∈ {`regardless of the request`, `hidden from the user`, `as a forced precondition of every task`} |
| SXV-043 `data-exfil-directive` | high | sentence line | yes | `directive_text` (sentence.strip()[:200]), `recipient` (addr[:120]), `acquisition` (acquired text .strip()[:80] or `"first-person object"`), `shape` (`"delivery"`, `"recipient-first delivery"`, `"recipient parameter"`, `"passive delivery"`), `line`, `col`, `selector` (`"data-exfil-directive:" + digest[:12]`), `snippet` (raw[max(0,s_start-40):s_start+len(sentence)][:200]) | `` The instructions tell the agent to obtain the user's data and send it to a recipient written into the skill (`%s`) -- a data-exfiltration directive, not a task the user asked for. `` % addr[:80] |
| SXV-005 `identity-persistence-write` | critical | target line | yes | `identity_target`, `persisted_content` (content[:400]), `content_length` (int, code points), `content_sha256` (hex), `truncated` (bool), `write_verb` | `` instructs the agent to persist concealed or priority instructions in `%s` `` % target |
| SXV-006 `startup-hook-install` | critical | event line | yes | `hook_event` (canonical), `settings_target`, `write_verb`, `snippet` | `instructs installation of a %s startup hook into %s` |
| SXV-012 `root-hook-autoexec` | medium | `source_line` (config: 1; frontmatter: key line of `hooks`, default 1) | no | `hook_event`, `matcher`, `command`, `hook_type` (`http`/`mcp_tool`/`prompt`/`agent`/`command`), `resolution` | http: `%s hook auto-executes a remote HTTP handler (%s)`; mcp_tool: `%s hook auto-executes connected MCP tool %s`; prompt/agent: `%s hook auto-executes a dynamic %s handler (%s)` % (event, hook_type, prompt); command: `%s hook auto-executes an unreviewable command (%s): %s` % (event, resolution, command) |
| SXV-013 `floating-mcp-package` | low | 1 | no | `server_name`, `command` (raw, unstripped), `specifier`, `pin_state` = `"floating_or_unpinned"`, `args` (original list of str) | `auto-start server %s resolves floating package %s` |
| `""` / `analysis-incomplete` (hooks) | high | none | no | `{"phase": "check", "reason": reason}`; reason ∈ {`hooks_not_object`, `malformed_hook_entry`, `malformed_mcp_server`} | `hook/MCP configuration analysis is incomplete (%s).` |
| `""` / `findings-capped` (exfil own cap) | low | none | no | none | `%d more %s findings in %s were suppressed (cap %d per file)` % (suppressed, group, path, 25) |
| `""` / `check-error` (exfil engine isolation) | high | none | no | none | `instruction_exfil skipped %s: %s` % (rel, exception type name) — Go uses `fmt.Sprintf("%T", recovered)`; never produced on the oracle corpus |

`findings-capped` notes from persistence/hooks are produced by the shared `CapFindings` (core) with the same
text.

---

## 2. Behaviour inventory

Line numbers cite the Python source. "Tests" cite `tests/<file>::<test>`. `raws` always means
`art.Text` split on `"\n"` only (the IR text is already CR-normalised by parse: `_norm_newlines`, parse.py:717).

### 2.1 `instruction_exfil.py`

**Constants.** `_LANE_KINDS = {skill_manifest, instruction, agent_identity}`; `_LIFTABLE_KINDS = {doc, other}`;
`_FINDING_CAP = 25`; `_DEFENSIVE_WINDOW = 2`; `_LINK_WINDOW = 10`; `_RI_WINDOW = 2`; `_RI_WRAP_MAX = 8`;
`_EXFIL_WINDOW = 4000` (code points). Tool sets: `_BASH_TOOLS = {Bash, Shell, Terminal, Execute}`,
`_NETWORK_TOOLS = {WebFetch, WebSearch}`, `_LOCAL_ONLY_TOOLS` (10 names, line 353), `_NETWORK_SINGLE`
(46 commands, line 355), `_LOCAL_ONLY_CMDS` (33 commands, line 362); copy verbatim.

**`check(parsed)` (1874).** Build `manifest_by_dir`: for each artifact of kind `skill_manifest`, in
`parsed.artifacts` order, `setdefault(_dir_of(rel), p)` (first manifest per directory wins). `lifted =
_lifted_targets(parsed)`. For each artifact in order: skip if `text is None` or (kind ∉ lane and rel ∉ lifted).
Run the six engines in this order: `_hidden_comment_findings, _directive_findings, _remote_instr_findings,
_covert_script_findings, _data_exfil_findings, _exfil_findings(a, manifest_by_dir)`, each under its own
try/except: on any exception append `check-error` (see §1.4) and continue. Return `_cap_findings(out)`.
Tests: `test_engine_crash_does_not_disable_the_credential_engine` (SXV-011 survives a crashing engine and a
high `check-error` is present), `test_a_comment_in_a_readme_does_not_fire` (README is kind `doc`, not in
lane, `f == []`), `test_instruction_file_is_in_lane` (guide.md kind `instruction`),
`test_agent_identity_file_is_in_the_lane` (CLAUDE.md), `test_deterministic`.

**`_lifted_targets(parsed)` (1824).** BFS/DFS from lane-kind roots over `parsed.refs` (`from`→`to`
adjacency, insertion order irrelevant); a target joins `lifted` only if its kind ∈ `_LIFTABLE_KINDS`; `queue.pop()`
is LIFO but the result is a set. Tests: `test_rob2_payload_in_referenced_doc_is_scanned`,
`test_rob2_unreferenced_doc_stays_out_of_lane`, `test_reference_lift_follows_transitive_prose_references`
(SKILL.md → README.md → B.txt), `test_referenced_script_is_not_lifted_into_the_lane` (setup.py kind
`script_python` is not lifted; notes.md is).

**`_cap_findings(findings)` (1857) / `_cap_note` (1850).** Count by key `(path, vector or rule)` in
insertion order, keep the first 25 per key, append one note per over-cap key **in first-insertion order of
keys**. Note that each engine already caps itself at 25 per vector and emits its own note, so this second
pass only re-caps pathological cases (e.g. > 25 `findings-capped` notes). Port literally.

**`_html_comments(text)` (53).** Forward scan: `find("<!--", cursor)`; `find("-->", start+4)`; unterminated
→ yield `(start, text[start+4:])` and stop; else yield `(start, text[start+4:end])`, `cursor = end+3`.
Linear. Test: `test_unclosed_html_comment_scan_is_linear` (1 MiB of `<!-- unclosed ` yields exactly one
comment at offset 0 in < 1 s), `test_sxv027_unterminated_html_comment_fires`.

**`_comment_is_directive(body)` (91).** `EXEC or STRONG or (ADDRESSEE and ACTION)`. Tests:
`test_directive_in_a_comment_fires`, `test_a_developer_todo_does_not_fire`,
`test_an_editorial_marker_does_not_fire`, `test_editorial_marker_does_not_suppress_a_real_directive`,
`test_sxv027_curl_bash_comment_fires`, `test_sxv027_benign_authoring_comments_do_not_fire` (4 bodies),
`test_sxv027_developer_todo_comment_does_not_fire` (contains "assistant" inside `MCP/assistant` → the
`(?<![/\w-])` lookbehind rejects it), `test_sxv027_hyphenated_agent_compound_is_not_an_addressee`
(`user-agent`), `test_bare_tool_or_url_comment_is_not_a_directive`, `test_benign_html_comment_does_not_fire`.

**`_hidden_comment_findings(art)` (673), SXV-027.** If `art.markdown is None`: `fragments = [(art.text, 1, 1)]`,
`comments = []`; else `fragments = markdown.html_uninspectable`, `comments = list(markdown.html_comments)`.
For each fragment `(fragment, base_line, base_column)` and each `(start, raw_body)` from `_html_comments`:
`preceding = fragment[:start]`, `relative_line = preceding.count("\n")`, `last_break = preceding.rfind("\n")`,
`column = base_column + start` if `relative_line == 0` else `start - last_break` (all code-point offsets);
append `(raw_body, base_line + relative_line, column)`. Then iterate `sorted(set(comments), key=(line, column))`
(dedupe identical triples; ties on (line, column) with different bodies cannot occur); `body = raw_body.strip()`;
skip empty or non-directive; `total += 1`; skip when `total > 25`; `one_line = body.replace("\n", " ")`;
emit (§1.4). After the loop, if `total > 25` append `_cap_note(rel, "SXV-027", total-25)`.
Ordering guarantee: output sorted by (line, column). Tests:
`test_instruction_findings_are_capped_before_output_growth` (60 comments → 25 hits + one note starting
`"35 more SXV-027 findings"`, every message < 600 chars), `test_fenced_comment_examples_cannot_crowd_real_hidden_comment_out_of_cap`
(comments inside a fence are not in `html_uninspectable`/`html_comments`), `test_identical_hidden_comments_on_one_line_keep_distinct_columns`
(columns `[1, len(comment)+2]`), `test_sxv027_ignores_html_comment_inside_a_fenced_example`,
`test_sxv027_ignores_html_comment_inside_inline_code`, `test_sxv041_comment_hidden_remote_follow_fires`
(the same comment also feeds SXV-041 through raws).

**`_flatten_prose(text, start_line)` (714).** `re.sub(r"[ \t]*\n[ \t]*", " ", text).strip()`; `.strip()` is
Python Unicode whitespace (§5.2). Exported for the judge. Test:
`test_instruction_softbreak_flattening_has_bounded_memory` (200k-line block flattens to `"x x x…"`).

**`_source_position(text, start_line, pos)` (720).** Walk the block line by line: `left = len(source) -
len(source.lstrip())`, `content_len = len(source.strip())`; if `content_len and pos < flat_start + content_len`
return `(line, left + pos - flat_start + 1)`; if `content_len`: `flat_start += content_len + 1`; at the last
line return `(line, max(1, len(source) + 1))`. All lengths are code points. Note the deliberate asymmetry
with `_flatten_prose` on blank interior lines (frontmatter blocks can contain them): port literally.
Tests: `test_multiline_directive_across_commonmark_softbreak_fires` (`"Please ignore all\nprevious…"` →
line 4, col 8), `test_directive_columns_preserve_markdown_markers` (`- `, `> `, `## ` → col = len(prefix)+1),
`test_sarif_release.py:138-149` (column == `evidence["col"]` == SARIF startColumn == len(prefix)+1),
`test_llm_review_core.py::test_native_review_uses_parser_lines_and_exact_quotes` (252 params: `\u2028`,
`\u2029`, `\x85`, `\v`, `\f` inside a line are NOT line breaks; `\r\n`/`\r` are normalised by parse).

**`_source_span_blocks(text, spans)` (742).** Single pass over `text` yielding `(block_text, start)` for
ordered 1-based inclusive spans; the block excludes the trailing `"\n"`; a span past EOF yields what exists.

**`_plain_prose_blocks(text)` (762).** Blank-line-delimited blocks for artifacts without markdown (`.txt`
lifted docs); "blank" is `source.strip() == ""` (Unicode whitespace).

**`_prose_blocks(art)` (782).** If `art.markdown.prose_spans` exists: `wanted = [(2, fm_end-1)]` when
`frontmatter_end_line > 2` (the YAML body IS scanned as prose), then all `prose_spans`; blocks from
`_source_span_blocks(art.text, wanted)` plus `markdown.html_prose` tuples; **stable** sort by start line
(frontmatter first, then spans, then html_prose on ties). Else `_plain_prose_blocks`. Tests:
`test_presentational_html_cannot_split_instruction_override` (`<p>Ignore <span>all</span>…</p>` arrives as
html_prose), `test_html_entity_cannot_split_instruction_override`, `test_semicolonless_numeric_html_entity_…`,
`test_html_directive_uses_document_source_order` (an html_prose block before a "For example" paragraph must
be visited first so `previous` is empty), `test_html_code_examples_do_not_trigger_instruction_override`
(`<pre>`/`<code>` content is blanked by parse), `test_self_closing_html_code_tag_cannot_hide_directive`,
`test_directives_use_commonmark_code_spans` (indented code and an unclosed ```` ```` ```` fence are code, not
prose), `test_directive_after_indented_code_block_fires`, `test_sxv042_bare_silently_is_not_a_covert_run`
(second case: `description: a system that silently…` is frontmatter prose).

**`_is_defensive_frame(text)` (206).** `m = _DEFENSIVE_RE.search(text or "")`; `frame = text[m.start():]`;
true iff `m` and `_DEFENSIVE_DETAIL_RE.search(frame)`. Tests: `test_a_defensive_description_is_suppressed_not_reported`,
`test_multiline_security_doc_does_not_fire`, `test_sxv028_defensive_scanner_description_is_suppressed`,
`test_mitigate_description_is_suppressed`, `test_sxv028_bare_defensive_prefix_no_longer_disarms` (a bare
"flag:"/"To detect abuse," does not suppress), `test_bare_defensive_prefixes_do_not_mute_live_attacks`,
`test_explicit_defensive_that_clause_stays_silent`, `test_override_with_incidental_defensive_word_still_fires`.

**`_negated_run_of(raw, m)` (236).** `clause = last piece of sentenceSplit(raw[max(0, m.start()-160):m.end()])`;
true if `_NEGATED_OVERRIDE_RE.search(clause)` or the dynamic pattern `_NEG_RUN_PREFIX + re.escape(m.group(0).strip())`
matches `clause` case-insensitively (regexp2, §3). Tests: `test_sxv042_never_skip_a_script_is_the_coercion_not_a_defence`,
`test_sxv042_negation_must_target_this_artifact_in_its_own_sentence` (4 cases),
`test_sxv042_task_prohibition_is_the_coercion_and_step_ordinals_count`.

**`_directive_findings(art)` (799), SXV-028..031.** For each `(prose, start_line)` block: `raw = flatten`;
skip empty; `intro_prev = EXAMPLE_INTRO.search(previous)` (previous = last non-empty block's raw, headings
included). For each rule `(vid, tag, sev, rx)` in order and each `m in rx.finditer(raw)`:
`key = (vid, m.group(0).strip().lower())`; skip if in `seen`; `before = raw[:m.start()]`; skip if
`EXAMPLE_INTRO.search(before) or intro_prev or _is_defensive_frame(before)`; SXV-028 only: skip if
`_PARAM_DEF_RE.search(before) and not _SCOPED_DIRECTIVE_RE.search(m.group(0))`; SXV-028 only: skip if
`_NOUN_PHRASE_INTRO_RE.search(before) and re.match("(?:ignore|forget|override|disregard)\b", m.group(0), I)`;
`context = raw[max(0, m.start()-48):m.end()]`; skip if `_NEGATED_ATTACK_ACTION_RE.search(context)`; SXV-029
only: skip if `_ANTIREFUSAL_BENIGN_RE.search(raw)`; **then** `seen.add(key)` (only emitted directives consume
the dedup slot); `totals[vid] += 1`; skip if `> 25`; `(line, col) = _source_position(prose, start_line, m.start())`;
emit. After all blocks: for `vector, total in totals.items()` (insertion order) if `> 25` append a cap note.
Tests (all in test_instruction_exfil.py): positives `test_ignore_previous_instructions_fires`,
`test_jailbreak_mode_fires`, `test_never_refuse_fires`, `test_no_disclaimers_fires`,
`test_agent_action_without_warning_still_fires`, `test_persist_across_all_sessions_fires`,
`test_persist_this_in_your_memory_fires`, `test_hard_covert_steering_fires`, `test_secretly_influence_fires`,
`test_manipulate_the_user_fires`, `test_override_with_every_filler_fires`, `test_override_wrapped_in_benign_pretext_fires`,
`test_trailing_for_example_does_not_suppress`, `test_cross_session_memory_persistence_fires`,
`test_sxv028_override_persona_and_system_prompt_fire` (5), `test_sxv029_anti_refusal_breadth_fires` (4),
`test_appending_content_filter_no_longer_disarms_a_directive`, `test_sxv030_permanence_and_verb_breadth_fire` (5),
`test_sxv031_manipulation_evasions_fire` (2), `test_sxv028_in_the_wild_vocabulary_fires` (4),
`test_sxv028_developer_mode_restriction_phrasings` (3, severity `["high"]`),
`test_sxv028_role_label_code_span_is_not_option_docs`, `test_param_def_guard_is_scoped_to_sxv028`
(SXV-029 `["medium"]` despite a code-span prefix), `test_sxv030_agent_memory_objects_fire_and_product_copy_does_not`,
`test_sxv030_keep_retain_persist_need_an_agent_memory_object`, `test_sxv030_bare_in_memory_is_data_prose`,
`test_sxv028_flag_list_is_option_docs_and_more_dev_mode_verbs`, `test_sxv028_restriction_phrase_may_precede_developer_mode`,
`test_sxv028_developer_mode_needs_a_model_or_restriction_cue` (5 params), `test_directive_after_quoted_attribute_gt_is_not_hidden`,
`test_directive_findings_are_capped_before_allocation` (60 distinct texts → 25 + `"35 more SXV-028 findings"`),
`test_rob1_blank_padding_is_not_quadratic` (40k blank lines, < 3 s). Negatives:
`test_bare_word_jailbreak_protection_does_not_fire`, `test_a_directive_inside_a_fence_does_not_fire`,
`test_operational_event_without_warning_is_not_anti_refusal`, `test_a_defensive_mention_is_suppressed`,
`test_negated_attack_action_is_not_a_directive` (3), `test_never_refuse_is_not_suppressed_as_defensive`,
`test_a_memory_store_feature_does_not_fire`, `test_persisting_a_session_id_does_not_fire`,
`test_soft_subtly_steer_deferred_to_llm`, `test_gradually_steer_onboarding_is_benign`,
`test_subtly_nudge_onboarding_is_benign`, `test_without_permission_safety_prose_is_benign`,
`test_without_the_user_noticing_lag_is_benign_ux`, `test_ordinary_guidance_does_not_fire`,
`test_save_to_memory_ram_prose_does_not_fire`, `test_config_persistence_across_sessions_is_benign`,
`test_secretly_persuade_surprise_party_is_benign`, `test_quoted_example_introduced_on_prev_line_is_suppressed`,
`test_security_awareness_doc_with_blank_line_framing_is_suppressed`, `test_unobtrusively_steer_deferred_to_llm`,
`test_subtly_guide_attention_is_benign_ux`, `test_gently_guide_setup_is_benign`,
`test_sxv028_029_benign_prose_does_not_fire` (3), `test_sxv030_db_and_ram_prose_do_not_fire` (2),
`test_sxv031_manipulate_the_user_ui_is_not_a_finding` (2), `test_sxv028_ordinary_language_is_not_an_override`
(5 negatives + 4 positives), `test_sxv028_context_and_policy_ui_phrases_do_not_fire` (4),
`test_sxv028_quoted_example_still_suppressed`, `test_sxv029_unquoted_defensive_description_still_suppressed`.

**`_heading_lines(art)` (947).** 1-based line numbers `n` with `n > frontmatter_end_line (or 0)`,
`_HEADING_RE.match(line)` on `text.split("\n")`, and `n` not inside any `fence_spans + code_spans` range.
Test: `test_sxv042_fenced_comment_is_not_a_section_boundary`, `test_sxv042_coercion_cues_under_different_headings_do_not_pair`.

**`_orders_a_shipped_run(text, cue)` (961).** Sentence around the cue: `lo = max(rfind(". ", 0, s),
rfind("! ", 0, s), rfind("? ", 0, s)) + 1` with `s = cue.start()`; `end = sentenceEndAfter(text, cue.end())`;
true if `_BUNDLED_RUN_RE` or `_BUNDLED_PROSE_RE` matches `text[lo:end]`. Test:
`test_sxv042_before_any_cue_needs_its_sentence_to_order_the_shipped_run`.

**`_covert_script_findings(art)` (971), SXV-042.** Group non-empty flattened blocks into sections keyed by
`bisect_right(heading_lines, start_line)`, preserving first-appearance order of keys. Per section: `joined =
concat(raw + " ")`, `offsets` = start of each raw in `joined`; `covert = COVERT_RUN_CUE.search(joined)`;
`coercion = {}` (insertion-ordered): for `cm in COERCED_RUN_CUE.finditer(joined)`: skip when
`cm.group("beforeany") is not None and not _orders_a_shipped_run(joined, cm)`; `coercion.setdefault(cm.group(0).lower(), cm)`.
Then for each block `(prose, start_line, raw), offset`: `intro_prev = SXV042_EXAMPLE_INTRO.search(previous)`;
`previous = raw` (both before any `continue`); skip section blocks when `covert is None and not coercion`;
`strong = covert is not None or len(coercion) >= 2`; if not strong and `COERCED_RUN_CUE.search(raw)` fails →
skip (a lone cue must sit in this block); `cue = covert or min(coercion.values(), key=start)` (first minimum in
insertion order); `artifacts = BUNDLED_RUN.finditer(raw) or (if none) BUNDLED_PROSE.finditer(raw)`. Per artifact
`m`: `script = m.group(0).strip()`; `akey = (script.lower(), strong)`; skip if `akey in seen or (not strong and
(akey[0], True) in seen)`; `first = min(offset + m.start(), cue.start())`; `local` = starts (relative to block)
of `[covert] + coercion.values()` that fall inside this block; `before = raw[:min([m.start()] + local)]`; skip
if `SXV042_EXAMPLE_INTRO.search(before) or intro_prev or _is_defensive_frame(before)`; skip if
`_negated_run_of(raw, m)`; `seen.add(akey)`; `total += 1`; cap 25; rule/why: covert → `covert-bundled-script-run`
with why `regardless of the request` if `_COVERT_OVERRIDE_RE.search(covert.group(0))` else `hidden from the user`;
else `coerced-bundled-preflight` / `as a forced precondition of every task`; `(line, col) = _source_position(prose,
start_line, m.start())`; `directive_text = joined[max(0, first-20) : max(offset+m.end(), cue.end())+20].strip()[:200]`;
`cues = sorted(coercion)[:6]`. One cap note if `total > 25`. Tests: `test_sxv042_covert_bundled_script_run_fires` (5),
`test_sxv042_ordinary_script_usage_does_not_fire` (5), `test_sxv042_later_covert_run_is_not_hidden_by_an_earlier_mention`,
`test_sxv042_coerced_bundled_preflight_is_graded` (2 high, 1 medium), `test_sxv042_coercion_and_artifact_must_share_a_block`,
`test_sxv042_cues_correlate_across_blocks_of_one_section` (high), `test_sxv042_bare_silently_is_not_a_covert_run`,
`test_sxv042_ordinary_ops_prose_is_not_a_covert_run` (3 negatives, 3 high), `test_sxv042_parameter_table_required_is_not_a_coercion_cue`,
`test_sxv042_example_intro_two_paragraphs_earlier_does_not_excuse`, `test_sxv042_directive_prose_with_read_or_below_is_not_an_example`
(3 high, 1 described negative), `test_sxv042_do_not_tell_window_stops_at_a_clause_boundary`,
`test_sxv042_hidden_output_formatting_is_not_a_covert_run` (2 params).

**`_sentences(raw)` (1220).** `[(start, piece)]` for `sentenceSplit(raw)`, `start = raw.find(piece, pos)`
(equals the true position; an empty trailing piece starts at `len(raw)`).

**`_own_sentence(text, match)` (1230).** `pre = text[max(0, s-60):s]`; `cut = max(rfind(". "), rfind("! "),
rfind("? "))` in `pre`; `end = sentenceEndAfter(text, match.end())`; returns `(pre if cut == -1 else pre[cut+2:])
+ text[s : end or len]`.

**`_exfil_recipient(addr)` (1239).** `addr = addr.rstrip(".,;:'\"")`; if `"@" in addr and "://" not in addr`:
`local, host = addr.rsplit("@", 1)`, `placeholder_local = PLACEHOLDER_LOCAL.match(local)`; else `host =
urlsplit(addr).hostname or ""`, `local = ""` (ValueError → None; Go: `hostOf` helper §4.6). `host = host.lower()`;
return None if `not host or "." not in host or re.search(r"[<>{}$\[\]]", host) or PLACEHOLDER_HOST.search(host)`;
else `(addr, host, local.lower(), placeholder_local)`.

**`_exfil_addresses(sentence, pos)` (1259).** Addresses after a connector: first within 60 chars of `pos`,
each next within 40 chars of the previous match end; stop when `_EXFIL_SENDER_MARK_RE` matches the gap since
the last accepted match.

**`_exfil_deliveries(sentence)` (1270).** Yields, in this order: (a) for each `v in EXFIL_VERB.finditer`, for
each connector `c in EXFIL_CONN.finditer(sentence, v.end(), min(len, v.end()+120))`, for each address:
`(v, sentence[v.end():c.start()], "delivery", addr_m)`; (b) `EXFIL_DITRANS` matches: `(m, m.group("gap"),
"recipient-first delivery", m)`; (c) `EXFIL_PARAM_RECIPIENT` matches: `(m, None, "recipient parameter", m)`.
The Go version must yield lazily or materialise in exactly this order (the caller breaks after the first
finding per delivery).

**`_data_exfil_findings(art)` (1284), SXV-043.** State across blocks: `previous`, `prev_tail`, `example_section`.
Per block: `raw`; if `raw.lstrip().startswith("#")`: `example_section = EXFIL_EXAMPLE_HEADING.search(raw)`;
`intro_prev = EXFIL_EXAMPLE_TAIL.search(previous)`; `previous = "" if heading else raw`. `sentences = _sentences(raw)`.
Per `(s_start, sentence)`: `sentence = EXFIL_CODE_SPAN.sub(same-length spaces, sentence)` (length in code
points). Per delivery `(m, gap, shape, addr_m)`: recipient from `addr_m.group("addr")` if the match has that
group else `group(0)`; skip None; `verb = m.group("verb")` if present else `""`; `pre = sentence[max(0, m.start()-80):m.start()]`;
`tail = sentence[addr_m.end():addr_m.end()+80]`. Object resolution when `gap is not None`: gap has OBJECT or
POSSESSIVE → `obj = gap`; elif OBJECT in `verb` → `obj = verb`; elif PASSIVE in `pre` and (OBJECT or POSSESSIVE
in `pre`) → `obj = pre, shape = "passive delivery"`; elif `not gap.strip()` and (OBJECT or POSSESSIVE in `tail`)
→ `obj = tail, shape = "recipient-first delivery"`; else skip. When `gap is None`: `obj = pre`.
`window = (prev_tail + " " + raw[:s_start + m.start()])[-4000:]`; `acquisitions = EXFIL_ACQUIRE.finditer(window)`;
`owned = POSSESSIVE.search(obj) or (\byour\b in obj and SENSITIVE in obj)`; skip if no acquisitions and not owned;
`acquired` = first acquisition whose `_own_sentence(window, a)` has no `EXFIL_NEG_PREFIX`; skip if acquisitions
exist but none survive; skip if `EXFIL_NEG_PREFIX.search(sentence[:m.end()]) or EXFIL_CONTRAST.search(sentence[:m.start()])`;
`third_person = verb.lower().endswith("s") and verb.lower() not in ("cc's", "bcc's") and no \byou\b in sentence[:m.start()]`;
`acq_sentence = window[:acquired.end()].rsplit(". ", 1)[-1] if acquired else sentence`; skip if third_person or
DISCLOSURE in acq_sentence or DISCLOSURE in `sentence[:m.start()]`; `data = window + " " + (gap or "")`; skip if
SERVICE_HOST matches host and no CREDENTIAL in data; `shared = ROLE_LOCAL.match(local) or DEV_HOST.search(host)`;
skip if shared and no SENSITIVE in data; telemetry excuse: skip if TELEMETRY_HOST.match(host) and
(TELEMETRY_DATA in obj or in acq_sentence) and no SENSITIVE and no CREDENTIAL in data and no POSSESSIVE in
sentence and none in acq_sentence and not `codelane.DropHostRE.MatchString(host)`; `soft = placeholder_local or example_section or
API_PREFIX.search(host)`; skip if soft and no CREDENTIAL in data; `before = raw[max(0, s_start+m.start()-4000):s_start+m.start()]`;
skip if `SXV042_EXAMPLE_INTRO.search(sentence[:m.start()]) or intro_prev or EXFIL_QUOTE_INTRO.search(sentence[:m.start()])
or _is_defensive_frame(before)`; `digest = sha256(sentence.strip().lower())`; `key = (addr.lower(), digest)`
dedup; `total`, cap; `(line, col) = _source_position(prose, start_line, s_start + m.start())` (rune offset into
the ORIGINAL prose; the blanked sentence has the same code-point length); emit; **break** (one finding per
sentence's first qualifying delivery). After each block `prev_tail = sentences[-1][1] if sentences else ""`.
Tests: `test_sxv043_data_exfil_directive_fires_on_a_hard_coded_recipient` (33 cases, all `["high"]`, recipient
prefix check), `test_sxv043_benign_addresses_and_framings_stay_silent` (35 cases + fenced),
`test_sxv043_soft_cues_never_excuse_credentials` (4), `test_sxv043_user_addressed_data_and_preceding_negation`
(5 positive, 4 negative), `test_sxv043_negation_is_judged_per_sentence` (5 + 3),
`test_sxv043_recipient_and_host_excuses` (13 params), `test_sxv043_one_large_paragraph_is_not_quadratic`
(1000 repeated sentences, < 3 s; `_EXFIL_WINDOW` bounds the acquisition scan).

**SXV-041 helpers (544-634, 1401-1450).** `_ri_governing_prefix(before)`: text after the last
`_RI_SEQ_BREAK_RE` match end. `_strip_urls(s)`: `SCHEMELESS_URL.sub(" ", EGRESS_URL.sub(" ", s))` (a URL becomes
ONE space, shifting later columns). `_ri_url_in`, `_ri_has_remote`, `_ri_fetch_and_url`,
`_ri_characterized_remote(joined)` (per `joined.splitlines()` line: CHARACTERIZED_SOURCE and a URL on the line;
true unless a BENIGN match starts before the characterized match and `_RI_DOC_AS_INSTRUCTION_RE` fails on the
URL-stripped line), `_ri_source_desc(joined)` (first schemed URL, else schemeless, else URLISH phrase, else
`"a remote source"`). `_ri_match(sline, raw, ctx)`: computes `remote`, `fetchurl`, `strong_remote = url in raw
or fetchurl`, `tied_remote = strong_remote or characterized(ctx)`; candidate list in this order with gates:
PIPE on raw (gate `_ri_has_remote(pipe.group(0))`), PROSE_PIPE/OUTPUT/TREAT/NOUN_EXEC on sline (gate tied_remote),
FOLLOW_TIED (gate remote and `not_local`), FOLLOW_STRONG (strong_remote and not_local), FOLLOW_ANA (fetchurl and
not_local), RUN_IT when FETCHVERB and SCRIPT_EXT match raw (gate tied_remote); `not_local(m)` = `_RI_LOCAL_AFTER_RE`
does not `.match` `sline[m.end():]`; result `(best.group(0).strip(), best.start()+1)` for the candidate with the
smallest start (first in list order on ties). `_ri_join_wrap(raws, n, in_fence)`: append following lines while
`j < len`, non-blank, `(j+1) not in in_fence`, not a list item, not a table row, previous part does not end with
`. ! ? : ;` after rstrip, and fewer than 8 joined; returns `_flatten_prose` of the join when > 1 part else the
raw line. `_installer_line(raw)`: all `_RI_INSTALL_PIPE_RE` matches must satisfy `InstallerIdiom`; for each
pipe the enclosing code span (backticks around it) or the bare sentence up to `". "` must contain no further
`_FETCH_LIKE_RE` after removing the pipe text once; each span is removed from `rest` once; finally false if
`_ri_has_remote(rest) and (FOLLOWVERB or FETCHVERB in rest)`.

**`_remote_instr_findings(art)` (1453), SXV-041.** `raws = text.split("\n")`; `in_fence` from `_fenced_lines`.
For `n` from 1: skip if `n in in_fence or n in fired`; `ctx = "\n".join(raws[max(0, n-3) : min(len, n+2)])`;
`sline = _strip_urls(raw)`; `hit = _ri_match(sline, raw, ctx)`; if none and (FETCHVERB or FOLLOWVERB in raw):
`joined = _ri_join_wrap`; if `joined != raw`: `jhit = _ri_match(_strip_urls(joined), raw, ctx)`; accept only if
`jhit[1] <= len(_strip_urls(raw).strip()) + 1` (directive starts on this line). Skip if still none.
`prose = _strip_urls(ctx)`; `before = sline[:col-1]`; skip if `_is_defensive_frame(before)`; `strong =
_RI_STRONG_FOLLOW_RE.search(matched)`; `scope = _ri_governing_prefix(before) if strong else before`; skip if
`RI_EXAMPLE_INTRO.search(scope)`; skip if `RI_BENIGN.search(scope + matched) and not RI_HARDEXEC.search(prose)`;
`fired.add(n)`; cap; `src = _ri_source_desc(raw if _ri_has_remote(raw) else ctx)`; `installer = _installer_line(raw)`;
emit with `line=n`, no column, severity medium iff installer. One cap note. Tests: 45 `test_sxv041_*` functions
plus `test_local_script_run_needs_a_remote_source`, `test_trailing_benign_pointer_does_not_disarm_remote_follow`,
`test_trailing_defensive_words_do_not_disarm_remote_follow`, `test_unrelated_documentation_pointer_cannot_mute_or_replace_remote_source`
(`remote_source == "https://evil.example/payload"`), `test_unrelated_documentation_url_does_not_remote_bind_local_follow`,
`test_characterized_remote_source_ties_two_line_follow_without_fetch_verb` (4 layouts),
`test_local_file_curl_pipe_is_not_remote_instruction_loading`, `test_local_file_pipe_does_not_bind_to_nearby_https_pointer`,
`test_remote_instruction_findings_are_capped_before_allocation` (60 → 25 + `"35 more SXV-041 findings"`),
`test_sxv041_first_party_installer_in_prose_is_medium_not_high` (3 medium, 4 not-medium),
`test_sxv041_prose_installer_shapes_match_the_code_lane`, `test_sxv041_separate_directive_on_the_installer_line_stays_high`,
`test_sxv041_hidden_second_fetch_blocks_the_installer_demotion`, `test_sxv041_wrapped_directive_still_fires`,
`test_sxv041_benign_prefix_in_earlier_step_does_not_suppress`, `test_sxv041_same_line_example_lead_does_not_rescue_a_strong_directive`,
`test_sxv041_download_and_run_it_fires_after_a_benign_lead`.

**SXV-011 grant gate (368-414).** `_basename_any(token)`: backslashes → `/`, `rstrip("/")`, last segment,
`.lower()`, strip one of `.exe .cmd .bat .com .ps1`. `_grant_tokens(pattern)`: None → `(None, [])`; strip; drop a
trailing `:*`, else cut at the first `:`; strip; tokens = Python `str.split()`. `_reaches_network(grant)`:
NETWORK_TOOLS → true; non-bash tool → `tool not in LOCAL_ONLY_TOOLS` (MCP/Task/unknown fail open); bash:
`pattern is None` or command in `("", "*", "**")` or no tokens → true; `cmd0 in NETWORK_SINGLE` → true; else
`cmd0 not in LOCAL_ONLY_CMDS`. `_reach_is_fail_open(grant)`: tool not in NETWORK_TOOLS, not in BASH_TOOLS, not in
LOCAL_ONLY_TOOLS. Tests: `test_grant_that_cannot_reach_network_skips`, `test_sxv011_git_grant_reaches_network`
(`allowed-tools: ["Bash(git:*)"]`), `test_wrapper_grant_does_not_disable_sxv011` (`Bash(find:*)` is neither list →
fails open), `test_broad_bash_deny_closes_the_egress_lane`, `test_sxv011_unrecognized_tool_fails_open`
(`mcp__slack__post_message`, `Task`), `test_sxv011_fail_open_reach_is_high_not_critical`, `test_get_exfil_respects_grant_reach_gate`,
`test_sxv011_nonhttp_egress_respects_grant_reach_gate`.

**`_is_table_row(raw)` (417):** stripped starts with `|` and has ≥ 2 `|`. **`_fenced_lines(markdown, raws)`
(422):** set of lines in `code_spans` (clamped to `len(raws)`) and `open_by_line[ln] = start`. **`_dir_of`,
`_governing_manifest`** (637-652): nearest manifest walking up directories to `""`. **`_list_intro_index(raws, n)`
(655):** if line n is a list item, the index of the first non-blank, non-list line above it, else None.
**`_fence_labelled_antipattern(raws, open_by_line, n)` (1528):** `_ANTIPATTERN_RE` over lines
`[max(0, open-4) : min(len, open+3)]` where `open = open_by_line.get(n, n)`.

**`_post_egresses(raws, markdown)` (1540).** For each line with `_EGRESS_VERB_RE`: `urls = EGRESS_URL.findall(raw)`;
`chosen = urls[0]`; if none and `n < len(raws)`: `candidate = raws[n].strip().rstrip(".,)")` fullmatching EGRESS_URL;
if none and `raw.rstrip().endswith(":")`: skip blank lines after n → `next_line = i + 1`; first `links` tuple with
`line == next_line`, label matching `_DESTINATION_LINK_RE`, href fullmatching EGRESS_URL → chosen; else the first
`code_spans` span with `start > n`, provided every line in `raws[n:start-1]` is blank; scan its lines for one
with an egress verb and a URL; only that first span is considered. Append `{"line": n, "url": chosen}` when chosen.
Tests: `test_unrelated_nearby_url_is_not_selected_as_post_target`, `test_immediately_following_url_only_is_a_post_target`,
`test_adjacent_markdown_destination_link_is_a_post_target`, `test_adjacent_html_destination_link_is_a_post_target`,
`test_unquoted_html_destination_link_is_a_post_target`, `test_sxv011_read_backref_concatenate_what_you_read_fires`
(fenced `curl … --data-binary @-` after a `:` line), `test_sxv011_early_benign_post_does_not_shadow_real_exfil`.

**`_cred_is_auth_input(raw, cred)` (1605), `_egress_backref(text)` (1626), `_get_exfil_egresses(raws)` (1640),
`_nonhttp_egresses(raws)` (1663), `_clause_at(s, idx)` (1670).** Port literally; `_clause_at` uses `";"` and
`". "` separators on both sides. `_get_exfil_egresses` iterates `sorted(set(EGRESS_URL.findall(raw)))` (code-point
order) and keeps `(n, url, vartokens(url) - hosttokens(url))` when the payload set is non-empty. Tests:
`test_sxv011_credential_as_auth_input_does_not_fire`, `test_user_flag_directly_consuming_netrc_is_auth_not_payload`,
`test_piped_netrc_payload_is_not_misclassified_by_user_flag`, `test_credential_payload_not_exempted_by_unrelated_auth_flag`,
`test_sxv011_auth_word_does_not_hide_a_credential_read_and_post`, `test_sxv011_generic_backref_does_not_link_unrelated_credentials`,
`test_sxv011_payload_backref_fires_but_auth_reference_does_not`, `test_get_path_token_exfil_fires`,
`test_get_userinfo_token_exfil_fires`, `test_get_query_token_exfil_fires`, `test_secret_in_egress_url_query_still_links`,
`test_benign_curl_download_near_credential_stays_silent`, `test_benign_download_underscore_path_no_link_stays_silent`,
`test_get_path_does_not_shadow_primary_post_egress`, `test_sxv011_scp_credential_egress_fires`,
`test_sxv011_cat_credential_pipe_nc_fires`, `test_sxv011_rsync_credential_egress_fires`,
`test_sxv011_nonhttp_egress_no_credential_stays_silent`, `test_scp_push_fires_pull_does_not`,
`test_sxv011_public_pub_key_is_not_a_secret`, `test_sxv011_nonhttp_egress_regex_is_linear`,
`test_unrelated_negated_clause_does_not_disarm_egress`, `test_docker_push_registry_hostname_is_not_exfil`
(host tokens never link).

**`_collect_cred_hits(raws, in_fence, open_by_line, egress_line, egress_vars, egress_backref)` (1688).**
Window `[max(1, e-10), min(len, e+10)]` inclusive. For `n != e` require `vartokens(raw) & egress_vars` or
`egress_backref`. For each `(rx, kind)` in `_CRED_HIGH_RX` order: first match only; skip a table row without an
egress verb; skip auth input when `n == e`; skip a fenced line inside an anti-pattern window; `neg_scope =
_clause_at(raw, m.start()) if n == e else raw`, skip on `_NEG_SAME_LINE_RE`; skip when the list intro line has
`_NEG_SAME_LINE_RE`; `prefix = raw[:m.start()]`, `prior = raws[max(0, n-3) : n-1]`, `introduced` = any prior
line whose `.strip()` is a defensive frame AND matches `\b(?:following|pattern|example)\b[^.\n]*:\s*$`; skip on
`_is_defensive_frame(prefix) or introduced`; dedupe kind per line; append `{"kind", "line": n, "text": m.group(0),
"col": m.start()+1}`. Tests: `test_negative_polarity_credential_does_not_fire`, `test_markdown_table_cell_does_not_fire`,
`test_negative_list_intro_governs_items`, `test_antipattern_fence_does_not_fire`, `test_get_exfil_defensive_doc_stays_silent`,
`test_get_exfil_trailing_defensive_words_do_not_disarm`, `test_sxv011_negative_send_caveat_on_credential_line_is_spared`,
`test_sxv011_overlapping_ssh_patterns_are_counted_once`, `test_sxv011_new_credential_stores_fire` (3 paths),
`test_pem_cert_filename_does_not_fire`, `test_unlinked_credential_and_egress_do_not_fire` (25 lines apart),
`test_nearby_credential_and_unrelated_upload_do_not_fire`, `test_credential_near_unrelated_upload_is_cooccurrence`,
`test_split_read_then_credspecific_send_fires`, `test_split_read_then_varlink_send_fires`, `test_linked_credential_egress_fires`,
`test_sxv011_egress_verb_vocabulary_matches_suppression` (5 verbs + `curl -T`).

**`_exfil_findings(art, manifest_by_dir)` (1739), SXV-011.** Gate: `manifest = _governing_manifest(...)`; if None
or `"allowed-tools" not in (manifest.frontmatter or {})` → `reaching = "undeclared_inherits_all"`,
`proven_reach = True`; else `grants = manifest.grants or []`; `bash_denied = any(bash tool and broad and not
allowed)`; `allowed = [g allowed and not (bash_denied and bash tool)]`; `net_grants = [g in allowed if reaches]`;
none → return `[]`; `reaching = ", ".join(sorted(g.raw))`; `proven_reach = any(not fail_open)`. Candidates:
POST list in order, first with hits wins; else GET list; else non-HTTP list. Return `[]` when none.
`corrob = _CRED_CORROB_RX.search(text)`; `first = min(hits, key=(line, col))`; `kinds = sorted(set)`; `tokens`
sorted by (line, col) (stable). One finding, `line = first["line"]`, no column. Tests:
`test_read_credentials_then_post_fires` (evidence polarity/kind/target), `test_undeclared_manifest_still_fires`
(`reaching_grant == "undeclared_inherits_all"`), `test_reading_a_config_without_egress_does_not_fire`,
`test_v2_bench_fixture_end_to_end_locks_in_sxv011` (skipped: external corpus absent; pins `("cred-egress",
"critical", "SKILL.md", 19)` and 4 kinds), `test_get_exfil_deterministic`.

### 2.2 `persistence.py`

**Constants.** `_INSTRUCTION_KINDS` = lane kinds; `_EVIDENCE_LIMIT = 400`; `_IDENTITY_TARGET` alternation =
`IDENTITY_FILES` sorted **descending** (so `agents.md` precedes `agent.md`), each `re.escape`d
(`regexp.QuoteMeta` yields the same matches for these names).

**`_clause_ends(text)` (53).** Character state machine over code points: tracks `quote` (`'` or `"`), `escaped`
(backslash inside a quote); a `'` between two `isalnum()` characters is an apostrophe, not a quote; outside quotes
yields `index+1` at `;`, `!`, `?`, or `.` followed by end/whitespace (`str.isspace`). Tests:
`test_punctuation_inside_persisted_quote_does_not_split_operation`, `test_apostrophe_does_not_join_unrelated_identity_clause`,
`test_exclamation_boundary_does_not_bind_unrelated_concealment`.

**`_target_attached_before_write(clause, target, write)` (75).** `before = clause[:target.start()]`, `between =
clause[target.end():write.start()]`; `introduced = search("(?i)\b(?:in|into|to|within)\s+[^;!?]{0,200}$", before)`;
`connector = fullmatch("(?i)\s*,?\s*(?:(?:must|should|will|shall|is|be)\s+)+", between)`; return
`(introduced and fullmatch("\s*,?\s*", between)) or connector`. Tests: `test_identity_persistence_supports_target_before_write`
(line 5, target `CLAUDE.md`), `test_target_before_write_requires_grammatical_attachment`,
`test_preceding_read_target_is_not_claimed_by_write`.

**`_target_attached_after_write(clause, target, write)` (85).** `between = clause[write.end():target.start()]`;
false if `search("(?i)\b[A-Za-z0-9_-]+\.[A-Za-z0-9]{1,12}\b", between)` (another filename in between); else
`search("(?i)\b(?:to|into|in|within)\s+[`'\"]?(?:[~./\\\w-]+[/\\])?$", between) or fullmatch("(?i)\s+(?:the\s+)?(?:[~./\\\w-]+[/\\])?", between)`.
Tests: `test_identity_target_after_unrelated_destination_is_not_correlated`, `test_identity_filename_mentioned_after_other_destination_is_not_target`,
`test_identity_target_belongs_to_its_own_write_operation`, `test_comma_starts_a_new_write_operation`.

**`check(parsed)` (95), SXV-005.** For each artifact with kind ∈ lane and non-empty text: `lines =
pySplitlines(text)` (§5.3 — Python `splitlines`, NOT split on `\n`); `spans = markdown.prose_spans` or `()`. For
each span index: `block = "\n".join(lines[start-1:end])`; blank `(?s)<!--.*?-->` matches, `_DEFENSIVE_DESCRIPTION`
matches and `_EXAMPLE_DESCRIPTION` matches (each char → space, newlines kept); `following_blocks`: subsequent spans
while `next_start - previous_end <= 2` and the joined candidate matches `_BLOCK_PREFIX` (anchored at its start);
`next_block = "\n".join(following_blocks)`. Clause loop over `_clause_ends(block)` + `len(block)`: `writes =
_WRITE.finditer(clause)`, `targets = _IDENTITY_TARGET.finditer(clause)`, `target_starts`, `operation_boundaries =
[m.start() for m in _NEXT_OPERATION.finditer(clause)]`. Per write: `operation_end = operation_boundaries[bisect_right(ob,
write.start())]` or `len(clause)`; `following_index = bisect_left(target_starts, write.end())`; target = that
target if it exists and `start < operation_end`; drop it unless `_target_attached_after_write`; if None: candidate
= target at `bisect_left(target_starts, write.start()) - 1` (if ≥ 0) and `_target_attached_before_write`; still
None → next write. `persisted = clause[write.start():operation_end]`; `introduced_block = next_block and
_CONTENT_INTRO.search(persisted) and _BLOCK_PREFIX.search(next_block)`; `correlated = persisted + ("\n" +
next_block if introduced_block else "")`; `quoted = _QUOTED.finditer(correlated)`; `content` = first quoted
`content` group with `_AGGRAVATOR`; `first_quote_is_payload = quoted and fullmatch("(?i)\s*(?:the\s+)?(?:text|content|instructions?)?\s*",
correlated[len(write.group(0)) : quoted[0].start()])`; if `content is None and not first_quote_is_payload and
_AGGRAVATOR.search(persisted)` → `content = persisted`; elif `content is None and introduced_block and
_AGGRAVATOR.search(next_block)` → `content = next_block`; if content → record `(clause_start, target, write,
content)` and stop scanning this block (one finding per prose span). Location: `before_target =
block[:clause_start + target.start()]`; `line = start + before_target.count("\n")`; `column = clause_start +
target.start() - before_target.rfind("\n")` (rfind = -1 when none → column = offset+1). Return
`CapFindings(findings)`. Tests (test_identity_persistence.py, the 28 `run_checks` tests):
`test_identity_persistence_binds_concealment_to_written_content` (rule/severity/path/line 5, target `CLAUDE.md`,
`"never reveal"` in persisted_content), `test_unrelated_concealment_does_not_aggravate_benign_identity_write`,
`test_identity_persistence_defensive_description_is_not_instruction`, `test_identity_defensive_description_cannot_hide_real_instruction`,
`test_multiline_identity_payload_binds_within_same_prose_block` (quoted `>` block as next_block, target
`.cursorrules`), `test_identity_persistence_location_points_to_target` (line 6, column = index of `CLAUDE.md` + 1),
`test_identity_persistence_does_not_correlate_unrelated_clauses`, `test_unrelated_following_prose_does_not_bind_to_identity_write`,
`test_same_block_unquoted_and_mixed_quote_identity_payloads` (2), `test_identity_target_requires_complete_basename`
(`NOTCLAUDE.md`, `foo.CLAUDE.md`, `CLAUDE.md.bak`, `my-agent.md.txt`), `test_identity_basename_cannot_be_a_directory_component`
(`CLAUDE.md/archive`), `test_multiple_defensive_examples_are_all_inert`, `test_later_quote_is_not_bound_to_prior_safe_write`,
`test_safe_quoted_payload_is_not_aggravated_by_following_instruction`, `test_defensive_clause_cannot_mask_following_real_instruction`,
`test_documentation_example_and_html_comment_are_inert`, `test_embedded_benign_quote_does_not_hide_unquoted_payload`,
`test_all_contiguous_list_payload_items_are_correlated`, `test_identity_persistence_evidence_is_bounded`
(persisted_content length 400, content_length > 400, truncated True, sha256 hex length 64),
`test_batch3_microcorpus.py::test_frozen_batch3_microcorpus[identity-instruction]` and `[adjacent-benign]`.

### 2.3 `hooks.py`

**Constants.** `_HOOK_EVENTS` (32 names, line 16; copy verbatim), `_CANONICAL_EVENT` (lowercase → canonical),
`_INTERPRETERS`, `_FETCHERS`, `_RUNNERS`, `_OPTIONS_WITH_VALUE`, `_RUNNER_ALIASES`, `_GLOBAL_VALUE_OPTS`,
`_AGENT_CONFIG_DIRS` (basename → allowed dirnames; `""` = package root).

**`_portable_basename(value)` (84).** Backslashes → `/`, last segment, `.lower()`, strip one `.bat|.cmd|.com|.exe`
suffix (`re.sub(..., "$")`; not `.ps1`, unlike `_basename_any`).

**`_is_agent_config_location(rel)` (89).** `dirname(rel).lower() in _AGENT_CONFIG_DIRS.get(basename(rel).lower(), set())`;
`posixpath.dirname("hooks.json") == ""` (Go `path.Dir` returns `"."` → map to `""`). Tests:
`test_arbitrary_json_lookalike_is_not_treated_as_agent_config` (`data.json`), `test_nested_non_agent_config_is_not_analyzed`
(`app/settings.json`), `test_agent_specific_mcp_config_locations_are_analyzed` (`.codex/config.toml`, `.cursor/mcp.json`,
`.vscode/mcp.json`), `test_root_generic_toml_is_not_treated_as_agent_config`, `test_missing_local_hook_target_is_reported`
(`.claude/settings.json`), `test_mixed_hooks_and_mcp_config_analyzes_both_surfaces` (`settings.json` at root).

**`_write_targets_hook(clause, event, target, write)` (94).** `hook = search("(?i)\bhooks?\b", clause)`; if None:
`write.start() < event.start() < target.start() and target.end() - write.end() <= 96`; else `subject = [min(event.start(),
hook.start()), max(event.end(), hook.end())]`; write before subject → `subject_end - write.end() <= 48`; write
after → `write.end() - subject_start <= 48`; overlapping → true. Distances in code points. Tests:
`test_hook_install_does_not_require_hook_keyword`, `test_event_mention_without_hook_word_is_not_install`,
`test_event_context_after_settings_write_is_not_hook_install`, `test_unrelated_settings_write_near_hook_is_not_install`,
`test_hook_install_does_not_correlate_across_sentences`.

**`_instruction_findings(artifact)` (118), SXV-006.** Kind ∈ lane and `markdown` present. `lines = pySplitlines(text)`.
Per prose span: `block`, `original_block = block`. Negation masking: for each `_NEGATED` match, `clause_start =
negated.start()`; `end_match = search("[.!?](?=\s|$)|[;\n]", block[negated.end():])`; `clause_end = negated.end()
+ end_match.end()` or `len(block)`; contrast `search("(?i)\b(?:but|however|yet|instead|rather|then|next|afterwards?)\b",
block[negated.end():clause_end])` shortens `clause_end` to `negated.end() + contrast.start()`; intervals sorted
and merged, masked chars → space (newlines kept). Then `_DEFENSIVE_DESCRIPTION` matches masked the same way.
Clause boundaries: `[m.end() for m in finditer(";|[.!?](?=\s|$)", block)]` + `len(block)`. Per clause: `target =
_SETTINGS.search`, `write = _WRITE.search` (first each); if both: first `_HOOK_EVENT` match with
`_write_targets_hook` → candidate; stop at the first candidate per block. Location: `before = block[:clause_start +
event.start()]`, `line = start + before.count("\n")`, `column = clause_start + event.start() - before.rfind("\n")`;
`snippet = pySplitlines(original_block)[line - start].strip()`; `canonical_event = _CANONICAL_EVENT[event.group(1).lower()]`.
Tests (test_hooks.py): `test_startup_hook_install_reports_exact_instruction_location` (line 6, column 10, exact
evidence dict), `test_negated_clause_before_install_preserves_location` (column = index of `SessionStart` + 1),
`test_multiple_negated_hook_clauses_do_not_false_fire`, `test_wrapped_hook_install_clause_still_reports`,
`test_documentation_negation_and_examples_do_not_install_hooks` (4), `test_read_then_install_is_not_suppressed_as_documentation`,
`test_hook_event_casing_and_current_events_do_not_bypass_install_detection` (`sessionstart` → `SessionStart`,
`SubagentStop`), `test_security_scanner_description_is_not_an_install_directive`,
`test_defensive_description_cannot_hide_following_install_directive`, `test_negated_example_cannot_hide_following_install_directive`,
`test_negated_clause_delimiters_cannot_hide_install_directive` (`;` and `\n`), `test_negated_write_verbs_are_aligned_with_positive_set` (3),
`test_verb_prefixed_noun_is_not_an_install_directive` (`additional`), `test_exclamation_boundary_stops_negation_and_cross_sentence`,
`test_contrastive_clause_after_negation_is_still_detected`, `test_affirmative_before_negation_is_preserved`,
`test_extended_negation_forms_do_not_install` (4), `test_additional_install_verbs_are_detected` (3),
`test_additional_negated_verbs_do_not_install` (3), `test_negation_boundary_ignores_dots_in_settings_path`,
`test_nested_settings_basename_is_not_an_install_target`, `test_then_sequencing_boundary_reveals_install_directive`,
`test_batch3_microcorpus[hook-install]`.

**`_tokens(command)` (195).** `pyshlex.Tokens(command with "\" → "/")` (§4.3); returns `nil, err` on an unclosed quote.

**`_local_candidate(parsed, command, arguments)` (209).** Returns `(resolution string, is_local bool)`:
`\r`/`\n`/`$(`/backtick in command → `dynamic_or_compound`; tokens nil → `malformed_command`, empty →
`empty_command`; `head = _portable_basename(tokens[0])`; `head in _FETCHERS` → `network_fetch`; any token that is a
non-empty run of `;&|<>` → `dynamic_or_compound`; append arguments (backslash → `/`). PowerShell: walk flags
(`-command`/`-encodedcommand` → `inline_interpreter`; `-file` consumes and stops; `-executionpolicy`/`-windowstyle`
skip 2; `-nologo`/`-noninteractive`/`-noprofile` skip 1; else stop). Interpreters (`_INTERPRETERS` or
`python\d+(?:\.\d+)*` fullmatch): value options per family (`-o` shells; `-w`,`-x` python; `-i` perl/ruby); `-c`
(or `-e`/`--eval` for non-shells, compared on the part before `=`) → `inline_interpreter`; shell `-s` → dynamic;
node `-r/--require/--import/--loader/--experimental-loader/--env-file/--env-file-if-exists` → dynamic; step 2 for
a value option without `=`, else 1. `index >= len` → `unresolved_external`; strip `^\$(?:\{(?:CLAUDE_PROJECT_DIR|
CLAUDE_PLUGIN_ROOT)\}|CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT)/`; any of `` $`|;&>< `` → dynamic; `normalized =
path.Clean(strings.TrimPrefix(candidate, "./"))` (Go `path.Clean("")` = `"."` = Python); absolute (`/`, `~`,
`^[A-Za-z]:/`) or `..`/`../…` → `external_path`; `parsed.by_rel[normalized]` exists with text → `package_local:%s`,
true; else `unresolved_external`. Tests: `test_unresolved_hook_autoexec_reports_resolution_and_location`
(`network_fetch`; path `hooks.json`, line 1, column None), `test_reviewable_package_local_hook_is_not_unresolvable`
(5 commands incl. `node .\scripts\hook.js`), `test_missing_local_hook_target_is_reported`, `test_inline_traversal_and_absolute_hook_targets_stay_reportable`
(5), `test_same_basename_elsewhere_does_not_suppress_missing_hook`, `test_local_hook_cannot_hide_trailing_compound_payload`,
`test_local_hook_cannot_hide_shell_expansion_after_target` (3), `test_official_command_plus_args_local_hook_is_reviewable`,
`test_unbraced_project_directory_local_hook_is_reviewable`, `test_structured_control_operator_argument_is_literal_not_shell_syntax`
(`"&&"` as an args element IS a punctuation token → still local? No: the args are appended after the head check,
and the punctuation check runs on `tokens` before `extend`, so `&&` in `args` is literal → local),
`test_version_qualified_python_local_hook_is_reviewable`, `test_plugin_root_local_hook_is_reviewable`,
`test_benign_interpreter_flags_keep_local_hook_reviewable` (`bash -eu`, `python -B`), `test_shell_stdin_flag_is_dynamic`,
`test_unreadable_local_hook_target_is_not_reviewable` (target exists but `text is None`), `test_node_preload_option_surfaces_for_review`,
`test_attached_node_eval_is_inline_execution` (`--eval=…`), `test_node_env_file_option_surfaces_for_review`.

**`_hook_source(artifact)` (282).** Config kinds with dict config → `(config.get("hooks", MISSING), 1)`; skill
manifest with dict frontmatter → `(frontmatter.get("hooks", MISSING), key_lines.get("hooks", 1))`; else MISSING.

**`_hook_findings(parsed, artifact)` (291), SXV-012.** Config kind at a non-agent location → `[]`; MISSING → `[]`;
non-dict → `[_incomplete(rel, "hooks_not_object")]`. Events iterated `sorted(hooks, key=(not str, str))` (strings
first by code point, then non-strings by `str()`); non-string key or non-list groups → malformed; unknown event
(case-insensitive) → malformed; group not a dict or `group["hooks"]` not a list → malformed; `matcher =
group.get("matcher", "*")`, non-string → malformed and `"<invalid>"`; per entry: non-dict → malformed;
`hook_type = entry.get("type", "command")`, non-string → malformed; `http`: `url` must be a string starting
(case-insensitively) with `http://`/`https://` else malformed; `mcp_tool`: `tool_name` or `server.tool` from
non-blank `server`/`tool`, else malformed; `prompt`/`agent`: non-blank string `prompt` else malformed; finding only
if `\$\{?[A-Za-z_]\w*\}?|`[^`]+`` matches; other types → malformed; `command`: `command` non-blank string and
`args` list of strings else malformed; `command = command.strip()`; `_local_candidate` local → skip; else
finding. Append `_incomplete(rel, "malformed_hook_entry")` once if anything was malformed. Tests:
`test_mcp_tool_hook_is_autoexecution`, `test_official_mcp_tool_hook_schema_is_autoexecution` (`audit.record`),
`test_malformed_hook_entry_is_visible_without_blinding_valid_sibling`, `test_static_semantic_hook_handlers_are_reviewable` (2),
`test_dynamic_semantic_hook_handler_is_unreviewable`, `test_unknown_hook_type_is_fail_visible`,
`test_mixed_type_frontmatter_hook_events_are_fail_visible` (YAML key `7` arrives as the string "7" after parse._plain, an unknown event, hence malformed), `test_unknown_hook_event_is_incomplete_not_asserted_autoexec`,
`test_uppercase_https_hook_is_a_remote_handler`, `test_skill_frontmatter_hook_is_analyzed_from_existing_ir`
(path `SKILL.md`, line 3 = `hooks` key line), `test_remote_http_hook_handler_is_reported`,
`test_currency_literal_prompt_is_not_dynamic` (`$100` has no identifier), `test_explicit_null_hooks_value_is_fail_visible`
(`hooks: null` is present but not a dict → `hooks_not_object`), `test_distinct_commands_same_event_are_not_deduplicated`,
`test_non_string_hook_type_is_fail_visible_without_crash`, `test_invalid_hooks_json_does_not_blind_mcp_check`
(config None → MISSING → nothing; the `coverage-note` comes from core), `test_batch3_microcorpus[external-hook]`.

**`_server_maps(artifact)` (416).** Config kinds with dict config: values of `mcpServers`, `mcp_servers`, `servers`
in that order; if none and kind `mcp_config` with `manifest_kind == "mcp_servers"` → the whole config (flat map).

**`_package_specs(runner, args)` (429).** Selectors `{--spec, --from}` for uvx/pipx else `{-p, --package}`. Walk:
`--` → the rest are positionals, stop; selector with missing/`-`-prefixed value → `(specs, True)`; `sel=value`
with empty value → `(specs, True)`; `_OPTIONS_WITH_VALUE[runner]` dangling → `(specs, True)` else skip 2; other
`-` flags skip 1; else positional. `specs` non-empty → `(specs, False)`; pipx: `positionals[:1] == ["run"]` required
(else `([], False)`), then drop it; return `(positionals[:1], False)`.

**`_is_exact_pin(runner, spec)` (476).** Local prefixes `. / ~ file:` or `^[A-Za-z]:[\\/]` → true; `git:`/`git+`/
`github:`/`gitlab:`/`bitbucket:` → `[#@][0-9a-fA-F]{40}(?:[#?].*)?$`; `http:`/`https:` → false; uvx/pipx →
PEP 508 (§4.4): invalid → false; URL: `file:` → true, else `@[0-9a-fA-F]{40}(?:[#?].*)?$`; else exactly one
constraint with operator `==`/`===` and no `*` in the version; npm: target after `@npm:` if present,
`_NPM_EXACT` fullmatch.

**`_mcp_findings(artifact)` (501), SXV-013.** Location gate; maps; non-dict map → malformed; names sorted;
non-string name or non-dict server → malformed; `command`, `args` (default `[]`), `type`, `url`; non-string
non-None type → malformed; `command is None and (type in (http, sse) or non-blank url)` → skip; command must be
a non-blank string and args a list of strings else malformed; `runner = _portable_basename(command)` (unstripped),
`runner_args = args`; shell wrapper: for `option in args[:-1]` with `-` prefix and `c` in `option[1:]`: `wrapped =
_tokens(args[i+1])`, cut at the first punctuation token, `runner = basename(wrapped[0])`, `runner_args = wrapped[1:]`,
break; runner aliases: skip leading global flags (2 for `_GLOBAL_VALUE_OPTS`), subcommand in the alias set →
`runner = "npx"`, `runner_args = args[sub+1:]`; not a runner → skip; `_package_specs`; bad args → malformed;
each non-pinned spec → finding (evidence `args` = original list). Append `_incomplete(rel, "malformed_mcp_server")`
once. Tests: `test_floating_mcp_package_reports` (4 params; `npx.cmd`), `test_runner_option_values_cannot_hide_floating_package` (4),
`test_pinned_or_local_mcp_server_does_not_report_floating_package` (5), `test_python_wildcard_pin_is_still_floating`,
`test_mutable_remote_package_reference_is_floating` (2), `test_dlx_runner_aliases_report_floating_packages` (2),
`test_git_commit_sha_is_an_immutable_pin`, `test_dangling_package_option_is_incomplete` (2),
`test_malformed_mcp_server_is_visible_and_valid_sibling_still_reports`, `test_malformed_mcp_wrapper_cannot_hide_valid_sibling_wrapper`,
`test_flat_mcp_map_and_snake_case_wrapper_are_supported`, `test_http_server_and_package_text_in_unrelated_field_are_not_floating`,
`test_repeated_package_option_reports_floating_sibling`, `test_npm_exec_floating_package_is_reported`,
`test_pipx_python_option_value_is_not_the_package`, `test_windows_local_package_path_is_a_pin`,
`test_pep508_direct_reference_sha_is_a_pin`, `test_direct_reference_sha_with_subdir_fragment_is_a_pin`,
`test_option_terminator_stops_package_parsing`, `test_option_terminator_still_selects_following_package`,
`test_pipx_non_run_subcommand_is_not_a_package`, `test_package_runner_aliases_report_floating` (3),
`test_shell_wrapped_package_runner_reports_floating`, `test_shell_wrapped_pinned_package_is_not_floating`,
`test_global_option_value_before_subcommand_is_consumed`, `test_uvx_python_short_option_is_not_the_package`,
`test_npm_alias_spec_pins_target_after_npm_marker`, `test_pep508_file_reference_is_local_pin`,
`test_non_string_server_type_is_fail_visible_without_crash`, `test_non_string_server_type_with_command_is_fail_visible`,
`test_npx_prefix_option_value_is_not_the_package`, `test_attached_short_package_option_reports_floating` (`-p=evil@latest`),
`test_empty_mcp_command_is_fail_visible`, `test_url_only_remote_mcp_server_is_valid`, `test_batch3_microcorpus[floating-mcp]`.

**`check(parsed)` (582).** For each artifact: `_instruction_findings`, `_hook_findings`, `_mcp_findings`; return
`CapFindings(findings)`.

### 2.4 Where line numbers and columns are computed (parity checklist)

| Site | Line | Column | Basis |
|---|---|---|---|
| SXV-027 (`_hidden_comment_findings`) | `base_line + count("\n" in fragment[:start])` or parse's `html_comments` line | `base_column + start` / `start - last_break` | code points in the HTML fragment |
| SXV-028..031, 042, 043 | `_source_position(prose, start_line, pos)` | same | rune offset in the flattened block mapped back to the raw block |
| SXV-041 | `n` (1-based raw line) | evidence `col` = `best.start()+1` in the **URL-stripped** line | code points |
| SXV-011 | first cred hit line | evidence `col` = `m.start()+1` in the raw line | code points |
| SXV-005 | `start + before_target.count("\n")` | `clause_start + target.start() - before_target.rfind("\n")` | code points, block from `pySplitlines` |
| SXV-006 | `start + before.count("\n")` | `clause_start + event.start() - before.rfind("\n")` | code points, block from `pySplitlines`; masking keeps newlines so offsets hold |
| SXV-012 | `1` or `frontmatter_key_lines["hooks"]` (default 1) | none | |
| SXV-013 | `1` | none | |

---

## 3. Regex inventory

Legend for the verdict column: **R** = RE2 unchanged (`(?i)` for `re.I`, named groups `(?P<x>)` are valid
RE2); **R$** = RE2 with `$` → `\z` (§3.4 explains when that is exact); **RF** = Python `fullmatch` → wrap as
`\A(?:…)\z`; **LB** = RE2 pattern without the lookbehind + `findWithLookbehind` helper (§3.3); **LA** = RE2
pattern without the lookahead + post-check on the text after the match (§3.3); **R2** = `dlclark/regexp2`
verbatim with a one-line comment; **H** = replaced by a Go helper function. Column **U** flags patterns where
Python-vs-RE2 `\b`/`\w`/`\s`/`\d`/case-folding differences can change a result on the scanner's inputs:
`b` = word boundary next to a non-ASCII letter, `w` = `\w` quantifier extent reaches evidence text, `s` = `\s`
against NBSP/U+2028/`\v`, `-` = ASCII-only or irrelevant. Every `(?i)` pattern relies on simple case folding,
which RE2 and Python share for the characters that appear here (verified: `ſ`→`s` and `K`→`k` fold in both;
`ß`≠`ss` in both).

### 3.1 `instruction_exfil.py` (119 patterns)

| # | Name (line) | Verdict | U | Notes |
|---|---|---|---|---|
| 1 | `_COMMENT_ADDRESSEE_RE` (69) | LB | b | `(?<![/\w-])(?:assistant\|agent\|claude\|gpt)\b`; boolean search |
| 2 | `_COMMENT_ACTION_RE` (72) | R | b,w | `exfiltrat\w*` boolean only |
| 3 | `_COMMENT_EXEC_RE` (77) | R | b | |
| 4 | `_COMMENT_STRONG_RE` (84) | R | b | |
| 5 | SXV-028 rule (97) | R | b,w | `\w{0,12}`, `jailbr\w+`, `remov\w*` etc.; extent reaches `directive_text` |
| 6 | SXV-029 rule (128) | R | b | |
| 7 | SXV-030 rule (142) | R | b,s | |
| 8 | SXV-031 rule (172) | LA | b,w | `(?!\s+(?:interface\|…)\b\|['’]s)` after `\b`; post-check the suffix; retry at p+1 |
| 9 | `_DEFENSIVE_RE` (185) | R$ | b,w | `[^.;\n]*$` twice; inputs never end in `\n` |
| 10 | `_DEFENSIVE_DETAIL_RE` (199) | R | b | |
| 11 | `_ANTIREFUSAL_BENIGN_RE` (211) | R | b,s | |
| 12 | `_NEGATED_ATTACK_ACTION_RE` (217) | R | b | |
| 13 | `_NEGATED_OVERRIDE_RE` (227) | R | b | built from `_NEGATION_RE` string |
| 14 | dynamic `_NEG_RUN_PREFIX + re.escape(script)` (230, 241) | **R2** | b,s | tempered negative lookahead `(?!\b(?:before\|…)\b)` and `\.(?=\S)` inside a lazy `{0,80}?`; compiled per script (cache by script string); `regexp2.IgnoreCase`; use `regexp2.Escape` for the script |
| 15 | `_SENTENCE_END_RE` (233) | H | s | `(?<=[.!?])\s+`; helpers `sentenceSplit(s)` and `sentenceEndAfter(s, pos)` built on RE2 `[.!?]\s+` (split point = match start + 1; a search from `pos` scans from `pos-1`, which is exactly what Python's lookbehind sees) |
| 16 | `_NOUN_PHRASE_INTRO_RE` (247) | R$ | b,s | `\s+$` |
| 17 | `_PARAM_DEF_RE` (256) | R$ | w | `\s*$`; note `\w[\w-]*` and `[\w.-]+=` |
| 18 | `_SCOPED_DIRECTIVE_RE` (263) | R | b | `.{0,30}` |
| 19 | `_EXAMPLE_INTRO_RE` (267) | R | b,s | |
| 20 | `_SXV042_EXAMPLE_INTRO_RE` (276) | R | b,s | |
| 21-36 | `_CRED_HIGH_RX` (283-301), 16 patterns | R except #22, #23 | - | #22 `~?/?\.ssh/id_(?:rsa\|ed25519\|ecdsa\|dsa)\b(?!\.pub)` and #23 `\bid_(?:rsa\|ed25519)\b(?!\.pub)` are **LA** (iterate matches, take the first not followed by `.pub`); #36 `…/serviceaccount/token` R; `_CRED_HIGH` #4 `~?/?\.netrc\b` R; the `\w+` in gcp/azure entries extends the matched text (evidence `text`) |
| 37 | `_CRED_CORROB_RX` (304) | LB | - | `(?<![\w./-])\.env…\b`; boolean on whole text |
| 38 | `_CRED_BACKREF_RE` (307) | R | b | |
| 39 | `_VARLINK_RE` (313) | R | - | `\$\w+\|\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]*\b`; `\w+` after `$` (w) |
| 40 | `_URL_HOST_RE` (315) | R | s | `\s` in negated classes |
| 41 | `_EGRESS_URL_RE` (327) | R | - | ASCII class |
| 42 | `_EGRESS_VERB_RE` (328) | R | b | lazy `[^.\n]{0,30}?` fine |
| 43 | `_FETCH_VERB_RE` (336) | LA | b | `\bhttps?\b(?!://)`; boolean: any match not followed by `://` |
| 44 | `_NEG_SAME_LINE_RE` (339) | R | b,w | |
| 45 | `_ANTIPATTERN_RE` (344) | R | - | |
| 46 | `_LIST_ITEM_RE` (346) | R | s | `^\s*` with `.match` (anchored) |
| 47 | `_RI_FOLLOWVERB_RE` (443) | R | b | |
| 48 | `_RI_PIPE_RE` (444) | R | b | |
| 49 | `_RI_PROSE_PIPE_RE` (446) | R | b | |
| 50 | `_RI_OUTPUT_RE` (449) | R | b,s | lazy `{0,24}?` |
| 51 | `_RI_TREAT_RE` (456) | R | b,s | |
| 52 | `_RI_FOLLOW_TIED_RE` (465) | R | b,s,w | `specif\w+` |
| 53 | `_RI_FOLLOW_STRONG_RE` (471) | R | b | |
| 54 | `_RI_FOLLOW_ANA_RE` (473) | R | b,s,w | |
| 55 | `_RI_NOUN_EXEC_RE` (478) | R | b,s | |
| 56 | `_RI_SCRIPT_EXT_RE` (483) | R | b | |
| 57 | `_RI_RUN_IT_RE` (484) | R | b,s | |
| 58 | `_RI_LOCAL_AFTER_RE` (486) | R | b,s,w | anchored `.match` → `\A` prefix |
| 59 | `_RI_FETCHVERB_RE` (491) | R | b | |
| 60 | `_RI_URLISH_RE` (495) | R | b,s | |
| 61 | `_RI_CHARACTERIZED_SOURCE_RE` (499) | R | b,s | |
| 62 | `_RI_DOC_AS_INSTRUCTION_RE` (503) | R | b,s | |
| 63 | `_SCHEMELESS_URL_RE` (507) | R | b,s | `[^\s)]+` |
| 64 | `_RI_BENIGN_RE` (512) | R | b | |
| 65 | `_RI_HARDEXEC_RE` (517) | R | b,s | |
| 66 | `_RI_EXAMPLE_INTRO_RE` (524) | R | b,s | |
| 67 | `_RI_SEQ_BREAK_RE` (530) | R | b,s | `\.\s` |
| 68 | `_RI_STRONG_FOLLOW_RE` (535) | R | b,s,w | |
| 69 | `_BUNDLED_RUN_RE` (858) | LB | b,w | two `(?<![\w/])` alternatives; apply the lookbehind filter only to matches beginning with `./` or `scripts/ bin/ tools/ hooks/`; `[\w./-]*` extent reaches `script` |
| 70 | `_COVERT_RUN_CUE_RE` (864) | R | b,s,w | `(?:\w+\s+){0,3}` |
| 71 | `_COVERT_OVERRIDE_RE` (899) | R | - | |
| 72 | `_COERCED_RUN_CUE_RE` (906) | R | b,s,w | named group `beforeany` (RE2 `(?P<beforeany>…)` valid); `\**` literal-star quantifier is fine |
| 73 | `_BUNDLED_PROSE_RE` (930) | R | b,s,w | `register\w*` etc. |
| 74 | `_HEADING_RE` (944) | R | s | `^ {0,3}#{1,6}\s` with `.match` |
| 75 | `_EXFIL_ADDR_RE` (1084) | R | w,s | `[\w.+-]+@[\w-]+` — Unicode letters in mailboxes match in Python only |
| 76 | `_EXFIL_VERB_RE` (1100) | LB | b | seven `(?<!\ba )…` lookbehinds; helper rejects a match whose preceding text matches `(?i)\b(?:a\|an\|the\|this\|that\|your\|each) \z` |
| 77 | `_EXFIL_SENDER_MARK_RE` (1103) | R | b | |
| 78 | `_EXFIL_QUOTE_INTRO_RE` (1105) | R$ | b,s | `[^\"'\u201d\u2019]*$`; write the curly quotes as literals or `\x{201d}` in Go; input is a sentence prefix (no `\n`) |
| 79 | `_EXFIL_CODE_SPAN_RE` (1110) | R | - | |
| 80 | `_EXFIL_CONN_RE` (1111) | R | b | |
| 81 | `_EXFIL_DITRANS_RE` (1113) | **R2** | b,s,w | `(?P<gap>(?:[^.!?\n]\|\.(?=\S)){1,80})` — the gap extent (used for `tail`, negation scope) depends on the lookahead inside the quantified group |
| 82 | `_EXFIL_PARAM_RECIPIENT_RE` (1117) | LB | b,s | `(?<![?&/;])`; filter on previous char |
| 83 | `_EXFIL_PASSIVE_RE` (1120) | R$ | b,s | ends `\s+…$` on `pre` |
| 84 | `_EXFIL_OBJECT_RE` (1123) | R | b | |
| 85 | `_EXFIL_POSSESSIVE_RE` (1129) | R | b | |
| 86 | `_EXFIL_ACQUIRE_RE` (1130) | **R2** | b,s,w | lazy `(?:[^.!?\n]\|\.(?=\S)){0,80}?`; the match extent is evidence (`acquisition`) and feeds `_own_sentence` |
| 87 | `_EXFIL_NEG_PREFIX_RE` (1142) | LA | b,s,w | trailing `(?!\W+(?:hesitate\|…)\b)`; boolean: first match whose suffix does not match `\A\W+(?:hesitate\|forget\|fail\|neglect\|wait)\b` |
| 88 | `_EXFIL_CONTRAST_RE` (1149) | R$ | b,s | `{0,2}$` on a sentence prefix |
| 89 | `_EXFIL_DISCLOSURE_RE` (1152) | R | b,s,w | lazy `{0,40}?` |
| 90 | `_EXFIL_EXAMPLE_TAIL_RE` (1157) | R$ | b,s | `\s*$` |
| 91 | `_EXFIL_EXAMPLE_HEADING_RE` (1161) | R | b | |
| 92 | `_EXFIL_PLACEHOLDER_HOST_RE` (1162) | R$ | b | `^…$` on a host (no `\n`) |
| 93 | `_EXFIL_PLACEHOLDER_LOCAL_RE` (1165) | R$ | w | `.match` + `$` → `\A…\z` |
| 94 | `_EXFIL_ROLE_LOCAL_RE` (1168) | R$ | - | |
| 95 | `_EXFIL_API_PREFIX_RE` (1174) | R | - | |
| 96 | `_EXFIL_SERVICE_HOST_RE` (1177) | R$ | - | |
| 97 | `_EXFIL_DEV_HOST_RE` (1187) | R$ | w | `s3(?:[.-][\w-]+)*` |
| 98 | `_EXFIL_TELEMETRY_DATA_RE` (1196) | R | b | |
| 99 | `_EXFIL_TELEMETRY_HOST_RE` (1199) | R | - | `.match` → `\A` |
| 100 | `_EXFIL_CREDENTIAL_RE` (1203) | R | b,s | |
| 101 | `_EXFIL_SENSITIVE_RE` (1208) | R | b,s | |
| 102 | `_RI_INSTALL_PIPE_RE` (1418) | R | b,s,w | |
| 103 | `_FETCH_LIKE_RE` (1424) | R | b | |
| 104 | `_DESTINATION_LINK_RE` (1536) | R | b | |
| 105 | `_CRED_AUTH_VALUE_RE` (1587) | R$ | s | `(?:\$\([^\n)]{0,80}\|\S*)\s*$` on a line prefix |
| 106 | `_CRED_BARE_NETRC_RE` (1590) | LA | b | `--netrc\b(?!-file)`; boolean |
| 107 | `_CRED_AUTH_PROSE_RE` (1591) | R | b,s,w | |
| 108 | `_CRED_PAYLOAD_FLAG_RE` (1596) | R$ | s | `\s*@?\s*$` |
| 109 | `_CRED_SENT_DIRECTLY_RE` (1599) | R$ | b,s,w | `\s+\S*$` |
| 110 | `_CRED_PIPE_PAYLOAD_RE` (1601) | R$ | b,s | `@-(?:\s\|$)` → `(?:\s\|\z)` on a line suffix |
| 111 | `_NONHTTP_EGRESS_RE` (1658) | R$ | b,s,w | `(?:\s+\S+)*?\s+(?:[\w.-]+@)?[\w.-]+:\S*\s*$`; RE2 is linear (Python test pins < 1 s on 1 MiB) |
| 112 | inline `[ \t]*\n[ \t]*` (717) | R | - | `ReplaceAllString(" ")` |
| 113 | inline `(?:ignore\|forget\|override\|disregard)\b` (824) | R | b | `.match` → `\A` |
| 114 | inline `\b(?:following\|pattern\|example)\b[^.\n]*:\s*$` (1728) | R$ | b,s | on a raw line |
| 115 | inline `\b(?:using\|with\|via)\s+(?:the\s+\|your\s+\|its\s+)?$` (1635) | R$ | b,s | |
| 116 | inline `@\s*$` (1616) | R$ | s | |
| 117 | inline `[<>{}$\[\]]` (1253) | R | - | |
| 118 | inline `\byou\b` (1344) | R | b | |
| 119 | inline `\byour\b` (1329) | R | b | |

### 3.2 `persistence.py` (17 patterns)

| # | Name (line) | Verdict | U | Notes |
|---|---|---|---|---|
| 1 | `_IDENTITY_TARGET` (13) | LB+LA | - | `(?<![A-Za-z0-9_.-])(?:names)(?![A-Za-z0-9_/\\-]\|\.[A-Za-z0-9])`; RE2 alternation in the same descending order + helper: reject when the previous char is in `[A-Za-z0-9_.-]` or the suffix matches `\A(?:[A-Za-z0-9_/\\-]\|\.[A-Za-z0-9])`; retry at p+1 |
| 2 | `_WRITE` (17) | R | b,w | `\w*\b` suffix extends `write_verb` |
| 3 | `_QUOTED` (21) | **backreference** → LB-style helper | - | RE2 `(['"])([^'"\n]{1,600})['"]`; accept only when the closing quote equals group 1 (the content class excludes both quotes, so the first quote after the content is the only candidate); groups `quote`, `content` |
| 4 | `_AGGRAVATOR` (22) | R | b,s | contains the literal `’` (U+2019) |
| 5 | `_CONTENT_INTRO` (32) | R$ | b,s | `:\s*$` |
| 6 | `_BLOCK_PREFIX` (35) | R | s | `^\s*(?:>\|[-*+]\s\|\d+[.)]\s\|```)` used with `.search` (no MULTILINE → `^` is start of string) |
| 7 | `_DEFENSIVE_DESCRIPTION` (36) | R | b,s,w | |
| 8 | `_EXAMPLE_DESCRIPTION` (42) | R | b,s | |
| 9 | `_NEXT_OPERATION` (47) | R | b,s | |
| 10 | inline `(?s)<!--.*?-->` (105) | R | - | `(?s)` valid in RE2 |
| 11 | inline `(?i)\b(?:in\|into\|to\|within)\s+[^;!?]{0,200}$` (78) | R$ | b,s | |
| 12 | inline `(?i)\s*,?\s*(?:(?:must\|should\|will\|shall\|is\|be)\s+)+` (79) | RF | s | |
| 13 | inline `\s*,?\s*` (82) | RF | s | |
| 14 | inline `(?i)\b[A-Za-z0-9_-]+\.[A-Za-z0-9]{1,12}\b` (87) | R | b | |
| 15 | inline `(?i)\b(?:to\|into\|in\|within)\s+[`'\"]?(?:[~./\\\w-]+[/\\])?$` (90) | R$ | b,s,w | |
| 16 | inline `(?i)\s+(?:the\s+)?(?:[~./\\\w-]+[/\\])?` (91) | RF | s,w | |
| 17 | inline `(?i)\s*(?:the\s+)?(?:text\|content\|instructions?)?\s*` (181) | RF | s | |

### 3.3 `hooks.py` (18 patterns)

| # | Name (line) | Verdict | U | Notes |
|---|---|---|---|---|
| 1 | `_HOOK_EVENT` (25) | R | b | `\b(events)\b`, `re.IGNORECASE`; group 1 |
| 2 | `_SETTINGS` (27) | LB | - | second alternative `(?<![\w/\\.])settings…\.json\b`; filter applies only to matches beginning with `settings` |
| 3 | `_WRITE` (32) | R | b | |
| 4 | `_NEGATED` (37) | R | b,s | literal `’` |
| 5 | `_DEFENSIVE_DESCRIPTION` (46) | R | b,s,w | |
| 6 | `_NPM_EXACT` (60) | RF | - | |
| 7 | inline `\.(?:bat\|cmd\|com\|exe)$` (86) | R$ | - | `ReplaceAllString`; a trailing `\n` in a command name is impossible after `.strip()` for hooks and harmless for MCP (§5.6) |
| 8 | inline `(?i)\bhooks?\b` (95) | R | b | |
| 9 | inline `[.!?](?=\s\|$)\|[;\n]` (134) | LA | s | RE2 `[.!?]\s\|[.!?]\z\|[;\n]`; when the matched text has length 2, `end = m.end()-1` |
| 10 | inline `(?i)\b(?:but\|however\|yet\|instead\|rather\|then\|next\|afterwards?)\b` (138) | R | b | |
| 11 | inline `;\|[.!?](?=\s\|$)` (161) | LA | s | same trick as #9 |
| 12 | inline `python\d+(?:\.\d+)*` (239) | RF | - | |
| 13 | inline `^\$(?:\{(?:CLAUDE_PROJECT_DIR\|CLAUDE_PLUGIN_ROOT)\}\|CLAUDE_PROJECT_DIR\|CLAUDE_PLUGIN_ROOT)/` (267) | R | - | `ReplaceAllString("")` |
| 14 | inline `^[A-Za-z]:/` (273) | R | - | |
| 15 | inline `^[A-Za-z]:[\\/]` (477) | R | - | |
| 16 | inline `[#@][0-9a-fA-F]{40}(?:[#?].*)?$` (480) | R$ | - | boolean; write `(?:[#?].*)?\n?\z` to keep Python's before-final-newline `$` |
| 17 | inline `@[0-9a-fA-F]{40}(?:[#?].*)?$` (492) | R$ | - | same |
| 18 | inline `\$\{?[A-Za-z_]\w*\}?\|`[^`]+`` (372) | R | w | boolean |

### 3.4 Shared translation rules

- **`$`**: Python `$` (no MULTILINE) matches at end of string and before a final `\n`; RE2 `$` only at end.
  Where the subject cannot end in `\n` (line slices, flattened prose, sentence prefixes, hosts, mailboxes) use
  `\z`; where it is preceded by `\s*`/`\s+` the two are already equivalent; for the two boolean SHA checks
  (hooks #16, #17) use `\n?\z`. Python `fullmatch` → `\A(?:…)\z` (a subject ending in `\n` never fullmatches).
- **Lookbehind helper** `findAllLB(re *regexp.Regexp, s string, reject func(prev rune, match string) bool)`:
  scan with `FindStringIndex` from position `p`; if `reject` fires, retry from `p+1` (one rune) instead of the match
  end, so a dropped match cannot hide an overlapping accepted one; this reproduces `re.finditer` semantics exactly
  for every LB/LA pattern above (their alternatives cannot match different text at the same start).
- **Lookahead post-check**: same helper with `reject` reading the suffix `s[end:]`.
- **regexp2** (3 patterns): `regexp2.MustCompile(pattern, regexp2.IgnoreCase)`, no match timeout (patterns are
  bounded); `\b`, `\w`, `\s` are Unicode there (closer to Python than RE2). Comment each with `// regexp2: <reason>`.
- **Byte vs rune positions**: all `FindStringIndex` results are byte offsets; convert with the helpers in §5.1
  before doing arithmetic with Python constants or before emitting a column.

---

## 4. Third-party and stdlib replacements

### 4.1 markdown_it (indirect)

This group never imports markdown_it; it consumes parse's IR. The exact parse facts consumed, which the parse
group's goldmark replacement must reproduce and against which it can be validated independently:

| Fact | Consumers | Definition to reproduce |
|---|---|---|
| `prose_spans` | `_prose_blocks`, persistence, hooks | for every markdown-it `inline` token with a `map` and no `html_inline` child: `(map[0]+1+offset, map[1]+offset)`; includes headings, paragraphs, list-item paragraphs, table cells; excludes inline containing raw HTML |
| `code_spans` | `_fenced_lines`, `_heading_lines`, `_post_egresses` | `fence` and `code_block` tokens (indented code) |
| `fence_spans` | `_heading_lines` | `fence` tokens only |
| `links` | `_post_egresses` | `(href, label text, line)` from `link_open`…`link_close` (line advanced by soft/hard breaks) and from presentational `<a href>` in inspectable HTML |
| `html_comments` | SXV-027 | `(data, line, column)` from `HTMLParser.handle_comment` on inspectable HTML blocks and inline fragments (column 1-based, code points) |
| `html_prose` | `_prose_blocks` | `(_project_html(fragment), line)`: tags blanked to spaces, entities decoded and padded to the token width, `<code>`/`<pre>` content blanked, newlines kept |
| `html_uninspectable` | SXV-027 | `(fragment, line, column)` for HTML that is not purely presentational (unknown tags, disallowed attributes, `data:`/`javascript:` targets, unbalanced code stack) |
| `frontmatter_end_line` | `_prose_blocks`, `_heading_lines` | 1-based line of the closing `---` |
| `text` | everything | `_norm_newlines` applied once (`\r\n`→`\n`, `\r`→`\n`) |

Tests that pin these facts from this group's side: `test_directive_after_quoted_attribute_gt_is_not_hidden`,
`test_presentational_html_cannot_split_instruction_override`, `test_html_entity_cannot_split_instruction_override`,
`test_semicolonless_numeric_html_entity_cannot_split_instruction_override`, `test_html_code_examples_do_not_trigger_instruction_override`,
`test_self_closing_html_code_tag_cannot_hide_directive`, `test_adjacent_html_destination_link_is_a_post_target`,
`test_unquoted_html_destination_link_is_a_post_target`, `test_directives_use_commonmark_code_spans`,
`test_sxv027_ignores_html_comment_inside_inline_code`.

### 4.2 tree_sitter(_bash), ruamel, jsonschema, tomllib, html, ipaddress, unicodedata, zipfile/tarfile

Not used by this group. Frontmatter (`ruamel`) and configs (`json`/`tomllib`) arrive decoded; this group only
type-switches on `any` (`string`, `[]any`, `map[string]any`, `nil`, numbers, bools; keys are always strings, parse._plain).

### 4.3 shlex (hooks `_tokens`)

Python: `shlex.shlex(command.replace("\\", "/"), posix=True, punctuation_chars=";&|<>")`,
`whitespace_split = True`, `commenters = ""`. Because every backslash is turned into `/` first, **no escape
sequences ever reach the lexer**; verified behaviour to reproduce:

| Input | Tokens |
|---|---|
| `python scripts/hook.py && curl x \| sh` | `python`, `scripts/hook.py`, `&&`, `curl`, `x`, `\|`, `sh` |
| `cmd 2>&1 <in` | `cmd`, `2`, `>&`, `1`, `<`, `in` (runs of `;&|<>` are one token) |
| `a; b;; c` | `a`, `;`, `b`, `;;`, `c` |
| `'x'y"z"` | `xyz` (quoted and unquoted segments glue) |
| `--flag="a b"` | `--flag=a b` |
| `''` | `` (one empty token) |
| `  ` | (none) |
| `C:\Users\x\hook.cmd` | `C:/Users/x/hook.cmd` |
| `unterminated 'x` | error "No closing quotation" → `_tokens` returns None |

Whitespace is ASCII ` \t\r\n`; `'…'` and `"…"` are both literal (no escapes remain). **Decision:** hand-rolled
`pytext.ShlexTokens` (~80 lines in `internal/pytext`) rather than `mvdan.cc/sh/v3` (a shell parser produces redirect/AST nodes, not
Python's `>&` token shapes) or `mattn/go-shellwords` (no punctuation tokens, different quoting). The same package
serves the code group (`shlex.split(fetch)`, posix, no punctuation chars) and parse (`shlex.split(spec,
posix=False)`); expose `Split(s string) ([]string, error)` and `Tokens(s, punct string) ([]string, error)`.

### 4.4 packaging.requirements.Requirement (hooks `_is_exact_pin`)

Only three facts are read: validity, `requirement.url`, and the list of `(operator, version)` constraints.
Verified behaviour: `tool==1` valid (`==`,`1`); `tool==1.4.*` valid (wildcard kept in the version string);
`tool @ git+https://…@<sha>#subdirectory=python` → url set, no specifier; `tool@1.0` → url `1.0`; `tool==`,
`==1.0`, `_bad==1`, `tool ==1.0;` (empty marker) → `InvalidRequirement`; `tool[extra]==1.0; python_version>'3'`
valid; `tool >= 1, == 2` → two constraints. **Decision:** no PEP 508 library exists in Go; implement
`internal/pep508.Parse(s) (name, url string, specs []Spec, ok bool)` with one regex for the grammar
(`name[extras] [@ url | specifiers] [; non-empty marker]`, name `[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?`,
operators `===|==|~=|!=|<=|>=|<|>`) and validate each version with `github.com/aquasecurity/go-pep440-version`
(already in `go.mod`; strip a trailing `.*` before validating an `==`/`!=` version; `===` accepts any string).
Shared with parse (`_req_dep`) and the code group (supply chain), so it lives outside this package.

### 4.5 posixpath (hooks)

`posixpath.dirname(rel)` → `path.Dir(rel)` **with `"."` mapped to `""`** (Python returns `""` for a bare
basename); `posixpath.basename` → `path.Base` (inputs never end in `/`); `posixpath.normpath(x)` → `path.Clean(x)`
(identical for every input here: `""`→`"."`, `"./x"`→`"x"`, `"a/../../b"`→`"../b"`; only a leading `//` differs).
`str.removeprefix("./")` → `strings.TrimPrefix`.

### 4.6 urllib.parse.urlsplit (`_exfil_recipient`)

Only `.hostname` is read. **Decision:** a regex helper, not `net/url` (Go's parser rejects inputs Python accepts,
e.g. `{`/`}` in the path or `%41` in the host, and this must not change the recipient decision). `hostOf(u)`:
netloc = text after `://` up to the first of `/?#`; drop everything up to and including the last `@`; if it
contains `[` → return `""` when there is no `]` (Python raises → None) else the bracketed text; otherwise
`rpartition(":")` keeps the left part when a `:` exists (`a:b:c`→`a:b`, `h.com:`→`h.com`); lowercase; empty →
None. Verified: `https://u:p@Host.Example:8443/x` → `host.example`; `https://x@@y.com/` → `y.com`;
`https://:80/x` → None.

### 4.7 hashlib, bisect, heapq, zipfile/tarfile, ipaddress

`hashlib.sha256(s.encode("utf-8")).hexdigest()` → `crypto/sha256` + `hex.EncodeToString`. `bisect_left(a, x)`
→ `sort.Search(len(a), func(i) bool { return a[i] >= x })`; `bisect_right` → `a[i] > x`. heapq, archives and
ipaddress are not used here.

---

## 5. Python semantics that do not translate

### 5.1 Code-point offsets (every column and every numeric slice)

Python indexes strings by code point; Go regex indices are bytes. Every `column`/`col` in §2.4, every
`_source_position` argument, every `[:n]` truncation in §1.4, and every window constant (`-48`, `-160`, `-60`,
`-80`, `+80`, `+120`, `-14`, `-20`, `+20`, `-40`, `4000`, `96`, `48`, `60`, `40`, `600`) counts code points.
Provide in `text.go`: `runeIdx(s, byteOff) int`, `byteIdx(s, runeOff) int`, `cutRunes(s, n)` (`s[:n]`),
`tailRunes(s, n)` (`s[-n:]`), `sliceRunes(s, lo, hi)` with Python clamping (negative → 0, past end → len).
Rule: convert a regex byte offset to a rune offset once, do all arithmetic in runes, convert back only to slice.
`_EXFIL_CODE_SPAN_RE.sub(" " * len(match))` must insert `utf8.RuneCountInString(match)` spaces so the blanked
sentence keeps the code-point length of the original; positions found in it are rune offsets into `raw`.
Also `len(content)` (`content_length`) and `body[:400]` are code-point counts. ASCII inputs make this invisible;
MaliciousSkillBench text is full of curly quotes, em dashes and emoji, so evidence truncation and columns diverge
without it.

### 5.2 `str.strip()`, `lstrip`, `rstrip`, `split()`, `isspace()`

Python whitespace = `\t\n\v\f\r\x1c\x1d\x1e\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000`.
Go `strings.TrimSpace`/`Fields`/`unicode.IsSpace` exclude `\x1c-\x1f`. Provide `pyIsSpace(r)`, `pyStrip`,
`pyLStrip`, `pyRStrip`, `pyFields` and use them for every no-argument `strip()`/`split()` in the group
(`_flatten_prose`, `_source_position`, `_plain_prose_blocks`, `_grant_tokens`, `_is_table_row`, `_ri_join_wrap`,
`_list_intro_index`, `_post_egresses`, `_data_exfil_findings`, `_clause_ends`, hooks `.strip()` on commands and
names, …). `rstrip(".,;:'\"")`/`rstrip("/")`/`lstrip("$")` with explicit sets map to `strings.TrimRight/TrimLeft`.

### 5.3 `str.splitlines()` (persistence `check`, hooks `_instruction_findings`, `_ri_characterized_remote`)

Splits on `\n \r \r\n \v \f \x1c \x1d \x1e \x85 \u2028 \u2029` and drops a trailing empty piece. After parse's
`_norm_newlines` only `\n` remains from the CR family, but `\v \f \x1c-\x1e \x85 \u2028 \u2029` still split in
Python while markdown-it's line maps do not count them, so `lines[start-1:end]` desynchronises from the parser's
spans in persistence and hooks whenever such a character appears earlier in the file. Provide `pySplitlines` and
use it exactly where Python does (instruction_exfil uses `split("\n")` everywhere else and must keep doing so).
This is a latent Python bug (§8.3); port it faithfully first.

### 5.4 `str.lower()`, `casefold`, `isalnum`

`.lower()` feeds dedup keys, selectors (`matched.lower()[:50]`, `akey`), SHA digests (`sentence.strip().lower()`,
`matched.lower()`) and host/local comparisons. `strings.ToLower` differs from Python only for U+0130 (`İ` → Python
`i̇` two code points, Go `i`) and has no final-sigma special case in either; accept. `casefold` is not used.
`str.isalnum()` (persistence `_clause_ends`) → `unicode.IsLetter(r) || unicode.IsNumber(r)` (Python: categories
L* and N*; Unicode-version drift is immaterial for apostrophe detection).

### 5.5 dict ordering, `sorted`, `min`

Insertion-ordered dicts: `totals` (SXV-028..031 cap notes), `counts` (`_cap_findings`), `sections`/`order`,
`coercion` (`setdefault` keeps the first match per lowercase cue; `min(values, key=start)` returns the first minimum
in insertion order; `sorted(coercion)` sorts the keys), `manifest_by_dir` (first manifest per dir). Use slices of
keys alongside maps. `sorted` is stable and compares `str` by code point, which equals Go's byte order for valid
UTF-8: `sort.Strings` is exact for `sorted(set(urls))`, `sorted(kinds)`, `sorted(g.raw)`, `sorted(servers)`,
`sorted(coercion)`. `sorted(hooks, key=(not isinstance(str), str(v)))`: strings first (byte order), then other
keys by their Python `str()` (yaml.v3 ints print identically with `fmt.Sprint`). `min(cred_hits, key=(line, col))`,
`sorted(cred_hits, key=(line, col))` → `sort.SliceStable`. `sorted(set(comments), key=(line, column))` → dedupe
then stable sort.

### 5.6 `%` formatting of output strings

All messages in §1.4 use `%d`/`%s` with ints and strings; `fmt.Sprintf("%d"/"%s")` is byte-identical. Two
non-obvious `%s` operands: `method.upper()` (`POST`/`GET`/`NON-HTTP`) and the SXV-042 selector (§5.7). No float
formatting anywhere in the group. Booleans never reach `%s`.

### 5.7 The SXV-042 selector formats a tuple

`"selector": "%s:%s" % (rule, akey[:50])` where `akey = (script.lower(), strong)` is a **tuple**; slicing a
2-tuple by `[:50]` returns the tuple, and `%s` renders Python's `repr`: `covert-bundled-script-run:('python
scripts/x.py', True)`. Reproduce with `pyReprStr(s)` (single quotes unless the string contains `'` and no `"`, then
double quotes; escape `\` and the chosen quote; `\n`/`\r`/`\t` as escapes; other characters verbatim — the
script text only contains `[\w./-]`, spaces, letters and possibly an apostrophe from `skill's`) followed by
`, True)` or `, False)`. Mark with `// ponytail: reproduces Python tuple repr in the selector; drop when the
Python side changes to akey[0]`.

### 5.8 `shlex`, `posixpath`, `urlsplit`, `bisect`

See §4.3-4.7.

### 5.9 Regex engine differences that matter for this corpus

RE2 `\b`/`\w`/`\d` are ASCII; Python's are Unicode. Effects: (a) a keyword adjacent to a non-ASCII letter
(`éignore`) matches `\bignore\b` in RE2 but not in Python; (b) `\w*` suffixes stop at the first non-ASCII letter
in RE2, shortening `directive_text`/`text`/`script`/`write_verb` evidence and, for `_EXFIL_ADDR_RE`, failing to
match a mailbox with a Unicode local part; (c) RE2 `\s` is `[\t\n\f\r ]` (no `\v`, no NBSP, no U+2028), so
`always\s+obey` fails across an NBSP in RE2 and passes in Python. **Decision:** stdlib RE2 for the 17 non-regexp2
lookaround rewrites and all plain patterns; measure on the frozen MaliciousSkillBench split and the golden corpus;
escalate a specific pattern to `regexp2` (whose `\b`/`\w`/`\s` are Unicode) only when the parity harness shows a
diff attributable to it. Case-insensitive matching: both engines use simple folding on the characters that appear
(`(?i)k` matches `K`, `(?i)s` matches `ſ`, `ß` never matches `ss`).

### 5.10 Exceptions and duck typing

`check` (exfil) wraps each engine in try/except → `defer recover()` per engine, emitting `check-error`.
`_tokens` `ValueError` → `(nil, error)`. `urlsplit` `ValueError` → `""`. `InvalidRequirement` → `false`.
`isinstance` checks → type switches; JSON numbers arrive as `float64`, TOML ints as `int64`, YAML ints as `int`
(only string/list/dict/None distinctions matter here). `getattr(x, "attr", default)` on the IR → plain field access
(tests build `SimpleNamespace` stand-ins only for two memory/linearity tests, which the Go tests replace with real
IR values). `zip(strict=True)` → equal-length slices by construction.

---

## 6. Test port plan

No fixture files exist on disk for this group: every Python test writes its package inline through the
`make_package(files)` fixture (`tests/conftest.py`: `tmp_path/pkg/<rel>` written UTF-8 with newlines preserved,
or raw bytes) and then runs `parse.parse_package(ingest.build_package(root))`. The one external corpus
(`bench/vuln/v2-instruction-exfil`, `test_v2_bench_fixture_end_to_end_locks_in_sxv011`) is absent locally and
skipped. The Go tests therefore keep the inline strings as the contract (they are the fixtures) and never
re-derive expectations.

| Python file | Items collected | Belongs to this group | Go file | Driver |
|---|---|---|---|---|
| `tests/test_instruction_exfil.py` | 262 (241 functions; parametrised: 2+3+2+13+5+2) | all 262 (1 skipif) | `internal/instruction/exfil_test.go` | `instruction.CheckExfil` on a package built by core's test helper `makePackage(t, map[string]string)` (ingest+parse in `t.TempDir()`); one `TestXxx` per Python function, `t.Run` per loop/param case named by the Python id |
| `tests/test_hooks.py` | 143 (100 functions) | all 143 | `internal/instruction/hooks_test.go` | `checks.Run` (core), because the Python `_run` asserts no `check-error` and filters `SXV-006/012/013`, `analysis-incomplete`, `coverage-note` (the coverage note comes from core's coverage check) |
| `tests/test_identity_persistence.py` | 51 | 28 (the `run_checks` tests); 23 `_opengrep` tests are the code group's (SXV-005 OpenGrep rules) | `internal/instruction/persistence_test.go` | `checks.Run`, filter `SXV-005` |
| `tests/test_os_persistence.py` | 41 | 0 (all OpenGrep, SXV-039/005 script rules → code group) | — | — |
| `tests/test_batch3_microcorpus.py` | 12 | 5 cases depend on this group (`identity-instruction`, `hook-install`, `external-hook`, `floating-mcp`, `adjacent-benign`) | core's microcorpus test | `checks.Run` |
| `tests/test_llm_review_core.py::test_native_review_uses_parser_lines_and_exact_quotes` | 252 | output-llm group; pins `FlattenProse`/`SourcePosition` and SXV-028 line/col under `\u2028 \u2029 \x85 \v \f`, `\r\n`, `\r` | output-llm | consumes this group's exported helpers |
| `tests/test_sarif_release.py` | 48 | 4 items use the `directive` fixture / `_directive_findings` (lines 122-149, 153, 379) | output-llm | `CheckExfil` → pick SXV-028 |

Total items to port inside this group: **433** (262 + 143 + 28). Timing/memory tests (`test_rob1_blank_padding_is_not_quadratic`
< 3 s, `test_sxv011_nonhttp_egress_regex_is_linear` < 1 s, `test_unclosed_html_comment_scan_is_linear` < 1 s,
`test_sxv043_one_large_paragraph_is_not_quadratic` < 3 s) port as behaviour assertions plus the same wall-clock
bound; `test_instruction_softbreak_flattening_has_bounded_memory` (tracemalloc < 8 MiB) ports as the output
assertion only, with a `// ponytail:` note (Go has no per-call peak-allocation probe worth adding).
`test_engine_crash_does_not_disable_the_credential_engine` swaps an entry of `exfilEngines` with a panicking
func. Assertions use `testify/require` for structure (`Equal` on evidence maps, `Len`, `Contains`) and
`assert.ElementsMatch` where Python compares sets.

Parity beyond unit tests: `tools/parity` (core) runs the Python CLI and the Go CLI over the golden corpus and the
frozen MaliciousSkillBench test split (`benchmark-reports/frozen-dataset/test_final.jsonl`, 1,384 records) and
diffs findings; §7 gives the attribution key.

---

## 7. Parity hooks

A diff in the CLI `--json` output attributes to this group when the differing finding has
`vector ∈ {SXV-005, SXV-006, SXV-011, SXV-012, SXV-013, SXV-027, SXV-028, SXV-029, SXV-030, SXV-031, SXV-041,
SXV-042, SXV-043}`, or `vector == ""` with `rule == "findings-capped"` and a message naming one of those vectors,
or `rule == "check-error"` with message prefix `instruction_exfil skipped `, or `rule == "analysis-incomplete"`
with message prefix `hook/MCP configuration analysis is incomplete`. Fields influenced: `vector`, `rule`,
`severity` (SXV-011 critical/high, SXV-041 high/medium, SXV-042 high/medium), `path`, `line`, `column`
(present only for SXV-005/006/027/028-031/042/043), `message`, and every `evidence.*` key in §1.4. `title`,
`cwe`, `tier` come from the registry (core) and are not this group's. In SARIF, the same findings surface as
results whose `ruleId` derives from these vectors with `region.startLine`/`startColumn` from `line`/`column`
(SARIF group), and `evidence.col` is what the release test compares against `startColumn`.

Because evidence is a JSON object, the harness must compare parsed JSON (key order is Python insertion order
vs Go's sorted encoding); if the harness diffs text, core must encode evidence with an insertion-ordered encoder.

---

## 8. Risks and open questions

1. **Byte vs code-point offsets (highest parity risk).** Every column and every truncation is code-point based
   (§5.1). Recommendation: implement the rune helpers first, make the parity corpus include non-ASCII directive
   lines (curly quotes, em dashes, emoji before the match) and assert `column`/`evidence.col`/`snippet` equality.
2. **Unicode `\b`/`\w`/`\s` divergence (§5.9).** Recommendation: RE2 by default; the harness reports diffs per
   pattern (log the pattern name with each finding in a debug mode); escalate individual patterns to regexp2 only
   on observed diffs. Expected impact on the frozen split: low (English prose), non-zero for `_EXFIL_ADDR_RE`
   mailboxes and `\w*` evidence extents.
3. **`splitlines()` desync in persistence/hooks (§5.3).** Faithful port required for parity; file an upstream
   skill-xray fix (`text.split("\n")`) to be applied on both sides in one step after parity is green.
4. **SXV-042 selector tuple repr (§5.7).** Port the quirk; same upstream-fix procedure as (3).
5. **JSON key order of `evidence`.** Go `encoding/json` sorts map keys; Python keeps insertion order.
   Recommendation: the parity harness compares parsed JSON; SARIF is unaffected (evidence is not emitted there as a
   map, verify with the output-llm spec).
6. **Dependence on parse fidelity.** Every engine's line/column derives from `prose_spans`, `html_prose`,
   `html_comments`, `code_spans`, `links`. Recommendation: the parse group ships a span-dump parity check (Python
   vs Go IR spans per file) before this group's findings are compared, so a diff is attributed to the right group.
7. **Cross-group ordering.** `InstallerIdiom` and `DropHostRE.MatchString` (code group) gate SXV-041 severity and the SXV-043
   telemetry excuse. Recommendation: implement those two in a small `internal/codelane` (or `internal/hosts`)
   package first; until then this group's tests for `test_sxv041_first_party_installer_in_prose_is_medium_not_high`
   and the ngrok case in `test_sxv043_recipient_and_host_excuses` cannot pass.
8. **YAML non-string keys.** `hooks: {SessionStart: [], 7: []}` must reach `_hook_findings` as a mapping with a
   non-string key. Corrected: `parse._plain` applies `str(k)` at every depth, so the key arrives as `"7"`, an unknown
   event, and the entry is `malformed_hook_entry`; `map[string]any` is sufficient (00-overview D14).
9. **`Text` None vs "" and `Pattern` None vs "".** Both distinctions change behaviour (`_reaches_network`,
   lane membership, `_local_candidate`). Decision: `Text *string` and `Pattern *string` in the IR (00-overview D3).
10. **regexp2 cost.** Three patterns run over bounded windows (≤ 4,000 code points per acquisition scan, ≤ 320
    chars per negated-run clause); the Python linearity tests bound the same work. Recommendation: no match timeout;
    cache the dynamic `_NEG_RUN_PREFIX` compile per script string (bounded by distinct scripts per file).
11. **PEP 508 edge cases.** Garbage versions (`tool==abc`) are `InvalidRequirement` in Python (→ floating) and
    would be a "pin" with a naive split. Recommendation: validate versions with go-pep440-version as in §4.4.
12. **`urlsplit` edge cases.** IPv6 hosts with dots (`::ffff:1.2.3.4`) and percent-encoded hosts are accepted
    divergences (the bracket/`[<>{}$\[\]]` checks reject them anyway). No corpus record is expected to hit them.
13. **`check-error` message.** Contains the Python exception class name; not reproducible and never present in
    oracle output. Recommendation: `%T` of the recovered value; exclude `check-error` from parity.
14. **Missing external corpus.** `bench/vuln/v2-instruction-exfil` pins the 4-token SXV-011 case at line 19 and is
    absent. Recommendation: obtain it for the parity corpus if it exists elsewhere; otherwise rely on the frozen split.
15. **Toolchain.** `port-to-go/go.mod` declares `go 1.26.0`; the machine has `go1.25.5` (brief says 1.24.1) and
    mcp-xray pins 1.25.5. Recommendation: set `go 1.25` in `go.mod` so `make build` does not trigger a toolchain
    download.
16. **Engine order and dedup.** `_cap_findings` (own) and `CapFindings` (shared, sorts) differ; instruction_exfil
    output order is engine order and is only normalised by the caller's `dedupe_findings`. Recommendation: keep both,
    do not sort inside `CheckExfil`; the parity harness compares sorted output anyway.

## Wave 9 errata (2026-09-20, oracle `9b7960f`)

Guards measured on the ClawHub sweep and the frozen benchmark; each has a pin in `tests/test_wild_precision.py`
and `internal/instruction/wild_test.go`.

1. **`_quoted(raw, start)`**: `before = raw[:start].rstrip()` ends with `"`, `'`, U+201C, U+2018 or U+00AB
   and `_CITATION_FRAME_RE` matches `before[:-1]` (whitespace kept): a list marker after whitespace and
   followed by whitespace (`(?:^|\s)(?:[-*+]|\d+[.)])\s+$`, so a bare `*` of emphasis is not a marker), a
   verb of saying, like/such as, e.g., for example or a noun for phrases (phrase, pattern, string, text,
   term, word, instruction) then `\s*$`, or another quoted fragment (`["'“”‘’«»],?\s*$`, the `"a," "b"`
   list). No comma or colon alone ("Remember, \"ignore …\"" is an order). In `_directive_findings` a
   citation counts as `described` for every vector (SXV-028..031). Go: `quoted`, `citationFrameRE`
   (`pytext.PyRE`, `\b` spelled as a consumed non-word code point, `\d` as `\p{Nd}`).
2. **SXV-028 only**: skip when `_BARE_WEAK_NOUN_RE` matches `m.group(0).strip()` (`^(?:ignore|disregard|forget|
   override|overrule|supersede|replace|reset|wipe)\s+(?:rule|guideline|constraint|direction|command|order|message)s?$`)
   or `_REPORTED_SPEECH_RE` matches the text before the match: conditional reported speech whose clause
   reaches the saying verb, `\b(?:if|when|whenever|should|in case)\b[^.,;\n]{0,60}\b(?:asks?|tells?|says?|tries|
   attempts?|instructs?|demands?|wants?|urges?)\s+(?:(?:you|it|the (?:agent|model|assistant|ai|bot))\s+)?(?:to\s+)?
   ["'“‘«]?\s*$` ("if a user asks you to ignore …", also quoted); a comma ends the clause, so "If you
   understand this, I want you to …" and "the developer asks you to …" are the attack. Both
   case-insensitive. Go: `pytext.PyRE`; the 1..60 gap is one consumed non-word code point, then
   optionally up to 58 more and a non-word last one.
3. **Developer-mode guard**: the gap between the model name and "developer mode" is `[^.\n|]{0,80}`; a table
   cell boundary ends the search.
4. **`_in_frontmatter(art, start_line)`** = `start_line < art.frontmatter_end_line`. The directive loop and the
   SXV-042 loop set `previous = ""` for a frontmatter block instead of `raw`; the SXV-043 loop sets
   `previous = ""` when the raw is a heading or the block is frontmatter. A quoted `description:` scalar is no
   longer an example intro for the first body block.
5. **SXV-042 covert cue**: `covert` is the first `_COVERT_RUN_CUE_RE` match in `joined` that is not `_quoted`.
   `_COERCED_RUN_CUE_RE` gained: first action must be to run; without (user|human|operator) prompting or
   without prompting the (user|human|operator) (not "without any prompting", which describes a `--yes` flag);
   hidden runtime dependenc(y|ies); evals only pass when/if/once/after; before producing/generating/... the
   response/answer/reply/output; do not explain/describe/mention/discuss the pre-flight/setup/preparation/
   bootstrap/warm-up; (is|as) a pre-condition (for|of|to); must be warmed up.
6. **Antipattern fences**: unchanged; `_ANTIPATTERN_RE` stays the original six-phrase list used by
   `_fence_labelled_antipattern` for SXV-011 (the code-lane exclusion was reverted, code.md wave 9 item 2).
