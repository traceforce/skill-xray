# Porting specification: group `parse`

> **Errata (00-overview).** Read this spec with these substitutions; `00-overview.md` is binding.
> - Names: the IR types are `parse.Package`, `parse.Artifact`, `parse.Markdown`, `parse.Span{Start, End}`;
>   the entry point is `parse.Parse(pkg *ingest.Package) *parse.Package` (the type name `Package` is taken).
>   `Link{Href, Label; Line}`, `HTMLComment{Body; Line, Column}`, `HTMLProse{Text; Line}` (its own type),
>   `HTMLFragment{Text; Line, Column}` for `HTMLUninspectable`. `Text *string` (nil == None),
>   `FrontmatterEndLine int` (0 == None), `LedgerExceptions []ingest.LedgerEntry` (`Detail *string`), and a new
>   `FrontmatterKeys []string` (top-level keys in document order, for obfuscation's `fm.items()` order).
> - `parse` also exports `ManifestIndex(p) map[string]*Artifact` and `GoverningManifest(index, rel) *Artifact`
>   (Python `code_lane._manifest_index/_governing_manifest`, behaviour in code.md §2.1).
> - `checks/preproc.py` -> `internal/preproc` (not `internal/checks/preproc`).
> - `pyIsSpace`, `pyFindAll`, `unquote`, `casefold` etc. come from `internal/pytext` (`pytext.IsSpace`,
>   `pytext.Space`, `pytext.CaseFold`, `pytext.Unquote`); the non-POSIX shlex of §4.6 is
>   `pytext.ShlexTokens(s, "", false)`.
> - §4.4: PEP 508 is the shared `internal/pep508` (`Parse(s) (Requirement, error)`; `SpecifierString()` is
>   the sorted comma join), validating versions with `github.com/aquasecurity/go-pep440-version` (already in
>   go.mod; its regex is packaging's `VERSION_PATTERN`). Hand-porting PEP 440 is dropped.
> - §7 correction: parse-phase ledger entries never reach `--json` `ledger.exceptions`. `ParsedPackage`
>   copies `pkg.ledger_exceptions` and `cli.py:239` builds the ledger before `parse_package` runs; the
>   entries feed only the coverage check and correlate's context digest. `detail` text is therefore an
>   IR-dump concern (`tools/parity dump-ir`), never an output field.
> - The Python side of `--dump-ir` is `tools/parity/py_dump_ir.py` (imports `skill_xray.parse`); nothing under
>   `skill-xray/` changes.
> - Toolchain: `go 1.26.0` (R9 superseded). Test helper: `testutil.MakePackage(t, map[string]string) string`
>   then `parse.Parse(ingest.BuildPackage(root))`.

Python sources: `src/skill_xray/parse.py` (1,471 lines) and `src/skill_xray/checks/preproc.py`
(127 lines). Oracle versions on this machine: Python 3.13.2, markdown-it-py 4.0.0 (CommonMark
0.31.2), ruamel.yaml 0.18.15, tree-sitter 0.26.0 + tree-sitter-bash 0.25.1, packaging 24.2.

Go packages: `internal/parse` (everything in `parse.py`) and `internal/preproc`
(`checks/preproc.py`). `preproc` imports `internal/parse` and `internal/findings` (core group);
`parse` imports `internal/ingest` (core: `Artifact`, `Package`) and `internal/pyast` (code group,
see 4.9). No interfaces, no factories: every Go function below exists because the Python one does
and the parity harness or the tests need it.

Conventions fixed for the whole group:

- Every `line` is 1-based and counted in the newline-normalised text (`\r\n` and lone `\r` become
  `\n` once, in `parse.NormNewlines`). Every `column` is a 1-based **code-point** index (Python
  indexes `str` by code point); Go computes byte offsets and converts with
  `utf8.RuneCountInString(line[:off]) + 1`. Every string length that reaches output
  (`command_length`, the `[:80]`, `[:160]`, `[:400]` caps) is a code-point count/slice.
- `pyIsSpace(r) = unicode.IsSpace(r) || 0x1c <= r <= 0x1f` replaces `str.isspace`, `str.strip()`,
  `str.split()` (with no argument) and the Python regex `\s`; the regex class is
  `[\t\n\v\f\r\x1c-\x1f \x85\p{Z}]` (verified on the oracle: Python `\s` matches U+001C, U+00A0,
  U+000B, U+2028 and not U+FEFF or U+200B).
- Python `\d` becomes `\p{Nd}` and Python `\w` becomes `[\p{L}\p{N}_]` (verified: `\d` matches
  U+0663, `\w` matches U+00E9 and U+2167).
- `re.match` becomes a `^`-anchored pattern; `fullmatch` becomes `\A...\z`.
- Diagnostics are `(code, detail)` pairs: Go `type Diagnostic struct{ Code string; Detail *string }`
  (nil for Python `None`). They are mirrored into the ledger as
  `{"outcome":"unresolved","phase":"parse","reasonCode":code,"detail":detail,"path":rel}`.

## 1. Public surface

Import sites outside the group (grep of `src/` and `tests/`):
`cli.py` and `__init__.py` import `parse_package`, `Artifact`, `Package`;
`checks/code_lane.py` imports `MAX_PY_CHARS`; tests import `parse` as a module and call
`parse_package` (99 sites), `parse_markdown`, `parse_frontmatter`, `parse_grants`, `parse_shell`,
`classify_manifest`, `_parse_requirements`, `_load_structured`, `_table_lines`, `MAX_PREPROC_TOKENS`,
`_MD` (monkeypatched to force the fallback path), `_PKG_BUDGET`, `_parse_md`.
`checks/__init__.py` registers `preproc.check`; `capability.py` reads the rule names
`preproc-inline-bang`/`preproc-fenced-bang`.

| Python | Go | Notes |
|---|---|---|
| `parse_package(pkg)` | `parse.Parse(pkg *ingest.Package) *Package` | entry point |
| `parse_markdown(text, line_offset)` | `parse.Markdown(text string, lineOffset int) (*Markdown, string)` | second value is the error name, `""` for none |
| `parse_frontmatter(text)` | `parse.Frontmatter(text) (values map[string]any, keyLines map[string]int, err string)` | `values == nil` is Python `None`; an empty block gives an empty non-nil map |
| `parse_grants(fm)` | `parse.Grants(fm map[string]any) []Grant` | |
| `parse_shell(text)` | `parse.Shell(text) (*syntax.File, []Span, bool)` | third value false = refused (Python `(None, None)`) |
| `classify_manifest(cfg)` | `parse.ClassifyManifest(cfg any) string` | `""` for Python `None` |
| `MAX_PY_CHARS` (524288) | `parse.MaxPyChars` | imported by code group |
| `MAX_PREPROC_TOKENS` (25) | `parse.MaxPreprocTokens` | test pins `== FINDING_CAP` |
| `_PKG_BUDGET` (60 s) | `parse.PkgBudget time.Duration` | package-level var so a test can set it negative |
| `_parse_requirements`, `_load_structured`, `_table_lines`, `_scan_inline_preproc`, `_scan_fenced_preproc`, `_fallback_links` | `parseRequirements`, `loadStructured`, `tableLines`, `scanInlinePreproc`, `scanFencedPreproc`, `fallbackLinks` | unexported, tested in-package |
| `preproc.check(parsed)` | `preproc.Check(p *parse.Package) []findings.Finding` | |

Data shapes (field names are the attribute names other groups read; none of these structs is
serialised directly except via the ledger and findings):

```
type Preproc struct { Kind string /* "inline"|"fenced" */; Code string; Line, Column int; Runs bool; Info string }
type Link struct { Href, Label string; Line int }                // Python (href, text, line)
type Fence struct { Info, Content string; Line int }              // (info, content, line); Info "" for indented code
type Span struct { Start, End int }                            // inclusive 1-based (start, end) tuples
type HTMLTag struct { Name string; Line, Column int; Closing bool; Attrs [][2]string }
type HTMLComment struct { Body string; Line, Column int }
type HTMLFragment struct { Text string; Line, Column int }        // html_uninspectable (text, line, column)
type HTMLProse struct { Text string; Line int }                   // html_prose (projected text, line)
type Markdown struct {
    Links []Link; Fences []Fence
    FenceSpans, CodeSpans, ProseSpans, ReferenceSpans, ParagraphSpans []Span
    Preproc []Preproc; PreprocCounts struct{ Inline, Fenced int }
    HTMLComments []HTMLComment; HTMLTags []HTMLTag; HTMLProse []HTMLProse; HTMLUninspectable []HTMLFragment
    HasHTML, HasUninspectableHTML bool
    HTMLHidesContent bool  // an uninspectable fragment carried text, or a construct the inspector could not resolve
}
type YamlTag struct { Tag string; Line, Column int }
type Grant struct { Tool string; Pattern *string; Raw string; Allowed, Broad, Parsed bool }
type Dep struct { Name, Specifier string; Pinned bool; Raw string; Line *int }   // dict in Python; "line" key absent for npm/pyproject
type Artifact struct {
    Rel, Kind string; Text *string /* nil == None */; Raw []byte /* nil when ingest read nothing */
    Frontmatter map[string]any /* nil = None */; FrontmatterKeys []string /* document order */; FrontmatterKeyLines map[string]int; FrontmatterEndLine int /* 0 = None */
    UnsafeYamlTags []YamlTag; Grants []Grant /* nil = None */; Markdown *Markdown; FallbackLinks []Link
    Preprocessing []Preproc; PreprocessingCounts struct{ Inline, Fenced int }
    PyTree *pyast.Module; ShellTree *syntax.File; Config any; ManifestKind string; Deps []Dep /* nil = None */
    Diagnostics []Diagnostic
}
type Package struct { Identity, Name string; Artifacts []*Artifact; ByRel map[string]*Artifact; Refs []Ref; LedgerExceptions []ingest.LedgerEntry }
type Ref struct { From, To string; Line int }   // JSON keys "from","to","line"
```

Consumers of each field, so the implementer knows which shapes are load-bearing: `Text`, `Rel`,
`Kind`, `Raw`, `Diagnostics`, `ByRel`, `Artifacts`, `LedgerExceptions` by every check, correlate,
disposition, sarif; `Markdown.Fences` by code_lane; `FenceSpans`/`CodeSpans` by instruction_exfil and
supply_chain; `ProseSpans` by hooks, persistence, obfuscation, instruction_exfil, llm/judge;
`ParagraphSpans` by capability; `ReferenceSpans` and `HTMLProse` by obfuscation and
instruction_exfil; `HTMLComments` and `HTMLUninspectable` by instruction_exfil (SXV-027 line and
column reach output); `Links`/`FallbackLinks` by `_resolve_refs` and llm/judge; `HTMLTags` and
`HasHTML` only by tests; `Frontmatter`, `FrontmatterKeyLines` by capability, grants, hooks, judge;
`FrontmatterEndLine` by instruction_exfil and obfuscation; `UnsafeYamlTags` by metadata (SXV-034
line, column and `Tag` string reach output); `Grants` by grants, capability, opengrep_bridge;
`Config`/`ManifestKind` by hooks and supply_chain; `Deps` by supply_chain; `PyTree` by
opengrep_bridge (`trees[name] = artifact.py_tree`); `ShellTree` by nothing outside parse (tests
only); `Preprocessing`/`PreprocessingCounts`/`Refs` by preproc and judge.

## 2. Behaviour inventory

Places where line numbers or columns are computed are marked **[line]** / **[column]**.

### 2.1 Newline and frontmatter bounds

- `_norm_newlines(text)` -> `NormNewlines`: `\r\n` then `\r` to `\n`. Applied once in
  `Artifact` construction and again (idempotently) in `parse_markdown` and `_fm_bounds`.
  Pins: `test_parse.py::test_preprocessing_cr_only_line_numbers` (line 3 for `a\r\rrun !`id`\r`),
  `test_preproc.py::test_inline_preprocessing_uses_normalized_crlf_location` (line 5, column 3).
- `_fm_bounds(text)` -> `fmBounds(text) (lines []string, hasOpen bool, end int /* -1 = None */)`.
  The first line, with every leading U+FEFF stripped, must `rstrip()` (pyIsSpace) to exactly `---`
  and must not start with space or tab; the terminator is the first later line, not starting with
  space or tab, whose `rstrip()` is `---` or `...`. **[line]** `end` is a 0-based line index.
  Pins: `test_frontmatter_bom_and_crlf`, `test_frontmatter_indented_delimiter_not_terminator`
  (an indented `  ---` inside a block scalar is content), `test_frontmatter_dot_terminator_and_key_lines_wired`.
- `_body_and_offset(text)` -> `bodyAndOffset`: without an open and close pair returns the whole
  text and offset 0; else the lines after `end` joined by `\n` and offset `end+1`. **[line]** The
  offset is added to every body line number.

### 2.2 Markdown (`parse_markdown`)

Normalise newlines, parse with CommonMark (raw HTML on; no tables, linkify, typographer or
strikethrough), then walk the block token stream in document order:

- `fence` / `code_block`: append `Fence{info, content, line}` where `info` is the fence info string
  `strip()`ped (`""` for indented code), `content` is the block body ending in one `\n` (fence
  content has up to the opener's indent removed per line; indented code has the 4-space or tab
  indent removed), and **[line]** `line = map[0] + 1 + offset` (opener line for fences, first
  content line for indented code). `CodeSpans` gets `(map[0]+1+off, map[1]+off)`; `FenceSpans` the
  same for fences only. The 0-based lines `[map[0], map[1])` are added to `preprocExcluded`.
  Pins: `test_markdown_distinguishes_fenced_and_indented_code_spans` (`code_spans == [(1,3),(5,5)]`,
  `fence_spans == [(1,3)]`), `test_markdown_indented_code_block_captured`, `test_markdown_links_and_fences`.
  If `info` starts with `!`: **[column]** `column = sourceLines[map[0]].find(markup) + 1`
  (code-point index of the first occurrence of the marker run, e.g. "```", in the raw opener line;
  1 if absent); `executable` = the content `strip()`s to non-empty (see 5 for `splitlines`).
  Executable bang fences increment `PreprocCounts.Fenced`; the first 25 become
  `Preproc{"fenced", content, line, runs=true, column, info}`.
  Pins (`test_preproc.py`): `test_bang_fence_reports_nonempty_commands` (line 4, info `!sh`),
  `test_blockquoted_bang_fence_reports_source_column` (column 3),
  `test_unicode_separator_does_not_shift_bang_fence_column` (U+2028 is not a line break; column 3),
  `test_bang_fence_variants_preserve_opener_location` (`   ```!sh` -> 4, `~~~!bash extra` -> 1),
  `test_indented_bang_fence_preserves_opener_column`, `test_tilde_bang_fence_is_executable`,
  `test_fenced_preprocessing_ir_and_findings_are_capped` (25 kept, count 28),
  `test_empty_preprocessing_constructs_do_not_create_cap_notes` (a blank bang fence is neither
  counted nor kept).
- `html_block`: `HasHTML = true`; `raw = "\n".join(sourceLines[map[0]:map[1]])` (the raw source
  lines, not the token content); `inspectHTML(raw, line, md, column=1)` (2.4); `map[0]` is added to
  `blockStarts`.
- `inline`: `hasInlineHTML` = any child of type `html_inline`. If the token has a map and no inline
  HTML: `ProseSpans` gets `(map[0]+1+off, map[1]+off)`; if the previous token is `paragraph_open`
  and `tok.level == 1` (a top-level paragraph: not inside a list or blockquote, not a heading) the
  same span goes to `ParagraphSpans`; `map[0]` is added to `blockStarts`. In every case
  `raw = "\n".join(sourceLines[map[0]:map[1]])` and `scanInline(tok, line, md, raw)` (2.3).
  An inline token containing inline HTML contributes no prose span and no block start.
- `table_open`: never produced by the commonmark preset (verified: active block rules are code,
  fence, blockquote, hr, list, reference, html_block, heading, lheading, paragraph). Dead branch;
  do not port. Table exclusion for preprocessing is entirely `tableLines` (2.5).

After the walk, for every reference definition (`env["references"]`, keyed by normalised label,
first definition wins, each with `map = [defLine, defLine+1)`), `ReferenceSpans` gets
`(map[0]+1+off, map[1]+off)` in first-seen order (verified: `[r]: refs/x.md 'T'` on 0-based line 15
gives `map [15, 16]`). Then `inline, total = scanInlinePreproc(text, off, preprocExcluded,
markdownExclusions=true, blockStarts)` is appended to `Preproc` and `PreprocCounts.Inline = total`.

Failure: Python returns `(None, "recursionerror" | "memoryerror")` when the parser raises. The Go
parser cannot fail, so `Markdown` never returns an error (8/R4); the fallback functions still exist
and are unit-tested directly.

Ordering: `Fences`, spans and `Links` are in document order; `md.Preproc` holds the fenced tokens
first, then inline tokens in line order (`_parse_md` reorders anyway, 2.7).

### 2.3 `_scan_inline(inline, line, md, source)`

`children` is the flat inline child list (markdown-it emits emphasis as flat open/close tokens, so
breaks inside emphasis are children, breaks inside code spans are not). If any child is
`html_inline`: `HasHTML = true` and `inspectHTML(maskInlineCode(source, children), line, md, 1)`.

`maskInlineCode` blanks each `code_inline` child in `source` with spaces (newlines kept):
`marker = child.markup or "`"`, `needle = marker + content + marker`; `start = source.find(needle,
cursor)`; if not found, `start = source.find(marker, cursor)` and `end = source.find(marker,
start+len(marker))`; else `end = start + len(needle) - len(marker)`; skip the child if either index
is -1; blank `[start, end+len(marker))` and move `cursor` past it. `content` is markdown-it's
code-span content: the text between the runs with `\n` replaced by a space, then one leading and
one trailing space removed when both are present and the content is not all spaces (verified:
`` `` a\nb `` `` -> markup "``", content "a b"). Pin: `test_inline_html_mapping_skips_identical_code_span_text`
(`` `<b>` <b>x</b> `` -> tag at column 7).

Then for each child `j`: `softbreak`/`hardbreak` increments `line` **[line]**; `link_open` appends
`Link{href, text, line}` with `href = attrs["href"]` (`""` if absent) and `text` = concatenation of
`children[k].content` for `k` after `j` up to the next `link_close` (text tokens carry decoded
content, `&amp;` -> `&`; `strong_open`/`em_open`/`link_close` carry `""`; `code_inline` its content;
`html_inline` the raw tag; `image` its alt text; breaks `""`). Pins:
`test_markdown_link_text_includes_formatting` (`[**admin**](x.md)` -> `admin`),
`test_markdown_link_line_in_multiline_paragraph` (lines 1 and 2), `test_markdown_many_links_no_quadratic_blowup`
(20k links, linear label collection), `test_markdown_line_offset_applied`. Reproduce the Python
quirk: a newline inside a code span is not a break token, so a link after a multi-line code span
keeps the pre-span line (verified: `[](empty) `x\ny` [after](z)` puts `after` on line 1).

### 2.4 HTML inspection (`_InspectableHTML`, `_inspect_html`, `_project_html`)

`inspectHTML(fragment, line, md, column)` runs a tolerant HTML tokenizer over the fragment and, in
token order, keeps three flags: `fullyInspected` (false once a construct could not be resolved),
`unknown` (a tag or attribute outside the presentational set) and `text` (content the prose and
link models never saw):

- start tag: `sawMarkup = true`; name lowercased; attrs `(name.lower(), value or "")` in source order
  with duplicates kept; `HTMLTags += {tag, line + tagLine - 1, sourceColumn, false, attrs}` where
  `tagLine` is the 1-based line of `<` within the fragment and `sourceColumn = col0 + (column if
  tagLine == 1 else 1)` (col0 = 0-based code-point column of `<`). Duplicate attribute names ->
  `fullyInspected = false`. A tag outside `_PRESENTATIONAL_HTML` (the 66-name set in the source)
  and `subject` -> `unknown = true`. Then per attribute: a modelled attribute (`_GLOBAL_HTML_ATTRS`:
  class, dir, id, lang, role, title, plus `_TAG_HTML_ATTRS[tag]`, on a known tag) named `href`,
  `src` or `cite` whose `compact` value (below) has the scheme `data`, `javascript` or `vbscript`
  before the first `:` -> `fullyInspected = false`; any other attribute whose name starts with `on`
  or whose value has such a scheme -> `fullyInspected = false`; any other unmodelled attribute ->
  `unknown = true`, and `text = true` when it names a reference on an unknown tag (`href`, `src`,
  `srcset`, `data`, `poster`, `action`, `formaction`, `cite`, `background`, `longdesc`,
  `xlink:href`, `ping`) or when its value is a URL (`://`, a leading `//` or a scheme followed
  directly by its payload, which a CSS `name: value` declaration is not) or holds at
  least two words of letters (runes, with the punctuation around a token trimmed first). The scheme and URL tests run on every comma-separated
  candidate of the value, since `srcset` names several; a `style` value has its CSS escapes decoded, then
  every `url()` argument tested as a URL, then is read per `;`-separated declaration with the
  property name before its `:` ignored. An unknown tag stops here. `code`/`pre` push onto
  `codeStack`. `target = href` for `a`, else `src`; if non-empty: `compact = lower(removeAll(
  [\x00-\x20]+, target))`; for `img`/`source`, `compact` starting with `//` or matching
  `^[a-z][a-z0-9+.-]*:` -> `fullyInspected = false`; for `a`, push `{target, label, line + tagLine
  - 1}` on `anchors`.
- self-closing tag `<x .../>`: as a start tag; then pop `codeStack` if `code`/`pre`; if `a`, pop the
  anchor and append `Link{target, strip(join(label)), line}`.
- end tag: `sawMarkup`; `HTMLTags += {tag, line + tagLine - 1, sourceColumn, true, ()}`; a
  non-presentational tag other than `subject` -> `unknown = true`; `code`/`pre` must equal the
  stack top (else `fullyInspected = false`) and pop; `a` pops the anchor into `Links` (label
  `strip()`ped).
- text: appended to every open anchor's label (all nested anchors receive it); a token that is not
  whitespace sets `text = true`.
- comment: `sawMarkup`; `HTMLComments += {data, line + cLine - 1, sourceColumn}`. A bogus comment
  `<!foo>` is a comment with data `foo` (both Python's html.parser and x/net/html agree).
- doctype (`<!DOCTYPE`), processing instruction (`<?...>`), marked section (`<![...`): `sawMarkup`
  and not inspected.

After feeding: unclosed anchors or code tags -> `fullyInspected = false`; a tokenizer panic ->
`fullyInspected = false`. If `!sawMarkup || !fullyInspected || unknown`: `HasUninspectableHTML =
true`, `HTMLUninspectable += {fragment, line, column}`, and `HTMLHidesContent = true` when
`!sawMarkup || !fullyInspected || text` (unknown tags or attributes alone, with nothing hidden,
leave it unchanged); else `HTMLProse += {projectHTML(fragment), line}`.

`projectHTML(fragment)`: iterate matches of regex 3; text between matches is kept verbatim, or
blanked (`blankSource`: every non-`\n` code point -> space) while `codeDepth > 0`; a tag token whose
name (regex 4) is `code`/`pre` changes `codeDepth` (+1 open, -1 close, 0 when the token ends in
`/>`, floor 0) and is blanked; an entity token outside code is `html.unescape(token)` with `\r`,
`\n` -> space, right-padded with spaces to `len(token)` code points and sliced to `len(token)` code
points (rune slice, the decoded entity may be 1 or 2 code points); anything else is blanked. The
tail is kept or blanked by `codeDepth`.
Pins: `test_presentational_html_link_is_parsed` (`("refs/x.md","sub",4)`),
`test_unquoted_html_link_preserves_label`, `test_html_media_source_is_not_a_document_link`,
`test_inert_prompt_placeholder_tag_is_source_mapped` (`("subject",4,1,False,())`,
`("subject",4,18,True,())`), `test_behavioral_or_unknown_html_remains_incomplete` (every case ->
`HasUninspectableHTML`), `test_markdown_html_comment_is_source_mapped` (`(" ignore all prior ",4,1)`),
`test_blockquoted_html_comment_preserves_source_column` (column 3),
`test_blockquoted_inline_html_preserves_source_column` (column 10).

### 2.5 Line-based Markdown helpers (used after a successful parse and in the fallback)

All operate on `lines = text.split("\n")`, 0-based indices, code-point columns.

- `blockquoteParts(line) -> (content, prefixLen, depth)`: repeatedly consume up to 3 spaces, a
  `>`, and one optional space or tab; return `(line, 0, 0)` when no `>` is found at all, otherwise
  the remainder, its code-point offset and the count of `>` markers.
- `_LIST_ITEM_RE` (regex 9); `containerLines(lines)` -> per line `(content, prefix, (depth,
  listIndent))`: blockquote-strip each line; a blank line inherits the current list indent of its
  depth; a list-item line sets `listIndents[depth] = len(match)` and yields the content after the
  marker with `prefix += listIndent`; a non-item line with `>= listIndents[depth]` leading spaces is
  a continuation (same stripping); a line with zero leading spaces pops that depth's list indent.
  Container identity is the `(depth, listIndent)` pair.
- `tableSeparators(line)`: positions of `|` outside backtick code spans (a run of N backticks opens,
  an equal run closes; `\` skips one char). `tableCellCount(line)`: `len(seps) + 1 - (seps[0] ==
  firstNonSpace) - (seps[-1] == lastNonSpace)` (pyIsSpace), 0 without separators.
- `tableLines(lines)` -> set of 0-based indices in a GFM-shaped table: a divider (regex 6, cell
  count > 0, equal to the previous line's cell count, same container) starts a table at `index-1`
  and extends over following lines in the same container that do not match regex 7 and have a
  non-zero cell count. Linear time is pinned by `test_table_classification_is_linear_on_hostile_divider_input`
  (8000 dividers) and `test_malformed_long_table_divider_is_linear` (900k spaces then `x`).
- `indentedCodeLines(lines)`: container content starting with `\t` or with 4+ leading spaces.
- `fallbackBlockStarts(lines)`: an index whose blockquote depth differs from the previous line's
  (never index 0 by this rule), or whose raw line is a list item, or whose container content matches
  regex 7 or 8.
- `fencedLines(lines)`: state machine over container lines; a container change closes the fence;
  an opener (regex 5) with `~` or with no backtick in the info opens `(marker, width, container)`;
  a closer is a line with indent <= 3 whose `lstrip(" ")` is `>= width` copies of the marker followed
  only by spaces and tabs (regex 14, a 3-line check in Go). Opener to closer inclusive are fenced;
  an unterminated fence runs to EOF.
- `scanFencedPreproc(text, off)` -> `([]Preproc, total)`: same fence walk; the opener records
  `info = strip(group 3)`, **[column]** `column = prefix + len(group 1) + 1`, and accumulates
  container-stripped content lines; `finish` skips fences whose info does not start with `!` or
  whose joined content `strip()`s to empty; else `total++` and while `total <= 25` append
  `Preproc{"fenced", join(content, "\n"), opener+1+off, true, column, info}`. Pins (fallback path):
  `test_fenced_preprocessing_survives_markdown_parser_failure` (4,1),
  `test_blockquoted_fence_survives_markdown_parser_failure` (4,3),
  `test_list_nested_fence_survives_markdown_parser_failure` (5,5),
  `test_list_nested_fence_keeps_container_across_blank_line` (4,3),
  `test_fence_closer_does_not_consume_following_bang_fence` (7,1),
  `test_blockquoted_documentation_fence_stays_inert_on_parser_failure`.
- `withoutInlineCode(line)`: blank matched backtick runs (open run of N, close = next identical
  run; `\` skips one char); unmatched runs stay.
- `maskedFallbackLines(lines, excluded)`: group consecutive non-excluded non-blank lines into
  blocks, splitting before a line whose blockquote-stripped text matches regex 7 or 8; apply
  `withoutInlineCode` to each block's joined text (so multi-line code spans mask); finally blank
  every `\[` preceded by an even number of backslashes (regex 16) in every line.
- `referenceLabel(v)`: `join(fields(v), " ")` case-folded.
- `fallbackLinks(text, off)` -> `[]Link`: `excluded = fenced ∪ indentedCode ∪ table`; masked lines;
  pass 1 collects definitions (regex 11; the last definition of a label wins; keyed by
  `referenceLabel`); pass 2, per non-excluded line in order: inline links (regex 10, group 1), then
  full/collapsed references (regex 12, label = group 2 or group 1 if group 2 is empty), then
  shortcut references (regex 13); each `Link{href, "", index+1+off}` **[line]**. Pins:
  `test_linked_preprocessing_survives_root_markdown_parser_failure`,
  `test_fallback_link_inside_inline_code_does_not_load_document`,
  `test_fallback_link_inside_multiline_code_span_does_not_load_document`,
  `test_escaped_fallback_link_does_not_load_document`,
  `test_reference_link_survives_root_markdown_parser_failure`,
  `test_shortcut_reference_survives_root_markdown_parser_failure`.
- `scanInlinePreproc(text, off, excludedLines /* nil = None */, markdownExclusions, blockStarts)`
  -> `([]Preproc, total)`: `conservative = excludedLines == nil`; when conservative and
  `blockStarts == nil`, `blockStarts = fallbackBlockStarts`. `table = tableLines if
  markdownExclusions`; `fenced = fencedLines if conservative && markdownExclusions`; `indentedCode =
  indentedCodeLines if conservative`. Block ids: walk lines; `block++` at each block start; a
  blank, fenced, table, indented or excluded line gets id nil and also `block++`; others get the
  current id. Per block, count runs of 2+ backticks by width (`remaining[block][width]`). Then scan
  each non-nil line left to right, resetting `inlineTicks` when the block id changes: a backtick run
  (only when `markdownExclusions`) of width >= 2 decrements `remaining[block][width]`; with no open
  span and a remaining count still > 0 it opens `inlineTicks = width`; an equal width closes;
  single backticks have no effect. Outside an open span, `!` followed by exactly one backtick
  (`source[p+2] != "`"`) whose closing single backtick exists (`end > p+2`, not followed by a
  backtick) yields `command = source[p+2:end]`; a blank command is skipped; `runs = p == 0 ||
  pyIsSpace(source[p-1])` (the previous code point); `total++` if runs else `decoys++`; the token is
  kept while its counter is <= 25: `Preproc{"inline", command, lineIndex+1+off, runs, column=p+1}`
  **[line][column]**. Returns `(tokens, total)`; `total` counts live tokens only.
  Pins: `test_preprocessing_live_position_vs_decoy` (`=`, letter, `\`, U+200B are decoys),
  `test_non_boundary_inline_preprocessing_is_a_decoy`, `test_unicode_whitespace_is_a_live_boundary`
  (U+00A0 and U+2003 live, column 2), `test_inline_preprocessing_inside_code_examples_is_inert`,
  `test_unmatched_multibacktick_run_cannot_suppress_later_preprocessing` (5,1),
  `test_code_span_delimiters_in_other_list_items_cannot_suppress_preprocessing` (5,3),
  `test_table_cell_preprocessing_example_is_inert`, `test_one_column_table_preprocessing_example_is_inert`,
  `test_escaped_pipe_prose_cannot_suppress_live_preprocessing` (6,7),
  `test_heading_after_table_remains_live_preprocessing` (7,9),
  `test_blockquoted_table_preprocessing_example_is_inert`,
  `test_blockquoted_table_cannot_absorb_unquoted_live_preprocessing` (7,1),
  `test_mismatched_table_columns_cannot_suppress_live_preprocessing` (6,1),
  `test_pipe_prose_before_table_remains_executable` (4,7),
  `test_indented_code_block_preprocessing_is_inert`, `test_tab_indented_code_block_preprocessing_is_inert`,
  `test_list_continuation_preprocessing_remains_executable`,
  `test_indented_code_cannot_crowd_real_preprocessing_out_of_cap`,
  `test_html_block_boundary_cannot_extend_code_span_over_preprocessing` (6,1),
  `test_html_block_boundary_survives_markdown_parser_failure`,
  `test_escaped_backtick_run_that_opens_code_context_is_inert`,
  `test_escaped_backticks_inside_open_code_span_remain_inert`,
  `test_fallback_heading_starts_new_code_span_scope` (5,3),
  `test_list_continuation_after_blank_survives_parser_failure` (6,5),
  `test_list_continuation_survives_markdown_parser_failure` (5,5),
  `test_container_relative_indented_code_stays_inert_on_parser_failure`,
  `test_indented_list_lookalike_stays_inert_on_parser_failure`,
  `test_list_nested_table_stays_inert_on_parser_failure`,
  `test_inline_preprocessing_survives_markdown_parser_failure` (4,5),
  `test_parse.py::test_preprocessing_inline_runs_vs_decoy`, `test_preprocessing_line_numbers_incremental`.

### 2.6 Frontmatter (`_parse_frontmatter_details`, `_fm_load`, `parse_frontmatter`)

`frontmatterDetails(text) -> (values, keyLines, err, unsafeTags)`: no open -> `(nil, {}, "", nil)`;
open without close -> `frontmatter_unterminated`; `block = join(lines[1:end], "\n")`;
`len(block) > 16384` code points -> `frontmatter_too_large`; `count("[") + count("{") > 256`
(plain character counts, quoted or not) -> `frontmatter_too_deep`; else `fmLoad(block)`.
Pins: `test_deeply_nested_frontmatter_fails_closed`, `test_frontmatter_depth_guard_ignores_quoted_brackets`
(70 is under the cap), `test_frontmatter_deep_flow_rejected` (5000), `test_depth_guard_not_fooled_by_bare_closes`,
`test_depth_guard_ignores_block_and_plain_scalar_brackets`, `test_frontmatter_multiline_plain_scalar_keeps_grant`,
`test_depth_guard_not_bypassed_by_node_property` (`!!seq `, `!foo `, `&a ` + 8000 brackets ->
`frontmatter_too_deep` or `yaml_alias_budget`), `test_depth_guard_hash_is_comment_only_when_spaced`,
`test_depth_guard_delimiters_inside_scalars_are_data`, `test_frontmatter_depth_guard_honors_escaped_quote_no_grant_evasion`.

`fmLoad(block)`, outcomes in this order (each returns `(nil, {}, code, tags)` unless noted):

1. Parse the block to a node tree without constructing values. Any anchor or alias sets `hasAlias`.
   Any node whose **long-form** tag satisfies `dangerousYamlTag` becomes `YamlTag{tag, mark.line +
   2, mark.column + 1}` **[line][column]**, the mark being the start of the tag token (verified:
   `x: !!python/object/apply:os.system [...]` on block line 0 has mark (0,3); the test
   `test_metadata.py::test_unsafe_object_tag_reports_exact_parser_location` expects file line 3,
   column 10 for `payload: !!python/...` on block line 2). Tag strings are long form:
   `tag:yaml.org,2002:python/object/apply:os.system`; `!ruby/object:Foo` stays as written. In
   yaml.v3 use `Node.LongTag()`, whose output matches ruamel's event tag for both forms.
   `dangerousYamlTag`: regex 19, or a prefix among `!ruby/exception:`, `!ruby/hash:`, `!ruby/object:`,
   `!ruby/struct:` and their `tag:yaml.org,2002:ruby/...:` forms, or exactly
   `tag:yaml.org,2002:javax.script.ScriptEngineManager` / `tag:yaml.org,2002:java.net.URLClassLoader`.
   Any unsafe tag -> `yaml_unsafe_tag` with the tag list.
2. `hasAlias` -> `yaml_alias_budget`.
3. Construct values. A duplicate key at any depth -> `yaml_duplicate_key` (ruamel compares
   constructed keys, so `1:` and `true:` collide; Go compares `(resolved tag, value)` of scalar keys,
   see 5). Verified: a nested duplicate raises `DuplicateKeyError`.
4. Any other error -> `yaml_alias_budget` if `hasAlias`, else `yaml_error:line N` with `N =
   mark.line + 2` when the error has a position, else `yaml_error`. Verified marks: `bad: : :` ->
   scanner error at (0,5) -> `yaml_error:line 3` for a block starting at file line 2
   (`test_frontmatter_yaml_error_reports_true_file_line`); a tab-indented mapping -> scanner error
   at (1,0); the invalid date `2001-02-30` -> ValueError with no mark -> `yaml_error`
   (`test_frontmatter_timestamp_value_error_fails_closed`); `!!bool notabool` -> KeyError with no
   mark -> `yaml_error` (`test_one_hostile_manifest_does_not_abort_scan`).
5. Empty document -> `({}, {}, "", nil)`. A non-mapping document -> `frontmatter_not_a_mapping`.
6. Success: `values = plain(data)` (keys `str(k)`, nested maps and lists recursively, scalars as
   constructed); `keyLines = {str(k): lc.data[k][0] + 2}` for top-level keys only **[line]**
   (verified `lc.data["name"] == [0,0,0,6]` -> line 2; the quoted key `"allowed-tools"` maps to its
   unquoted text). Pins: `test_frontmatter_key_lines` (`{"name":2,"description":3}`),
   `test_frontmatter_quoted_key_gets_line`, `test_frontmatter_no_phantom_key_from_flow_value`,
   `test_frontmatter_key_line_prefers_top_level`, `test_frontmatter_description_shapes`,
   `test_frontmatter_inline_merge_without_alias_is_bounded` (`<<: {k: v}` merges),
   `test_frontmatter_merge_bomb_defused_all_forms`, `test_frontmatter_recursive_alias_refused`,
   `test_frontmatter_alias_budget_refused`, `test_frontmatter_alias_budget_counts_non_ascii_anchors`,
   `test_frontmatter_scalar_ampersand_star_not_alias`, `test_frontmatter_loader_is_per_artifact_isolated`,
   `test_frontmatter_unsafe_python_tag_flagged`, `test_frontmatter_duplicate_key_rejected`.

`Frontmatter(text)` drops the tag list.

### 2.7 Grants (`_split_grants`, `_GRANT_RE`, `_grant_parentheses_balanced`, `parse_grants`)

- `splitGrants(val)`: a list -> its string elements `strip()`ped and non-empty (non-strings dropped
  here, flagged by `parseOne`); a non-string scalar -> empty; a string -> the character walk in the
  source: `\` escapes the next char outside single quotes; a quote opens a quoted run; at depth 0 a
  `,` or pyIsSpace char ends the specifier unless the specifier is non-blank and the next non-space
  char is `(` (then the whitespace is kept, so `Bash (curl:*)` is one specifier); `(`/`)` track depth
  with floor 0. Precompute `nextNonSpace` so this is linear (`test_grant_whitespace_before_parenthesis_is_linear`).
- `Grants(fm)`: for `("allowed-tools", true)` then `("disallowed-tools", false)`, for each specifier
  in order: `m = regex 18 match`; a match with a pattern group whose spec is not
  `grantParenthesesBalanced` -> unparsed; a pattern on which shlex non-posix splitting raises (an
  unterminated quote at token start, see 5) -> unparsed; parsed -> `Grant{Tool: g1, Pattern: g2 (nil
  if absent), Raw: spec, Allowed, Broad: g2 == nil, Parsed: true}`; unparsed -> `Grant{Tool: spec,
  Pattern: nil, Raw: spec, Allowed, Broad: true, Parsed: false}`.
- `grantParenthesesBalanced(spec)`: from the first `(`, with the same quote and escape rules, the
  depth must return to 0 exactly once with only whitespace after; a negative depth is unbalanced;
  no `(` is balanced.
  Pins: `test_grants_specifier_vs_bare_broad`, `test_grants_list_form_and_disallowed`,
  `test_grants_comma_inside_parens_not_split` (pattern `a, b`), `test_grants_space_separated_specifiers_are_independent`,
  `test_grant_keeps_whitespace_before_pattern_parenthesis`, `test_unbalanced_grant_parentheses_remain_unparsed`
  (`Bash(curl:*))`, `Bash((curl:*)`), `test_quoted_parenthesis_does_not_absorb_following_grant`
  (`Bash(echo "(":*) Read`), `test_grant_specifier_padding_no_redos` (`Bash` + 40k spaces + `x`:
  the regex fails, the whole specifier becomes an unparsed broad grant; the test asserts `broad`),
  `test_grants_non_list_str_shape_flagged`, `test_grant_non_string_element_flagged_not_stringified`,
  `test_grants.py` lines 13 and 25.

### 2.8 Shell (`parse_shell`, `_error_spans`)

Refuse when the UTF-8 byte length is `> 524288` or the count of single `|` characters (a `|` whose
neighbours are not `|`, regex 20 as a byte loop) is `> 3000`. Otherwise parse and return the tree
plus **[line]** error spans `(startLine+1, endLine+1)` of every top-level ERROR/MISSING node. Pins:
`test_shell_tree_sitter_cst`, `test_shell_error_region_recorded_not_dropped` (`echo ok\nif then $( \``),
`test_parse_shell_dos_guard_is_at_the_public_boundary` (`"a|" * 40000` refused),
`test_shell_pipe_bomb_is_bounded_not_parsed`, `test_shell_nested_error_region_is_covered` (mvdan/sh stops on
line 3, inside the tree-sitter span, R1), `test_shell_error_region_is_a_coverage_gap`, `test_python_and_shell_scripts`. What
changes with mvdan/sh is in 4.8 and 8/R1.

### 2.9 Config and dependency manifests

- `loadStructured(text, rel)`: a `.toml` suffix (case-insensitive) selects TOML, else JSON; errors
  -> `toml_parse_error:<msg[:80]>` / `json_parse_error:<msg[:80]>` (code points); JSON rejects
  `NaN`, `Infinity`, `-Infinity` (`test_json_config_rejects_nonstandard_constants`,
  `test_malformed_config_fails_closed`, `test_toml_oversized_int_fails_closed`, `test_toml_config_is_parsed`,
  `test_agent_config_json_is_classified`).
- `ClassifyManifest(cfg)`: non-map -> `""`; key `mcpServers` or `mcp_servers` -> `mcp_servers`;
  `hooks` value a map or list -> `hooks`; key `lockVersion` or `integrity` -> `lockfile`; key `skills`
  or `interface`, or both `name` and `version` -> `plugin`; any value that is a map with both `args`
  and `command`, or with `type` in {`http`,`sse`} and `url` -> `mcp_servers`; else `generic`.
  14 pins in `test_manifest_classification` and `test_manifest_classification_precedence`.
- `reqDep(raw, line)`: PEP 508 parse; failure -> nil; `pinned` = any specifier with operator `==`
  or `===` whose version contains no `*`; `{name (as written), specifier: str(SpecifierSet), pinned,
  raw, line}` where `str(SpecifierSet)` is the comma-join of the **sorted** normalised specifiers
  (verified: `a>=1,<2` -> `<2,>=1`; `==  1.0` -> `==1.0`).
- `parseRequirements(text)`: iterate `lines + [""]` with 1-based numbers; a line whose `rstrip()`
  ends in `\` and whose `lstrip()` does not start with `#` is a continuation (`buf += stripped[:-1]`,
  remember `startLine`); otherwise `s = strip(split(buf+raw, regex 21, 1)[0])`; blank or `#` lines
  are skipped; `reqDep(s, startLine or line)` goes to `deps`, else `s[:80]` to `unhandled`. Linear
  in the continuation count (`test_requirements_continuation_is_linear`, 200k). Pins:
  `test_requirements_deps_pinned`, `test_requirements_prefix_range_not_pinned` (`==2.*` not pinned),
  `test_requirements_url_continuation_and_comment` (`pkg @ https://h/p.whl#sha256=abc` keeps the
  fragment; `--hash` continuation dropped), `test_requirements_trailing_backslash_not_dropped`,
  `test_requirements_vcs_and_local_surfaced`.
- `pyprojectDeps(cfg)`: groups in order: `project.dependencies`, `build-system.requires`, each
  value of `project.optional-dependencies`, each value of `dependency-groups`; `bad` messages
  exactly: `project not a table`, `%s is dynamic` (for `dependencies`, `optional-dependencies`),
  `dynamic has a non-string entry`, `dynamic not a list`, `tool.poetry dependencies not modeled`,
  `%s not a table`, `non-list dependency group`, `str(x)[:80]` for a non-string entry, `x[:80]` for
  an unparsable string. `bad` order is output order (joined into the diagnostic detail). Pins:
  `test_pyproject_deps_parsed`, `test_pyproject_build_system_requires_captured`,
  `test_pyproject_dependency_groups_captured`, `test_pyproject_dynamic_dependencies_flagged`,
  `test_pyproject_malformed_dep_surfaced_not_dropped`, `test_pyproject_optional_deps_malformed_not_silent`,
  `test_pyproject_optional_dependencies_collected`, `test_pyproject_non_list_dependencies_fails_safe`,
  `test_non_string_dep_entries_flagged_not_coerced`.
- `npmDeps(cfg)`: sections `dependencies`, `devDependencies`, `optionalDependencies`,
  `peerDependencies` in that order; a non-map config -> `["package.json is not a JSON object"]`; a
  non-object section -> `"%s not an object"`; a non-string version -> `"%s non-string version"`;
  `pinned` = regex 22 full match of the spec, or for `npm:<pkg>@<ver>` of the part after the last
  `@` when that `@` index is > 4; `raw = name + "@" + spec`; no `line`. Section entries must be
  visited in **document order** (Python dict order), so decode `package.json` with an
  order-preserving decoder (see 4.5). Pins: `test_npm_floating_versions_not_pinned`,
  `test_npm_semver_prerelease_build_is_pinned`, `test_npm_peer_dependencies_captured`,
  `test_npm_malformed_shape_not_silent`.

### 2.10 Artifact dispatch (`Artifact`, `_parse_one`, `_parse_md`, `_parse_python`, `_structured_deps`, `parse_package`, `_resolve_refs`)

`Artifact` construction copies `rel`, `kind`, `NormNewlines(text)`, `raw`. `parseOne` switches
on `kind` (kinds come from `ingest._classify` and `_classify_shebang`):

- `skill_manifest`, `instruction`, `doc`, `agent_identity`: for the three non-`doc` kinds,
  `FrontmatterEndLine = end + 1` when a closed block exists **[line]**; store values, key lines and
  unsafe tags; an error adds `("frontmatter_parse_error", err)`; when values are non-empty:
  `Grants = Grants(fm)`; for each of `allowed-tools`, `disallowed-tools`: a value that is neither
  list nor string, or a list with a non-string element, adds `("grants_unparsed_shape", key)`; any
  grant with `!Parsed && Allowed == (key == "allowed-tools")` adds the same pair unless already
  present. Then `parseMD(p, text, stripFM = kind != "doc")`.
  Pins: `test_skill_manifest_frontmatter_grants_markdown` (link line 6 past a 3-line frontmatter),
  `test_instruction_file_frontmatter_grants_parsed`, `test_doc_file_frontmatter_not_grant_parsed`
  (`Grants == nil`, `Markdown != nil`), `test_grants_non_list_str_shape_flagged`.
- `parseMD`: a `.rst` suffix adds `("unsupported_markup", "rst")` first. `body, off` from
  `bodyAndOffset` (or `text, 0` for docs). `md, mderr = Markdown(body, off)`.
  Success: `inline` = md's inline tokens, `inlineTotal = md.PreprocCounts.Inline`; if `stripFM &&
  off > 0`, scan the frontmatter lines `join(NormNewlines(text).split("\n")[:off], "\n")` with
  `scanInlinePreproc(fm, 0, excluded = empty set (not nil), markdownExclusions = false, nil)` and
  **prepend**: `inline = fmInline + inline`, `inlineTotal += fmTotal`; `fenced` = md's fenced tokens,
  `fencedTotal = md.PreprocCounts.Fenced`.
  Failure: `FallbackLinks = fallbackLinks(body, off)`; the frontmatter scan as above (if any) then
  `scanInlinePreproc(body, off, nil, true, nil)` (conservative), concatenated frontmatter first;
  `fenced, fencedTotal = scanFencedPreproc(body, off)`.
  Then re-cap: keep the first 25 inline tokens with `Runs` and the first 25 without, counted
  separately in list order. `Preprocessing = inline + fenced`; `PreprocessingCounts = {inlineTotal,
  fencedTotal}`; when `Markdown != nil`, its `Preproc` and `PreprocCounts` are overwritten with
  copies. `mderr != ""` -> `("markdown_parse_error", mderr)`; else `HasUninspectableHTML` ->
  `("raw_html", nil)` when `HTMLHidesContent` (an uninspectable fragment carried text, or a
  construct the inspector could not resolve), else `("raw_html_markup", nil)` (unknown tags or
  attributes alone).
  Pins: `test_inline_preprocessing_in_frontmatter_uses_raw_file_location` (3,18),
  `test_frontmatter_and_body_share_one_inline_cap` (25 kept, all `front-`, note `25 more SXV-001`),
  `test_frontmatter_decoys_cannot_crowd_out_live_body_preprocessing`,
  `test_frontmatter_yaml_scalar_is_not_suppressed_as_markdown_example` (5,3: a fence inside a YAML
  block scalar does not exclude), `test_frontmatter_preprocessing_survives_markdown_parser_failure`,
  `test_doc_markdown_not_frontmatter_stripped`, `test_rst_flagged_unsupported`,
  `test_preprocessing_ir_and_evidence_are_bounded` (100 live tokens -> 25 kept).
- `script_python`: `len(text) > MaxPyChars` code points -> `("python_oversize", str(len))` and no
  parse; parse; an iterative child walk with depth `> 512` -> `("python_too_complex", nil)` and no
  tree; a syntax error -> `("python_syntax_error", "line <lineno>")` (`"line ?"` when unknown);
  recursion -> `python_too_complex`; memory -> `("memoryerror", nil)`. Pins:
  `test_python_syntax_error_is_a_diagnostic`, `test_python_oversize_flagged_not_parsed` (600k
  chars, under ingest's read cap), `test_python_ast_depth_is_platform_independent` (`"a"+"a"+...`
  3000 terms), `test_untrusted_python_syntax_warnings_do_not_escape`, `test_python_and_shell_scripts`.
- `script_shell`: refused -> `("shell_too_complex", str(len(text)))` (code points); spans ->
  `("shell_error_region", "%d:%s" % (len(spans), join(first 20 as "%d-%d", ",")))`.
- `script_javascript`, `script_typescript` -> no IR and no diagnostic; the code lane runs OpenGrep on
  them (wave 9, `test_parse::test_unsupported_script_language_is_flagged`, `jslane_test.go`).
- any other `script_*` -> `("unsupported_language", kind[len("script_"):])`
  (`test_unsupported_script_language_is_flagged`: `powershell`, `ruby`).
- `agent_config`, `hooks_config`, `mcp_config`, `plugin_manifest`, `app_manifest`, `plugin_lock`:
  `Config, err = loadStructured(text, rel)`; error -> `("config_parse_error", err)` else
  `ManifestKind = ClassifyManifest(Config)`.
- `dep_manifest`: `base = lower(basename(rel))`; `*requirements*.txt` -> `parseRequirements`
  (unhandled -> `("requirement_unparsed", join(unhandled[:8], ";"))`); `package.json` or
  `pyproject.toml` -> `structuredDeps` (sets `Config`; a parse error adds `config_parse_error` and
  leaves `Deps` nil; `bad` adds `requirement_unparsed`); else `("dep_manifest_unparsed", base)`.
- `secret_material`: nothing (`test_secret_material_carried_not_parsed`). Any other kind with text
  -> `("unmodeled_content", kind)` (`test_unmodeled_text_file_not_read_clean`).

`Package(pkg)`: `deadline = now + PkgBudget`; for each artifact in `pkg.Artifacts` order (ingest
sorts directory entries; deterministic): an artifact with `Text == nil` (Python `text is None`) is
added untouched with no diagnostics (`test_opaque_and_compiled_are_skipped`); past the deadline ->
`("parse_budget_exceeded", nil)`; else `parseOne` under `recover`, recording `("parse_crash",
<Go error/panic type name>)` (`test_parse_crash_isolation`, `test_package_wall_clock_budget_flags_not_skips`).
Then `Refs = resolveRefs(out)` and each diagnostic is appended to `LedgerExceptions` in artifact
order, diagnostic order (`test_diagnostics_mirrored_into_ledger`, `test_parse_is_deterministic`,
`test_one_hostile_manifest_does_not_abort_scan`).

`resolveRefs(pkg)`: per artifact, `links = Markdown.Links` if the markdown parsed else
`FallbackLinks`; `base = rel` up to the last `/`, or `""`; for each `(href, _, line)`: `target =
strip(href before first "#", then before first "?")`; skip empty or scheme-like
(`^[a-z][a-z0-9+.-]*:` case-insensitive); `target = NFC(pyUnquote(target))`; `resolved =
posixNormpath(posixJoin(base, target))`; skip `..`, anything starting `../`, and `.`; append
`Ref{From: rel, To: resolved, Line: line}` when `resolved` is a `ByRel` key. Pins:
`test_refs_resolved_external_ignored`, `test_refs_nfc_matched_and_in_root_dotfile_kept` (`..keep.md`
kept), `test_refs_parent_escape_dropped`, `test_refs_scheme_in_fragment_still_resolves`,
`test_refs_query_string_stripped`, `test_refs_uri_scheme_not_resolved` (`data:`, `file:`).

### 2.11 `checks/preproc.py`

- `loadedPaths(parsed)`: roots = artifacts of kind `skill_manifest` or `agent_identity`; follow
  `Refs` (adjacency by `From`) into `instruction`/`doc` artifacts only; return the reachable set.
  Pins: `test_preprocessing_in_loaded_document_is_detected`, `test_preprocessing_in_loaded_identity_is_detected`
  (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`), `test_unreferenced_document_preprocessing_is_inert`
  (`README.md`, `CHANGELOG.md`, `LICENSE.md`, `SECURITY.md`, `THIRD_PARTY_NOTICES.md`).
- `Check(parsed)`: for each artifact in order whose `Rel` is loaded, for each `Preprocessing` token
  in order: an inline token with `Runs` and non-blank `Code` -> `inlineFinding`; a fenced token with
  a non-blank line -> `fencedFinding`. Then for `("inline","SXV-001")`, `("fenced","SXV-002")`: if
  `PreprocessingCounts[kind] > 25`, append `Finding{Vector: "", Rule: "findings-capped", Severity:
  "low", Path: rel, Message: fmt.Sprintf("%d more %s findings in %s were suppressed (cap %d per
  file)", count-25, vector, rel, 25)}`. Return `findings.Sort(findings)`.
- `inlineFinding`: `digest = hex(sha256(utf8(command)))`; `shown, truncated = command[:400],
  runeLen > 400`; `Finding{Vector: "SXV-001", Rule: "preproc-inline-bang", Severity: "critical",
  Path, Line, Column, Message: "inline preprocessing executes `" + command[:160] + "` while loading
  the skill, before its instructions are evaluated", Evidence: {command_text: shown,
  command_length: runeLen(command), command_sha256: digest, truncated, column, fence_state:
  "outside", selector: "inline-bang:" + digest[:12]}}`.
- `fencedFinding`: `normalized = rstrip(code, "\n")`; `lines = split(normalized, "\n")`;
  `executable = count(lines with non-blank strip())`; digest, `shown`, `truncated` over
  `normalized`; `Finding{Vector: "SXV-002", Rule: "preproc-fenced-bang", Severity: "critical", Path,
  Line, Column, Message: fmt.Sprintf("bang-tagged fenced preprocessing executes %d command line(s)
  while loading the skill", executable), Evidence: {command_text: split(shown, "\n") /* a JSON
  array */, command_length: runeLen(normalized), command_sha256, truncated, column, fence_info:
  token.Info, block_line_count: executable, selector: "fenced-bang:" + digest[:12]}}`.
  Evidence key order above is Python insertion order (7).
  Pins: `test_inline_preprocessing_reports_exact_location_and_evidence`,
  `test_repeated_inline_preprocessing_preserves_each_column` ((4,1),(4,12); `Offset` nil; both
  survive `dedupe_findings`), `test_inline_evidence_preserves_command_whitespace`,
  `test_bang_fence_preserves_indentation_and_internal_blank_lines`,
  `test_multiple_preprocessing_forms_are_independent` (sorted SXV-001 line 4 before SXV-002 line 5),
  `test_preprocessing_findings_are_capped_with_visible_note` (`3 more SXV-001 findings`),
  `test_preprocessing_finding_serialization_keeps_location_contract`,
  `test_non_executable_examples_do_not_report`, `test_preprocessing_check_is_registered`,
  `test_parser_and_output_caps_share_one_contract`, `test_disposition.py` line 404,
  `test_sarif_release.py` line 227, `test_batch3_microcorpus.py` rows `inline-preproc`, `fenced-preproc`.

## 3. Regex inventory

23 distinct patterns (24 sites: regex 14 is built at two sites). 5 use lookaround, 2 use
possessive quantifiers, 0 need `dlclark/regexp2`: every lookaround is replaced by a leftmost-match
loop with a one-character check (`pyFindAll` below) or by a byte loop. Flags: `re.S` -> `(?s)`,
`re.I` -> `(?i)`, `re.DOTALL` -> `(?s)`. `S` = the pyIsSpace class `[\t\n\v\f\r\x1c-\x1f \x85\p{Z}]`.

`pyFindAll(re, s, before, after)`: `pos = 0`; loop `m = re.FindStringSubmatchIndex(s[pos:])`; if
none, stop; `start = pos + m[0]`; if `before(prev char)` and `after(next char)` hold, emit and
`pos = pos + m[1]` (or `+1` on an empty match); else `pos = start + 1`. This reproduces Python's
leftmost-first scan exactly because every zero-width assertion here sits at the match start or end
and each pattern admits one candidate match per start position (the bracket classes exclude `]`).

| # | Python pattern (site) | RE2 verdict | Notes |
|---|---|---|---|
| 1 | `[\x00-\x20]+` (`_InspectableHTML.handle_starttag`, `re.sub`) | unchanged | |
| 2 | `^[a-z][a-z0-9+.-]*:` (same) | unchanged | applied to a `lower()`ed string |
| 3 | `_HTML_PROJECTION_TOKEN` `<!--.*?(?:-->\|$)\|<(?:[^>"']\|"[^"]*"\|'[^']*')*>\|&(?:#[xX][0-9A-Fa-f]+;?\|#\d+;?\|[A-Za-z][A-Za-z0-9]+;)` with `re.S` | `(?s)` prefix, `\d` -> `\p{Nd}` | Python `$` also matches before a final `\n`; RE2 `$` only at end. Output-equivalent: the unterminated-comment branch blanks either way and `\n` survives `blankSource`. Lazy `.*?` is fine in RE2. |
| 4 | `(?is)<\s*(/?)\s*([a-z][a-z0-9-]*)` (`_project_html`) | `\s` -> `S` | `(?i)` folding of `[a-z]` agrees with Python (both fold U+212A and U+017F, verified) |
| 5 | `_FENCE_OPEN_RE` `^( {0,3})(`{3,}\|~{3,})(.*)$` | unchanged | per-line input, no `\n` |
| 6 | `_TABLE_DIVIDER_RE` `^\s*+\|?\s*+:?-{3,}:?(?:\s*+\|\s*+:?-{3,}:?)*\s*+\|?\s*+$` | possessive `\s*+` -> `\s*` (as `S*`) | Possessive only pruned backtracking; `\s` and `\|` are disjoint so the language is identical. RE2 is linear anyway. |
| 7 | `_BLOCK_OPENER_RE` `^ {0,3}(?:#{1,6}(?:[ \t]\|$)\|`{3,}\|~{3,}\|(?:[-+*]\|\d+[.)])[ \t]+)` | `\d` -> `\p{Nd}` | |
| 8 | `_HTML_BLOCK_OPENER_RE` (CommonMark type-6 tag list plus `<!--`, `<?`, `<![A-Z]`, `<!\[CDATA\[`) | unchanged | |
| 9 | `_LIST_ITEM_RE` `^( {0,3})(?:[-+*]\|\d+[.)])([ \t]+)` | `\d` -> `\p{Nd}` | |
| 10 | `_FALLBACK_LINK_RE` `(?<!!)\[[^\]\n]{0,500}\]\(\s*<?([^\s)>]{1,1000})>?[^)\n]{0,1000}\)` | drop `(?<!!)`; `pyFindAll` with `before = prev != '!'`; `\s` -> `S` | |
| 11 | `_REFERENCE_DEFINITION_RE` `^ {0,3}\[([^\]\n]{1,500})\]:[ \t]*<?([^\s>]{1,1000})>?` | `\s` -> `S` | |
| 12 | `_REFERENCE_USE_RE` `(?<!!)\[([^\]\n]{1,500})\]\[([^\]\n]{0,500})\]` | drop lookbehind; `pyFindAll`, `before = prev != '!'` | |
| 13 | `_SHORTCUT_REFERENCE_RE` `(?<![!\]])\[([^\]\n]{1,500})\](?![\[(:])` | drop both; `pyFindAll`, `before = prev not in "!]"`, `after = next not in "[(:"` | one candidate per start position because `[^\]\n]` cannot span a `]` |
| 14 | `^(<marker>{<width>,})[ \t]*$` built with `re.escape` (`_fenced_lines`, `_scan_fenced_preproc`) | replace with a 3-line check: count the leading run of `marker`, require `>= width`, require the rest to be spaces/tabs | |
| 15 | (counted with 14) | | |
| 16 | `(?<!\\)(?:\\\\)*\\\[` (`_masked_fallback_lines`, `re.sub` to spaces) | byte loop: for each maximal backslash run, if its length is odd and the next char is `[`, blank the run and the `[` | A consuming rewrite `(^\|[^\\])` breaks on adjacent `\[\[`; the loop is exact because the lookbehind forces the match to start at a run start. |
| 17 | `` `{2,} `` (`_scan_inline_preproc`, `finditer`) | unchanged | |
| 18 | `_GRANT_RE` `^([A-Za-z_][\w.-]*)\s*+(?:\((.*)\))?\s*+$` with `re.DOTALL` | `(?s)`; `\w` -> `[\p{L}\p{N}_]`; `\s*+` -> `S*`; `$` -> `\z` | possessive removal does not change the language (`S` disjoint from `(`; `.*` greedy already reaches the last `)`) |
| 19 | `_PY_DANGEROUS_TAG` `^tag:yaml\.org,2002:python/(?:name\|module\|object)(?:/(?:new\|apply))?(?::\|$)` | unchanged (`$` -> `\z`) | |
| 20 | `_SHELL_PIPE_RE` `(?<!\|)\|(?!\|)` (`findall` count) | byte loop: count `\|` whose previous and next bytes are not `\|` | exact: `\|\|\|` counts 0 in both |
| 21 | `\s(?:#\|--)` (`_parse_requirements`, `re.split` maxsplit 1) | `\s` -> `S`; use `FindStringIndex` and take the prefix | |
| 22 | `[=v]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?` (`_npm_deps`, `fullmatch`) | `\A...\z`; `\d` -> `\p{Nd}` | |
| 23 | `[a-z][a-z0-9+.-]*:` with `re.I` (`_resolve_refs`, `re.match`) | `(?i)^[a-z][a-z0-9+.-]*:` | folding agrees (see 4) |

Non-ASCII flags: patterns 3, 4, 6, 7, 9, 10, 11, 18, 21, 22 are the ones where `\s`/`\d`/`\w`
semantics differ; the replacements above make them exact. `\b` is not used. Case-insensitive
non-ASCII matters only in 4 and 23, where Go and Python agree.

## 4. Third-party replacements

### 4.1 markdown_it (`MarkdownIt("commonmark")`) -> `github.com/yuin/goldmark` (new dependency)

Decision: goldmark over `gitlab.com/golang-commonmark/markdown` (an unmaintained markdown-it port
at CommonMark 0.28 with GFM on by default) because goldmark tracks 0.31.2 like markdown-it-py 4.0
and is maintained; the token maps goldmark lacks are recovered from segments. Configure
`goldmark.New()` with no extensions and `html.WithUnsafe()` irrelevant (we never render); use
`parser.Parse(text.NewReader(src))` and walk the AST.

Parse facts the group consumes, and how each is obtained (validate the replacement against these
facts only; a `lineOf(offset)` table built once per document from `\n` positions with
`sort.Search` gives 0-based lines from segment offsets):

| Fact (markdown-it) | goldmark source |
|---|---|
| block `map = [start, end)` for `fence` | `*ast.FencedCodeBlock`: start = line of the opener; goldmark does not store the opener or closer lines, so replace its fenced-code block parser with a copy (~120 lines) that records `OpenLine` and `CloseLine` (`CloseLine = OpenLine + len(Lines()) + 1`, or the last content line + 1 when unterminated). This is the one place goldmark needs a fork; register it with `parser.WithBlockParsers(util.Prioritized(fenceParser, 700))` replacing the default. |
| `fence.info` | the opener line text after the marker run, `strip()`ped; goldmark's `Info` segment is nil for an empty info, so read it from the opener line directly (markdown-it also unescapes backslash escapes and entities in info: apply `unescapeAll`). |
| `fence.markup` | the marker run (`` ``` `` or longer, or `~~~`) read from the opener line |
| `fence.content` | `Lines()` segments joined; each line has up to `openerIndent` leading spaces removed (goldmark already does this in its fence parser: keep that behaviour in the copy) |
| `code_block.map` | `*ast.CodeBlock`: first `Lines()` segment line to last + 1 (goldmark trims trailing blank lines like markdown-it) |
| `code_block.content` | `Lines()` joined (indent already stripped) |
| `html_block.map` | `*ast.HTMLBlock`: first `Lines()` line to last + 1, or `ClosureLine` + 1 when set (types 1-5) |
| `inline.map` | parent `*ast.Paragraph`/`*ast.Heading`: `Lines()` first line to last + 1; for a setext heading the underline line is included in markdown-it's map (`[start, underline+1)`), goldmark's `Heading.Lines()` excludes it: add 1 for `Heading` nodes with `IsSetext()`... goldmark exposes `Heading.Level` only; detect setext by checking whether the line after `Lines()` is `=+` or `-+` (with up to 3 spaces indent). Blank lines between a paragraph's lines never occur. |
| `inline.level == 1` and previous token `paragraph_open` | `Paragraph` whose `Parent()` is `*ast.Document` |
| `inline.children` in order: `text`, `softbreak`, `hardbreak`, `code_inline`, `html_inline`, `link_open`/`link_close`, `image`, `strong_*`/`em_*` | depth-first walk of the paragraph's inline children: `*ast.Text` (segment; `SoftLineBreak()`/`HardLineBreak()` flags give the break tokens that follow it), `*ast.String` (decoded entity text), `*ast.CodeSpan` (children `Text` segments joined; markup = the backtick run immediately before the first child segment, scanning back over one optional space), `*ast.RawHTML` (`Segments`), `*ast.Link` (`Destination`; the label = concatenation of descendant `Text`/`String` values and `CodeSpan` contents; `Image` inside a link contributes its alt text), `*ast.AutoLink` (markdown-it emits `link_open` with the URL as href and the text as label: include it), `*ast.Image` (alt text). |
| `env["references"][label].map` | goldmark stores reference definitions in `parser.Context.References()` without positions; take positions from a small block parser wrapper: run regex 11 over lines that goldmark consumed as link reference definitions, or simpler, record in the copied fence parser's sibling: a `parser.ASTTransformer` cannot see them either. Recommended: after parsing, for each `ref` in `ctx.References()`, find the definition line by scanning `lines` (outside fenced/indented/html-block spans already known) for `^ {0,3}\[label\]:` with the label matched case-insensitively after `referenceLabel`; the first match is the definition (CommonMark keeps the first). Only `ReferenceSpans` depends on this, consumed by obfuscation for prose scanning; a title spanning several lines makes `map[1] > map[0]+1`, so extend the span while the following lines belong to the definition (goldmark's `link.go` parseLinkReferenceDefinition consumes them: reuse its length by re-parsing the candidate with `parser.ParseLinkReferenceDefinition` if exported, else accept single-line spans and record the gap in the parity notes). |
| NUL handling | markdown-it replaces U+0000 with U+FFFD in token content. Ingest already rejects buffers containing NUL bytes (`_decode`: `binary_content`), so this never fires. |

Test-visible failure hooks: Python tests monkeypatch `_MD.parse` to raise; Go tests call
`scanInlinePreproc`, `scanFencedPreproc`, `fallbackLinks` and `parseMD` with a `mdFail` package
variable (`var parseMarkdown = Markdown` swapped in tests) instead. A variable, not an interface.

### 4.2 html.parser.HTMLParser -> `golang.org/x/net/html` Tokenizer (new direct dependency; already indirect in mcp-xray)

`html.NewTokenizer(strings.NewReader(fragment))` with `AllowCDATA(false)`. Positions: keep a running
byte offset advanced by `len(z.Raw())` after every `Next()`; `Raw()` slices are contiguous over the
input for the tokenizer, so `offset` at token start gives `(line, col0)` through the fragment's
line table. Mapping: `StartTagToken` -> start tag; `SelfClosingTagToken` -> self-closing;
`EndTagToken` -> end tag; `TextToken` -> data (already unescaped, as Python with
`convert_charrefs=True`); `CommentToken`: dispatch on `Raw()` prefix: `<!--` -> comment; `<?` ->
processing instruction; `<![` -> unknown declaration; other `<!` -> bogus comment (comment with
`Data`); `DoctypeToken` -> declaration; `ErrorToken` with `io.EOF` ends. `Token.Attr` keeps
duplicates and lowercases keys; values are unescaped as in Python. Raw-text elements: Python
switches to CDATA mode only for `script` and `style`; x/net/html also for `textarea`, `title`,
`xmp`, `iframe`, `noembed`, `noframes`, `noscript`, `plaintext`. All of those tags already make the
fragment uninspectable, so the difference only changes `HTMLTags` entries inside them (test-only
field) and never `HTMLComments`/`HTMLProse`. Python exceptions from the parser are mirrored by a
`recover` that sets `fullyInspected = false`.

### 4.3 ruamel.yaml (round-trip, event stream) -> `gopkg.in/yaml.v3` (already chosen)

`yaml.Unmarshal([]byte(block), &node)` into a `yaml.Node` gives the tree with `Line`/`Column`
(1-based) per node; ruamel's `mark.line + 2` equals `node.Line + 1` and `mark.column + 1` equals
`node.Column` (both engines put the node mark at the tag token when a tag is present, per the
verified ruamel mark (0,3) for `x: !!tag`; verify against `test_metadata.py` column 10 in the first
parity run). Walk every node: `Kind == AliasNode || Anchor != ""` -> `hasAlias`; `Tag` with
`Style&TaggedStyle != 0` -> `LongTag()` -> `dangerousYamlTag`. Duplicate keys: walk every
`MappingNode` and compare `(ShortTag(), Value)` of scalar keys; yaml.v3 reports duplicates only when
decoding into a map and with a message, so do it on the node. Values: `node.Decode(&any)`; key
`str(k)` = the key node's `Value` for scalars (`true` -> Python `True`, `~` -> `None`; see 5).
Merge keys `<<` are handled by `Decode`. Error line: yaml.v3 errors read `yaml: line N: ...`; parse
`N` with `^yaml: line (\d+):` and emit `yaml_error:line N+1`; no line -> `yaml_error`. Scalar typing
differences are in 5. Timestamp validation (`2001-02-30` must fail): yaml.v3 resolves an unparsable
timestamp-shaped plain scalar to `!!str` silently; add a post-walk check: a plain (`Style == 0`)
scalar whose `ShortTag()` is `!!str` and whose value matches ruamel's timestamp regex
(`^\d{4}-\d{1,2}-\d{1,2}(?:[Tt]|[ \t]+)?...` as in ruamel `resolver.py`) but fails `time.Parse` ->
`yaml_error`. This is the only construction-time `ValueError` ruamel raises on well-formed YAML.

### 4.4 packaging.requirements -> hand-port (no dependency)

`aquasecurity/go-pep440-version` covers versions and specifier sets but not the PEP 508 requirement
grammar (name, extras, `@ url`, marker), and the group needs only: accept/reject, `name`,
`str(specifier)`, per-specifier `(operator, version)`. Port `packaging/_tokenizer.py` rules
(`LEFT_PARENTHESIS`, `IDENTIFIER` `\b[a-zA-Z0-9][a-zA-Z0-9._-]*\b`, `SPECIFIER` = the PEP 440
operator+version regex flattened from `re.VERBOSE|re.IGNORECASE` to a single `(?i)` line, `URL`,
markers) and `_parser.py`'s recursive descent (~250 lines of Go). Go `regexp` has no `(?x)`: flatten
the VERSION pattern by hand and keep a comment naming the source. `str(SpecifierSet)`: each
specifier rendered `operator + version` with surrounding whitespace removed, then `sort.Strings`
and `strings.Join(",")`.

### 4.5 tomllib and json -> `github.com/BurntSushi/toml` v1.5 (new direct; indirect in mcp-xray) and `encoding/json`

TOML: `toml.Decode(text, &map[string]any)`; dates decode to `time.Time`/`toml.LocalDate`, tomllib to
`datetime`; nothing in the group reads them. Errors -> `toml_parse_error:` + message (detail text
differs from Python, see 7). JSON: `json.NewDecoder` with `UseNumber()` into `any`; Go rejects
`NaN`/`Infinity` natively. For `package.json` section iteration order, decode the section objects
with a small ordered decoder (`json.Decoder.Token()` loop over the object, ~30 lines) or store
`Config` as `any` and re-decode the four sections in order with `Token()`. Nesting: Python fails
around depth 1000 (`RecursionError`), Go at 10000; accepted divergence (8/R7).

### 4.6 shlex (non-posix) -> hand-port (15 lines)

Only the `ValueError("No closing quotation")` matters. Verified semantics: whitespace is ASCII
` \t\r\n`; a token that begins with `'` or `"` runs to the next identical quote (whitespace inside
included) and errors at end of input; quotes inside a token are literal (`Do"Not"Separate` is one
token); escapes are not recognised. Implement exactly that scan.

### 4.7 posixpath, urllib.parse.unquote, unicodedata.normalize, html.unescape

- `posixpath.join(base, target)` + `normpath` -> `path.Join` + `path.Clean` (Go `path.Join` already
  cleans). Differences: `normpath("//x") == "//x"` vs `path.Clean == "/x"`; both never match a
  `ByRel` key. `posixpath.join("", "/x") == "/x"` == `path.Join("", "/x")`. `normpath("") == "."`
  == `path.Clean("")`.
- `unquote` -> 15-line port: decode every valid `%XX`, leave invalid sequences verbatim (verified
  `%41%zz%e9` -> `A%zz�`), then decode the byte string as UTF-8 with U+FFFD replacement
  (`strings.ToValidUTF8` is not equivalent: Python replaces each invalid byte with one U+FFFD; use a
  manual loop). `url.PathUnescape` rejects the whole string on one bad escape, so it is not usable.
- `unicodedata.normalize("NFC", s)` -> `golang.org/x/text/unicode/norm.NFC.String(s)` (new direct
  dependency; already indirect). Unicode version differences only affect unassigned code points.
- `html.unescape` -> `html.UnescapeString` (stdlib): both use the HTML5 entity table, the
  0x80-0x9F cp1252 replacement table and U+FFFD for 0/out-of-range (verified Python:
  `&#x110000;&#128;&amp&NotEqualTilde;&#0;` -> `�€&≂̸�`; check Go gives the
  same in the first unit test; regex 3 only feeds `;`-terminated named entities anyway).

### 4.8 tree_sitter_bash -> `mvdan.cc/sh/v3/syntax` (new dependency; brief's suggestion)

No check reads `ShellTree`; only the diagnostics do. `syntax.NewParser(syntax.Variant(syntax.LangBash))`
`.Parse(strings.NewReader(text), "")`: success -> `(file, nil spans, ok)`; a `syntax.ParseError`
-> `(nil, [{err.Pos.Line(), err.Pos.Line()}], ok)`. This changes the `shell_error_region` detail
from tree-sitter's `count:span,span` to `1:L-L` and drops the partial tree (8/R1). tree-sitter's
error recovery cannot be reproduced without cgo or a wasm runtime; the brief allows mvdan/sh.

### 4.9 ast.parse -> `internal/pyast` (code group owns it; cross-group need)

The parse group calls `pyast.Parse(text) (*pyast.Module, *pyast.SyntaxError)` and
`pyast.Depth(m) int` (iterative, counts nesting the way `ast.iter_child_nodes` does). The code
group chooses the implementation (see 8/R2); parse only fixes this contract and the three
diagnostics.

### 4.10 Not used by this group

jsonschema, zipfile/tarfile, ipaddress, bisect, heapq, secrets, zlib, tree_sitter (other than
bash), `MarkdownIt` rendering. `hashlib.sha256` -> `crypto/sha256` in preproc.

## 5. Python semantics that do not translate

| Use | Site | Go treatment |
|---|---|---|
| `str.isspace` / `\s` | `_scan_inline_preproc` boundary, `_split_grants`, `_table_cell_count`, regexes 4, 6, 10, 11, 18, 21 | `pyIsSpace` and class `S` (preamble); the only Go-vs-Python delta, U+001C-U+001F, is covered by the extra range |
| `str.strip()`/`lstrip()`/`rstrip()` with no argument | throughout (`info.strip()`, `code.strip()`, `s.strip()`, `target.strip()`, label strip) | `strings.TrimFunc(s, pyIsSpace)`; `strip(" ")`/`rstrip("\n")`/`lstrip("﻿")` keep their explicit cutsets |
| `str.split()` (no argument) | `_reference_label` | `strings.FieldsFunc(s, pyIsSpace)` |
| `str.splitlines()` | `parse_markdown` executable test, `preproc.check` fenced test | both reduce to "contains a non-pyIsSpace code point" because every `splitlines` separator (`\n \r \v \f \x1c \x1d \x1e \x85    `) is itself whitespace; use `TrimFunc != ""` |
| `str.casefold` | `_reference_label` | `golang.org/x/text/cases.Fold().String(s)` (full folding: `Straße` -> `strasse`, `ς` -> `σ`, `İ` -> `i̇`, verified on the oracle); `strings.ToLower` would differ on those |
| `str.lower()` | `compact_target.lower()`, tag names, `rel.lower()`, `base.lower()` | `strings.ToLower`; differs from Python only for `İ` (Python yields `i` + U+0307, Go `i`); affects only the javascript-scheme check on absurd hrefs |
| `str[:n]`, `len(str)` | `[:80]`, `[:160]`, `[:400]`, `command_length`, `MAX_PY_CHARS`, `_MAX_FM_BYTES`, `str(len(text))` details, `find()` columns | rune-based: `[]rune` slices and `utf8.RuneCountInString` |
| `str.find` returning code-point index | `source_line.find(tok.markup)`, `_mask_inline_code` | byte index then rune conversion |
| `str(k)` for YAML keys | `_plain`, `key_lines` | key node `Value`; Python renders `true` as `True`, `~`/`null` as `None`, `1.0` as `1.0`, a date as `2001-02-03`; Go should emit Python's spellings for bool/null keys (`True`/`False`/`None`) so `keyLines` match; dates as written. Frontmatter keys are almost always strings. |
| YAML scalar typing | `_plain` values reaching checks | ruamel (YAML 1.2 core): `yes` -> str, `014` -> int 14, `0o14` -> 12, `0x1f` -> 31, `1_000` -> 1000, `1e3` -> float, `.inf` -> inf, `2001-02-03` -> date, `12:30:00` -> str, `~` -> None. yaml.v3 agrees on `yes`, `0o14`, `0x1f`, `1e3`, `.inf`, `~`; differs on `014` (yaml.v3: 14 as well via `ParseInt(…, 0)` handles `0` prefix as octal 12 -- check), `1_000` (yaml.v3 strips `_`: 1000), and dates (yaml.v3 gives `time.Time`; ruamel a `date`). Checks read `name`, `description`, `allowed-tools`, `disallowed-tools`, `hooks`, `license` as strings/lists; a non-string there is treated as absent or flagged, so the typing delta is inert unless a manifest puts a bare number/date in a string field. Record the value's `Kind` and compare in the harness only for string-typed keys. |
| duplicate YAML keys by constructed equality | `_fm_load` | ruamel: `1:` and `true:` collide (Python `1 == True`), `1:` and `1.0:` collide, `"1":` and `1:` do not; Go compares `(ShortTag, Value)` so `1`/`true` do not collide. Accepted divergence, pathological. |
| `\u`/`\U` escapes of surrogate code points in double-quoted scalars | `_fm_load` | ruamel's pure-Python scanner takes `chr(int(code, 16))` and keeps each half as a lone surrogate code point, with no diagnostic (measured, ruamel 0.18.15): `"\ud83e\uddea"` -> `'\ud83e\uddea'` (two code points; the shape OpenClaw `metadata:` JSON flow mappings carry for emoji), `"\ud83e"` -> `'\ud83e'`, `"\uddea"` -> `'\uddea'`, `"\U0000D83E"` -> `'\ud83e'`; single-quoted and plain `\ud83e\uddea` stay literal text. libyaml-derived yaml.v3 refuses the escape (`found invalid Unicode character escape code`, naming only the line the scalar starts on), so `fmLoad` probes each surrogate escape as `\z` (rejected only inside a double-quoted scalar) and rewrites the one yaml.v3 rejected: a high+low pair to `\U000XXXXX` (Go holds U+1F9EA where Python holds the two halves; `json.dumps` renders both as `\ud83e\uddea`), a lone half to `�` (Go strings cannot hold a surrogate). Accepted representation divergence. `"\U00110000"` is `chr()`'s ValueError without a mark, `yaml_error` on both sides. |
| dict ordering | `_plain` (YAML), `_npm_deps` sections, `definitions` in `_fallback_links`, `_scan_inline_preproc` `remaining`, `env["references"]`, `by_rel` | Go maps are unordered: `by_rel` iteration never happens (lists are iterated); npm sections need document order (4.5); YAML values reach checks that look keys up, never iterate (verify in core spec for `hooks`); `definitions`/`remaining` are lookup-only |
| `sorted` | `preproc.check` -> `sort_findings` (core `_sort_key`); `str(SpecifierSet)` sorts specifier strings by Python `str` order | `sort.SliceStable` with the core key; `sort.Strings` (byte order == Python code-point order for these ASCII strings) |
| `%` formatting | all diagnostic details and finding messages listed in 2.10/2.11 | `fmt.Sprintf` with `%d`/`%s`; no floats are formatted in this group |
| `shlex.split(posix=False)` | grants | 4.6 |
| `posixpath.normpath/join`, `unquote`, `html.unescape`, `unicodedata.normalize` | refs, projection | 4.7 |
| `bisect`, `heapq` | not used in this group | the `lineOf(offset)` table in 4.1 uses `sort.Search` |
| `time.monotonic` | `parse_package` budget | `time.Now()` (monotonic in Go) |
| `text.encode("utf-8", "surrogatepass")` | `parse_shell` byte cap | ingest decodes with `utf-8-sig` then `cp1252`, never producing surrogates; `len(text)` in bytes |
| `type(exc).__name__` | `parse_crash` detail | the Go panic value's type name; only equality across runs matters, not equality with Python (8/R6) |
| `enumerate(lines + [""], 1)` | requirements | append one empty line so a trailing continuation flushes |

## 6. Test port plan

Pytest files that cover the group and their test counts (`def test_` on main):

| File | Tests | What it pins | Go home |
|---|---|---|---|
| `tests/test_parse.py` | 118 | every parser, frontmatter, grants, manifests, deps, refs, DoS bounds, determinism | `internal/parse/*_test.go` |
| `tests/test_preproc.py` | 70 | SXV-001/002 findings, columns, caps, fallback path via `_MD.parse` monkeypatch (23 tests) | `internal/preproc/preproc_test.go` (findings) and `internal/parse/preproc_scan_test.go` (fallback scanners) |
| `tests/test_fence_locations.py` | 9 | fence-to-source column mapping; exercises `parse_package` but asserts opengrep_bridge/correlate/sarif behaviour | code group ports it; parse supplies `Fences`, `FenceSpans`, `Text` |
| `tests/test_grants.py` (2 direct `parse_grants` calls), `tests/test_disposition.py` (1 `preproc.check`), `tests/test_sarif_release.py` (1), `tests/test_batch3_microcorpus.py` (2 rows) | 6 | integration through other groups | stay with their groups |

Total to port in this group: 118 + 70 = 188 (plus 9 shared with code). Fixtures: none of the three
files read files under `tests/`; every input is an inline literal built with the `make_package`
fixture (`conftest.py`: writes `str` values UTF-8 with newlines preserved byte for byte, `bytes`
raw) and `ingest.build_package`. So the Go tests are table tests whose inputs are the same literal
strings, written to `t.TempDir()` through the Go `ingest` package (a shared `testutil.MakePackage(t,
map[string]string)` helper in `internal/ingest` mirrors `make_package`; the core group owns it and
parse depends on it). Do not translate the literals into a fixture directory: the Python tests are
the fixtures, and a table row per pytest case keeps the `tests/<file>::<name>` citation searchable.

Test-only hooks: `PkgBudget` is a package variable set negative by one test; the markdown-failure
tests replace the `parseMarkdown` variable with a function returning `(nil, "memoryerror")`, and
the two `fail_root` tests return an error only when the text contains the root's link (the Go test
checks `strings.Contains`). The `parse_crash` test replaces the `parseMD` variable with a panicking
function. These three variables replace `monkeypatch`; nothing else in `parse` is swappable.

Performance pins to keep as Go tests with `testing.Short()`-independent time bounds (1 s):
`test_markdown_many_links_no_quadratic_blowup`, `test_grant_whitespace_before_parenthesis_is_linear`,
`test_grant_specifier_padding_no_redos`, `test_requirements_continuation_is_linear`,
`test_table_classification_is_linear_on_hostile_divider_input`, `test_malformed_long_table_divider_is_linear`,
`test_frontmatter_merge_bomb_defused_all_forms`, `test_shell_pipe_bomb_is_bounded_not_parsed`.

Tests that cannot pass unchanged and how they are ported: `test_shell_tree_sitter_cst` and
`test_python_and_shell_scripts` assert `root_node.type == "program"`: assert `ShellTree != nil`
instead. `test_shell_error_region_recorded_not_dropped` asserts `tree is not None and errs`: with
mvdan/sh the tree is nil on error, so assert `errs` non-empty only (8/R1). `test_shell_nested_error_region_is_covered`
asserts line 2 lies in a span: holds (mvdan reports the error on line 2). `test_python_*` depend on
`internal/pyast` (8/R2). `test_frontmatter_timestamp_value_error_fails_closed` needs the 4.3
timestamp check. `test_one_hostile_manifest_does_not_abort_scan` (`!!bool notabool`) passes
because yaml.v3 fails to decode a mistyped tagged scalar.

## 7. Parity hooks

Group `parse` influences these `skill-xray --json` fields (`cli.py` lines 272-282) and their SARIF
counterparts:

- `findings[]` with `rule == "preproc-inline-bang"` (SXV-001) and `"preproc-fenced-bang"` (SXV-002):
  `path`, `line`, `column`, `message`, `evidence.{command_text, command_length, command_sha256,
  truncated, column, fence_state|fence_info, block_line_count, selector}`; plus `rule ==
  "findings-capped"` with a message naming `SXV-001`/`SXV-002`. Attribute to `parse` when the
  vector is 001/002.
- `findings[]` with `rule == "coverage-note"` or `"analysis-incomplete"` whose
  `evidence.phase == "parse"`: one per distinct `(parse, reasonCode, path)` from
  `checks/coverage.py`; severity `low` for `config_parse_error, dep_manifest_unparsed,
  frontmatter_parse_error, grants_unparsed_shape, markdown_parse_error, raw_html_markup,
  requirement_unparsed, unmodeled_content, unsupported_markup`, `high` otherwise; message `"parse analysis coverage is
  incomplete (<reasonCode>)."`. The ledger `detail` is **not** in the finding, so detail-text
  differences (TOML/JSON error messages, shell span lists) do not reach findings, only the ledger.
- `ledger.exceptions[]` entries with `phase == "parse"`: `reasonCode`, `detail`, `path` (sorted by
  `(path, reasonCode)` in `build_ledger`). The harness should compare `reasonCode` exactly and
  `detail` exactly except for `config_parse_error` (engine message text) and `shell_error_region`
  (4.8), which it compares as "present".
- Indirectly, every other finding: `disposition._source_known` returns false for any artifact with
  a non-empty `Diagnostics`, and `apply_dispositions` sets a package-wide gap when any parse ledger
  entry exists (`_material_ledger_entry` returns true for every non-static phase), so a spurious or
  missing parse diagnostic flips `properties.disposition`/`limitations`/`coverage` on **all**
  SARIF results of that package. This makes diagnostic parity the group's highest-value hook:
  the harness should print the set difference of `(path, reasonCode)` per package before diffing
  findings.
- `correlate` embeds `artifact.diagnostics` in each result's context digest, and every
  span-consuming check (instruction_exfil, obfuscation, persistence, hooks, supply_chain, capability,
  code_lane) reads `ProseSpans`, `FenceSpans`, `CodeSpans`, `ParagraphSpans`, `ReferenceSpans`,
  `Fences`, `HTMLComments`, `HTMLProse`, `HTMLUninspectable`, `FrontmatterEndLine`,
  `FrontmatterKeyLines`, `Grants`, `Deps`, `Config`, `Refs`. For attribution, `tools/parity` should
  add a `--dump-ir` mode on both sides that writes, per artifact, these fields as sorted JSON
  (`ir.json`) so an IR diff is checked before a findings diff; a findings diff with an identical IR
  belongs to the consuming group.
- JSON key order: Python emits `evidence` in insertion order; Go `map[string]any` sorts keys. The
  harness must compare parsed JSON, not bytes, for `--json`; SARIF byte parity (if required by the
  output group) needs an ordered evidence type owned by core.
- Frozen benchmark: `test_final.jsonl` records only `{vector, rule, severity, tier, line}` per
  finding, so reason codes are not recoverable from it; it contains 190 `analysis-incomplete` (30
  without a line, the shape coverage findings have) and 3 `coverage-note` findings, 0 SXV-001/002,
  0 SXV-034 and 0 `findings-capped`, so the corpus barely exercises this group's own vectors.
  Parity must be run against the Python CLI `--json` output, not the frozen file.

## 8. Risks and open questions

R1. **Shell error regions (mvdan/sh vs tree-sitter-bash).** Python emits `shell_error_region` with a
count and up to 20 spans and keeps a partial tree; mvdan/sh stops at the first error. No check reads
the tree, so the only visible deltas are the ledger `detail` string and, when tree-sitter recovers
but mvdan errors (or the reverse), the presence of the diagnostic itself, which flips a high-severity
coverage finding and the package disposition. Recommendation: use mvdan/sh (brief's suggestion, no
cgo), measure the presence delta over the MSB corpus in the first parity run, and if it exceeds a
handful of packages, fall back to shelling out to a pinned tree-sitter CLI is not acceptable; the
remaining option is tree-sitter-bash compiled to wasm under `wazero` (pure Go; mcp-xray already
pulls `wazero` indirectly via `go-re2`). Decide after the measurement, not before.

R2. **Python AST (cross-group).** `_parse_python` needs a Python 3.13-grammar parser for three
diagnostics, and opengrep_bridge needs the tree for its post-filter. No pure-Go Python 3 parser
exists (`gpython` stops at 3.4 grammar and would emit false `python_syntax_error` on f-strings and
`match`, each of which becomes a high coverage finding and a disposition flip). Recommendation to
the code group: tree-sitter-python via wasm/wazero for the tree, plus accept that
`python_syntax_error` presence follows tree-sitter's ERROR nodes rather than CPython (document the
delta class); `python_too_complex` (depth 512) must be computed on the same node kinds as
`ast.iter_child_nodes`, which tree-sitter's CST does not mirror (`"a"+"a"+…` is a left-nested
`binary_operator` chain in both, so the pinned test passes, but general depth parity is
approximate). Parse only fixes the call contract in 4.9.

R3. **Column and length units.** Every column and length in this group is code-point based. A byte
column anywhere silently breaks parity on any non-ASCII line (`test_unicode_separator_does_not_shift_bang_fence_column`,
`test_fence_locations.py` `é😀` cases). Recommendation: one `runeCol(line string, byteOff int) int`
helper in `internal/parse` and no direct `+1` on byte offsets; the review checklist greps for
`len(` on user text.

R4. **`markdown_parse_error` never fires in Go.** Python only fails on `RecursionError`/`MemoryError`
(no corpus incidence known); goldmark cannot fail. Accepted divergence; the fallback scanners still
ship because 23 tests pin them and because they are the only path for frontmatter preprocessing.

R5. **goldmark fidelity vs markdown-it 4.0.** Both target CommonMark 0.31.2, but the group depends
on token maps, inline child order, code-span content normalisation, link label text, and setext
heading spans that the goldmark AST does not expose one-to-one (4.1 lists each derivation,
including the forked fence parser). Recommendation: a dedicated `markdown_facts_test.go` that runs
both engines over the golden corpus and the MSB `SKILL.md` set and diffs the fact tuples (fences,
code blocks, html blocks, inline spans, links with lines, reference spans, preproc tokens) before
any check is ported; this isolates parser drift from check-logic bugs. Known unknown: goldmark's
handling of a link reference definition's `map` (4.1) may yield single-line spans where
markdown-it spans a multi-line title; obfuscation consumes `ReferenceSpans`, so record the gap.

R6. **Diagnostic detail strings that cannot match.** `config_parse_error` (tomllib/json vs
BurntSushi/encoding-json messages), `parse_crash` (Python exception name vs Go panic type),
`shell_error_region` (R1). Recommendation: the Go side emits the same `code:` prefix and the harness
compares those three details as presence-only. `python_syntax_error` detail `line N` should match
when R2's parser reports the first error line like CPython; treat as compare-exact and review
failures.

R7. **Pathological-input divergences accepted:** JSON nesting between 1000 and 10000 levels (Python
errors, Go parses); a YAML block with an alias followed by a syntax error (Python `yaml_alias_budget`
from the partial event stream, Go `yaml_error:line N`); duplicate YAML keys under Python numeric
equality (`1`/`true`/`1.0`); `İ` lowercasing in scheme checks; `\x1c-\x1f` are covered by
`pyIsSpace`. None has a corpus incidence; list them in the harness's known-divergence file.

R8. **YAML scalar typing (5).** yaml.v3 and ruamel agree on the YAML 1.2 core schema for the values
the checks read as strings; dates and `1_000` differ in type. Open check for the implementer: yaml.v3
on `014` (verify it yields 14 like ruamel, not 12). Recommendation: the IR dump (7) records
`reflect.Kind` per top-level frontmatter value so the harness can show any typing drift on the
corpus.

R9. **Go version.** Nothing in this group needs Go 1.25 features; `for range int` and `min/max`
(1.21+) are enough. Recommendation: pin `go 1.24` in `go.mod` (the machine's toolchain) unless
another group needs 1.25.

R10. **Dependency additions this group requests** (ponytail rung 5 checked: none is replaceable by
a few lines): `github.com/yuin/goldmark`, `golang.org/x/net/html`, `golang.org/x/text`
(`unicode/norm`, `cases`), `github.com/BurntSushi/toml`, `mvdan.cc/sh/v3`. Not requested:
`dlclark/regexp2` (0 patterns need it), any PEP 508/440 library (hand-port, 4.4), any HTML entity
library (stdlib `html`).

## Errata from wave 3

R4 applied: the markdown fallback scanners are not ported; goldmark cannot fail, so the path is unreachable; the corpus fact diff shows 0 cases where markdown-it fell back.

## Errata from wave 5

R1 measured: over the 3,613 corpus packages the `shell_error_region` presence delta between
tree-sitter-bash and mvdan/sh is one artifact (`hooks/pre-rebase.sample` in
`pytest/test_schema_packaging.py_test_git_checkout_preserves_pinned_bytes_with_autocrlf-2ecffc47/.git`,
where tree-sitter reports an error region and mvdan/sh parses cleanly). mvdan/sh stays; the wasm
fallback is not taken. The coverage lane lists that package as a known divergence in
`internal/checks/parity_test.go`, and `testutil.CheckParity` fails if it ever stops diverging.
The 2026-09-18 full parity run confirmed the incidence at 1 of 3,612 packages, so mvdan/sh is kept
and `known_divergences.json` accepts that package whole only when the oracle alone carries the
`shell_error_region` finding (the three packages diagnosing it on both sides stay strictly compared).

## Errata from wave 8 (posture audit, 2026-09-19)

Output parity never measured time or memory, and a nine-lens audit of the built binary found the
places where the Go side was exponential or quadratic on inputs the Python side handles:

- `internal/pyast` memoises the rules pegen memoises (`expression`, `star_expression`,
  `disjunction`, `conjunction`, `inversion`, the binary levels, `factor`, `await_primary`,
  `primary`, `strings`, `star_target`, `target_with_star_atom`, `del_target`, `t_primary`), keyed
  by (rule, position). Before, only `expression` was memoised: the `star_targets` attempt on an
  assignment's right-hand side re-descended each parenthesis twice (2^depth, a 62-byte file never
  returned) and the `invalid_*` second pass re-descended each bracket about six times. The
  `(fstring|string)+` repetition in `strings` now stops when `fstring` fails instead of appending
  nil and re-peeking the same token forever. Output on the 12,007-input contract corpus is
  unchanged.
- `parse_package`: a single artifact's parse is abandoned at the remaining package budget and
  recorded as `parse_budget_exceeded` (00-overview §7); Python checks only between artifacts.
- `parse_markdown`: `markdown_too_complex` refuses a body line with more than 10,000 leading
  container markers or `](` openers before goldmark (00-overview §7).
- `tomllib.loads`: a key path deeper than 1,000 segments is refused as `config_parse_error`
  before BurntSushi/toml decodes it (00-overview §7).
- Instruction lane (`_exfil_deliveries`, `_exfil_sentences`): byte/code-point offsets come from a
  per-sentence index built once, and the article guard on a verb reads the last six bytes of the
  prefix (the pattern is end-anchored and at most five bytes). Obfuscation (`checkConcealment`):
  the misreport-context regex runs once per block and the imperative-prefix search is one forward
  scan per pattern. All three are output-neutral; Python keeps its quadratic prefix rescans.
