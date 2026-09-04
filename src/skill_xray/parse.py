"""Parse an ingested skill package into one shared representation (the IR).

Each file is parsed once with a real parser per format. Fail closed and per-artifact
isolated: any error is a typed diagnostic, never a crash or a silent-clean file; a
missing diagnostic means "parsed", not "safe" (prose lives only in the raw `.text`)."""

from __future__ import annotations

import ast
import io
import json
import posixpath
import re
import time
import tomllib
import unicodedata
import warnings
from dataclasses import dataclass, field
from urllib.parse import unquote

import tree_sitter_bash
from markdown_it import MarkdownIt
from packaging.requirements import InvalidRequirement, Requirement
from ruamel.yaml import YAML
from ruamel.yaml.constructor import DuplicateKeyError
from ruamel.yaml.events import AliasEvent
from tree_sitter import Language, Parser

__all__ = ["Grant", "Preproc", "Markdown", "ParsedArtifact", "ParsedPackage",
           "parse_package", "parse_markdown", "parse_frontmatter", "parse_grants",
           "parse_shell", "classify_manifest"]

# Artifact kinds come from ingest._classify, grouped by how they are parsed.
_MARKDOWN_KINDS = {"skill_manifest", "instruction", "doc", "agent_identity"}
_JSON_CONFIG_KINDS = {"hooks_config", "mcp_config", "plugin_manifest",
                      "app_manifest", "plugin_lock"}
_MAX_ERROR_SPANS = 20      # per-file ERROR spans listed in a diagnostic (count is kept)
_DETAIL_CAP = 80           # chars of a parser error message kept in a diagnostic
_MAX_SHELL_BYTES = 524288  # coarse backstop for any superlinear tree-sitter-bash construct
_MAX_SHELL_PIPES = 3000    # long pipe chains are its known O(n^2) case; bound them (|| is fine)
MAX_PY_CHARS = 524288      # ast.parse retains a node graph that amplifies source size in memory
MAX_PREPROC_TOKENS = 25
_MAX_PY_AST_DEPTH = 512    # deterministic across platform recursion-stack sizes
_PKG_BUDGET = 60           # whole-package wall-clock cap; many bomb files cannot sum unbounded


# --- markdown (markdown-it-py: CommonMark tokens, read never rendered) ---

_MD = MarkdownIt("commonmark")


@dataclass
class Preproc:
    """A load-time preprocessing token (target-model row 2); runs = live substitution vs decoy."""

    kind: str
    code: str
    line: int
    runs: bool
    column: int = 1
    info: str = ""


@dataclass
class Markdown:
    """Line-anchored markdown: links, fenced/indented code, prose and reference-definition source
    spans (so a prose check can skip code without reconstructing Markdown), preproc, has_html."""

    links: list = field(default_factory=list)
    fences: list = field(default_factory=list)
    code_spans: list = field(default_factory=list)
    prose_spans: list = field(default_factory=list)
    reference_spans: list = field(default_factory=list)
    preproc: list = field(default_factory=list)
    preproc_counts: dict = field(default_factory=lambda: {"inline": 0, "fenced": 0})
    has_html: bool = False


def _scan_inline(inline, line, md):
    children = inline.children or []
    for j, c in enumerate(children):
        if c.type in ("softbreak", "hardbreak"):
            line += 1                     # inline children carry no map; count line breaks
        elif c.type == "link_open":
            href = (c.attrs or {}).get("href", "")
            txt = ""                                   # whole label; index not slice (O(n^2))
            for k in range(j + 1, len(children)):
                if children[k].type == "link_close":
                    break
                txt += children[k].content or ""
            md.links.append((href, txt, line))
        elif c.type == "html_inline":
            md.has_html = True                    # opaque to CommonMark; a check reads .text


_FENCE_OPEN_RE = re.compile(r"^( {0,3})(`{3,}|~{3,})(.*)$")
_TABLE_DIVIDER_RE = re.compile(
    r"^\s*+\|?\s*+:?-{3,}:?(?:\s*+\|\s*+:?-{3,}:?)*\s*+\|?\s*+$"
)
_BLOCK_OPENER_RE = re.compile(
    r"^ {0,3}(?:#{1,6}(?:[ \t]|$)|`{3,}|~{3,}|(?:[-+*]|\d+[.)])[ \t]+)"
)
_LIST_ITEM_RE = re.compile(r"^(\s*)(?:[-+*]|\d+[.)])([ \t]+)")
_FALLBACK_LINK_RE = re.compile(
    r"(?<!!)\[[^\]\n]{0,500}\]\(\s*<?([^\s)>]{1,1000})>?[^)\n]{0,1000}\)"
)
_REFERENCE_DEFINITION_RE = re.compile(
    r"^ {0,3}\[([^\]\n]{1,500})\]:[ \t]*<?([^\s>]{1,1000})>?"
)
_REFERENCE_USE_RE = re.compile(
    r"(?<!!)\[([^\]\n]{1,500})\]\[([^\]\n]{0,500})\]"
)
_SHORTCUT_REFERENCE_RE = re.compile(
    r"(?<![!\]])\[([^\]\n]{1,500})\](?![\[(:])"
)


def _blockquote_parts(line):
    position = 0
    depth = 0
    while position < len(line):
        segment_start = position
        spaces = 0
        while position < len(line) and line[position] == " " and spaces < 3:
            position += 1
            spaces += 1
        if position >= len(line) or line[position] != ">":
            return ((line, 0, 0) if depth == 0 else
                    (line[segment_start:], segment_start, depth))
        depth += 1
        position += 1
        if position < len(line) and line[position] in " \t":
            position += 1
    return line[position:], position, depth


def _table_separators(line):
    separators = []
    code_width = None
    index = 0
    while index < len(line):
        if line[index] == "\\":
            index += 2
            continue
        if line[index] == "`":
            end = index + 1
            while end < len(line) and line[end] == "`":
                end += 1
            width = end - index
            if code_width is None:
                code_width = width
            elif code_width == width:
                code_width = None
            index = end
            continue
        if line[index] == "|" and code_width is None:
            separators.append(index)
        index += 1
    return separators


def _table_cell_count(line):
    separators = _table_separators(line)
    if not separators:
        return 0
    first = len(line) - len(line.lstrip())
    last = len(line.rstrip()) - 1
    return (len(separators) + 1 - int(separators[0] == first)
            - int(separators[-1] == last))


def _table_lines(lines):
    table = set()
    index = 1
    while index < len(lines):
        line, _line_prefix, line_depth = _blockquote_parts(lines[index])
        header, _header_prefix, header_depth = _blockquote_parts(lines[index - 1])
        if (not _TABLE_DIVIDER_RE.match(line) or not _table_cell_count(line)
                or _table_cell_count(line) != _table_cell_count(header)
                or line_depth != header_depth):
            index += 1
            continue
        start = index - 1
        end = index
        while end + 1 < len(lines):
            candidate, _prefix, depth = _blockquote_parts(lines[end + 1])
            if (depth != line_depth or _BLOCK_OPENER_RE.match(candidate)
                    or not _table_cell_count(candidate)):
                break
            end += 1
        table.update(range(start, end + 1))
        index = end + 1
    return table


def _indented_code_lines(lines):
    return {
        index for index, (content, _prefix, _container) in enumerate(_container_lines(lines))
        if content.startswith("\t") or len(content) - len(content.lstrip(" ")) >= 4
    }


def _container_lines(lines):
    list_indents = {}
    prepared = []
    for source in lines:
        content, quote_prefix, depth = _blockquote_parts(source)
        if not content.strip():
            list_indent = list_indents.get(depth, 0)
            prepared.append((content, quote_prefix, (depth, list_indent)))
            continue
        item = _LIST_ITEM_RE.match(content)
        if item:
            list_indent = len(item.group(0))
            list_indents[depth] = list_indent
            prepared.append((
                content[list_indent:], quote_prefix + list_indent, (depth, list_indent),
            ))
            continue
        list_indent = list_indents.get(depth)
        leading = len(content) - len(content.lstrip(" "))
        if list_indent is not None and leading >= list_indent:
            prepared.append((
                content[list_indent:], quote_prefix + list_indent, (depth, list_indent),
            ))
        else:
            if leading == 0:
                list_indents.pop(depth, None)
            prepared.append((content, quote_prefix, (depth, 0)))
    return prepared


def _fallback_block_starts(lines):
    starts = set()
    previous_depth = None
    prepared = _container_lines(lines)
    for index, (candidate, _prefix, _container) in enumerate(prepared):
        raw, _quote_prefix, depth = _blockquote_parts(lines[index])
        if index and depth != previous_depth:
            starts.add(index)
        if _LIST_ITEM_RE.match(raw) or _BLOCK_OPENER_RE.match(candidate):
            starts.add(index)
        previous_depth = depth
    return starts


def _fenced_lines(lines):
    fenced = set()
    fence = None
    for index, (source, _prefix, container) in enumerate(_container_lines(lines)):
        if fence is not None and container != fence[2]:
            fence = None
        match = _FENCE_OPEN_RE.match(source)
        if fence is None:
            if match:
                marker_run = match.group(2)
                if marker_run[0] == "~" or "`" not in match.group(3):
                    fence = marker_run[0], len(marker_run), container
                    fenced.add(index)
            continue
        fenced.add(index)
        marker, width, _container = fence
        stripped = source.lstrip(" ")
        indent = len(source) - len(stripped)
        if (indent <= 3
                and re.match(r"^(%s{%d,})[ \t]*$" % (re.escape(marker), width), stripped)):
            fence = None
    return fenced


def _scan_fenced_preproc(text, line_offset=0):
    tokens = []
    total = 0
    active = None

    def finish(state):
        nonlocal total
        marker, width, info, opener, column, content, _container = state
        code = "\n".join(content)
        if not info.startswith("!") or not code.strip():
            return
        total += 1
        if total <= MAX_PREPROC_TOKENS:
            tokens.append(Preproc(
                "fenced", code, opener + 1 + line_offset, runs=True,
                column=column, info=info,
            ))

    prepared = _container_lines(text.split("\n"))
    for index, (candidate, prefix, container) in enumerate(prepared):
        if active is not None:
            marker, width, info, opener, column, content, active_container = active
            if container != active_container:
                finish(active)
                active = None
            else:
                stripped = candidate.lstrip(" ")
                indent = len(candidate) - len(stripped)
                if (indent <= 3 and re.match(
                        r"^(%s{%d,})[ \t]*$" % (re.escape(marker), width), stripped)):
                    finish(active)
                    active = None
                else:
                    content.append(candidate)
                continue
        match = _FENCE_OPEN_RE.match(candidate)
        if not match:
            continue
        marker_run = match.group(2)
        if marker_run[0] == "`" and "`" in match.group(3):
            continue
        active = (
            marker_run[0], len(marker_run), match.group(3).strip(), index,
            prefix + len(match.group(1)) + 1, [], container,
        )
    if active is not None:
        finish(active)
    return tokens, total


def _without_inline_code(line):
    masked = list(line)
    index = 0
    while index < len(line):
        if line[index] == "\\":
            index += 2
            continue
        if line[index] != "`":
            index += 1
            continue
        end = index + 1
        while end < len(line) and line[end] == "`":
            end += 1
        marker = line[index:end]
        close = line.find(marker, end)
        if close < 0:
            index = end
            continue
        masked[index:close + len(marker)] = " " * (close + len(marker) - index)
        index = close + len(marker)
    return "".join(masked)


def _masked_fallback_lines(lines, excluded):
    masked = list(lines)
    block = []

    def flush():
        if not block:
            return
        content = "\n".join(lines[index] for index in block)
        for index, value in zip(
            block, _without_inline_code(content).split("\n"), strict=True,
        ):
            masked[index] = value
        block.clear()

    for index, line in enumerate(lines):
        candidate = _blockquote_parts(line)[0]
        if index in excluded or not line.strip():
            flush()
            continue
        if block and _BLOCK_OPENER_RE.match(candidate):
            flush()
        block.append(index)
    flush()
    return masked


def _reference_label(value):
    return " ".join(value.split()).casefold()


def _fallback_links(text, line_offset=0):
    lines = text.split("\n")
    excluded = _fenced_lines(lines) | _indented_code_lines(lines) | _table_lines(lines)
    masked = _masked_fallback_lines(lines, excluded)
    definitions = {}
    for index, line in enumerate(masked):
        if index in excluded:
            continue
        match = _REFERENCE_DEFINITION_RE.match(line)
        if match:
            definitions[_reference_label(match.group(1))] = match.group(2)
    links = []
    for index, line in enumerate(masked):
        if index in excluded:
            continue
        for match in _FALLBACK_LINK_RE.finditer(line):
            links.append((match.group(1), "", index + 1 + line_offset))
        for match in _REFERENCE_USE_RE.finditer(line):
            label = _reference_label(match.group(2) or match.group(1))
            if label in definitions:
                links.append((definitions[label], "", index + 1 + line_offset))
        for match in _SHORTCUT_REFERENCE_RE.finditer(line):
            label = _reference_label(match.group(1))
            if label in definitions:
                links.append((definitions[label], "", index + 1 + line_offset))
    return links


def _scan_inline_preproc(
    text, line_offset=0, excluded_lines=None, *, markdown_exclusions=True,
    block_starts=None,
):
    """Linear harness-syntax scan outside fences, multi-backtick spans, and tables."""
    lines = text.split("\n")
    # Successful CommonMark parsing supplies exact code spans. If parsing fails, conservative
    # indentation also keeps obvious examples from becoming executable findings.
    conservative = excluded_lines is None
    if conservative and block_starts is None:
        block_starts = _fallback_block_starts(lines)
    table = _table_lines(lines) if markdown_exclusions else set()
    fenced = _fenced_lines(lines) if conservative and markdown_exclusions else set()
    excluded = set() if excluded_lines is None else excluded_lines
    indented_code = _indented_code_lines(lines) if conservative else set()
    block_ids = []
    block = 0
    for index, source in enumerate(lines):
        if block_starts and index in block_starts:
            block += 1
        if (not source.strip() or index in fenced or index in table or index in indented_code
                or index in excluded):
            block += 1
            block_ids.append(None)
        else:
            block_ids.append(block)
    remaining = {}
    for index, source in enumerate(lines):
        block_id = block_ids[index]
        if block_id is None:
            continue
        counts = remaining.setdefault(block_id, {})
        for match in re.finditer(r"`{2,}", source):
            width = len(match.group(0))
            counts[width] = counts.get(width, 0) + 1
    tokens = []
    total = 0
    decoys = 0
    inline_ticks = None
    active_block = None
    for line_index, source in enumerate(lines):
        block_id = block_ids[line_index]
        if block_id is None:
            inline_ticks = None
            active_block = None
            continue
        if block_id != active_block:
            inline_ticks = None
            active_block = block_id
        position = 0
        while position < len(source):
            if markdown_exclusions and source[position] == "`":
                end = position + 1
                while end < len(source) and source[end] == "`":
                    end += 1
                width = end - position
                if width >= 2:
                    remaining[block_id][width] -= 1
                    if inline_ticks is None:
                        if remaining[block_id][width] > 0:
                            inline_ticks = width
                    elif inline_ticks == width:
                        inline_ticks = None
                position = end
                continue
            if (inline_ticks is None and source[position] == "!"
                    and position + 2 < len(source) and source[position + 1] == "`"
                    and source[position + 2] != "`"):
                end = source.find("`", position + 2)
                if end > position + 2 and (end + 1 == len(source) or source[end + 1] != "`"):
                    command = source[position + 2:end]
                    if not command.strip():
                        position = end + 1
                        continue
                    runs = position == 0 or source[position - 1].isspace()
                    if runs:
                        total += 1
                    else:
                        decoys += 1
                    if ((runs and total <= MAX_PREPROC_TOKENS)
                            or (not runs and decoys <= MAX_PREPROC_TOKENS)):
                        tokens.append(Preproc(
                            "inline", command,
                            line_index + 1 + line_offset, runs=runs, column=position + 1,
                        ))
                    position = end + 1
                    continue
            position += 1
    return tokens, total


def _norm_newlines(text):
    """CRLF and lone-CR -> LF. The single newline-normalization used across parse, so the text the
    IR exposes and the line numbers it emits share one line space (returns None unchanged)."""
    if text is None:
        return None
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _fm_bounds(text):
    """(lines, has_open, end): normalized lines and the column-0 open/close of a `---` block."""
    lines = _norm_newlines(text).split("\n")
    first = lines[0].lstrip("\ufeff") if lines else ""
    if first[:1] in (" ", "\t") or first.rstrip() != "---":
        return lines, False, None
    for i in range(1, len(lines)):
        s = lines[i]
        if s[:1] not in (" ", "\t") and s.rstrip() in ("---", "..."):
            return lines, True, i
    return lines, True, None


def _body_and_offset(text):
    """(markdown_body, line_offset) past a leading `--- ... ---` block (setext-safe)."""
    lines, has_open, end = _fm_bounds(text)
    if not has_open or end is None:
        return text, 0
    return "\n".join(lines[end + 1:]), end + 1


def parse_markdown(text, line_offset=0):
    """Markdown -> (Markdown, err), lines offset to the file (indented code kept too)."""
    text = _norm_newlines(text)                 # normalize breaks so line counts match
    env = {}
    try:
        tokens = _MD.parse(text, env)
    except (RecursionError, MemoryError) as exc:
        return None, type(exc).__name__.lower()
    md = Markdown()
    source_lines = text.split("\n")
    preproc_excluded = set()
    block_starts = set()
    for tok in tokens:
        line = (tok.map[0] + 1 + line_offset) if tok.map else 0
        if tok.type in ("fence", "code_block"):
            if tok.map:
                preproc_excluded.update(range(tok.map[0], tok.map[1]))
            info = tok.info.strip() if tok.type == "fence" else ""
            md.fences.append((info, tok.content, line))
            if tok.map:
                md.code_spans.append((tok.map[0] + 1 + line_offset, tok.map[1] + line_offset))
            if info.startswith("!"):
                source_line = source_lines[tok.map[0]] if tok.map else ""
                marker = source_line.find(tok.markup)
                column = marker + 1 if marker >= 0 else 1
                executable = any(source.strip() for source in tok.content.splitlines())
                if executable:
                    md.preproc_counts["fenced"] += 1
                if executable and md.preproc_counts["fenced"] <= MAX_PREPROC_TOKENS:
                    md.preproc.append(Preproc(
                        "fenced", tok.content, line, runs=True, column=column, info=info,
                    ))
        elif tok.type == "html_block":
            md.has_html = True
            if tok.map:
                md.prose_spans.append((tok.map[0] + 1 + line_offset, tok.map[1] + line_offset))
                block_starts.add(tok.map[0])
        elif tok.type == "inline":
            if tok.map:
                md.prose_spans.append((tok.map[0] + 1 + line_offset, tok.map[1] + line_offset))
                block_starts.add(tok.map[0])
            _scan_inline(tok, line, md)
        elif tok.type == "table_open" and tok.map:
            preproc_excluded.update(range(tok.map[0], tok.map[1]))
    # A CommonMark link reference definition (`[label]: url "title"`) emits no token, so its title
    # text lands in no prose span; keep its source span so a prose check still scans that title.
    for ref in (env.get("references") or {}).values():
        span = ref.get("map")
        if span:
            md.reference_spans.append((span[0] + 1 + line_offset, span[1] + line_offset))
    inline, total = _scan_inline_preproc(
        text, line_offset, preproc_excluded, block_starts=block_starts,
    )
    md.preproc.extend(inline)
    md.preproc_counts["inline"] = total
    return md, None


# --- frontmatter (ruamel.yaml round-trip: gives per-key line/col) + allowed-tools grants ---

# tool + optional `(...)`. Possessive `\s*+` blocks O(n^2) backtracking (padded-spec DoS).
_GRANT_RE = re.compile(r"^([A-Za-z_][\w.-]*)\s*+(?:\((.*)\))?\s*+$", re.DOTALL)
# DoS bound on the YAML parser: metadata is tiny, but ruamel's event parse is superlinear in flow
# nesting (measured: 256 openers 0.015s, 2000 -> 3.3s, 8000 (a 16KB block) -> 20.5s). Legitimate
# frontmatter has a handful of flow openers, so a block over the cap is refused outright rather
# than parsed. This replaces an earlier killable-subprocess path -- refusing is both leaner (no
# per-manifest process spawn) and safe (no unguarded-__main__ misdiagnosis on a spawn platform).
_MAX_FM_BYTES = 16384
_MAX_FM_FLOW = 256         # `[`/`{` count above which the block is refused as a flow-nesting bomb


def _plain(obj):
    """ruamel round-trip types -> plain dict/list/scalars (so nothing downstream sees ruamel)."""
    if isinstance(obj, dict):
        return {str(k): _plain(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_plain(v) for v in obj]
    return obj


def _fm_load(block):
    """Refuse anchors/aliases/`!!python` tags via the event stream, then load -> (values,
    key_lines, error). Slow only on deep flow nesting, which the caller bounds by refusing a
    block whose flow-opener count exceeds _MAX_FM_FLOW before this runs."""
    try:
        for ev in YAML(typ="rt").parse(io.StringIO(block)):   # events resolve nothing: bomb-safe
            if isinstance(ev, AliasEvent) or getattr(ev, "anchor", None) is not None:
                return None, {}, "yaml_alias_budget"
            if "python/" in str(getattr(ev, "tag", "")):      # !!python/* deserialization RCE
                return None, {}, "yaml_unsafe_tag"
        data = YAML(typ="rt").load(io.StringIO(block))        # fresh loader per artifact: isolated
    except DuplicateKeyError:                                 # specific code before generic below
        return None, {}, "yaml_duplicate_key"
    except Exception as exc:                                  # any hostile-YAML error, fail closed
        mark = getattr(exc, "problem_mark", None)             # +2: block dropped the opening `---`
        return None, {}, "yaml_error:line %d" % (mark.line + 2) if mark else "yaml_error"
    if data is None:
        return {}, {}, None
    if not isinstance(data, dict):               # CommentedMap is a dict; a list/scalar is not
        return None, {}, "frontmatter_not_a_mapping"
    lc = getattr(data, "lc", None)               # .lc carries the real top-level key line
    key_lines = {str(k): lc.data[k][0] + 2 for k in data if lc and lc.data and k in lc.data}
    return _plain(dict(data)), key_lines, None


@dataclass
class Grant:
    """One allowed/disallowed-tools entry; broad=True for a bare tool (`Bash`), row-3 pre-grant."""

    tool: str
    pattern: str | None
    raw: str
    allowed: bool
    broad: bool
    parsed: bool = True


def parse_frontmatter(text):
    """Leading `--- ... ---` YAML block -> (values, key_lines, error). Anchors/aliases and unsafe
    tags are refused; a flow-nesting bomb (too many `[`/`{` for tiny metadata) is refused before the
    parser runs, so a deep-nest block cannot hang. Values are plain (no ruamel types)."""
    lines, has_open, end = _fm_bounds(text)
    if not has_open:
        return None, {}, None
    if end is None:
        return None, {}, "frontmatter_unterminated"
    block = "\n".join(lines[1:end])
    if len(block) > _MAX_FM_BYTES:
        return None, {}, "frontmatter_too_large"
    if block.count("[") + block.count("{") > _MAX_FM_FLOW:
        return None, {}, "frontmatter_too_deep"    # flow-nesting bomb: refuse before parsing
    return _fm_load(block)


def _split_grants(val):
    """Split allowed-tools into specifiers (a list, or a comma string; commas in `(...)` stay)."""
    if isinstance(val, list):
        return [x.strip() for x in val if isinstance(x, str) and x.strip()]   # non-str: flag later
    if not isinstance(val, str):
        return []
    out, depth, cur = [], 0, ""
    for ch in val:
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        cur += ch
    out.append(cur)
    return [s.strip() for s in out if s.strip()]


def parse_grants(frontmatter):
    """allowed/disallowed-tools -> Grants; an unrecognized specifier is kept raw+broad."""
    grants = []
    for key, allowed in (("allowed-tools", True), ("disallowed-tools", False)):
        for spec in _split_grants((frontmatter or {}).get(key)):
            m = _GRANT_RE.match(spec)
            if m:
                grants.append(Grant(m.group(1), m.group(2), spec, allowed, m.group(2) is None))
            else:
                grants.append(Grant(spec, None, spec, allowed, True, False))
    return grants


# --- shell (tree-sitter-bash: error-recovering CST) ---

_BASH_PARSER = Parser(Language(tree_sitter_bash.language()))
_SHELL_PIPE_RE = re.compile(r"(?<!\|)\|(?!\|)")   # a single `|` (pipeline), never `||` (logical or)


def _error_spans(root):
    """(start,end) of each top-level ERROR/MISSING region; its span covers any nested one."""
    spans, stack = [], [root]
    while stack:
        node = stack.pop()
        if node.is_error or node.is_missing:
            spans.append((node.start_point[0] + 1, node.end_point[0] + 1))
        else:
            stack.extend(node.children)
    return spans


def parse_shell(text):
    """(tree, error_spans), or (None, None) when refused. The pipe/byte DoS bound lives here, at the
    public parser, so every caller is protected (tree-sitter-bash is superlinear on pipe chains)."""
    data = text.encode("utf-8", "surrogatepass")
    if len(data) > _MAX_SHELL_BYTES or len(_SHELL_PIPE_RE.findall(text)) > _MAX_SHELL_PIPES:
        return None, None
    tree = _BASH_PARSER.parse(data)
    spans = _error_spans(tree.root_node) if tree.root_node.has_error else []
    return tree, spans


# --- config manifests + dependency manifests ---

def _no_nan(c):
    raise ValueError(c)                        # strict JSON forbids NaN/Infinity


def _load_structured(text, rel):
    """Parse a config by extension (tomllib for .toml, else json) -> (obj, err)."""
    if rel.lower().endswith(".toml"):
        try:
            return tomllib.loads(text), None
        except (ValueError, RecursionError) as exc:      # TOMLDecodeError + huge-int ValueError
            return None, "toml_parse_error:%s" % str(exc)[:_DETAIL_CAP]
    try:
        return json.loads(text, parse_constant=_no_nan), None
    except (ValueError, RecursionError) as exc:
        return None, "json_parse_error:%s" % str(exc)[:_DETAIL_CAP]


def classify_manifest(config):
    """Classify a manifest by content, not filename (§5); most-specific first (lockfile>plugin)."""
    if not isinstance(config, dict):
        return None
    if "mcpServers" in config or "mcp_servers" in config:   # camelCase (Claude) or snake (Codex)
        return "mcp_servers"
    if isinstance(config.get("hooks"), (dict, list)):
        return "hooks"
    if "lockVersion" in config or "integrity" in config:
        return "lockfile"
    if "skills" in config or "interface" in config or ("name" in config and "version" in config):
        return "plugin"
    if any(isinstance(v, dict) and ("args" in v and "command" in v
                                    or v.get("type") in ("http", "sse") and "url" in v)
           for v in config.values()):   # a flat stdio or http/sse server map, no mcpServers wrapper
        return "mcp_servers"
    return "generic"


def _req_dep(raw):
    """A requirements/pyproject line -> dep dict or None; pinned = exact ==/=== (not `1.*`)."""
    try:
        req = Requirement(raw)
    except InvalidRequirement:
        return None
    pinned = any(s.operator in ("==", "===") and "*" not in s.version for s in req.specifier)
    return {"name": req.name, "specifier": str(req.specifier), "pinned": pinned, "raw": raw}


def _parse_requirements(text):
    deps, unhandled, buf = [], [], ""
    for raw in text.split("\n") + [""]:        # trailing "" flushes a dangling `\` continuation
        stripped = raw.rstrip()
        # A comment line is never a continuation, even ending in "\": pip's join_lines guards the
        # rule with COMMENT_RE, so "# note \" does not swallow the next dependency. Detecting the
        # comment BEFORE honoring "\" closes an evasion (hide a dep behind a backslash comment).
        if stripped.endswith("\\") and not stripped.lstrip().startswith("#"):
            buf += stripped[:-1]               # pip line continuation: accumulate, never rescan buf
            continue                            # (rescanning the whole buffer each line is O(n^2))
        s = re.split(r"\s(?:#|--)", buf + raw, maxsplit=1)[0].strip()   # drop trailing comment/opts
        buf = ""
        if not s or s.startswith("#"):
            continue
        dep = _req_dep(s)
        if dep is not None:
            deps.append(dep)
        else:
            unhandled.append(s[:80])           # -r/-e/VCS/local/option line, not a PEP 508 dep
    return deps, unhandled


def _pyproject_deps(config):
    raw = config.get("project")
    project = raw if isinstance(raw, dict) else {}
    bs = config.get("build-system")
    opt = project.get("optional-dependencies")
    dg = config.get("dependency-groups")          # PEP 735 dev/test groups (pip install --group)
    groups = [project.get("dependencies"), bs.get("requires") if isinstance(bs, dict) else None]
    deps, bad = [], []
    if raw is not None and not isinstance(raw, dict):
        bad.append("project not a table")         # malformed shape, never silent-clean
    dyn = project.get("dynamic")
    if isinstance(dyn, list):
        for f in ("dependencies", "optional-dependencies"):
            if f in dyn:
                bad.append("%s is dynamic" % f)   # resolved by the build backend, not visible here
        if not all(isinstance(x, str) for x in dyn):
            bad.append("dynamic has a non-string entry")
    elif dyn is not None:
        bad.append("dynamic not a list")          # malformed shape, never silent-clean
    tool = config.get("tool")
    if isinstance(tool, dict) and "poetry" in tool:
        bad.append("tool.poetry dependencies not modeled")   # non-PEP-621 layout, flagged
    for name, table in (("optional-dependencies", opt), ("dependency-groups", dg)):
        if isinstance(table, dict):
            groups += list(table.values())        # each named group is its own dependency list
        elif table is not None:
            bad.append("%s not a table" % name)   # malformed shape, never silent-clean
    for g in groups:
        if not isinstance(g, list):
            if g is not None:
                bad.append("non-list dependency group")
            continue
        for x in g:
            if not isinstance(x, str):              # PEP 621 entries are strings; do not coerce
                bad.append(str(x)[:80])
                continue
            d = _req_dep(x)
            (deps if d else bad).append(d or x[:80])   # never drop a declared dep silently
    return deps, bad


def _npm_deps(config):
    if not isinstance(config, dict):
        return [], ["package.json is not a JSON object"]   # malformed manifest, never silent-clean
    deps, bad = [], []
    pat = re.compile(r"[=v]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")  # npm pin

    def _pinned(spec):
        # an npm alias `npm:<pkg>@<version>` pins the resolved package to an exact version, so
        # judge the version part after the last '@', not the whole alias string.
        if spec.startswith("npm:"):
            at = spec.rfind("@")
            return at > 4 and bool(pat.fullmatch(spec[at + 1:]))
        return bool(pat.fullmatch(spec))

    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        block = config.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            bad.append("%s not an object" % section)
            continue
        for name, spec in block.items():
            if not isinstance(spec, str):           # npm versions are strings; coercing hides junk
                bad.append("%s non-string version" % name)
                continue
            deps.append({"name": name, "specifier": spec, "pinned": _pinned(spec),
                         "raw": "%s@%s" % (name, spec)})
    return deps, bad


class ParsedArtifact:
    """Parse results for one artifact: rel/kind/text (no fs path), fields + diagnostics."""

    def __init__(self, art):
        self.rel = art.rel
        self.kind = art.kind
        # Normalize newlines ONCE here so the text every check sees is in the same line space
        # as the markdown line numbers parse emits (parse_markdown/_fm_bounds normalize the same
        # way). Without this, a line-anchored check that splits .text on "\n" indexes against
        # CR-normalized fence line numbers, and a lone \r desyncs the two -- an attacker could
        # shift the fence window onto a live directive and have it skipped as "inside a fence".
        self.text = _norm_newlines(art.text)
        # Raw bytes ingest captured (bounded), carried into the IR so the byte-level
        # checks read the package's bytes here and never re-open a file. None when
        # ingest read nothing (a size/budget/read skip).
        self.raw = getattr(art, "raw", None)
        self.frontmatter = None
        self.frontmatter_key_lines = {}
        self.frontmatter_end_line = None
        self.grants = None
        self.markdown = None
        self.fallback_links = []
        self.preprocessing = []
        self.preprocessing_counts = {"inline": 0, "fenced": 0}
        self.py_tree = None
        self.shell_tree = None
        self.config = None
        self.manifest_kind = None
        self.deps = None
        self.diagnostics = []


class ParsedPackage:
    """All artifacts by package-relative path in by_rel, plus refs and the ingest ledger."""

    def __init__(self, pkg):
        self.identity = pkg.identity
        self.name = pkg.name
        self.artifacts = []
        self.by_rel = {}
        self.refs = []
        self.ledger_exceptions = list(pkg.ledger_exceptions)

    def add(self, parsed):
        self.artifacts.append(parsed)
        self.by_rel[parsed.rel] = parsed


def _resolve_refs(pkg):
    """Resolve in-package markdown links to target artifacts (§1); ext/`../` drop, targets NFC."""
    refs = []
    for p in pkg.artifacts:
        links = p.markdown.links if p.markdown is not None else p.fallback_links
        if not links:
            continue
        base = p.rel.rsplit("/", 1)[0] if "/" in p.rel else ""
        for href, _text, line in links:
            target = href.split("#", 1)[0].split("?", 1)[0].strip()
            if not target or re.match(r"[a-z][a-z0-9+.-]*:", target, re.I):
                continue                                   # empty/pure-fragment, or any URI scheme
            target = unicodedata.normalize("NFC", unquote(target))
            resolved = posixpath.normpath(posixpath.join(base, target))
            if resolved == ".." or resolved.startswith("../") or resolved == ".":
                continue
            if resolved in pkg.by_rel:
                refs.append({"from": p.rel, "to": resolved, "line": line})
    return refs


# --- entry point ---

def _parse_python(p, text):
    """ast.parse -> p.py_tree, failing closed (ingest routes every .py, setup.py included, here)."""
    if len(text) > MAX_PY_CHARS:                 # a huge source builds a huge retained AST (memory)
        p.diagnostics.append(("python_oversize", str(len(text))))
        return
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text)
        stack = [(tree, 0)]
        while stack:
            node, depth = stack.pop()
            if depth > _MAX_PY_AST_DEPTH:
                p.diagnostics.append(("python_too_complex", None))
                return
            stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
        p.py_tree = tree
    except (SyntaxError, ValueError) as exc:
        p.diagnostics.append(("python_syntax_error", "line %s" % getattr(exc, "lineno", "?")))
    except RecursionError:
        p.diagnostics.append(("python_too_complex", None))
    except MemoryError:
        p.diagnostics.append(("memoryerror", None))


def _parse_md(p, text, strip_fm=True):
    """Markdown into the IR; raw HTML flagged. strip_fm=False for a doc (no frontmatter)."""
    if p.rel.lower().endswith(".rst"):
        p.diagnostics.append(("unsupported_markup", "rst"))    # reStructuredText is not CommonMark
    body, off = _body_and_offset(text) if strip_fm else (text, 0)
    p.markdown, mderr = parse_markdown(body, off)
    if p.markdown is None:
        p.fallback_links = _fallback_links(body, off)
        if strip_fm and off:
            frontmatter = "\n".join(_norm_newlines(text).split("\n")[:off])
            fm_inline, fm_total = _scan_inline_preproc(
                frontmatter, excluded_lines=set(), markdown_exclusions=False,
            )
            body_inline, body_total = _scan_inline_preproc(body, off)
            inline = fm_inline + body_inline
            inline_total = fm_total + body_total
        else:
            inline, inline_total = _scan_inline_preproc(body, off)
        fenced, fenced_total = _scan_fenced_preproc(body, off)
    else:
        inline = [token for token in p.markdown.preproc if token.kind == "inline"]
        inline_total = p.markdown.preproc_counts["inline"]
        if strip_fm and off:
            frontmatter = "\n".join(_norm_newlines(text).split("\n")[:off])
            fm_inline, fm_total = _scan_inline_preproc(
                frontmatter, excluded_lines=set(), markdown_exclusions=False,
            )
            inline = fm_inline + inline
            inline_total += fm_total
        fenced = [token for token in p.markdown.preproc if token.kind == "fenced"]
        fenced_total = p.markdown.preproc_counts["fenced"]
    retained = {True: 0, False: 0}
    capped_inline = []
    for token in inline:
        retained[token.runs] += 1
        if retained[token.runs] <= MAX_PREPROC_TOKENS:
            capped_inline.append(token)
    inline = capped_inline
    p.preprocessing = inline + fenced
    p.preprocessing_counts = {
        "inline": inline_total,
        "fenced": fenced_total,
    }
    if p.markdown is not None:
        p.markdown.preproc = list(p.preprocessing)
        p.markdown.preproc_counts = dict(p.preprocessing_counts)
    if mderr:
        p.diagnostics.append(("markdown_parse_error", mderr))
    elif p.markdown is not None and p.markdown.has_html:
        p.diagnostics.append(("raw_html", None))


def _structured_deps(text, rel, extractor, p):
    """Load a JSON/TOML dep manifest, set p.config, run extractor; None on parse failure."""
    cfg, cerr = _load_structured(text, rel)
    p.config = cfg
    if cerr:
        p.diagnostics.append(("config_parse_error", cerr))
        return None
    deps, unhandled = extractor(cfg)
    if unhandled:
        p.diagnostics.append(("requirement_unparsed", ";".join(unhandled[:8])))
    return deps


def _parse_one(art, p):
    """Parse a single already-read artifact into `p`, recording diagnostics."""
    text = p.text              # the newline-normalized text, so shell/config parse in the same
    kind = art.kind            # line space as p.text (tree-sitter-bash treats a lone \r as no
    # newline, which otherwise desyncs shell node line numbers from the text a check indexes).
    if kind in _MARKDOWN_KINDS:
        if kind != "doc":          # doc = README/LICENSE class (§5): body only, grants inert
            _lines, has_open, fm_end = _fm_bounds(text)
            if has_open and fm_end is not None:
                p.frontmatter_end_line = fm_end + 1
            fm, key_lines, err = parse_frontmatter(text)
            p.frontmatter, p.frontmatter_key_lines = fm, key_lines
            if err:
                p.diagnostics.append(("frontmatter_parse_error", err))
            if fm:
                p.grants = parse_grants(fm)
                for gkey in ("allowed-tools", "disallowed-tools"):
                    v = fm.get(gkey)
                    # a non-string grant form or element has no real specifier; flag, never silent
                    bad_shape = v is not None and not isinstance(v, (list, str))
                    bad_elem = isinstance(v, list) and not all(isinstance(x, str) for x in v)
                    if bad_shape or bad_elem:
                        p.diagnostics.append(("grants_unparsed_shape", gkey))
        _parse_md(p, text, kind != "doc")      # a doc has no frontmatter to strip
    elif kind == "script_python":
        _parse_python(p, text)
    elif kind == "script_shell":
        p.shell_tree, spans = parse_shell(text)
        if spans is None:                          # parse_shell refused it (pipe/byte DoS bound)
            p.diagnostics.append(("shell_too_complex", str(len(text))))
        elif spans:
            # a localized ERROR region (with total count) is a coverage gap, not clean
            shown = ",".join("%d-%d" % s for s in spans[:_MAX_ERROR_SPANS])
            p.diagnostics.append(("shell_error_region", "%d:%s" % (len(spans), shown)))
    elif kind.startswith("script_"):
        # a script language with no parser (ps1/js/ts/bat/rb/pl) must not read clean (§7)
        p.diagnostics.append(("unsupported_language", kind.split("_", 1)[1]))
    elif kind == "agent_config" or kind in _JSON_CONFIG_KINDS:
        p.config, cerr = _load_structured(text, p.rel)
        if cerr:
            p.diagnostics.append(("config_parse_error", cerr))
        else:
            p.manifest_kind = classify_manifest(p.config)
    elif kind == "dep_manifest":
        base = p.rel.rsplit("/", 1)[-1].lower()
        if base.endswith(".txt") and "requirements" in base:
            p.deps, unhandled = _parse_requirements(text)
            if unhandled:            # -r/-e/VCS/local lines surfaced, not silently dropped
                p.diagnostics.append(("requirement_unparsed", ";".join(unhandled[:8])))
        elif base == "package.json":
            p.deps = _structured_deps(text, p.rel, _npm_deps, p)
        elif base == "pyproject.toml":
            p.deps = _structured_deps(text, p.rel, _pyproject_deps, p)
        else:
            p.diagnostics.append(("dep_manifest_unparsed", base))   # a manifest kind not modeled
    elif kind == "secret_material":
        pass                       # carried verbatim in .text for a secret check; nothing to parse
    else:
        p.diagnostics.append(("unmodeled_content", kind))   # decoded text, no parser: never clean


def parse_package(pkg):
    """Parse each read artifact once; per-artifact isolated so one bad file cannot abort. The whole
    package shares a wall-clock budget, so thousands of bomb files cannot sum the per-file timeout
    into an unbounded scan; artifacts past the budget are flagged, never silently skipped."""
    out = ParsedPackage(pkg)
    deadline = time.monotonic() + _PKG_BUDGET
    for art in pkg.artifacts:
        p = ParsedArtifact(art)
        if art.text is not None:
            if time.monotonic() > deadline:
                p.diagnostics.append(("parse_budget_exceeded", None))
            else:
                try:
                    _parse_one(art, p)
                except Exception as exc:           # last-resort per-artifact isolation
                    p.diagnostics.append(("parse_crash", type(exc).__name__))
        out.add(p)

    out.refs = _resolve_refs(out)
    for p in out.artifacts:
        for code, detail in p.diagnostics:
            out.ledger_exceptions.append(
                {"outcome": "unresolved", "phase": "parse",
                 "reasonCode": code, "detail": detail, "path": p.rel})
    return out
