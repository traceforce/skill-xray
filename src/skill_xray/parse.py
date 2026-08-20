"""Parse an ingested skill package into one shared representation (the IR).

Each file is parsed once with a real parser per format. Fail closed and per-artifact
isolated: any error is a typed diagnostic, never a crash or a silent-clean file; a
missing diagnostic means "parsed", not "safe" (prose lives only in the raw `.text`)."""

from __future__ import annotations

import ast
import io
import json
import multiprocessing
import posixpath
import queue
import re
import time
import tomllib
import unicodedata
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
_MAX_PY_CHARS = 524288     # ast.parse retains a node graph that amplifies source size in memory
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


@dataclass
class Markdown:
    """Line-anchored markdown structure: links, fenced/indented code, preproc, has_html."""

    links: list = field(default_factory=list)
    fences: list = field(default_factory=list)
    preproc: list = field(default_factory=list)
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


def _fm_bounds(text):
    """(lines, has_open, end): normalized lines and the column-0 open/close of a `---` block."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
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
    text = text.replace("\r\n", "\n").replace("\r", "\n")  # normalize breaks so line counts match
    try:
        tokens = _MD.parse(text)
    except (RecursionError, MemoryError) as exc:
        return None, type(exc).__name__.lower()
    md = Markdown()
    for tok in tokens:
        line = (tok.map[0] + 1 + line_offset) if tok.map else 0
        if tok.type in ("fence", "code_block"):
            info = tok.info.strip() if tok.type == "fence" else ""
            md.fences.append((info, tok.content, line))
            if info.startswith("!"):
                md.preproc.append(Preproc("fenced", tok.content, line, runs=True))
        elif tok.type == "html_block":
            md.has_html = True
        elif tok.type == "inline":
            _scan_inline(tok, line, md)
    # inline !`cmd` is substituted by the harness on RAW text (before markdown, even inside a
    # fence, ignoring backslash escapes), so scan the source, not markdown-it's normalized tokens.
    pos, ln = 0, 1 + line_offset
    for m in re.finditer(r"!`([^`\n]+)`", text):
        ln += text.count("\n", pos, m.start())             # count only the gap, not from 0
        pos = m.start()
        b = text[pos - 1] if pos else ""                   # the true char before `!`
        runs = (not b) or b.isspace()                      # live at SOL/whitespace only (SXE-01)
        md.preproc.append(Preproc("inline", m.group(1), ln, runs))
    return md, None


# --- frontmatter (ruamel.yaml round-trip: gives per-key line/col) + allowed-tools grants ---

# tool + optional `(...)`. Possessive `\s*+` blocks O(n^2) backtracking (padded-spec DoS).
_GRANT_RE = re.compile(r"^([A-Za-z_][\w.-]*)\s*+(?:\((.*)\))?\s*+$", re.DOTALL)
# DoS bound on the YAML parser: metadata is tiny, but ruamel's scanner is superlinear in flow
# nesting, so a block with many flow openers is parsed in a killable child, never inline.
_MAX_FM_BYTES = 16384
_MAX_FM_FLOW = 256         # `[`/`{` count above which the parse runs under the kill-timeout
_FM_TIMEOUT = 1.0
_MP = multiprocessing.get_context("spawn")   # spawn, not fork: safe to call from a threaded host


def _plain(obj):
    """ruamel round-trip types -> plain dict/list/scalars, so a result can cross a process line."""
    if isinstance(obj, dict):
        return {str(k): _plain(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_plain(v) for v in obj]
    return obj


def _fm_load(block):
    """Refuse anchors/aliases/`!!python` tags via the event stream, then load -> a picklable
    (values, key_lines, error). Slow only on deep flow nesting, which the caller bounds by time."""
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


def _fm_worker(block, q):
    try:
        q.put(_fm_load(block))
    except Exception as exc:                     # never let a worker exit without a result
        q.put((None, {}, "yaml_error:%s" % type(exc).__name__))


@dataclass
class Grant:
    """One allowed/disallowed-tools entry; broad=True for a bare tool (`Bash`), row-3 pre-grant."""

    tool: str
    pattern: str | None
    raw: str
    allowed: bool
    broad: bool


def parse_frontmatter(text):
    """Leading `--- ... ---` YAML block -> (values, key_lines, error). Anchors/aliases and unsafe
    tags are refused; a flow-heavy block parses in a killable child, so a deep-nest bomb bounds
    wall-clock and memory instead of hanging. Values are plain (no ruamel types)."""
    lines, has_open, end = _fm_bounds(text)
    if not has_open:
        return None, {}, None
    if end is None:
        return None, {}, "frontmatter_unterminated"
    block = "\n".join(lines[1:end])
    if len(block) > _MAX_FM_BYTES:
        return None, {}, "frontmatter_too_large"
    if block.count("[") + block.count("{") <= _MAX_FM_FLOW:
        return _fm_load(block)                     # too few flow openers to bomb: parse inline
    q = _MP.Queue()                                # flow-heavy: bound time/memory, kill a hang
    proc = _MP.Process(target=_fm_worker, args=(block, q))
    proc.start()
    try:
        result = q.get(timeout=_FM_TIMEOUT)
    except queue.Empty:
        result = (None, {}, "frontmatter_too_deep")
    if proc.is_alive():
        proc.terminate()
    proc.join()
    return result


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
                grants.append(Grant(spec, None, spec, allowed, True))
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
        if stripped.endswith("\\"):            # pip line continuation: accumulate, never rescan buf
            buf += stripped[:-1]               # (rescanning the whole buffer each line is O(n^2))
            continue
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
            deps.append({"name": name, "specifier": spec, "pinned": bool(pat.fullmatch(spec)),
                         "raw": "%s@%s" % (name, spec)})
    return deps, bad


class ParsedArtifact:
    """Parse results for one artifact: rel/kind/text (no fs path), fields + diagnostics."""

    def __init__(self, art):
        self.rel = art.rel
        self.kind = art.kind
        self.text = art.text
        self.frontmatter = None
        self.frontmatter_key_lines = {}
        self.grants = None
        self.markdown = None
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
        if p.markdown is None:
            continue
        base = p.rel.rsplit("/", 1)[0] if "/" in p.rel else ""
        for href, _text, line in p.markdown.links:
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
    if len(text) > _MAX_PY_CHARS:                # a huge source builds a huge retained AST (memory)
        p.diagnostics.append(("python_oversize", str(len(text))))
        return
    try:
        p.py_tree = ast.parse(text)
    except (SyntaxError, ValueError) as exc:
        p.diagnostics.append(("python_syntax_error", "line %s" % getattr(exc, "lineno", "?")))
    except (RecursionError, MemoryError) as exc:
        p.diagnostics.append((type(exc).__name__.lower(), None))


def _parse_md(p, text, strip_fm=True):
    """Markdown into the IR; raw HTML flagged. strip_fm=False for a doc (no frontmatter)."""
    if p.rel.lower().endswith(".rst"):
        p.diagnostics.append(("unsupported_markup", "rst"))    # reStructuredText is not CommonMark
    body, off = _body_and_offset(text) if strip_fm else (text, 0)
    p.markdown, mderr = parse_markdown(body, off)
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
    text = art.text
    kind = art.kind
    if kind in _MARKDOWN_KINDS:
        if kind != "doc":          # doc = README/LICENSE class (§5): body only, grants inert
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
        if base == "requirements.txt":
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
