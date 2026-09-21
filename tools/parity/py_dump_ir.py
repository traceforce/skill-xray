"""Dump the parsed IR of one package as JSON Lines: one sorted-key document per artifact.

    PYTHONPATH=<oracle>/src python tools/parity/py_dump_ir.py <package dir>

Field list and shapes are 00-overview.md section 6. Spans are [start, end]; links, fences and
HTML records are dicts; config carries a per-value type tag ([type name, value] at every level);
diagnostics are [code, detail] with the detail of config_parse_error, shell_error_region and
parse_crash reduced to true (presence-only, parse.md R6). Values JSON cannot carry (dates, bytes)
become [type name, str(value)].
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import sys

from skill_xray import ingest, parse

PRESENCE_ONLY = {"config_parse_error", "shell_error_region", "parse_crash"}


def _sha256(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def _typed(value):
    if isinstance(value, dict):
        return ["dict", {str(k): _typed(v) for k, v in value.items()}]
    if isinstance(value, list):
        return ["list", [_typed(v) for v in value]]
    return [type(value).__name__, value if isinstance(value, (str, int, float, bool, type(None)))
            else str(value)]


def _records(items, *fields):
    return None if items is None else [dict(zip(fields, item, strict=False)) for item in items]


def _spans(spans):
    return None if spans is None else [list(span) for span in spans]


def _dicts(items):
    return None if items is None else [dataclasses.asdict(item) for item in items]


def artifact_doc(p, refs):
    md = p.markdown
    return {
        "rel": p.rel, "kind": p.kind,
        "text_sha256": _sha256(p.text.encode("utf-8", "surrogatepass")
                               if p.text is not None else None),
        "raw_sha256": _sha256(p.raw),
        "frontmatter": p.frontmatter,
        "frontmatter_keys": None if p.frontmatter is None else list(p.frontmatter),
        "frontmatter_key_lines": p.frontmatter_key_lines,
        "frontmatter_end_line": p.frontmatter_end_line,
        "unsafe_yaml_tags": _dicts(p.unsafe_yaml_tags),
        "grants": _dicts(p.grants),
        "fences": _records(md and md.fences, "info", "content", "line"),
        "fence_spans": _spans(md and md.fence_spans),
        "code_spans": _spans(md and md.code_spans),
        "prose_spans": _spans(md and md.prose_spans),
        "reference_spans": _spans(md and md.reference_spans),
        "paragraph_spans": _spans(md and md.paragraph_spans),
        "links": _records(md and md.links, "href", "label", "line"),
        "fallback_links": _records(p.fallback_links, "href", "label", "line"),
        "html_comments": _records(md and md.html_comments, "body", "line", "column"),
        "html_prose": _records(md and md.html_prose, "text", "line"),
        "html_uninspectable": _records(md and md.html_uninspectable, "text", "line", "column"),
        "has_html": md and md.has_html,
        "has_uninspectable_html": md and md.has_uninspectable_html,
        "preprocessing": _dicts(p.preprocessing),
        "preprocessing_counts": p.preprocessing_counts,
        "config": None if p.config is None else _typed(p.config),
        "manifest_kind": p.manifest_kind,
        "deps": p.deps,
        "diagnostics": [[code, True if code in PRESENCE_ONLY and detail is not None else detail]
                        for code, detail in p.diagnostics],
        "refs": [ref for ref in refs if ref["from"] == p.rel],
    }


def dump(root):
    parsed = parse.parse_package(ingest.build_package(root))
    return [artifact_doc(p, parsed.refs) for p in parsed.artifacts]


def _default(value):
    return [type(value).__name__, str(value)]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("package")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.package):
        sys.stderr.write("not a directory: %s\n" % args.package)
        return 2
    for doc in dump(args.package):
        sys.stdout.write(
            json.dumps(doc, sort_keys=True, ensure_ascii=True, default=_default) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
