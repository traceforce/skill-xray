#!/usr/bin/env python3
"""Fail if a top-level function, class or UPPER_CASE constant under the source
root is used nowhere in that source. Names listed in __all__ are exempt, since
they are the public API. Standard library only.

    python dev/deadcode.py [src_dir]     # exit 1 if anything is unused
"""

from __future__ import annotations

import ast
import os
import sys


def _py_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


def main(argv=None) -> int:
    root = (argv if argv is not None else sys.argv[1:] or ["src"])[0]
    defs, used, exported = {}, set(), set()

    for path in _py_files(root):
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), path)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defs[node.name] = "%s:%d" % (path, node.lineno)
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id.isupper():
                        defs[tgt.id] = "%s:%d" % (path, node.lineno)
                    if (isinstance(tgt, ast.Name) and tgt.id == "__all__"
                            and isinstance(node.value, (ast.List, ast.Tuple))):
                        exported |= {e.value for e in node.value.elts
                                     if isinstance(e, ast.Constant)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                used.add(node.attr)

    dead = sorted(n for n in defs
                  if n not in used and n not in exported and not n.startswith("__"))
    for n in dead:
        print("DEAD  %-24s %s" % (n, defs[n]))
    if dead:
        print("\n%d dead symbol(s): delete them or wire them up." % len(dead))
        return 1
    print("no dead symbols under %s" % root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
