"""Shared Python AST helpers for the check engines."""

from __future__ import annotations

import ast
import warnings

__all__ = ["dotted", "parse"]


def parse(source):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(source)


def dotted(node):
    """Dotted name for a Name/Attribute chain (os.path.join -> 'os.path.join'), else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None
