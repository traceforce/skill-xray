"""Best-effort credential removal before constructing an opt-in LLM request."""

import re

from ..checks.supply_chain import _SECRET_RULES, _sanitize_source

_PEM = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)", re.DOTALL)
_AUTH = re.compile(r"\b(?:Bearer|Basic)[ \t]+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_VALUE_GAP = r"[ \t]*(?:\n(?:[ \t]*\n)*[ \t]+)?"
_NAMED = re.compile(
    r'''(?ims)((?<![\w-])(?=[\w-]*(?:token|password|passwd|secret|api[_-]?key|authorization))'''
    r'''[\w-]+'''
    r"""["']?[ \t]*[:=]""" + _VALUE_GAP + r")(?:[!&][^\s]*" + _VALUE_GAP + r"){0,2}(?:"
    r'[>|][1-9+-]*[^\n]*\n(?:[ \t]+[^\n]*(?:\n|\Z)|\n)*|'
    r'"""(?:\\.|(?!""").)*(?:"""|\Z)|'
    r"'''(?:\\.|(?!''').)*(?:'''|\Z)|"
    r'''"(?:\\.|[^"\\])*(?:"|\Z)|'''
    r"""'(?:''|\\.|[^'\\])*(?:'|\Z)|"""
    r"[^\n]+(?:\n[ \t][^\n]*|\n(?=\n))*)")
_URL = re.compile(r'''(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://[^\s<>"']+''', re.IGNORECASE)


def redact(text):
    """Keep source lines stable; arbitrary or encoded secrets are not reliably recognizable."""
    text = _PEM.sub(lambda m: "[REDACTED]" + "\n" * m[0].count("\n"), text)
    for _, pattern, _ in _SECRET_RULES:
        text = pattern.sub("[REDACTED]", text)
    text = _AUTH.sub(lambda m: "[REDACTED]" + "\n" * m[0].count("\n"), text)
    text = _NAMED.sub(
        lambda m: m[1] + "[REDACTED]" + "\n" * (m[0].count("\n") - m[1].count("\n")), text)
    return _URL.sub(lambda m: _sanitize_source(m[0]), text)
