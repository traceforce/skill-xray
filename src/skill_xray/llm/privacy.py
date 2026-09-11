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
    r"""["']?[ \t]*[:=]""" + _VALUE_GAP + r")(?:[!&][^\s]*" + _VALUE_GAP + r"){0,2}("
    r'"""(?:\\.|(?!""").)*(?:"""|\Z)|'
    r"'''(?:\\.|(?!''').)*(?:'''|\Z)|"
    r'''"(?:\\.|[^"\\])*(?:"|\Z)|'''
    r"""'(?:''|\\.|[^'\\])*(?:'|\Z)|"""
    r"[^\n]+)")
_CONTINUATION = re.compile(r"\n([ \t]*)([^\n]*)")
_URL = re.compile(r'''(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://[^\s<>"']+''', re.IGNORECASE)


def redact(text):
    """Keep source lines stable; arbitrary or encoded secrets are not reliably recognizable."""
    text = _PEM.sub(lambda m: "[REDACTED]" + "\n" * m[0].count("\n"), text)
    for _, pattern, _ in _SECRET_RULES:
        text = pattern.sub("[REDACTED]", text)
    text = _AUTH.sub(lambda m: "[REDACTED]" + "\n" * m[0].count("\n"), text)
    parts, pos = [], 0
    while m := _NAMED.search(text, pos):
        prefix = text[text.rfind("\n", 0, m.start()) + 1:m.start()].rstrip("\"'")
        indent = len(prefix) if not prefix.strip(" \t-") else len(prefix) - len(prefix.lstrip())
        value_prefix = text[text.rfind("\n", 0, m.start(2)) + 1:m.start(2)]
        if "\n" in text[m.start():m.start(2)] and len(value_prefix) <= indent:
            parts.append(text[pos:m.start(2)])
            pos = m.start(2)
            continue
        end = m.end()
        if not m[2].startswith(('"', "'")):
            # A sibling YAML key is not a continuation of the credential value.
            while following := _CONTINUATION.match(text, end):
                if following[2] and len(following[1]) <= indent:
                    break
                end = following.end()
        parts.extend((text[pos:m.start()], m[1], "[REDACTED]",
                      "\n" * text[m.end(1):end].count("\n")))
        pos = end
    text = "".join(parts) + text[pos:]
    return _URL.sub(lambda m: _sanitize_source(m[0]), text)
