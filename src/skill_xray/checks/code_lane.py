"""Select executable files and instruction fences once for all code engines."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..findings import Finding
from ..parse import MAX_PY_CHARS
from ._pyast import parse as parse_python

_FENCE_LANG = {
    "bash": ("shell", "bash"), "sh": ("shell", "sh"),
    "shell": ("shell", "sh"), "zsh": ("shell", "zsh"),
    "console": ("shell", "sh"), "shell-session": ("shell", "sh"),
    "shellsession": ("shell", "sh"), "shell-script": ("shell", "sh"),
    "sh-session": ("shell", "sh"), "bash-session": ("shell", "bash"),
    "ksh": ("shell", "ksh"), "dash": ("shell", "dash"),
    "fish": ("shell", "fish"), "powershell": ("shell", "powershell"),
    "pwsh": ("shell", "powershell"), "ps1": ("shell", "powershell"),
    "bat": ("shell", "cmd"), "cmd": ("shell", "cmd"),
    "batch": ("shell", "cmd"), "python": ("python", "python"),
    "py": ("python", "python"), "python3": ("python", "python"),
    "python2": ("python", "python"), "ipython": ("python", "python"),
}
_CONSOLE_PROMPT_RE = re.compile(r"^\s{0,3}\$\s+")
_SCRIPT_KINDS = {"script_shell", "script_python"}
_SUPPORTED_SHELL_DIALECTS = {"bash", "sh", "dash"}


@dataclass(frozen=True)
class CodeUnit:
    rel: str
    kind: str
    text: str
    origin: str = "file"
    dialect: str | None = None


def _fence_lang(info: str):
    parts = info.split()
    if not parts:
        return None
    match = re.search(r"[A-Za-z0-9_+-]+", parts[0])
    return _FENCE_LANG.get(match.group(0).lower()) if match else None


def _shell_dialect(rel: str, text: str) -> str:
    first = text.split("\n", 1)[0].lower()
    match = re.match(r"^#!.*\b(bash|sh|dash|ksh|zsh|fish)\b", first)
    if match:
        return match.group(1)
    suffix = rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
    return {"bash": "bash", "zsh": "zsh", "sh": "sh"}.get(suffix, "sh")


def _python_is_module(source: str) -> bool:
    if len(source) > MAX_PY_CHARS:
        return True
    try:
        parse_python(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    return True


def _pad_blocks(blocks) -> str:
    lines = []
    for marker_line, body_lines in blocks:
        while len(lines) < marker_line:
            lines.append("")
        lines.extend(body_lines)
    return "\n".join(lines)


def _lift_fences(fences):
    """Combine supported executable fences without changing their line numbers."""
    kept = {}
    for info, content, marker_line in fences:
        classified = _fence_lang(info)
        if classified is None:
            continue
        language, dialect = classified
        if language == "shell" and dialect not in _SUPPORTED_SHELL_DIALECTS:
            continue
        lines = content.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        if language == "shell":
            lines = [
                _CONSOLE_PROMPT_RE.sub(lambda match: " " * len(match.group(0)), line)
                for line in lines
            ]
        elif not _python_is_module("\n".join(lines)):
            continue
        block = marker_line, lines
        kept.setdefault(language, []).append(block)
    output = []
    for language, blocks in kept.items():
        combined = _pad_blocks(blocks)
        if language == "shell" or _python_is_module(combined):
            output.append((language, "bash" if language == "shell" else language, combined))
        else:
            output.extend((language, language, _pad_blocks([block])) for block in blocks)
    return output


def _unsupported_shell(
    rel: str, dialect: str, origin: str, line: int | None = None,
) -> Finding:
    return Finding(
        vector="",
        rule="analysis-incomplete",
        severity="high",
        path=rel,
        line=line,
        message="OpenGrep does not support executable %s code." % dialect,
        evidence={"reason": "unsupported_language", "language": dialect, "origin": origin},
    )


def build_code_lane(parsed) -> tuple[list[CodeUnit], list[Finding]]:
    """Return real scripts, executable fences, and fail-visible coverage notes."""
    units = []
    notes = []
    for artifact in parsed.artifacts:
        if artifact.kind not in _SCRIPT_KINDS or artifact.text is None:
            continue
        dialect = _shell_dialect(artifact.rel, artifact.text) \
            if artifact.kind == "script_shell" else None
        if dialect and dialect not in _SUPPORTED_SHELL_DIALECTS:
            notes.append(_unsupported_shell(artifact.rel, dialect, "file"))
            continue
        units.append(CodeUnit(
            artifact.rel,
            artifact.kind,
            artifact.text,
            dialect=dialect,
        ))
    for artifact in parsed.artifacts:
        if artifact.kind not in ("skill_manifest", "instruction", "agent_identity"):
            continue
        if not artifact.markdown or not artifact.markdown.fences:
            continue
        for info, content, marker_line in artifact.markdown.fences:
            classified = _fence_lang(info)
            if (classified and classified[0] == "shell"
                    and classified[1] not in _SUPPORTED_SHELL_DIALECTS):
                notes.append(_unsupported_shell(
                    artifact.rel, classified[1], "fence", marker_line + 1,
                ))
            if classified and classified[0] == "python" and not _python_is_module(content):
                notes.append(Finding(
                    vector="",
                    rule="analysis-incomplete",
                    severity="high",
                    path=artifact.rel,
                    line=marker_line + 1,
                    message="Python fence could not be parsed, so it was not analysed.",
                    evidence={"language": info.split()[0], "origin": "fence"},
                ))
        for language, dialect, source in _lift_fences(artifact.markdown.fences):
            units.append(CodeUnit(
                artifact.rel,
                "script_" + language,
                source,
                origin="fence",
                dialect=dialect,
            ))
    return units, notes
