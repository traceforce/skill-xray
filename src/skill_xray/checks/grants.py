"""Classify dynamic and over-broad execution/network pre-grants from the shared IR."""

from __future__ import annotations

import re
import shlex

from ..findings import Finding, cap_findings

_EXECUTION_TOOLS = {"Bash", "Shell", "Terminal", "Execute"}
_NETWORK_TOOLS = {"WebFetch", "WebSearch"}
_VARIABLE = re.compile(
    r"\$(?i:env):[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|"
    r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::[-+?=][^}\n]*)?\}|"
    r"\$[A-Za-z_][A-Za-z0-9_]*|\$\d+"
)
_COMMAND_SUBSTITUTION = re.compile(
    r"(?:^|&&|\|\||[;|])\s*(?:sudo\s+|env\s+)?"
    r"(\$\([^\n)]{1,200}\)|`[^\n`]{1,200}`)"
)
_VERSION_SUFFIX = re.compile(r"\d+(?:\.\d+)*$")
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*=")
_WRAPPER_ARGUMENT = re.compile(r"^-|=|^\d+(?:\.\d+)?[smhd]?$")

_BROAD_COMMANDS = {
    "bash", "bun", "chmod", "chown", "curl", "dash", "deno", "env", "eval",
    "fish", "ksh", "nc", "ncat", "node", "npx", "osascript", "perl", "php",
    "pip", "pip3", "powershell", "pwsh", "py", "python", "python3", "ruby",
    "scp", "sftp", "sh", "socat", "ssh", "su", "sudo", "wget", "xargs", "zsh",
}
_INSTALLERS = {
    ("apt", "install"), ("apt-get", "install"), ("brew", "install"),
    ("cargo", "install"), ("dotnet", "tool"), ("gem", "install"),
    ("go", "install"), ("npm", "i"), ("npm", "install"), ("pip", "install"),
    ("pip3", "install"), ("pnpm", "add"), ("uv", "add"), ("uv", "pip"),
    ("yarn", "add"),
}
_INTERPRETERS = {
    "bash", "bun", "dash", "deno", "ksh", "node", "osascript", "perl", "php",
    "cmd", "powershell", "pwsh", "py", "python", "python3", "ruby", "sh", "zsh",
}
_EVAL_FLAGS = {
    "--eval", "--print", "-c", "-command", "-e", "-enc", "-encodedcommand", "-p",
    "-r", "/c", "/k", "eval", "run",
}
_WRAPPERS = {
    "command", "doas", "env", "ionice", "nice", "nohup", "setsid", "stdbuf",
    "sudo", "time", "timeout", "xargs",
}
_WRAPPER_VALUE_OPTIONS = {
    "env": {"-u", "--unset"},
    "sudo": {"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
}
_PRIVILEGE_COMMANDS = {"su", "sudo"}
_NETWORK_COMMANDS = {
    "aria2c", "curl", "http", "httpie", "nc", "ncat", "node", "npx", "perl", "python",
    "python3", "ruby", "scp", "sftp", "socat", "ssh", "wget",
}
_NETWORK_ONLY_COMMANDS = {"aria2c", "curl", "http", "httpie", "scp", "sftp", "wget"}
_REMOTE_COMMANDS = _NETWORK_ONLY_COMMANDS | {"nc", "ncat", "socat", "ssh"}


def _basename(token):
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "'\"":
        token = token[1:-1]
    name = token.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".com", ".ps1"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def _command_tokens(pattern):
    if pattern is None:
        return None, []
    command = pattern.strip()
    if command.endswith(":*"):
        command = command[:-2]
    command = command.strip()
    try:
        lexer = shlex.shlex(command, posix=False, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return command, list(lexer)
    except ValueError:
        return command, command.split()


def _effective_tokens(tokens):
    remaining = list(tokens)
    privileged = False
    while remaining:
        if _ENV_ASSIGNMENT.search(remaining[0]):
            remaining.pop(0)
            continue
        head = _basename(remaining[0])
        if head not in _WRAPPERS:
            break
        privileged |= head in {"sudo", "doas"}
        remaining.pop(0)
        while remaining:
            option = remaining[0]
            if option in _WRAPPER_VALUE_OPTIONS.get(head, set()):
                remaining.pop(0)
                if remaining:
                    remaining.pop(0)
            elif _WRAPPER_ARGUMENT.search(option):
                remaining.pop(0)
            else:
                break
    return remaining, privileged


def _segments(tokens):
    segments = []
    current = []
    for token in tokens:
        if token and set(token) <= set(";&|"):
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def _segment_breadth(tokens):
    effective, privileged = _effective_tokens(tokens)
    if privileged:
        return "privilege_escalation"
    if not effective:
        effective = tokens
    head = _basename(effective[0])
    normalized = _VERSION_SUFFIX.sub("", head) or head
    if normalized in _PRIVILEGE_COMMANDS:
        return "privilege_escalation"
    if (
        normalized in {"py", "python", "python3"}
        and len(effective) >= 3
        and effective[1].lower() == "-m"
        and effective[2].lower() in {"pip", "ensurepip"}
    ):
        return "package_installer"
    if len(effective) >= 2 and (normalized, effective[1].lower()) in _INSTALLERS:
        return "package_installer"
    if normalized in _INTERPRETERS and any(
        token.lower() in _EVAL_FLAGS for token in effective[1:]
    ):
        return "interpreter_or_downloader"
    if normalized in _REMOTE_COMMANDS:
        return "interpreter_or_downloader"
    if normalized == "npx":
        return "interpreter_or_downloader"
    if len(effective) == 1 and normalized in _BROAD_COMMANDS:
        return "interpreter_or_downloader"
    return None


def _breadth(tool, pattern, command, tokens):
    if tool in _NETWORK_TOOLS:
        wildcard = (pattern or "").strip().lower()
        return "unrestricted_network" if pattern is None or wildcard in {
            "*", "**", ":*", "domain:*",
        } else None
    if tool not in _EXECUTION_TOOLS:
        return None
    if pattern is None or command in {"", "*", "**"}:
        return "wildcard_all_commands"
    classes = {_segment_breadth(segment) for segment in _segments(tokens)}
    for candidate in ("privilege_escalation", "package_installer",
                      "interpreter_or_downloader"):
        if candidate in classes:
            return candidate
    return None


def _reaches_network(tool, pattern, tokens):
    if tool in _NETWORK_TOOLS:
        return True
    if tool not in _EXECUTION_TOOLS:
        return False
    if pattern is None or not tokens or tokens[0] in {"", "*", "**"}:
        return True
    return any(
        effective and _basename(effective[0]) in _NETWORK_COMMANDS
        for segment in _segments(tokens)
        if (effective := _effective_tokens(segment)[0])
    )


def _dynamic_command_target(tokens):
    for segment in _segments(tokens):
        effective = _effective_tokens(segment)[0]
        if not effective or _basename(effective[0]) not in _INTERPRETERS:
            continue
        for index, token in enumerate(effective[1:-1], 1):
            if token.lower() in _EVAL_FLAGS:
                variable = _VARIABLE.search(effective[index + 1])
                if variable:
                    return variable
    return None


def check(parsed) -> list[Finding]:
    findings = []
    manifests = sorted(
        (artifact for artifact in parsed.artifacts if artifact.kind == "skill_manifest"),
        key=lambda artifact: artifact.rel,
    )
    for artifact in manifests:
        line = artifact.frontmatter_key_lines.get("allowed-tools") or 1
        for grant in artifact.grants or ():
            if not grant.allowed or not grant.tool or not grant.parsed:
                continue
            command, tokens = _command_tokens(grant.pattern)
            if grant.tool in _EXECUTION_TOOLS and grant.pattern:
                substitution = _COMMAND_SUBSTITUTION.search(command)
                variable = substitution
                if variable is None:
                    for segment in _segments(tokens):
                        segment_head = _effective_tokens(segment)[0]
                        if segment_head and (variable := _VARIABLE.search(segment_head[0])):
                            break
                if variable is None:
                    variable = _dynamic_command_target(tokens)
                if variable:
                    value = variable.group(1) if substitution else variable.group(0)
                    findings.append(Finding(
                        vector="SXV-003", rule="grant-variable-substitution", severity="high",
                        path=artifact.rel, line=line,
                        message=("execution pre-grant `%s` has a dynamic command target (%s)"
                                 % (grant.raw, value)),
                        evidence={"grant_text": grant.raw, "variable_name": value,
                                  "line": line},
                    ))
            breadth = _breadth(grant.tool, grant.pattern, command, tokens)
            if breadth:
                severity = "critical" if breadth in {
                    "wildcard_all_commands", "privilege_escalation",
                } else "high"
                findings.append(Finding(
                    vector="SXV-004", rule="grant-over-broad", severity=severity,
                    path=artifact.rel, line=line,
                    message="pre-granted tool `%s` is over-broad (%s)" % (grant.raw, breadth),
                    evidence={"grant_text": grant.raw, "breadth_class": breadth, "line": line,
                              "reaches_network": _reaches_network(
                                  grant.tool, grant.pattern, tokens)},
                ))
    return cap_findings(findings)
