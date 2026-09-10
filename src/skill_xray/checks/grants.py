"""Classify dynamic and over-broad execution/network pre-grants from the shared IR."""

from __future__ import annotations

import re
import shlex

from ..findings import Finding, cap_findings

_EXECUTION_TOOLS = {"Bash", "Shell", "Terminal", "Execute"}
_NETWORK_TOOLS = {"WebFetch", "WebSearch"}
_VARIABLE = re.compile(
    r"\$(?i:env):[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|"
    r"\$\{(?i:env):[A-Za-z_][A-Za-z0-9_]*\}|"
    r"\$\{!?[A-Za-z_][A-Za-z0-9_]*[^}\n]*\}|"
    r"\$[A-Za-z_][A-Za-z0-9_]*|\$\d+|\$[@*]"
)
_VERSION_SUFFIX = re.compile(r"\d+(?:\.\d+)*$")
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*=")
_WRAPPER_ARGUMENT = re.compile(r"^-|=|^\d+(?:\.\d+)?[smhd]?$")

_BROAD_COMMANDS = {
    "bash", "bun", "chmod", "chown", "cmd", "curl", "dash", "deno", "env", "eval", "git",
    "fish", "ksh", "nc", "ncat", "node", "npx", "osascript", "perl", "php",
    "pip", "pip3", "powershell", "pwsh", "py", "python", "python3", "ruby",
    "scp", "sftp", "sh", "socat", "ssh", "su", "sudo", "wget", "xargs", "zsh",
}
_INSTALLERS = {
    ("apk", "add"), ("apt", "install"), ("apt-get", "install"), ("brew", "install"),
    ("cargo", "install"), ("dotnet", "tool", "install"),
    ("dotnet", "tool", "restore"), ("dotnet", "tool", "update"), ("gem", "install"),
    ("go", "install"), ("npm", "ci"), ("npm", "i"), ("npm", "install"),
    ("pip", "install"),
    ("pip3", "install"), ("pnpm", "add"), ("uv", "add"),
    ("uv", "pip", "install"),
    ("yarn", "add"),
}
_INSTALLER_COMMANDS = {action[0] for action in _INSTALLERS}
_INSTALLER_VALUE_OPTIONS = {
    "cargo": {"--color", "--config", "--target-dir"},
    "pip": {"--proxy", "--python"}, "pip3": {"--proxy", "--python"},
}
_INTERPRETERS = {
    "bash", "bun", "dash", "deno", "fish", "ksh", "node", "osascript", "perl", "php",
    "cmd", "powershell", "pwsh", "py", "python", "python3", "ruby", "sh", "zsh",
}
_EVAL_FLAGS = {
    "bash": {"-c"}, "dash": {"-c"}, "fish": {"-c"}, "ksh": {"-c"},
    "sh": {"-c"}, "zsh": {"-c"},
    "cmd": {"/c", "/k"},
    "powershell": {"-command", "-enc", "-encodedcommand"},
    "pwsh": {"-command", "-enc", "-encodedcommand"},
    "py": {"-c"}, "python": {"-c"}, "python3": {"-c"},
    "bun": {"-e", "--eval", "-p", "--print"},
    "node": {"-e", "--eval", "-p", "--print"},
    "perl": {"-e"}, "php": {"-r"}, "ruby": {"-e"}, "osascript": {"-e"},
}
_WRAPPERS = {
    "command", "doas", "env", "exec", "ionice", "nice", "nohup", "setsid", "stdbuf",
    "sudo", "time", "timeout", "xargs",
}
_WRAPPER_VALUE_OPTIONS = {
    "env": {"-C", "--chdir", "-u", "--unset"},
    "sudo": {"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt"},
    "stdbuf": {"-i", "--input", "-o", "--output", "-e", "--error"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
}
_PRIVILEGE_COMMANDS = {"su", "sudo"}
_NETWORK_COMMANDS = {
    "aria2c", "curl", "http", "httpie", "nc", "ncat", "node", "npx", "perl", "python",
    "python3", "ruby", "scp", "sftp", "socat", "ssh", "wget", "git",
    "powershell", "pwsh", "ftp", "telnet",
} | _INSTALLER_COMMANDS
_NETWORK_ONLY_COMMANDS = {"aria2c", "curl", "http", "httpie", "scp", "sftp", "wget"}
_REMOTE_COMMANDS = _NETWORK_ONLY_COMMANDS | {"ftp", "nc", "ncat", "socat", "ssh", "telnet"}
_GIT_REMOTE_SUBCOMMANDS = {"clone", "fetch", "pull", "push", "remote", "submodule"}
_NON_EXECUTION_COMMANDS = _NETWORK_ONLY_COMMANDS | {
    "alias", "bg", "break", "cd", "chmod", "chown", "command", "continue", "declare", "dirs",
    "disown", "echo", "exit", "export", "false", "fg", "getopts", "hash", "help",
    "history", "jobs", "local", "logout", "mapfile", "popd", "printf", "pushd", "pwd",
    "read", "readarray", "readonly", "return", "set", "shift", "shopt", "suspend",
    "test", "times", "true", "type", "typeset", "ulimit", "umask", "unalias", "unset",
    "wait",
}


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
        lexer = shlex.shlex(command, posix=False, punctuation_chars=";&|\n")
        lexer.whitespace = " \t\r"
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
        if head == "command" and len(remaining) > 1 and remaining[1] in {"-v", "-V"}:
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
        if token and set(token) <= set(";&|\n"):
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
    if not effective and tokens and _basename(tokens[0]) in _WRAPPERS:
        return "interpreter_or_downloader"
    if not effective:
        effective = tokens
    head = _basename(effective[0])
    normalized = _VERSION_SUFFIX.sub("", head) or head
    if normalized in _PRIVILEGE_COMMANDS:
        return "privilege_escalation"
    if (normalized in {"py", "python", "python3"} and len(effective) >= 3
            and effective[1].lower() == "-m"):
        module = effective[2].lower()
        if (module == "ensurepip" or (module == "pip" and (
                len(effective) == 3
                or _installer_subcommand(effective[2:], "pip") is not None))):
            return "package_installer"
        if module == "http.server":
            return "interpreter_or_downloader"
    if _installer_subcommand(effective, normalized) is not None:
        return "package_installer"
    if len(effective) == 1 and normalized in _INSTALLER_COMMANDS:
        return "package_installer"
    if normalized == "eval":
        return "interpreter_or_downloader"
    if normalized in _INTERPRETERS and _eval_option(effective, normalized) is not None:
        return "interpreter_or_downloader"
    if normalized in _REMOTE_COMMANDS:
        return "interpreter_or_downloader"
    if (normalized == "git" and (len(effective) == 1
                                  or effective[1].lower() in _GIT_REMOTE_SUBCOMMANDS)):
        return "interpreter_or_downloader"
    if normalized == "npx":
        return "interpreter_or_downloader"
    if len(effective) == 1 and normalized in _BROAD_COMMANDS:
        return "interpreter_or_downloader"
    return None


def _installer_subcommand(effective, normalized):
    if normalized not in _INSTALLER_COMMANDS:
        return None
    index = 1
    while index < len(effective) and effective[index].startswith("-"):
        option = effective[index].split("=", 1)[0]
        index += 1
        if option in _INSTALLER_VALUE_OPTIONS.get(normalized, set()) and index < len(effective):
            index += 1
    tail = tuple(token.lower() for token in effective[index:])
    for action in _INSTALLERS:
        if action[0] == normalized and tail[:len(action) - 1] == action[1:]:
            return action[-1]
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
        effective and (_VERSION_SUFFIX.sub("", _basename(effective[0]))
                       or _basename(effective[0])) in _NETWORK_COMMANDS
        for segment in _segments(tokens)
        if (effective := _effective_tokens(segment)[0])
    )


def _eval_option(effective, interpreter):
    accepted = _EVAL_FLAGS.get(interpreter, set())
    for index, token in enumerate(effective[1:], 1):
        lowered = token.lower() if interpreter in {"cmd", "powershell", "pwsh"} else token
        if lowered == "--":
            return None
        if lowered in accepted:
            return index, None
        if interpreter in {"bash", "dash", "fish", "ksh", "sh", "zsh"}:
            cluster = token[1:] if token.startswith("-") else ""
            if "c" in cluster:
                suffix = cluster[cluster.index("c") + 1:]
                return index, suffix or None
        if interpreter in {"py", "python", "python3"}:
            cluster = token[1:] if token.startswith("-") else ""
            if "c" in cluster:
                suffix = cluster[cluster.index("c") + 1:]
                return index, suffix or None
        for prefix in accepted & {"-c", "-e", "/c", "/k"}:
            if lowered.startswith(prefix) and len(token) > len(prefix):
                return index, token[len(prefix):]
        if not token.startswith(("-", "/")):
            return None
    return None


def _expandable_variable(token):
    for match in _VARIABLE.finditer(token):
        if _shell_expands_at(token, match.start()):
            return match
    return None


def _shell_expands_at(token, target):
    single = False
    double = False
    escaped = False
    for char in token[:target]:
        if escaped:
            escaped = False
        elif char == "\\" and not single:
            escaped = True
        elif char == "'" and not double:
            single = not single
        elif char == '"' and not single:
            double = not double
    return not single and not escaped


def _dynamic_command_target(tokens):
    for segment in _segments(tokens):
        effective = _effective_tokens(segment)[0]
        if not effective:
            continue
        head = _VERSION_SUFFIX.sub("", _basename(effective[0])) or _basename(effective[0])
        if head == "eval":
            payload = " ".join(effective[1:])
            return _expandable_substitution(payload) or _expandable_variable(payload)
        if head not in _INTERPRETERS:
            continue
        option = _eval_option(effective, head)
        if option is not None:
            index, attached = option
            payload = attached if attached is not None else (
                " ".join(effective[index + 1:]) if index + 1 < len(effective) else ""
            )
            substitution = _expandable_substitution(payload)
            if substitution:
                return substitution
            variable = _expandable_variable(payload)
            if variable:
                return variable
    return None


def _command_substitution_head(tokens):
    effective = _effective_tokens(tokens)[0]
    if not effective:
        return None
    joined = " ".join(effective)
    substitution = _expandable_substitution(joined)
    if substitution is None or joined.find(substitution) >= len(effective[0]):
        return None
    return substitution


def _denial_covers(denial, grant):
    if denial.tool != grant.tool or denial.allowed or not denial.parsed:
        return False
    denied = (denial.pattern or "").strip()
    allowed = (grant.pattern or "").strip()
    if not denied or denied.lower() in {"*", "**", ":*"} or denied == allowed:
        return True
    if denied.endswith(":*"):
        prefix = denied[:-2].rstrip()
        candidate = allowed[:-2].rstrip() if allowed.endswith(":*") else allowed
        return candidate == prefix or candidate.startswith(prefix + " ")
    return False


def effective_grants(grants):
    """Allowed, parsed grants not closed by a matching denial."""
    values = list(grants or ())
    denials = [grant for grant in values if not grant.allowed]
    return [
        grant for grant in values
        if grant.allowed and grant.parsed
        and not any(_denial_covers(denial, grant) for denial in denials)
    ]


def _grant_capabilities(grants):
    grants = list(grants)
    execution = False
    for grant in grants:
        if grant.tool not in _EXECUTION_TOOLS:
            continue
        command, tokens = _command_tokens(grant.pattern)
        execution |= grant.pattern is None or command in {"", "*", "**"}
        for segment in _segments(tokens):
            effective = _effective_tokens(segment)[0] or segment
            raw_head = _basename(effective[0]) if effective else ""
            head = _VERSION_SUFFIX.sub("", raw_head) or raw_head
            execution |= bool(head and head not in _NON_EXECUTION_COMMANDS)
    network = any(
        _reaches_network(grant.tool, grant.pattern, _command_tokens(grant.pattern)[1])
        for grant in grants
    )
    return {capability for capability, present in (
        ("execution", execution), ("network", network),
    ) if present}


def declared_capabilities(grants):
    """Capabilities materially declared by effective allowed grants."""
    return _grant_capabilities(effective_grants(grants))


def denied_capabilities(grants):
    """Capabilities explicitly governed by parsed denial grants."""
    denials = [
        grant for grant in (grants or ()) if not grant.allowed and grant.parsed
    ]
    capabilities = _grant_capabilities(denials)
    # Denying a shell (or one URL) is not a blanket denial of network APIs.
    if not any(grant.tool in _NETWORK_TOOLS
               and (grant.pattern or "").strip() in {"", "*", "**", ":*"} for grant in denials):
        capabilities.discard("network")
    return capabilities


def _expandable_substitution(value):
    single_quoted = False
    double_quoted = False
    escaped = False
    index = 0
    while index < len(value):
        char = value[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and not single_quoted:
            escaped = True
            index += 1
            continue
        if char == "'" and not double_quoted:
            single_quoted = not single_quoted
            index += 1
            continue
        if char == '"' and not single_quoted:
            double_quoted = not double_quoted
            index += 1
            continue
        if single_quoted:
            index += 1
            continue
        if value.startswith("$(", index):
            depth = 1
            end = index + 2
            while end < len(value) and depth:
                if value[end] == "(" and value[end - 1] != "\\":
                    depth += 1
                elif value[end] == ")" and value[end - 1] != "\\":
                    depth -= 1
                end += 1
            if depth == 0:
                return value[index:end]
        elif char == "`":
            end = index + 1
            while end < len(value):
                if value[end] == "`" and value[end - 1] != "\\":
                    return value[index:end + 1]
                end += 1
        index += 1
    return None


def check(parsed) -> list[Finding]:
    findings = []
    manifests = sorted(
        (artifact for artifact in parsed.artifacts if artifact.kind == "skill_manifest"),
        key=lambda artifact: artifact.rel,
    )
    for artifact in manifests:
        line = artifact.frontmatter_key_lines.get("allowed-tools") or 1
        denials = [grant for grant in artifact.grants or () if not grant.allowed]
        for grant in artifact.grants or ():
            if (not grant.allowed or not grant.tool or not grant.parsed
                    or any(_denial_covers(denial, grant) for denial in denials)):
                continue
            command, tokens = _command_tokens(grant.pattern)
            if grant.tool in _EXECUTION_TOOLS and grant.pattern:
                value = None
                variable = None
                if value is None:
                    for segment in _segments(tokens):
                        if (value := _command_substitution_head(segment)) is not None:
                            break
                        segment_head = _effective_tokens(segment)[0]
                        if segment_head and (variable := _expandable_variable(segment_head[0])):
                            break
                if value is None and variable is None:
                    variable = _dynamic_command_target(tokens)
                if value is None and variable is not None:
                    value = variable if isinstance(variable, str) else variable.group(0)
                if value is not None:
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
