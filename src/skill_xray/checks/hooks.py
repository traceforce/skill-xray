"""Structured startup-hook and MCP auto-start detection."""

from __future__ import annotations

import posixpath
import re
import shlex

from packaging.requirements import InvalidRequirement, Requirement

from ..findings import Finding, cap_findings

_MISSING = object()
_CONFIG_KINDS = {"hooks_config", "mcp_config", "agent_config"}
_INSTRUCTION_KINDS = {"skill_manifest", "instruction", "agent_identity"}
_HOOK_EVENTS = (
    "ConfigChange", "CwdChanged", "DirectoryAdded", "Elicitation", "ElicitationResult",
    "FileChanged", "InstructionsLoaded", "MessageDisplay", "Notification", "PermissionDenied",
    "PermissionRequest", "PostCompact", "PostModelSwitch", "PostToolBatch", "PostToolUse",
    "PostToolUseFailure", "PreCompact", "PreModelSwitch", "PreToolUse", "SessionEnd",
    "SessionStart", "Setup", "Stop", "StopFailure", "SubagentStart", "SubagentStop",
    "TaskCompleted", "TaskCreated", "TeammateIdle", "UserPromptExpansion", "UserPromptSubmit",
    "WorktreeCreate", "WorktreeRemove",
)
_HOOK_EVENT = re.compile(r"\b(%s)\b" % "|".join(_HOOK_EVENTS), re.IGNORECASE)
_CANONICAL_EVENT = {event.lower(): event for event in _HOOK_EVENTS}
_SETTINGS = re.compile(
    r"(?i)(?:~[/\\]|%USERPROFILE%[/\\])?\.claude[/\\]"
    r"settings(?:\.local)?\.json|\bsettings(?:\.local)?\.json\b"
)
# Inflected verb forms only, so nouns like "additional"/"installation" do not read as directives.
_WRITE = re.compile(
    r"(?i)\b(?:add(?:s|ed|ing)?|append(?:s|ed|ing)?|install(?:s|ed|ing)?"
    r"|insert(?:s|ed|ing)?|merg(?:e|es|ed|ing)|prepend(?:s|ed|ing)?"
    r"|register(?:s|ed|ing)?|writ(?:e|es|ing|ten)|wrote)\b"
)
_NEGATED = re.compile(
    r"(?i)\b(?:(?:do\s+not|don['’]t|never|cannot|can['’]t"
    r"|(?:must|should|shall|would)\s+not|(?:must|should)n['’]t)\s+(?:ever\s+)?"
    r"(?:add|append|install|insert|merge|modify|prepend|register|write)|"
    r"(?:avoid|without)\s+(?:adding|appending|installing|inserting|merging|modifying|"
    r"prepending|registering|writing)|refrain\s+from\s+(?:adding|appending|installing|"
    r"inserting|merging|modifying|prepending|registering|writing))\b"
)
_DEFENSIVE_DESCRIPTION = re.compile(
    r"(?i)\b(?:check|detector|rule|scanner)\s+(?:detects|flags|identifies|reports)\b"
    r"[^.\n]{0,120}\b(?:that|which)\s+[^.\n]{0,40}"
    r"\b(?:add|append|install|insert|merge|prepend|register|write)\w*\b"
)
_INTERPRETERS = {
    "bash", "dash", "node", "perl", "php", "powershell", "pwsh", "python", "python3",
    "ruby", "sh", "zsh",
}
_FETCHERS = {
    "aria2c", "bitsadmin", "curl", "http", "httpie", "invoke-restmethod",
    "invoke-webrequest", "irm", "iwr", "wget",
}
_RUNNERS = {"bunx", "npx", "pipx", "pnpx", "uvx"}
_NPM_EXACT = re.compile(
    r"^(?:@[^/@]+/)?[^/@]+@v?\d+\.\d+\.\d+"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_OPTIONS_WITH_VALUE = {
    "npx": {"-c", "--cache", "--call", "--registry", "--userconfig"},
    "pnpx": {"--registry"},
    "pipx": {"--python", "--index-url", "--pip-args"},
    "uvx": {"--index", "--python", "--python-platform"},
}


def _portable_basename(value):
    name = value.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return re.sub(r"\.(?:bat|cmd|com|exe)$", "", name)


def _is_agent_config_location(rel):
    # Config kinds are classified by basename anywhere in the tree; only root-level or .claude/
    # files are agent-recognized wiring, so nested fixtures are not treated as live config.
    return posixpath.dirname(rel) in ("", ".claude")


def _incomplete(path, reason):
    return Finding(
        vector="", rule="analysis-incomplete", severity="high", path=path,
        message="hook/MCP configuration analysis is incomplete (%s)." % reason,
        evidence={"phase": "check", "reason": reason},
    )


def _instruction_findings(artifact):
    if artifact.kind not in _INSTRUCTION_KINDS or not artifact.markdown:
        return []
    lines = artifact.text.splitlines()
    findings = []
    for start, end in artifact.markdown.prose_spans:
        block = "\n".join(lines[start - 1:end])
        original_block = block
        masked = list(block)
        intervals = []
        for negated in _NEGATED.finditer(block):
            # Mask only from the negation onward so an earlier affirmative directive in the same
            # clause ("Append a hook..., but do not add...") stays analyzable.
            clause_start = negated.start()
            ends = [
                position for delimiter in (".", ";", "!", "?", "\n")
                if (position := block.find(delimiter, negated.end())) >= 0
            ]
            clause_end = min(ends) + 1 if ends else len(block)
            # A contrastive turn ("...but append...") begins a fresh affirmative directive.
            contrast = re.search(
                r"(?i)\b(?:but|however|yet|instead|rather)\b", block[negated.end():clause_end]
            )
            if contrast:
                clause_end = negated.end() + contrast.start()
            intervals.append((clause_start, clause_end))
        # Merge intervals so a delimiter-free block with many negations stays linear, not quadratic.
        intervals.sort()
        merged_end = -1
        for lo, hi in intervals:
            for position in range(max(lo, merged_end), hi):
                if masked[position] != "\n":
                    masked[position] = " "
            merged_end = max(merged_end, hi)
        block = "".join(masked)
        masked = list(block)
        for defensive in _DEFENSIVE_DESCRIPTION.finditer(block):
            for position in range(defensive.start(), defensive.end()):
                if masked[position] != "\n":
                    masked[position] = " "
        block = "".join(masked)
        candidate = None
        clause_start = 0
        boundaries = [match.end() for match in re.finditer(r";|[.!?](?=\s|$)", block)]
        for clause_end in (*boundaries, len(block)):
            clause = block[clause_start:clause_end]
            event = _HOOK_EVENT.search(clause)
            target = _SETTINGS.search(clause)
            write = _WRITE.search(clause)
            # Require the word "hook" so a clause that names the event while writing something
            # else ("append release notes ... for the SessionStart event") is not an install.
            if event and target and write and re.search(r"(?i)\bhooks?\b", clause):
                candidate = clause_start, event, target, write
                break
            clause_start = clause_end
        if candidate is None:
            continue
        clause_start, event, target, write = candidate
        before = block[:clause_start + event.start()]
        line = start + before.count("\n")
        column = clause_start + event.start() - before.rfind("\n")
        snippet = original_block.splitlines()[line - start].strip()
        canonical_event = _CANONICAL_EVENT[event.group(1).lower()]
        findings.append(Finding(
            vector="SXV-006", rule="startup-hook-install", severity="critical",
            path=artifact.rel, line=line, column=column,
            message="instructs installation of a %s startup hook into %s"
                    % (canonical_event, target.group(0)),
            evidence={
                "hook_event": canonical_event, "settings_target": target.group(0),
                "write_verb": write.group(0), "snippet": snippet,
            },
        ))
    return findings


def _tokens(command):
    try:
        # Package paths are represented with POSIX separators in the IR. Converting separators
        # before shlex keeps Windows-relative paths comparable without using host path semantics.
        lexer = shlex.shlex(
            command.replace("\\", "/"), posix=True, punctuation_chars=";&|<>",
        )
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError:
        return None


def _local_candidate(parsed, command, arguments=()):
    if "\r" in command or "\n" in command or "$(" in command or "`" in command:
        return "dynamic_or_compound", False
    tokens = _tokens(command)
    if not tokens:
        return "malformed_command" if tokens is None else "empty_command", False
    head = _portable_basename(tokens[0])
    if head in _FETCHERS:
        return "network_fetch", False
    if any(token and set(token) <= set(";&|<>") for token in tokens):
        return "dynamic_or_compound", False
    tokens.extend(argument.replace("\\", "/") for argument in arguments)

    index = 0
    if head in {"powershell", "pwsh"}:
        index = 1
        while index < len(tokens):
            flag = tokens[index].lower()
            if flag in {"-command", "-encodedcommand"}:
                return "inline_interpreter", False
            if flag == "-file":
                index += 1
                break
            if flag in {"-executionpolicy", "-windowstyle"}:
                index += 2
                continue
            if flag in {"-nologo", "-noninteractive", "-noprofile"}:
                index += 1
                continue
            break
    elif head in _INTERPRETERS or re.fullmatch(r"python\d+(?:\.\d+)*", head):
        is_shell = head in {"bash", "dash", "sh", "zsh"}
        index = 1
        while index < len(tokens) and tokens[index].startswith("-"):
            flag = tokens[index].lower()
            if flag == "-c" or (not is_shell and flag in {"-e", "--eval"}):
                return "inline_interpreter", False
            if is_shell and flag == "-s":
                # `sh -s` runs the program from stdin; the path is only $0, not the script.
                return "dynamic_or_compound", False
            index += 1
    if index >= len(tokens):
        return "unresolved_external", False
    candidate = re.sub(
        r"^\$(?:\{(?:CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT)\}"
        r"|CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT)/", "", tokens[index],
    )
    if any(char in candidate for char in "$`|;&><"):
        return "dynamic_or_compound", False
    normalized = posixpath.normpath(candidate.removeprefix("./"))
    if (candidate.startswith(("/", "~")) or re.match(r"^[A-Za-z]:/", candidate)
            or normalized == ".." or normalized.startswith("../")):
        return "external_path", False
    art = parsed.by_rel.get(normalized)
    if art is not None and getattr(art, "text", None) is not None:
        return "package_local:%s" % normalized, True
    return "unresolved_external", False


def _hook_source(artifact):
    if artifact.kind in _CONFIG_KINDS and isinstance(artifact.config, dict):
        return artifact.config.get("hooks", _MISSING), 1
    if artifact.kind == "skill_manifest" and isinstance(artifact.frontmatter, dict):
        return (artifact.frontmatter.get("hooks", _MISSING),
                artifact.frontmatter_key_lines.get("hooks", 1))
    return _MISSING, 1


def _hook_findings(parsed, artifact):
    if artifact.kind in _CONFIG_KINDS and not _is_agent_config_location(artifact.rel):
        return []
    hooks, source_line = _hook_source(artifact)
    if hooks is _MISSING:
        return []
    if not isinstance(hooks, dict):
        return [_incomplete(artifact.rel, "hooks_not_object")]
    findings = []
    malformed = False
    for event in sorted(hooks, key=lambda value: (not isinstance(value, str), str(value))):
        groups = hooks[event]
        if not isinstance(event, str) or not isinstance(groups, list):
            malformed = True
            continue
        canonical_event = _CANONICAL_EVENT.get(event.lower())
        if canonical_event is None:
            malformed = True
            continue
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                malformed = True
                continue
            matcher = group.get("matcher", "*")
            if not isinstance(matcher, str):
                malformed = True
                matcher = "<invalid>"
            for entry in group["hooks"]:
                if not isinstance(entry, dict):
                    malformed = True
                    continue
                hook_type = entry.get("type", "command")
                if hook_type == "http":
                    url = entry.get("url")
                    if (not isinstance(url, str)
                            or not url.lower().startswith(("http://", "https://"))):
                        malformed = True
                        continue
                    findings.append(Finding(
                        vector="SXV-012", rule="root-hook-autoexec", severity="medium",
                        path=artifact.rel, line=source_line,
                        message="%s hook auto-executes a remote HTTP handler (%s)"
                                % (canonical_event, url),
                        evidence={
                            "hook_event": canonical_event, "matcher": matcher, "command": url,
                            "hook_type": "http", "resolution": "remote_http",
                        },
                    ))
                    continue
                if hook_type == "mcp_tool":
                    tool_name = entry.get("tool_name")
                    if tool_name is None:
                        server = entry.get("server")
                        tool = entry.get("tool")
                        if (isinstance(server, str) and server.strip()
                                and isinstance(tool, str) and tool.strip()):
                            tool_name = "%s.%s" % (server.strip(), tool.strip())
                    if not isinstance(tool_name, str) or not tool_name.strip():
                        malformed = True
                        continue
                    tool_name = tool_name.strip()
                    findings.append(Finding(
                        vector="SXV-012", rule="root-hook-autoexec", severity="medium",
                        path=artifact.rel, line=source_line,
                        message="%s hook auto-executes connected MCP tool %s"
                                % (canonical_event, tool_name),
                        evidence={
                            "hook_event": canonical_event, "matcher": matcher,
                            "command": tool_name, "hook_type": "mcp_tool",
                            "resolution": "connected_mcp_tool",
                        },
                    ))
                    continue
                if hook_type in {"prompt", "agent"}:
                    prompt = entry.get("prompt")
                    if not isinstance(prompt, str) or not prompt.strip():
                        malformed = True
                        continue
                    if re.search(r"\$\{?[A-Za-z_]\w*\}?|`[^`]+`", prompt):
                        findings.append(Finding(
                            vector="SXV-012", rule="root-hook-autoexec", severity="medium",
                            path=artifact.rel, line=source_line,
                            message="%s hook auto-executes a dynamic %s handler (%s)"
                                    % (canonical_event, hook_type, prompt),
                            evidence={
                                "hook_event": canonical_event, "matcher": matcher,
                                "command": prompt, "hook_type": hook_type,
                                "resolution": "dynamic_semantic",
                            },
                        ))
                    continue
                if hook_type != "command":
                    malformed = True
                    continue
                command = entry.get("command")
                arguments = entry.get("args", [])
                if not isinstance(command, str) or not command.strip():
                    malformed = True
                    continue
                if (not isinstance(arguments, list)
                        or not all(isinstance(argument, str) for argument in arguments)):
                    malformed = True
                    continue
                command = command.strip()
                resolution, is_local = _local_candidate(parsed, command, arguments)
                if is_local:
                    continue
                findings.append(Finding(
                    vector="SXV-012", rule="root-hook-autoexec", severity="medium",
                    path=artifact.rel, line=source_line,
                    message="%s hook auto-executes an unreviewable command (%s): %s"
                    % (canonical_event, resolution, command),
                    evidence={
                        "hook_event": canonical_event, "matcher": matcher, "command": command,
                        "hook_type": "command", "resolution": resolution,
                    },
                ))
    if malformed:
        findings.append(_incomplete(artifact.rel, "malformed_hook_entry"))
    return findings


def _server_maps(artifact):
    config = artifact.config
    if artifact.kind not in _CONFIG_KINDS or not isinstance(config, dict):
        return []
    maps = []
    for key in ("mcpServers", "mcp_servers", "servers"):
        if key in config:
            maps.append(config[key])
    if not maps and artifact.kind == "mcp_config" and artifact.manifest_kind == "mcp_servers":
        maps.append(config)
    return maps


def _package_specs(runner, args):
    # npm/pipx allow the package-selecting option more than once, so every selected package is
    # evaluated; once one is given the trailing positional is the command to run, not a package.
    specs = []
    positionals = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            # Everything after the option terminator is passed to the launched tool, not the runner.
            break
        if arg in {"-p", "--package", "--spec"}:
            if index + 1 >= len(args) or args[index + 1].startswith("-"):
                return specs, True
            specs.append(args[index + 1])
            index += 2
            continue
        if arg.startswith(("--package=", "--spec=")):
            value = arg.split("=", 1)[1]
            if not value:
                return specs, True
            specs.append(value)
            index += 1
            continue
        if arg in _OPTIONS_WITH_VALUE.get(runner, set()):
            if index + 1 >= len(args):
                return specs, True
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        positionals.append(arg)
        index += 1
    if specs:
        return specs, False
    if runner == "pipx":
        # pipx fetches an ephemeral package only for `run`; other subcommands act on installed ones.
        if positionals[:1] != ["run"]:
            return [], False
        positionals = positionals[1:]
    return positionals[:1], False


def _is_exact_pin(runner, spec):
    if spec.startswith((".", "/", "~", "file:")) or re.match(r"^[A-Za-z]:[\\/]", spec):
        return True
    if spec.startswith(("git:", "git+", "github:", "gitlab:", "bitbucket:")):
        return bool(re.search(r"[#@][0-9a-fA-F]{40}(?:[#?].*)?$", spec))
    if spec.startswith(("http:", "https:")):
        return False
    if runner in {"uvx", "pipx"}:
        try:
            requirement = Requirement(spec)
        except InvalidRequirement:
            return False
        if requirement.url:
            # A PEP 508 direct reference is immutable only when it pins a full commit SHA.
            return bool(re.search(r"@[0-9a-fA-F]{40}(?:[#?].*)?$", requirement.url))
        constraints = list(requirement.specifier)
        return (len(constraints) == 1 and constraints[0].operator in {"==", "==="}
                and "*" not in constraints[0].version)
    return bool(_NPM_EXACT.fullmatch(spec))


def _mcp_findings(artifact):
    if artifact.kind in _CONFIG_KINDS and not _is_agent_config_location(artifact.rel):
        return []
    server_maps = _server_maps(artifact)
    if not server_maps:
        return []
    findings = []
    malformed = False
    for servers in server_maps:
        if not isinstance(servers, dict):
            malformed = True
            continue
        for name in sorted(servers):
            server = servers[name]
            if not isinstance(name, str) or not isinstance(server, dict):
                malformed = True
                continue
            command = server.get("command")
            args = server.get("args", [])
            if command is None and server.get("type") in {"http", "sse"}:
                continue
            if (not isinstance(command, str) or not command.strip()
                    or not isinstance(args, list)
                    or not all(isinstance(arg, str) for arg in args)):
                malformed = True
                continue
            runner = _portable_basename(command)
            runner_args = args
            if runner in {"npm", "pnpm", "yarn", "bun"}:
                # Skip leading global flags ("npm --silent exec ...") to find the subcommand.
                sub = 0
                while sub < len(args) and args[sub].startswith("-"):
                    sub += 1
                subcommand = args[sub] if sub < len(args) else ""
                aliases = {"npm": {"exec", "x"}, "bun": {"x"}, "pnpm": {"dlx"}, "yarn": {"dlx"}}
                if subcommand in aliases[runner]:
                    runner, runner_args = "npx", args[sub + 1:]
            if runner not in _RUNNERS:
                continue
            specs, bad_args = _package_specs(runner, runner_args)
            if bad_args:
                malformed = True
                continue
            for spec in specs:
                if _is_exact_pin(runner, spec):
                    continue
                findings.append(Finding(
                    vector="SXV-013", rule="floating-mcp-package", severity="low",
                    path=artifact.rel, line=1,
                    message="auto-start server %s resolves floating package %s" % (name, spec),
                    evidence={
                        "server_name": name, "command": command, "specifier": spec,
                        "pin_state": "floating_or_unpinned", "args": args,
                    },
                ))
    if malformed:
        findings.append(_incomplete(artifact.rel, "malformed_mcp_server"))
    return findings


def check(parsed):
    findings = []
    for artifact in parsed.artifacts:
        findings.extend(_instruction_findings(artifact))
        findings.extend(_hook_findings(parsed, artifact))
        findings.extend(_mcp_findings(artifact))
    return cap_findings(findings)
