// Package hooks reports startup-hook and MCP auto-start findings from the parsed IR, Python
// checks/hooks.py: SXV-006 startup-hook-install (prose), SXV-012 root-hook-autoexec (hook
// configs and skill frontmatter) and SXV-013 floating-mcp-package (MCP server configs).
package hooks

import (
	"cmp"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pep508"
	"github.com/traceforce/skill-xray/internal/pytext"
)

var (
	configKinds = map[string]bool{"hooks_config": true, "mcp_config": true, "agent_config": true}
	hookEvents  = []string{
		"ConfigChange", "CwdChanged", "DirectoryAdded", "Elicitation", "ElicitationResult",
		"FileChanged", "InstructionsLoaded", "MessageDisplay", "Notification", "PermissionDenied",
		"PermissionRequest", "PostCompact", "PostModelSwitch", "PostToolBatch", "PostToolUse",
		"PostToolUseFailure", "PreCompact", "PreModelSwitch", "PreToolUse", "SessionEnd",
		"SessionStart", "Setup", "Stop", "StopFailure", "SubagentStart", "SubagentStop",
		"TaskCompleted", "TaskCreated", "TeammateIdle", "UserPromptExpansion", "UserPromptSubmit",
		"WorktreeCreate", "WorktreeRemove",
	}
	canonicalEvent = func() map[string]string {
		m := map[string]string{}
		for _, e := range hookEvents {
			m[pytext.Lower(e)] = e
		}
		return m
	}()
	interpreters     = pytext.Set("bash", "dash", "node", "perl", "php", "powershell", "pwsh", "python", "python3", "ruby", "sh", "zsh")
	shells           = pytext.Set("bash", "dash", "sh", "zsh")
	fetchers         = pytext.Set("aria2c", "bitsadmin", "curl", "http", "httpie", "invoke-restmethod", "invoke-webrequest", "irm", "iwr", "wget")
	runners          = pytext.Set("bunx", "npx", "pipx", "pnpx", "uvx")
	nodePreload      = pytext.Set("-r", "--require", "--import", "--loader", "--experimental-loader", "--env-file", "--env-file-if-exists")
	optionsWithValue = map[string]map[string]bool{
		"npx":  pytext.Set("-c", "--cache", "--call", "--prefix", "--registry", "--userconfig"),
		"pnpx": pytext.Set("--registry"),
		"pipx": pytext.Set("-p", "--python", "--index-url", "--pip-args"),
		"uvx":  pytext.Set("-p", "--index", "--python", "--python-platform"),
	}
	runnerAliases   = map[string]map[string]bool{"npm": pytext.Set("exec", "x"), "bun": pytext.Set("x"), "pnpm": pytext.Set("dlx"), "yarn": pytext.Set("dlx")}
	globalValueOpts = pytext.Set("-c", "--prefix", "--loglevel", "--registry", "--workspace", "-w", "--dir", "--filter")
	agentConfigDirs = map[string]map[string]bool{
		".mcp.json":                  pytext.Set(""),
		"hooks.json":                 pytext.Set(""),
		"settings.json":              pytext.Set("", ".claude"),
		"settings.local.json":        pytext.Set("", ".claude"),
		"mcp.json":                   pytext.Set("", ".cursor", ".vscode"),
		"claude_desktop_config.json": pytext.Set(""),
		"config.toml":                pytext.Set(".codex"),
	}
)

var (
	hookEventRE = pytext.PyRE(`(?i)\b(` + strings.Join(hookEvents, "|") + `)\b`)
	// _SETTINGS split at its alternation; the second alternative's (?<![\w/\\.]) and \b are
	// applied by settingsSearch through pytext.FindAllBounded.
	settingsClaudeRE = pytext.PyRE(`(?i)(?:~[/\\]|%USERPROFILE%[/\\])?\.claude[/\\]settings(?:\.local)?\.json`)
	settingsBareRE   = pytext.PyRE(`(?i)settings(?:\.local)?\.json`)
	writeRE          = pytext.PyRE(`(?i)\b(?:add(?:s|ed|ing)?|append(?:s|ed|ing)?|configur(?:e|es|ed|ing)` +
		`|creat(?:e|es|ed|ing)|install(?:s|ed|ing)?|insert(?:s|ed|ing)?|merg(?:e|es|ed|ing)` +
		`|prepend(?:s|ed|ing)?|register(?:s|ed|ing)?|sets?|setting|writ(?:e|es|ing|ten)|wrote)\b`)
	negatedRE = pytext.PyRE(`(?i)\b(?:(?:do\s+not|don['’]t|never|cannot|can['’]t` +
		`|(?:must|should|shall|would)\s+not|(?:must|should)n['’]t)\s+(?:ever\s+)?` +
		`(?:add|append|configure|create|install|insert|merge|modify|prepend|register|set|write)|` +
		`(?:avoid|without)\s+(?:adding|appending|configuring|creating|installing|inserting|` +
		`merging|modifying|prepending|registering|setting|writing)|` +
		`refrain\s+from\s+(?:adding|appending|configuring|creating|installing|inserting|` +
		`merging|modifying|prepending|registering|setting|writing))\b`)
	defensiveRE = pytext.PyRE(`(?i)\b(?:check|detector|rule|scanner)\s+(?:detects|flags|identifies|reports)\b` +
		`[^.\n]{0,120}\b(?:that|which)\s+[^.\n]{0,40}` +
		`\b(?:add|append|install|insert|merge|prepend|register|write)\w*\b`)
	// [.!?](?=\s|$)|[;\n] and ;|[.!?](?=\s|$) with the lookahead consumed; clauseEnd trims it.
	negationEndRE    = pytext.PyRE(`[.!?]\s|[.!?]\z|[;\n]`)
	clauseBoundaryRE = pytext.PyRE(`;|[.!?]\s|[.!?]\z`)
	contrastRE       = pytext.PyRE(`(?i)\b(?:but|however|yet|instead|rather|then|next|afterwards?)\b`)
	hookWordRE       = pytext.PyRE(`(?i)\bhooks?\b`)
	pythonVersionRE  = pytext.PyRE(`\Apython\d+(?:\.\d+)*\z`)
	projectDirRE     = pytext.PyRE(`^\$(?:\{(?:CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT)\}|CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT)/`)
	drivePathRE      = pytext.PyRE(`^[A-Za-z]:/`)
	dynamicPromptRE  = pytext.PyRE(`\$\{?[A-Za-z_]\w*\}?|` + "`[^`]+`")
)

// clauseEnd is m.end() for a match of negationEndRE/clauseBoundaryRE: the consumed
// whitespace after [.!?] is not part of the Python match.
func clauseEnd(m []int) int {
	if m[1]-m[0] > 1 {
		return m[0] + 1
	}
	return m[1]
}

// settingsSearch is _SETTINGS.search: the leftmost of either alternative.
func settingsSearch(clause string) []int {
	best := settingsClaudeRE.FindStringIndex(clause)
	bare := pytext.FindAllBounded(settingsBareRE, clause,
		func(r rune) bool { return !(pytext.IsWord(r) || r == '/' || r == '\\' || r == '.') },
		func(r rune) bool { return !pytext.IsWord(r) })
	if len(bare) > 0 && (best == nil || bare[0][0] < best[0]) {
		best = bare[0][:2]
	}
	return best
}

// runes is the code-point distance from byte offset a to b in s.
func runes(s string, a, b int) int { return utf8.RuneCountInString(s[a:b]) }

// portableSuffixes are the suffixes _portable_basename strips (no .ps1, and no trailing-slash trim).
var portableSuffixes = []string{".bat", ".cmd", ".com", ".exe"}

// portableBasename is _portable_basename.
func portableBasename(value string) string { return pytext.CommandBasename(value, portableSuffixes...) }

func isAgentConfigLocation(rel string) bool {
	dir := path.Dir(rel)
	if dir == "." {
		dir = ""
	}
	return agentConfigDirs[pytext.Lower(path.Base(rel))][pytext.Lower(dir)]
}

func writeTargetsHook(clause string, event, target, write []int) bool {
	hook := hookWordRE.FindStringIndex(clause)
	if hook == nil {
		return write[0] < event[0] && event[0] < target[0] && runes(clause, write[1], target[1]) <= 96
	}
	subjectStart, subjectEnd := min(event[0], hook[0]), max(event[1], hook[1])
	if write[1] <= subjectStart {
		return runes(clause, write[1], subjectEnd) <= 48
	}
	if subjectEnd <= write[0] {
		return runes(clause, subjectStart, write[1]) <= 48
	}
	return true
}

func incomplete(rel, reason string) findings.Finding {
	return findings.Finding{Rule: "analysis-incomplete", Severity: "high", Path: rel,
		Message:  fmt.Sprintf("hook/MCP configuration analysis is incomplete (%s).", reason),
		Evidence: map[string]any{"phase": "check", "reason": reason}}
}

// mask blanks every code point except "\n" inside the byte intervals (the list(block)
// rewrites); overlapping intervals are merged in one sweep.
func mask(s string, intervals [][]int) string {
	slices.SortFunc(intervals, func(a, b []int) int { return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1])) })
	var b strings.Builder
	k, end := 0, -1
	for i, r := range s {
		for k < len(intervals) && intervals[k][0] <= i {
			end = max(end, intervals[k][1])
			k++
		}
		if i < end && r != '\n' {
			b.WriteByte(' ')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// instructionFindings is _instruction_findings, SXV-006: at most one per prose span.
func instructionFindings(a *parse.Artifact) []findings.Finding {
	if !parse.InstructionKinds[a.Kind] || a.Markdown == nil || a.Text == nil {
		return nil
	}
	lines := pytext.SplitLines(*a.Text)
	var out []findings.Finding
	for _, span := range a.Markdown.ProseSpans {
		original := pytext.JoinLines(lines, span.Start-1, span.End)
		var intervals [][]int
		for _, negated := range negatedRE.FindAllStringIndex(original, -1) {
			end := len(original)
			if m := negationEndRE.FindStringIndex(original[negated[1]:]); m != nil {
				end = negated[1] + clauseEnd(m)
			}
			if c := contrastRE.FindStringIndex(original[negated[1]:end]); c != nil {
				end = negated[1] + c[0]
			}
			intervals = append(intervals, []int{negated[0], end})
		}
		block := mask(original, intervals)
		block = mask(block, defensiveRE.FindAllStringIndex(block, -1))
		var boundaries []int
		for _, m := range clauseBoundaryRE.FindAllStringIndex(block, -1) {
			boundaries = append(boundaries, clauseEnd(m))
		}
		var candidate []int // clauseStart, event start/end, target start/end, write start/end
		clauseStart := 0
		for _, end := range append(boundaries, len(block)) {
			clause := block[clauseStart:end]
			target, write := settingsSearch(clause), writeRE.FindStringIndex(clause)
			if target != nil && write != nil {
				for _, event := range hookEventRE.FindAllStringSubmatchIndex(clause, -1) {
					if writeTargetsHook(clause, event, target, write) {
						candidate = []int{clauseStart, event[0], event[1], target[0], target[1], write[0], write[1]}
						break
					}
				}
			}
			if candidate != nil {
				break
			}
			clauseStart = end
		}
		if candidate == nil {
			continue
		}
		clause := block[candidate[0]:]
		before := block[:candidate[0]+candidate[1]]
		line := span.Start + strings.Count(before, "\n")
		column := utf8.RuneCountInString(before[strings.LastIndex(before, "\n")+1:]) + 1
		event := canonicalEvent[pytext.Lower(clause[candidate[1]:candidate[2]])]
		target := clause[candidate[3]:candidate[4]]
		out = append(out, findings.Finding{
			Vector: "SXV-006", Rule: "startup-hook-install", Severity: "critical",
			Path: a.Rel, Line: findings.Int(line), Column: findings.Int(column),
			Message: fmt.Sprintf("instructs installation of a %s startup hook into %s", event, target),
			Evidence: map[string]any{
				"hook_event": event, "settings_target": target,
				"write_verb": clause[candidate[5]:candidate[6]],
				"snippet":    pytext.Strip(pytext.SplitLines(original)[line-span.Start]),
			},
		})
	}
	return out
}

// tokens is _tokens: shlex with punctuation chars over a command whose backslashes became "/";
// ok is false on an unclosed quote.
func tokens(command string) ([]string, bool) {
	toks, err := pytext.ShlexTokens(strings.ReplaceAll(command, "\\", "/"), true, ";&|<>", " \t\r\n")
	return toks, err == nil
}

func isPunctuationRun(token string) bool {
	return token != "" && strings.Trim(token, ";&|<>") == ""
}

// localCandidate is _local_candidate: how a hook command resolves and whether it names a
// readable package-local script.
func localCandidate(p *parse.Package, command string, arguments []string) (string, bool) {
	if strings.ContainsAny(command, "\r\n") || strings.Contains(command, "$(") || strings.Contains(command, "`") {
		return "dynamic_or_compound", false
	}
	toks, ok := tokens(command)
	if !ok {
		return "malformed_command", false
	}
	if len(toks) == 0 {
		return "empty_command", false
	}
	head := portableBasename(toks[0])
	if fetchers[head] {
		return "network_fetch", false
	}
	if slices.ContainsFunc(toks, isPunctuationRun) {
		return "dynamic_or_compound", false
	}
	for _, arg := range arguments {
		toks = append(toks, strings.ReplaceAll(arg, "\\", "/"))
	}
	index := 0
	if head == "powershell" || head == "pwsh" {
		index = 1
	flags:
		for index < len(toks) {
			switch flag := pytext.Lower(toks[index]); flag {
			case "-command", "-encodedcommand":
				return "inline_interpreter", false
			case "-file":
				index++
				break flags
			case "-executionpolicy", "-windowstyle":
				index += 2
			case "-nologo", "-noninteractive", "-noprofile":
				index++
			default:
				break flags
			}
		}
	} else if interpreters[head] || pythonVersionRE.MatchString(head) {
		isShell := shells[head]
		var valueOpts map[string]bool
		switch {
		case isShell:
			valueOpts = pytext.Set("-o")
		case strings.HasPrefix(head, "python"):
			valueOpts = pytext.Set("-w", "-x")
		case head == "perl" || head == "ruby":
			valueOpts = pytext.Set("-i")
		}
		for index = 1; index < len(toks) && strings.HasPrefix(toks[index], "-"); {
			token := pytext.Lower(toks[index])
			base, _, attached := strings.Cut(token, "=")
			if base == "-c" || (!isShell && (base == "-e" || base == "--eval")) {
				return "inline_interpreter", false
			}
			if isShell && base == "-s" {
				// `sh -s` runs the program from stdin; the path is only $0, not the script.
				return "dynamic_or_compound", false
			}
			if head == "node" && nodePreload[base] {
				return "dynamic_or_compound", false
			}
			if !attached && valueOpts[base] {
				index += 2
			} else {
				index++
			}
		}
	}
	if index >= len(toks) {
		return "unresolved_external", false
	}
	candidate := projectDirRE.ReplaceAllString(toks[index], "")
	if strings.ContainsAny(candidate, "$`|;&><") {
		return "dynamic_or_compound", false
	}
	normalized := path.Clean(strings.TrimPrefix(candidate, "./"))
	if strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "~") || drivePathRE.MatchString(candidate) ||
		normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "external_path", false
	}
	if art := p.ByRel[normalized]; art != nil && art.Text != nil {
		return "package_local:" + normalized, true
	}
	return "unresolved_external", false
}

// hookSource is _hook_source: the hooks value, whether the key exists, and its source line.
func hookSource(a *parse.Artifact) (any, bool, int) {
	if configKinds[a.Kind] {
		if cfg, ok := a.Config.(map[string]any); ok {
			v, present := cfg["hooks"]
			return v, present, 1
		}
	}
	if a.Kind == "skill_manifest" && a.Frontmatter != nil {
		v, present := a.Frontmatter["hooks"]
		line, ok := a.FrontmatterKeyLines["hooks"]
		if !ok {
			line = 1
		}
		return v, present, line
	}
	return nil, false, 1
}

func stringList(v any) ([]string, bool) {
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(items))
	for i, item := range items {
		if out[i], ok = item.(string); !ok {
			return nil, false
		}
	}
	return out, true
}

// hookFindings is _hook_findings, SXV-012.
func hookFindings(p *parse.Package, a *parse.Artifact) []findings.Finding {
	if configKinds[a.Kind] && !isAgentConfigLocation(a.Rel) {
		return nil
	}
	source, present, sourceLine := hookSource(a)
	if !present {
		return nil
	}
	hooks, ok := source.(map[string]any)
	if !ok {
		return []findings.Finding{incomplete(a.Rel, "hooks_not_object")}
	}
	var out []findings.Finding
	malformed := false
	report := func(event, matcher, command, hookType, resolution, message string) {
		out = append(out, findings.Finding{
			Vector: "SXV-012", Rule: "root-hook-autoexec", Severity: "medium",
			Path: a.Rel, Line: findings.Int(sourceLine), Message: message,
			Evidence: map[string]any{"hook_event": event, "matcher": matcher, "command": command,
				"hook_type": hookType, "resolution": resolution},
		})
	}
	for _, eventKey := range slices.Sorted(maps.Keys(hooks)) {
		groups, ok := hooks[eventKey].([]any)
		if !ok {
			malformed = true
			continue
		}
		event, known := canonicalEvent[pytext.Lower(eventKey)]
		if !known {
			malformed = true
			continue
		}
		for _, g := range groups {
			group, ok := g.(map[string]any)
			entries, isList := group["hooks"].([]any)
			if !ok || !isList {
				malformed = true
				continue
			}
			matcherValue, present := group["matcher"]
			if !present {
				matcherValue = "*"
			}
			matcher, ok := matcherValue.(string)
			if !ok {
				malformed = true
				matcher = "<invalid>"
			}
			for _, e := range entries {
				entry, ok := e.(map[string]any)
				if !ok {
					malformed = true
					continue
				}
				typeValue, present := entry["type"]
				if !present {
					typeValue = "command"
				}
				hookType, ok := typeValue.(string)
				if !ok {
					malformed = true
					continue
				}
				switch hookType {
				case "http":
					url, ok := entry["url"].(string)
					if low := pytext.Lower(url); !ok || !(strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://")) {
						malformed = true
						continue
					}
					report(event, matcher, url, "http", "remote_http",
						fmt.Sprintf("%s hook auto-executes a remote HTTP handler (%s)", event, url))
				case "mcp_tool":
					toolName := entry["tool_name"]
					if toolName == nil {
						server, _ := entry["server"].(string)
						tool, _ := entry["tool"].(string)
						if pytext.Strip(server) != "" && pytext.Strip(tool) != "" {
							toolName = pytext.Strip(server) + "." + pytext.Strip(tool)
						}
					}
					name, ok := toolName.(string)
					if !ok || pytext.Strip(name) == "" {
						malformed = true
						continue
					}
					name = pytext.Strip(name)
					report(event, matcher, name, "mcp_tool", "connected_mcp_tool",
						fmt.Sprintf("%s hook auto-executes connected MCP tool %s", event, name))
				case "prompt", "agent":
					prompt, ok := entry["prompt"].(string)
					if !ok || pytext.Strip(prompt) == "" {
						malformed = true
						continue
					}
					if dynamicPromptRE.MatchString(prompt) {
						report(event, matcher, prompt, hookType, "dynamic_semantic",
							fmt.Sprintf("%s hook auto-executes a dynamic %s handler (%s)", event, hookType, prompt))
					}
				case "command":
					command, ok := entry["command"].(string)
					if !ok || pytext.Strip(command) == "" {
						malformed = true
						continue
					}
					argsValue, present := entry["args"]
					if !present {
						argsValue = []any{}
					}
					args, ok := stringList(argsValue)
					if !ok {
						malformed = true
						continue
					}
					command = pytext.Strip(command)
					resolution, local := localCandidate(p, command, args)
					if local {
						continue
					}
					report(event, matcher, command, "command", resolution,
						fmt.Sprintf("%s hook auto-executes an unreviewable command (%s): %s", event, resolution, command))
				default:
					malformed = true
				}
			}
		}
	}
	if malformed {
		out = append(out, incomplete(a.Rel, "malformed_hook_entry"))
	}
	return out
}

// serverMaps is _server_maps: the candidate MCP server maps of a config artifact.
func serverMaps(a *parse.Artifact) []any {
	config, ok := a.Config.(map[string]any)
	if !configKinds[a.Kind] || !ok {
		return nil
	}
	var out []any
	for _, key := range []string{"mcpServers", "mcp_servers", "servers"} {
		if v, present := config[key]; present {
			out = append(out, v)
		}
	}
	if out == nil && a.Kind == "mcp_config" && a.ManifestKind == "mcp_servers" {
		out = append(out, a.Config)
	}
	return out
}

// packageSpecs is _package_specs: the package specifiers a runner invocation resolves, and
// whether a selector option dangles.
func packageSpecs(runner string, args []string) ([]string, bool) {
	selectors := pytext.Set("-p", "--package")
	if runner == "uvx" || runner == "pipx" {
		selectors = pytext.Set("--spec", "--from")
	}
	var specs, positionals []string
	for index := 0; index < len(args); {
		arg := args[index]
		if arg == "--" {
			positionals = append(positionals, args[index+1:]...)
			break
		}
		if selectors[arg] {
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "-") {
				return specs, true
			}
			specs = append(specs, args[index+1])
			index += 2
			continue
		}
		if name, value, attached := strings.Cut(arg, "="); attached && selectors[name] {
			if value == "" {
				return specs, true
			}
			specs = append(specs, value)
			index++
			continue
		}
		if optionsWithValue[runner][arg] {
			if index+1 >= len(args) {
				return specs, true
			}
			index += 2
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, arg)
		}
		index++
	}
	if len(specs) > 0 {
		return specs, false
	}
	if runner == "pipx" {
		// pipx fetches an ephemeral package only for `run`; other subcommands act on installed ones.
		if len(positionals) == 0 || positionals[0] != "run" {
			return nil, false
		}
		positionals = positionals[1:]
	}
	return positionals[:min(len(positionals), 1)], false
}

// mcpFindings is _mcp_findings, SXV-013.
func mcpFindings(a *parse.Artifact) []findings.Finding {
	if configKinds[a.Kind] && !isAgentConfigLocation(a.Rel) {
		return nil
	}
	var out []findings.Finding
	malformed := false
	for _, m := range serverMaps(a) {
		servers, ok := m.(map[string]any)
		if !ok {
			malformed = true
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(servers)) {
			server, ok := servers[name].(map[string]any)
			if !ok {
				malformed = true
				continue
			}
			commandValue := server["command"]
			argsValue, present := server["args"]
			if !present {
				argsValue = []any{}
			}
			stype, stypeIsString := server["type"].(string)
			if server["type"] != nil && !stypeIsString {
				malformed = true
				continue
			}
			if url, _ := server["url"].(string); commandValue == nil && (stype == "http" || stype == "sse" || pytext.Strip(url) != "") {
				continue
			}
			command, isString := commandValue.(string)
			args, isList := stringList(argsValue)
			if !isString || pytext.Strip(command) == "" || !isList {
				malformed = true
				continue
			}
			runner, runnerArgs := portableBasename(command), args
			if shells[runner] {
				for index, option := range args[:max(len(args)-1, 0)] {
					if strings.HasPrefix(option, "-") && strings.Contains(option[1:], "c") {
						wrapped, _ := tokens(args[index+1])
						if i := slices.IndexFunc(wrapped, isPunctuationRun); i >= 0 {
							wrapped = wrapped[:i]
						}
						if len(wrapped) > 0 {
							runner, runnerArgs = portableBasename(wrapped[0]), wrapped[1:]
						}
						break
					}
				}
			}
			if aliases, ok := runnerAliases[runner]; ok {
				// Skip leading global flags ("npm --prefix /tmp exec ...") to find the subcommand.
				sub := 0
				for sub < len(args) && strings.HasPrefix(args[sub], "-") {
					if globalValueOpts[args[sub]] {
						sub += 2
					} else {
						sub++
					}
				}
				if sub < len(args) && aliases[args[sub]] {
					runner, runnerArgs = "npx", args[sub+1:]
				}
			}
			if !runners[runner] {
				continue
			}
			specs, badArgs := packageSpecs(runner, runnerArgs)
			if badArgs {
				malformed = true
				continue
			}
			for _, spec := range specs {
				if pep508.IsExactPin(runner, spec) {
					continue
				}
				out = append(out, findings.Finding{
					Vector: "SXV-013", Rule: "floating-mcp-package", Severity: "low",
					Path: a.Rel, Line: findings.Int(1),
					Message: fmt.Sprintf("auto-start server %s resolves floating package %s", name, spec),
					Evidence: map[string]any{"server_name": name, "command": command, "specifier": spec,
						"pin_state": "floating_or_unpinned", "args": argsValue},
				})
			}
		}
	}
	if malformed {
		out = append(out, incomplete(a.Rel, "malformed_mcp_server"))
	}
	return out
}

// Check is hooks.check.
func Check(p *parse.Package) []findings.Finding {
	var out []findings.Finding
	for _, a := range p.Artifacts {
		out = append(out, instructionFindings(a)...)
		out = append(out, hookFindings(p, a)...)
		out = append(out, mcpFindings(a)...)
	}
	return findings.CapFindings(out)
}
