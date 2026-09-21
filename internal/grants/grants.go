// Package grants classifies dynamic (SXV-003) and over-broad (SXV-004) execution and network
// pre-grants from the parsed allowed/disallowed-tools (Python checks/grants.py).
package grants

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

var (
	ExecutionTools = pytext.Set("Bash", "Shell", "Terminal", "Execute")
	NetworkTools   = pytext.Set("WebFetch", "WebSearch")
)

var (
	variableRE = regexp.MustCompile(`\$(?i:env):[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|` +
		`\$\{(?i:env):[A-Za-z_][A-Za-z0-9_]*\}|\$\{!?[A-Za-z_][A-Za-z0-9_]*[^}\n]*\}|` +
		`\$[A-Za-z_][A-Za-z0-9_]*|\$\p{Nd}+|\$[@*]`)
	versionSuffixRE   = regexp.MustCompile(`\p{Nd}+(?:\.\p{Nd}+)*$`)
	envAssignmentRE   = regexp.MustCompile(`^[A-Za-z_][\pL\pN_]*=`)
	wrapperArgumentRE = regexp.MustCompile(`^-|=|^\p{Nd}+(?:\.\p{Nd}+)?[smhd]?$`)
)

var (
	broadCommands = pytext.Set("bash", "bun", "chmod", "chown", "cmd", "curl", "dash", "deno", "env", "eval", "git",
		"fish", "ksh", "nc", "ncat", "node", "npx", "osascript", "perl", "php",
		"pip", "pip3", "powershell", "pwsh", "py", "python", "python3", "ruby",
		"scp", "sftp", "sh", "socat", "ssh", "su", "sudo", "wget", "xargs", "zsh")
	installers = [][]string{
		{"apk", "add"}, {"apt", "install"}, {"apt-get", "install"}, {"brew", "install"},
		{"cargo", "install"}, {"dotnet", "tool", "install"},
		{"dotnet", "tool", "restore"}, {"dotnet", "tool", "update"}, {"gem", "install"},
		{"go", "install"}, {"npm", "ci"}, {"npm", "i"}, {"npm", "install"},
		{"pip", "install"},
		{"pip3", "install"}, {"pnpm", "add"}, {"uv", "add"},
		{"uv", "pip", "install"},
		{"yarn", "add"},
	}
	installerCommands     = map[string]bool{}
	installerValueOptions = map[string]map[string]bool{
		"cargo": pytext.Set("--color", "--config", "--target-dir"),
		"pip":   pytext.Set("--proxy", "--python"), "pip3": pytext.Set("--proxy", "--python"),
	}
	interpreters = pytext.Set("bash", "bun", "dash", "deno", "fish", "ksh", "node", "osascript", "perl", "php",
		"cmd", "powershell", "pwsh", "py", "python", "python3", "ruby", "sh", "zsh")
	evalFlags = map[string]map[string]bool{
		"bash": pytext.Set("-c"), "dash": pytext.Set("-c"), "fish": pytext.Set("-c"), "ksh": pytext.Set("-c"),
		"sh": pytext.Set("-c"), "zsh": pytext.Set("-c"),
		"cmd":        pytext.Set("/c", "/k"),
		"powershell": pytext.Set("-command", "-enc", "-encodedcommand"),
		"pwsh":       pytext.Set("-command", "-enc", "-encodedcommand"),
		"py":         pytext.Set("-c"), "python": pytext.Set("-c"), "python3": pytext.Set("-c"),
		"bun":  pytext.Set("-e", "--eval", "-p", "--print"),
		"node": pytext.Set("-e", "--eval", "-p", "--print"),
		"perl": pytext.Set("-e"), "php": pytext.Set("-r"), "ruby": pytext.Set("-e"), "osascript": pytext.Set("-e"),
	}
	posixShells = pytext.Set("bash", "dash", "fish", "ksh", "sh", "zsh")
	pythons     = pytext.Set("py", "python", "python3")
	wrappers    = pytext.Set("command", "doas", "env", "exec", "ionice", "nice", "nohup", "setsid", "stdbuf",
		"sudo", "time", "timeout", "xargs")
	wrapperValueOptions = map[string]map[string]bool{
		"env":     pytext.Set("-C", "--chdir", "-u", "--unset"),
		"sudo":    pytext.Set("-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt"),
		"stdbuf":  pytext.Set("-i", "--input", "-o", "--output", "-e", "--error"),
		"timeout": pytext.Set("-s", "--signal", "-k", "--kill-after"),
	}
	privilegeCommands = pytext.Set("su", "sudo")
	networkCommands   = pytext.Set("aria2c", "curl", "http", "httpie", "nc", "ncat", "node", "npx", "perl", "python",
		"python3", "ruby", "scp", "sftp", "socat", "ssh", "wget", "git", "powershell", "pwsh", "ftp", "telnet")
	networkOnlyCommands = pytext.Set("aria2c", "curl", "http", "httpie", "scp", "sftp", "wget")
	remoteCommands      = pytext.Set("ftp", "nc", "ncat", "socat", "ssh", "telnet")
	gitRemoteSubcommand = pytext.Set("clone", "fetch", "pull", "push", "remote", "submodule")
	nonExecutionCommand = pytext.Set(
		"alias", "bg", "break", "cd", "chmod", "chown", "command", "continue", "declare", "dirs",
		"disown", "echo", "exit", "export", "false", "fg", "getopts", "hash", "help",
		"history", "jobs", "local", "logout", "mapfile", "popd", "printf", "pushd", "pwd",
		"read", "readarray", "readonly", "return", "set", "shift", "shopt", "suspend",
		"test", "times", "true", "type", "typeset", "ulimit", "umask", "unalias", "unset",
		"wait")
)

func init() {
	for _, action := range installers {
		installerCommands[action[0]] = true
	}
	maps.Copy(networkCommands, installerCommands)
	maps.Copy(remoteCommands, networkOnlyCommands)
	maps.Copy(nonExecutionCommand, networkOnlyCommands)
}

// launcherSuffixes are the suffixes _basename strips.
var launcherSuffixes = []string{".exe", ".cmd", ".bat", ".com", ".ps1"}

// basename is _basename: the token unquoted, then its command basename.
func basename(token string) string {
	if len(token) >= 2 && token[0] == token[len(token)-1] && (token[0] == '\'' || token[0] == '"') {
		token = token[1 : len(token)-1]
	}
	return pytext.CommandBasename(strings.TrimRight(token, `/\`), launcherSuffixes...)
}

// normalize drops a version suffix (python3.12 -> python) unless nothing would be left.
func normalize(head string) string {
	if n := versionSuffixRE.ReplaceAllString(head, ""); n != "" {
		return n
	}
	return head
}

// commandTokens is _command_tokens; a nil pattern yields ("", nil) for Python (None, []).
func commandTokens(pattern *string) (string, []string) {
	if pattern == nil {
		return "", nil
	}
	command := pytext.Strip(strings.TrimSuffix(pytext.Strip(*pattern), ":*"))
	tokens, err := pytext.ShlexTokens(command, false, ";&|\n", " \t\r")
	if err != nil { // unclosed quote
		tokens = pytext.Fields(command)
	}
	return command, tokens
}

// effectiveTokens drops leading NAME=value tokens and wrappers with their options; privileged
// reports sudo/doas.
func effectiveTokens(tokens []string) (remaining []string, privileged bool) {
	remaining = tokens
	for len(remaining) > 0 {
		if envAssignmentRE.MatchString(remaining[0]) {
			remaining = remaining[1:]
			continue
		}
		head := basename(remaining[0])
		if !wrappers[head] || head == "command" && len(remaining) > 1 && (remaining[1] == "-v" || remaining[1] == "-V") {
			break
		}
		privileged = privileged || head == "sudo" || head == "doas"
		remaining = remaining[1:]
		for len(remaining) > 0 {
			if option := remaining[0]; wrapperValueOptions[head][option] {
				remaining = remaining[min(2, len(remaining)):]
			} else if wrapperArgumentRE.MatchString(option) {
				remaining = remaining[1:]
			} else {
				break
			}
		}
	}
	return remaining, privileged
}

// segments splits on tokens made only of ;&| and newline, dropping empty segments.
func segments(tokens []string) [][]string {
	var segs [][]string
	var cur []string
	for _, t := range tokens {
		if t != "" && strings.Trim(t, ";&|\n") == "" {
			if len(cur) > 0 {
				segs, cur = append(segs, cur), nil
			}
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		segs = append(segs, cur)
	}
	return segs
}

func segmentBreadth(tokens []string) string {
	effective, privileged := effectiveTokens(tokens)
	if privileged {
		return "privilege_escalation"
	}
	if len(effective) == 0 {
		if len(tokens) > 0 && wrappers[basename(tokens[0])] {
			return "interpreter_or_downloader"
		}
		effective = tokens
	}
	normalized := normalize(basename(effective[0]))
	if privilegeCommands[normalized] {
		return "privilege_escalation"
	}
	if pythons[normalized] && len(effective) >= 3 && pytext.Lower(effective[1]) == "-m" {
		module := pytext.Lower(effective[2])
		if module == "ensurepip" || module == "pip" && (len(effective) == 3 || installerSubcommand(effective[2:], "pip")) {
			return "package_installer"
		}
		if module == "http.server" {
			return "interpreter_or_downloader"
		}
	}
	if installerSubcommand(effective, normalized) || len(effective) == 1 && installerCommands[normalized] {
		return "package_installer"
	}
	_, _, evalOK := evalOption(effective, normalized)
	if normalized == "eval" || interpreters[normalized] && evalOK || remoteCommands[normalized] ||
		normalized == "git" && (len(effective) == 1 || gitRemoteSubcommand[pytext.Lower(effective[1])]) ||
		normalized == "npx" || len(effective) == 1 && broadCommands[normalized] {
		return "interpreter_or_downloader"
	}
	return ""
}

// installerSubcommand skips the installer's leading options and matches a mutating action.
func installerSubcommand(effective []string, normalized string) bool {
	if !installerCommands[normalized] {
		return false
	}
	index := 1
	for index < len(effective) && strings.HasPrefix(effective[index], "-") {
		option, _, _ := strings.Cut(effective[index], "=")
		index++
		if installerValueOptions[normalized][option] && index < len(effective) {
			index++
		}
	}
	tail := effective[index:]
	for _, action := range installers {
		if action[0] != normalized || len(tail) < len(action)-1 {
			continue
		}
		if slices.EqualFunc(action[1:], tail[:len(action)-1], func(a, t string) bool { return a == pytext.Lower(t) }) {
			return true
		}
	}
	return false
}

func breadth(tool string, pattern *string, command string, tokens []string) string {
	if NetworkTools[tool] {
		if pattern == nil {
			return "unrestricted_network"
		}
		switch pytext.Lower(pytext.Strip(*pattern)) {
		case "*", "**", ":*", "domain:*":
			return "unrestricted_network"
		}
		return ""
	}
	if !ExecutionTools[tool] {
		return ""
	}
	if pattern == nil || command == "" || command == "*" || command == "**" {
		return "wildcard_all_commands"
	}
	classes := map[string]bool{}
	for _, seg := range segments(tokens) {
		classes[segmentBreadth(seg)] = true
	}
	for _, c := range []string{"privilege_escalation", "package_installer", "interpreter_or_downloader"} {
		if classes[c] {
			return c
		}
	}
	return ""
}

func reachesNetwork(tool string, pattern *string, tokens []string) bool {
	if NetworkTools[tool] {
		return true
	}
	if !ExecutionTools[tool] {
		return false
	}
	if pattern == nil || len(tokens) == 0 || tokens[0] == "" || tokens[0] == "*" || tokens[0] == "**" {
		return true
	}
	for _, seg := range segments(tokens) {
		if effective, _ := effectiveTokens(seg); len(effective) > 0 && networkCommands[normalize(basename(effective[0]))] {
			return true
		}
	}
	return false
}

// evalOption finds the interpreter's inline-code option; attached is a payload glued to the
// flag ("" for none) and ok false means no eval option before the first operand.
func evalOption(effective []string, interpreter string) (index int, attached string, ok bool) {
	accepted := evalFlags[interpreter]
	for index = 1; index < len(effective); index++ {
		token, lowered := effective[index], effective[index]
		if interpreter == "cmd" || interpreter == "powershell" || interpreter == "pwsh" {
			lowered = pytext.Lower(token)
		}
		if lowered == "--" {
			return 0, "", false
		}
		if accepted[lowered] {
			return index, "", true
		}
		if (posixShells[interpreter] || pythons[interpreter]) && strings.HasPrefix(token, "-") {
			if cluster := token[1:]; strings.Contains(cluster, "c") {
				return index, cluster[strings.IndexByte(cluster, 'c')+1:], true
			}
		}
		for _, prefix := range []string{"-c", "-e", "/c", "/k"} {
			if accepted[prefix] && strings.HasPrefix(lowered, prefix) {
				if r := []rune(token); len(r) > len(prefix) {
					return index, string(r[len(prefix):]), true
				}
			}
		}
		if !strings.HasPrefix(token, "-") && !strings.HasPrefix(token, "/") {
			return 0, "", false
		}
	}
	return 0, "", false
}

// expandableVariable is the first shell variable reference the shell would expand.
func expandableVariable(token string) (string, bool) {
	for _, m := range variableRE.FindAllStringIndex(token, -1) {
		if shellExpandsAt(token, m[0]) {
			return token[m[0]:m[1]], true
		}
	}
	return "", false
}

// shellExpandsAt reports whether position target is outside single quotes and not escaped.
func shellExpandsAt(token string, target int) bool {
	single, double, escaped := false, false, false
	for i := 0; i < target; i++ {
		switch ch := token[i]; {
		case escaped:
			escaped = false
		case ch == '\\' && !single:
			escaped = true
		case ch == '\'' && !double:
			single = !single
		case ch == '"' && !single:
			double = !double
		}
	}
	return !single && !escaped
}

// dynamicCommandTarget is a substitution or variable inside an eval/-c payload.
func dynamicCommandTarget(tokens []string) (string, bool) {
	for _, seg := range segments(tokens) {
		effective, _ := effectiveTokens(seg)
		if len(effective) == 0 {
			continue
		}
		head := normalize(basename(effective[0]))
		if head == "eval" {
			payload := strings.Join(effective[1:], " ")
			if s, ok := expandableSubstitution(payload); ok {
				return s, true
			}
			return expandableVariable(payload)
		}
		if !interpreters[head] {
			continue
		}
		index, payload, ok := evalOption(effective, head)
		if !ok {
			continue
		}
		if payload == "" && index+1 < len(effective) {
			payload = strings.Join(effective[index+1:], " ")
		}
		if s, ok := expandableSubstitution(payload); ok {
			return s, true
		}
		if v, ok := expandableVariable(payload); ok {
			return v, true
		}
	}
	return "", false
}

// commandSubstitutionHead is a command substitution that starts inside the command head.
func commandSubstitutionHead(tokens []string) (string, bool) {
	effective, _ := effectiveTokens(tokens)
	if len(effective) == 0 {
		return "", false
	}
	joined := strings.Join(effective, " ")
	sub, ok := expandableSubstitution(joined)
	if !ok || strings.Index(joined, sub) >= len(effective[0]) {
		return "", false
	}
	return sub, true
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func blanketGrant(g parse.Grant) bool {
	switch p := pytext.Lower(pytext.Strip(deref(g.Pattern))); p {
	case "", "*", "**", ":*":
		return true
	case "domain:*":
		return NetworkTools[g.Tool]
	}
	return false
}

func denialCovers(denial, grant parse.Grant) bool {
	if denial.Tool != grant.Tool || denial.Allowed || !denial.Parsed {
		return false
	}
	denied, allowed := pytext.Strip(deref(denial.Pattern)), pytext.Strip(deref(grant.Pattern))
	if blanketGrant(denial) || denied == allowed {
		return true
	}
	if strings.HasSuffix(denied, ":*") {
		prefix, candidate := pytext.RStrip(strings.TrimSuffix(denied, ":*")), allowed
		if strings.HasSuffix(allowed, ":*") {
			candidate = pytext.RStrip(strings.TrimSuffix(allowed, ":*"))
		}
		return candidate == prefix || strings.HasPrefix(candidate, prefix+" ")
	}
	return false
}

func covered(denials []parse.Grant, grant parse.Grant) bool {
	return slices.ContainsFunc(denials, func(d parse.Grant) bool { return denialCovers(d, grant) })
}

// Effective is effective_grants: allowed, parsed grants not closed by a matching denial.
func Effective(grants []parse.Grant) []parse.Grant {
	denials, out := slices.DeleteFunc(slices.Clone(grants), func(g parse.Grant) bool { return g.Allowed }), []parse.Grant{}
	for _, g := range grants {
		if g.Allowed && g.Parsed && !covered(denials, g) {
			out = append(out, g)
		}
	}
	return out
}

// Declared is declared_capabilities: the axes the effective allowed grants materially declare.
func Declared(grants []parse.Grant) map[string]bool {
	execution, network := false, false
	for _, g := range Effective(grants) {
		command, tokens := commandTokens(g.Pattern)
		network = network || reachesNetwork(g.Tool, g.Pattern, tokens)
		if !ExecutionTools[g.Tool] {
			continue
		}
		execution = execution || g.Pattern == nil || command == "" || command == "*" || command == "**"
		for _, seg := range segments(tokens) {
			effective, _ := effectiveTokens(seg)
			if len(effective) == 0 {
				effective = seg
			}
			head := normalize(basename(effective[0]))
			execution = execution || head != "" && !nonExecutionCommand[head]
		}
	}
	caps := map[string]bool{}
	if execution {
		caps["execution"] = true
	}
	if network {
		caps["network"] = true
	}
	return caps
}

// Denied is denied_capabilities: axes whose tool is denied outright; a forbidden command or
// URL does not deny its axis.
func Denied(grants []parse.Grant) map[string]bool {
	out := map[string]bool{}
	for _, g := range grants {
		if g.Allowed || !g.Parsed || !blanketGrant(g) {
			continue
		}
		if ExecutionTools[g.Tool] {
			out["execution"] = true
		}
		if NetworkTools[g.Tool] {
			out["network"] = true
		}
	}
	return out
}

// expandableSubstitution is the first $( ... ) or ` ... ` outside single quotes and escapes.
func expandableSubstitution(value string) (string, bool) {
	single, double, escaped := false, false, false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch {
		case escaped:
			escaped = false
		case ch == '\\' && !single:
			escaped = true
		case ch == '\'' && !double:
			single = !single
		case ch == '"' && !single:
			double = !double
		case single:
		case strings.HasPrefix(value[i:], "$("):
			depth, end := 1, i+2
			for end < len(value) && depth > 0 {
				if value[end] == '(' && value[end-1] != '\\' {
					depth++
				} else if value[end] == ')' && value[end-1] != '\\' {
					depth--
				}
				end++
			}
			if depth == 0 {
				return value[i:end], true
			}
		case ch == '`':
			for end := i + 1; end < len(value); end++ {
				if value[end] == '`' && value[end-1] != '\\' {
					return value[i : end+1], true
				}
			}
		}
	}
	return "", false
}

// Check is grants.check: SXV-003 then SXV-004 per effective execution/network grant of every
// skill manifest (by rel), capped per file.
func Check(p *parse.Package) []findings.Finding {
	var manifests []*parse.Artifact
	for _, a := range p.Artifacts {
		if a.Kind == "skill_manifest" {
			manifests = append(manifests, a)
		}
	}
	slices.SortStableFunc(manifests, func(a, b *parse.Artifact) int { return strings.Compare(a.Rel, b.Rel) })
	fs := []findings.Finding{}
	for _, a := range manifests {
		line := cmp.Or(a.FrontmatterKeyLines["allowed-tools"], 1)
		for _, g := range Effective(a.Grants) {
			if g.Tool == "" {
				continue
			}
			command, tokens := commandTokens(g.Pattern)
			if ExecutionTools[g.Tool] && deref(g.Pattern) != "" {
				value, ok := "", false
				for _, seg := range segments(tokens) {
					if value, ok = commandSubstitutionHead(seg); ok {
						break
					}
					if head, _ := effectiveTokens(seg); len(head) > 0 {
						if value, ok = expandableVariable(head[0]); ok {
							break
						}
					}
				}
				if !ok {
					value, ok = dynamicCommandTarget(tokens)
				}
				if ok {
					fs = append(fs, findings.Finding{
						Vector: "SXV-003", Rule: "grant-variable-substitution", Severity: "high",
						Path: a.Rel, Line: findings.Int(line),
						Message:  fmt.Sprintf("execution pre-grant `%s` has a dynamic command target (%s)", g.Raw, value),
						Evidence: map[string]any{"grant_text": g.Raw, "variable_name": value, "line": line},
					})
				}
			}
			if b := breadth(g.Tool, g.Pattern, command, tokens); b != "" {
				severity := "high"
				if b == "wildcard_all_commands" || b == "privilege_escalation" {
					severity = "critical"
				}
				fs = append(fs, findings.Finding{
					Vector: "SXV-004", Rule: "grant-over-broad", Severity: severity,
					Path: a.Rel, Line: findings.Int(line),
					Message: fmt.Sprintf("pre-granted tool `%s` is over-broad (%s)", g.Raw, b),
					Evidence: map[string]any{"grant_text": g.Raw, "breadth_class": b, "line": line,
						"reaches_network": reachesNetwork(g.Tool, g.Pattern, tokens)},
				})
			}
		}
	}
	return findings.CapFindings(fs)
}
