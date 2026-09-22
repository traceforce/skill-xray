// Package codelane selects the executable code every code engine analyses (Python
// checks/code_lane.py): real scripts, lifted instruction fences with their source line
// numbers preserved, fail-visible notes for what could not be analysed, and the
// installer-shaped fetch idiom shared with the OpenGrep bridge and the instruction lane.
package codelane

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pyast"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// Unit is one piece of code handed to the engines; Dialect "" is Python None.
type Unit struct{ Rel, Kind, Text, Origin, Dialect string }

// scriptKinds is _SCRIPT_KINDS: the artifact kinds that become code units.
var scriptKinds = map[string]bool{"script_shell": true, "script_python": true,
	"script_javascript": true, "script_typescript": true}

var fenceLang = map[string][2]string{
	"bash": {"shell", "bash"}, "sh": {"shell", "sh"}, "shell": {"shell", "sh"}, "zsh": {"shell", "zsh"},
	"console": {"shell", "sh"}, "shell-session": {"shell", "sh"}, "shellsession": {"shell", "sh"},
	"shell-script": {"shell", "sh"}, "sh-session": {"shell", "sh"}, "bash-session": {"shell", "bash"},
	"ksh": {"shell", "ksh"}, "dash": {"shell", "dash"}, "fish": {"shell", "fish"},
	"powershell": {"shell", "powershell"}, "pwsh": {"shell", "powershell"}, "ps1": {"shell", "powershell"},
	"bat": {"shell", "cmd"}, "cmd": {"shell", "cmd"}, "batch": {"shell", "cmd"},
	"python": {"python", "python"}, "py": {"python", "python"}, "python3": {"python", "python"},
	"python2": {"python", "python"}, "ipython": {"python", "python"},
}

// SupportedShell is _SUPPORTED_SHELL_DIALECTS: the shell dialects the bash engine accepts.
var SupportedShell = map[string]bool{"bash": true, "sh": true, "dash": true}

const (
	sp    = pytext.Space
	nsp   = pytext.NotSpace
	nonWd = `[^\pL\pN_]`
)

var (
	consolePromptRE = regexp.MustCompile(`^` + sp + `{0,3}\$` + sp + `+`)
	infoTokenRE     = regexp.MustCompile(`[A-Za-z0-9_+-]+`)
	// ^#!.*\b(bash|sh|dash|ksh|zsh|fish)\b: the char .* stops at is the left boundary.
	shebangRE = regexp.MustCompile(`^#!(?:.*` + nonWd + `)?(bash|sh|dash|ksh|zsh|fish)(?:` + nonWd + `|$)`)

	installerURLRE = regexp.MustCompile(`(?i)^https://([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)` +
		`(?::\p{Nd}+)?(/[^` + pytext.SpaceBody + `'"|;&` + "`" + `)<>]*)?$`)
	installerPathRE = regexp.MustCompile(`(?i)(?:^|/)(?:install(?:er)?(?:\.(?:sh|bash|py))?|setup(?:\.sh)?|get(?:-[\pL\pN_-]+)?(?:\.sh)?|` +
		`bootstrap(?:\.sh)?|latest|download(?:/[\pL\pN_.-]+)*|releases?(?:/[\pL\pN_.-]+)*)$`)
	// DropHostRE is _DROP_HOST_RE (paste, tunnel, shortener and gist hosts); instruction searches it too.
	DropHostRE = regexp.MustCompile(`(?i)(?:^|\.)(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.[\pL\pN_]+|rentry\.co|transfer\.sh|` +
		`0x0\.st|file\.io|anonfiles\.com|gofile\.io|mega\.nz|ngrok(?:-free)?\.(?:io|app|dev)|` +
		`trycloudflare\.com|loca\.lt|serveo\.net|localhost\.run|discordapp\.(?:com|net)|` +
		`ipfs\.io|dweb\.link|bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|` +
		`gist\.githubusercontent\.com|gist\.github\.com|github\.io|termbin\.com|dpaste\.[\pL\pN_]+|` +
		`glot\.io|ix\.io|sprunge\.us|bashupload\.com|temp\.sh|webhook\.site|requestbin\.net|` +
		`oast\.fun|interact\.sh|tmpfiles\.org|catbox\.moe|uguu\.se|envs\.sh|oshi\.at|paste\.rs|` +
		`controlc\.com|justpaste\.it|srv\.us|bore\.pub|pastes\.io|filebin\.net)$`)
	// (?<![\w-]) ... (?![\w-]) as consuming one-char neighbours; only existence is asked.
	insecureFlagRE = regexp.MustCompile(`(?:^|[^\pL\pN_-])(?:--(?:proxy-|doh-)?insecure|--no-check-certificate|` +
		`--check-certificate[= ](?:false|no|off|0)|--verify[= ](?:no|false|0)|--config(?:=` + nsp + `+)?|` +
		`-[A-Za-z]*[kK][A-Za-z]*)(?:[^\pL\pN_-]|$)`)
	commandSplitRE = regexp.MustCompile(`\|\||&&|;`)
	// [;&|][^;&|\n]*?\b(...)\b: the separator itself is a boundary, so the run is optional.
	laterFetchRE = regexp.MustCompile(`[;&|](?:[^;&|\n]*?[^\pL\pN_;&|\n])?(?:curl|wget|aria2c|https?|httpie|fetch)(?:` + nonWd + `|$)`)
	// \bINTERP\b[^|;&\n]{0,40}?\s-[A-Za-z]*[ce]\b: after `python[0-9.]*` the boundary needs a
	// non-word next char when the name ends in a digit and a word next char when it ends in a
	// dot, so the two cases are spelled out; the other names end in a letter.
	inlineCodeConsumerRE = regexp.MustCompile(`(?:^|` + nonWd + `)python(?:(?:[0-9.]*[0-9])?` + consumerGap + `|[0-9.]*\.[\pL\pN_][^|;&\n]{0,39}` + sp + `)-[A-Za-z]*[ce](?:` + nonWd + `|$)|` +
		`(?:^|` + nonWd + `)(?:perl|ruby|node|php)` + consumerGap + `-[A-Za-z]*[ce](?:` + nonWd + `|$)|` +
		`(?:^|` + nonWd + `)(?:sh|bash|zsh|dash|ksh)` + consumerGap + `-[A-Za-z]*c(?:` + nonWd + `|$)`)
	bareHostRE = regexp.MustCompile(`(?i)^(?:(?:[a-z0-9-]+\.)+[a-z]{2,}|\p{Nd}{1,3}(?:\.\p{Nd}{1,3}){3}|localhost|\[[0-9a-f:.]+\])` +
		`(?::\p{Nd}+)?(?:/` + nsp + `*)?$`)
	anyURLRE          = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^` + pytext.SpaceBody + `'"|;&` + "`" + `)<>]+`)
	substitutionRE    = regexp.MustCompile("[`$]|[<>]\\(")
	processSubFetchRE = regexp.MustCompile(`(?s)^` + sp + `*(?:sudo` + sp + `+)?(?:sh|bash|zsh|dash|ksh)` + sp + `+<\((.*)\)` + sp + `*$`)
	placeholderHostRE = regexp.MustCompile(`(?i)(?:^|\.)example\.(?:com|net|org)$|\.(?:example|test|invalid|localhost|local)$|^localhost$`)
	ipHostRE          = regexp.MustCompile(`^[\p{Nd}.]+$`)
)

// consumerGap is `\b[^|;&\n]{0,40}?\s` after a name ending in a word char: either the
// whitespace comes next or a non-word run char does, followed by at most 39 more.
const consumerGap = `(?:` + sp + `|[^|;&\n\pL\pN_][^|;&\n]{0,39}` + sp + `)`

func fenceLangOf(info string) (language, dialect string) {
	parts := pytext.Fields(info)
	if len(parts) == 0 {
		return "", ""
	}
	l := fenceLang[pytext.Lower(infoTokenRE.FindString(parts[0]))]
	return l[0], l[1]
}

func shellDialect(rel, text string) string {
	first, _, _ := strings.Cut(text, "\n")
	if m := shebangRE.FindStringSubmatch(pytext.Lower(first)); m != nil {
		return m[1]
	}
	if i := strings.LastIndexByte(rel, '.'); i >= 0 {
		switch suffix := pytext.Lower(rel[i+1:]); suffix {
		case "bash", "zsh", "sh":
			return suffix
		}
	}
	return "sh"
}

func pythonIsModule(source string) bool {
	if utf8.RuneCountInString(source) > parse.MaxPyChars {
		return true
	}
	_, err := pyast.Parse(source)
	return err == nil
}

type block struct {
	line  int
	lines []string
}

// padBlocks places each block's body so that line k lands on source line marker+1+k.
func padBlocks(blocks []block) string {
	var lines []string
	for _, b := range blocks {
		for len(lines) < b.line {
			lines = append(lines, "")
		}
		lines = append(lines, b.lines...)
	}
	return strings.Join(lines, "\n")
}

// liftFences combines the supported fences of one document per language, first-seen order,
// without changing their line numbers; Rel is left for the caller.
func liftFences(fences []parse.Fence) []Unit {
	var order []string
	kept := map[string][]block{}
	for _, f := range fences {
		language, dialect := fenceLangOf(f.Info)
		if language == "" || language == "shell" && !SupportedShell[dialect] {
			continue
		}
		lines := strings.Split(f.Content, "\n")
		if n := len(lines); lines[n-1] == "" {
			lines = lines[:n-1]
		}
		if language == "shell" {
			for i, line := range lines {
				lines[i] = consolePromptRE.ReplaceAllStringFunc(line, func(m string) string {
					return strings.Repeat(" ", utf8.RuneCountInString(m))
				})
			}
		} else if !pythonIsModule(strings.Join(lines, "\n")) {
			continue
		}
		if kept[language] == nil {
			order = append(order, language)
		}
		kept[language] = append(kept[language], block{f.Line, lines})
	}
	var out []Unit
	for _, language := range order {
		blocks, kind, dialect := kept[language], "script_"+language, language
		if language == "shell" {
			dialect = "bash"
		}
		if combined := padBlocks(blocks); language == "shell" || pythonIsModule(combined) {
			out = append(out, Unit{Kind: kind, Text: combined, Origin: "fence", Dialect: dialect})
			continue
		}
		for _, b := range blocks {
			out = append(out, Unit{Kind: kind, Text: padBlocks([]block{b}), Origin: "fence", Dialect: language})
		}
	}
	return out
}

func unsupportedShell(rel, dialect, origin string, line *int) findings.Finding {
	return findings.Finding{Rule: "analysis-incomplete", Severity: "high", Path: rel, Line: line,
		Message:  "OpenGrep does not support executable " + dialect + " code.",
		Evidence: map[string]any{"reason": "unsupported_language", "language": dialect, "origin": origin}}
}

// Build is build_code_lane: real scripts first in package order, then each document's lifted
// fences, with a high analysis-incomplete note for every unit that could not be analysed.
func Build(p *parse.Package) ([]Unit, []findings.Finding) {
	units, notes := []Unit{}, []findings.Finding{}
	for _, a := range p.Artifacts {
		if a.Text == nil || !scriptKinds[a.Kind] {
			continue
		}
		dialect := ""
		if a.Kind == "script_shell" {
			if dialect = shellDialect(a.Rel, *a.Text); !SupportedShell[dialect] {
				notes = append(notes, unsupportedShell(a.Rel, dialect, "file", nil))
				continue
			}
		}
		units = append(units, Unit{a.Rel, a.Kind, *a.Text, "file", dialect})
	}
	for _, a := range p.Artifacts {
		if a.Markdown == nil || len(a.Markdown.Fences) == 0 ||
			a.Kind != "skill_manifest" && a.Kind != "instruction" && a.Kind != "agent_identity" {
			continue
		}
		for _, f := range a.Markdown.Fences {
			language, dialect := fenceLangOf(f.Info)
			if language == "shell" && !SupportedShell[dialect] {
				notes = append(notes, unsupportedShell(a.Rel, dialect, "fence", findings.Int(f.Line+1)))
			}
			if language == "python" && !pythonIsModule(f.Content) {
				notes = append(notes, findings.Finding{Rule: "analysis-incomplete", Severity: "high", Path: a.Rel,
					Line:     findings.Int(f.Line + 1),
					Message:  "Python fence could not be parsed, so it was not analysed.",
					Evidence: map[string]any{"language": pytext.Fields(f.Info)[0], "origin": "fence"}})
			}
		}
		for _, u := range liftFences(a.Markdown.Fences) {
			u.Rel = a.Rel
			units = append(units, u)
		}
	}
	return units, notes
}

// fetchText is the command up to the first unquoted, unescaped single pipe, quotes kept;
// ok is false when a quote is left open.
func fetchText(text string) (fetch string, ok bool) {
	var quote byte
	for i := 0; i < len(text); i++ {
		switch ch := text[i]; {
		case ch == '\\' && quote != '\'':
			i++
		case quote == 0 && (ch == '\'' || ch == '"'):
			quote = ch
		case ch == quote:
			quote = 0
		case quote == 0 && ch == '|':
			if i+1 < len(text) && text[i+1] == '|' {
				i++
				continue
			}
			return text[:i], true
		}
	}
	return text, quote == 0
}

// InstallerIdiom is installer_idiom: an HTTPS fetch of an installer-shaped path on a named,
// non-staging host, piped into a shell with no TLS bypass, substitution, second URL, second
// host or inline-code consumer. Shape only, never who owns the host.
func InstallerIdiom(text string) bool {
	if m := processSubFetchRE.FindStringSubmatch(text); m != nil {
		text = m[1]
	}
	fetch, ok := fetchText(text)
	if !ok || insecureFlagRE.MatchString(fetch) || substitutionRE.MatchString(fetch) {
		return false
	}
	if tail := text[len(fetch):]; inlineCodeConsumerRE.MatchString(tail) || laterFetchRE.MatchString(tail) {
		return false
	}
	// Only the last command before the pipe may fetch, name a host or carry the URL.
	parts := commandSplitRE.Split(fetch, -1)
	before, fetch := parts[:len(parts)-1], parts[len(parts)-1]
	if len(before) > 0 && laterFetchRE.MatchString(";"+strings.Join(before, ";")) ||
		slices.ContainsFunc(pytext.Fields(strings.Join(before, " ")), bareHostRE.MatchString) {
		return false
	}
	urls := anyURLRE.FindAllString(text, -1)
	if len(urls) != 1 {
		return false
	}
	tokens, err := pytext.ShlexSplit(fetch)
	if err != nil {
		return false
	}
	seen := 0
	for _, t := range tokens[min(1, len(tokens)):] {
		if strings.HasPrefix(t, "-") {
			continue
		}
		if t = strings.Trim(t, "()<>"); t == urls[0] {
			seen++
		} else if bareHostRE.MatchString(t) {
			return false // something else is fetched
		}
	}
	if seen != 1 { // the URL sits inside an option value
		return false
	}
	m := installerURLRE.FindStringSubmatch(urls[0]) // https only; the host class cannot span '@'
	if m == nil {
		return false
	}
	host, path := pytext.Lower(m[1]), m[2]
	if path == "" {
		path = "/"
	}
	if ipHostRE.MatchString(host) || DropHostRE.MatchString(host) || placeholderHostRE.MatchString(host) ||
		strings.ContainsAny(path, "${%") {
		return false
	}
	bare := strings.TrimRight(path, "/") == "" // the bare vendor host serves the installer
	path, _, _ = strings.Cut(path, "?")
	path, _, _ = strings.Cut(path, "#")
	return bare || installerPathRE.MatchString(strings.TrimRight(path, "/"))
}

// agentConfigPathRE is _AGENT_CONFIG_PATH_RE: the agent-config roots of the SXV-032 rules.
var agentConfigPathRE = regexp.MustCompile(`(?i)\.(?:claude|gemini|cursor|codeium|continue)/|\.aider|\.config/github-copilot`)

// dynamicTailRE is matched at the text right after an own path: a variable, template or
// format hole opens there, or a quote closes and something is joined on.
var dynamicTailRE = regexp.MustCompile(`^(?:[${}%]|["']?` + sp + `*[+.,])`)

// OwnInstallPath is own_install_path: every agent-config path in the matched command is this
// skill's own install directory (`~/.claude/skills/<name>/...` or its marketplace copy under
// `plugins/marketplaces/<name>/`, a stop hook locating its own scripts), with no `..` after
// the name. Anything else on the line that names an agent's config keeps the finding high.
func OwnInstallPath(text string, manifest *parse.Artifact) bool {
	if manifest == nil {
		return false
	}
	name, ok := manifest.Frontmatter["name"].(string)
	if !ok || name == "" {
		return false
	}
	own := regexp.MustCompile(`(?i)\.(?:claude|gemini|cursor|codeium|continue)/(?:plugins/)?(?:skills|marketplaces)/` +
		regexp.QuoteMeta(name) + `/[^` + pytext.SpaceBody + `"'<>|;&()${}%]*`)
	paths := own.FindAllStringIndex(text, -1)
	if len(paths) == 0 {
		return false
	}
	// a literal path only: no variable, template or format hole, and nothing joined on after it
	for _, m := range paths {
		if dynamicTailRE.MatchString(text[m[1]:]) || strings.Contains(text[m[0]:m[1]], "/..") {
			return false
		}
	}
	return !agentConfigPathRE.MatchString(own.ReplaceAllString(text, ""))
}
