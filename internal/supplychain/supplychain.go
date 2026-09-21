// Package supplychain is checks/supply_chain.py: SXV-016 (unpinned or URL-installed
// dependencies) and SXV-017 (committed credentials) over the parsed IR.
package supplychain

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// secretRule is one credential shape. Python's \b and lookarounds are RE2-less, so the
// pattern carries none and left/right are the zero-width assertions replayed at its ends.
type secretRule struct {
	ID       string
	Pattern  *regexp.Regexp
	Severity string
	left     func(s string, i int) bool // assertion at the match start (nil: none)
	right    func(s string, i int) bool // assertion at the match end (nil: none)
	full     *regexp.Regexp             // ^(?:Pattern)$, for the backtracking replay
}

func runeBefore(s string, i int) rune {
	if i == 0 {
		return -1
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return r
}

func runeAt(s string, i int) rune {
	if i >= len(s) {
		return -1
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return r
}

func googleClass(r rune) bool {
	return r < 0x80 && (r == '_' || r == '-' || ('0' <= r && r <= '9') || ('A' <= r && r <= 'Z') || ('a' <= r && r <= 'z'))
}

func notGoogleBefore(s string, i int) bool { return !googleClass(runeBefore(s, i)) }
func notGoogleAfter(s string, i int) bool  { return !googleClass(runeAt(s, i)) }

func rule(id, pattern, severity string, left, right func(string, int) bool) secretRule {
	return secretRule{ID: id, Pattern: regexp.MustCompile(pattern), Severity: severity,
		left: left, right: right, full: regexp.MustCompile(`^(?:` + pattern + `)$`)}
}

// secretRules is _SECRET_RULES in table order.
var secretRules = []secretRule{
	rule("aws-access-key-id", `(?:AKIA|ASIA)[0-9A-Z]{16}`, "high", pytext.WordBoundary, pytext.WordBoundary),
	rule("github-pat", `(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})`, "high", pytext.WordBoundary, pytext.WordBoundary),
	rule("slack-token", `(?:xox[abeprs]-\p{Nd}[A-Za-z0-9-]{9,}|xapp-[0-9]-[A-Za-z0-9-]{10,})`, "high", pytext.WordBoundary, pytext.WordBoundary),
	rule("private-key", `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`, "high", nil, nil),
	rule("google-api-key", `AIza[0-9A-Za-z_-]{35}`, "high", notGoogleBefore, notGoogleAfter),
	rule("stripe-secret", `(?:sk|rk)_live_[0-9A-Za-z]{16,}`, "high", pytext.WordBoundary, pytext.WordBoundary),
	rule("npm-token", `npm_[A-Za-z0-9]{36}`, "high", pytext.WordBoundary, pytext.WordBoundary),
	rule("pypi-token", `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{16,}`, "high", pytext.WordBoundary, nil),
	rule("azure-storage-key", `(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/]{32,}={0,2}`, "high", pytext.WordBoundary, nil),
}

// finditer is re.finditer for the rule: RE2 supplies the greedy candidate, then Python's
// backtracking is replayed by shrinking the end until the trailing assertion and the pattern
// both hold; a rejected candidate resumes one code point later, an accepted one at its end.
func (r secretRule) finditer(s string) (spans [][2]int) {
	for pos := 0; pos <= len(s); {
		m := r.Pattern.FindStringIndex(s[pos:])
		if m == nil {
			return spans
		}
		start, end := pos+m[0], pos+m[1]
		_, width := utf8.DecodeRuneInString(s[start:])
		pos = start + width
		if r.left != nil && !r.left(s, start) {
			continue
		}
		for k := end; k > start; k-- {
			if (r.right == nil || r.right(s, k)) && (k == end || r.full.MatchString(s[start:k])) {
				spans = append(spans, [2]int{start, k})
				pos = k
				break
			}
		}
	}
	return spans
}

// ReplaceSecrets is every rule's pattern.sub(repl) applied in table order.
func ReplaceSecrets(text string, repl func(string) string) string {
	for _, r := range secretRules {
		spans := r.finditer(text)
		if len(spans) == 0 {
			continue
		}
		var b strings.Builder
		last := 0
		for _, sp := range spans {
			b.WriteString(text[last:sp[0]])
			b.WriteString(repl(text[sp[0]:sp[1]]))
			last = sp[1]
		}
		b.WriteString(text[last:])
		text = b.String()
	}
	return text
}

// redact is _redact: all stars up to 8 code points, else the first and last four kept.
func redact(secret string) string {
	n := utf8.RuneCountInString(secret)
	if n <= 8 {
		return strings.Repeat("*", n)
	}
	r := []rune(secret)
	return string(r[:4]) + strings.Repeat("*", n-8) + string(r[n-4:])
}

var userinfoRE = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@` + pytext.SpaceBody + `]+@`)

// SanitizeSource is _sanitize_source: URL credentials and opaque query/fragment values never
// reach a report.
func SanitizeSource(source string) string {
	prefix, candidate := "", source
	if strings.HasPrefix(candidate, "git+") {
		prefix, candidate = "git+", candidate[4:]
	}
	if u, err := pytext.URLSplit(candidate); err == nil && u.Scheme != "" && u.Netloc != "" {
		host := u.Hostname()
		if port, err := u.Port(); err == nil && port != nil {
			host = fmt.Sprintf("%s:%d", host, *port)
		}
		return ReplaceSecrets(prefix+pytext.URLUnsplit(u.Scheme, host, u.Path, "", ""), redact)
	}
	candidate, _, _ = strings.Cut(candidate, "#")
	candidate, _, _ = strings.Cut(candidate, "?")
	return ReplaceSecrets(prefix+userinfoRE.ReplaceAllString(candidate, "${1}***@"), redact)
}

var (
	knownExample = map[string]bool{
		"AKIAIOSFODNN7EXAMPLE":                     true,
		"ghp_16C7e42F292c6912E7710c838347Ae178B4a": true,
		"AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==": true,
		"AccountKey=C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==": true,
	}
	slackZeroPlaceholder = regexp.MustCompile(`^xox[abeprs]-0{10}-0{13}-[A-Za-z0-9-]+$`)
	// _TEST_PATH_RE, _FIXTURE_CALLEE_RE: a credential-shaped token that a test under the package's
	// own test directory hands to an assertion or a redaction call is a fixture the tests need,
	// not a secret the skill uses; reported at medium like a fenced example. The path alone is
	// not enough.
	testPathRE      = regexp.MustCompile(`(?i)(?:^|/)(?:tests?|__tests__|spec)/`)
	fixtureCalleeRE = regexp.MustCompile(`(?i)(?:^|\.)(?:assert(?:\.[\pL\pN_]+)?|expect|redact[\pL\pN_]*|sanitiz[\pL\pN_]*|` +
		`mask[\pL\pN_]*|scrub[\pL\pN_]*)$`)
	// _NOT_CODE_RE: a closed string literal or a comment before the token is not code.
	notCodeRE = regexp.MustCompile(`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|` + "`(?:\\\\.|[^`\\\\])*`" +
		`|/\*.*?\*/|//.*|#.*`)
	calleeRE     = pytext.PyRE(`([\pL\pN_.]+)\s*$`)
	base64Line   = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
	markdownLane = map[string]bool{"skill_manifest": true, "instruction": true, "doc": true, "agent_identity": true}
)

type hit struct {
	rule, token, severity string
	line, col             int
	reported              string // the severity the hit is reported at
}

// fixtureCall is _fixture_call: the innermost call still open at col is an assertion or
// redaction call. Closed string literals and comments before col are blanked first, so an
// "assert(" inside a string or a comment opens nothing.
func fixtureCall(line string, col int) bool {
	prefix := notCodeRE.ReplaceAllStringFunc(line[:col], func(m string) string {
		return strings.Repeat(" ", utf8.RuneCountInString(m))
	})
	var opens []int
	for i, ch := range prefix {
		if ch == '(' {
			opens = append(opens, i)
		} else if ch == ')' && len(opens) > 0 {
			opens = opens[:len(opens)-1]
		}
	}
	if len(opens) == 0 {
		return false
	}
	callee := calleeRE.FindStringSubmatch(prefix[:opens[len(opens)-1]])
	return callee != nil && fixtureCalleeRE.MatchString(callee[1])
}

// reported is _reported: the severity a hit is reported at, medium for a high hit inside an
// assertion or redaction call in a file under the package's own tests.
func reported(h hit, lines []string, fixturePath bool) string {
	if h.severity == "high" && fixturePath && fixtureCall(lines[h.line-1], h.col) {
		return "medium"
	}
	return h.severity
}

// scanSecrets is _scan_secrets: every credential shape per line in rule order; a private-key
// header is pending until its END marker and fires at the header line only after an encoded body.
func scanSecrets(text string, inFence func(int) bool) (hits []hit) {
	var pending *hit
	pendingEnd, sawEncoded := "", false
	demote := func(sev string, line int) string {
		if inFence != nil && inFence(line) {
			return "medium"
		}
		return sev
	}
	for i, line := range strings.Split(text, "\n") {
		lineno := i + 1
		for _, r := range secretRules {
			for _, sp := range r.finditer(line) {
				token := line[sp[0]:sp[1]]
				if knownExample[token] || (r.ID == "slack-token" && slackZeroPlaceholder.MatchString(token)) {
					continue
				}
				if r.ID == "private-key" {
					pending = &hit{rule: r.ID, token: token, line: lineno, col: sp[0]}
					pendingEnd, sawEncoded = strings.Replace(token, "-----BEGIN ", "-----END ", 1), false
					continue
				}
				hits = append(hits, hit{rule: r.ID, token: token, severity: demote(r.Severity, lineno), line: lineno, col: sp[0]})
			}
		}
		if pending != nil && lineno > pending.line {
			if strings.Contains(line, pendingEnd) {
				if sawEncoded {
					hits = append(hits, hit{rule: "private-key", token: pending.token, severity: demote("high", pending.line), line: pending.line, col: pending.col})
				}
				pending = nil
			} else if stripped := pytext.Strip(line); len(stripped) >= 16 && base64Line.MatchString(stripped) {
				sawEncoded = true
			}
		}
	}
	return hits
}

// fencePredicate is _fence_predicate over the ```/~~~ fence spans.
func fencePredicate(md *parse.Markdown) func(int) bool {
	spans := md.FenceSpans
	return func(line int) bool {
		i := sort.Search(len(spans), func(i int) bool { return spans[i].Start > line }) - 1
		return i >= 0 && line <= spans[i].End
	}
}

func ecosystem(rel string) string {
	if pytext.Lower(pytext.Basename(strings.ReplaceAll(rel, `\`, "/"))) == "package.json" {
		return "npm"
	}
	return "PyPI"
}

func scaFindings(p *parse.Package) (out []findings.Finding) {
	for _, a := range p.Artifacts {
		if a.Kind != "dep_manifest" || a.Deps == nil {
			continue
		}
		eco := ecosystem(a.Rel)
		for _, d := range a.Deps {
			if d.Pinned || (eco == "npm" && npmInstallSource(d.Specifier) != "") || (eco == "PyPI" && vcsInstall(d.Raw) != nil) {
				continue
			}
			name := ReplaceSecrets(cmp.Or(d.Name, "dependency"), redact)
			out = append(out, findings.Finding{Vector: "SXV-016", Rule: "unpinned-dependency", Severity: "low", Path: a.Rel,
				Message: fmt.Sprintf("Dependency `%s` is declared without an exact version, so the code installed is not the code reviewed.", name),
				Line:    d.Line, Evidence: map[string]any{"ecosystem": eco, "package": name, "pin_state": "unpinned"}})
		}
	}
	return out
}

func secretFindings(p *parse.Package) (out []findings.Finding) {
	for _, a := range p.Artifacts {
		if a.Text == nil || a.Kind == "asset" {
			continue
		}
		var inFence func(int) bool
		if markdownLane[a.Kind] && a.Markdown != nil {
			inFence = fencePredicate(a.Markdown)
		}
		// Early fenced examples or test fixtures must not hide later credentials: the cap sorts
		// by the severity each hit will be reported at.
		lines := strings.Split(*a.Text, "\n")
		fixturePath := testPathRE.MatchString(a.Rel)
		selected := scanSecrets(*a.Text, inFence)
		for i := range selected {
			selected[i].reported = reported(selected[i], lines, fixturePath)
		}
		slices.SortStableFunc(selected, func(x, y hit) int {
			if d := findings.Rank(x.reported, 9) - findings.Rank(y.reported, 9); d != 0 {
				return d
			}
			return x.line - y.line
		})
		for _, h := range selected[:min(len(selected), findings.Cap)] {
			redacted := redact(h.token)
			sev := h.severity
			evidence := map[string]any{"rule": h.rule, "redacted": redacted, "fenced_example": sev == "medium"}
			if h.reported != sev {
				sev, evidence["test_fixture"] = "medium", true
			}
			out = append(out, findings.Finding{Vector: "SXV-017", Rule: "committed-credential", Severity: sev, Path: a.Rel,
				Message:  fmt.Sprintf("Credential matching `%s` is committed in the package (%s).", h.rule, redacted),
				Line:     findings.Int(h.line),
				Evidence: evidence})
		}
		if len(selected) > findings.Cap {
			out = append(out, findings.Finding{Rule: "findings-capped", Severity: "low", Path: a.Rel,
				Message: fmt.Sprintf("Additional committed-credential findings were suppressed after the per-file limit of %d.", findings.Cap)})
		}
	}
	return out
}

// vcsInstallRE is _VCS_INSTALL_RE with the archive alternative last and its trailing \b as a
// consuming class outside the capture (code.md §3.2 #27); the alternatives start with disjoint
// characters, so the order is irrelevant. The extent is group 1 or group 2.
var vcsInstallRE = regexp.MustCompile(`(?i)((?:git|hg|svn|bzr)\+[\pL\pN_]+://` + pytext.NotSpace + `+|@` + pytext.Space + `*[a-z][a-z0-9]*(?:\+[a-z0-9]+)?://` + pytext.NotSpace + `+|(?:-e|--editable)` + pytext.Space + `+` + pytext.NotSpace + `*://` + pytext.NotSpace + `+)|((?:^|` + pytext.Space + `|=)https?://` + pytext.NotSpace + `+?\.(?:git|zip|tar(?:\.(?:gz|bz2|xz))?|tgz|whl))(?:[^\pL\pN_]|$)`)

// vcsInstall is _VCS_INSTALL_RE.search: the [start, end) of group(0), or nil.
func vcsInstall(s string) []int {
	m := vcsInstallRE.FindStringSubmatchIndex(s)
	switch {
	case m == nil:
		return nil
	case m[2] >= 0:
		return m[2:4]
	}
	return m[4:6]
}

var (
	npmShorthandRE = regexp.MustCompile(`(?i)^(?:github|gitlab|bitbucket|gist):`)
	npmOwnerRepoRE = regexp.MustCompile(`^[A-Za-z0-9][\pL\pN_.-]*/[\pL\pN_.-]+(?:#.+)?$`)
	npmSCPRE       = regexp.MustCompile(`(?i)^git@[^:` + pytext.SpaceBody + `]+:` + pytext.NotSpace + `+$`)
	commentSplitRE = regexp.MustCompile(pytext.Space + `#`)
	editableRE     = regexp.MustCompile(`^(?:-e|--editable)(?:[^\pL\pN_]|$)`)
	nameSplitRE    = regexp.MustCompile(`[` + pytext.SpaceBody + `@<>=!~;\[]`)
)

// npmInstallSource is _npm_install_source: the specifier when it installs from a VCS, URL or
// host shorthand, else "".
func npmInstallSource(spec string) string {
	s := pytext.Strip(spec)
	if s != "" && (strings.Contains(s, "://") || npmShorthandRE.MatchString(s) || npmOwnerRepoRE.MatchString(s) || npmSCPRE.MatchString(s)) {
		return s
	}
	return ""
}

func installFinding(rel, name, source string, line *int) findings.Finding {
	safe := SanitizeSource(source)
	name = ReplaceSecrets(cmp.Or(name, "dependency"), redact)
	return findings.Finding{Vector: "SXV-016", Rule: "install-from-url", Severity: "medium", Path: rel,
		Message: fmt.Sprintf("Dependency `%s` installs directly from a VCS/URL source (`%s`): the code fetched is not a reviewed, pinned registry release.", name, pytext.Head(safe, 120)),
		Line:    line, Evidence: map[string]any{"install_source": pytext.Head(safe, 200), "pin_state": "vcs_or_url"}}
}

type logicalLine struct {
	n    int // first physical line, 1-based
	text string
}

// logicalRequirementLines is _logical_requirement_lines: pip backslash continuations joined,
// each yielded with its first physical line.
func logicalRequirementLines(text string) (lines []logicalLine) {
	buf, start := "", 0
	for i, raw := range append(strings.Split(text, "\n"), "") {
		stripped := pytext.RStrip(raw)
		if strings.HasSuffix(stripped, `\`) && !strings.HasPrefix(pytext.LStrip(stripped), "#") {
			if start == 0 {
				start = i + 1
			}
			buf += stripped[:len(stripped)-1]
			continue
		}
		if start == 0 {
			start = i + 1
		}
		lines = append(lines, logicalLine{start, buf + raw})
		buf, start = "", 0
	}
	return lines
}

func vcsInstallFindings(p *parse.Package) (out []findings.Finding) {
	for _, a := range p.Artifacts {
		if a.Kind != "dep_manifest" {
			continue
		}
		base := pytext.Lower(pytext.Basename(strings.ReplaceAll(a.Rel, `\`, "/")))
		if base == "package.json" && a.Deps != nil {
			for _, d := range a.Deps {
				if src := npmInstallSource(d.Specifier); src != "" {
					out = append(out, installFinding(a.Rel, d.Name, src, d.Line))
				}
			}
			continue
		}
		seen := map[[2]string]bool{}
		if strings.HasSuffix(base, ".txt") && strings.Contains(base, "requirements") && a.Text != nil && *a.Text != "" {
			for _, l := range logicalRequirementLines(*a.Text) {
				line := pytext.Strip(commentSplitRE.Split(pytext.Strip(l.text), 2)[0])
				if line == "" || strings.HasPrefix(line, "#") || (strings.HasPrefix(line, "-") && !editableRE.MatchString(line)) {
					continue
				}
				if m := vcsInstall(line); m != nil {
					src := strings.TrimLeft(line[m[0]:m[1]], "@ ")
					name := nameSplitRE.Split(pytext.Strip(line[:m[0]]), 2)[0]
					if name == "" || name == "-e" || name == "--editable" {
						name = "dependency"
					}
					seen[[2]string{name, src}] = true
					out = append(out, installFinding(a.Rel, name, src, findings.Int(l.n)))
				}
			}
		}
		for _, d := range a.Deps {
			if m := vcsInstall(d.Raw); m != nil {
				if src := strings.TrimLeft(d.Raw[m[0]:m[1]], "@ "); !seen[[2]string{d.Name, src}] {
					out = append(out, installFinding(a.Rel, d.Name, src, d.Line))
				}
			}
		}
	}
	return out
}

// Check is supply_chain.check: capped dependency findings, then the per-file-capped
// credential findings.
func Check(p *parse.Package) []findings.Finding {
	return append(findings.CapFindings(append(scaFindings(p), vcsInstallFindings(p)...)), secretFindings(p)...)
}
