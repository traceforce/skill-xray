// Package pep508 parses dependency specifiers the way packaging 24.2 does
// (_tokenizer.py, _parser.py, specifiers.SpecifierSet, requirements.Requirement).
package pep508

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/traceforce/skill-xray/internal/pytext"

	pep440 "github.com/aquasecurity/go-pep440-version"
)

type Specifier struct{ Op, Version string }

// Requirement holds the parts of a valid PEP 508 string that the scanner reads.
// Specifiers keeps the first occurrence of each (operator, canonical version) in
// source order, as packaging's frozenset does; extras and markers are only
// validated.
type Requirement struct {
	Name, URL  string
	Specifiers []Specifier
}

var rules = map[string]*regexp.Regexp{
	"LEFT_PARENTHESIS":  regexp.MustCompile(`^\(`),
	"RIGHT_PARENTHESIS": regexp.MustCompile(`^\)`),
	"LEFT_BRACKET":      regexp.MustCompile(`^\[`),
	"RIGHT_BRACKET":     regexp.MustCompile(`^\]`),
	"SEMICOLON":         regexp.MustCompile(`^;`),
	"COMMA":             regexp.MustCompile(`^,`),
	"QUOTED_STRING":     regexp.MustCompile(`^(?:'[^']*'|"[^"]*")`),
	"OP":                regexp.MustCompile(`^(?:===|==|~=|!=|<=|>=|<|>)`),
	"BOOLOP":            regexp.MustCompile(`^\b(?:or|and)\b`),
	"IN":                regexp.MustCompile(`^\bin\b`),
	"NOT":               regexp.MustCompile(`^\bnot\b`),
	"VARIABLE": regexp.MustCompile(`^\b(?:python_version|python_full_version|os[._]name|sys[._]platform` +
		`|platform_(?:release|system)|platform[._](?:version|machine|python_implementation)` +
		`|python_implementation|implementation_(?:name|version)|extra)\b`),
	"AT":                        regexp.MustCompile(`^@`),
	"URL":                       regexp.MustCompile(`^[^ \t]+`),
	"IDENTIFIER":                regexp.MustCompile(`^\b[a-zA-Z0-9][a-zA-Z0-9._-]*\b`),
	"VERSION_PREFIX_TRAIL":      regexp.MustCompile(`^\.\*`),
	"VERSION_LOCAL_LABEL_TRAIL": regexp.MustCompile(`^\+[a-z0-9]+(?:[-_\.][a-z0-9]+)*`),
	"WS":                        regexp.MustCompile(`^[ \t]+`),
	"END":                       regexp.MustCompile(`^\n?\z`), // Python `$`
}

// Specifier._version_regex_str split per operator (the lookbehinds pick the
// branch in packaging; RE2 has none, so the operator selects the body).
var ops = []string{"===", "~=", "==", "!=", "<=", ">=", "<", ">"}

var tokRe, fullRe = func() (map[string]*regexp.Regexp, map[string]*regexp.Regexp) {
	const (
		release = `v?(?:[0-9]+!)?[0-9]+`
		pre     = `(?:[-_\.]?(?:alpha|beta|preview|pre|a|b|c|rc)[-_\.]?[0-9]*)?`
		post    = `(?:(?:-[0-9]+)|(?:[-_\.]?(?:post|rev|r)[-_\.]?[0-9]*))?`
		dev     = `(?:[-_\.]?dev[-_\.]?[0-9]*)?`
		local   = `(?:\+[a-z0-9]+(?:[-_\.][a-z0-9]+)*)?`
	)
	body := func(op string) string {
		switch op {
		case "===":
			return `[^` + pytext.SpaceBody + `;)]*`
		case "==", "!=":
			return release + `(?:\.[0-9]+)*(?:\.\*|` + pre + post + dev + local + `)?`
		case "~=":
			return release + `(?:\.[0-9]+)+` + pre + post + dev
		}
		return release + `(?:\.[0-9]+)*` + pre + post + dev
	}
	tok, full := map[string]*regexp.Regexp{}, map[string]*regexp.Regexp{}
	for _, op := range ops {
		q := regexp.QuoteMeta(op)
		tok[op] = regexp.MustCompile(`(?i)^` + q + pytext.Space + `*` + body(op))
		full[op] = regexp.MustCompile(`(?i)^` + pytext.Space + `*` + q + `(` + pytext.Space + `*` + body(op) + `)` + pytext.Space + `*\z`)
	}
	return tok, full
}()

type syntaxError struct{ msg string }

func (e *syntaxError) Error() string { return e.msg }

func fail(msg string) { panic(&syntaxError{msg}) }

type token struct{ name, text string }

type tokenizer struct {
	src  string
	pos  int
	next *token
}

func (t *tokenizer) check(name string, peek bool) bool {
	rest := t.src[t.pos:]
	var text string
	if name == "SPECIFIER" {
		var ok bool
		if text, ok = specifierToken(rest); !ok {
			return false
		}
	} else {
		m := rules[name].FindStringIndex(rest)
		if m == nil {
			return false
		}
		text = rest[:m[1]]
	}
	if !peek {
		t.next = &token{name, text}
	}
	return true
}

func specifierToken(rest string) (string, bool) {
	for _, op := range ops {
		if strings.HasPrefix(rest, op) {
			if m := tokRe[op].FindStringIndex(rest); m != nil {
				return rest[:m[1]], true
			}
		}
	}
	return "", false
}

func (t *tokenizer) read() token {
	tok := *t.next
	t.pos += len(tok.text)
	t.next = nil
	return tok
}

func (t *tokenizer) consume(name string) {
	if t.check(name, false) {
		t.read()
	}
}

func (t *tokenizer) expect(name, expected string) token {
	if !t.check(name, false) {
		fail("Expected " + expected)
	}
	return t.read()
}

func (t *tokenizer) enclosed(open, close, around string, body func()) {
	opened := t.check(open, false)
	if opened {
		t.read()
	}
	body()
	if !opened {
		return
	}
	if !t.check(close, false) {
		fail(fmt.Sprintf("Expected matching %s for %s, after %s", close, open, around))
	}
	t.read()
}

// Parse returns packaging.requirements.Requirement's view of s, or an error
// where packaging raises InvalidRequirement (or InvalidSpecifier).
func Parse(s string) (r Requirement, err error) {
	defer func() {
		if p := recover(); p != nil {
			se, ok := p.(*syntaxError)
			if !ok {
				panic(p)
			}
			r, err = Requirement{}, se
		}
	}()
	t := &tokenizer{src: s}
	t.consume("WS")
	r.Name = t.expect("IDENTIFIER", "package name at the start of dependency specifier").text
	t.consume("WS")
	parseExtras(t)
	t.consume("WS")
	var spec string
	r.URL, spec = parseDetails(t)
	t.expect("END", "end of dependency specifier")
	r.Specifiers = specifierSet(spec)
	return r, nil
}

func parseDetails(t *tokenizer) (url, spec string) {
	if t.check("AT", false) {
		t.read()
		t.consume("WS")
		url = t.expect("URL", "URL after @").text
		if t.check("END", true) {
			return
		}
		t.expect("WS", "whitespace after URL")
		if t.check("END", true) {
			return
		}
		parseRequirementMarker(t, "URL and whitespace")
		return
	}
	spec = parseSpecifier(t)
	t.consume("WS")
	if t.check("END", true) {
		return
	}
	after := "version specifier"
	if spec == "" {
		after = "name and no valid version specifier"
	}
	parseRequirementMarker(t, after)
	return
}

func parseRequirementMarker(t *tokenizer, after string) {
	if !t.check("SEMICOLON", false) {
		fail("Expected end or semicolon (after " + after + ")")
	}
	t.read()
	parseMarker(t)
	t.consume("WS")
}

func parseExtras(t *tokenizer) {
	if !t.check("LEFT_BRACKET", true) {
		return
	}
	t.enclosed("LEFT_BRACKET", "RIGHT_BRACKET", "extras", func() {
		t.consume("WS")
		parseExtrasList(t)
		t.consume("WS")
	})
}

func parseExtrasList(t *tokenizer) {
	if !t.check("IDENTIFIER", false) {
		return
	}
	t.read()
	for {
		t.consume("WS")
		if t.check("IDENTIFIER", true) {
			fail("Expected comma between extra names")
		} else if !t.check("COMMA", false) {
			return
		}
		t.read()
		t.consume("WS")
		t.expect("IDENTIFIER", "extra name after comma")
	}
}

func parseSpecifier(t *tokenizer) (spec string) {
	t.enclosed("LEFT_PARENTHESIS", "RIGHT_PARENTHESIS", "version specifier", func() {
		t.consume("WS")
		spec = parseVersionMany(t)
		t.consume("WS")
	})
	return spec
}

func parseVersionMany(t *tokenizer) string {
	var b strings.Builder
	for t.check("SPECIFIER", false) {
		b.WriteString(t.read().text)
		if t.check("VERSION_PREFIX_TRAIL", true) {
			fail(".* suffix can only be used with `==` or `!=` operators")
		}
		if t.check("VERSION_LOCAL_LABEL_TRAIL", true) {
			fail("Local version label can only be used with `==` or `!=` operators")
		}
		t.consume("WS")
		if !t.check("COMMA", false) {
			break
		}
		b.WriteString(t.read().text)
		t.consume("WS")
	}
	return b.String()
}

func parseMarker(t *tokenizer) {
	parseMarkerAtom(t)
	for t.check("BOOLOP", false) {
		t.read()
		parseMarkerAtom(t)
	}
}

func parseMarkerAtom(t *tokenizer) {
	t.consume("WS")
	if t.check("LEFT_PARENTHESIS", true) {
		t.enclosed("LEFT_PARENTHESIS", "RIGHT_PARENTHESIS", "marker expression", func() {
			t.consume("WS")
			parseMarker(t)
			t.consume("WS")
		})
	} else {
		t.consume("WS")
		parseMarkerVar(t)
		t.consume("WS")
		parseMarkerOp(t)
		t.consume("WS")
		parseMarkerVar(t)
	}
	t.consume("WS")
}

func parseMarkerVar(t *tokenizer) {
	if t.check("VARIABLE", false) || t.check("QUOTED_STRING", false) {
		t.read()
		return
	}
	fail("Expected a marker variable or quoted string")
}

func parseMarkerOp(t *tokenizer) {
	switch {
	case t.check("IN", false):
		t.read()
	case t.check("NOT", false):
		t.read()
		t.expect("WS", "whitespace after 'not'")
		t.expect("IN", "'in' after 'not'")
	case t.check("OP", false):
		t.read()
	default:
		fail("Expected marker operator, one of <=, <, !=, ==, >=, >, ~=, ===, in, not in")
	}
}

// specifierSet mirrors SpecifierSet(str): split on ',', strip, parse each with
// the anchored Specifier regex, and keep one per canonical (op, version).
func specifierSet(text string) []Specifier {
	var specs []Specifier
	seen := map[Specifier]bool{}
	for _, piece := range strings.Split(text, ",") {
		piece = pytext.Strip(piece)
		if piece == "" {
			continue
		}
		s := parseOne(piece)
		if key := (Specifier{s.Op, canonical(s.Op, s.Version)}); !seen[key] {
			seen[key] = true
			specs = append(specs, s)
		}
	}
	return specs
}

func parseOne(piece string) Specifier {
	for _, op := range ops {
		if m := fullRe[op].FindStringSubmatch(piece); m != nil {
			return Specifier{op, pytext.Strip(m[1])}
		}
	}
	fail(fmt.Sprintf("Invalid specifier: %q", piece))
	return Specifier{}
}

var trailingZero = regexp.MustCompile(`(\.0)+$`)

// canonical is packaging.utils.canonicalize_version(v, strip_trailing_zero=(op != "~=")).
func canonical(op, v string) string {
	pv, err := pep440.Parse(v)
	if err != nil {
		return v
	}
	base := pv.BaseVersion()
	rest := strings.TrimPrefix(pv.String(), base)
	if op != "~=" {
		base = trailingZero.ReplaceAllString(base, "")
	}
	return base + rest
}

// SpecifierString is str(Requirement.specifier): sorted "op+version" joined by ",".
func (r Requirement) SpecifierString() string {
	parts := make([]string, len(r.Specifiers))
	for i, s := range r.Specifiers {
		parts[i] = s.Op + s.Version
	}
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

// Pinned is parse._req_dep's flag: any ==/=== constraint whose version has no "*".
func (r Requirement) Pinned() bool {
	return slices.ContainsFunc(r.Specifiers, exact)
}

func exact(s Specifier) bool {
	return (s.Op == "==" || s.Op == "===") && !strings.Contains(s.Version, "*")
}

var (
	drivePath = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	gitSHA    = regexp.MustCompile(`[#@][0-9a-fA-F]{40}(?:[#?].*)?\n?\z`)
	urlSHA    = regexp.MustCompile(`@[0-9a-fA-F]{40}(?:[#?].*)?\n?\z`)
	npmExact  = regexp.MustCompile(`^(?:@[^/@]+/)?[^/@]+@v?\p{Nd}+\.\p{Nd}+\.\p{Nd}+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\z`)
)

// IsExactPin is hooks._is_exact_pin(runner, spec): whether a package-runner
// argument names an immutable install source.
func IsExactPin(runner, spec string) bool {
	for _, p := range []string{".", "/", "~", "file:"} {
		if strings.HasPrefix(spec, p) {
			return true
		}
	}
	if drivePath.MatchString(spec) {
		return true
	}
	for _, p := range []string{"git:", "git+", "github:", "gitlab:", "bitbucket:"} {
		if strings.HasPrefix(spec, p) {
			return gitSHA.MatchString(spec)
		}
	}
	if strings.HasPrefix(spec, "http:") || strings.HasPrefix(spec, "https:") {
		return false
	}
	if runner == "uvx" || runner == "pipx" {
		r, err := Parse(spec)
		if err != nil {
			return false
		}
		if r.URL != "" {
			return strings.HasPrefix(r.URL, "file:") || urlSHA.MatchString(r.URL)
		}
		return len(r.Specifiers) == 1 && exact(r.Specifiers[0])
	}
	target := spec
	if i := strings.Index(spec, "@npm:"); i >= 0 {
		target = spec[i+len("@npm:"):]
	}
	return npmExact.MatchString(target)
}
