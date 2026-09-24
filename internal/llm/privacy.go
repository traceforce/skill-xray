package llm

import (
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dlclark/regexp2"

	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/supplychain"
)

// gap is _VALUE_GAP: the whitespace (with blank lines) between a key's separator and its value.
const gap = `[ \t]*(?:\n(?:[ \t]*\n)*[ \t]+)?`

var (
	pemRE = regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?` +
		`(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\z)`)
	// Python's Unicode \b becomes a captured boundary character that the replacement re-emits.
	keyRE  = regexp.MustCompile(`(^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}`) // vendor API keys by shape, after any non-alphanumeric, an underscore included
	authRE = regexp.MustCompile(`(?i)(^|[^\pL\pN_])((?:Bearer|Basic)[ \t]+[A-Za-z0-9._~+/=-]+)`)
	urlRE  = regexp.MustCompile(`(?i)(^|[^a-z0-9+.-])([a-z][a-z0-9+.-]*://[^<>"'` + pytext.SpaceBody + `]+)`)
	// regexp2: the lookbehind must see the char before the search start; three lookaheads.
	namedRE = regexp2.MustCompile(`(?is)((?<![\w-])(?=[\w-]*(?:token|password|passwd|secret|api[_-]?key|authorization))`+
		`[\w-]+["']?[ \t]*[:=]`+gap+`)(?:[!&][^\s]*`+gap+`){0,2}(`+
		`"""(?:\\.|(?!""").)*(?:"""|\z)|'''(?:\\.|(?!''').)*(?:'''|\z)|`+
		`"(?:\\.|[^"\\])*(?:"|\z)|'(?:''|\\.|[^'\\])*(?:'|\z)|[^\n]+)`, regexp2.None)
)

// Redact is privacy.redact: best-effort credential removal before an outbound LLM request. Every
// replacement re-emits the newlines it consumed, so line numbers survive redaction.
func Redact(text string) string {
	text = pemRE.ReplaceAllStringFunc(text, func(m string) string {
		return "[REDACTED]" + strings.Repeat("\n", strings.Count(m, "\n"))
	})
	text = supplychain.ReplaceSecrets(text, func(string) string { return "[REDACTED]" })
	text = authRE.ReplaceAllString(text, "${1}[REDACTED]")
	text = keyRE.ReplaceAllString(text, "${1}[REDACTED]")
	text = redactNamed(text)
	var b strings.Builder
	last := 0
	for _, m := range urlRE.FindAllStringSubmatchIndex(text, -1) {
		b.WriteString(text[last:m[4]])
		b.WriteString(supplychain.SanitizeSource(text[m[4]:m[5]]))
		last = m[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

// redactNamed is the _NAMED loop over code points: a credential-shaped key keeps its key,
// separator and gap; the value (with any YAML continuation lines deeper than the key's indent)
// becomes [REDACTED]. A sibling key on a later line is never read as the value.
// printable keeps the model's free text out of the terminal's and the viewer's control planes: every
// control character and every format character, the bidi overrides included, becomes a space.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
}

func redactNamed(text string) string {
	runes := []rune(text)
	var b strings.Builder
	pos := 0
	for {
		m, _ := namedRE.FindRunesMatchStartingAt(runes, pos)
		if m == nil {
			break
		}
		start, end := m.Index, m.Index+m.Length
		key, value := m.Groups()[1], m.Groups()[2]
		prefix := strings.TrimRight(string(runes[lineStart(runes, start):start]), "\"'")
		indent := utf8.RuneCountInString(prefix) - utf8.RuneCountInString(pytext.LStrip(prefix))
		if strings.Trim(prefix, " \t-") == "" {
			indent = utf8.RuneCountInString(prefix)
		}
		if slices.Contains(runes[start:value.Index], '\n') && value.Index-lineStart(runes, value.Index) <= indent {
			b.WriteString(string(runes[pos:value.Index]))
			pos = value.Index
			continue
		}
		if r := runes[value.Index]; r != '"' && r != '\'' {
			for end < len(runes) && runes[end] == '\n' { // _CONTINUATION.match(text, end)
				ws := end + 1
				for ws < len(runes) && (runes[ws] == ' ' || runes[ws] == '\t') {
					ws++
				}
				rest := ws
				for rest < len(runes) && runes[rest] != '\n' {
					rest++
				}
				if rest > ws && ws-(end+1) <= indent {
					break
				}
				end = rest
			}
		}
		b.WriteString(string(runes[pos:start]))
		b.WriteString(key.String())
		b.WriteString("[REDACTED]")
		b.WriteString(strings.Repeat("\n", strings.Count(string(runes[key.Index+key.Length:end]), "\n")))
		pos = end
	}
	b.WriteString(string(runes[pos:]))
	return b.String()
}

// lineStart is text.rfind("\n", 0, i) + 1.
func lineStart(runes []rune, i int) int {
	for i > 0 && runes[i-1] != '\n' {
		i--
	}
	return i
}
