// Package obfuscation is the concealment and unicode-deception check (Python
// checks/obfuscation.py): SXV-007 instructed concealment over instruction-lane prose (fence-
// skipping), SXV-014 hidden-codepoint smuggling and SXV-015 homoglyph tokens over every decoded
// artifact (fence-blind). Every index, slice and length is in code points, as in Python.
package obfuscation

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// Check runs the three vectors over the IR in artifact order, isolating each artifact.
func Check(p *parse.Package) []findings.Finding {
	out := []findings.Finding{}
	lifted := parse.LiftedTargets(p)
	for _, a := range p.Artifacts {
		scanArtifact(a, parse.InstructionKinds[a.Kind] || lifted[a.Rel], &out)
	}
	return capFindings(out)
}

// scanArtifact keeps a poisoned artifact from aborting the scan: its panic becomes a high
// check-error finding, because skipped analysis is coverage loss, not "clean".
func scanArtifact(a *parse.Artifact, conceal bool, out *[]findings.Finding) {
	defer func() {
		if recover() != nil {
			*out = append(*out, findings.Finding{Rule: "check-error", Severity: "high", Path: a.Rel,
				Message: "obfuscation skipped " + a.Rel + ": panic"})
		}
	}()
	if conceal {
		checkConcealment(a, out)
	}
	checkUnicode(a, out)
	checkObfuscatedScript(a, out)
}

// SXV-044: a script whose source is one machine-generated line cannot be reviewed. A JavaScript
// obfuscator leaves hex identifiers (_0x3a2f) and escaped string tables (\x57\x50); a minifier
// leaves only the one long line. Both are JavaScript tooling, so only JavaScript and TypeScript
// are checked: a Python or shell script that embeds bytes on one line is readable.
const obfuscatedMinChars = 32 * 1024

var (
	obfuscatedKinds   = map[string]bool{"script_javascript": true, "script_typescript": true}
	obfuscatedIdentRE = regexp.MustCompile(`_0x[0-9a-f]{4,}`) // Python's \b at both ends: FindAllBounded
	hexEscapeRE       = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	minifiedNameRE    = regexp.MustCompile(`(?i)[.-]min\.(?:[cm]?[jt]s|[jt]sx)$`)
	// _PATTERN_DATA_FILE_RE, _PATTERN_KEY_RE: the zero-width characters inside a detection rule's
	// own "regex": "..." value are the thing it detects, not a hidden instruction: a data file only,
	// the value still open at the run, and no more code points than the invisible tables track.
	patternDataFileRE = regexp.MustCompile(`(?i)\.(?:json|ya?ml|toml)$`)
	patternKeyRE      = pytext.PyRE(`(?i)["']?regexp?["']?\s*[:=]\s*(["'])`)
)

// inPatternValue is _in_pattern_value: prefix ends inside a "regex": "..." value, the last key's
// quote still open.
func inPatternValue(prefix string) bool {
	ms := patternKeyRE.FindAllStringSubmatchIndex(prefix, -1)
	if ms == nil {
		return false
	}
	m := ms[len(ms)-1]
	return !strings.Contains(prefix[m[1]:], prefix[m[2]:m[3]])
}

// hexIdents is the number of distinct obfuscator identifiers (_0x…) in s.
func hexIdents(s string) int {
	idents := map[string]bool{}
	notWord := func(r rune) bool { return !pytext.IsWord(r) }
	for _, m := range pytext.FindAllBounded(obfuscatedIdentRE, s, notWord, notWord) {
		idents[s[m[0]:m[1]]] = true
	}
	return len(idents)
}

// generatedLine is _generated_line: the 1-based number of the first line carrying an
// obfuscator's identifiers or string table, whatever the file size; 0 when there is none.
func generatedLine(lines []string) int {
	for i, line := range lines {
		if hexIdents(line) >= 20 || len(hexEscapeRE.FindAllStringIndex(line, -1)) >= 200 {
			return i + 1
		}
	}
	return 0
}

// checkObfuscatedScript is _check_obfuscated_script: SXV-044, a shipped script that is one
// machine-generated line cannot be reviewed.
func checkObfuscatedScript(a *parse.Artifact, out *[]findings.Finding) {
	if !obfuscatedKinds[a.Kind] || a.Text == nil {
		return
	}
	text := *a.Text
	lines := strings.Split(text, "\n")
	longestAt, longest := 0, 0
	for i, line := range lines {
		if n := utf8.RuneCountInString(line); n > longest { // a tie keeps the first line, as max() does
			longestAt, longest = i, n
		}
	}
	idents := hexIdents(text)
	escapes := len(hexEscapeRE.FindAllStringIndex(text, -1))
	generated := generatedLine(lines)
	chars := utf8.RuneCountInString(text)
	if generated == 0 && (chars < obfuscatedMinChars || longest < obfuscatedMinChars/2 || minifiedNameRE.MatchString(a.Rel)) {
		return // short, multi-line, or a declared minified build (x.min.js) that hides nothing
	}
	obfuscated := generated > 0
	rule, severity, what, detail := "minified-script", "medium", "minified", ""
	if obfuscated {
		rule, severity, what = "obfuscated-script", "high", "obfuscated machine output"
		detail = fmt.Sprintf(", %d hex identifiers, %d escaped bytes", idents, escapes)
	}
	mk(out, a.Rel, "SXV-044", rule, severity, cmp.Or(generated, longestAt+1), 0,
		fmt.Sprintf("Shipped script is %s: %d characters on %d line(s), longest line %d%s. Code that cannot "+
			"be read cannot be reviewed.",
			what, chars, strings.Count(text, "\n")+1, longest, detail),
		map[string]any{"chars": chars, "longest_line": longest, "hex_identifiers": idents, "escaped_bytes": escapes})
}

// capFindings keeps the first Cap findings per (path, vector, rule, severity) and appends one
// note per capped key in first-seen order; rule and severity are in the key so cheap padding on
// one rule cannot hide a different critical rule.
func capFindings(fs []findings.Finding) []findings.Finding {
	type key struct{ path, vector, rule, severity string }
	kept := []findings.Finding{}
	counts := map[key]int{}
	var order []key
	for _, f := range fs {
		k := key{f.Path, f.Vector, f.Rule, f.Severity}
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
		if counts[k] <= findings.Cap {
			kept = append(kept, f)
		}
	}
	for _, k := range order {
		if n := counts[k]; n > findings.Cap {
			kept = append(kept, findings.Finding{Rule: "findings-capped", Severity: "low", Path: k.path,
				Message: fmt.Sprintf("%d more %s %s/%s findings in %s were suppressed (cap %d per rule)",
					n-findings.Cap, k.severity, cmp.Or(k.vector, "-"), k.rule, k.path, findings.Cap)})
		}
	}
	return kept
}

// checkUnicode runs the codepoint sweep over one artifact's decoded text line by line, capping
// each (vector, rule, severity) at Cap with one scan-truncated note per artifact. A variable so
// a test can make it panic.
var checkUnicode = func(a *parse.Artifact, out *[]findings.Finding) {
	if a.Text == nil || pytext.IsASCII(*a.Text) {
		return
	}
	lines := strings.Split(*a.Text, "\n")
	keymap := frontmatterKeyMap(a, lines)
	isCode := strings.HasPrefix(a.Kind, "script_")
	counts := map[[3]string]int{}
	truncated := false
	for i, s := range lines {
		if pytext.IsASCII(s) {
			continue
		}
		n := i + 1
		line := []rune(s)
		var lineOut []findings.Finding
		scanInvisible(line, n, a.Rel, &lineOut, isCode)
		nearby := []rune(strings.Join(slices.Concat(lines[max(0, n-3):n-1], lines[n:min(len(lines), n+2)]), "\n"))
		nearbyNative := map[string]bool{}
		for _, script := range []string{"CYRILLIC", "GREEK"} {
			if nativeCount(nearby, script) >= 2 {
				nearbyNative[script] = true
			}
		}
		scanHomoglyph(line, n, a.Rel, keymap[n], &lineOut, isCode, nearbyNative)
		for _, f := range lineOut {
			k := [3]string{f.Vector, f.Rule, f.Severity}
			counts[k]++
			if counts[k] <= findings.Cap {
				*out = append(*out, f)
			} else if !truncated {
				truncated = true
				*out = append(*out, findings.Finding{Rule: "scan-truncated", Severity: "low", Path: a.Rel,
					Message: fmt.Sprintf("unicode scan of %s exceeded a per-rule finding budget (%d); further same-rule findings suppressed", a.Rel, findings.Cap)})
			}
		}
	}
}

// frontmatterKeyMap maps each frontmatter value or continuation line to its key, skipping YAML
// comments and blank lines so a confusable in a comment is not graded as a governed field.
func frontmatterKeyMap(a *parse.Artifact, lines []string) map[int]string {
	if a.FrontmatterEndLine == 0 || a.Frontmatter == nil || len(a.FrontmatterKeyLines) == 0 {
		return nil
	}
	type keyLine struct {
		line int
		key  string
	}
	var ordered []keyLine
	for key, line := range a.FrontmatterKeyLines {
		ordered = append(ordered, keyLine{line, pytext.Lower(key)})
	}
	slices.SortFunc(ordered, func(x, y keyLine) int {
		return cmp.Or(cmp.Compare(x.line, y.line), cmp.Compare(x.key, y.key))
	})
	out := map[int]string{}
	for i, kl := range ordered {
		stop := a.FrontmatterEndLine
		if i+1 < len(ordered) {
			stop = ordered[i+1].line
		}
		for line := kl.line; line < stop; line++ {
			if !isYamlNoise(sourceLine(lines, line)) {
				out[line] = kl.key
			}
		}
	}
	return out
}

// sourceLine is the 1-based line, or "" out of range.
func sourceLine(lines []string, n int) string {
	if 0 < n && n <= len(lines) {
		return lines[n-1]
	}
	return ""
}

// isYamlNoise is a frontmatter line with no scalar value: blank or a full-line comment.
func isYamlNoise(src string) bool {
	s := pytext.Strip(src)
	return s == "" || strings.HasPrefix(s, "#")
}

// mk appends one finding with col as the last evidence key.
func mk(out *[]findings.Finding, rel, vector, rule, severity string, line, col int, message string, evidence map[string]any) {
	evidence["col"] = col
	*out = append(*out, findings.Finding{Vector: vector, Rule: rule, Severity: severity, Path: rel,
		Message: message, Line: findings.Int(line), Evidence: evidence})
}

// prefix is the Python slice rs[:n] as a string.
func prefix(rs []rune, n int) string { return string(rs[:min(n, len(rs))]) }

// stripRunes is str.strip() on a rune slice.
func stripRunes(rs []rune) []rune { return []rune(pytext.Strip(string(rs))) }
