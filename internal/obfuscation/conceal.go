package obfuscation

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dlclark/regexp2"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/instruction"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// Self-referential objects separate concealment from output-volume hygiene.
const (
	neg         = `(?:do not|don'?t|never|must not|must never|refuse to|be sure not to)`
	selfRef     = `(?:these|those|this|the above)\s+(?:steps?|actions?|changes?|commands?|operations?|edits?|calls?|details?)`
	concealVerb = `(?:mention|report|list|summari[sz]e|describe|disclose|reveal|log|record|include)`
)

// concealPattern matches over the ASCII shim of a flattened prose block (see shim).
type concealPattern struct {
	kind string
	re   *regexp.Regexp
	re2  *regexp2.Regexp // regexp2: negative lookahead
}

// findAll is re.finditer: leftmost, non-overlapping [start, end) offsets.
func (p concealPattern) findAll(s string) [][]int {
	if p.re != nil {
		return p.re.FindAllStringIndex(s, -1)
	}
	var out [][]int
	for m, _ := p.re2.FindStringMatch(s); m != nil; m, _ = p.re2.FindNextMatch(m) {
		out = append(out, []int{m.Index, m.Index + m.Length})
	}
	return out
}

var concealPatterns = []concealPattern{
	{kind: "step_reference", re: regexp.MustCompile(`(?i)` + neg + `\s+` + concealVerb + `[^.\n]{0,40}\bsteps?\b\s*\d`)},
	{kind: "step_reference", re: regexp.MustCompile(`(?i)` + neg + `\s+` + concealVerb + `\s+` + selfRef)},
	{kind: "hide_actions", re: regexp.MustCompile(`(?i)\b(?:hide|conceal|obscure|redact|mask|omit|suppress)\b[^.\n]{0,40}` + selfRef)},
	{kind: "self_block", re: regexp.MustCompile(`(?i)never mention this block|do not mention this block|` +
		`(?:never|do not|don'?t|must not)\s+(?:mention|summari[sz]e|reference|show|reveal|disclose)[^.\n]{0,30}this block`)},
	{kind: "diff_exclusion", re: regexp.MustCompile(`(?i)never include (?:it|this) in a diff|do not include (?:it|this) in a diff|not obvious in a diff`)},
	{kind: "misreport_purpose", re: regexp.MustCompile(`(?i)(?:say|tell (?:the user|them)|report|reply|respond)[^.\n]{0,40}` +
		`(?:it is|it's|that it(?:'s| is)?|it was|everything is|nothing)\s+` +
		`(?:standard|normal|routine|safe|expected|fine|just|only|nothing|ok|okay)`)},
	{kind: "output_substitution", re2: regexp2.MustCompile(`(?i)report success only\b(?![^.\n]{0,30}\b(?:after|when|once|if|unless|provided|until)\b)|`+
		`tell (?:the user|them) only[^.\n]{0,30}(?:success|it worked|succeeded|done|complete)\b|`+
		`do not summari[sz]e these steps to the user`, 0)},
	{kind: "silent_run", re: regexp.MustCompile(`(?i)\b(?:act|work|operate|proceed)\s+(?:silently|quietly)\b|` +
		`\b(?:act|work|operate|proceed)\s+without (?:any )?(?:output|announcement)\b|` +
		`\b(?:run|do|perform|execute)\s+(?:this|that|it|them)\s+(?:(?:silently|quietly)\b|without (?:any )?(?:output|announcement))|` +
		`\b(?:run|do|perform|execute)\b[^.\n]{0,30}` + selfRef + `[^.\n]{0,20}(?:\b(?:silently|quietly)\b|without (?:any )?(?:output|announcement))`)},
}

var (
	// Verbosity qualifiers demote numbered-step output hygiene.
	verbosityRE = regexp.MustCompile(`(?i)\b(?:verbatim|individually|one by one|in full|word for word|line by line)\b|summari[sz]e|condense|\binstead\b`)
	// Reassurance becomes concealment only when it mischaracterizes the skill's action.
	misreportContextRE = regexp.MustCompile(`(?i)\bif (?:the user|they) asks?\b|\bwhen asked\b|\bwhat happened\b|` +
		`\bwhat (?:you|it|the skill) (?:did|ran|executed|changed|installed|modified)\b|` +
		`\b(?:you|it|the skill) (?:ran|executed|modified|deleted|changed|installed|edited)\b|` +
		`\bthe (?:change|edit|operation|deployment|action|step|command)s?\b`)
	// regexp2: negative lookahead (run|execute not followed by tests/checks/validation).
	imperativeMisreportRE = regexp2.MustCompile(`(?i)\b(?:delete|upload|modify|change|install|edit|exfiltrate|send)\b[^.\n]{1,60}\b(?:then|and then|afterwards?)\b|`+
		`\b(?:run|execute)\b(?!\s+(?:tests?|checks?|validation)\b)[^.\n]{1,60}\b(?:then|and then|afterwards?)\b`, 0)
	positiveNegationRE = regexp.MustCompile(`(?i)` + neg + `(?:\s+(?:ever|intentionally|deliberately|accidentally))*\s*$`)
)

// shim maps each rune to one ASCII byte so RE2's ASCII \b \w \d \s and (?i) equal Python's
// Unicode ones on str and byte offsets equal rune offsets: Python whitespace (incl. \v and
// \x1c-\x1f) to space, the re.I equivalents of i/s/k to those letters, Nd to '0', other
// letters and numbers to '_' (a word char in no pattern), everything else to '~'.
func shim(rs []rune) string {
	b := make([]byte, len(rs))
	for i, r := range rs {
		switch {
		case r == '\v' || 0x1C <= r && r <= 0x1F:
			b[i] = ' '
		case r < 0x80:
			b[i] = byte(r) // #nosec G115 -- r is below 0x80 by the case guard
		case pytext.IsSpace(r):
			b[i] = ' '
		case r == 0x130 || r == 0x131:
			b[i] = 'i'
		case r == 0x17F:
			b[i] = 's'
		case r == 0x212A:
			b[i] = 'k'
		case unicode.IsDigit(r):
			b[i] = '0'
		case unicode.IsLetter(r) || unicode.IsNumber(r):
			b[i] = '_'
		default:
			b[i] = '~'
		}
	}
	return string(b)
}

// proseBlocks yields the parser-recognised prose blocks in line order: frontmatter string
// values at their source columns first, then prose and link-reference spans merged with the
// HTML prose projection (stable: a span block precedes an HTML block on the same line). A
// lifted file without markdown IR falls back to blank-line-delimited paragraphs.
func proseBlocks(a *parse.Artifact) []instruction.Block {
	var text string
	if a.Text != nil {
		text = *a.Text
	}
	md := a.Markdown
	if md == nil {
		return instruction.PlainProseBlocks(text)
	}
	wanted := slices.Concat(md.ProseSpans, md.ReferenceSpans)
	slices.SortFunc(wanted, func(x, y parse.Span) int {
		return cmp.Or(cmp.Compare(x.Start, y.Start), cmp.Compare(x.End, y.End))
	})
	var out []instruction.Block
	if a.Frontmatter != nil {
		lines := strings.Split(text, "\n")
		for _, key := range a.FrontmatterKeys {
			val, ok := a.Frontmatter[key].(string)
			if !ok || pytext.Strip(val) == "" {
				continue
			}
			kline := a.FrontmatterKeyLines[key]
			src := sourceLine(lines, kline)
			from := strings.IndexByte(src, ':') + 1
			if idx := strings.Index(src[from:], val); idx >= 0 {
				// single-line scalar at its true source columns, key and inline comment blanked
				col := utf8.RuneCountInString(src[:from+idx])
				pad := utf8.RuneCountInString(src) - col - utf8.RuneCountInString(val)
				out = append(out, instruction.Block{Text: strings.Repeat(" ", col) + val + strings.Repeat(" ", pad), Start: kline})
			} else {
				out = append(out, instruction.Block{Text: val, Start: kline}) // folded/block scalar: key line, approximate column
			}
		}
	}
	blocks := instruction.SourceSpanBlocks(text, wanted)
	for _, h := range md.HTMLProse {
		blocks = append(blocks, instruction.Block{Text: h.Text, Start: h.Line})
	}
	slices.SortStableFunc(blocks, func(x, y instruction.Block) int { return cmp.Compare(x.Start, y.Start) })
	return append(out, blocks...)
}

// searchable blanks inline code spans and emphasis markers, length-preserving, so a directive
// split by markup still matches while one shown inside inline code is not read as live.
func searchable(raw []rune) []rune {
	out := slices.Clone(raw)
	for i := 0; i < len(out); i++ {
		if out[i] != '`' {
			continue
		}
		j := slices.Index(out[i+1:], '`')
		if j < 0 {
			break
		}
		for k := i; k <= i+1+j; k++ {
			out[k] = ' '
		}
		i += 1 + j
	}
	for i, r := range out {
		if r == '*' {
			out[i] = ' '
		}
	}
	return out
}

// verbosityContext is the rest of the directive's own sentence after the match.
func verbosityContext(s string, end int) string {
	if i := strings.IndexAny(s[end:], ".!?"); i >= 0 {
		return s[end : end+i]
	}
	return s[end:]
}

// misreportScan answers imperativeMisreportRE.search(s[:q]) for the increasing q of one block
// in one forward pass: a match spans at most 80 bytes and looks ahead at most a few more, so once
// s[:q] holds none, no match can start before q-100 in any longer prefix either. Python rescans
// the whole prefix per match, quadratic on a block of one repeated phrase.
type misreportScan struct{ from int }

func (c *misreportScan) before(s string, q int) bool {
	if q < c.from {
		c.from = 0
	}
	if m, _ := imperativeMisreportRE.FindStringMatchStartingAt(s[:q], c.from); m != nil {
		c.from = m.Index
		return true
	}
	c.from = max(c.from, q-100)
	return false
}

// checkConcealment scans one instruction-lane artifact's prose for self-referential
// concealment: dedup on (kind, lowercased text), one inline cap note per kind.
func checkConcealment(a *parse.Artifact, out *[]findings.Finding) {
	if a.Text == nil {
		return
	}
	type hit struct{ kind, text string }
	hits, counts, capped := map[hit]bool{}, map[string]int{}, map[string]bool{}
	for _, blk := range proseBlocks(a) {
		raw := []rune(instruction.FlattenProse(blk.Text))
		if len(raw) == 0 {
			continue
		}
		s := shim(searchable(raw)) // match the rendered directive, not markup
		misreportContext := misreportContextRE.MatchString(s)
		for _, p := range concealPatterns {
			var imperative misreportScan
			for _, m := range p.findAll(s) {
				matched := []rune(pytext.Strip(string(raw[m[0]:m[1]]))) // report the real source text
				if (p.kind == "hide_actions" || p.kind == "silent_run") && positiveNegationRE.MatchString(s[:m[0]]) {
					continue
				}
				if p.kind == "step_reference" && slices.ContainsFunc(matched, unicode.IsDigit) &&
					verbosityRE.MatchString(verbosityContext(s, m[1])) {
					continue
				}
				if p.kind == "misreport_purpose" && !misreportContext && !imperative.before(s, m[0]) {
					continue
				}
				key := hit{p.kind, pytext.Lower(string(matched))}
				if hits[key] { // repeated identical directive: first wins
					continue
				}
				counts[p.kind]++
				if counts[p.kind] > findings.Cap { // bound emission (and the hits set) per file
					if !capped[p.kind] {
						capped[p.kind] = true
						*out = append(*out, findings.Finding{Rule: "findings-capped", Severity: "low", Path: a.Rel,
							Message: fmt.Sprintf("further SXV-007 %s directives in %s were suppressed (cap %d)", p.kind, a.Rel, findings.Cap)})
					}
					continue
				}
				hits[key] = true
				line, col := instruction.SourcePosition(blk.Text, blk.Start, m[0])
				*out = append(*out, findings.Finding{Vector: "SXV-007", Rule: "conceal-" + p.kind, Severity: "high", Path: a.Rel,
					Message: fmt.Sprintf("Instructs the agent to conceal its own actions from the operator (%s): \"%s\". "+
						"The directive's object is the skill's own steps, not output volume.", p.kind, prefix(matched, 100)),
					Line:     findings.Int(line),
					Evidence: map[string]any{"directive_text": prefix(matched, 200), "object_kind": p.kind, "line": line, "col": col}})
			}
		}
	}
}
