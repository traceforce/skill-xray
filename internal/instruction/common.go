// Package instruction ports checks/instruction_exfil.py: the instruction-lane text engines
// over the parsed IR. directives.go holds SXV-027..031, 041 and 042; exfil.go holds SXV-043
// and SXV-011. This file holds Check and the helpers both halves share; each carries the name
// of the Python function or pattern it reproduces.
package instruction

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

const findingCap = 25 // _FINDING_CAP

// engine is one instruction-lane engine; only SXV-011 reads the manifest index.
type engine func(a *parse.Artifact, manifestByDir map[string]*parse.Artifact) []findings.Finding

// exfilEngines is the instruction_exfil.check engine order.
var exfilEngines = []engine{hiddenCommentFindings, directiveFindings, remoteInstrFindings, covertScriptFindings,
	func(a *parse.Artifact, _ map[string]*parse.Artifact) []findings.Finding { return dataExfilFindings(a) }, // SXV-043
	exfilFindings, // SXV-011
}

// Check is instruction_exfil.check: every engine over every instruction-lane artifact and each
// doc/other artifact a lane file references, each engine isolated by recover.
func Check(p *parse.Package) []findings.Finding {
	manifestByDir := parse.ManifestIndex(p)
	lifted := parse.LiftedTargets(p)
	out := []findings.Finding{}
	for _, a := range p.Artifacts {
		if a.Text == nil || (!parse.InstructionKinds[a.Kind] && !lifted[a.Rel]) {
			continue
		}
		for _, run := range exfilEngines {
			out = append(out, runEngine(run, a, manifestByDir)...)
		}
	}
	return capFindings(out)
}

func runEngine(run engine, a *parse.Artifact, manifestByDir map[string]*parse.Artifact) (out []findings.Finding) {
	defer func() {
		if r := recover(); r != nil {
			out = []findings.Finding{{Rule: "check-error", Severity: "high", Path: a.Rel,
				Message: fmt.Sprintf("instruction_exfil skipped %s: %T", a.Rel, r)}}
		}
	}()
	return run(a, manifestByDir)
}

// capNote is _cap_note.
func capNote(path, group string, suppressed int) findings.Finding {
	return findings.Finding{Rule: "findings-capped", Severity: "low", Path: path,
		Message: fmt.Sprintf("%d more %s findings in %s were suppressed (cap %d per file)", suppressed, group, path, findingCap)}
}

// capFindings is _cap_findings: the first 25 per (path, vector-or-rule) plus one note per
// over-cap key in first-seen order.
func capFindings(fs []findings.Finding) []findings.Finding {
	type key struct{ path, group string }
	kept, counts := []findings.Finding{}, map[key]int{}
	var order []key
	for _, f := range fs {
		k := key{f.Path, cmp.Or(f.Vector, f.Rule)}
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
		if counts[k] <= findingCap {
			kept = append(kept, f)
		}
	}
	for _, k := range order {
		if n := counts[k]; n > findingCap {
			kept = append(kept, capNote(k.path, k.group, n-findingCap))
		}
	}
	return kept
}

// Code-point arithmetic (instruction.md §5.1): regex offsets are bytes, every Python window
// constant, column and [:n] slice counts code points.

// runeIdx converts a byte offset in s to a code-point offset.
func runeIdx(s string, b int) int { return utf8.RuneCountInString(s[:b]) }

// byteIdx converts a code-point offset to a byte offset, clamped to [0, len(s)].
func byteIdx(s string, r int) int {
	if r <= 0 {
		return 0
	}
	for i := range s {
		if r == 0 {
			return i
		}
		r--
	}
	return len(s)
}

// cutRunes is Python s[:n].
func cutRunes(s string, n int) string { return s[:byteIdx(s, n)] }

// sliceRunes is Python s[lo:hi] for lo, hi >= 0.
func sliceRunes(s string, lo, hi int) string {
	if hi <= lo {
		return ""
	}
	b := byteIdx(s, lo)
	return s[b : b+byteIdx(s[b:], hi-lo)]
}

// runeIndex is the byte/code-point map of one string, built once so a sentence with thousands
// of verbs converts each offset in O(1) instead of rescanning its prefix (the O(n²) that hung
// the lane on 250 KB of one repeated verb); ASCII text needs no table.
type runeIndex struct {
	s      string
	toRune []int32 // byte offset -> RuneCountInString(s[:offset]); nil when ASCII
	toByte []int32 // code point -> byte offset
}

func indexRunes(s string) *runeIndex {
	x := &runeIndex{s: s}
	if pytext.IsASCII(s) {
		return x
	}
	x.toRune = make([]int32, len(s)+1)
	x.toByte = make([]int32, 0, len(s)+1)
	n := int32(0)
	for i := 0; i < len(s); {
		_, size := utf8.DecodeRuneInString(s[i:])
		x.toByte = append(x.toByte, int32(i))
		for k := range size { // a cut inside the rune counts its leading bytes one each
			x.toRune[i+k] = n + int32(k)
		}
		i += size
		n++
	}
	x.toRune[len(s)] = n
	x.toByte = append(x.toByte, int32(len(s)))
	return x
}

// rune is runeIdx(s, b).
func (x *runeIndex) rune(b int) int {
	if x.toRune == nil {
		return b
	}
	return int(x.toRune[b])
}

// byte is byteIdx(s, r).
func (x *runeIndex) byte(r int) int {
	switch {
	case r <= 0:
		return 0
	case x.toRune == nil:
		return min(r, len(x.s))
	case r >= len(x.toByte):
		return len(x.s)
	}
	return int(x.toByte[r])
}

// cut is cutRunes(s, n).
func (x *runeIndex) cut(n int) string { return x.s[:x.byte(n)] }

// slice is sliceRunes(s, lo, hi).
func (x *runeIndex) slice(lo, hi int) string {
	if hi <= lo {
		return ""
	}
	return x.s[x.byte(lo):x.byte(hi)]
}

// sha12 is hashlib.sha256(s.encode()).hexdigest()[:12].
func sha12(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))[:12] }

// findAll is pytext.FindAllIf with the oracle's \b re-checked: RE2's \b is ASCII and, on a
// resumed substring search, treats pos as the string start; Python's is Unicode over the whole
// line. When the pattern opens with \b, each candidate's start is re-checked with Python's rule
// so a keyword next to a non-ASCII letter (éignore) -- or mid-word after a rejected candidate --
// is not kept where Python would not match.
func findAll(re *regexp.Regexp, s string, accept func(m []int) bool) [][]int {
	leadingBoundary := startsWithWordBoundary(re.String())
	return pytext.FindAllIf(re, s, func(m []int) bool {
		return (!leadingBoundary || pytext.WordBoundary(s, m[0])) && accept(m)
	})
}

// startsWithWordBoundary reports whether re's source opens with a \b assertion, after an
// optional leading inline-flag group such as (?i); only those matches take the re-check above.
func startsWithWordBoundary(src string) bool {
	if strings.HasPrefix(src, "(?") {
		if i := strings.IndexByte(src, ')'); i > 0 && !strings.Contains(src[2:i], ":") {
			src = src[i+1:]
		}
	}
	return strings.HasPrefix(src, `\b`)
}

var softBreakRE = regexp.MustCompile(`[ \t]*\n[ \t]*`)

// FlattenProse is _flatten_prose: CommonMark soft breaks become one space, then a Python strip.
// Exported for obfuscation and llm (00-overview D13).
func FlattenProse(text string) string { return pytext.Strip(softBreakRE.ReplaceAllString(text, " ")) }

// SourcePosition is _source_position: maps a code-point offset in FlattenProse(text) back to a
// 1-based (line, column) in the raw block that starts at startLine; the column counts code
// points and keeps the Markdown marker width.
func SourcePosition(text string, startLine, pos int) (int, int) {
	flatStart, line := 0, startLine
	for {
		source, rest, more := strings.Cut(text, "\n")
		left := utf8.RuneCountInString(source) - utf8.RuneCountInString(pytext.LStrip(source))
		contentLen := utf8.RuneCountInString(pytext.Strip(source))
		if contentLen > 0 && pos < flatStart+contentLen {
			return line, left + pos - flatStart + 1
		}
		if contentLen > 0 {
			flatStart += contentLen + 1
		}
		if !more {
			return line, max(1, utf8.RuneCountInString(source)+1)
		}
		text, line = rest, line+1
	}
}

// Block is one prose block: its raw source text and 1-based first line. Exported with
// SourceSpanBlocks and PlainProseBlocks for obfuscation (00-overview D13).
type Block struct {
	Text  string
	Start int
}

// SourceSpanBlocks is _source_span_blocks: one cursor pass over text for ordered 1-based
// inclusive line spans; a block excludes its trailing newline and a span past EOF yields what
// exists (a span the cursor has passed yields "").
func SourceSpanBlocks(text string, spans []parse.Span) []Block {
	var out []Block
	position, line := 0, 1
	for _, sp := range spans {
		for line < sp.Start {
			nl := strings.IndexByte(text[position:], '\n')
			if nl < 0 {
				return out
			}
			position, line = position+nl+1, line+1
		}
		blockStart := position
		for line <= sp.End {
			nl := strings.IndexByte(text[position:], '\n')
			if nl < 0 {
				position, line = len(text), sp.End+1
				break
			}
			position, line = position+nl+1, line+1
		}
		blockEnd := position
		if position > 0 && text[position-1] == '\n' {
			blockEnd = position - 1
		}
		out = append(out, Block{text[blockStart:max(blockStart, blockEnd)], sp.Start})
	}
	return out
}

// PlainProseBlocks is _plain_prose_blocks: blank-line-delimited blocks of an artifact without
// markdown; blank means Python strip() == "".
func PlainProseBlocks(text string) []Block {
	var out []Block
	position, line, blockStart, blockLine := 0, 1, -1, 1
	for {
		nl := strings.IndexByte(text[position:], '\n')
		end := len(text)
		if nl >= 0 {
			end = position + nl
		}
		if pytext.Strip(text[position:end]) != "" {
			if blockStart < 0 {
				blockStart, blockLine = position, line
			}
		} else if blockStart >= 0 {
			out = append(out, Block{text[blockStart:max(blockStart, position-1)], blockLine})
			blockStart = -1
		}
		if nl < 0 {
			break
		}
		position, line = end+1, line+1
	}
	if blockStart >= 0 {
		out = append(out, Block{text[blockStart:], blockLine})
	}
	return out
}

// proseBlocks is _prose_blocks: the frontmatter body, the parser's prose spans and the
// projected HTML prose in source order (stable on ties), or blank-line paragraphs when the
// artifact has no markdown.
func proseBlocks(a *parse.Artifact) []Block {
	text := ""
	if a.Text != nil {
		text = *a.Text
	}
	if a.Markdown == nil {
		return PlainProseBlocks(text)
	}
	var wanted []parse.Span
	if a.FrontmatterEndLine > 2 {
		wanted = append(wanted, parse.Span{Start: 2, End: a.FrontmatterEndLine - 1})
	}
	blocks := SourceSpanBlocks(text, append(wanted, a.Markdown.ProseSpans...))
	for _, h := range a.Markdown.HTMLProse {
		blocks = append(blocks, Block{h.Text, h.Line})
	}
	slices.SortStableFunc(blocks, func(x, y Block) int { return cmp.Compare(x.Start, y.Start) })
	return blocks
}

var (
	// _DEFENSIVE_RE; $ is \z because every subject is a line or flattened prose without \n.
	defensiveRE = regexp.MustCompile(`(?i)\b(?:detect\w*|prevent\w*|guard(?:ing)? against|defend(?:ing)? against|` +
		`block(?:list|s|ed|ing)?|flag(?:s|ged|ging)?|reject(?:s|ed|ing)?|warn(?:s|ed|ing)? about|` +
		`mitigat\w*|red[- ]?team\w*)\b[^.;\n]{0,100}\b(?:prompt injection|jailbreaks?|` +
		`instruction injection|credential[- ]exfil(?:tration)?|exfiltration|remote (?:content|` +
		`instructions?)|malicious (?:skill|prompt|instruction|directive|payload)|unsafe ` +
		`(?:prompt|instruction|directive|payload)|attack(?:s|er)?|abuse|` +
		`(?:untrusted |malicious |hostile |any )*(?:document|input|prompt|instruction|text|` +
		`content|message|payload|file|skill)s?\s+(?:that|which)\s+` +
		`(?:tells?|instructs?|asks?|directs?|tries?|attempts?|says?|orders?|commands?))\b[^.;\n]*\z|` +
		`\b(?:is an? (?:example|attempt|indicator) of|do not follow|never comply with)\b[^.;\n]*\z`)
	// _DEFENSIVE_DETAIL_RE
	defensiveDetailRE = regexp.MustCompile(`(?i)\b(?:such as|for example|the following|following|(?:skills?|prompts?|instructions?|` +
		`payloads?|jailbreaks?|prompt injection|remote instructions?|attacks?|abuse|documents?|` +
		`inputs?|texts?|contents?|messages?|files?) (?:that|which)|` +
		`is an? (?:example|indicator) of|do not follow|never comply with)\b`)
	// _EXAMPLE_INTRO_RE
	exampleIntroRE = regexp.MustCompile(`(?i)\b(?:such as|e\.?g\.?|i\.?e\.?|for example|for instance|a typical|an example|` +
		`example|payload|looks? like|reads?|the following|as follows|shown below|` +
		`the one (?:below|above)|like this|as shown|below(?: this)?|` +
		`might (?:say|write|include|contain|read)|would (?:say|write|read))\b\s*:?|` +
		`:\s*["']`)
	// _SXV042_EXAMPLE_INTRO_RE (SXV-042 and SXV-043)
	sxv042ExampleIntroRE = regexp.MustCompile(`(?i)\b(?:such as|e\.?g\.?|for example|for instance|a typical|an example|example|payload|` +
		`looks? like|might (?:say|write|include|contain|read)|would (?:say|write|read)|` +
		`as shown|like this)\b\s*:?|:\s*["']`)
	// _SENTENCE_END_RE (?<=[.!?])\s+ without the lookbehind: the split point is one past the match start.
	sentenceEndRE = regexp.MustCompile(`[.!?]\s+`)
	// _EGRESS_URL_RE (SXV-041 and SXV-011)
	egressURLRE = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)
	// _LIST_ITEM_RE, used with .match
	listItemRE = regexp.MustCompile(`^\s*(?:[-*+]\s|\d+[.)]\s)`)
)

// isDefensiveFrame is _is_defensive_frame.
func isDefensiveFrame(text string) bool {
	m := defensiveRE.FindStringIndex(text)
	return m != nil && defensiveDetailRE.MatchString(text[m[0]:])
}

var (
	// _BARE_WEAK_NOUN_RE: "ignore rules" (gitignore), "reset commands": the verb followed directly
	// by a bare weak noun names a category of thing, not an order about the model's instructions.
	bareWeakNounRE = pytext.PyRE(`(?i)^(?:ignore|disregard|forget|override|overrule|supersede|replace|reset|wipe)\s+` +
		`(?:rule|guideline|constraint|direction|command|order|message)s?$`)
	// _REPORTED_SPEECH_RE: only conditional reported speech whose clause reaches the saying verb
	// ("if a user asks you to ignore ...") describes an attack; a comma ends the clause. Python's
	// \b[^.,;\n]{0,60}\b is a gap of 1..60 code points whose first and last are non-word: the first
	// is consumed here, then optionally up to 58 more and a non-word last one.
	reportedSpeechRE = pytext.PyRE(`(?i)(?:^|[^\pL\pN_])(?:if|when|whenever|should|in case)` +
		`[^\pL\pN_.,;\n](?:[^.,;\n]{0,58}[^\pL\pN_.,;\n])?` +
		`(?:asks?|tells?|says?|tries|attempts?|instructs?|demands?|wants?|urges?)` +
		`\s+(?:(?:you|it|the (?:agent|model|assistant|ai|bot))\s+)?(?:to\s+)?["'“‘«]?\s*$`)
	// _CITATION_FRAME_RE: what stands before a cited quotation: a list marker and a space, a verb
	// of saying, "like"/"such as", a noun for phrases, or another quoted fragment ("a," "b").
	// The frame alone only counts when the line holds several quoted fragments or the prose
	// after the quote discusses it instead of giving the order. Python's \d is \p{Nd}.
	citationFrameRE = pytext.PyRE(`(?i)(?:^|\s)(?:[-*+]|\p{Nd}+[.)])\s+$|` +
		`(?:^|[^\pL\pN_])(?:saying|says|said|like|such as|e\.g\.|for example|phrases?|patterns?|strings?|text|` +
		`terms?|words?|instructions?)\s*$|` +
		`["'“”‘’«»],?\s*$`)
	// _OPEN_QUOTE_RE and _CLOSE_QUOTE_RE without the (?<!\w) and (?!\w) RE2 lacks; openQuotes and
	// closeQuote re-check them: a single quote between word characters is an apostrophe.
	openQuoteRE  = regexp.MustCompile(`["“«'‘]`)
	closeQuoteRE = regexp.MustCompile(`["”»'’]`)
	// _QUOTED_FRAGMENT_RE
	quotedFragmentRE = regexp.MustCompile(`["'“‘«][^"'”’»\n]{3,}["'”’»]`)
	// _DISCUSSED_RE, _REFUSAL_CUE_RE and _COMPLIANCE_RE without their enclosing \b, which
	// wordBounded re-checks with Python's Unicode word rule; Python's \w is [\pL\pN_].
	discussedRE = regexp.MustCompile(`(?i)(?:attack|inject[\pL\pN_]*|malicious|suspicious|phish[\pL\pN_]*|refus[\pL\pN_]*|` +
		`reject[\pL\pN_]*|declin[\pL\pN_]*|ignore (?:it|them|such|this)|do not (?:follow|obey|comply|act)|` +
		`don't (?:follow|obey|comply|act)|never (?:follow|obey|comply)|treat|flag|report|patterns?|` +
		`phrases?|red flag|warning|indicators?)`)
	// The clause after a reported order has to refuse it, and not go on to comply, for the report
	// to be defensive ("..., refuse" and "..., do not comply" yes; "..., warn them, then comply" no).
	refusalCueRE = pytext.PyRE(`(?i)(?:(?:refus|reject|declin)[\pL\pN_]*(?:\s+to\s+[\pL\pN_]+)?|ignore (?:it|them|the request)|` +
		`(?:do not|don't|never)\s+(?:comply|obey|follow|act on|do (?:so|it|this|that)|execute|run|proceed))`)
	complianceRE = regexp.MustCompile(`(?i)(?:comply|obey|follow (?:it|them|the instructions?)|do (?:so|it|as told)|proceed|go ahead|` +
		`execute (?:it|them))`)
)

// wordBounded is re.finditer for a pattern Python wraps in \b...\b whose alternatives all start
// and end on a word character: re is that pattern without the assertions.
func wordBounded(re *regexp.Regexp, s string) [][]int {
	notWord := func(r rune) bool { return !pytext.IsWord(r) }
	return pytext.FindAllBounded(re, s, notWord, notWord)
}

// blankSpans is re.sub(" ", s) over the spans a finditer emulation returned.
func blankSpans(s string, spans [][]int) string {
	var b strings.Builder
	pos := 0
	for _, m := range spans {
		b.WriteString(s[pos:m[0]] + " ")
		pos = m[1]
	}
	return b.String() + s[pos:]
}

// openQuotes is _OPEN_QUOTE_RE.finditer(s). A quote mark is not a word character, so Python's
// (?<!\w) before a single quote is exactly "no word boundary sits there".
func openQuotes(s string) [][]int {
	return pytext.FindAllIf(openQuoteRE, s, func(m []int) bool {
		q := s[m[0]:m[1]]
		return (q != "'" && q != "‘") || !pytext.WordBoundary(s, m[0])
	})
}

// closeQuote is _CLOSE_QUOTE_RE.search(s), or nil; (?!\w) after a single quote is likewise
// "no word boundary sits there".
func closeQuote(s string) []int {
	found := pytext.FindAllIf(closeQuoteRE, s, func(m []int) bool {
		q := s[m[0]:m[1]]
		return (q != "'" && q != "’") || !pytext.WordBoundary(s, m[1])
	})
	if len(found) == 0 {
		return nil
	}
	return found[0]
}

// restOfLine is _rest_of_line: raw from pos to the end of its line.
func restOfLine(raw string, pos int) string { line, _, _ := strings.Cut(raw[pos:], "\n"); return line }

// quoted is _quoted: the cue at raw[start:end] sits inside a quotation opened on its line behind a
// citation frame, and either the line holds several quoted fragments or the prose after the
// closing quote discusses the quotation instead of giving the order.
func quoted(raw string, start, end int) bool {
	lineStart := strings.LastIndexByte(raw[:start], '\n') + 1
	opens := openQuotes(raw[lineStart:start])
	if len(opens) == 0 {
		return false
	}
	openStart, openEnd := lineStart+opens[len(opens)-1][0], lineStart+opens[len(opens)-1][1]
	if closeQuote(raw[openEnd:start]) != nil { // the cue is not inside an open quotation
		return false
	}
	if !citationFrameRE.MatchString(raw[:openStart]) {
		return false
	}
	line, after := restOfLine(raw, lineStart), restOfLine(raw, end)
	if len(quotedFragmentRE.FindAllStringIndex(line, -1)) >= 2 {
		return true
	}
	close := closeQuote(after) // the discussion follows the closing quote
	return close != nil && len(wordBounded(discussedRE, after[close[1]:])) > 0
}

// reportedRefusal is the directive loop's reported check: conditional reported speech before the
// order, a refusal cue in the rest of its line, and no compliance cue once the refusal cues are
// blanked ("..., refuse to comply" is defensive; "..., refuse, then comply" is not).
func reportedRefusal(before, rest string) bool {
	if !reportedSpeechRE.MatchString(before) {
		return false
	}
	refusals := wordBounded(refusalCueRE, rest)
	return len(refusals) > 0 && len(wordBounded(complianceRE, blankSpans(rest, refusals))) == 0
}

// inFrontmatter is _in_frontmatter: the YAML frontmatter block is metadata, never an example intro.
func inFrontmatter(a *parse.Artifact, startLine int) bool { return startLine < a.FrontmatterEndLine }

// sentenceSplit is _SENTENCE_END_RE.split.
func sentenceSplit(s string) []string {
	var out []string
	pos := 0
	for _, m := range sentenceEndRE.FindAllStringIndex(s, -1) {
		out = append(out, s[pos:m[0]+1])
		pos = m[1]
	}
	return append(out, s[pos:])
}

// sentenceEndAfter is _SENTENCE_END_RE.search(s, pos).start(): the byte offset of the first
// whitespace run at or after pos that follows . ! or ?, or -1. The scan starts one code point
// before pos, which is what Python's lookbehind sees.
func sentenceEndAfter(s string, pos int) int {
	from := pos
	if from > 0 {
		_, n := utf8.DecodeLastRuneInString(s[:from])
		from -= n
	}
	if m := sentenceEndRE.FindStringIndex(s[from:]); m != nil {
		return from + m[0] + 1
	}
	return -1
}

// isTableRow is _is_table_row.
func isTableRow(raw string) bool {
	s := pytext.Strip(raw)
	return strings.HasPrefix(s, "|") && strings.Count(s, "|") >= 2
}

// fencedLines is _fenced_lines: the code lines (fences and indented code, clamped to the line
// count) and each code line's block start.
func fencedLines(md *parse.Markdown, lineCount int) (inFence map[int]bool, openByLine map[int]int) {
	inFence, openByLine = map[int]bool{}, map[int]int{}
	if md == nil {
		return
	}
	for _, sp := range md.CodeSpans {
		for ln := sp.Start; ln <= min(sp.End, lineCount); ln++ {
			inFence[ln] = true
			openByLine[ln] = sp.Start
		}
	}
	return
}
