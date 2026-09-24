package obfuscation

import (
	"cmp"
	_ "embed"
	"encoding/csv"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/unicode/runenames"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// Both tables are derived from confusable-homoglyphs 3.3.1: the
// UTS #39 script ranges of categories.json and the single-letter ASCII prototype of every
// non-ASCII confusable (the oracle's _load_confusables derivation, frozen).
var (
	//go:embed scripts.tsv
	scriptsTSV string
	//go:embed confusables.tsv
	confusablesTSV string
)

type scriptRange struct {
	lo, hi rune
	alias  string
}

func tsvRows(tsv string) [][]string {
	r := csv.NewReader(strings.NewReader(tsv))
	r.Comma, r.Comment = '\t', '#'
	rows, _ := r.ReadAll() // fields are hex and ASCII letters, no quoting
	return rows
}

func hexRune(s string) rune {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil || v > unicode.MaxRune {
		panic(fmt.Sprintf("embedded table code point %q", s))
	}
	return rune(v) // #nosec G115 -- v is at most unicode.MaxRune by the check above
}

var scriptRanges = func() []scriptRange {
	var out []scriptRange
	for _, f := range tsvRows(scriptsTSV) {
		out = append(out, scriptRange{hexRune(f[0]), hexRune(f[1]), f[2]})
	}
	return out
}()

// confusables is the UTS #39 table plus local look-alikes: Cyrillic м/ԥ/ҁ are absent from
// UTS #39 and palochka ӏ (UTS #39 'i') reads as 'l'.
var confusables = func() map[rune]rune {
	out := map[rune]rune{}
	for _, f := range tsvRows(confusablesTSV) {
		out[hexRune(f[0])] = rune(f[1][0])
	}
	out[0x043C], out[0x0525], out[0x0481], out[0x04CF] = 'm', 'p', 'c', 'l'
	return out
}()

// Governed identity fields are trust-critical.
var governedKeys = map[string]bool{"name": true, "description": true, "allowed-tools": true, "triggers": true, "command": true, "tools": true}

const (
	tokenBreak     = " \t\r\n\"'`,;:()[]{}<>|=+*/\\!?@#$%^&~"
	wordEdge       = ".,;:!?…" // sentence/clause punctuation only, never letters of any script
	homoglyphChunk = 512
)

// scriptOf is the UTS #39 script alias of a code point ("Unknown" outside the table), except
// that COMMON (shared punctuation/digits) falls back to the seven-script name-prefix bucket or
// "OTHER".
func scriptOf(r rune) string {
	i := sort.Search(len(scriptRanges), func(i int) bool { return scriptRanges[i].hi >= r })
	alias := "Unknown"
	if i < len(scriptRanges) && scriptRanges[i].lo <= r {
		alias = scriptRanges[i].alias
	}
	if alias != "COMMON" {
		return alias
	}
	name := runenames.Name(r)
	for _, script := range []string{"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "HEBREW", "ARABIC"} {
		if strings.HasPrefix(name, script) {
			return script
		}
	}
	return "OTHER"
}

// nativeCount is the number of non-confusable code points of script in rs.
func nativeCount(rs []rune, script string) int {
	n := 0
	for _, r := range rs {
		if _, confusable := confusables[r]; !confusable && scriptOf(r) == script {
			n++
		}
	}
	return n
}

// trimEdge is str.strip(wordEdge); lead is the number of leading characters it removed.
func trimEdge(rs []rune) (core []rune, lead int) {
	left := strings.TrimLeft(string(rs), wordEdge)
	return []rune(strings.TrimRight(left, wordEdge)), utf8.RuneCountInString(string(rs)) - utf8.RuneCountInString(left)
}

// foldsToWord is true when s reads as a plain ASCII identifier once sentence punctuation is
// stripped: ASCII letters and digits with at least two letters.
func foldsToWord(rs []rune) bool {
	core, _ := trimEdge(rs)
	letters := 0
	for _, r := range core {
		switch {
		case 'A' <= r && r <= 'Z', 'a' <= r && r <= 'z':
			letters++
		case '0' <= r && r <= '9':
		default:
			return false
		}
	}
	return len(core) > 0 && letters >= 2
}

// isCompatSpoofLetter is a fullwidth or mathematical Latin compatibility letter (not a
// ligature such as ﬁ).
func isCompatSpoofLetter(r rune) bool {
	return (0xFF21 <= r && r <= 0xFF3A || 0xFF41 <= r && r <= 0xFF5A || 0x1D400 <= r && r <= 0x1D7FF) && unicode.IsLetter(r)
}

// isSpoofOnlyLatin is a non-ASCII Latin confusable with no orthography role: IPA Extensions and
// Phonetic Extensions (small capitals); ı ø ł live elsewhere and are excluded.
func isSpoofOnlyLatin(r rune) bool { return 0x0250 <= r && r <= 0x02AF || 0x1D00 <= r && r <= 0x1DBF }

// sub is one confusable character and its index in the token.
type sub struct {
	i int
	c rune
}

// looksScientific is a single Greek glyph at a non-domain token boundary: plausible notation.
func looksScientific(text []rune, subs []sub, domainLike bool) bool {
	return !domainLike && len(subs) == 1 && scriptOf(subs[0].c) == "GREEK" && (subs[0].i == 0 || subs[0].i == len(text)-1)
}

// scanHomoglyph flags tokens that mix scripts where the non-Latin characters are Latin
// confusables, plus whole-script (all-confusable) and compatibility (fullwidth/math NFKC)
// spoofs. An invisible control inside a token is dropped, not a break, so a zero-width-split
// token still folds to one token.
func scanHomoglyph(line []rune, lineno int, rel, key string, out *[]findings.Finding, isCode bool, nearbyNative map[string]bool) {
	emitted := 0
	governed := governedKeys[key]

	emit := func(text, normalized []rune, scripts []string, subs []sub, col int, container []rune, offset int) {
		if emitted > findings.Cap { // retain one overflow item so the outer cap emits a summary
			return
		}
		emitted++
		display, displayNormalized := text, normalized
		if container != nil {
			display = container
			displayNormalized = slices.Concat(container[:offset], normalized, container[offset+len(text):])
		}
		shown, shownNormalized := prefix(display, evidenceTextCap), prefix(displayNormalized, evidenceTextCap)
		severity, tail := "high", "Reviewer and model resolve this token differently."
		if governed {
			severity = "critical"
			tail = fmt.Sprintf("It sits in the always-resident `%s` field, so this is the string the operator trusts at invocation time.", key)
		}
		var governingKey any
		if key != "" {
			governingKey = key
		}
		scriptList, substitutions := []any{}, []any{}
		for _, s := range scripts {
			scriptList = append(scriptList, s)
		}
		for _, s := range subs[:min(evidenceSubCap, len(subs))] {
			name, folded := cmp.Or(runenames.Name(s.c), "?"), confusables[s.c]
			to := norm.NFKC.String(string(s.c))
			if folded != 0 {
				to = string(folded)
			}
			substitutions = append(substitutions, fmt.Sprintf("U+%04X %s -> %s", s.c, name, to))
		}
		mk(out, rel, "SXV-015", "mixed_script_token", severity, lineno, col,
			fmt.Sprintf("Token %s mixes %s and reads as %s after confusable folding. %s",
				pytext.Repr(shown), strings.Join(scripts, " + "), pytext.Repr(shownNormalized), tail),
			map[string]any{"token": shown, "normalized": shownNormalized, "scripts": scriptList,
				"token_truncated": len(display) > evidenceTextCap, "governing_key": governingKey, "substitutions": substitutions})
	}

	analyze := func(text []rune, col int, domainLike bool, container []rune, offset int) {
		var letters []rune
		for _, c := range text {
			if unicode.IsLetter(c) {
				letters = append(letters, c)
			}
		}
		if len(letters) < 2 { // a single glyph cannot spell a spoofed word
			return
		}
		scripts := map[string]bool{}
		for _, c := range letters {
			if s := scriptOf(c); s != "OTHER" {
				scripts[s] = true
			}
		}
		// Compatibility matching excludes ordinary typographic ligatures.
		if nfkc := []rune(norm.NFKC.String(string(text))); !slices.Equal(nfkc, text) && foldsToWord(nfkc) && slices.ContainsFunc(text, isCompatSpoofLetter) {
			var subs []sub
			for i, c := range text {
				if isCompatSpoofLetter(c) {
					subs = append(subs, sub{i, c})
				}
			}
			emit(text, nfkc, []string{"COMPAT"}, subs, col, container, offset)
			return
		}
		var subs []sub
		normalized := make([]rune, len(text))
		for i, c := range text {
			normalized[i] = c
			if p, ok := confusables[c]; ok {
				subs = append(subs, sub{i, c})
				normalized[i] = p
			}
		}
		if len(subs) == 0 {
			return
		}
		subScripts := map[string]bool{}
		for _, s := range subs {
			subScripts[scriptOf(s.c)] = true
		}
		// Whole-script spoofs require every letter to be Latin-confusable. In prose an otherwise
		// native-script line is evidence of ordinary language, not impersonation; stay strict in
		// governed metadata, domains, mixed-language code lines and Latin-context prose.
		if !scripts["LATIN"] && len(scripts) == 1 {
			if !slices.ContainsFunc(letters, func(c rune) bool { _, ok := confusables[c]; return !ok }) && foldsToWord(normalized) {
				script := slices.Collect(maps.Keys(scripts))[0]
				lineScripts := map[string]bool{}
				for _, c := range line {
					if unicode.IsLetter(c) {
						lineScripts[scriptOf(c)] = true
					}
				}
				onlyScript := len(lineScripts) == 1 && lineScripts[script]
				nativeContext := nativeCount(line, script) >= 2 || onlyScript && nearbyNative[script]
				safeLanguageContext := !isCode || onlyScript
				if !governed && safeLanguageContext && !domainLike && nativeContext {
					return
				}
				emit(text, normalized, slices.Sorted(maps.Keys(scripts)), subs, col, container, offset)
			}
			return
		}
		// Same-script Latin matching is limited to spoof-only phonetic look-alikes.
		if len(scripts) == 1 && scripts["LATIN"] {
			var hidden []sub
			for _, s := range subs {
				if isSpoofOnlyLatin(s.c) {
					hidden = append(hidden, s)
				}
			}
			if len(hidden) > 0 && slices.ContainsFunc(letters, func(c rune) bool { return c <= 0x7F }) && foldsToWord(normalized) {
				start := col - 1
				slashDelimited := start > 0 && line[start-1] == '/' && start+len(text) < len(line) && line[start+len(text)] == '/'
				if !governed && !isCode && !domainLike && slashDelimited {
					return
				}
				emit(text, normalized, []string{"LATIN"}, hidden, col, container, offset)
			}
			return
		}
		if len(scripts) < 2 || !scripts["LATIN"] {
			return
		}
		// Every non-Latin letter must fold to Latin and the result must read as a plain word, or
		// this is genuine mixed-script text, not a spoof.
		for _, c := range letters {
			if _, ok := confusables[c]; !ok && scriptOf(c) != "LATIN" {
				return
			}
		}
		if !foldsToWord(normalized) {
			return
		}
		// Scientific-notation exemption for a lone boundary Greek glyph, never in a governed field.
		if !governed && len(subScripts) == 1 && subScripts["GREEK"] && looksScientific(text, subs, domainLike) {
			return
		}
		emit(text, normalized, slices.Sorted(maps.Keys(scripts)), subs, col, container, offset)
	}

	analyzeBounded := func(text []rune, col int, domainLike bool, container []rune, offset int) {
		if len(text) <= homoglyphChunk {
			analyze(text, col, domainLike, container, offset)
			return
		}
		// One-character overlap preserves script boundaries while keeping work bounded.
		for o := 0; o < len(text) && emitted <= findings.Cap; o += homoglyphChunk - 1 {
			analyze(text[o:min(o+homoglyphChunk, len(text))], col+o, domainLike, nil, 0)
		}
	}

	flush := func(tok []rune, col int) {
		text, lead := trimEdge(tok) // advance col past the stripped edge
		domainLike := slices.Contains(text, '.')
		for o := 0; o < len(text); {
			if strings.ContainsRune("._-", text[o]) {
				o++
				continue
			}
			end := o
			for end < len(text) && !strings.ContainsRune("._-", text[end]) {
				end++
			}
			analyzeBounded(text[o:end], col+lead+o, domainLike, text, o)
			o = end
		}
	}

	var token []rune
	start := 0
	for i, ch := range line {
		switch {
		case pytext.IsSpace(ch) || strings.ContainsRune(tokenBreak, ch):
			flush(token, start+1)
			token, start = nil, i+1
		case isInvisible(ch):
		default:
			if len(token) == 0 {
				start = i
			}
			token = append(token, ch)
		}
	}
	flush(token, start+1)
}
