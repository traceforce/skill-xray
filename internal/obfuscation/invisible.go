package obfuscation

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/bidi"
	"golang.org/x/text/unicode/runenames"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/uba"
)

var (
	bidiNames = map[rune]string{0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO", 0x202E: "RLO",
		0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI"}
	dirMarkNames   = map[rune]string{0x200E: "LRM", 0x200F: "RLM", 0x061C: "ALM"}
	zeroWidthNames = map[rune]string{0x200B: "ZWSP", 0x200C: "ZWNJ", 0x200D: "ZWJ", 0x2060: "WJ", 0xFEFF: "BOM", 0x180E: "MVS"}
	// Default-ignorables with legitimate typography uses are excluded or handled separately.
	invisibleExtra = map[rune]string{
		0x00AD: "SOFT HYPHEN", // renders as nothing mid-word: a zero-width channel
		0x2061: "FUNCTION APPLICATION", 0x2062: "INVISIBLE TIMES", 0x2063: "INVISIBLE SEPARATOR", 0x2064: "INVISIBLE PLUS",
		0x206A: "INHIBIT SYMMETRIC SWAPPING", 0x206B: "ACTIVATE SYMMETRIC SWAPPING",
		0x206C: "INHIBIT ARABIC FORM SHAPING", 0x206D: "ACTIVATE ARABIC FORM SHAPING",
		0x206E: "NATIONAL DIGIT SHAPES", 0x206F: "NOMINAL DIGIT SHAPES",
		0xFFF9: "INTERLINEAR ANNOTATION ANCHOR", 0xFFFA: "INTERLINEAR ANNOTATION SEPARATOR", 0xFFFB: "INTERLINEAR ANNOTATION TERMINATOR",
		0x180B: "MONGOLIAN FVS1", 0x180C: "MONGOLIAN FVS2", 0x180D: "MONGOLIAN FVS3",
	}
	rgiFlagTags = map[string]bool{"gbeng": true, "gbsct": true, "gbwls": true}
	// Extended_Pictographic cannot be derived from general category.
	pictographicRanges = [][2]rune{
		{0x00A9, 0x00A9}, {0x00AE, 0x00AE}, {0x203C, 0x203C}, {0x2049, 0x2049}, {0x2122, 0x2122}, {0x2139, 0x2139},
		{0x2194, 0x21AA}, {0x231A, 0x2328}, {0x2388, 0x2388}, {0x23CF, 0x23FA}, {0x24C2, 0x24C2}, {0x25AA, 0x25FE},
		{0x2600, 0x27BF}, {0x2934, 0x2935}, {0x2B00, 0x2BFF}, {0x3030, 0x3030}, {0x303D, 0x303D}, {0x3297, 0x3297},
		{0x3299, 0x3299}, {0x1F000, 0x1FAFF}, {0x1FC00, 0x1FFFD},
	}
)

const (
	evidenceTextCap = 200
	evidenceSubCap  = 32
)

func isEmojiBase(r rune) bool {
	for _, p := range pictographicRanges {
		if p[0] <= r && r <= p[1] {
			return true
		}
	}
	return false
}

// isCJK covers the BMP and Ext-A ideographs, compatibility ideographs and the supplementary
// planes through Ext-H; a variation selector after one is presentation, not smuggling.
func isCJK(r rune) bool {
	return 0x3400 <= r && r <= 0x9FFF || 0xF900 <= r && r <= 0xFAFF || 0x20000 <= r && r <= 0x2FA1F || 0x30000 <= r && r <= 0x323AF
}

// isDefaultIgnorable is the default-ignorables not caught elsewhere: CGJ, Hangul fillers, the
// musical invisibles.
func isDefaultIgnorable(r rune) bool {
	return r == 0x034F || 0x115F <= r && r <= 0x1160 || 0x17B4 <= r && r <= 0x17B5 || r == 0x180F || r == 0x2065 ||
		r == 0x3164 || r == 0xFFA0 || 0xFFF0 <= r && r <= 0xFFF8 || 0x1BCA0 <= r && r <= 0x1BCA3 || 0x1D173 <= r && r <= 0x1D17A
}

// isInvisible is a code point that renders as nothing: any Cf, a variation selector, an extra
// invisible or a default-ignorable; ordinary combining accents (Mn) are not invisible.
func isInvisible(r rune) bool {
	return unicode.Is(unicode.Cf, r) || 0xFE00 <= r && r <= 0xFE0F || 0xE0100 <= r && r <= 0xE01EF ||
		invisibleExtra[r] != "" || isDefaultIgnorable(r)
}

func stripInvisible(rs []rune) []rune {
	return slices.DeleteFunc(slices.Clone(rs), isInvisible)
}

// legitimateJoinerContext is an actual Arabic-letter or Indic-virama shaping context for a
// ZWJ/ZWNJ; a range-only test would turn arbitrary Arabic/Indic characters into a bypass.
func legitimateJoinerContext(prev, nxt rune) bool {
	if unicode.IsLetter(prev) && unicode.IsLetter(nxt) && scriptOf(prev) == "ARABIC" && scriptOf(nxt) == "ARABIC" {
		return true
	}
	name := runenames.Name(prev)
	return (strings.Contains(name, "VIRAMA") || strings.Contains(name, "HALANT")) &&
		(unicode.IsLetter(nxt) || unicode.Is(unicode.M, nxt))
}

// readableOrder is the characters an LTR reviewer reads for meaning: not strong-RTL, not
// Arabic-Indic digits, not whitespace, and here also not a bidi control (the Python strips
// those from both sides before comparing).
func readableOrder(rs []rune) []rune {
	var out []rune
	for _, r := range rs {
		p, _ := bidi.LookupRune(r)
		if c := p.Class(); bidiNames[r] == "" && c != bidi.R && c != bidi.AL && c != bidi.AN && !pytext.IsSpace(r) {
			out = append(out, r)
		}
	}
	return out
}

func stripDirMarks(rs []rune) []rune {
	return slices.DeleteFunc(slices.Clone(rs), func(r rune) bool { return dirMarkNames[r] != "" })
}

// firstStrongDir is the direction of the first strong character: "L", "R" (incl. AL) or "".
func firstStrongDir(rs []rune) string {
	for _, r := range rs {
		p, _ := bidi.LookupRune(r)
		switch p.Class() {
		case bidi.L:
			return "L"
		case bidi.R, bidi.AL:
			return "R"
		}
	}
	return ""
}

// bidiReordersReadable is true when explicit bidi controls make the readable text render in a
// different order than logical under a forced-LTR paragraph (Trojan-Source).
func bidiReordersReadable(line []rune) bool {
	return !slices.Equal(readableOrder(line), readableOrder(uba.Visual(line)))
}

// hit is one flagged code point and its 1-based column.
type hit struct {
	col int
	cp  rune
}

func codes(hs []hit, n int, format string, names map[rune]string) []any {
	out := []any{}
	for _, h := range hs[:min(n, len(hs))] {
		if names != nil {
			out = append(out, fmt.Sprintf(format, h.cp, names[h.cp]))
		} else {
			out = append(out, fmt.Sprintf(format, h.cp))
		}
	}
	return out
}

func sortedNames(hs []hit, names map[rune]string) []string {
	set := map[string]bool{}
	for _, h := range hs {
		set[names[h.cp]] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// scanInvisible classifies every format/invisible code point on one non-ASCII line and emits
// at most one finding per class; the first matching branch wins for each code point.
func scanInvisible(line []rune, lineno int, rel string, out *[]findings.Finding, isCode bool) {
	var tagCps, zwRuns, bidiHits, suppVS, dirSplits, cjkVS []hit
	at := func(i int) rune { // "" is -1
		if 0 <= i && i < len(line) {
			return line[i]
		}
		return -1
	}
	isVS := func(r rune) bool { return 0xFE00 <= r && r <= 0xFE0F }
	for i, cp := range line {
		col := i + 1
		switch {
		case 0xE0000 <= cp && cp <= 0xE007F:
			tagCps = append(tagCps, hit{col, cp})
		case bidiNames[cp] != "":
			bidiHits = append(bidiHits, hit{col, cp})
		case 0xE0100 <= cp && cp <= 0xE01EF:
			// Sparse CJK variation sequences are legitimate; dense/non-CJK use is a channel.
			if isCJK(at(i - 1)) {
				cjkVS = append(cjkVS, hit{col, cp})
			} else {
				suppVS = append(suppVS, hit{col, cp})
			}
		case isVS(cp):
			prev, nxt := at(i-1), at(i+1)
			// Keycaps need their combiner; emoji accept only VS15/VS16.
			isKeycap := cp == 0xFE0F && prev >= 0 && strings.ContainsRune("0123456789#*", prev) && nxt == 0x20E3
			emojiPres := (cp == 0xFE0E || cp == 0xFE0F) && isEmojiBase(prev)
			switch {
			case emojiPres || isKeycap: // legitimate emoji/keycap presentation
			case isCJK(prev):
				cjkVS = append(cjkVS, hit{col, cp}) // sparse SVS spared, dense run fired below
			default:
				zwRuns = append(zwRuns, hit{col, cp})
			}
		case dirMarkNames[cp] != "":
			// Directional marks split same-script words; inspect each run once.
			if dirMarkNames[at(i-1)] != "" {
				continue
			}
			prev := at(i - 1)
			run := []hit{{col, cp}}
			j := i + 1
			for j < len(line) && dirMarkNames[line[j]] != "" {
				run = append(run, hit{j + 1, line[j]})
				j++
			}
			nxt := at(j)
			if isCode || len(run) >= 2 { // executable text and repeated runs get no boundary exemption
				dirSplits = append(dirSplits, run...)
			} else if unicode.IsLetter(prev) && unicode.IsLetter(nxt) {
				if s := scriptOf(prev); s != "OTHER" && s == scriptOf(nxt) {
					dirSplits = append(dirSplits, run...)
				}
			}
		case isInvisible(cp): // any remaining Cf / default-ignorable
			if cp == 0xFEFF && col == 1 && lineno == 1 {
				continue // leading BOM: encoding metadata, benign
			}
			if cp == 0x200C || cp == 0x200D {
				if prev, nxt := at(i-1), at(i+1); prev >= 0 && nxt >= 0 && legitimateJoinerContext(prev, nxt) {
					continue // legitimate Arabic/Indic orthographic joiner
				}
			}
			if cp == 0x200D {
				pj := i - 1
				if pj >= 1 && isVS(line[pj]) {
					pj-- // step back over a leading VS16 to the base (rainbow/trans/heart flags)
				}
				prev, nxt := at(pj), at(i+1)
				if isVS(nxt) && i+2 < len(line) {
					nxt = line[i+2] // step over a trailing VS to the joined char
				}
				if isEmojiBase(prev) && isEmojiBase(nxt) {
					continue // a normal emoji ZWJ sequence: benign
				}
			}
			zwRuns = append(zwRuns, hit{col, cp})
		}
	}

	if len(tagCps) > 0 {
		decode := func(hs []hit) []rune {
			out := make([]rune, len(hs))
			for i, h := range hs {
				out[i] = h.cp - 0xE0000
			}
			return out
		}
		decoded := decode(tagCps[:min(evidenceTextCap, len(tagCps))])
		// Every tag run needs its own valid RGI subdivision-flag base and cancel tag.
		allFlags := true
		for start := 0; start < len(tagCps) && allFlags; {
			end := start + 1
			for end < len(tagCps) && tagCps[end].col == tagCps[end-1].col+1 {
				end++
			}
			run := tagCps[start:end]
			allFlags = len(run) == 6 && at(run[0].col-2) == 0x1F3F4 && run[5].cp == 0xE007F && rgiFlagTags[string(decode(run[:5]))]
			start = end
		}
		if !allFlags {
			mk(out, rel, "SXV-014", "tag_block", "critical", lineno, tagCps[0].col,
				fmt.Sprintf("Unicode tag block (U+E0000-U+E007F) carries %d codepoints of instruction text that render as nothing. Decoded payload: %s",
					len(tagCps), pytext.Repr(prefix(decoded, 160))),
				map[string]any{"codepoint_count": len(tagCps), "decoded_payload": string(decoded),
					"decoded_truncated": len(tagCps) > evidenceTextCap, "first_codepoint": fmt.Sprintf("U+%04X", tagCps[0].cp)})
		}
	}

	if len(bidiHits) > 0 {
		hard := slices.ContainsFunc(bidiHits, func(h hit) bool { return h.cp == 0x202D || h.cp == 0x202E }) // LRO/RLO: no legitimate use
		fire, engine := true, "code-context"                                                                // code never carries legitimate bidi controls
		if !isCode {
			// Strip injected marks before deciding whether genuine RTL prose is exempt.
			fire, engine = hard || (bidiReordersReadable(line) && firstStrongDir(stripDirMarks(line)) != "R"), "uba"
		}
		if fire {
			logical := stripRunes(stripInvisible(line))
			mk(out, rel, "SXV-014", "bidi_override", "critical", lineno, bidiHits[0].col,
				fmt.Sprintf("Bidirectional controls (%s) reorder the rendered text so a reviewer reads a different order than the agent or shell receives (Trojan-Source). Logical order: %s",
					strings.Join(sortedNames(bidiHits, bidiNames), ", "), pytext.Repr(prefix(logical, 120))),
				map[string]any{"control_count": len(bidiHits), "controls": codes(bidiHits, evidenceSubCap, "U+%04X %s", bidiNames),
					"controls_truncated": len(bidiHits) > evidenceSubCap, "logical_order": prefix(logical, evidenceTextCap),
					"logical_order_truncated": len(line) > evidenceTextCap, "engine": engine})
		}
	}

	if len(suppVS) > 0 {
		bytes := []any{}
		for _, h := range suppVS[:min(64, len(suppVS))] {
			bytes = append(bytes, int(h.cp-0xE0100+16))
		}
		mk(out, rel, "SXV-014", "variation_selector_smuggling", "critical", lineno, suppVS[0].col,
			fmt.Sprintf("%d supplementary variation selector(s) (U+E0100-U+E01EF) carry no presentation meaning and encode %d hidden byte value(s) behind the preceding glyph.",
				len(suppVS), len(suppVS)),
			map[string]any{"codepoint_count": len(suppVS), "decoded_bytes": bytes})
	}

	if len(cjkVS) > 0 {
		// A byte channel is a line-wide run of varying selectors; a sparse or uniform selector set
		// (one glyph variant, or the same selector repeated) stays a low note.
		distinct := map[rune]bool{}
		for _, h := range cjkVS {
			distinct[h.cp] = true
		}
		if len(cjkVS) >= 4 && len(distinct) >= 2 {
			mk(out, rel, "SXV-014", "variation_selector_smuggling", "critical", lineno, cjkVS[0].col,
				fmt.Sprintf("%d variation selector(s), each hidden behind a CJK ideograph, carry %d distinct values on one line; a varying selector run is a byte channel, not presentation.",
					len(cjkVS), len(distinct)),
				map[string]any{"codepoint_count": len(cjkVS), "distinct_values": len(distinct), "codepoints": codes(cjkVS, 64, "U+%04X", nil)})
		} else {
			mk(out, rel, "SXV-014", "variation_selector_isolated", "low", lineno, cjkVS[0].col,
				fmt.Sprintf("%d CJK-anchored variation selector(s), most likely legitimate IVS/SVS; retained as a low note because repeated selectors can form a hidden channel.", len(cjkVS)),
				map[string]any{"codepoint_count": len(cjkVS), "codepoints": codes(cjkVS, 64, "U+%04X", nil)})
		}
	}

	if len(zwRuns) > 0 && !(len(zwRuns) == 1 && zwRuns[0].cp == 0x00AD) { // a lone soft hyphen is a hyphenation hint
		recovered := stripRunes(stripInvisible(line))
		runOfTwo := len(zwRuns) >= 2 // >= 2 zero-widths is a hidden run: escalate
		classes := map[string]bool{}
		for _, h := range zwRuns {
			classes[cmp.Or(zeroWidthNames[h.cp], invisibleExtra[h.cp], fmt.Sprintf("U+%04X", h.cp))] = true
		}
		sorted := slices.Sorted(maps.Keys(classes))
		rule, severity, phrase := "zero_width_isolated", "medium", "present outside any emoji sequence"
		if runOfTwo {
			rule, severity, phrase = "zero_width_run", "critical", "form a hidden zero-width run in the text, defeating substring matching"
		}
		tracked := len(zeroWidthNames) + len(invisibleExtra) // a rule lists each code point once; a channel needs more
		if patternDataFileRE.MatchString(rel) && len(zwRuns) <= tracked && inPatternValue(string(line[:zwRuns[0].col])) {
			rule, severity = "zero_width_pattern_data", "low" // a detector's own regex value
		}
		classList := []any{}
		for _, c := range sorted {
			classList = append(classList, c)
		}
		mk(out, rel, "SXV-014", rule, severity, lineno, zwRuns[0].col,
			fmt.Sprintf("%d zero-width/invisible codepoint(s) (%s) %s. De-obfuscated line: %s",
				len(zwRuns), strings.Join(sorted, ", "), phrase, pytext.Repr(prefix(recovered, 160))),
			map[string]any{"codepoint_count": len(zwRuns), "classes": classList,
				"deobfuscated": prefix(recovered, evidenceTextCap), "deobfuscated_truncated": len(recovered) > evidenceTextCap})
	}

	if len(dirSplits) > 0 {
		recovered := stripRunes(stripInvisible(line))
		mk(out, rel, "SXV-014", "directional_mark_split", "critical", lineno, dirSplits[0].col,
			fmt.Sprintf("%d invisible directional mark(s) (%s) split a word between same-script letters, hiding it from substring matching. De-obfuscated line: %s",
				len(dirSplits), strings.Join(sortedNames(dirSplits, dirMarkNames), ", "), pytext.Repr(prefix(recovered, 160))),
			map[string]any{"codepoint_count": len(dirSplits), "marks": codes(dirSplits, evidenceSubCap, "U+%04X %s", dirMarkNames),
				"marks_truncated": len(dirSplits) > evidenceSubCap, "deobfuscated": prefix(recovered, evidenceTextCap),
				"deobfuscated_truncated": len(recovered) > evidenceTextCap})
	}
}
