// Package uba is the Unicode Bidirectional Algorithm core of golang.org/x/text/unicode/bidi
// (core.go and bracket.go copied verbatim from v0.42.0, BSD-3-Clause, see NOTICE).
// The public bidi.Paragraph API can neither force paragraph level 0 nor apply rule L2, which
// python-bidi's get_display(line, base_dir="L") does; the copy exposes both through Visual.
package uba

import "golang.org/x/text/unicode/bidi"

// Class is bidi.Class; a local type so the copied methods compile unchanged.
type Class bidi.Class

const (
	L   = Class(bidi.L)
	R   = Class(bidi.R)
	EN  = Class(bidi.EN)
	ES  = Class(bidi.ES)
	ET  = Class(bidi.ET)
	AN  = Class(bidi.AN)
	CS  = Class(bidi.CS)
	B   = Class(bidi.B)
	S   = Class(bidi.S)
	WS  = Class(bidi.WS)
	ON  = Class(bidi.ON)
	BN  = Class(bidi.BN)
	NSM = Class(bidi.NSM)
	AL  = Class(bidi.AL)
	LRO = Class(bidi.LRO)
	RLO = Class(bidi.RLO)
	LRE = Class(bidi.LRE)
	RLE = Class(bidi.RLE)
	PDF = Class(bidi.PDF)
	LRI = Class(bidi.LRI)
	RLI = Class(bidi.RLI)
	FSI = Class(bidi.FSI)
	PDI = Class(bidi.PDI)

	unknownClass = ^Class(0)
)

// Visual returns line in visual order for a forced left-to-right paragraph, controls included
// (python-bidi get_display(line, base_dir="L")). A class-B rune ends a paragraph (P1) and is
// kept at its end, as unicode-bidi does.
func Visual(line []rune) []rune {
	out := make([]rune, 0, len(line))
	for start := 0; start < len(line); {
		end := start
		for end < len(line) {
			p, _ := bidi.LookupRune(line[end])
			end++
			if p.Class() == bidi.B { // the B stays at the paragraph's end
				break
			}
		}
		out = append(out, paragraphVisual(line[start:end])...)
		start = end
	}
	return out
}

// paragraphVisual is bidi.Paragraph.prepareInput plus the forced level and rule L2.
// ponytail: N0 pairing inert (raw rune pair values, as upstream), upgrade = BidiBrackets
// closer-to-opener table.
func paragraphVisual(para []rune) []rune {
	types := make([]Class, len(para))
	pairTypes := make([]bracketType, len(para))
	pairValues := make([]rune, len(para))
	for i, r := range para {
		p, _ := bidi.LookupRune(r)
		types[i] = Class(p.Class())
		switch {
		case p.IsOpeningBracket():
			pairTypes[i], pairValues[i] = bpOpen, r
		case p.IsBracket():
			pairTypes[i], pairValues[i] = bpClose, r
		}
	}
	p, _ := newParagraph(types, pairTypes, pairValues, 0) // one non-empty paragraph by construction; a nil p panics into scanArtifact's recover
	out := make([]rune, len(para))
	for i, j := range p.getReordering([]int{len(para)}) {
		out[i] = para[j]
	}
	return out
}
