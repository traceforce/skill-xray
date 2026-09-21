// Package persistence reports SXV-005 identity-persistence-write findings from the parsed IR,
// Python checks/persistence.py: an instruction-lane write of concealment or priority content
// into an agent identity file.
package persistence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

const evidenceLimit = 400

func identityAlternation() string {
	names := slices.Sorted(maps.Keys(ingest.IdentityFiles))
	slices.Reverse(names)
	for i, n := range names {
		names[i] = regexp.QuoteMeta(n)
	}
	return strings.Join(names, "|")
}

const verbs = `(?:append|write|add|insert|save|persist|store|replace|overwrite|prepend|update|edit|copy)`

var (
	// _IDENTITY_TARGET without its lookarounds; identityTargets applies them.
	identityTargetRE = pytext.PyRE(`(?i)(?:` + identityAlternation() + `)`)
	identityAfterRE  = pytext.PyRE(`^(?:[A-Za-z0-9_/\\-]|\.[A-Za-z0-9])`)
	writeRE          = pytext.PyRE(`(?i)\b` + verbs + `\w*\b`)
	// _QUOTED without its backreference; quoted keeps only matches whose quotes agree.
	quotedRE     = pytext.PyRE(`(['"])([^'"\n]{1,600})(['"])`)
	aggravatorRE = pytext.PyRE(`(?i)\b(?:always\s+(?:obey|follow|prioriti[sz]e)|never\s+(?:reveal|disclose|remove)|` +
		`do\s+not\s+(?:reveal|disclose|mention|remove)|don['’]t\s+(?:reveal|disclose|mention)|` +
		`secretly|without\s+(?:telling|` +
		`notifying)|(?:cannot|must\s+not|do\s+not)\s+(?:be\s+)?(?:delete|remove)|` +
		`(?:hidden|concealed)\s+(?:rule|instruction|directive|content)|` +
		`(?:hide|conceal)\s+(?:this|the)\s+(?:rule|instruction|directive|content)|` +
		`higher\s+priority|(?:ignore|override)\s+(?:other|prior|previous)\s+instructions?|` +
		`(?:load|follow)\s+(?:this|it)\s+(?:on|every)\s+(?:startup|session))\b`)
	contentIntroRE = pytext.PyRE(`(?i)(?:\b(?:following|below|this)\s+(?:block|text|content|instructions?)\b|:\s*$)`)
	blockPrefixRE  = pytext.PyRE(`^\s*(?:>|[-*+]\s|\d+[.)]\s|` + "```" + `)`)
	defensiveRE    = pytext.PyRE(`(?i)\b(?:check|detector|rule|scanner)\s+(?:detects|flags|identifies|reports)\b` +
		`[^.;!?\n]{0,160}\b(?:that|which)\s+[^.;!?\n]{0,80}\b` + verbs + `\w*\b`)
	exampleRE       = pytext.PyRE(`(?i)\b(?:for\s+example|e\.g\.)\s*,?\s+(?:an?\s+)?(?:attacker|malicious\s+skill)\b[^;.!?\n]{0,300}`)
	nextOperationRE = pytext.PyRE(`(?i)(?:\s+\b(?:and|then)|\s*,)\s+(?:(?:note|mention|describe|explain|report)|` + verbs + `)\b`)
	htmlCommentRE   = pytext.PyRE(`(?s)<!--.*?-->`)
	// _target_attached_before_write / _target_attached_after_write / payload-quote inlines.
	introducedRE  = pytext.PyRE(`(?i)\b(?:in|into|to|within)\s+[^;!?]{0,200}\n?\z`)
	connectorRE   = pytext.PyRE(`(?i)\A\s*,?\s*(?:(?:must|should|will|shall|is|be)\s+)+\z`)
	commaOnlyRE   = pytext.PyRE(`\A\s*,?\s*\z`)
	otherFileRE   = pytext.PyRE(`(?i)\b[A-Za-z0-9_-]+\.[A-Za-z0-9]{1,12}\b`)
	destinationRE = pytext.PyRE(`(?i)\b(?:to|into|in|within)\s+[` + "`" + `'"]?(?:[~./\\\w-]+[/\\])?\n?\z`)
	bareDestRE    = pytext.PyRE(`(?i)\A\s+(?:the\s+)?(?:[~./\\\w-]+[/\\])?\z`)
	payloadLeadRE = pytext.PyRE(`(?i)\A\s*(?:the\s+)?(?:text|content|instructions?)?\s*\z`)
)

func isTargetEdge(r rune) bool {
	return r < utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' || r == '-')
}

// identityTargets is _IDENTITY_TARGET.finditer: (?<![A-Za-z0-9_.-]) … (?![A-Za-z0-9_/\\-]|\.[A-Za-z0-9]).
func identityTargets(s string) [][]int {
	return pytext.FindAllIf(identityTargetRE, s, func(m []int) bool {
		prev, _ := utf8.DecodeLastRuneInString(s[:m[0]])
		return !(m[0] > 0 && isTargetEdge(prev)) && !identityAfterRE.MatchString(s[m[1]:])
	})
}

// quoted is _QUOTED.finditer: the closing quote must repeat the opening one.
func quoted(s string) [][]int {
	return pytext.FindAllIf(quotedRE, s, func(m []int) bool { return s[m[2]:m[3]] == s[m[6]:m[7]] })
}

func isAlnum(r rune) bool { return unicode.IsLetter(r) || unicode.IsNumber(r) }

// clauseEnds yields the byte offset after each clause-ending ; ! ? or sentence-final dot
// outside quotes; a ' between two alphanumerics is an apostrophe.
func clauseEnds(text string) []int {
	var ends []int
	var quote rune
	escaped := false
	for i, w := 0, 0; i < len(text); i += w {
		var c rune
		c, w = utf8.DecodeRuneInString(text[i:])
		next, _ := utf8.DecodeRuneInString(text[i+w:])
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && quote != 0 {
			escaped = true
			continue
		}
		if c == '\'' || c == '"' {
			prev, _ := utf8.DecodeLastRuneInString(text[:i])
			if !(c == '\'' && i > 0 && i+w < len(text) && isAlnum(prev) && isAlnum(next)) {
				switch quote {
				case c:
					quote = 0
				case 0:
					quote = c
				}
				continue
			}
		}
		if quote == 0 && (strings.ContainsRune(";!?", c) || (c == '.' && (i+w == len(text) || pytext.IsSpace(next)))) {
			ends = append(ends, i+w)
		}
	}
	return ends
}

func attachedBeforeWrite(clause string, target, write []int) bool {
	before := clause[:target[0]]
	between := clause[target[1]:write[0]]
	return (introducedRE.MatchString(before) && commaOnlyRE.MatchString(between)) || connectorRE.MatchString(between)
}

func attachedAfterWrite(clause string, target, write []int) bool {
	between := clause[write[1]:target[0]]
	if otherFileRE.MatchString(between) {
		return false
	}
	return destinationRE.MatchString(between) || bareDestRE.MatchString(between)
}

func starts(ms [][]int) []int {
	out := make([]int, len(ms))
	for i, m := range ms {
		out[i] = m[0]
	}
	return out
}

type operation struct {
	clauseStart   int
	target, write []int
	content       string
}

// findOperation is the clause loop of check: the first write whose identity target carries an
// aggravated payload, or nil.
func findOperation(block, nextBlock string) *operation {
	clauseStart := 0
	for _, clauseEnd := range append(clauseEnds(block), len(block)) {
		clause := block[clauseStart:clauseEnd]
		targets := identityTargets(clause)
		targetStarts := starts(targets)
		operationBoundaries := starts(nextOperationRE.FindAllStringIndex(clause, -1))
		for _, write := range writeRE.FindAllStringIndex(clause, -1) {
			operationEnd := len(clause)
			if i := sort.Search(len(operationBoundaries), func(i int) bool { return operationBoundaries[i] > write[0] }); i < len(operationBoundaries) {
				operationEnd = operationBoundaries[i]
			}
			var target []int
			if i := sort.SearchInts(targetStarts, write[1]); i < len(targets) && targets[i][0] < operationEnd {
				target = targets[i]
			}
			if target != nil && !attachedAfterWrite(clause, target, write) {
				target = nil
			}
			if target == nil {
				if i := sort.SearchInts(targetStarts, write[0]) - 1; i >= 0 && attachedBeforeWrite(clause, targets[i], write) {
					target = targets[i]
				}
			}
			if target == nil {
				continue
			}
			persisted := clause[write[0]:operationEnd]
			introducedBlock := nextBlock != "" && contentIntroRE.MatchString(persisted) && blockPrefixRE.MatchString(nextBlock)
			correlated := persisted
			if introducedBlock {
				correlated += "\n" + nextBlock
			}
			quotes := quoted(correlated)
			var content string
			found := false
			for _, q := range quotes {
				if c := correlated[q[4]:q[5]]; aggravatorRE.MatchString(c) {
					content, found = c, true
					break
				}
			}
			firstQuoteIsPayload := len(quotes) > 0 && payloadLeadRE.MatchString(correlated[write[1]-write[0]:quotes[0][0]])
			switch {
			case !found && !firstQuoteIsPayload && aggravatorRE.MatchString(persisted):
				content, found = persisted, true
			case !found && introducedBlock && aggravatorRE.MatchString(nextBlock):
				content, found = nextBlock, true
			}
			if found {
				return &operation{clauseStart, target, write, content}
			}
		}
		clauseStart = clauseEnd
	}
	return nil
}

// Check is persistence.check: one SXV-005 finding at most per prose span.
func Check(p *parse.Package) []findings.Finding {
	var out []findings.Finding
	for _, a := range p.Artifacts {
		if !parse.InstructionKinds[a.Kind] || a.Text == nil || *a.Text == "" || a.Markdown == nil {
			continue
		}
		lines := pytext.SplitLines(*a.Text)
		for index, span := range a.Markdown.ProseSpans {
			block := pytext.JoinLines(lines, span.Start-1, span.End)
			block = htmlCommentRE.ReplaceAllStringFunc(block, pytext.BlankKeepNewlines)
			block = defensiveRE.ReplaceAllStringFunc(block, pytext.BlankKeepNewlines)
			block = exampleRE.ReplaceAllStringFunc(block, pytext.BlankKeepNewlines)
			var following []string
			previousEnd := span.End
			for _, next := range a.Markdown.ProseSpans[index+1:] {
				if next.Start-previousEnd > 2 {
					break
				}
				candidate := pytext.JoinLines(lines, next.Start-1, next.End)
				if !blockPrefixRE.MatchString(candidate) {
					break
				}
				following = append(following, candidate)
				previousEnd = next.End
			}
			op := findOperation(block, strings.Join(following, "\n"))
			if op == nil {
				continue
			}
			beforeTarget := block[:op.clauseStart+op.target[0]]
			line := span.Start + strings.Count(beforeTarget, "\n")
			column := utf8.RuneCountInString(beforeTarget[strings.LastIndex(beforeTarget, "\n")+1:]) + 1
			clause := block[op.clauseStart:]
			target := clause[op.target[0]:op.target[1]]
			content := []rune(op.content)
			sum := sha256.Sum256([]byte(op.content))
			out = append(out, findings.Finding{
				Vector: "SXV-005", Rule: "identity-persistence-write", Severity: "critical",
				Path: a.Rel, Line: findings.Int(line), Column: findings.Int(column),
				Message: fmt.Sprintf("instructs the agent to persist concealed or priority instructions in `%s`", target),
				Evidence: map[string]any{
					"identity_target":   target,
					"persisted_content": string(content[:min(len(content), evidenceLimit)]),
					"content_length":    len(content),
					"content_sha256":    hex.EncodeToString(sum[:]),
					"truncated":         len(content) > evidenceLimit,
					"write_verb":        clause[op.write[0]:op.write[1]],
				},
			})
		}
	}
	return findings.CapFindings(out)
}
