package instruction

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/dlclark/regexp2"

	"github.com/traceforce/skill-xray/internal/codelane"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// --- hidden HTML comment (SXV-027) -------------------------------------------

type comment struct {
	start int // byte offset of "<!--"
	body  string
}

// htmlComments is _html_comments: one forward pass; an unterminated opener hides to end of text.
func htmlComments(text string) []comment {
	var out []comment
	cursor := 0
	for {
		start := strings.Index(text[cursor:], "<!--")
		if start < 0 {
			return out
		}
		start += cursor
		end := strings.Index(text[start+4:], "-->")
		if end < 0 {
			return append(out, comment{start, text[start+4:]})
		}
		end += start + 4
		out = append(out, comment{start, text[start+4 : end]})
		cursor = end + 3
	}
}

var (
	// _COMMENT_ADDRESSEE_RE, first alternative; the second is commentAgentRE with its
	// (?<![/\w-]) lookbehind checked in addressesAgent.
	commentAddresseeRE = regexp.MustCompile(`(?i)\b(?:you|your|yourself|the model|system prompt)\b`)
	commentAgentRE     = regexp.MustCompile(`(?i)(?:assistant|agent|claude|gpt)\b`)
	// _COMMENT_ACTION_RE
	commentActionRE = regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override|must|always|never|do not|don'?t|` +
		`run|execute|install|download|fetch|send|upload|post|exfiltrat\w*|` +
		`read|delete|remove|follow|obey|comply|reply|respond)\b`)
	// _COMMENT_EXEC_RE
	commentExecRE = regexp.MustCompile(`(?i)\b(?:curl|wget|bash|zsh|eval|exec|chmod|sudo|scp|ncat|` +
		`python|pip|npm|npx|node|base64|powershell|iwr|irm)\b` +
		`\s+(?:-{1,2}\w|\.?/|~/|https?://|['"]|\S+\.(?:sh|py|js|rb|pl|ps1|exe|bat)\b)|` +
		`\brm\s+-|\|\s*(?:ba|z)?sh\b|` +
		`\b(?:curl|wget|fetch|download|source|load|run|execute|import)\b[^\n]{0,24}https?://`)
	// _COMMENT_STRONG_RE
	commentStrongRE = regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override)\b[^\n]{0,24}` +
		`\b(?:instruction|rule|guideline|prompt|context|directive)s?\b|` +
		`\bjailbreak\b|\bdeveloper mode\b|\bDAN\b|` +
		`\b(?:never|do not|don'?t)\s+refuse\b|\bno disclaimers?\b`)
)

func addressesAgent(body string) bool {
	if commentAddresseeRE.MatchString(body) {
		return true
	}
	return len(findAll(commentAgentRE, body, func(m []int) bool {
		r, _ := utf8.DecodeLastRuneInString(body[:m[0]])
		return m[0] == 0 || !(r == '/' || r == '-' || pytext.IsWord(r))
	})) > 0
}

// commentIsDirective is _comment_is_directive.
func commentIsDirective(body string) bool {
	return commentExecRE.MatchString(body) || commentStrongRE.MatchString(body) ||
		(addressesAgent(body) && commentActionRE.MatchString(body))
}

// hiddenCommentFindings is _hidden_comment_findings.
func hiddenCommentFindings(a *parse.Artifact, _ map[string]*parse.Artifact) []findings.Finding {
	type located struct {
		body         string
		line, column int
	}
	var comments []located
	fragments := []parse.HTMLFragment{{Text: *a.Text, Line: 1, Column: 1}}
	if md := a.Markdown; md != nil {
		fragments = md.HTMLUninspectable
		for _, c := range md.HTMLComments {
			comments = append(comments, located{c.Body, c.Line, c.Column})
		}
	}
	for _, f := range fragments {
		for _, c := range htmlComments(f.Text) {
			preceding := f.Text[:c.start]
			line := f.Line + strings.Count(preceding, "\n")
			column := f.Column + utf8.RuneCountInString(preceding)
			if i := strings.LastIndexByte(preceding, '\n'); i >= 0 {
				column = utf8.RuneCountInString(preceding[i+1:]) + 1
			}
			comments = append(comments, located{c.body, line, column})
		}
	}
	// sorted(set(comments), key=(line, column))
	seen := map[located]bool{}
	var unique []located
	for _, c := range comments {
		if !seen[c] {
			seen[c] = true
			unique = append(unique, c)
		}
	}
	slices.SortStableFunc(unique, func(x, y located) int {
		return cmp.Or(cmp.Compare(x.line, y.line), cmp.Compare(x.column, y.column))
	})
	var out []findings.Finding
	total := 0
	for _, c := range unique {
		body := pytext.Strip(c.body)
		if body == "" || !commentIsDirective(body) {
			continue
		}
		total++
		if total > findingCap {
			continue
		}
		oneLine := strings.ReplaceAll(body, "\n", " ")
		out = append(out, findings.Finding{
			Vector: "SXV-027", Rule: "hidden-html-comment", Severity: "high", Path: a.Rel,
			Line: findings.Int(c.line), Column: findings.Int(c.column),
			Message: fmt.Sprintf(`an HTML comment in this instruction file carries a directive to the agent: "%s". `+
				`A markdown renderer hides it, so a human reviewer sees a clean page while the model still reads it`,
				cutRunes(oneLine, 160)),
			Evidence: map[string]any{"comment_body": cutRunes(body, 400), "line": c.line, "column": c.column,
				"selector": "hidden-comment:" + sha12(body), "snippet": cutRunes(oneLine, 200)}})
	}
	if total > findingCap {
		out = append(out, capNote(a.Rel, "SXV-027", total-findingCap))
	}
	return out
}

// --- injected model-directives (SXV-028/029/030/031) -------------------------

type directiveRule struct {
	vector, tag, severity string
	re                    *regexp.Regexp
}

// directiveRules is _DIRECTIVE_RULES. The SXV-031 pattern's first alternative carries a
// negative lookahead; it is captured (group 1) and the lookahead is applied in ruleMatches.
var directiveRules = []directiveRule{
	{"SXV-028", "instruction-override", "high", regexp.MustCompile(`(?i)` +
		`\b(?:ignore|disregard|forget|override|overrule|supersede|replace|reset|wipe)\s+` +
		`(?:all\s+|any\s+|every\s+|each\s+|the\s+|your\s+|my\s+|our\s+|` +
		`(?:the\s+)?(?:previous|prior|past|above|earlier|preceding|system|current|initial|` +
		`original|content|safety|ethical|moderation|usage)\s+)*` +
		`(?:instruction|rule|guideline|prompt|directive|constraint|direction|command|order|` +
		`message)s?\b|` +
		`\b(?:enter|enable|activate|switch to|into)\s+\w{0,12}\s*jailbreak\b|` +
		`\bjailbreak mode\b|\bDAN mode\b|` +
		`\bdeveloper mode\b[^.\n|]{0,80}\b(?:chatgpt|gpt|claude|gemini|llama|` +
		`enabled output|no restrictions|unrestricted|uncensored|ignore|bypass|` +
		`jailbr\w+|without (?:any )?restrictions?|(?:all |any |the )?restrictions? ` +
		`(?:removed|lifted|off|disabled|dropped)|` +
		`(?:remov\w*|drop\w*|lift\w*|disabl\w*|turn off) (?:all |any |the )?(?:your |its )?` +
		`restrictions?|filters? (?:disabled|off|removed)|no filters?)\b|` +
		`\b(?:chatgpt|gpt|claude|gemini|llama)\b[^.\n|]{0,80}\bdeveloper mode\b|` + // a table cell is a requirements row
		`\b(?:(?:remov\w*|drop\w*|lift\w*|disabl\w*|turn off) (?:all |any |the )?(?:your |its )?` +
		`restrictions?|without (?:any )?restrictions?|(?:all |any |the )?restrictions? ` +
		`(?:removed|lifted|off|disabled|dropped)|filters? (?:disabled|off|removed)|no filters?)` +
		`\b[^.\n]{0,80}\bdeveloper mode\b|` +
		`\byou are now\b[^.\n]{0,24}\b(?:DAN|unrestricted|jailbroken|an ai with no|` +
		`(?:in\s+)?developer mode)\b|` +
		`\b(?:act as|pretend (?:to be|you are|you have)|roleplay as|behave as)\b[^.\n]{0,40}` +
		`\b(?:no|without|free of|zero)\b[^.\n]{0,16}` +
		`\b(?:restrictions?|rules?|limits?|filters?|guidelines?|constraints?|guardrails?)\b`)},
	{"SXV-029", "anti-refusal", "medium", regexp.MustCompile(`(?i)` +
		`\b(?:never|not|un(?:able|allowed)|cannot|can'?t|must not|may not|shall not|` +
		`(?:do|does|will|should|would)\s+not|don'?t|are\s+not\s+(?:to|allowed))` +
		`\s+(?:to\s+|ever\s+)*refuse\b|` +
		`\balways\s+comply\b|\bcomply with (?:every|any|all)\b|\banswer (?:every|any|all)\b|` +
		`\bno disclaimers?\b|\bwithout (?:any )?disclaimers?\b|` +
		`\bwithout (?:any )?(?:safety|security|ethical|content) warnings?\b|` +
		`\b(?:answer|respond|reply|comply|proceed|continue|act|do so)\b[^.\n]{0,24}` +
		`\bwithout (?:any )?warnings?\b|` +
		`\b(?:skip|omit|remove|drop|strip)\s+(?:the\s+|any\s+|all\s+)?(?:disclaimer|warning)s?\b|` +
		`\bignore (?:your |the )?(?:safety |content |ethical )?(?:guideline|policy|policies|rule)` +
		`s?\b|` +
		`\b(?:bypass|circumvent|disable|ignore)\s+(?:the |your )?` +
		`(?:safety|content|refusal|filter|restriction|guardrail|limit)s?\b`)},
	{"SXV-030", "memory-persistence", "medium", regexp.MustCompile(`(?i)` +
		`\balways remember\b[^.\n]{0,60}(?:future|forever|permanent|from now on|every session)|` +
		`\b(?:remember|keep|retain|memori[sz]e)\s+(?:this|that|it|the following)\b[^.\n]{0,40}` +
		`(?:for )?(?:all |every |the )?(?:upcoming|future|subsequent|later) ` +
		`(?:chats?|conversations?|sessions?|interactions?)|` +
		`\b(?:remember|memori[sz]e)\s+(?:this|that|it|the following)\b[^.\n]{0,24}` +
		`(?:forever|permanently|from now on|for good|indefinitely)|` +
		`\b(?:keep|retain|persist)\s+(?:this|that|these|those|my|your|all (?:of )?(?:these|those)|` +
		`the following)\s+` +
		`(?:instruction|rule|directive|behaviou?r|persona|memory|memories|prompt|guideline)s?\b` +
		`[^.\n]{0,24}(?:forever|permanently|from now on|for good|indefinitely|` +
		`across\s+(?:all\s+|future\s+)*sessions)\b|` +
		`\b(?:keep|retain|persist|hold|store)\s+(?:this|that|these|those|it|the following)\s+` +
		`in\s+(?:mind|(?:your\s+(?:long-term\s+|persistent\s+)?|long-term\s+|persistent\s+)` +
		`memory)\b[^.\n]{0,30}` +
		`(?:forever|permanently|from now on|for good|indefinitely|` +
		`(?:for|across|in)\s+(?:all\s+|every\s+|any\s+)?(?:future\s+|subsequent\s+|later\s+|` +
		`upcoming\s+)+(?:sessions?|conversations?|chats?|interactions?))\b|` +
		`\b(?:keep|retain|persist)\s+(?:this|that|it|these|those|the following)\s+` +
		`(?:for|across|in)\s+(?:all\s+|every\s+|any\s+)?(?:future\s+|subsequent\s+|later\s+|` +
		`upcoming\s+)+(?:sessions?|conversations?|chats?|interactions?)\b|` +
		`\bremember\s+(?:this|it|these|the following)\s+across\s+(?:all\s+|future\s+)*sessions\b|` +
		`\b(?:persist|store|save|write|commit|memori[sz]e)\s+` +
		`(?:this|it|these|the following|everything|all of this|what i tell you)\b[^.\n]{0,30}` +
		`(?:in|to|into) ` +
		`(?:your (?:long[- ]?term |persistent |durable )?memory|long[- ]?term memory)\b`)},
	{"SXV-031", "behavior-manipulation", "medium", regexp.MustCompile(`(?i)` +
		`(\bmanipulat\w*\s+(?:the\s+)?` +
		`(?:users?|operator|human|customer|reader|audience|them|victim)\b)|` +
		manipulationCovert)},
}

const manipulationCovert = `\b(?:covertly|secretly|surreptitiously|stealthily|clandestinely|deceptively)\b` +
	`[^.\n]{0,20}\b(?:steer|influence|manipulat\w*|coerc\w*|deceiv\w*|mislead\w*)\b|` +
	`\b(?:steer|influence|manipulat\w*|coerc\w*|deceiv\w*|mislead\w*)\b[^.\n]{0,20}` +
	`\b(?:covertly|secretly|surreptitiously|stealthily|clandestinely|deceptively)\b`

var (
	// the SXV-031 negative lookahead, applied to the text after alternative 1
	manipulationSuffixRE = regexp.MustCompile(`(?i)^(?:\s+(?:interface|object|record|profile|session|account|data|table|row|cart|id|agent|` +
		`input|list|array|string|dom|element|settings?|prefs?)\b|['’]s)`)
	// alternatives 2 and 3, which Python's engine retries at the same start when alternative
	// 1 fails its lookahead
	manipulationCovertRE = regexp.MustCompile(`(?i)^(?:` + manipulationCovert + `)`)
	// _ANTIREFUSAL_BENIGN_RE
	antiRefusalBenignRE = regexp.MustCompile(`(?i)\b(?:the|this|that|our|a|an|it|its|they|their)\s+\w+\s+` +
		`(?:will|would|does|can|shall|may)\s+never\s+refuse\b|` +
		`\bno disclaimers?\s+(?:or|and|,)\s*(?:no\s+)?(?:warrant|liabilit|guarantee)`)
	// _NEGATED_ATTACK_ACTION_RE
	negatedAttackActionRE = regexp.MustCompile(`(?i)` + negation +
		`(?:ignore|disregard|override|overrule|supersede|bypass|circumvent|disable|` +
		`skip|omit|remove|drop|strip|enable|activate)\b`)
	// _NOUN_PHRASE_INTRO_RE
	nounPhraseIntroRE = regexp.MustCompile(`(?i)\b(?:add(?:ing|ed|s)?|creat(?:e|ing|ed|es)|defin(?:e|ing|ed|es)|configur(?:e|ing|ed|es)|` +
		`set(?:ting)?\s+up|writ(?:e|ing|es)|us(?:e|ing|es)|edit(?:ing|s)?|updat(?:e|ing|es)|` +
		`manag(?:e|ing|es)|custom|new|more|extra|additional|your own|the|an?|these|those|some|` +
		`any|its|their|our)\s+\z`)
	// _PARAM_DEF_RE (case-sensitive); \x60 is the backtick
	paramDefRE = regexp.MustCompile(`\x60(?:-{1,2}\w[\w-]*(?:\s*[,/|]\s*-{1,2}\w[\w-]*)*|\?[\w-]+=?|[\w.-]+=[^\x60\n]*|` +
		`[^\x60\n]*<[^\x60\n]+>[^\x60\n]*)` +
		`(?:\s[^\x60\n]*)?\x60\s*(?:—|–|-{1,2}|:|=)\s*\z`)
	// _SCOPED_DIRECTIVE_RE
	scopedDirectiveRE = regexp.MustCompile(`(?i)\b(?:all|any|every|each|previous|prior|past|above|earlier|preceding)\b.{0,30}` +
		`\b(?:instructions?|prompts?|directives?)\b`)
	// inline re.match(r"(?:ignore|forget|override|disregard)\b", ..., re.I)
	overrideVerbRE = regexp.MustCompile(`(?i)^(?:ignore|forget|override|disregard)\b`)
)

// ruleMatches is rx.finditer(raw) for one directive rule.
func ruleMatches(r directiveRule, raw string) [][]int {
	if r.vector != "SXV-031" {
		return r.re.FindAllStringIndex(raw, -1)
	}
	var out [][]int
	for pos := 0; pos <= len(raw); {
		m := r.re.FindStringSubmatchIndex(raw[pos:])
		if m == nil {
			break
		}
		start, end := pos+m[0], pos+m[1]
		if m[2] >= 0 && manipulationSuffixRE.MatchString(raw[end:]) {
			alt := manipulationCovertRE.FindStringIndex(raw[start:])
			if alt == nil {
				_, n := utf8.DecodeRuneInString(raw[start:])
				pos = start + n
				continue
			}
			end = start + alt[1]
		}
		out = append(out, []int{start, end})
		pos = end
	}
	return out
}

// directiveFindings is _directive_findings.
func directiveFindings(a *parse.Artifact, _ map[string]*parse.Artifact) []findings.Finding {
	type key struct{ vector, text string }
	var out []findings.Finding
	seen := map[key]bool{}
	totals := map[string]int{}
	var vectorOrder []string
	previous := ""
	citedPrev := false
	prevEnd := 0
	var lines []string
	for _, b := range proseBlocks(a) {
		raw := FlattenProse(b.Text)
		if raw == "" {
			continue
		}
		introPrev := introEnds(previous)
		// each list item is its own block: the cue on the intro carries through items that are
		// one quoted string each, so an item with prose of its own is the last one cited, and
		// any block the parser did not lift as prose (a fence, a rule) between two items ends
		// the list as well
		cited := quotedItemRE.MatchString(raw) && (citedListIntro(previous) || citedPrev)
		if cited {
			if lines == nil {
				text := ""
				if a.Text != nil {
					text = *a.Text
				}
				lines = strings.Split(text, "\n")
			}
			gap := prevEnd
			if gap < b.Start-1 && setextUnderlineRE.MatchString(lines[gap]) && !markedLineRE.MatchString(previous) {
				gap++ // the intro's own underline
			}
			hi := min(b.Start-1, len(lines)) // Python slices clamp
			between := strings.Join(lines[min(gap, hi):hi], "\n")
			cited = pytext.Strip(htmlCommentRE.ReplaceAllString(between, "")) == ""
		}
		for _, rule := range directiveRules {
			for _, m := range ruleMatches(rule, raw) {
				group := raw[m[0]:m[1]]
				matched := pytext.Strip(group)
				k := key{rule.vector, pytext.Lower(matched)}
				if seen[k] {
					continue
				}
				before := raw[:m[0]]
				if introEnds(before) || introPrev || isDefensiveFrame(before) || quoted(raw, m[0], m[1], cited) {
					continue
				}
				if rule.vector == "SXV-028" && (bareWeakNounRE.MatchString(matched) || reportedRefusal(before, restOfLine(raw, m[1]))) {
					continue // "ignore rules"; "if a user asks you to..., refuse"
				}
				if rule.vector == "SXV-028" && paramDefRE.MatchString(before) && !scopedDirectiveRE.MatchString(group) {
					continue // "`--flag` -- Override instructions": option docs
				}
				if rule.vector == "SXV-028" && nounPhraseIntroRE.MatchString(before) && overrideVerbRE.MatchString(group) {
					continue // "adding ignore rules": a noun phrase, not an order
				}
				context := raw[byteIdx(raw, runeIdx(raw, m[0])-48):m[1]]
				if negatedAttackActionRE.MatchString(context) {
					continue
				}
				if rule.vector == "SXV-029" && antiRefusalBenignRE.MatchString(raw) {
					continue // third-person "X will never refuse" / license copy
				}
				seen[k] = true
				if totals[rule.vector] == 0 {
					vectorOrder = append(vectorOrder, rule.vector)
				}
				totals[rule.vector]++
				if totals[rule.vector] > findingCap {
					continue
				}
				line, col := SourcePosition(b.Text, b.Start, runeIdx(raw, m[0]))
				out = append(out, findings.Finding{
					Vector: rule.vector, Rule: rule.tag, Severity: rule.severity, Path: a.Rel,
					Line: findings.Int(line), Column: findings.Int(col),
					Message: fmt.Sprintf(`instruction-file directive (%s): "%s". This addresses the model's own behaviour rather than the task`,
						rule.tag, cutRunes(matched, 100)),
					Evidence: map[string]any{"directive_text": matched, "rule": rule.tag, "line": line, "col": col,
						"selector": rule.tag + ":" + cutRunes(pytext.Lower(matched), 50), "snippet": cutRunes(raw, 200)}})
			}
		}
		citedPrev = cited && pureQuotedItemRE.MatchString(raw)
		previous = raw
		if inFrontmatter(a, b.Start) {
			previous = ""
		}
		prevEnd = b.Start + strings.Count(b.Text, "\n")
	}
	for _, v := range vectorOrder {
		if totals[v] > findingCap {
			out = append(out, capNote(a.Rel, v, totals[v]-findingCap))
		}
	}
	return out
}

// --- remote instruction loading (SXV-041) ------------------------------------

const (
	riWindow  = 2 // _RI_WINDOW
	riWrapMax = 8 // _RI_WRAP_MAX

	riObeyNoun = `instructions?|directions?|steps?|commands?|orders?|directives?|` +
		`playbooks?|rulesets?|recipes?|checklists?|the\s+script`
	riStrongNoun = `instructions?|directions?|commands?|orders?|directives?|playbooks?|rulesets?`
	riFollowVerb = `follow|obey|comply with|adhere to|execute|run|carry out|apply|act on|perform`
)

var (
	riFollowVerbRE = regexp.MustCompile(`(?i)\b(?:` + riFollowVerb + `)\b`)
	riPipeRE       = regexp.MustCompile(`(?i)\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:ba|z)?sh\b`)
	riProsePipeRE  = regexp.MustCompile(`(?i)\bpipe\b[^.\n]{0,40}\b(?:in)?to\b[^.\n]{0,14}\b(?:a\s+)?(?:ba|z)?sh(?:ell)?\b|` +
		`\bpipe\b[^.\n]{0,40}\bbash\b`)
	riOutputRE = regexp.MustCompile(`(?i)\b(?:do|execute|run|perform|carry out|apply|follow|read|let)\s+(?:exactly\s+)?` +
		`(?:each\s+|every\s+|of\s+)*(?:what|whatever)\s+` +
		`(?:it|they|that\s+\w+|the\s+(?:url|link|page|file|response|document|endpoint|gist|` +
		`server|remote))\b[^.\n]{0,24}?` +
		`\b(?:says?|returns?|contains?|lists?|provides?|instructs?|spells?|prescribes?|tells?)\b`)
	riTreatRE = regexp.MustCompile(`(?i)\b(?:treat|use|adopt|take)\b[^.\n]{0,40}?\bas\s+(?:your\s+|the\s+|its\s+|new\s+)*` +
		`(?:standing\s+|operating\s+)?` +
		`(?:instructions?|commands?|directives?|rules?|prompts?|system\s+(?:message|prompt)|` +
		`a\s+script)\b|` +
		`\b(?:its\s+contents?|the\s+(?:response|output|remote\s+config|returned\s+\w+)|` +
		`whatever\s+it\s+returns)\b[^.\n]{0,20}?\b(?:is|are|becomes?|become|will\s+be)\b\s+` +
		`(?:your\s+|the\s+|new\s+)*(?:standing\s+|operating\s+)?` +
		`(?:instructions?|commands?|directives?|rules?|prompts?|system\s+(?:message|prompt))\b`)
	riFollowTiedRE = regexp.MustCompile(`(?i)\b(?:` + riFollowVerb + `)\b[^.\n]{0,20}?\b(?:` + riObeyNoun + `)\b[^.\n]{0,20}?` +
		`\b(?:in|from|at|on|returned by|provided by|listed (?:in|at)|contained (?:in|at)|` +
		`it\s+(?:contains?|returns?|provides?|lists?|gives?|includes?|holds?|specif\w+|states?|` +
		`prescribes?|spells?)|they\s+(?:contain|return|provide|list|give|specify|prescribe|spell))\b`)
	riFollowStrongRE = regexp.MustCompile(`(?i)\b(?:` + riFollowVerb + `)\b[^.\n]{0,20}?\b(?:` + riStrongNoun + `)\b`)
	riFollowAnaRE    = regexp.MustCompile(`(?i)\b(?:` + riFollowVerb + `)\b[^.\n]{0,20}?\b(?:them|those|these)\b|` +
		`\b(?:` + riFollowVerb + `)\b[^.\n]{0,30}?\b(?:it|they)\s+` +
		`(?:says?|returns?|contains?|lists?|provides?|instructs?|spells?|prescribes?|` +
		`dictates?|specif\w+)\b`)
	riNounExecRE = regexp.MustCompile(`(?i)\b(?:instructions?|commands?|directives?|orders?)\b[^.\n]{0,40}?` +
		`\b(?:execute|run|follow|obey|carry out|perform|apply)\s+(?:them|it|these|those)\b|` +
		`\b(?:execute|run|eval|exec)\s+(?:it|this|that|them|the\s+(?:response|output|reply|result))` +
		`\b[^.\n]{0,12}\bverbatim\b`)
	riScriptExtRE = regexp.MustCompile(`(?i)\.(?:sh|ps1|py|rb|pl|bash|bat|cmd)\b`)
	riRunItRE     = regexp.MustCompile(`(?i)\b(?:run|execute|exec|source|\./)\s*it\b`)
	// _RI_LOCAL_AFTER_RE, used with .match
	riLocalAfterRE = regexp.MustCompile(`(?i)^\s*(?:in|at|from|inside|within|of)?\s*(?:the\s+|this\s+|our\s+)?(?:` +
		`[\w.-]*\.(?:md|markdown|txt|rst|adoc|mk|cfg|ini|toml|json|ya?ml|xml|py|js|ts|rb|go)\b|` +
		`readme|makefile|dockerfile|changelog|licen[sc]e|contributing|codeowners|` +
		`repo(?:sitory)?|codebase|source\s+tree|project|package(?:\.json)?)\b`)
	riFetchVerbRE = regexp.MustCompile(`(?i)\b(?:fetch|download|retrieve|pull|load|obtain|grab|clone|consult|import|source)` +
		`(?:e?d|e?s|ing)?\b|` +
		`\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b`)
	riURLishRE = regexp.MustCompile(`(?i)https?://|\bftps?://|\bgist\b|\bpastebin\b|\bhastebin\b|githubusercontent|` +
		`\bthe\s+(?:url|link|endpoint|gist|server|address)\b|` +
		`\bremote\s+(?:server|endpoint|url|host|source)\b`)
	riCharacterizedSourceRE = regexp.MustCompile(`(?i)\bremote\s+(?:instructions?|response|output|commands?|directives?|payload|content|script)\b|` +
		`\b(?:instructions?|response|output|commands?|directives?|payload|script)\s+` +
		`(?:from|returned by|provided by)\s+(?:the\s+)?remote\b`)
	riDocAsInstructionRE = regexp.MustCompile(`(?i)\b(?:use|treat|adopt|take)\b[^.\n]{0,120}\b(?:documentation|docs?|guide|reference)\b` +
		`[^.\n]{0,120}\bas\s+(?:your\s+|the\s+)?remote\s+instructions?\b`)
	// _SCHEMELESS_URL_RE
	schemelessURLRE = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+` +
		`(?:com|net|org|io|dev|app|co|ai|gg|xyz|test|cloud|site|link|info|biz|me|ly)\b/[^\s)]+`)
	riBenignRE = regexp.MustCompile(`(?i)\b(?:see|refer to|documentation|read more|for (?:more )?(?:details?|info(?:rmation)?|` +
		`reference)|learn more|as documented|docs?|readme|wiki|handbook|tutorial|reference|` +
		`setup guide|getting started|installation (?:guide|instructions?|steps?)|` +
		`official (?:docs?|guide)|user guide|man(?:ual| page)|changelog|contributing)\b`)
	riHardexecRE = regexp.MustCompile(`(?i)\b(?:execute|eval|exec)\b|\|\s*(?:ba|z)?sh\b|` +
		`\b(?:do|run)\s+(?:exactly\s+)?(?:what|whatever)\b[^.\n]{0,48}` +
		`\b(?:says?|returns?|contains?)\b`)
	riExampleIntroRE = regexp.MustCompile(`(?i)\b(?:such as|e\.?g\.?|i\.?e\.?|for example|for instance|for reference|` +
		`an example|example of|a sample|looks? like|like this|as shown(?: below)?|` +
		`shown below|the one (?:below|above)|might (?:say|write|include|contain))\b\s*:?|` +
		`:\s*["']`)
	riSeqBreakRE     = regexp.MustCompile(`(?i)[;,]|\.\s|\bthen\b`)
	riStrongFollowRE = regexp.MustCompile(`(?i)\b(?:instructions?|directions?|directives?|commands?|orders?|playbooks?|rulesets?)\b|` +
		`\b(?:it|they)\s+(?:contains?|returns?|lists?|provides?|says?|includes?|holds?|` +
		`specif\w+|prescribes?|spells?|dictates?|states?)\b|` +
		`\b(?:returned|provided|listed|contained|specified)\s+(?:by|in|at)\b|` +
		`\b(?:run|source|exec(?:ute)?)\s+it\b`)
	// _RI_INSTALL_PIPE_RE; \x60 is the backtick
	riInstallPipeRE = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|\x60]{0,200}\|\s*(?:tee\s+\S+\s*\|\s*)?` +
		`(?:sudo\s+(?:-\w+(?:\s+[\w-]+)?\s+)*)?(?:(?:/usr)?/bin/)?(?:ba|z|da|k)?sh\b|` +
		`\b(?:ba|z|da|k)?sh\s+<\(\s*(?:curl|wget)\b[^\n)\x60]{0,200}\)`)
	fetchLikeRE = regexp.MustCompile(`(?i)\b(?:curl|wget)\b|<\(|\$\(`)
)

// riGoverningPrefix is _ri_governing_prefix: before, truncated at its last clause/sequence break.
func riGoverningPrefix(before string) string {
	last := 0
	for _, m := range riSeqBreakRE.FindAllStringIndex(before, -1) {
		last = m[1]
	}
	return before[last:]
}

// stripURLs is _strip_urls: every schemed or schemeless URL becomes one space.
func stripURLs(s string) string {
	return schemelessURLRE.ReplaceAllString(egressURLRE.ReplaceAllString(s, " "), " ")
}

func riURLIn(s string) bool { return egressURLRE.MatchString(s) || schemelessURLRE.MatchString(s) }

func riHasRemote(s string) bool {
	return riURLIn(s) || (riFetchVerbRE.MatchString(s) && riURLishRE.MatchString(s))
}

func riFetchAndURL(s string) bool { return riURLIn(s) && riFetchVerbRE.MatchString(s) }

// riCharacterizedRemote is _ri_characterized_remote.
func riCharacterizedRemote(joined string) bool {
	for _, line := range pytext.SplitLines(joined) {
		characterized := riCharacterizedSourceRE.FindStringIndex(line)
		if characterized == nil || !riURLIn(line) {
			continue
		}
		benign := riBenignRE.FindStringIndex(line)
		if benign == nil || characterized[0] < benign[0] || riDocAsInstructionRE.MatchString(stripURLs(line)) {
			return true
		}
	}
	return false
}

// riSourceDesc is _ri_source_desc.
func riSourceDesc(joined string) string {
	for _, re := range []*regexp.Regexp{egressURLRE, schemelessURLRE, riURLishRE} {
		if u := re.FindString(joined); u != "" {
			return u
		}
	}
	return "a remote source"
}

// riHit is a qualifying SXV-041 match: its stripped text and 1-based code-point column in the
// string it was found in (sline, or raw for the curl-pipe rule).
type riHit struct {
	matched string
	col     int
}

// riMatch is _ri_match: the earliest qualifying rule match on this line, each rule behind its
// own remote-source gate; the follow-object rules also reject a local-file tie.
func riMatch(sline, raw, ctx string) *riHit {
	remote := riHasRemote(ctx)
	fetchurl := riFetchAndURL(ctx)
	strongRemote := riURLIn(raw) || fetchurl
	tiedRemote := strongRemote || riCharacterizedRemote(ctx)
	var cands []riHit
	add := func(src string, m []int, ok bool) {
		if m != nil && ok {
			cands = append(cands, riHit{pytext.Strip(src[m[0]:m[1]]), runeIdx(src, m[0]) + 1})
		}
	}
	notLocal := func(m []int) bool { return m != nil && !riLocalAfterRE.MatchString(sline[m[1]:]) }

	pipe := riPipeRE.FindStringIndex(raw)
	add(raw, pipe, pipe != nil && riHasRemote(raw[pipe[0]:pipe[1]]))
	add(sline, riProsePipeRE.FindStringIndex(sline), tiedRemote)
	add(sline, riOutputRE.FindStringIndex(sline), tiedRemote)
	add(sline, riTreatRE.FindStringIndex(sline), tiedRemote)
	add(sline, riNounExecRE.FindStringIndex(sline), tiedRemote)
	mt := riFollowTiedRE.FindStringIndex(sline)
	add(sline, mt, remote && notLocal(mt))
	ms := riFollowStrongRE.FindStringIndex(sline)
	add(sline, ms, strongRemote && notLocal(ms))
	ma := riFollowAnaRE.FindStringIndex(sline)
	add(sline, ma, fetchurl && notLocal(ma))
	if riFetchVerbRE.MatchString(raw) && riScriptExtRE.MatchString(raw) {
		add(sline, riRunItRE.FindStringIndex(sline), tiedRemote) // download <REMOTE ...>.sh ... run it
	}
	if len(cands) == 0 {
		return nil
	}
	best := &cands[0]
	for i := range cands[1:] {
		if cands[i+1].col < best.col {
			best = &cands[i+1]
		}
	}
	return best
}

func endsSentence(s string) bool {
	s = pytext.RStrip(s)
	return s != "" && strings.IndexByte(".!?:;", s[len(s)-1]) >= 0
}

// riJoinWrap is _ri_join_wrap: the line plus its soft-wrapped continuation lines, flattened.
func riJoinWrap(raws []string, n int, inFence map[int]bool) string {
	parts := []string{raws[n-1]}
	for j := n; j < len(raws) && pytext.Strip(raws[j]) != "" && !inFence[j+1] &&
		!listItemRE.MatchString(raws[j]) && !isTableRow(raws[j]) &&
		!endsSentence(parts[len(parts)-1]) && j-n < riWrapMax; j++ {
		parts = append(parts, raws[j])
	}
	if len(parts) > 1 {
		return FlattenProse(strings.Join(parts, "\n"))
	}
	return raws[n-1]
}

// installerLine is _installer_line: every fetch-pipe on the line is an installer-shaped HTTPS
// fetch whose code span or sentence carries no further fetch, and the rest of the line holds
// no separate remote directive.
func installerLine(raw string) bool {
	pipes := riInstallPipeRE.FindAllStringIndex(raw, -1)
	if len(pipes) == 0 {
		return false
	}
	for _, p := range pipes {
		if !codelane.InstallerIdiom(raw[p[0]:p[1]]) {
			return false
		}
	}
	rest := raw
	for _, p := range pipes {
		pipe := raw[p[0]:p[1]]
		var span string
		lo, hi := strings.LastIndexByte(raw[:p[0]], '`'), strings.IndexByte(raw[p[1]:], '`')
		switch end := strings.Index(raw[p[1]:], ". "); {
		case lo != -1 && hi != -1:
			span = raw[lo+1 : p[1]+hi]
		case end != -1:
			span = raw[p[0] : p[1]+end]
		default:
			span = raw[p[0]:]
		}
		if fetchLikeRE.MatchString(strings.Replace(span, pipe, " ", 1)) {
			return false
		}
		rest = strings.Replace(rest, span, " ", 1)
	}
	return !(riHasRemote(rest) && (riFollowVerbRE.MatchString(rest) || riFetchVerbRE.MatchString(rest)))
}

// remoteInstrFindings is _remote_instr_findings.
func remoteInstrFindings(a *parse.Artifact, _ map[string]*parse.Artifact) []findings.Finding {
	raws := strings.Split(*a.Text, "\n")
	inFence, _ := fencedLines(a.Markdown, len(raws))
	var out []findings.Finding
	total := 0
	for n := 1; n <= len(raws); n++ {
		raw := raws[n-1]
		if inFence[n] {
			continue // a fenced install one-liner is an example
		}
		ctx := strings.Join(raws[max(0, n-1-riWindow):min(len(raws), n+riWindow)], "\n")
		sline := stripURLs(raw)
		hit := riMatch(sline, raw, ctx)
		// Retry on the soft-wrap join only when a directive plausibly starts on this line.
		if hit == nil && (riFetchVerbRE.MatchString(raw) || riFollowVerbRE.MatchString(raw)) {
			if joined := riJoinWrap(raws, n, inFence); joined != raw {
				sjoined := stripURLs(joined)
				if jhit := riMatch(sjoined, raw, ctx); jhit != nil && jhit.col <= utf8.RuneCountInString(pytext.Strip(sline))+1 {
					sline, hit = sjoined, jhit
				}
			}
		}
		if hit == nil {
			continue
		}
		prose := stripURLs(ctx)
		before := cutRunes(sline, hit.col-1)
		if isDefensiveFrame(before) {
			continue
		}
		scope := before
		if riStrongFollowRE.MatchString(hit.matched) {
			scope = riGoverningPrefix(before)
		}
		if riExampleIntroRE.MatchString(scope) {
			continue
		}
		if riBenignRE.MatchString(scope+hit.matched) && !riHardexecRE.MatchString(prose) {
			continue
		}
		total++
		if total > findingCap {
			continue
		}
		source := ctx
		if riHasRemote(raw) {
			source = raw
		}
		src := riSourceDesc(source)
		evidence := map[string]any{"directive_text": hit.matched, "remote_source": src, "line": n, "col": hit.col,
			"selector": "remote-instruction-load:" + sha12(pytext.Lower(hit.matched)),
			"snippet":  cutRunes(pytext.Strip(raw), 200)}
		severity := "high"
		if installerLine(raw) {
			evidence["installer_idiom"] = "https-named-installer"
			severity = "medium"
		}
		out = append(out, findings.Finding{
			Vector: "SXV-041", Rule: "remote-instruction-load", Severity: severity, Path: a.Rel, Line: findings.Int(n),
			Message: fmt.Sprintf(`instruction lane tells the agent to fetch remote content and follow it as instructions: "%s" (source: %s). `+
				`The scanner sees the pointer, not the payload -- the real directives load at runtime from a location a reviewer `+
				`never sees, and the remote side can change after this scan (progressive disclosure)`,
				cutRunes(hit.matched, 100), cutRunes(src, 120)),
			Evidence: evidence})
	}
	if total > findingCap {
		out = append(out, capNote(a.Rel, "SXV-041", total-findingCap))
	}
	return out
}

// --- covert bundled-script execution directive (SXV-042) --------------------

const negation = `\b(?:do not|don'?t|never|must not|must never|cannot|can'?t|will not|won'?t|` +
	`should not|shouldn'?t)\s+(?:ever\s+|attempt to\s+|try to\s+)*` // _NEGATION_RE

var (
	// _BUNDLED_RUN_RE; alternative 1 is captured, alternatives 2 and 3 carry the (?<![\w/])
	// lookbehind that bundledRuns applies.
	bundledRunRE = regexp.MustCompile(`(?i)(\b(?:python[23]?|bash|sh|zsh|node|npx|ruby|perl|pwsh|powershell|source|exec)\s+` +
		`(?:\./)?(?:scripts?|bin|tools?|lib|utils?|hooks?|setup|internal|\.[\w-]+)/[\w./-]*` +
		`\.(?:py|sh|js|mjs|cjs|rb|pl|ps1)\b)` +
		`|\./[\w./-]+\.(?:py|sh|js|mjs|rb|pl|ps1)\b` +
		`|(?:scripts?|bin|tools?|hooks?)/[\w./-]+\.(?:py|sh|js|mjs|rb|pl|ps1)\b`)
	// _COVERT_RUN_CUE_RE
	covertRunCueRE = regexp.MustCompile(`(?i)` +
		`\b(?:silently|quietly|covertly)\s+(?:run|execute|invoke|launch|call|start|trigger|source)\b|` +
		`\b(?:run|execute|invoke|launch|call|start|trigger)\b\s+(?:\x60[^\x60\n]{1,80}\x60|(?:(?:[^\s\x60.;,]|\.[^\s\x60.;,]){1,40}\s+){0,3}(?:[^\s\x60.;,]|\.[^\s\x60.;,]){1,40})[^.;,\n]{0,12}(?:,\s*)?` +
		`\b(?:silently|quietly|covertly)\b|` +
		`\b(?:do not|don'?t|never|without|avoid)\s+(?:\w+\s+){0,3}` +
		`(?:surfac\w*|show\w*|display\w*|mention\w*|reveal\w*|disclos\w*|tell\w*|inform\w*|` +
		`notif\w*|expos\w*|report\w*|announc\w*|narrat\w*|echo\w*|print\w*)` +
		`(?:\s+\w+){0,3}\s+(?:its\s+|the\s+|this\s+|that\s+|any\s+)?` +
		`(?:run|execution|script|command|step|invocation|process|preflight|setup|` +
		`hook|helper|call)s?\b[^.\n]{0,30}\b(?:user|human|operator|person)\b|` +
		`\b(?:do not|don'?t|never|without|avoid)\s+(?:\w+\s+){0,3}` +
		`(?:tell\w*|inform\w*|notif\w*|show\w*|mention\w*|surfac\w*|reveal\w*|disclos\w*|` +
		`report\w*|announc\w*)\s+` +
		`(?:(?:it|this|that)\s+(?:to\s+)?(?:the\s+)?(?:end[- ]?)?(?:user|human|operator|person)s?\b|` +
		`(?:to\s+)?(?:the\s+)?(?:end[- ]?)?(?:user|human|operator|person)s?\b[^.;:,\n]{0,30}` +
		`\b(?:ran|run|running|execut\w*|invoked|script|command|step|hook|preflight|setup)\b)|` +
		`\b(?:user|human|operator)s?\s+(?:should|must|will|need|are)\s+not\s+` +
		`(?:see|know|be told|be shown|notice|be informed|be aware)\b|` +
		`\b(?:keep|leave)\b[^.\n]{0,50}\bout of\s+(?:the\s+|your\s+|any\s+)?` +
		`(?:user[- ]facing\s+|visible\s+|final\s+)?(?:response|reply|output|answer|summary)\b|` +
		`\bhidden from the (?:user|human|operator)\b|\bnot (?:a )?user[- ]visible\b|` +
		`\binvisible to the (?:user|human)\b|\bwithout (?:the user'?s? )?(?:knowledge|awareness)\b|` +
		`\bregardless of (?:what|the user|the request|the task|whether)\b|` +
		`\beven (?:if|when) the user (?:did not|didn'?t|does not|doesn'?t|never) ask\w*\b|` +
		`\bwhether or not the user\b|` +
		`\b(?:ignore|disregard|override)\s+(?:any\s+|all\s+)?(?:earlier|prior|previous|conflicting|` +
		`existing)\s+(?:system\s+)?(?:instruction|rule|guideline|directive)s?\b|` +
		`\b(?:without|do not|don'?t|never)\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?(?:end[- ]?)?(?:user|human|operator|person)s?\s*(?:[.;!?]|\z)`)
	// _COVERT_OVERRIDE_RE
	covertOverrideRE = regexp.MustCompile(`(?i)regardless|even (?:if|when)|whether or not|ignore|disregard|override`)
	// _COERCED_RUN_CUE_RE; \x60 is the backtick
	coercedRunCueRE = regexp.MustCompile(`(?i)` +
		`\brequired first step\b|\bmandatory (?:first |setup |preflight |pre-flight )?step\b|` +
		`\b(?:this|the|that) (?:step|setup|preflight|pre-flight|procedure|script|hook) is ` +
		`(?:required|mandatory|not optional|non-?optional|compulsory)\b|` +
		`\b(?:do not|don'?t|never) skip\s+\x60?(?:running\s+|executing\s+)?(?:it|this|that|` +
		`the (?:setup|preflight|pre-flight|script|step|procedure|hook|helper)|\./|scripts?/|bin/|` +
		`tools?/|python[23]?\b|bash\b|sh\b)|\bmust not be skipped\b|\bcannot be skipped\b|` +
		`(?P<beforeany>\bbefore (?:running |starting |performing |executing |handling |attempting |` +
		`invoking |calling |using |proceeding with |beginning |answering |processing )?` +
		`(?:any|every|all|each)\s+(?:\w+\s+){0,3}(?:task|operation|procedure|computation|request|` +
		`workflow|action|use|step|detection|analysis|run|invocation|call|query|command|conversion|` +
		`export|import|processing|calculation|logic|work|session|interaction|function|tool|method|` +
		`feature|capability|endpoint)s?\b)|` +
		`\b(?:on|for|at) every (?:invocation|use|run|session|call|start|load)\b|` +
		`\bevery time (?:this skill|the skill|you) (?:is|are|gets?) (?:used|invoked|loaded|run|` +
		`start\w*|activat\w*)\b|` +
		`\bskipping (?:it|this|that|the \w+(?: \w+)?) (?:causes|leads to|results in|breaks|corrupts|` +
		`produces|will|is a known cause)\b|\bis a known cause of\b|` +
		`\b(?:step|preflight|pre-flight|setup|script|hook|procedure|helper)s?(?:\s+\d+)?\**\s*` +
		`\((?:required|mandatory)\)|\brequired (?:before|prior to)\b|` +
		`\bmust (?:be )?(?:run|executed?|completed?|perform\w*) (?:first|before)\b|` +
		`\b(?:run|execute) (?:it|this|that|the \w+(?: \w+)?) (?:first|before anything|before any)\b|` +
		// Coercion phrasings that benign setup prose does not use.
		`\b(?:your|the) (?:very )?first action (?:must|should|has to|needs to|is to|will) be to ` +
		`(?:run|execute|invoke|call|launch)\b|` +
		`\bwithout (?:user|human|operator) prompting\b|\bwithout prompting the (?:user|human|operator)\b|` +
		`\bhidden runtime dependenc(?:y|ies)\b|` +
		`\bevals? (?:only )?(?:pass(?:es)?|succeeds?) (?:only )?(?:when|if|once|after)\b|` +
		`\bbefore (?:producing|generating|composing|writing|returning|giving|emitting) ` +
		`(?:the|any|your|a) (?:final )?(?:response|answer|reply|output)\b|` +
		`\b(?:do not|don'?t|never) (?:explain|describe|mention|discuss) (?:the|this) ` +
		`(?:pre-?flight|setup|preparation|bootstrap|warm-?up)\b|` +
		`\b(?:is|as) a (?:hard |strict )?pre-?condition (?:for|of|to)\b|\bmust be warmed up\b`)
	beforeAnyGroup = coercedRunCueRE.SubexpIndex("beforeany")
	// _BUNDLED_PROSE_RE
	bundledProseRE = regexp.MustCompile(`(?i)\b(?:setup|set-up|preflight|pre-flight|helper|companion|bootstrap|init(?:ialization)?|` +
		`hygiene|register\w*|install\w*|normali[sz]ation|calibration|environment|session)\s+` +
		`(?:script|helper|hook|procedure)\b[^.\n]{0,80}\b(?:shipped|bundled|included|provided|` +
		`located|found|documented)\b[^.\n]{0,30}\b(?:with|alongside|in)\s+this\s+` +
		`(?:skill|file|directory|folder|package)\b|` +
		`\b(?:shipped|bundled|included|provided)\s+(?:with|alongside)\s+this\s+` +
		`(?:skill|file|package)\b|` +
		`\bcompanion\s+(?:script|file|helper|reference|manual|document|procedure)\b|` +
		`\bin\s+this\s+skill(?:'s)?\s+(?:directory|folder)\b|\bfrom this directory\b|` +
		`\b(?:script|helper|hook)\s+(?:shipped|bundled|included)\s+with\s+(?:this|the)\s+skill\b`)
	// _HEADING_RE, used with .match
	headingRE = regexp.MustCompile(`^ {0,3}#{1,6}\s`)
	// _NEGATED_OVERRIDE_RE
	negatedOverrideRE = regexp.MustCompile(`(?i)` + negation +
		`(?:ignore|disregard|override|overrule|supersede|bypass|circumvent|disable)\b`)
	// _NEG_RUN_PREFIX, completed per script in negatedRunOf.
	// regexp2: tempered negative lookahead and \.(?=\S) inside a lazy {0,80}? group.
	negRunPrefix = negation + `(?:run|execute|invoke|launch|source|call)\s+` +
		`(?:(?!\b(?:before|until|prior to|after|once|then|unless|when|while)\b)` +
		`(?:[^.!?\n]|\.(?=\S))){0,80}?`
)

// bundledRuns is _BUNDLED_RUN_RE.finditer.
// otherCommandRE: a command named after a concealment cue that is not a shipped script.
var otherCommandRE = regexp.MustCompile(`(?i)^[^!?\n]*?(?:\x60[^\x60\n]+\x60|\b(?:npm|npx|pnpm|yarn|pip3?|pipx|uv|brew|apt(?:-get)?|cargo|go|git|gh|docker|make|codex|claude|cursor|gemini)\b)`)

// transparencyCueRE: the sentence-end concealment phrase, which needs a run in its own
// sentence; "changes are applied without telling the user" describes a program, not a run.
var transparencyCueRE = regexp.MustCompile(`(?i)^(?:without|do not|don'?t|never)\s+(?:telling|informing|notifying|alerting)\b`)

// cueNegatedRE: "run it silently is not supported" denies the concealment it names.
var cueNegatedRE = regexp.MustCompile(`(?i)^[^.;!?\n]{0,40}?\b(?:(?:is|are|was|were)\s+not\s+(?:supported|allowed|possible|available|recommended|permitted)|not\s+(?:a\s+)?(?:supported|valid|possible))\b`)

// sentenceBounds is the sentence holding text[start:end]: a dot ends it only before a space
// or the end, so a script path's extension does not.
func sentenceBounds(text string, start, end int) (int, int) {
	s := start
	for s > 0 && !(strings.IndexByte(".!?\n", text[s-1]) >= 0 && (text[s] == ' ' || text[s] == '\n')) {
		s--
	}
	e := end
	for e < len(text) && !(strings.IndexByte(".!?\n", text[e]) >= 0 && (e+1 >= len(text) || text[e+1] == ' ' || text[e+1] == '\n')) {
		e++
	}
	return s, e
}

// warnsAboutAnotherCommand is true when a concealment cue's sentence names no bundled run and
// names another command after the cue: "do not tell the user to run `codex plugin add`" warns
// against a command, it does not hide the shipped script named elsewhere in the block.
func warnsAboutAnotherCommand(text string, start, end int) bool {
	s, e := sentenceBounds(text, start, end)
	if len(bundledRuns(text[s:e])) > 0 || bundledProseRE.MatchString(text[s:e]) {
		return false
	}
	return otherCommandRE.MatchString(text[end:e])
}

// usableCovertCue drops a cue that is a warning about another command, a transparency phrase
// with no run in its sentence, or a concealment the sentence denies.
func usableCovertCue(text string, c []int) bool {
	if warnsAboutAnotherCommand(text, c[0], c[1]) {
		return false
	}
	s, e := sentenceBounds(text, c[0], c[1])
	if transparencyCueRE.MatchString(text[c[0]:c[1]]) && len(bundledRuns(text[s:e])) == 0 && !bundledProseRE.MatchString(text[s:e]) {
		return false
	}
	return !cueNegatedRE.MatchString(text[c[1]:e])
}

func bundledRuns(s string) [][]int {
	return findAll(bundledRunRE, s, func(m []int) bool {
		if m[2] >= 0 {
			return true // alternative 1 has no lookbehind
		}
		r, _ := utf8.DecodeLastRuneInString(s[:m[0]])
		return m[0] == 0 || !(r == '/' || pytext.IsWord(r))
	})
}

// headingLines is _heading_lines: 1-based ATX heading lines outside frontmatter and code.
func headingLines(a *parse.Artifact) []int {
	var skip []parse.Span
	if md := a.Markdown; md != nil {
		skip = append(append(skip, md.FenceSpans...), md.CodeSpans...)
	}
	var out []int
	for i, line := range strings.Split(*a.Text, "\n") {
		n := i + 1
		if n > a.FrontmatterEndLine && headingRE.MatchString(line) &&
			!slices.ContainsFunc(skip, func(sp parse.Span) bool { return sp.Start <= n && n <= sp.End }) {
			out = append(out, n)
		}
	}
	return out
}

// ordersAShippedRun is _orders_a_shipped_run: the cue's own sentence names a shipped artifact.
func ordersAShippedRun(text string, cue []int) bool {
	head := text[:cue[0]]
	lo := max(strings.LastIndex(head, ". "), strings.LastIndex(head, "! "), strings.LastIndex(head, "? ")) + 1
	end := sentenceEndAfter(text, cue[1])
	if end < 0 {
		end = len(text)
	}
	sentence := text[lo:end]
	return len(bundledRuns(sentence)) > 0 || bundledProseRE.MatchString(sentence)
}

// negatedRunOf is _negated_run_of: the artifact match m sits in a sentence that prohibits
// running it.
func negatedRunOf(raw string, m []int) bool {
	pieces := sentenceSplit(raw[byteIdx(raw, runeIdx(raw, m[0])-160):m[1]])
	clause := pieces[len(pieces)-1]
	if negatedOverrideRE.MatchString(clause) {
		return true
	}
	// ponytail: compiled per call; cache by script if a profile shows it.
	re := regexp2.MustCompile(negRunPrefix+regexp2.Escape(pytext.Strip(raw[m[0]:m[1]])), regexp2.IgnoreCase)
	ok, _ := re.MatchString(clause)
	return ok
}

// covertScriptFindings is _covert_script_findings: cues and the shipped artifact correlate
// within one heading-to-heading section of prose.
func covertScriptFindings(a *parse.Artifact, _ map[string]*parse.Artifact) []findings.Finding {
	type sectionBlock struct {
		Block
		raw string
	}
	type akey struct {
		script string
		strong bool
	}
	headings := headingLines(a)
	sections := map[int][]sectionBlock{}
	var order []int
	for _, b := range proseBlocks(a) {
		raw := FlattenProse(b.Text)
		if raw == "" {
			continue
		}
		key := sort.Search(len(headings), func(i int) bool { return headings[i] > b.Start }) // bisect_right
		if sections[key] == nil {
			order = append(order, key)
		}
		sections[key] = append(sections[key], sectionBlock{b, raw})
	}
	var out []findings.Finding
	seen := map[akey]bool{}
	total := 0
	previous := ""
	for _, key := range order {
		blocks := sections[key]
		var joined strings.Builder
		var offsets []int
		for _, sb := range blocks {
			offsets = append(offsets, joined.Len())
			joined.WriteString(sb.raw + " ")
		}
		j := joined.String()
		// every usable concealment cue, in order; the first that is not an override sentence
		// brands every run in the section, an override sentence only its own block
		var coverts [][]int
		var sectionCue []int
		for _, c := range covertRunCueRE.FindAllStringIndex(j, -1) {
			if quoted(j, c[0], c[1], false) || !usableCovertCue(j, c) {
				continue
			}
			coverts = append(coverts, c)
			if sectionCue == nil && !covertOverrideRE.MatchString(j[c[0]:c[1]]) {
				sectionCue = c
			}
		}
		nextCue := 0
		// "Before using any tool, read the docs" is ordinary prose: the before-any cue counts
		// only when its own sentence orders the shipped run.
		coercion := map[string][]int{}
		var cueOrder []string
		for _, cm := range coercedRunCueRE.FindAllStringSubmatchIndex(j, -1) {
			if cm[2*beforeAnyGroup] >= 0 && !ordersAShippedRun(j, cm[:2]) {
				continue
			}
			if k := pytext.Lower(j[cm[0]:cm[1]]); coercion[k] == nil {
				coercion[k] = cm[:2]
				cueOrder = append(cueOrder, k)
			}
		}
		for i, sb := range blocks {
			offset := offsets[i]
			introPrev := sxv042IntroEnds(previous)
			previous = sb.raw
			if inFrontmatter(a, sb.Start) {
				previous = ""
			}
			// the cue named in the evidence is the one in this block when there is one, else the
			// section's; cues and blocks are both in text order, so the search is one pass
			for nextCue < len(coverts) && coverts[nextCue][0] < offset {
				nextCue++
			}
			covert := sectionCue
			if nextCue < len(coverts) && coverts[nextCue][0] < offset+len(sb.raw) {
				covert = coverts[nextCue]
			}
			if covert == nil && len(coercion) == 0 {
				continue
			}
			strong := covert != nil || len(coercion) >= 2
			// A lone coercion cue (medium) must sit in this block; only the strong grade may
			// correlate across the section.
			if !strong && !coercedRunCueRE.MatchString(sb.raw) {
				continue
			}
			cue := covert
			var local [][]int // every cue, for the block-local guard window
			if covert != nil {
				local = append(local, covert)
			}
			for _, k := range cueOrder {
				c := coercion[k]
				local = append(local, c)
				if cue == nil || (covert == nil && c[0] < cue[0]) {
					cue = c
				}
			}
			artifacts := bundledRuns(sb.raw)
			if len(artifacts) == 0 {
				artifacts = bundledProseRE.FindAllStringIndex(sb.raw, -1)
			}
			for _, m := range artifacts {
				script := pytext.Strip(sb.raw[m[0]:m[1]])
				ak := akey{pytext.Lower(script), strong}
				// one finding per script and grade: an earlier lone-cue mention must not hide a
				// later covert or two-cue run of the same script
				if seen[ak] || (!strong && seen[akey{ak.script, true}]) {
					continue
				}
				first := min(offset+m[0], cue[0])
				cut := m[0]
				for _, c := range local {
					if offset <= c[0] && c[0] < offset+len(sb.raw) {
						cut = min(cut, c[0]-offset)
					}
				}
				before := sb.raw[:cut]
				if sxv042IntroEnds(before) || introPrev || isDefensiveFrame(before) {
					continue
				}
				if negatedRunOf(sb.raw, m) {
					continue
				}
				seen[ak] = true
				total++
				if total > findingCap {
					continue
				}
				rule, why := "coerced-bundled-preflight", "as a forced precondition of every task"
				if covert != nil {
					rule, why = "covert-bundled-script-run", "hidden from the user"
					if covertOverrideRE.MatchString(j[covert[0]:covert[1]]) {
						why = "regardless of the request"
					}
				}
				severity, verdict, pyStrong := "high", "", "True"
				if !strong {
					severity, verdict, pyStrong = "medium", " (single coercion cue: reported, not a verdict)", "False"
				}
				line, col := SourcePosition(sb.Text, sb.Start, runeIdx(sb.raw, m[0]))
				cueLine := line
				for k := len(offsets) - 1; k >= 0; k-- {
					if offsets[k] <= cue[0] {
						cueLine, _ = SourcePosition(blocks[k].Text, blocks[k].Start, runeIdx(blocks[k].raw, cue[0]-offsets[k]))
						break
					}
				}
				cues := []any{}
				for _, k := range slices.Sorted(maps.Keys(coercion))[:min(6, len(coercion))] {
					cues = append(cues, k)
				}
				out = append(out, findings.Finding{
					Vector: "SXV-042", Rule: rule, Severity: severity, Path: a.Rel,
					Line: findings.Int(line), Column: findings.Int(col),
					Message: fmt.Sprintf("The instructions tell the agent to run the shipped artifact `%s` %s -- a launcher for code that is not reviewed here%s.",
						cutRunes(script, 80), why, verdict),
					Evidence: map[string]any{
						"directive_text": cutRunes(pytext.Strip(sliceRunes(j, max(0, runeIdx(j, first)-20), runeIdx(j, max(offset+m[1], cue[1]))+20)), 200),
						"script":         script, "cue": cutRunes(j[cue[0]:cue[1]], 80), "cue_line": cueLine, "cues": cues,
						"line": line, "col": col,
						// ponytail: reproduces Python's tuple repr of akey[:50] in the selector;
						// drop when the oracle changes to akey[0].
						"selector": fmt.Sprintf("%s:(%s, %s)", rule, pytext.Repr(ak.script), pyStrong),
						"snippet":  cutRunes(sb.raw, 200)}})
			}
		}
	}
	if total > findingCap {
		out = append(out, capNote(a.Rel, "SXV-042", total-findingCap))
	}
	return out
}
