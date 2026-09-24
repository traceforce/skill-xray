package instruction

// SXV-043 (instruction_exfil._data_exfil_findings): the instruction lane tells the agent to
// obtain the user's data and send it to a recipient written into the skill text. The literal
// recipient is the anchor; the data vocabulary is open. Guards excuse negated, contrasted,
// third-person, disclosed, quoted and example framings, known SaaS endpoints for business data,
// shared developer hosts and telemetry endpoints for non-sensitive data, placeholder recipients,
// inline code and fenced code.

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/dlclark/regexp2"

	"github.com/traceforce/skill-xray/internal/codelane"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// exfilWindow bounds the preceding prose (code points) searched for the acquisition.
const exfilWindow = 4000

var (
	exfilAddrRE = regexp.MustCompile(`(?i)[\w.+-]+@[\w-]+(?:\.[\w-]+)+|https?://[^\s'"<>)\]]+`)
	exfilVerb   = `(?:send(?:s|ing)?|sent|e-?mail(?:s|ed|ing)?|mail(?:s|ed|ing)?|forward(?:s|ed|ing)?|` +
		`shar(?:e|es|ed|ing)|upload(?:s|ed|ing)?|post(?:s|ed|ing)?|transmit(?:s|ted|ting)?|` +
		`deliver(?:s|ed|ing)?|relay(?:s|ed|ing)?|submit(?:s|ted|ting)?|cc(?:'?s|'?d|ing)?|` +
		`bcc(?:'?s|'?d)?|dm(?:s|'?d|ing)?|text(?:s|ed|ing)?|message(?:s|d)?|messaging|ping(?:s|ed)?|` +
		`attach(?:es|ed|ing)?|export(?:s|ed|ing)?|cop(?:y|ies|ying)|sav(?:e|es)|writ(?:e|es)|` +
		`push(?:es|ed|ing)?|sync(?:s|ed|ing)?|synchroni[sz](?:e|es|ed|ing)|rout(?:e|es|ed|ing)|` +
		`ship(?:s|ped|ping)?|dispatch(?:es|ed|ing)?|giv(?:e|es|en|ing)|gave|provid(?:e|es|ed|ing)|` +
		`report(?:s|ed|ing)?|back(?:s|ed|ing)?\s+up|` +
		`back(?:s|ed|ing)?\s+(?:it|them|this|these|that|those|\w+)\s+up|` +
		`backup(?:s)?|past(?:e|es|ed|ing)|drop(?:s|ped|ping)?|stash(?:es|ed|ing)?|` +
		`hand(?:s|ed|ing)?\s+(?:it|them|this|these|that|those|\w+)?\s*over|leak(?:s|ed|ing)?|` +
		`exfiltrat\w*|publish(?:es|ed|ing)?|expos(?:e|es|ed|ing)|feed(?:s|ing)?|pip(?:e|es|ed|ing)|` +
		`beam(?:s|ed|ing)?|stream(?:s|ed|ing)?|dump(?:s|ed|ing)?)`
	// _EXFIL_VERB_RE: its seven (?<!\b<article> ) lookbehinds are exfilArticleRE on the prefix.
	exfilVerbRE       = regexp.MustCompile(`(?i)\b(?P<verb>` + exfilVerb + `)\b`)
	exfilArticleRE    = regexp.MustCompile(`(?i)\b(?:a|an|the|this|that|your|each) $`)
	exfilSenderMarkRE = regexp.MustCompile(`(?i)\b(?:from|sender|reply-to|on behalf of|signed(?: as)?)\b`)
	exfilQuoteIntroRE = regexp.MustCompile(`(?i)\b(?:like|says?|said|writ(?:e|es|ing)|reads?|requests?(?: to)?|asks?(?: the agent| you)? to|` +
		`prompts?(?: such as| like)?|such as|e\.?g\.?|for example|blocked|flagged|reject(?:s|ed)?|` +
		`detects?|catch(?:es)?|instructions? like)\s*:?\s*["'\x{201c}\x{2018}][^"'\x{201d}\x{2019}]*$`)
	exfilCodeSpanRE = regexp.MustCompile("`[^`\n]*`")
	exfilConnRE     = regexp.MustCompile(`(?i)\b(?:to|with|at|for|into|onto|via|through|over to|off to|addressed to)\b`)
	// regexp2: the gap group's inner lookahead \.(?=\S) decides the extent that becomes the object.
	exfilDitransRE = regexp2.MustCompile(`\b(?<verb>send(?:s)?|e-?mail(?:s)?|mail(?:s)?|forward(?:s)?|giv(?:e|es)|cc|bcc|dm|`+
		`text(?:s)?)\s+(?:the\s+)?(?<addr>[\w.+-]+@[\w-]+(?:\.[\w-]+)+)\s+`+
		`(?<gap>(?:[^.!?\n]|\.(?=\S)){1,80})`, regexp2.IgnoreCase)
	// _EXFIL_PARAM_RECIPIENT_RE: its (?<![?&/;]) is checked on the prefix by findAll's accept.
	exfilParamRecipientRE = regexp.MustCompile(`(?i)\b(?:to|recipients?|cc|bcc|dest(?:ination)?|target|address|mailto)\s*[=:]\s*['"]?` +
		`(?P<addr>[\w.+-]+@[\w-]+(?:\.[\w-]+)+|https?://[^\s'"<>)\]]+)`)
	exfilPassiveRE = regexp.MustCompile(`(?i)\b(?:should|must|will|shall|may|can|to|then|be|is|are|was|were|get|gets|got)\s+(?:be\s+)?` +
		`(?:also\s+|then\s+|immediately\s+)?$`)
	exfilObjectRE = regexp.MustCompile(`(?i)\b(?:it|them|they|this|these|that|those|details?|information|data|list|files?|results?|` +
		`summary|cop(?:y|ies)|records?|reports?|e-?mails?|history|passwords?|credentials?|holdings|` +
		`contents?|logs?|screenshots?|export|dump|backup|keys?|tokens?|secrets?|messages?|` +
		`contacts?|notes?|inbox|attachments?|archive|bundle|zip|snapshot|package|blob|table|` +
		`spreadsheet|csv|json|pdf|payload|everything)\b`)
	exfilPossessiveRE = regexp.MustCompile(`(?i)\b(?:my|the user'?s|users?'|their)\b`)
	// regexp2: the lazy gap with an inner lookahead fixes the extent that is the acquisition evidence.
	exfilAcquireRE = regexp2.MustCompile(`\b(?:retri\w*|get|fetch\w*|list|find|download\w*|access\w*|search\w*|read|export\w*|`+
		`collect\w*|gather\w*|look up|pull(?: up| down)?|obtain\w*|extract\w*|dump|cop(?:y|ies)|`+
		`query|scrape|enumerate|locate|grab|snag|bring up|take|captur\w*|harvest\w*|acquir\w*|`+
		`load)\b(?:[^.!?\n]|\.(?=\S)){0,80}?`+
		`\b(?:my|the user'?s|users?'|their|his|her|all (?:my|of my|the)|`+
		`(?:the |a )?(?:saved|stored|linked|personal|private|sensitive|confidential)\b|`+
		`(?:the |a )?(?:details?|information|data|records?|list|history|logs?|files?|holdings|`+
		`passwords?|credentials?|accounts?|payees?|contacts?|messages?|profile|prescriptions?|`+
		`image|summary|shipments?|friends|e-?mails?|notes?))|`+
		`\b(?:generat\w*|provide|check|use|open|view)\b(?:[^.!?\n]|\.(?=\S)){0,80}?`+
		`\b(?:my|the user'?s|users?'|their)\b`, regexp2.IgnoreCase)
	// _EXFIL_NEG_PREFIX_RE: its trailing (?!\W+(?:hesitate|...)\b) is exfilNegTailRE on the suffix.
	exfilNegPrefixRE = regexp.MustCompile(`(?i)\b(?:do not|don'?t|never|must not|must never|cannot|can'?t|will not|won'?t|should not|` +
		`shouldn'?t|under no circumstances|refrain from|forbidden to|not (?:allowed|permitted) to|` +
		`avoid(?:ing)?\s+(?:send|upload|shar|forward|post|transmit|e-?mail|export|leak|disclos|` +
		`transfer|giv)\w*|prohibited from)\b`)
	exfilNegTailRE  = regexp.MustCompile(`(?i)^\W+(?:hesitate|forget|fail|neglect|wait)\b`)
	exfilContrastRE = regexp.MustCompile(`(?i)\b(?:without(?: ever)?|instead of|rather than|in place of|as opposed to)\s+` +
		`(?:(?:ever|first|actually|also|then|directly|immediately|simply|just)\s+){0,2}$`)
	exfilDisclosureRE = regexp.MustCompile(`(?i)\b(?:this|the|our|its?)\s+(?:\w+\s+){0,2}(?:skill|tool|cli|plugin|app|extension|agent|` +
		`script|service|library|integration|telemetry|module)\b[^.!?\n]{0,40}?` +
		`\b(?:collects?|gathers?|sends?|posts?|uploads?|reports?|shares?|transmits?|logs?|records?)\b|` +
		`\bwe\s+(?:collect|gather|send|post|upload|share|report|log|record)\b`)
	exfilExampleTailRE = regexp.MustCompile(`(?i)\b(?:for example|for instance|e\.?g\.?|such as|like this|examples?|sample|payload|` +
		`looks? like|might (?:say|write|include|contain|read)|would (?:say|write|read))` +
		`\s*:?\s*["'` + "`" + `]?\s*$`)
	exfilExampleHeadingRE  = regexp.MustCompile(`(?i)\b(?:examples?|samples?|prompts?|demo)\b`)
	exfilPlaceholderHostRE = regexp.MustCompile(`(?i)(?:^|\.)example\.[a-z]{2,}$|\.(?:test|invalid|local|localhost)$|^localhost$|^your[-_.]|` +
		`^(?:my|our|the)[-_.]?(?:server|host|domain|company|site)\b`)
	exfilPlaceholderLocalRE = regexp.MustCompile(`(?i)^(?:you|user|users|name|email|someone|somebody|your[._-]?\w*|first[._-]?\w*|` +
		`john[._-]?doe|jane[._-]?doe|me|test|foo|bar|example|sample|placeholder|x+|abc)$`)
	exfilRoleLocalRE = regexp.MustCompile(`(?i)^(?:support|help(?:desk)?|bugs?|bug-?reports?|crash(?:es)?|feedback|security|issues?|` +
		`privacy|abuse|info|contact|hello|hi|team|dev(?:s|ops)?|ops|oncall|alerts?|sales|billing|` +
		`legal|press|careers|jobs|hr|postmaster|webmaster|noreply|no-reply|admin|root|it)$`)
	exfilAPIPrefixRE   = regexp.MustCompile(`(?i)^(?:api|apis|graph|rest|gateway)\d*\.|\.(?:api|apis)\.`)
	exfilServiceHostRE = regexp.MustCompile(`(?i)(?:^|\.)(?:(?:www|gmail|people|drive|sheets|calendar|oauth2|docs|admin)\.googleapis\.com|` +
		`graph\.microsoft\.com|api\.hubspot\.com|salesforce\.com|force\.com|dropboxapi\.com|` +
		`api\.dropbox\.com|api\.notion\.com|api\.sendgrid\.com|api\.mailchimp\.com|api\.twilio\.com|` +
		`api\.stripe\.com|api\.github\.com|api\.openai\.com|api\.anthropic\.com|slack\.com|` +
		`api\.airtable\.com|zendesk\.com|api\.trello\.com|api\.asana\.com|api\.box\.com|` +
		`api\.telegram\.org|api\.zoom\.us|api\.linear\.app|api\.intercom\.io|api\.pagerduty\.com)$`)
	exfilDevHostRE = regexp.MustCompile(`(?i)(?:^|\.)(?:github\.com|gitlab\.com|bitbucket\.org|codecov\.io|coveralls\.io|pypi\.org|` +
		`npmjs\.com|npmjs\.org|index\.docker\.io|ghcr\.io|quay\.io|crates\.io|rubygems\.org|` +
		`hooks\.slack\.com|discord\.com|discordapp\.com|sentry\.io|datadoghq\.com|newrelic\.com|` +
		`atlassian\.net|readthedocs\.io|huggingface\.co|hf\.co|s3(?:[.-][\w-]+)*\.amazonaws\.com|` +
		`storage\.googleapis\.com|blob\.core\.windows\.net|r2\.cloudflarestorage\.com|circleci\.com|` +
		`buildkite\.com|travis-ci\.com|jenkins\.io|semaphoreci\.com|dev\.azure\.com)$`)
	exfilTelemetryDataRE = regexp.MustCompile(`(?i)\b(?:logs?|crash (?:logs?|reports?|dumps?)|error logs?|build logs?|stack traces?|` +
		`diagnostics|metrics|telemetry|usage (?:data|stats))\b`)
	exfilTelemetryHostRE = regexp.MustCompile(`(?i)^(?:crash(?:es)?|errors?|logs?|telemetry|metrics|ingest|diagnostics|sentry|events?)\.`)
	exfilCredentialRE    = regexp.MustCompile(`(?i)\b(?:passwords?|passphrases?|credentials?|secrets?|tokens?|api keys?|private keys?|` +
		`ssh keys?|recovery codes?|2fa|otp|payment methods?|credit cards?|bank|ssn|social security|` +
		`health|medical|patient|private|confidential|(?:chat|browsing|browser|search) history|` +
		`(?:my|the user'?s|their|your)\s+(?:e-?mails?|messages?|chats?|inbox|history))\b`)
	exfilSensitiveRE = regexp.MustCompile(`(?i)\b(?:passwords?|passphrases?|credentials?|secrets?|tokens?|api keys?|private keys?|` +
		`ssh keys?|payment|credit cards?|cards?|bank|(?:bank|saving|linked|brokerage|crypto\w*) ` +
		`accounts?|account (?:numbers?|passwords?|credentials?|tokens?|recovery)|payees?|holdings|` +
		`health|medical|genetic|patient|prescriptions?|personal|private|confidential|ssn|` +
		`social security|contacts?|address book|(?:chat|browsing|browser|search) history|` +
		`(?:my|the user'?s|their|your)\s+(?:e-?mails?|` +
		`messages?|chats?|inbox|history|photos?|documents?|files|location)|` +
		`(?:browsing|search|purchase|order|location|access) history|wallet|seed phrase|identity|` +
		`2fa|mfa|one-time codes?)\b`)
	hostMetaRE = regexp.MustCompile(`[<>{}$\[\]]`)
	youRE      = regexp.MustCompile(`(?i)\byou\b`)
	yourRE     = regexp.MustCompile(`(?i)\byour\b`)
)

// span is one regexp2 match in code points.
type span struct {
	start, end int
	text       string
}

// firstAcquisition is the lazy form of `next((a for a in EXFIL_ACQUIRE.finditer(window)
// if not neg(_own_sentence(window, a))), None)` plus whether any acquisition exists: the
// first non-negated acquisition ends the scan, so it does not materialise every match over the
// bounded 4000-code-point window (the oracle's list() is cheap only because CPython's re is C).
func firstAcquisition(window string) (*span, bool) {
	any := false
	for m, _ := exfilAcquireRE.FindStringMatch(window); m != nil; m, _ = exfilAcquireRE.FindNextMatch(m) {
		any = true
		if !negated(ownSentence(window, m.Index, m.Index+m.Length)) {
			return &span{m.Index, m.Index + m.Length, m.String()}, true
		}
	}
	return nil, any
}

// sentence is one piece of _sentences: its code-point offset, byte offset and text in the block.
// byteStart keeps the backward window bounded to _EXFIL_WINDOW: the delivery's byte position is
// s.byteStart + byteIdx(s.text, d.start), so the window never rescans the whole prefix from 0.
type sentence struct {
	start, byteStart int
	text             string
}

func exfilSentences(raw string) []sentence {
	var out []sentence
	pos, runes := 0, 0 // runes counts raw[:pos] incrementally: one pass, not one per sentence
	for _, piece := range sentenceSplit(raw) {
		start := pos + strings.Index(raw[pos:], piece)
		runes += utf8.RuneCountInString(raw[pos:start])
		out = append(out, sentence{runes, start, piece})
		runes += utf8.RuneCountInString(piece)
		pos = start + len(piece)
	}
	return out
}

// lastRunes is s[-n:] on code points, scanned from the end so the cost is O(n), not O(len(s)).
func lastRunes(s string, n int) string {
	i := len(s)
	for cnt := 0; i > 0 && cnt < n; cnt++ {
		_, sz := utf8.DecodeLastRuneInString(s[:i])
		i -= sz
	}
	return s[i:]
}

// ownSentence is _own_sentence: the sentence of text around the code points [start, end), with
// up to 60 code points of lead-in.
func ownSentence(text string, start, end int) string {
	pre := sliceRunes(text, max(0, start-60), start)
	if c := max(strings.LastIndex(pre, ". "), strings.LastIndex(pre, "! "), strings.LastIndex(pre, "? ")); c >= 0 {
		pre = pre[c+2:]
	}
	stop := sentenceEndAfter(text, byteIdx(text, end))
	if stop < 0 {
		stop = len(text)
	}
	return pre + text[byteIdx(text, start):stop]
}

// negated is _EXFIL_NEG_PREFIX_RE.search(s) is not None.
func negated(s string) bool {
	return len(findAll(exfilNegPrefixRE, s, func(m []int) bool {
		return pytext.WordBoundary(s, m[0]) && !exfilNegTailRE.MatchString(s[m[1]:])
	})) > 0
}

// recipient is _exfil_recipient's result.
type recipient struct {
	addr, host, local string
	placeholderLocal  bool
}

// exfilRecipient is _exfil_recipient; ok is false for a placeholder or template host.
func exfilRecipient(addr string) (r recipient, ok bool) {
	addr = strings.TrimRight(addr, `.,;:'"`)
	var host, local string
	placeholder := false
	if strings.Contains(addr, "@") && !strings.Contains(addr, "://") {
		i := strings.LastIndexByte(addr, '@')
		local, host = addr[:i], addr[i+1:]
		placeholder = exfilPlaceholderLocalRE.MatchString(local)
	} else {
		u, err := pytext.URLSplit(addr)
		if err != nil {
			return recipient{}, false
		}
		host = u.Hostname()
	}
	host = pytext.Lower(host)
	if host == "" || !strings.Contains(host, ".") || hostMetaRE.MatchString(host) || exfilPlaceholderHostRE.MatchString(host) {
		return recipient{}, false
	}
	return recipient{addr, host, pytext.Lower(local), placeholder}, true
}

// exfilAddresses is _exfil_addresses: address matches (byte spans) after a connector ending at
// byte pos: the first within 60 code points, each next within 40 of the previous match, none
// past a sender mark.
func exfilAddresses(sentence string, pos int, x *runeIndex) [][]int {
	var out [][]int
	limit, last := x.rune(pos)+60, pos
	for _, m := range exfilAddrRE.FindAllStringIndex(sentence[pos:], -1) {
		start, end := pos+m[0], pos+m[1]
		if x.rune(start) > limit || exfilSenderMarkRE.MatchString(sentence[last:start]) {
			return out
		}
		out = append(out, []int{start, end})
		limit, last = x.rune(end)+40, end
	}
	return out
}

// delivery is one item of _exfil_deliveries; positions are code points in the sentence.
type delivery struct {
	start, end int     // the verb, ditransitive or parameter match m
	verb       string  // m.group("verb"), "" for a parameter
	gap        *string // the object text between verb and connector, the ditransitive gap, or None
	shape      string
	addr       string // the address text
	addrEnd    int    // end of the address match addr_m
}

// exfilDeliveries is _exfil_deliveries in its order: verb + connector + address, then
// ditransitive verbs, then recipient parameters.
func exfilDeliveries(sentence string, x *runeIndex) []delivery {
	var out []delivery
	verbs := findAll(exfilVerbRE, sentence, func(m []int) bool {
		// The article pattern is end-anchored and at most five bytes plus one of boundary
		// context, so the last six bytes decide it; the whole prefix per verb was O(n²).
		return pytext.WordBoundary(sentence, m[0]) && !exfilArticleRE.MatchString(sentence[max(0, m[0]-6):m[0]])
	})
	for _, v := range verbs {
		vEnd := v[1]
		limit := x.byte(x.rune(vEnd) + 120)
		for _, c := range exfilConnRE.FindAllStringIndex(sentence[vEnd:limit], -1) {
			for _, a := range exfilAddresses(sentence, vEnd+c[1], x) {
				gap := sentence[vEnd : vEnd+c[0]]
				out = append(out, delivery{x.rune(v[0]), x.rune(vEnd), sentence[v[2]:v[3]],
					&gap, "delivery", sentence[a[0]:a[1]], x.rune(a[1])})
			}
		}
	}
	for m, _ := exfilDitransRE.FindStringMatch(sentence); m != nil; m, _ = exfilDitransRE.FindNextMatch(m) {
		gap := m.GroupByName("gap").String()
		out = append(out, delivery{m.Index, m.Index + m.Length, m.GroupByName("verb").String(),
			&gap, "recipient-first delivery", m.GroupByName("addr").String(), m.Index + m.Length})
	}
	addr := exfilParamRecipientRE.SubexpIndex("addr")
	params := findAll(exfilParamRecipientRE, sentence, func(m []int) bool {
		prev, _ := utf8.DecodeLastRuneInString(sentence[:m[0]])
		return pytext.WordBoundary(sentence, m[0]) && (m[0] == 0 || !strings.ContainsRune("?&/;", prev))
	})
	for _, m := range params {
		out = append(out, delivery{x.rune(m[0]), x.rune(m[1]), "", nil,
			"recipient parameter", sentence[m[2*addr]:m[2*addr+1]], x.rune(m[1])})
	}
	return out
}

// dataExfilFindings is _data_exfil_findings: SXV-043 over one instruction-lane artifact.
func dataExfilFindings(a *parse.Artifact) []findings.Finding {
	var out []findings.Finding
	seen := map[[2]string]bool{}
	total := 0
	previous, prevTail, exampleSection := "", "", false
	for _, b := range proseBlocks(a) {
		raw := FlattenProse(b.Text)
		if raw == "" {
			continue
		}
		heading := strings.HasPrefix(raw, "#") // a heading opens a section and introduces nothing
		if heading {
			exampleSection = exfilExampleHeadingRE.MatchString(raw)
		}
		introPrev := exfilExampleTailRE.MatchString(previous)
		previous = raw
		if heading || inFrontmatter(a, b.Start) {
			previous = ""
		}
		sentences := exfilSentences(raw)
		for _, s := range sentences {
			sentence := exfilCodeSpanRE.ReplaceAllStringFunc(s.text, func(code string) string {
				return strings.Repeat(" ", utf8.RuneCountInString(code))
			})
			normalised := pytext.Lower(pytext.Strip(sentence)) // the digest's input and dedup key
			x, tx := indexRunes(sentence), indexRunes(s.text)
			for _, d := range exfilDeliveries(sentence, x) {
				rcp, ok := exfilRecipient(d.addr)
				if !ok {
					continue
				}
				// Dedup a delivery already emitted for this (recipient, sentence) before the
				// expensive window/acquisition scan: a duplicate produces no output, and the
				// intervening guards only ever `continue`, so skipping early cannot change results.
				key := [2]string{pytext.Lower(rcp.addr), normalised}
				if seen[key] {
					continue
				}
				pre := x.slice(max(0, d.start-80), d.start)
				tail := x.slice(d.addrEnd, d.addrEnd+80)
				obj, shape := pre, d.shape
				if d.gap != nil {
					switch gap := *d.gap; {
					case exfilObjectRE.MatchString(gap) || exfilPossessiveRE.MatchString(gap):
						obj = gap
					case exfilObjectRE.MatchString(d.verb): // "back them up", "hand it over"
						obj = d.verb
					case exfilPassiveRE.MatchString(pre) && (exfilObjectRE.MatchString(pre) || exfilPossessiveRE.MatchString(pre)):
						shape = "passive delivery"
					case pytext.Strip(gap) == "" && (exfilObjectRE.MatchString(tail) || exfilPossessiveRE.MatchString(tail)):
						obj, shape = tail, "recipient-first delivery" // "share with X a copy"
					default:
						continue
					}
				}
				// The block so far, plus the tail of the previous paragraph or list item, bounded
				// to the last _EXFIL_WINDOW code points (Python's [...][-4000:] without building the
				// whole prefix each delivery). before is the same window without the previous tail.
				head := raw[:s.byteStart+tx.byte(d.start)]
				before := lastRunes(head, exfilWindow)
				window := before
				if bc := utf8.RuneCountInString(before); bc < exfilWindow {
					window = lastRunes(prevTail+" ", exfilWindow-bc) + before
				}
				// Negation is judged sentence by sentence: an acquisition counts unless its own
				// sentence negates it, and the delivery sentence must not negate or contrast it.
				acquired, anyAcquisition := firstAcquisition(window)
				owned := exfilPossessiveRE.MatchString(obj) || (yourRE.MatchString(obj) && exfilSensitiveRE.MatchString(obj))
				if !anyAcquisition && !owned { // "send your passwords to ..."
					continue
				}
				if anyAcquisition && acquired == nil {
					continue
				}
				sentenceBefore := x.cut(d.start)
				if negated(x.cut(d.end)) || exfilContrastRE.MatchString(sentenceBefore) {
					continue
				}
				// a disclosure, not an order: third-person delivery verb or a product subject
				verb := pytext.Lower(d.verb)
				thirdPerson := strings.HasSuffix(verb, "s") && verb != "cc's" && verb != "bcc's" && !youRE.MatchString(sentenceBefore)
				acqSentence := sentence
				if acquired != nil {
					acqSentence = cutRunes(window, acquired.end)
					if i := strings.LastIndex(acqSentence, ". "); i >= 0 {
						acqSentence = acqSentence[i+2:]
					}
				}
				if thirdPerson || exfilDisclosureRE.MatchString(acqSentence) || exfilDisclosureRE.MatchString(sentenceBefore) {
					continue
				}
				data := window + " "
				if d.gap != nil {
					data += *d.gap
				}
				if exfilServiceHostRE.MatchString(rcp.host) && !exfilCredentialRE.MatchString(data) {
					continue
				}
				shared := exfilRoleLocalRE.MatchString(rcp.local) || exfilDevHostRE.MatchString(rcp.host)
				if shared && !exfilSensitiveRE.MatchString(data) {
					continue
				}
				if exfilTelemetryHostRE.MatchString(rcp.host) &&
					(exfilTelemetryDataRE.MatchString(obj) || exfilTelemetryDataRE.MatchString(acqSentence)) &&
					!exfilSensitiveRE.MatchString(data) && !exfilCredentialRE.MatchString(data) &&
					!exfilPossessiveRE.MatchString(sentence) && !exfilPossessiveRE.MatchString(acqSentence) &&
					!codelane.DropHostRE.MatchString(rcp.host) {
					continue
				}
				soft := rcp.placeholderLocal || exampleSection || exfilAPIPrefixRE.MatchString(rcp.host)
				if soft && !exfilCredentialRE.MatchString(data) {
					continue
				}
				if sxv042ExampleIntroRE.MatchString(sentenceBefore) || introPrev ||
					exfilQuoteIntroRE.MatchString(sentenceBefore) || isDefensiveFrame(before) {
					continue
				}
				seen[key] = true
				total++
				if total > findingCap {
					continue
				}
				line, col := SourcePosition(b.Text, b.Start, s.start+d.start)
				acquisition := "first-person object"
				if acquired != nil {
					acquisition = cutRunes(pytext.Strip(acquired.text), 80)
				}
				out = append(out, findings.Finding{
					Vector: "SXV-043", Rule: "data-exfil-directive", Severity: "high", Path: a.Rel,
					Line: findings.Int(line), Column: findings.Int(col),
					Message: "The instructions tell the agent to obtain the user's data and send it to a recipient " +
						"written into the skill (`" + cutRunes(rcp.addr, 80) + "`) -- a data-exfiltration directive, " +
						"not a task the user asked for.",
					Evidence: map[string]any{
						"directive_text": cutRunes(pytext.Strip(sentence), 200), "recipient": cutRunes(rcp.addr, 120),
						"acquisition": acquisition, "shape": shape, "line": line, "col": col,
						"selector": "data-exfil-directive:" + sha12(normalised),
						"snippet":  cutRunes(sliceRunes(raw, max(0, s.start-40), s.start+utf8.RuneCountInString(sentence)), 200)},
				})
				break // one finding per delivery
			}
		}
		prevTail = lastRunes(sentences[len(sentences)-1].text, exfilWindow) // only its tail reaches a window
	}
	if total > findingCap {
		out = append(out, capNote(a.Rel, "SXV-043", total-findingCap))
	}
	return out
}

// --- credential read directed to egress (SXV-011) ----------------------------
// _exfil_findings: the instruction lane directs the agent to READ a high-specificity credential
// artifact AND send it to a reachable network destination, positive polarity. Every egress path
// shares the governing manifest's network-reach gate; the same credential-linkage suppressions
// apply to the POST, GET-in-URL and non-HTTP sinks.

const (
	linkWindow      = 10 // _LINK_WINDOW
	defensiveWindow = 2  // _DEFENSIVE_WINDOW (SXV-011 only)
)

// _BASH_TOOLS, _NETWORK_TOOLS, _LOCAL_ONLY_TOOLS, _NETWORK_SINGLE and _LOCAL_ONLY_CMDS, copied verbatim.
var (
	bashTools      = map[string]bool{"Bash": true, "Shell": true, "Terminal": true, "Execute": true}
	networkTools   = map[string]bool{"WebFetch": true, "WebSearch": true}
	localOnlyTools = map[string]bool{"Read": true, "Write": true, "Edit": true, "MultiEdit": true,
		"NotebookEdit": true, "Glob": true, "Grep": true, "LS": true, "TodoWrite": true, "NotebookRead": true}
	networkSingle = map[string]bool{"curl": true, "wget": true, "nc": true, "ncat": true, "socat": true,
		"ssh": true, "scp": true, "sftp": true, "http": true, "httpie": true, "python": true, "python3": true,
		"node": true, "npx": true, "perl": true, "ruby": true, "git": true, "gh": true, "hub": true, "pip": true,
		"pip3": true, "pipx": true, "poetry": true, "uv": true, "npm": true, "yarn": true, "pnpm": true, "bun": true,
		"deno": true, "aws": true, "gcloud": true, "gsutil": true, "az": true, "kubectl": true, "helm": true,
		"docker": true, "podman": true, "rsync": true, "rclone": true, "aria2c": true, "ftp": true, "telnet": true,
		"openssl": true, "apt": true, "apt-get": true, "apk": true, "brew": true, "go": true, "cargo": true,
		"mvn": true, "gradle": true}
	localOnlyCmds = map[string]bool{"ls": true, "cat": true, "grep": true, "echo": true, "head": true,
		"tail": true, "cut": true, "sort": true, "uniq": true, "wc": true, "tr": true, "cp": true, "mv": true,
		"rm": true, "mkdir": true, "touch": true, "chmod": true, "chown": true, "diff": true, "tee": true,
		"date": true, "pwd": true, "basename": true, "dirname": true, "test": true, "true": true, "false": true,
		"sleep": true, "which": true, "printf": true, "jq": true, "yq": true, "gzip": true, "gunzip": true}
)

var (
	// _VARLINK_RE
	varlinkRE = regexp.MustCompile(`\$\w+|\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]*\b`)
	// _URL_HOST_RE
	urlHostRE = regexp.MustCompile(`://(?:[^/@?#\s]*@)?([^/?#\s]+)`)
	// _EGRESS_VERB_RE
	egressVerbRE = regexp.MustCompile(`(?i)\bPOST(?:ing|ed)?\b|\bPUT(?:ting)?\b|--data-binary|--data\b|-d @|` +
		`\bcurl\b[^\n]*\s-T\b|\bupload(?:s|ing)?\b|\bexfiltrat|\bcurl -X POST\b|` +
		`\b(?:send|transmit|share|forward|leak|email|mail|push|deliver|relay)\b` +
		`[^.\n]{0,30}?\b(?:it|them|its?|the(?:ir)?|to|with|at)\b`)
	// _FETCH_VERB_RE: LA on \bhttps?\b(?!://) applied in fetchVerbSearch.
	fetchVerbRE = regexp.MustCompile(`(?i)\bcurl\b|\bwget\b|\bfetch\b|\bInvoke-WebRequest\b|` +
		`\bInvoke-RestMethod\b|\biwr\b|\birm\b|\bhttpie\b|\bhttps?\b`)
	// _NEG_SAME_LINE_RE
	negSameLineRE = regexp.MustCompile(`(?i)\b(?:do not|don'?t|never|must not|refuse to|avoid)\s+` +
		`(?:read|open|access|touch|load|include|quote|print|expose|collect|` +
		`send|transmit|upload|post|share|exfiltrat\w*|leak|forward|email|expose)\b|` +
		`\bexclud(?:e|ed|ing)\b|\bblocklist\b|\bblacklist\b|\bprohibit`)
	// _ANTIPATTERN_RE
	antipatternRE = regexp.MustCompile(`(?i)ANTI-?PATTERN|do not run|never run|bad example|` +
		`vulnerable example|counter-?example`)
	// _DESTINATION_LINK_RE
	destinationLinkRE = regexp.MustCompile(`(?i)\b(?:collector|endpoint|destination|receiver|server|` +
		`webhook|upload|target|url)\b`)
	// _CRED_BACKREF_RE
	credBackrefRE = regexp.MustCompile(`(?i)\bthe (?:key|keys|private key|credential|credentials|secret|secrets|` +
		`token|tokens|password|passwords|api key)\b|\b(?:its|their) (?:contents?|value)\b|` +
		`\bwhat (?:you|we)(?:'ve| have)? read\b|\bwhat was read\b|` +
		`\b(?:everything|all|the (?:contents?|files?|data|output|snapshot)) (?:you|we)(?:'ve| have)? read\b`)
	// _CRED_CORROB_RX: LB on (?<![\w./-]) applied in credCorrobSearch.
	credCorrobRE = regexp.MustCompile(`(?i)\.env(?:\.local|\.production)?\b`)
	// defensiveIntroTailRE: inline r"\b(?:following|pattern|example)\b[^.\n]*:\s*$" in _collect_cred_hits, $ -> \z on a raw line.
	defensiveIntroTailRE = regexp.MustCompile(`(?i)\b(?:following|pattern|example)\b[^.\n]*:\s*\z`)
	// usingWithViaRE: inline r"\b(?:using|with|via)\s+(?:the\s+|your\s+|its\s+)?$" in _egress_backref.
	usingWithViaRE = regexp.MustCompile(`(?i)\b(?:using|with|via)\s+(?:the\s+|your\s+|its\s+)?\z`)
	// _CRED_AUTH_VALUE_RE
	credAuthValueRE = regexp.MustCompile(`(?i)(?:--(?:netrc-file|key|cert|cacert|config|user|oauth2-bearer|pass)|-[EKu])\s+` +
		`(?:\$\([^\n)]{0,80}|\S*)\s*\z`)
	// _CRED_BARE_NETRC_RE: LA on (?!-file) applied in credBareNetrcSearch.
	credBareNetrcRE = regexp.MustCompile(`(?i)--netrc\b`)
	// _CRED_AUTH_PROSE_RE
	credAuthProseRE = regexp.MustCompile(`(?i)\b(?:auth(?:enticate)?(?:\s+\w+){0,2}\s+(?:from|with|using)|` +
		`log\s?in(?:\s+\w+){0,2}\s+(?:from|with)|registry auth|credentials?\s+(?:for|from)|` +
		`(?:with|using)\s+(?:the\s+|your\s+)?(?:token|credential|key|secret|password|api\s+key)s?)\b`)
	// _CRED_PAYLOAD_FLAG_RE
	credPayloadFlagRE = regexp.MustCompile(`(?i)(?:-d|--data(?:-binary|-raw|-urlencode)?|-T|--upload-file|-F|--form)\s*@?\s*\z`)
	// _CRED_SENT_DIRECTLY_RE
	credSentDirectlyRE = regexp.MustCompile(`(?i)\b(?:upload|send|post|exfiltrat\w*|transmit|leak|forward|email|mail)\s+\S*\z`)
	// _CRED_PIPE_PAYLOAD_RE
	credPipePayloadRE = regexp.MustCompile(`(?i)\|\s*curl\b[^\n]*(?:--data(?:-binary|-raw|-urlencode)?|-d)\s+@-(?:\s|\z)`)
	// credAtEndRE: inline r"@\s*$" in _cred_is_auth_input.
	credAtEndRE = regexp.MustCompile(`@\s*\z`)
	// _NONHTTP_EGRESS_RE, $ -> \z on a raw line; RE2 is linear.
	nonhttpEgressRE = regexp.MustCompile(`(?i)\b(?:scp|sftp|rsync)\b(?:\s+\S+)*?\s+(?:[\w.-]+@)?[\w.-]+:\S*\s*\z|` +
		`\b(?:nc|ncat|netcat|socat)\b[^\n]*?\b\d{1,5}\b`)
)

// credPat is one _CRED_HIGH row; reject is the (?!\.pub) lookahead post-check, nil for plain patterns.
type credPat struct {
	re     *regexp.Regexp
	kind   string
	reject func(raw string, m []int) bool
}

// _CRED_HIGH_RX; #22/#23 are LA (skip a match followed by .pub).
var credHighRX = []credPat{
	{regexp.MustCompile(`(?i)~?/?\.aws/credentials`), "aws_credentials", nil},
	{regexp.MustCompile(`(?i)~?/?\.ssh/id_(?:rsa|ed25519|ecdsa|dsa)\b`), "ssh_private_key", rejectDotPub},
	{regexp.MustCompile(`(?i)\bid_(?:rsa|ed25519)\b`), "ssh_private_key", rejectDotPub},
	{regexp.MustCompile(`(?i)~?/?\.netrc\b`), "netrc", nil},
	{regexp.MustCompile(`(?i)~?/?\.config/gh/hosts\.ya?ml`), "gh_token_store", nil},
	{regexp.MustCompile(`(?i)~?/?\.claude/settings(?:\.local)?\.json`), "agent_settings", nil},
	{regexp.MustCompile(`(?i)~?/?\.docker/config\.json`), "docker_registry_auth", nil},
	{regexp.MustCompile(`(?i)~?/?\.kube/config\b`), "kubeconfig", nil},
	{regexp.MustCompile(`(?i)~?/?\.gnupg/`), "gpg_keyring", nil},
	{regexp.MustCompile(`(?i)~?/?\.git-credentials\b`), "git_credentials", nil},
	{regexp.MustCompile(`(?i)~?/?\.npmrc\b`), "npm_authtoken", nil},
	{regexp.MustCompile(`(?i)~?/?\.pypirc\b`), "pypi_credentials", nil},
	{regexp.MustCompile(`(?i)~?/?\.config/gcloud/(?:application_default_credentials|credentials)\.\w+`), "gcp_adc", nil},
	{regexp.MustCompile(`(?i)~?/?\.config/gcloud/legacy_credentials`), "gcp_gcloud", nil},
	{regexp.MustCompile(`(?i)~?/?\.azure/(?:accessTokens\.json|azureProfile\.json|msal_token_cache\.\w+)`), "azure_token", nil},
	{regexp.MustCompile(`(?i)/var/run/secrets/kubernetes\.io/serviceaccount/token`), "kube_sa_token", nil},
}

func rejectDotPub(raw string, m []int) bool {
	s := raw[m[1]:]
	return len(s) >= 4 && strings.EqualFold(s[:4], ".pub") // .pub is a PUBLIC key, not a secret
}

// firstCredMatch is rx.search(raw): the first match, honouring the .pub lookahead post-check.
func firstCredMatch(p credPat, raw string) (start, end int, ok bool) {
	if p.reject == nil {
		if m := p.re.FindStringIndex(raw); m != nil {
			return m[0], m[1], true
		}
		return 0, 0, false
	}
	hits := findAll(p.re, raw, func(m []int) bool { return !p.reject(raw, m) })
	if len(hits) > 0 {
		return hits[0][0], hits[0][1], true
	}
	return 0, 0, false
}

// varTokens is _vartokens: leading $ stripped, case-folded identifiers on a line, as a set.
func varTokens(s string) map[string]bool {
	out := map[string]bool{}
	for _, t := range varlinkRE.FindAllString(s, -1) {
		out[pytext.Lower(strings.TrimLeft(t, "$"))] = true
	}
	return out
}

// egressHostTokens is _egress_host_tokens: the destination host's tokens (never link a secret).
func egressHostTokens(url string) map[string]bool {
	if m := urlHostRE.FindStringSubmatch(url); m != nil {
		return varTokens(m[1])
	}
	return map[string]bool{}
}

func subtractSets(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if !b[k] {
			out[k] = true
		}
	}
	return out
}

// credCorrobSearch is _CRED_CORROB_RX.search: .env corroboration, with the (?<![\w./-]) lookbehind.
func credCorrobSearch(text string) bool {
	return len(findAll(credCorrobRE, text, func(m []int) bool {
		if m[0] == 0 {
			return true
		}
		r, _ := utf8.DecodeLastRuneInString(text[:m[0]])
		return !(pytext.IsWord(r) || r == '.' || r == '/' || r == '-')
	})) > 0
}

// fetchVerbSearch is _FETCH_VERB_RE.search: a fetch verb not followed by :// (the https? case).
func fetchVerbSearch(raw string) bool {
	return len(findAll(fetchVerbRE, raw, func(m []int) bool {
		return !strings.HasPrefix(raw[m[1]:], "://")
	})) > 0
}

// credBareNetrcSearch is _CRED_BARE_NETRC_RE.search: --netrc not followed by -file.
func credBareNetrcSearch(raw string) bool {
	return len(findAll(credBareNetrcRE, raw, func(m []int) bool {
		return !strings.HasPrefix(raw[m[1]:], "-file")
	})) > 0
}

// launcherSuffixes are the suffixes _basename_any strips.
var launcherSuffixes = []string{".exe", ".cmd", ".bat", ".com", ".ps1"}

// grantTokens is _grant_tokens: (command, tokens) from a grant paren-spec.
func grantTokens(pattern *string) (string, []string) {
	if pattern == nil {
		return "", nil
	}
	cmd := pytext.Strip(*pattern)
	if strings.HasSuffix(cmd, ":*") {
		cmd = cmd[:len(cmd)-2]
	} else if i := strings.IndexByte(cmd, ':'); i >= 0 {
		cmd = cmd[:i]
	}
	cmd = pytext.Strip(cmd)
	return cmd, pytext.Fields(cmd)
}

// reachesNetwork is Grant.reaches_network reconstructed from the IR's data-only Grant.
func reachesNetwork(g parse.Grant) bool {
	if networkTools[g.Tool] {
		return true
	}
	if !bashTools[g.Tool] { // non-bash: known-local cannot reach, MCP/Task/unknown fail open
		return !localOnlyTools[g.Tool]
	}
	command, tokens := grantTokens(g.Pattern)
	if g.Pattern == nil || command == "" || command == "*" || command == "**" {
		return true
	}
	if len(tokens) == 0 {
		return true
	}
	cmd0 := pytext.CommandBasename(strings.TrimRight(tokens[0], `/\`), launcherSuffixes...) // _basename_any
	if networkSingle[cmd0] {
		return true
	}
	return !localOnlyCmds[cmd0]
}

// reachIsFailOpen is _reach_is_fail_open: network-capable only by the unrecognized-tool rule.
func reachIsFailOpen(g parse.Grant) bool {
	return !networkTools[g.Tool] && !bashTools[g.Tool] && !localOnlyTools[g.Tool]
}

// hasAllowedTools is `"allowed-tools" in (manifest.frontmatter or {})`.
func hasAllowedTools(m *parse.Artifact) bool {
	if m.Frontmatter == nil {
		return false
	}
	_, ok := m.Frontmatter["allowed-tools"]
	return ok
}

// clauseAt is _clause_at: the ';'/'. '-delimited clause of s containing byte index idx.
func clauseAt(s string, idx int) string {
	start := 0
	for _, sep := range []string{";", ". "} {
		if p := strings.LastIndex(s[:idx], sep); p != -1 {
			start = max(start, p+len(sep))
		}
	}
	end := len(s)
	for _, sep := range []string{";", ". "} {
		if p := strings.Index(s[idx:], sep); p != -1 {
			end = min(end, idx+p)
		}
	}
	return s[start:end]
}

// listIntroIndex is _list_intro_index: 0-based index of the prose line introducing the bullet
// list line n sits in, or -1 (Python None).
func listIntroIndex(raws []string, n int) int {
	if !listItemRE.MatchString(raws[n-1]) {
		return -1
	}
	for i := n - 2; i >= 0; i-- {
		if probe := raws[i]; pytext.Strip(probe) == "" || listItemRE.MatchString(probe) {
			continue
		}
		return i
	}
	return -1
}

// fenceLabelledAntipattern is _fence_labelled_antipattern.
func fenceLabelledAntipattern(raws []string, openByLine map[int]int, n int) bool {
	openLine := n
	if v, ok := openByLine[n]; ok {
		openLine = v
	}
	lo := max(0, openLine-4)
	hi := min(len(raws), openLine+3)
	return antipatternRE.MatchString(strings.Join(raws[lo:hi], "\n"))
}

// credIsAuthInput is _cred_is_auth_input: the credential authenticates the request (auth flag or
// prose) rather than being the payload sent.
func credIsAuthInput(raw, cred string) bool {
	before, after := raw, ""
	if i := strings.Index(raw, cred); i >= 0 {
		before, after = raw[:i], raw[i+len(cred):]
	}
	inURL := strings.Contains(strings.Join(egressURLRE.FindAllString(raw, -1), ""), cred)
	payload := credPayloadFlagRE.MatchString(before) || credAtEndRE.MatchString(before) || inURL ||
		credSentDirectlyRE.MatchString(before) || credPipePayloadRE.MatchString(after)
	if payload {
		return false
	}
	directAuthValue := credAuthValueRE.MatchString(before)
	defaultNetrc := strings.HasSuffix(pytext.Lower(cred), ".netrc") && credBareNetrcSearch(raw)
	return directAuthValue || defaultNetrc || credAuthProseRE.MatchString(before)
}

// egressBackref is _egress_backref: a credential noun on the send line links a split read as a
// payload back-reference, unless the noun is itself governed by using/with/via (the auth).
func egressBackref(text string) bool {
	for _, m := range credBackrefRE.FindAllStringIndex(text, -1) {
		if !usingWithViaRE.MatchString(text[max(0, m[0]-14):m[0]]) {
			return true
		}
	}
	return false
}

// egressCand is one egress candidate: its 1-based line and the destination URL/sink text.
type egressCand struct {
	line int
	url  string
}

// getEgress is one _get_exfil_egresses candidate: line, URL and the payload tokens outside the host.
type getEgress struct {
	line    int
	url     string
	payload map[string]bool
}

// fullMatchURL is _EGRESS_URL_RE.fullmatch(s): the whole string is one egress URL.
func fullMatchURL(s string) bool {
	m := egressURLRE.FindStringIndex(s)
	return m != nil && m[0] == 0 && m[1] == len(s)
}

// postEgresses is _post_egresses: every POST/upload egress candidate in document order.
func postEgresses(raws []string, md *parse.Markdown) []egressCand {
	var out []egressCand
	var links []parse.Link
	var codeSpans []parse.Span
	if md != nil {
		links, codeSpans = md.Links, md.CodeSpans
	}
	for n := 1; n <= len(raws); n++ {
		raw := raws[n-1]
		if !egressVerbRE.MatchString(raw) {
			continue
		}
		chosen, has := "", false
		if urls := egressURLRE.FindAllString(raw, -1); len(urls) > 0 { // same-line URL, document order
			chosen, has = urls[0], true
		}
		if !has && n < len(raws) {
			if candidate := strings.TrimRight(pytext.Strip(raws[n]), ".,)"); fullMatchURL(candidate) {
				chosen, has = candidate, true
			}
		}
		if !has && strings.HasSuffix(pytext.RStrip(raw), ":") { // one adjacent link or code block
			i := n
			for i < len(raws) && pytext.Strip(raws[i]) == "" {
				i++
			}
			nextLine := i + 1
			for _, lk := range links {
				if lk.Line == nextLine && destinationLinkRE.MatchString(lk.Label) && fullMatchURL(lk.Href) {
					chosen, has = lk.Href, true
					break
				}
			}
			if !has {
				for _, sp := range codeSpans {
					if sp.Start <= n {
						continue
					}
					gapEnd := min(sp.Start-1, len(raws))
					blankGap := true
					for _, l := range raws[n:gapEnd] {
						if pytext.Strip(l) != "" {
							blankGap = false
							break
						}
					}
					if !blankGap {
						break
					}
					for lineNo := sp.Start; lineNo <= min(sp.End, len(raws)); lineNo++ {
						if command := raws[lineNo-1]; egressVerbRE.MatchString(command) {
							if u := egressURLRE.FindString(command); u != "" {
								chosen, has = u, true
								break
							}
						}
					}
					break
				}
			}
		}
		if has {
			out = append(out, egressCand{n, chosen})
		}
	}
	return out
}

// getExfilEgresses is _get_exfil_egresses: fetch-verb lines whose URL carries a token in its
// path/query/userinfo, in document order.
func getExfilEgresses(raws []string) []getEgress {
	var out []getEgress
	for n := 1; n <= len(raws); n++ {
		raw := raws[n-1]
		if !fetchVerbSearch(raw) {
			continue
		}
		urls := map[string]bool{}
		for _, u := range egressURLRE.FindAllString(raw, -1) {
			urls[u] = true
		}
		for _, u := range slices.Sorted(maps.Keys(urls)) {
			if payload := subtractSets(varTokens(u), egressHostTokens(u)); len(payload) > 0 {
				out = append(out, getEgress{n, u, payload})
			}
		}
	}
	return out
}

// nonhttpEgresses is _nonhttp_egresses: scp/sftp/rsync to user@host: or a pipe/host:port to nc/socat.
func nonhttpEgresses(raws []string) []egressCand {
	var out []egressCand
	for n := 1; n <= len(raws); n++ {
		if nonhttpEgressRE.MatchString(raws[n-1]) {
			out = append(out, egressCand{n, cutRunes(pytext.Strip(raws[n-1]), 80)})
		}
	}
	return out
}

// credHit is one _collect_cred_hits entry; col counts code points (m.start()+1).
type credHit struct {
	kind, text string
	line, col  int
}

// collectCredHits is _collect_cred_hits: credential reads linked to the egress at egressLine,
// classified by polarity and context. Shared by the POST, GET and non-HTTP paths.
func collectCredHits(raws []string, inFence map[int]bool, openByLine map[int]int,
	egressLine int, egressVars map[string]bool, backref bool) []credHit {
	var hits []credHit
	lo := max(1, egressLine-linkWindow)
	hi := min(len(raws), egressLine+linkWindow)
	for n := lo; n <= hi; n++ {
		raw := raws[n-1]
		if n != egressLine {
			shared := false
			for t := range varTokens(raw) {
				if egressVars[t] {
					shared = true
					break
				}
			}
			if !shared && !backref {
				continue
			}
		}
		lineKinds := map[string]bool{} // dedup overlapping matches on this line
		tableRow, egressVerb := isTableRow(raw), egressVerbRE.MatchString(raw)
		for _, p := range credHighRX {
			start, end, ok := firstCredMatch(p, raw)
			if !ok {
				continue
			}
			text := raw[start:end]
			if tableRow && !egressVerb {
				continue
			}
			if n == egressLine && credIsAuthInput(raw, text) {
				continue
			}
			if inFence[n] && fenceLabelledAntipattern(raws, openByLine, n) {
				continue
			}
			negScope := raw // split-line safety statements govern the whole line
			if n == egressLine {
				negScope = clauseAt(raw, start)
			}
			if negSameLineRE.MatchString(negScope) {
				continue
			}
			if intro := listIntroIndex(raws, n); intro >= 0 && negSameLineRE.MatchString(raws[intro]) {
				continue
			}
			introduced := false
			for _, frame := range raws[max(0, n-1-defensiveWindow) : n-1] {
				if isDefensiveFrame(pytext.Strip(frame)) && defensiveIntroTailRE.MatchString(frame) {
					introduced = true
					break
				}
			}
			if isDefensiveFrame(raw[:start]) || introduced {
				continue
			}
			if lineKinds[p.kind] {
				continue
			}
			lineKinds[p.kind] = true
			hits = append(hits, credHit{p.kind, text, n, runeIdx(raw, start) + 1})
		}
	}
	return hits
}

// exfilFindings is _exfil_findings: SXV-011.
func exfilFindings(a *parse.Artifact, manifestByDir map[string]*parse.Artifact) []findings.Finding {
	text := ""
	if a.Text != nil {
		text = *a.Text
	}
	raws := strings.Split(text, "\n")
	inFence, openByLine := fencedLines(a.Markdown, len(raws))

	// The reach gate all egress paths share.
	var reaching string
	var provenReach bool
	if manifest := parse.GoverningManifest(manifestByDir, a.Rel); manifest == nil || !hasAllowedTools(manifest) {
		reaching, provenReach = "undeclared_inherits_all", true // inherits Bash/WebFetch
	} else {
		grants := manifest.Grants
		bashDenied := false
		for _, g := range grants {
			if bashTools[g.Tool] && g.Broad && !g.Allowed {
				bashDenied = true
				break
			}
		}
		var netGrants []parse.Grant
		for _, g := range grants {
			if g.Allowed && !(bashDenied && bashTools[g.Tool]) && reachesNetwork(g) {
				netGrants = append(netGrants, g)
			}
		}
		if len(netGrants) == 0 { // declared, but nothing reaches the network
			return nil
		}
		raw := make([]string, len(netGrants))
		for i, g := range netGrants {
			raw[i] = g.Raw
		}
		slices.Sort(raw)
		reaching = strings.Join(raw, ", ")
		for _, g := range netGrants {
			if !reachIsFailOpen(g) {
				provenReach = true
				break
			}
		}
	}

	// POST candidates first, then bare GET, then non-HTTP; the first with linked hits wins.
	var egress *egressCand
	method := "post"
	var credHits []credHit
	for _, cand := range postEgresses(raws, a.Markdown) {
		egressText := raws[cand.line-1]
		egressVars := subtractSets(varTokens(egressText), egressHostTokens(cand.url))
		if hits := collectCredHits(raws, inFence, openByLine, cand.line, egressVars, egressBackref(egressText)); len(hits) > 0 {
			c := cand
			egress, credHits = &c, hits
			break
		}
	}
	if len(credHits) == 0 {
		for _, ge := range getExfilEgresses(raws) {
			if hits := collectCredHits(raws, inFence, openByLine, ge.line, ge.payload, false); len(hits) > 0 {
				egress, credHits, method = &egressCand{ge.line, ge.url}, hits, "get"
				break
			}
		}
	}
	if len(credHits) == 0 {
		for _, cand := range nonhttpEgresses(raws) {
			egressText := raws[cand.line-1]
			if hits := collectCredHits(raws, inFence, openByLine, cand.line, varTokens(egressText), egressBackref(egressText)); len(hits) > 0 {
				c := cand
				egress, credHits, method = &c, hits, "non-http"
				break
			}
		}
	}
	if egress == nil || len(credHits) == 0 {
		return nil
	}

	first := credHits[0]
	for _, h := range credHits[1:] {
		if h.line < first.line || (h.line == first.line && h.col < first.col) {
			first = h
		}
	}
	kindSet := map[string]bool{}
	for _, h := range credHits {
		kindSet[h.kind] = true
	}
	kinds := slices.Sorted(maps.Keys(kindSet))
	sorted := append([]credHit(nil), credHits...)
	slices.SortStableFunc(sorted, func(a, b credHit) int { return cmp.Or(cmp.Compare(a.line, b.line), cmp.Compare(a.col, b.col)) })
	tokens := make([]any, len(sorted)) // evidence lists are []any with integral numbers as int
	for i, h := range sorted {
		tokens[i] = map[string]any{"kind": h.kind, "line": h.line, "text": h.text}
	}
	severity, tail := "high", "network reach unproven (fail-open on unrecognized grant "+reaching+")"
	if provenReach {
		severity, tail = "critical", "the declared grant "+reaching+" can reach the network"
	}
	return []findings.Finding{{
		Vector: "SXV-011", Rule: "cred-egress", Severity: severity, Path: a.Rel, Line: findings.Int(first.line),
		Message: fmt.Sprintf("instruction lane directs the agent to read %d credential artifact reference(s) (%s) "+
			"and send them to %s via %s; positive imperative polarity and %s",
			len(credHits), strings.Join(kinds, ", "), egress.url, strings.ToUpper(method), tail),
		Evidence: map[string]any{
			"credential_tokens": tokens, "egress_target": egress.url, "egress_line": egress.line,
			"egress_method": method, "polarity": "positive", "reaching_grant": reaching,
			"dotenv_corroboration": credCorrobSearch(text), "line": first.line, "col": first.col,
			"selector": "cred-egress:" + strings.Join(kinds, "|"), "snippet": pytext.Strip(raws[first.line-1]),
		},
	}}
}
