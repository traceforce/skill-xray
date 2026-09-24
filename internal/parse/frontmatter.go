package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	yaml "go.yaml.in/yaml/v3"

	"github.com/traceforce/skill-xray/internal/pytext"
)

// fmBounds is _fm_bounds: the normalised lines, whether line 0 opens a `---` block and the
// 0-based index of its `---`/`...` terminator (-1 when unterminated).
func fmBounds(text string) (lines []string, hasOpen bool, end int) {
	lines = strings.Split(normNewlines(text), "\n")
	first := strings.TrimLeft(lines[0], "\ufeff")
	if pytext.RStrip(first) != "---" {
		return lines, false, -1
	}
	for i := 1; i < len(lines); i++ {
		s := lines[i]
		if t := pytext.RStrip(s); t == "---" || t == "..." {
			return lines, true, i
		}
	}
	return lines, true, -1
}

// bodyAndOffset is _body_and_offset: the markdown body past a closed frontmatter block and the
// line offset to add to every body line.
func bodyAndOffset(text string) (string, int) {
	lines, hasOpen, end := fmBounds(text)
	if !hasOpen || end < 0 {
		return text, 0
	}
	return strings.Join(lines[end+1:], "\n"), end + 1
}

const (
	maxFMChars = 16384 // _MAX_FM_BYTES (code points: Python len)
	maxFMFlow  = 256   // _MAX_FM_FLOW
)

// loadFrontmatter is _parse_frontmatter_details plus the frontmatter_end_line assignment of
// _parse_one: it fills Frontmatter, FrontmatterKeys, FrontmatterKeyLines, FrontmatterEndLine and
// UnsafeYamlTags and returns the error code ("" for none or no block).
func loadFrontmatter(a *Artifact, text string) string {
	lines, hasOpen, end := fmBounds(text)
	switch {
	case !hasOpen:
		return ""
	case end < 0:
		return "frontmatter_unterminated"
	}
	a.FrontmatterEndLine = end + 1
	block := strings.Join(lines[1:end], "\n")
	if utf8.RuneCountInString(block) > maxFMChars {
		return "frontmatter_too_large"
	}
	if strings.Count(block, "[")+strings.Count(block, "{") > maxFMFlow {
		return "frontmatter_too_deep"
	}
	return fmLoad(a, block)
}

var (
	yamlLineRE = regexp.MustCompile(`^yaml: line (\d+):`)
	// nodePropertyRE is an `&anchor` or `*alias` where a node can start: after an indicator.
	nodePropertyRE = regexp.MustCompile(`(?m)(?:^|[-:,\[{?]) *[&*][^\s\[\]{},]+`)
	// surrogateEscRE is a `\u`/`\U` escape of a surrogate code point: a high half with its
	// adjacent low half (groups 1 and 2) or a lone half.
	surrogateEscRE = regexp.MustCompile(`\\(?:u|U0000)(?:([dD][89abAB][0-9a-fA-F]{2})(?:\\(?:u|U0000)([dD][c-fC-F][0-9a-fA-F]{2}))?|[dD][c-fC-F][0-9a-fA-F]{2})`)
)

const invalidEscape = "found invalid Unicode character escape code"

// decodeFM parses the block to its node tree. The leading newline shifts every yaml.v3 mark by
// one line, so node lines and the "yaml: line N:" of scanner errors read directly as file lines
// (block line 0 is file line 2) and an error on the block's first line keeps its number (yaml.v3
// drops a line-0 mark).
func decodeFM(block string) (*yaml.Decoder, *yaml.Node, error) {
	dec := yaml.NewDecoder(strings.NewReader("\n" + block))
	root := &yaml.Node{}
	return dec, root, dec.Decode(root)
}

// yamlErr is a construction failure code raised through the node walk.
type yamlErr string

// fmLoad is _fm_load: refuse unsafe tags and anchors/aliases on the node tree, then construct
// values the way ruamel's round-trip loader does.
func fmLoad(a *Artifact, block string) (code string) {
	dec, root, err := decodeFM(block)
	// yaml.v3 (libyaml) refuses a \u escape of a surrogate code point where ruamel's pure-Python
	// scanner takes chr(code). The error names only the line the scalar starts on, so each
	// surrogate escape is probed as \z, which yaml.v3 rejects only inside a double-quoted scalar,
	// and the one it rejected is rewritten in place (columns move, lines do not): a high+low pair
	// to its code point, a lone half to U+FFFD, an accepted difference from Python's YAML loader.
	for from := 0; err != nil && strings.Contains(err.Error(), invalidEscape); {
		m := surrogateEscRE.FindStringSubmatchIndex(block[from:])
		if m == nil {
			break
		}
		start, end := from+m[0], from+m[1]
		if _, _, e := decodeFM(block[:start] + `\z` + block[end:]); e == nil || !strings.Contains(e.Error(), "found unknown escape character") {
			from = end
			continue
		}
		cp := rune(utf8.RuneError)
		if m[2] >= 0 && m[4] >= 0 {
			hi, _ := strconv.ParseUint(block[from+m[2]:from+m[3]], 16, 32)
			lo, _ := strconv.ParseUint(block[from+m[4]:from+m[5]], 16, 32)
			cp = utf16.DecodeRune(rune(hi), rune(lo))
		}
		repl := fmt.Sprintf(`\U%08X`, cp)
		block, from = block[:start]+repl+block[end:], start+len(repl)
		dec, root, err = decodeFM(block)
	}
	if err != nil && err != io.EOF {
		// ruamel walks the event stream and sees an anchor or alias emitted before the error;
		// yaml.v3 gives up on the syntax error, so the properties are read off the text up to
		// the error line.
		upTo := block
		m := yamlLineRE.FindStringSubmatch(err.Error())
		if m != nil {
			n, _ := strconv.Atoi(m[1])
			upTo = strings.Join(strings.Split(block, "\n")[:min(max(n-1, 0), strings.Count(block, "\n")+1)], "\n")
		}
		if strings.Contains(err.Error(), "unknown anchor") || nodePropertyRE.MatchString(upTo) {
			return "yaml_alias_budget"
		}
		if m != nil && !strings.Contains(err.Error(), invalidEscape) { // a \U past 0x10FFFF: ruamel's chr() ValueError has no mark
			return "yaml_error:line " + m[1]
		}
		return "yaml_error"
	}
	var alias bool
	var tags []YamlTag
	walkYAML(root, func(n *yaml.Node) {
		alias = alias || n.Anchor != "" || n.Kind == yaml.AliasNode
		if tag := n.LongTag(); n.Style&yaml.TaggedStyle != 0 && dangerousYamlTag.MatchString(tag) {
			tags = append(tags, YamlTag{Tag: tag, Line: n.Line, Column: n.Column})
		}
	})
	if len(tags) > 0 {
		a.UnsafeYamlTags = tags
		return "yaml_unsafe_tag"
	}
	if alias {
		return "yaml_alias_budget"
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF { // ruamel: "expected a single document in the stream"
		return fmt.Sprintf("yaml_error:line %d", extra.Line)
	}
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(yamlErr)
			if !ok {
				panic(r)
			}
			code = string(e)
		}
	}()
	if root.Kind == 0 || root.Content[0].Kind == yaml.ScalarNode && construct(root.Content[0]) == nil {
		a.Frontmatter = map[string]any{}
		return ""
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return "frontmatter_not_a_mapping"
	}
	values, keys, lines := mapping(doc)
	a.Frontmatter, a.FrontmatterKeys, a.FrontmatterKeyLines = values, keys, lines
	return ""
}

func walkYAML(n *yaml.Node, visit func(*yaml.Node)) {
	visit(n)
	for _, c := range n.Content {
		walkYAML(c, visit)
	}
}

// dangerousYamlTag is regex 19 (python/name|module|object), the ruby prefixes and the two exact Java gadget tags.
var dangerousYamlTag = regexp.MustCompile(`^(?:!ruby/(?:exception|hash|object|struct):|tag:yaml\.org,2002:(?:ruby/(?:exception|hash|object|struct):|python/(?:name|module|object)(?:/(?:new|apply))?(?::|\z)|javax\.script\.ScriptEngineManager\z|java\.net\.URLClassLoader\z))`)

// Opaque is a frontmatter scalar Python holds as a non-JSON object (a date, datetime, ruamel
// TimeStamp or TaggedScalar): Type is the Python class name and Text its str(), the shape the
// IR dump renders such values in.
type Opaque struct{ Type, Text string }

func (o Opaque) MarshalJSON() ([]byte, error) { return json.Marshal([2]string{o.Type, o.Text}) }

// construct builds the Python value of one node (ruamel RoundTripConstructor semantics with
// _plain applied: str keys, plain dicts and lists).
func construct(n *yaml.Node) any {
	switch n.Kind {
	case yaml.MappingNode:
		v, _, _ := mapping(n)
		return v
	case yaml.SequenceNode:
		if n.Style&yaml.TaggedStyle != 0 && n.ShortTag() == "!!map" {
			panic(yamlErr(fmt.Sprintf("yaml_error:line %d", n.Line)))
		}
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			out = append(out, construct(c))
		}
		return out
	}
	return scalar(n)
}

// mapping constructs a mapping: own pairs in document order, then `<<` merges (own keys win),
// returning the values, the str(k) keys in that order and each own key's file line.
func mapping(n *yaml.Node) (map[string]any, []string, map[string]int) {
	out, lines := map[string]any{}, map[string]int{}
	var order []string
	seen := map[any]bool{}
	var merges []*yaml.Node
	put := func(k string, v any) {
		if _, dup := out[k]; !dup {
			order = append(order, k)
		}
		out[k] = v
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		kn, vn := n.Content[i], n.Content[i+1]
		if kn.Kind == yaml.ScalarNode && kn.Style&yaml.TaggedStyle == 0 && kn.ShortTag() == "!!merge" {
			merges = append(merges, vn)
			continue
		}
		k := construct(kn)
		if kn.Kind == yaml.ScalarNode { // ruamel compares constructed keys (Python equality)
			if seen[k] {
				panic(yamlErr("yaml_duplicate_key"))
			}
			seen[k] = true
		}
		ks := pyStr(k)
		put(ks, construct(vn))
		lines[ks] = kn.Line
	}
	for _, m := range merges {
		nodes := []*yaml.Node{m}
		if m.Kind == yaml.SequenceNode {
			nodes = m.Content
		}
		for _, mn := range nodes {
			if mn.Kind != yaml.MappingNode {
				panic(yamlErr(fmt.Sprintf("yaml_error:line %d", m.Line)))
			}
			sub, subOrder, _ := mapping(mn)
			for _, k := range subOrder {
				if _, own := out[k]; !own {
					put(k, sub[k])
				}
			}
		}
	}
	return out, order, lines
}

var (
	// ruamel's implicit !!timestamp resolver (resolver.py); the date-only form needs 2-digit
	// month and day, the constructor's regex (util.timestamp_regexp, tsRE) does not.
	tsPlainRE = regexp.MustCompile(`^(?:[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt]|[ \t]+)[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?)$`)
	tsRE      = regexp.MustCompile(`^([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})(?:(?:([Tt])|[ \t]+)([0-9]{1,2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]*))?(?:[ \t]*(Z|([-+])([0-9]{1,2})(?::([0-9]{2}))?))?)?$`)
	// ruamel's YAML 1.2 decimal int (leading zeros are decimal; yaml.v3 would read them as octal).
	decIntRE  = regexp.MustCompile(`^[-+]?[0-9][0-9_]*$`)
	yamlBools = map[string]bool{"true": true, "yes": true, "on": true, "false": false, "no": false, "off": false}
)

// scalar constructs one scalar as ruamel does: explicit tags pick their constructor, a plain
// scalar resolves by the YAML 1.2 core schema, everything else is yaml.v3's resolution.
func scalar(n *yaml.Node) any {
	tagged := n.Style&yaml.TaggedStyle != 0
	plain := n.Style == 0
	tag, v := n.ShortTag(), n.Value
	switch {
	case tagged && (tag == "!!seq" || tag == "!!map"):
		panic(yamlErr(fmt.Sprintf("yaml_error:line %d", n.Line)))
	case tagged && tag == "!!null":
		return nil
	case tagged && tag == "!!bool":
		if b, ok := yamlBools[pytext.Lower(v)]; ok {
			return b
		}
		panic(yamlErr("yaml_error"))
	case tagged && tag == "!!timestamp":
		if !tsRE.MatchString(v) {
			panic(yamlErr(fmt.Sprintf("yaml_error:line %d", n.Line)))
		}
		return timestamp(v)
	case plain && tsPlainRE.MatchString(v):
		return timestamp(v)
	case plain && decIntRE.MatchString(v):
		digits := strings.ReplaceAll(v, "_", "")
		if i, err := strconv.ParseInt(digits, 10, 64); err == nil {
			return int(i)
		}
		if u, err := strconv.ParseUint(digits, 10, 64); err == nil {
			return u
		}
		f, _ := strconv.ParseFloat(digits, 64) // ponytail: beyond uint64 Python keeps an exact int
		return f
	case tagged && tag != "!!int" && tag != "!!float" && tag != "!!binary":
		return Opaque{"TaggedScalar", v}
	case tag == "!!timestamp": // yaml.v3 resolved a form ruamel's regex rejects, such as 2001-2-3
		return v
	}
	var out any
	if err := n.Decode(&out); err != nil {
		panic(yamlErr("yaml_error"))
	}
	return out
}

// timestamp is ruamel's create_timestamp plus the TimeStamp wrapping of construct_yaml_timestamp;
// an invalid date or time is the ValueError the oracle reports as a mark-less yaml_error.
func timestamp(v string) Opaque {
	m := tsRE.FindStringSubmatch(v)
	num := func(s string) int { i, _ := strconv.Atoi(s); return i }
	y, mo, d := num(m[1]), num(m[2]), num(m[3])
	if y < 1 || mo < 1 || mo > 12 || d < 1 || d > time.Date(y, time.Month(mo)+1, 0, 0, 0, 0, 0, time.UTC).Day() {
		panic(yamlErr("yaml_error"))
	}
	if m[5] == "" {
		return Opaque{"date", fmt.Sprintf("%04d-%02d-%02d", y, mo, d)}
	}
	h, mi, s := num(m[5]), num(m[6]), num(m[7])
	if h > 23 || mi > 59 || s > 59 {
		panic(yamlErr("yaml_error"))
	}
	micro := 0
	if frac := m[8]; frac != "" {
		micro = num((frac + "000000")[:6])
		if len(frac) > 6 && frac[6] > '4' {
			micro++
		}
	}
	t := time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC)
	if micro > 999999 { // create_timestamp: fraction 0 and one second forward
		micro, t = 0, t.Add(time.Second)
	}
	typ, sep, tz := "datetime", " ", ""
	if m[4] != "" {
		typ, sep = "TimeStamp", "T"
	}
	switch {
	case m[9] == "Z":
		tz = "+00:00"
	case m[9] != "":
		th, tm := num(m[11]), num(m[12])
		if th > 23 || tm > 59 {
			panic(yamlErr("yaml_error"))
		}
		typ, tz = "TimeStamp", fmt.Sprintf("%s%02d:%02d", m[10], th, tm)
	}
	text := t.Format("2006-01-02") + sep + t.Format("15:04:05")
	if micro != 0 {
		text += fmt.Sprintf(".%06d", micro)
	}
	return Opaque{typ, text + tz}
}

// pyStr is Python str() of a constructed value (dict keys and non-string dependency entries).
func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	case float64:
		switch {
		case math.IsNaN(x):
			return "nan"
		case math.IsInf(x, 1):
			return "inf"
		case math.IsInf(x, -1):
			return "-inf"
		}
		return pytext.Dumps(x, 0)
	case Opaque:
		return x.Text
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = pyRepr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		parts := make([]string, 0, len(x))
		for _, k := range slices.Sorted(maps.Keys(x)) {
			parts = append(parts, pytext.Repr(k)+": "+pyRepr(x[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprint(v)
}

// pyRepr is repr(): str() except that strings are quoted.
func pyRepr(v any) string {
	if s, ok := v.(string); ok {
		return pytext.Repr(s)
	}
	return pyStr(v)
}

// --- grants (_split_grants, _GRANT_RE, _grant_parentheses_balanced, parse_grants) ---

// grantRE is _GRANT_RE: tool name plus an optional parenthesised pattern; \w is [\p{L}\p{N}_].
var grantRE = regexp.MustCompile(`(?s)^([A-Za-z_][\p{L}\p{N}_.-]*)` + pytext.Space + `*(?:\((.*)\))?` + pytext.Space + `*\z`)

// splitGrants splits list, comma or space-delimited grants without splitting patterns.
func splitGrants(val any) []string {
	var out []string
	switch v := val.(type) {
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && pytext.Strip(s) != "" {
				out = append(out, pytext.Strip(s))
			}
		}
	case string:
		r := []rune(v)
		next := make([]int, len(r)+1) // index of the next non-space rune at or after i
		nearest := len(r)
		next[len(r)] = nearest
		for i := len(r) - 1; i >= 0; i-- {
			if !pytext.IsSpace(r[i]) {
				nearest = i
			}
			next[i] = nearest
		}
		var cur []rune
		var quote rune
		depth, escaped := 0, false
		hasText := false // cur holds a non-space rune, i.e. strip(cur) != "" without re-scanning
		flush := func() {
			if s := pytext.Strip(string(cur)); s != "" {
				out = append(out, s)
			}
			cur, hasText = cur[:0], false
		}
		for i, ch := range r {
			switch {
			case escaped:
				escaped = false
			case ch == '\\' && quote != '\'':
				escaped = true
			case quote != 0:
				if ch == quote {
					quote = 0
				}
			case ch == '\'' || ch == '"':
				quote = ch
			case depth == 0 && (ch == ',' || pytext.IsSpace(ch)):
				if f := next[i+1]; pytext.IsSpace(ch) && hasText && f < len(r) && r[f] == '(' {
					break // `Bash (curl:*)` stays one specifier
				}
				flush()
				continue
			case ch == '(':
				depth++
			case ch == ')':
				depth = max(0, depth-1)
			}
			cur = append(cur, ch)
			hasText = hasText || !pytext.IsSpace(ch)
		}
		flush()
	}
	return out
}

// parseGrants is parse_grants: allowed/disallowed-tools specifiers to Grants; an unrecognised
// specifier is kept raw and broad.
func parseGrants(fm map[string]any) []Grant {
	grants := []Grant{}
	for _, key := range [...]string{"allowed-tools", "disallowed-tools"} {
		allowed := key == "allowed-tools"
		for _, spec := range splitGrants(fm[key]) {
			m := grantRE.FindStringSubmatchIndex(spec)
			var pattern *string
			if m != nil && m[4] >= 0 {
				p := spec[m[4]:m[5]]
				pattern = &p
				if _, err := pytext.ShlexTokens(p, false, "", " \t\r\n"); err != nil || !grantParenthesesBalanced(spec) {
					m = nil
				}
			}
			if m == nil {
				grants = append(grants, Grant{Tool: spec, Raw: spec, Allowed: allowed, Broad: true})
				continue
			}
			grants = append(grants, Grant{Tool: spec[m[2]:m[3]], Pattern: pattern, Raw: spec, Allowed: allowed, Broad: pattern == nil, Parsed: true})
		}
	}
	return grants
}

func grantParenthesesBalanced(spec string) bool {
	start := strings.IndexByte(spec, '(')
	if start < 0 {
		return true
	}
	var quote rune
	depth, escaped := 0, false
	for i, ch := range spec[start:] {
		switch {
		case escaped:
			escaped = false
		case ch == '\\' && quote != '\'':
			escaped = true
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '\'' || ch == '"':
			quote = ch
		case ch == '(':
			depth++
		case ch == ')':
			depth--
			if depth == 0 {
				return pytext.Strip(spec[start+i+1:]) == ""
			}
			if depth < 0 {
				return false
			}
		}
	}
	return false
}
