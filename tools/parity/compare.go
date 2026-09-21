package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/traceforce/skill-xray/internal/testutil"
)

// absent marks a value present on one side only.
const absent = "<absent>"

// diff is one difference between the oracle document (Py) and the Go document (Go).
type diff struct {
	Segs  []string `json:"-"`
	Path  string   `json:"path"`
	Py    any      `json:"py"`
	Go    any      `json:"go"`
	Group string   `json:"group,omitempty"`
	Check string   `json:"check,omitempty"` // Python check module the finding belongs to
	Known bool     `json:"known,omitempty"`
}

func formatPath(segs []string) string {
	var b strings.Builder
	for i, s := range segs {
		if isIndex(s) {
			b.WriteString("[" + s + "]")
		} else {
			if i > 0 && !strings.HasSuffix(segs[i-1], ":") {
				b.WriteByte('.')
			}
			b.WriteString(s)
		}
	}
	return b.String()
}

func isIndex(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }

// parseJSON decodes with float64 numbers so 100.0 == 100 (00-overview section 6).
func parseJSON(data []byte) (any, error) {
	var v any
	err := json.Unmarshal(data, &v)
	return v, err
}

// normalize applies the --json rules of 00-overview section 6: drop source, rewrite the identity
// root, sort the by-id lists, delete every "drop" path of known_divergences.json. Sorting is by
// candidate_id for raw_candidates and links, by id for results, wherever those keys occur.
func normalize(doc any, corpusRoot string, known []divergence) any {
	m, ok := doc.(map[string]any)
	if !ok {
		return doc
	}
	delete(m, "source")
	if id, ok := m["identity"].(string); ok {
		m["identity"] = rewriteRoot(id, corpusRoot)
	}
	sortByID(m)
	for _, k := range known {
		if k.Match == "drop" {
			dropPath(m, patternSegs(k.Where))
		}
	}
	return m
}

// dropPath deletes the map value at every path matching pattern ("*" matches any key or index).
func dropPath(v any, pattern []string) {
	switch t := v.(type) {
	case map[string]any:
		if len(pattern) == 1 {
			delete(t, pattern[0])
			return
		}
		for k, child := range t {
			if pattern[0] == "*" || pattern[0] == k {
				dropPath(child, pattern[1:])
			}
		}
	case []any:
		for i, child := range t {
			if len(pattern) > 1 && (pattern[0] == "*" || pattern[0] == fmt.Sprint(i)) {
				dropPath(child, pattern[1:])
			}
		}
	}
}

var idKeys = map[string]string{"raw_candidates": "candidate_id", "links": "candidate_id", "results": "id"}

func sortByID(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if idKey, ok := idKeys[k]; ok {
				if list, ok := child.([]any); ok {
					slices.SortStableFunc(list, func(a, b any) int { return cmp.Compare(idOf(a, idKey), idOf(b, idKey)) })
				}
			}
			sortByID(child)
		}
	case []any:
		for _, child := range t {
			sortByID(child)
		}
	}
}

func idOf(v any, key string) string {
	if m, ok := v.(map[string]any); ok {
		return fmt.Sprint(m[key])
	}
	return ""
}

// rewriteRoot replaces the corpus root prefix of an identity path with "<corpus>"; both sides
// are slash-normalised and the match ignores case (Windows drive letters).
func rewriteRoot(identity, corpusRoot string) string {
	if corpusRoot == "" {
		return identity
	}
	id := filepath.ToSlash(identity)
	root := strings.TrimSuffix(filepath.ToSlash(corpusRoot), "/")
	if len(id) < len(root) || !strings.EqualFold(id[:len(root)], root) {
		return id
	}
	return "<corpus>" + id[len(root):]
}

// compare walks both values and appends every difference; lists are compared in order.
func compare(py, gov any, segs []string, out *[]diff) {
	switch a := py.(type) {
	case map[string]any:
		b, ok := gov.(map[string]any)
		if !ok {
			*out = append(*out, mk(segs, py, gov))
			return
		}
		all := maps.Clone(a)
		maps.Copy(all, b)
		for _, k := range slices.Sorted(maps.Keys(all)) {
			av, aok := a[k]
			bv, bok := b[k]
			child := append(append([]string{}, segs...), k)
			switch {
			case !aok:
				*out = append(*out, mk(child, absent, bv))
			case !bok:
				*out = append(*out, mk(child, av, absent))
			default:
				compare(av, bv, child, out)
			}
		}
	case []any:
		b, ok := gov.([]any)
		if !ok {
			*out = append(*out, mk(segs, py, gov))
			return
		}
		for i := 0; i < len(a) || i < len(b); i++ {
			child := append(append([]string{}, segs...), fmt.Sprint(i))
			switch {
			case i >= len(a):
				*out = append(*out, mk(child, absent, b[i]))
			case i >= len(b):
				*out = append(*out, mk(child, a[i], absent))
			default:
				compare(a[i], b[i], child, out)
			}
		}
	default:
		if py != gov {
			*out = append(*out, mk(segs, py, gov))
		}
	}
}

func mk(segs []string, py, gov any) diff {
	return diff{Segs: segs, Path: formatPath(segs), Py: py, Go: gov}
}

// divergence is one entry of known_divergences.json. Where is a path pattern
// ("findings[*].message", "sarif:runs[*].results[*].message.text", trailing "**" matches any
// suffix); Rules restricts it to diffs inside a finding whose rule is listed; When restricts it
// to packages where either side's findings carry a finding matching one of the matchers (keys
// rule, message, reason for evidence.reason; every key must equal; "side": "py" instead requires
// the oracle to carry the finding and the Go side to carry no equal finding); Match is "prefix"
// (strings equal up to the last ": "), "presence" (both sides present), "any", or "drop" (the
// path is deleted from both documents by normalize before comparison).
type divergence struct {
	Where string              `json:"where"`
	Rules []string            `json:"rules,omitempty"`
	When  []map[string]string `json:"when,omitempty"`
	Match string              `json:"match"`
}

// applies reports whether the package's findings satisfy one of k.When (see divergence).
func (k divergence) applies(py, gov any) bool {
	if len(k.When) == 0 {
		return true
	}
	pyList, goList := findingsOf(py), findingsOf(gov)
	for _, w := range k.When {
		pyOnly := w["side"] == "py"
		for _, f := range pyList {
			if matchesWhen(f, w) && (!pyOnly || !slices.ContainsFunc(goList, func(g any) bool { return reflect.DeepEqual(f, g) })) {
				return true
			}
		}
		if !pyOnly && slices.ContainsFunc(goList, func(f any) bool { return matchesWhen(f, w) }) {
			return true
		}
	}
	return false
}

func findingsOf(doc any) []any {
	m, _ := doc.(map[string]any)
	list, _ := m["findings"].([]any)
	return list
}

// matchesWhen reports whether every key of w other than "side" equals the finding's value.
func matchesWhen(f any, w map[string]string) bool {
	fm, _ := f.(map[string]any)
	evidence, _ := fm["evidence"].(map[string]any)
	for key, want := range w {
		got := fm[key]
		switch key {
		case "side":
			continue
		case "reason":
			got = evidence["reason"]
		}
		if fmt.Sprint(got) != want {
			return false
		}
	}
	return true
}

func loadDivergences(path string) ([]divergence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []divergence
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// patternSegs splits a where pattern; a "sarif:" or "ir:" prefix becomes its own first segment,
// matching the marker segment the SARIF and IR diffs carry.
func patternSegs(where string) []string {
	var segs []string
	for _, marker := range []string{"sarif:", "ir:"} {
		if strings.HasPrefix(where, marker) {
			segs, where = []string{marker}, where[len(marker):]
		}
	}
	return append(segs, strings.FieldsFunc(where, func(r rune) bool { return r == '.' || r == '[' || r == ']' })...)
}

func pathMatches(pattern, segs []string) bool {
	for i, p := range pattern {
		if p == "**" {
			return true
		}
		if i >= len(segs) || (p != "*" && p != segs[i]) {
			return false
		}
	}
	return len(pattern) == len(segs)
}

// enclosingFinding returns the nearest map on the path that carries a "rule" key, from the first
// of docs that has one.
func enclosingFinding(segs []string, docs ...any) map[string]any {
	for _, doc := range docs {
		for k := len(segs); k >= 0; k-- {
			if m, ok := resolve(doc, segs[:k]).(map[string]any); ok {
				if _, has := m["rule"]; has {
					return m
				}
			}
		}
	}
	return nil
}

func resolve(doc any, segs []string) any {
	cur := doc
	for _, s := range segs {
		switch t := cur.(type) {
		case map[string]any:
			cur = t[s]
		case []any:
			var i int
			if _, err := fmt.Sscan(s, &i); err != nil || i < 0 || i >= len(t) {
				return nil
			}
			cur = t[i]
		default:
			return nil
		}
	}
	return cur
}

// classify fills Known and Group on every diff. A diff is known when an entry matches its
// path, its enclosing finding's rule (when the entry lists rules) and its match mode.
func classify(diffs []diff, known []divergence, py, gov any) {
	for i := range diffs {
		d := &diffs[i]
		d.Group, d.Check = attribute(*d, py, gov)
		for _, k := range known {
			if !pathMatches(patternSegs(k.Where), d.Segs) {
				continue
			}
			if len(k.Rules) > 0 {
				f := enclosingFinding(d.Segs, py, gov)
				if f == nil || !slices.Contains(k.Rules, fmt.Sprint(f["rule"])) {
					continue
				}
			}
			if !k.applies(py, gov) {
				continue
			}
			ps, pok := d.Py.(string)
			gs, gok := d.Go.(string)
			switch k.Match {
			case "any":
				d.Known = true
			case "prefix":
				d.Known = pok && gok && testutil.MessagePrefix(ps) == testutil.MessagePrefix(gs)
			case "presence":
				d.Known = d.Py != absent && d.Go != absent
			}
			if d.Known {
				break
			}
		}
	}
}

// Attribution tables (00-overview section 6, code.md section 7).
var (
	vectorGroup = map[string]string{
		"SXV-001": "parse", "SXV-002": "parse",
		"SXV-003": "code", "SXV-004": "code", "SXV-016": "code", "SXV-017": "code",
		"SXV-035": "code", "SXV-036": "code", "SXV-037": "code",
		"SXV-008": "code", "SXV-009": "code", "SXV-010": "code", "SXV-018": "code",
		"SXV-019": "code", "SXV-020": "code", "SXV-021": "code", "SXV-022": "code",
		"SXV-023": "code", "SXV-024": "code", "SXV-025": "code", "SXV-026": "code",
		"SXV-032": "code", "SXV-033": "code", "SXV-039": "code", "SXV-040": "code",
		"SXV-005": "instruction", "SXV-006": "instruction", "SXV-011": "instruction",
		"SXV-012": "instruction", "SXV-013": "instruction", "SXV-027": "instruction",
		"SXV-028": "instruction", "SXV-029": "instruction", "SXV-030": "instruction",
		"SXV-031": "instruction", "SXV-041": "instruction", "SXV-042": "instruction",
		"SXV-043": "instruction",
		"SXV-007": "obfuscation", "SXV-014": "obfuscation", "SXV-015": "obfuscation",
		"SXV-038": "output-llm",
	}
	codeRules = []string{"grant-variable-substitution", "grant-over-broad", "unpinned-dependency",
		"install-from-url", "committed-credential", "magic-mismatch", "polyglot", "unreferenced-bytes",
		"analyzer-error", "permission-understatement", "findings-capped"}
	codeIncompleteReasons = []string{"unsupported_language", "dynamic-subprocess-kwargs",
		"capability-declaration-unparsed", "capability-validation-budget"}
	codeEvidenceKeys = []string{"installer_idiom", "understated_capability", "fenced_example",
		"pin_state", "breadth_class", "variable_name", "detail"}
	moduleGroup = map[string]string{"coverage": "core", "metadata": "core", "grants": "code",
		"supply_chain": "code", "taint_engine": "code", "analyze": "code", "hooks": "instruction",
		"instruction_exfil": "instruction", "persistence": "instruction",
		"obfuscation": "obfuscation", "preproc": "parse", "llm": "output-llm"}
	moreFindings = regexp.MustCompile(`^\d+ more (SXV-\d{3}) `)
	checkFailed  = regexp.MustCompile(`^check (\S+) failed`)
	// vectorCheck is the check module (py_dump_findings.py name) that emits each vector; every
	// code vector not listed is OpenGrep's (taint_engine).
	vectorCheck = map[string]string{
		"SXV-001": "preproc", "SXV-002": "preproc", "SXV-003": "grants", "SXV-004": "grants",
		"SXV-005": "persistence", "SXV-006": "hooks", "SXV-012": "hooks", "SXV-013": "hooks",
		"SXV-007": "obfuscation", "SXV-014": "obfuscation", "SXV-015": "obfuscation",
		"SXV-016": "supply_chain", "SXV-017": "supply_chain", "SXV-034": "metadata",
		"SXV-035": "analyze", "SXV-036": "analyze", "SXV-037": "analyze", "SXV-038": "llm",
	}
	ruleCheck = map[string]string{"grant-variable-substitution": "grants", "grant-over-broad": "grants",
		"unpinned-dependency": "supply_chain", "install-from-url": "supply_chain", "committed-credential": "supply_chain",
		"magic-mismatch": "analyze", "polyglot": "analyze", "unreferenced-bytes": "analyze", "analyzer-error": "analyze",
		"permission-understatement": "taint_engine"}
	prefixCheck = map[string]string{"further SXV-007 ": "obfuscation", "unicode scan of ": "obfuscation",
		"obfuscation skipped ": "obfuscation", "instruction_exfil skipped ": "instruction_exfil",
		"hook/MCP configuration analysis is incomplete": "hooks"}
)

func attribute(d diff, py, gov any) (group, check string) {
	if len(d.Segs) > 0 {
		switch d.Segs[0] {
		case "sarif:":
			return "output-llm", ""
		case "ir:":
			return "parse", ""
		}
	}
	if f := enclosingFinding(d.Segs, py, gov); f != nil {
		return attributeFinding(f), attributeCheck(f)
	}
	return "core", ""
}

// attributeCheck names the check module behind a finding: by vector, then by the rule slugs and
// message forms that carry a vector or module name; "" for anything no single check owns.
func attributeCheck(f map[string]any) string {
	evidence, _ := f["evidence"].(map[string]any)
	vector := fmt.Sprint(f["vector"])
	if evidence["engine"] == "opengrep" {
		return "taint_engine"
	}
	if c, ok := vectorCheck[vector]; ok {
		return c
	}
	switch vectorGroup[vector] {
	case "instruction":
		return "instruction_exfil"
	case "code":
		return "taint_engine"
	}
	rule := fmt.Sprint(f["rule"])
	switch {
	case strings.HasPrefix(rule, "opengrep-"):
		return "taint_engine"
	case rule == "analysis-incomplete" && slices.Contains(codeIncompleteReasons, fmt.Sprint(evidence["reason"])):
		return "taint_engine"
	case strings.HasPrefix(rule, "llm-"):
		return "llm"
	case ruleCheck[rule] != "":
		return ruleCheck[rule]
	}
	msg := fmt.Sprint(f["message"])
	for prefix, c := range prefixCheck {
		if strings.HasPrefix(msg, prefix) {
			return c
		}
	}
	if m := moreFindings.FindStringSubmatch(msg); m != nil {
		return attributeCheck(map[string]any{"vector": m[1]})
	}
	if m := checkFailed.FindStringSubmatch(msg); m != nil {
		parts := strings.Split(m[1], ".")
		return parts[len(parts)-1]
	}
	return ""
}

func attributeFinding(f map[string]any) string {
	evidence, _ := f["evidence"].(map[string]any)
	vector := fmt.Sprint(f["vector"])
	if g, ok := vectorGroup[vector]; ok {
		// SXV-005 is emitted by the instruction lane and by OpenGrep taint; the engine decides.
		if g == "instruction" && evidence["engine"] == "opengrep" {
			return "code"
		}
		return g
	}
	if slices.Contains(codeRules, fmt.Sprint(f["rule"])) {
		return "code"
	}
	if g, ok := moduleGroup[attributeCheck(f)]; ok {
		return g
	}
	for _, k := range codeEvidenceKeys {
		if _, ok := evidence[k]; ok {
			return "code"
		}
	}
	return "core"
}

// findingTuples projects findings to the CLAUDE.md minimum (vector, rule, severity, tier, path,
// line) as a sorted multiset.
func findingTuples(doc any) []string {
	m, _ := doc.(map[string]any)
	list, _ := m["findings"].([]any)
	out := make([]string, 0, len(list))
	for _, f := range list {
		fm, _ := f.(map[string]any)
		out = append(out, fmt.Sprintf("%v|%v|%v|%v|%v|%v", fm["vector"], fm["rule"], fm["severity"],
			fm["tier"], fm["path"], fm["line"]))
	}
	slices.Sort(out)
	return out
}
