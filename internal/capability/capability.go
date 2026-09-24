// Package capability builds the manifest-scoped capability context (Python capability.py): for
// every governing SKILL.md, what its prose claims, what its tool grants declare and what the
// engines observed in the code it governs. None of these states authorise behaviour.
package capability

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/checks"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/grants"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

var axes = []string{"execution", "network"}

// Triad is CapabilityTriad; each axis map holds "unknown", "present" or "denied".
type Triad struct {
	Manifest    *string           `json:"manifest"`
	Claimed     map[string]string `json:"claimed"`
	Declared    map[string]string `json:"declared"`
	Observed    map[string]string `json:"observed"`
	Evidence    []map[string]any  `json:"evidence"`
	Limitations []string          `json:"limitations"`
}

func newTriad(manifest string) *Triad {
	t := &Triad{Claimed: map[string]string{}, Declared: map[string]string{}, Observed: map[string]string{},
		Evidence: []map[string]any{}, Limitations: []string{}}
	for _, axis := range axes {
		t.Claimed[axis], t.Declared[axis], t.Observed[axis] = "unknown", "unknown", "unknown"
	}
	if manifest != "" {
		t.Manifest = &manifest
	}
	return t
}

var (
	// _CLAIMS and _DENIALS, matched whole; Python's trailing \b is implied by $ after a letter.
	claims = map[string]*regexp.Regexp{
		"execution": regexp.MustCompile(`^(?:runs?|executes?) (?:shell commands|commands|scripts)$`),
		"network": regexp.MustCompile(`^(?:uploads? (?:diagnostic logs|logs|data)|` +
			`sends? (?:diagnostic logs|logs|data) (?:over the network|via http)|` +
			`(?:access(?:es)?|uses?) the network|makes? (?:http|network) requests)$`),
	}
	denials = map[string]*regexp.Regexp{
		"execution": regexp.MustCompile(`^(?:runs?|executes?) commands$`),
		"network":   regexp.MustCompile(`^(?:access(?:es)?|uses?) the network$`),
	}
	// Python's \b is Unicode-aware; an explicit non-word rune or the text edge replaces it.
	qualifierRE = regexp.MustCompile(`(?i)^(?:this (?:is|was)|that|these|those|but|however|unless|except|only|not|never|does not)(?:[^\p{L}\p{N}_]|$)`)
	exampleRE   = regexp.MustCompile(`(?i)^(?:(?:for )?example|the following example)(?:[^\p{L}\p{N}_]|$)`)
	negationRE  = regexp.MustCompile(`(?:^|[^\p{L}\p{N}_])(?:does not|never)(?:[^\p{L}\p{N}_]|$)`)
	negativeRE  = regexp.MustCompile(`^(?:does not|never)\s+`)
	// re.split(r"(?<=[.!])\s+") without the lookbehind: a statement ends after the punctuation
	// and the next starts after the whitespace run.
	statementEndRE = regexp.MustCompile(`[.!]` + pytext.Space + `+`)
	// Tools whose grants leave both axes certain (the read/write set of _declarations).
	fileTools = map[string]bool{"Read": true, "Write": true, "Edit": true, "MultiEdit": true, "Glob": true, "Grep": true, "LS": true}
)

func statements(text string) []string {
	out, pos := []string{}, 0
	for _, m := range statementEndRE.FindAllStringIndex(text, -1) {
		out = append(out, text[pos:m[0]+1])
		pos = m[1]
	}
	return append(out, text[pos:])
}

// sub is Python's lines[a:b] for 0 <= a: both bounds clamp to the slice.
func sub(lines []string, a, b int) []string {
	a = min(a, len(lines))
	return lines[a:max(min(b, len(lines)), a)]
}

// claims is _claims: the description and every self-referential ("This skill ...") top-level
// paragraph are read as complete statements; one unrecognised statement voids its whole source.
func (t *Triad) claims(m *parse.Artifact) {
	type source struct {
		text  string
		line  int
		prose bool
	}
	var sources []source
	if d, ok := m.Frontmatter["description"].(string); ok {
		sources = append(sources, source{d, m.FrontmatterKeyLines["description"], false})
	}
	if m.Markdown != nil {
		var text string
		if m.Text != nil {
			text = *m.Text
		}
		lines := pytext.SplitLines(text)
		var spans []parse.Span
		for _, s := range m.Markdown.ParagraphSpans {
			qualifier := qualifierRE.MatchString(pytext.Strip(lines[s.Start-1]))
			if n := len(spans); n > 0 && (qualifier || exampleRE.MatchString(pytext.Strip(lines[spans[n-1].Start-1]))) &&
				!slices.ContainsFunc(sub(lines, spans[n-1].End, s.Start-1), func(l string) bool { return pytext.Strip(l) != "" }) {
				spans[n-1].End = s.End
			} else {
				spans = append(spans, s)
			}
		}
		for _, s := range spans {
			if block := sub(lines, s.Start-1, s.End); len(block) > 0 && strings.HasPrefix(pytext.Lower(block[0]), "this skill ") {
				sources = append(sources, source{strings.Join(block, "\n"), s.Start, true})
			}
		}
	}
	states := map[string]string{}
	for _, src := range sources {
		var evidence []map[string]any
		supported, position, line := true, 0, src.line
		for _, statement := range statements(pytext.Strip(src.text)) {
			start := position + strings.Index(src.text[position:], statement)
			statementLine := line
			if src.prose {
				statementLine = line + strings.Count(src.text[position:start], "\n")
				line = statementLine + strings.Count(statement, "\n")
			}
			position = start + len(statement)
			sentence := strings.TrimRight(strings.Join(pytext.Fields(pytext.Lower(statement)), " "), ".!")
			clauses := strings.Split(sentence, " and ")
			if utf8.RuneCountInString(statement) > 400 || len(clauses) > 1 && negationRE.MatchString(sentence) {
				supported = false
				break
			}
			for _, clause := range clauses {
				clause = strings.TrimPrefix(clause, "this skill ")
				action, state, patterns := clause, "present", claims
				if neg := negativeRE.FindStringIndex(clause); neg != nil {
					action, state, patterns = clause[neg[1]:], "denied", denials
				}
				matched := false
				for _, axis := range axes {
					if patterns[axis].MatchString(action) {
						matched = true
						evidence = append(evidence, map[string]any{"path": m.Rel, "line": statementLine,
							"leg": "claimed", "capability": axis, "state": state, "text": statement})
					}
				}
				if !matched {
					supported = false
					break
				}
			}
			if !supported {
				break
			}
		}
		if supported {
			for _, hit := range evidence {
				axis, state := hit["capability"].(string), hit["state"].(string)
				if prev, seen := states[axis]; seen && prev != state {
					state = "conflict"
				}
				states[axis] = state
			}
			t.Evidence = append(t.Evidence, evidence...)
		}
	}
	for _, axis := range axes {
		switch s := states[axis]; s {
		case "":
		case "conflict":
			t.Limitations = append(t.Limitations, "conflicting-"+axis+"-claims")
		default:
			t.Claimed[axis] = s
		}
	}
}

// blankValue is the unparsed-declaration test of _declarations: a null, a blank string or a
// list holding a blank string.
func blankValue(v any) bool {
	switch v := v.(type) {
	case nil:
		return true
	case string:
		return pytext.Strip(v) == ""
	case []any:
		return slices.ContainsFunc(v, func(item any) bool { s, ok := item.(string); return ok && pytext.Strip(s) == "" })
	}
	return false
}

// declarations is _declarations: explicit states only from fully parsed grants; anything
// unparsed or unrecognised is a limitation, never a denial.
func (t *Triad) declarations(m *parse.Artifact) {
	fields := slices.DeleteFunc([]string{"allowed-tools", "disallowed-tools"}, func(k string) bool { _, ok := m.Frontmatter[k]; return !ok })
	if slices.ContainsFunc(m.Diagnostics, func(d parse.Diagnostic) bool {
		return d.Code == "frontmatter_parse_error" || d.Code == "grants_unparsed_shape"
	}) || slices.ContainsFunc(fields, func(k string) bool { return blankValue(m.Frontmatter[k]) }) ||
		slices.ContainsFunc(m.Grants, func(g parse.Grant) bool { return !g.Parsed }) {
		t.Limitations = append(t.Limitations, "declaration-unparsed")
		return
	}
	allowed, denied := grants.Declared(m.Grants), grants.Denied(m.Grants)
	uncertain := map[string]bool{}
	for _, g := range grants.Effective(m.Grants) {
		switch {
		case grants.ExecutionTools[g.Tool]: // a command not proven network-capable is not proven network-free
			one := grants.Declared([]parse.Grant{g})
			for _, axis := range axes {
				if !one[axis] {
					uncertain[axis] = true
				}
			}
		case !grants.NetworkTools[g.Tool] && !fileTools[g.Tool]:
			for _, axis := range axes {
				uncertain[axis] = true
			}
		}
	}
	if len(uncertain) > 0 {
		t.Limitations = append(t.Limitations, "declaration-capability-unknown")
	}
	_, hasAllowed := m.Frontmatter["allowed-tools"]
	for _, axis := range axes {
		if allowed[axis] {
			t.Declared[axis] = "present"
		} else if !uncertain[axis] && (hasAllowed || denied[axis]) {
			t.Declared[axis] = "denied"
		}
	}
	for _, k := range fields {
		t.Evidence = append(t.Evidence, map[string]any{"path": m.Rel, "leg": "declared", "field": k, "line": m.FrontmatterKeyLines[k]})
	}
}

// Build is build_triads: one triad per governing manifest, plus "" for observations no
// manifest governs, keyed by manifest rel. Observations are the engines' records;
// coverage is the raw finding list, whose preprocessing hits become execution observations and
// whose vector-less gaps become limitations of the manifests they touch.
func Build(p *parse.Package, observations []map[string]any, coverage []findings.Finding) map[string]*Triad {
	manifests := parse.ManifestIndex(p)
	triads := map[string]*Triad{}
	for _, m := range manifests {
		triads[m.Rel] = newTriad(m.Rel)
	}
	observations = slices.Clone(observations)
	for _, f := range coverage {
		sha, _ := f.Evidence["command_sha256"].(string)
		if (f.Rule == "preproc-inline-bang" || f.Rule == "preproc-fenced-bang") &&
			(f.Vector == "SXV-001" || f.Vector == "SXV-002") && sha != "" {
			observations = append(observations, map[string]any{"path": f.Path, "line": f.Line,
				"column": f.Column, "capability": "execution", "state": "present",
				"analyzer": "preproc-ir", "rule": f.Rule, "vector": f.Vector, "command_sha256": sha})
		}
	}
	for _, obs := range observations {
		path, _ := obs["path"].(string)
		key := ""
		if m := parse.GoverningManifest(manifests, path); m != nil {
			key = m.Rel
		}
		t := triads[key]
		if t == nil {
			t = newTriad(key)
			triads[key] = t
		}
		t.Evidence = append(t.Evidence, pytext.DeepCopy(obs).(map[string]any))
		if axis, _ := obs["capability"].(string); slices.Contains(axes, axis) && obs["state"] == "present" {
			t.Observed[axis] = "present"
		} else if reason, ok := obs["reason"].(string); ok {
			t.Limitations = append(t.Limitations, reason)
		} else {
			t.Limitations = append(t.Limitations, "observation-unvalidated")
		}
	}
	for _, m := range manifests {
		t := triads[m.Rel]
		t.claims(m)
		t.declarations(m)
		if m.Text == nil {
			t.Limitations = append(t.Limitations, "manifest-unread")
		}
	}
	for _, f := range coverage {
		if f.Vector != "" || checks.IsInventoryNote(f.Vector, f.Rule, f.Severity, f.Evidence) {
			continue
		}
		var m *parse.Artifact
		if f.Path != "" {
			m = parse.GoverningManifest(manifests, f.Path)
		}
		for _, t := range triads {
			if m == nil || t == triads[m.Rel] {
				t.Limitations = append(t.Limitations, f.Rule)
			}
		}
	}
	for _, t := range triads {
		slices.Sort(t.Limitations)
		t.Limitations = slices.Compact(t.Limitations)
	}
	return triads
}
