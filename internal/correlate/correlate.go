// Package correlate links equivalent emitted candidates to one result (Python correlate.py) and
// applies operator and LLM-review dispositions to the linked results (disposition.py).
package correlate

import (
	"cmp"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/checks"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

const (
	FingerprintVersion = "skill-xray/evidence/v1"
	contextVersion     = "skill-xray/context/v1"
)

type Candidate struct {
	CandidateID string         `json:"candidate_id"`
	Finding     map[string]any `json:"finding"` // findings.Finding.ToMap()
	Analyzer    string         `json:"analyzer"`
	Provenance  string         `json:"provenance"`
	Coverage    string         `json:"coverage"`
}

type FlowStep struct {
	Role    string         `json:"role"`
	Path    string         `json:"path"`
	Start   map[string]any `json:"start"`
	End     map[string]any `json:"end"`
	Content string         `json:"content"`
}

type Provenance struct {
	Analyzer   string  `json:"analyzer"`
	Provenance string  `json:"provenance"`
	EngineRule *string `json:"engine_rule"`
}

type Result struct {
	ID                 string           `json:"id"`
	RuleID             string           `json:"rule_id"`
	Fingerprint        string           `json:"fingerprint"`
	FingerprintVersion string           `json:"fingerprint_version"`
	ContextDigest      string           `json:"context_digest"`
	Finding            map[string]any   `json:"finding"`
	Manifest           *string          `json:"manifest"`
	CandidateIDs       []string         `json:"candidate_ids"`
	Provenance         []Provenance     `json:"provenance"`
	Evidence           []map[string]any `json:"evidence"`
	CodeFlow           []FlowStep       `json:"code_flow"`
	Limitations        []string         `json:"limitations"`
	*Decision                           // nil until ApplyDispositions
}

// Decision is the disposition phase of a Result, inlined into its JSON when set.
type Decision struct {
	Disposition        string         `json:"disposition"`
	DecisionReason     string         `json:"decision_reason"`
	DecisionProvenance string         `json:"decision_provenance"`
	PolicyVersion      string         `json:"policy_version"`
	OriginalSeverity   string         `json:"original_severity"`
	EffectiveSeverity  string         `json:"effective_severity"`
	CapabilityContext  map[string]any `json:"capability_context"` // triad minus evidence; nil == null
	Coverage           string         `json:"coverage"`
	LLMApplied         bool           `json:"llm_applied,omitempty"`
	LLMCandidateID     string         `json:"llm_candidate_id,omitempty"`
}

type Link struct {
	CandidateID       string `json:"candidate_id"`
	ResultID          string `json:"result_id"`
	StableCandidateID string `json:"stable_candidate_id"`
	Disposition       string `json:"disposition"`
	Reason            string `json:"reason"`
	*LinkDecision            // nil until ApplyDispositions
}

type LinkDecision struct {
	PolicyVersion string `json:"policy_version"`
	Provenance    string `json:"provenance"`
}

type PackageInfo struct {
	Name          string `json:"name"`
	ContentDigest string `json:"content_digest"`
	DigestVersion string `json:"digest_version"`
}

type ContextLimit struct {
	Manifest    string   `json:"manifest"`
	Limitations []string `json:"limitations"`
}

// Applied is the package-level disposition phase of a Correlation.
type Applied struct {
	CapabilityContexts  map[string]map[string]any `json:"capability_contexts"`
	Coverage            string                    `json:"coverage"`
	ContextLimitations  []ContextLimit            `json:"context_limitations"`
	ExecutionSuccessful bool                      `json:"execution_successful"`
	LLMApplied          *int                      `json:"llm_applied,omitempty"`
}

type Correlation struct {
	RawCandidates []Candidate  `json:"raw_candidates"`
	Results       []*Result    `json:"results"`
	Package       *PackageInfo `json:"package,omitempty"` // absent on the scan fallback value
	Links         []Link       `json:"links"`
	Errors        []string     `json:"errors,omitempty"`
	*Applied                   // nil until ApplyDispositions
}

func isInventoryNote(finding map[string]any) bool {
	ev, _ := finding["evidence"].(map[string]any)
	return checks.IsInventoryNote(str(finding, "vector"), str(finding, "rule"), str(finding, "severity"), ev)
}

// Candidates numbers the emitted findings as scan-local candidates (scan_report): the analyzer
// is the evidence engine or "ir-check"; coverage is "incomplete" for every finding on a path
// that also carries an operational (vector-less, non-inventory) finding, or package-wide when
// such a finding has no path.
func Candidates(fs []findings.Finding) []Candidate {
	gaps := map[string]bool{}
	for _, f := range fs {
		if f.Vector == "" && !checks.IsInventoryNote(f.Vector, f.Rule, f.Severity, f.Evidence) {
			gaps[f.Path] = true
		}
	}
	out := make([]Candidate, len(fs))
	for i, f := range fs {
		c := Candidate{CandidateID: fmt.Sprintf("candidate-%06d", i), Analyzer: "ir-check",
			Provenance: "deterministic-check-output", Coverage: "no-reported-gap"}
		c.Finding = pytext.DeepCopy(f.ToMap()).(map[string]any)
		if engine, ok := f.Evidence["engine"].(string); ok {
			c.Analyzer = engine
		}
		if gaps[""] || gaps[f.Path] {
			c.Coverage = "incomplete"
		}
		out[i] = c
	}
	return out
}

// ToMap is the generic JSON document of c; integral numbers are Go int (00-overview D7).
func (c *Correlation) ToMap() map[string]any {
	return pytext.JSONView(c).(map[string]any)
}

func sha256hex(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// digest is the sha256 hex of pytext.Canonical(v).
func digest(v any) string { return sha256hex([]byte(pytext.Canonical(v))) }

// evidence is a deep copy of the candidate's evidence without an OpenGrep run fingerprint,
// which carries temporary-run identity.
func evidence(c Candidate) map[string]any {
	ev, _ := pytext.DeepCopy(c.Finding["evidence"]).(map[string]any)
	if ev == nil {
		ev = map[string]any{}
	}
	if c.Analyzer == "opengrep" || ev["engine"] == any("opengrep") {
		delete(ev, "fingerprint")
	}
	return ev
}

// comparable is the evidence without the engine identity keys.
func comparable(ev map[string]any) map[string]any {
	out := maps.Clone(ev)
	delete(out, "engine")
	delete(out, "engine_rule")
	return out
}

var positionKeys = map[string]bool{"line": true, "col": true, "column": true, "offset": true,
	"end_line": true, "end_column": true}

// semanticEvidence drops int-valued position keys at every depth so line shifts do not
// change identity.
func semanticEvidence(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = semanticEvidence(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if _, isInt := e.(int); isInt && positionKeys[k] {
				continue
			}
			out[k] = semanticEvidence(e)
		}
		return out
	}
	return v
}

func nonblank(text string) []string {
	out := []string{}
	for _, line := range strings.Split(text, "\n") {
		if pytext.Strip(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func artifactContext(a *parse.Artifact) map[string]any {
	ctx := map[string]any{"content": nil, "raw_sha256": nil, "kind": a.Kind, "diagnostics": a.Diagnostics}
	if a.Text != nil {
		ctx["content"] = *a.Text
	}
	if a.Raw != nil {
		ctx["raw_sha256"] = sha256hex(a.Raw)
	}
	return ctx
}

// anchor is the source identity of a finding: the digest of its byte span, else the nonblank
// lines of its line range; nil when neither is provable.
func anchor(finding map[string]any, a *parse.Artifact) any {
	if a == nil {
		return nil
	}
	offset, okO := finding["offset"].(int)
	length, okL := finding["length"].(int)
	if a.Raw != nil && okO && offset >= 0 && okL && length > 0 && offset+length <= len(a.Raw) {
		return map[string]any{"bytes": sha256hex(a.Raw[offset : offset+length])}
	}
	line, ok := finding["line"].(int)
	if a.Text == nil || !ok {
		return nil
	}
	lines := strings.Split(*a.Text, "\n")
	ev, _ := finding["evidence"].(map[string]any)
	end := any(line)
	if v, present := ev["end"]; present {
		end = nil
		if m, isMap := v.(map[string]any); isMap {
			end = line
			if l, ok := m["line"]; ok {
				end = l
			}
		}
	}
	if e, ok := end.(int); ok && 1 <= line && line <= e && e <= len(lines) {
		return map[string]any{"text": nonblank(strings.Join(lines[line-1:e], "\n"))}
	}
	return nil
}

// SourceRegion validates native byte columns (OpenGrep) or IR character columns against the
// captured source and returns the spanned text with 1-based character columns. lines may be nil.
func SourceRegion(a *parse.Artifact, start, end map[string]any, byteColumns bool, lines []string) (text string, startCol, endCol int, err error) {
	if a == nil || a.Text == nil {
		return "", 0, 0, errors.New("source unavailable")
	}
	if lines == nil {
		lines = strings.Split(*a.Text, "\n")
	}
	var pos [2][2]int
	for i, position := range [2]map[string]any{start, end} {
		line, okL := position["line"].(int)
		col, okC := position["col"].(int)
		if !okL || !okC || line < 1 || line > len(lines) {
			return "", 0, 0, errors.New("invalid source position")
		}
		text := lines[line-1]
		width := utf8.RuneCountInString(text)
		if byteColumns {
			width = len(text)
		}
		if col < 1 || col > width+1 {
			return "", 0, 0, errors.New("invalid source column")
		}
		character := col - 1
		if byteColumns {
			if !utf8.ValidString(text[:col-1]) {
				return "", 0, 0, errors.New("invalid source column")
			}
			character = utf8.RuneCountInString(text[:col-1])
		}
		pos[i] = [2]int{line, character}
	}
	if slices.Compare(pos[1][:], pos[0][:]) < 0 {
		return "", 0, 0, errors.New("inverted source region")
	}
	span := slices.Clone(lines[pos[0][0]-1 : pos[1][0]])
	span[len(span)-1] = string([]rune(span[len(span)-1])[:pos[1][1]])
	span[0] = string([]rune(span[0])[pos[0][1]:])
	return strings.Join(span, "\n"), pos[0][1] + 1, pos[1][1] + 1, nil
}

// traceLocation validates one ["CliLoc", [location, content]] trace step against the source.
func traceLocation(value any, p *parse.Package, role string) (FlowStep, error) {
	v, _ := value.([]any)
	if len(v) != 2 || v[0] != any("CliLoc") {
		return FlowStep{}, errors.New("unsupported trace")
	}
	payload, _ := v[1].([]any)
	if len(payload) != 2 {
		return FlowStep{}, errors.New("invalid trace location")
	}
	content, okS := payload[1].(string)
	location, okL := payload[0].(map[string]any)
	if !okS || !okL {
		return FlowStep{}, errors.New("invalid trace location")
	}
	var a *parse.Artifact
	path, isStr := location["path"].(string)
	if isStr {
		a = p.ByRel[path]
	}
	start, _ := location["start"].(map[string]any)
	end, _ := location["end"].(map[string]any)
	text, _, _, err := SourceRegion(a, start, end, true, nil)
	if err != nil {
		return FlowStep{}, err
	}
	if pytext.Strip(text) == "" || pytext.Strip(text) != pytext.Strip(content) {
		return FlowStep{}, errors.New("trace content does not match source")
	}
	return FlowStep{Role: role, Path: path, Start: pytext.DeepCopy(start).(map[string]any),
		End: pytext.DeepCopy(end).(map[string]any), Content: content}, nil
}

func traceSteps(raw any, p *parse.Package) ([]FlowStep, error) {
	trace, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("invalid trace")
	}
	source, ok := trace["taint_source"]
	if !ok {
		return nil, errors.New("taint_source")
	}
	step, err := traceLocation(source, p, "source")
	if err != nil {
		return nil, err
	}
	steps := []FlowStep{step}
	var intermediate []any
	if v, present := trace["intermediate_vars"]; present {
		intermediate, ok = v.([]any)
		if !ok || len(intermediate) > 128 {
			return nil, errors.New("invalid trace steps")
		}
	}
	for _, item := range intermediate {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid trace step")
		}
		location, okL := m["location"]
		content, okC := m["content"]
		if !okL || !okC {
			return nil, errors.New("location")
		}
		if step, err = traceLocation([]any{"CliLoc", []any{location, content}}, p, "intermediate"); err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	sink, ok := trace["taint_sink"]
	if !ok {
		return nil, errors.New("taint_sink")
	}
	if step, err = traceLocation(sink, p, "sink"); err != nil {
		return nil, err
	}
	return append(steps, step), nil
}

// codeFlow is the validated dataflow trace of an OpenGrep finding, or the limitation that
// explains why none is reported.
func codeFlow(ev map[string]any, p *parse.Package) ([]FlowStep, []string) {
	if ev["trace_mapping"] == any("unvalidated") {
		return []FlowStep{}, []string{"trace-unvalidated"}
	}
	raw, ok := ev["dataflow_trace"]
	if !ok {
		return []FlowStep{}, []string{}
	}
	steps, err := traceSteps(raw, p)
	if err != nil {
		return []FlowStep{}, []string{"trace-unvalidated"}
	}
	return steps, []string{}
}

// occurrence orders findings by position; -1 stands for a missing coordinate.
func occurrence(finding map[string]any) [4]int {
	var out [4]int
	for i, key := range [...]string{"line", "column", "offset", "length"} {
		out[i] = -1
		if v, ok := finding[key].(int); ok {
			out[i] = v
		}
	}
	return out
}

func str(finding map[string]any, key string) string {
	s, _ := finding[key].(string)
	return s
}

func copyCandidates(cs []Candidate) []Candidate {
	out := make([]Candidate, len(cs))
	for i, c := range cs {
		out[i] = c
		out[i].Finding, _ = pytext.DeepCopy(c.Finding).(map[string]any)
	}
	return out
}

func sortedValues[T any](m map[string]T) []T {
	out := make([]T, 0, len(m))
	for _, k := range slices.Sorted(maps.Keys(m)) {
		out = append(out, m[k])
	}
	return out
}

// Correlate keeps the raw candidates intact and links only equivalent occurrences to one
// result. Fingerprints ignore line shifts; identical anchors at different occurrences get an
// ordered occurrence suffix; context digests invalidate scoped decisions after other edits.
func Correlate(p *parse.Package, candidates []Candidate) (*Correlation, error) {
	raw := copyCandidates(candidates)
	manifests := parse.ManifestIndex(p)
	signatures, order := map[string]string{}, map[string]string{}
	for _, c := range raw {
		if _, dup := signatures[c.CandidateID]; c.CandidateID == "" || dup {
			return nil, errors.New("candidate IDs must be unique nonempty strings")
		}
		finding := maps.Clone(c.Finding)
		finding["evidence"] = evidence(c)
		order[c.CandidateID] = pytext.Canonical(map[string]any{"finding": finding, "analyzer": c.Analyzer,
			"provenance": c.Provenance, "coverage": c.Coverage})
		signatures[c.CandidateID] = sha256hex([]byte(order[c.CandidateID]))
	}
	ids := slices.SortedFunc(maps.Keys(signatures), func(a, b string) int {
		return cmp.Or(cmp.Compare(signatures[a], signatures[b]), cmp.Compare(a, b))
	})
	counts, stable := map[string]int{}, map[string]string{}
	for _, id := range ids {
		stable[id] = fmt.Sprintf("candidate-%s-%d", signatures[id], counts[signatures[id]])
		counts[signatures[id]]++
	}
	groups := map[string][]Candidate{}
	for _, c := range raw {
		finding := pytext.DeepCopy(c.Finding).(map[string]any)
		cmpEv := comparable(evidence(c))
		finding["evidence"] = cmpEv
		// Wording is not identity when matching security evidence has a known source.
		if str(finding, "vector") != "" && len(cmpEv) > 0 && anchor(finding, p.ByRel[str(finding, "path")]) != nil {
			delete(finding, "message")
		}
		key := pytext.Canonical(finding)
		groups[key] = append(groups[key], c)
	}
	contextCache := make(map[string]any, len(p.Artifacts))
	for _, a := range p.Artifacts {
		contextCache[a.Rel] = digest(artifactContext(a))
	}
	packageContext := digest(contextCache)
	results, links := []*Result{}, []Link{}
	occurrences := map[string]int{}
	for _, key := range slices.SortedFunc(maps.Keys(groups), func(a, b string) int {
		fa, fb := groups[a][0].Finding, groups[b][0].Finding
		oa, ob := occurrence(fa), occurrence(fb)
		return cmp.Or(cmp.Compare(str(fa, "path"), str(fb, "path")), slices.Compare(oa[:], ob[:]), cmp.Compare(a, b))
	}) {
		group := groups[key]
		slices.SortFunc(group, func(a, b Candidate) int {
			return cmp.Or(cmp.Compare(order[a.CandidateID], order[b.CandidateID]), cmp.Compare(a.CandidateID, b.CandidateID))
		})
		finding := pytext.DeepCopy(group[0].Finding).(map[string]any)
		ev := evidence(group[0])
		finding["evidence"] = ev
		path := str(finding, "path")
		a := p.ByRel[path]
		manifest := parse.GoverningManifest(manifests, path)
		rule := cmp.Or(str(finding, "rule"), "unknown-rule")
		ruleID := "skill-xray/" + pytext.Quote(rule, "-._")
		cmpEv := comparable(ev)
		flow, limitations := codeFlow(ev, p)
		if ev["location_mapping"] == any("unvalidated") {
			limitations = append(limitations, "location-unvalidated")
		}
		if len(flow) > 0 {
			steps := make([]any, len(flow))
			for i, s := range flow {
				steps[i] = map[string]any{"path": s.Path, "role": s.Role, "content": nonblank(s.Content)}
			}
			cmpEv["dataflow_trace"] = steps
		}
		base := digest(map[string]any{"version": FingerprintVersion, "rule": ruleID, "path": path,
			"vector": finding["vector"], "severity": finding["severity"],
			"evidence": semanticEvidence(cmpEv), "source": anchor(finding, a)})
		fingerprint := digest(map[string]any{"anchor": base, "occurrence": occurrences[base]})
		occurrences[base]++
		id := "finding-" + fingerprint
		var manifestRel *string
		context := map[string]any{"version": contextVersion, "anchor": base, "package": packageContext,
			"artifact": contextCache[path], "manifest": nil}
		if manifest != nil {
			rel := manifest.Rel
			manifestRel = &rel
			context["manifest"] = contextCache[rel]
		}
		if a == nil || a.Text == nil && a.Raw == nil {
			limitations = append(limitations, "source-unavailable")
		}
		evidences, provenances := map[string]map[string]any{}, map[string]Provenance{}
		members := make([]string, 0, len(group))
		for i, item := range group {
			e := evidence(item)
			evidences[pytext.Canonical(e)] = e
			prov := Provenance{Analyzer: item.Analyzer, Provenance: item.Provenance}
			if itemEv, _ := item.Finding["evidence"].(map[string]any); itemEv != nil {
				if r, ok := itemEv["engine_rule"].(string); ok {
					prov.EngineRule = &r
				}
			}
			provenances[pytext.Canonical(prov)] = prov
			members = append(members, item.CandidateID)
			link := Link{CandidateID: item.CandidateID, ResultID: id, StableCandidateID: stable[item.CandidateID],
				Disposition: "reported", Reason: "Original deterministic evidence retained"}
			if i > 0 {
				link.Disposition, link.Reason = "duplicate", "Equivalent occurrence; evidence and provenance preserved"
			}
			links = append(links, link)
		}
		slices.Sort(members)
		results = append(results, &Result{ID: id, RuleID: ruleID, Fingerprint: fingerprint,
			FingerprintVersion: FingerprintVersion, ContextDigest: digest(context), Finding: finding,
			Manifest: manifestRel, CandidateIDs: members, Provenance: sortedValues(provenances),
			Evidence: sortedValues(evidences), CodeFlow: flow, Limitations: limitations})
	}
	slices.SortFunc(results, func(a, b *Result) int {
		oa, ob := occurrence(a.Finding), occurrence(b.Finding)
		return cmp.Or(cmp.Compare(findings.Rank(str(a.Finding, "severity"), 9), findings.Rank(str(b.Finding, "severity"), 9)),
			cmp.Compare(str(a.Finding, "path"), str(b.Finding, "path")), slices.Compare(oa[:], ob[:]), cmp.Compare(a.ID, b.ID))
	})
	slices.SortFunc(links, func(a, b Link) int { return cmp.Compare(a.CandidateID, b.CandidateID) })
	return &Correlation{RawCandidates: raw, Results: results, Links: links,
		Package: &PackageInfo{Name: p.Name, ContentDigest: packageContext, DigestVersion: contextVersion}}, nil
}
