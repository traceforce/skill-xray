// Package sarif serialises an audited scan report as validated SARIF 2.1.0 (Python sarif.py):
// Build maps final decisions without re-deciding anything, Validate re-checks the schema and every
// cross-reference, Encode emits the canonical bytes and Write places them atomically outside the
// scanned package.
package sarif

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/traceforce/skill-xray/internal/correlate"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/llm"
	"github.com/traceforce/skill-xray/internal/metadata"
	"github.com/traceforce/skill-xray/internal/opengrep"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/scan"
)

// schemaJSON is the unmodified OASIS SARIF 2.1.0 Errata 01 schema (schemas/README.md).
//
//go:embed schemas/sarif-schema-2.1.0.json
var schemaJSON []byte

const maxReportBytes = 64 << 20

var (
	level        = map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note"}
	reviewFields = []string{"candidate_id", "disposition", "status", "reason", "policy_version", "provenance",
		"proposal", "tags", "reviewer", "request_sha256", "response_sha256", "reviewed_candidate_id", "failure_reason"}
	hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rename = os.Rename // os.replace; the atomic-write test makes it fail
)

// compile is Draft4Validator(schema) with no format checker: Draft 4, format assertions off.
func compile(id string, doc any) *jsonschema.Schema {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft4)
	if err := c.AddResource(id, doc); err != nil {
		panic(err)
	}
	return c.MustCompile(id)
}

// schema is the embedded document's validator and its id (the "$schema" value).
var schema = sync.OnceValues(func() (*jsonschema.Schema, string) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		panic(err)
	}
	id := doc.(map[string]any)["id"].(string)
	return compile(id, doc), id
})

// SchemaID is the "$schema" value every emitted document carries.
func SchemaID() string {
	_, id := schema()
	return id
}

var responseSchema = sync.OnceValue(func() *jsonschema.Schema {
	return compile("urn:skill-xray:review-response", llm.ResponseSchema)
})

// location is _location: the SARIF location for a finding or flow step and whether its
// coordinates could not be verified against the captured source.
func location(p *parse.Package, path any, cache map[string][]string, start map[string]any, end, offset, length any, byteColumns bool) (map[string]any, bool) {
	rel, isStr := path.(string)
	a := p.ByRel[rel]
	if !isStr || rel == "" || strings.HasPrefix(rel, "/") || slices.Contains(strings.Split(rel, "/"), "..") ||
		a == nil && (windowsDrive(rel) || strings.Contains(rel, `\`)) {
		return nil, true
	}
	physical := map[string]any{"artifactLocation": map[string]any{"uri": pytext.QuoteBytes([]byte(rel), "/")}}
	region, ok := region(a, cache, rel, start, end, offset, length, byteColumns)
	if region != nil {
		physical["region"] = region
	}
	return map[string]any{"physicalLocation": physical}, !ok || a == nil
}

// windowsDrive is bool(PureWindowsPath(p).drive): a "X:" prefix or a UNC "\\host" prefix.
func windowsDrive(p string) bool {
	r := []rune(p)
	sep := func(c rune) bool { return c == '\\' || c == '/' }
	return len(r) >= 2 && (r[1] == ':' || sep(r[0]) && sep(r[1]))
}

// region is _location's try block: a byte region, a text region, or none; ok is false where
// Python raises ValueError, TypeError or AttributeError.
func region(a *parse.Artifact, cache map[string][]string, rel string, start map[string]any, end, offset, length any, byteColumns bool) (map[string]any, bool) {
	if offset != nil {
		o, okO := offset.(int)
		n, okN := length.(int)
		if a == nil || a.Raw == nil || !okO || o < 0 || !okN || n <= 0 || o+n > len(a.Raw) {
			return nil, false
		}
		return map[string]any{"byteOffset": o, "byteLength": n}, true
	}
	if len(start) == 0 || start["line"] == nil {
		return nil, true
	}
	last := start
	if end != nil {
		if last, _ = end.(map[string]any); last["col"] == nil {
			return nil, false // incomplete end boundary
		}
	}
	lines, cached := cache[rel]
	if !cached {
		if a == nil || a.Text == nil {
			return nil, false
		}
		lines = strings.Split(*a.Text, "\n")
		cache[rel] = lines
	}
	var pos [2][2]int // (line, 1-based code-point column or 0 for None)
	for i, position := range [2]map[string]any{start, last} {
		point := map[string]any{"line": position["line"], "col": 1}
		if position["col"] != nil {
			point["col"] = position["col"]
		}
		_, character, _, err := correlate.SourceRegion(a, point, point, byteColumns, lines)
		if err != nil {
			return nil, false
		}
		pos[i] = [2]int{position["line"].(int), 0}
		if position["col"] != nil {
			pos[i][1] = character
		}
	}
	if pos[1][0] < pos[0][0] || pos[1][0] == pos[0][0] && max(pos[1][1], 1) < max(pos[0][1], 1) {
		return nil, false // inverted text region
	}
	out := map[string]any{"startLine": pos[0][0]}
	if pos[0][1] != 0 {
		out["startColumn"] = pos[0][1]
	}
	if end != nil {
		out["endLine"], out["endColumn"] = pos[1][0], pos[1][1]
	}
	return out, true
}

// title is finding.get("title") or finding["rule"].
func title(f map[string]any) string {
	if s, _ := f["title"].(string); s != "" {
		return s
	}
	s, _ := f["rule"].(string)
	return s
}

// ruleName is the rule's identifier in the Pascal case SARIF asks of a reportingDescriptor name:
// skill-xray/preproc-inline-bang becomes PreprocInlineBang.
func ruleName(rid string) string {
	var b strings.Builder
	slug := rid[strings.LastIndexByte(rid, '/')+1:]
	for _, part := range strings.FieldsFunc(slug, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

// describe is the finding's title followed by its vector, tier and CWE identifiers, so a reader
// of the report has the whole classification in words without the vector registry.
func describe(f map[string]any) string {
	text := title(f)
	var tags []string
	if v, _ := f["vector"].(string); v != "" {
		tags = append(tags, v)
	}
	if t, _ := f["tier"].(string); t != "" {
		tags = append(tags, "tier "+t)
	}
	switch c := f["cwe"].(type) { // a decoded list or the finding's own slice; absent on a diagnostic
	case []string:
		tags = append(tags, c...)
	case []any:
		tags = append(tags, strs(c)...)
	}
	if len(tags) == 0 {
		return text
	}
	return text + " (" + strings.Join(tags, ", ") + ")"
}

func category(f map[string]any) string {
	if pytext.Truthy(f["vector"]) {
		return "security-finding"
	}
	return "analysis-diagnostic"
}

func byID(a, b any) int {
	return strings.Compare(a.(map[string]any)["candidate_id"].(string), b.(map[string]any)["candidate_id"].(string))
}

// reviewAudit is _review_audit: the compact, stable-id view of the judge decisions (never the
// request, which holds whole source files).
func reviewAudit(annotated bool, decisions []any, identities map[string]string) (map[string]any, error) {
	mode := "shadow"
	if annotated {
		mode = "annotated"
	}
	records := []any{}
	for _, d := range decisions {
		decision, record := d.(map[string]any), map[string]any{}
		for _, key := range reviewFields {
			if v, ok := decision[key]; ok {
				record[key] = v
			}
		}
		for _, key := range []string{"candidate_id", "reviewed_candidate_id"} {
			if v, ok := record[key]; ok {
				stable, known := identities[fmt.Sprint(v)]
				if !known {
					return nil, errors.New("Unknown LLM review candidate")
				}
				record[key] = stable
			}
		}
		if proposal, _ := record["proposal"].(map[string]any); proposal != nil {
			if proposal["candidate_id"] != decision["candidate_id"] {
				return nil, errors.New("LLM proposal candidate mismatch")
			}
			proposal["candidate_id"] = record["candidate_id"]
		}
		records = append(records, record)
	}
	slices.SortStableFunc(records, byID)
	return map[string]any{"mode": mode, "authoritative": false, "decisions": records}, nil
}

// Build is build_sarif: the SARIF document, as generic JSON, of an already correlated and
// dispositioned report. Nothing is re-decided; the report is never aliased or mutated.
func Build(p *parse.Package, r *scan.ScanReport) (map[string]any, error) {
	doc := r.ToMap()
	correlation, _ := doc["correlation"].(map[string]any)
	if errs, _ := correlation["errors"].([]any); len(errs) > 0 {
		return nil, errors.New("Cannot emit final SARIF after correlation failure; raw report retained")
	}
	identities := map[string]string{}
	links, _ := correlation["links"].([]any)
	for _, l := range links {
		link := l.(map[string]any)
		cid := link["candidate_id"].(string)
		identities[cid] = cid
		if stable, ok := link["stable_candidate_id"].(string); ok {
			identities[cid] = stable
		}
		link["candidate_id"] = identities[cid]
		delete(link, "stable_candidate_id")
	}
	raw, _ := correlation["raw_candidates"].([]any)
	for _, c := range raw {
		candidate := c.(map[string]any)
		candidate["candidate_id"] = identities[candidate["candidate_id"].(string)]
		finding := candidate["finding"].(map[string]any)
		evidence, _ := finding["evidence"].(map[string]any)
		if candidate["analyzer"] == any("opengrep") || evidence["engine"] == any("opengrep") {
			delete(evidence, "fingerprint") // the run-scoped engine id, never identity
		}
	}
	if raw == nil {
		raw = []any{}
	}
	if links == nil {
		links = []any{}
	}
	slices.SortStableFunc(raw, byID)
	slices.SortStableFunc(links, byID)

	entries, _ := correlation["results"].([]any)
	titles, described := map[string][]string{}, map[string][]string{}
	for _, e := range entries {
		entry := e.(map[string]any)
		rid := entry["rule_id"].(string)
		finding := entry["finding"].(map[string]any)
		titles[rid] = append(titles[rid], title(finding))
		described[rid] = append(described[rid], describe(finding))
	}
	rules, index := []any{}, map[string]int{}
	for i, rid := range slices.Sorted(maps.Keys(titles)) {
		rules = append(rules, map[string]any{"id": rid, "name": ruleName(rid),
			"shortDescription": map[string]any{"text": slices.Min(titles[rid])},
			"fullDescription":  map[string]any{"text": slices.Min(described[rid])}})
		index[rid] = i
	}
	cache := map[string][]string{}
	results := []any{}
	for _, e := range entries {
		entry := e.(map[string]any)
		finding := entry["finding"].(map[string]any)
		evidence, _ := finding["evidence"].(map[string]any)
		effective, _ := entry["effective_severity"].(string)
		lvl, ok := level[effective]
		if !ok {
			return nil, fmt.Errorf("KeyError: %q", effective)
		}
		candidateIDs := []any{}
		cids, _ := entry["candidate_ids"].([]any)
		for _, cid := range cids {
			candidateIDs = append(candidateIDs, identities[cid.(string)])
		}
		slices.SortFunc(candidateIDs, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
		limitations, _ := entry["limitations"].([]any)
		properties := map[string]any{
			"id": entry["id"], "title": title(finding), "category": category(finding),
			"originalSeverity": entry["original_severity"], "effectiveSeverity": effective,
			"evidence": entry["evidence"], "disposition": entry["disposition"], "reason": entry["decision_reason"],
			"policyVersion": entry["policy_version"], "decisionProvenance": entry["decision_provenance"],
			"candidateIds": candidateIDs, "provenance": entry["provenance"], "contextDigest": entry["context_digest"],
			"coverage": entry["coverage"], "governingManifest": entry["manifest"],
			"limitations": append([]any{}, limitations...),
		}
		for _, kv := range [][2]string{{"sxv", "vector"}, {"cwe", "cwe"}, {"tier", "tier"}} {
			if pytext.Truthy(finding[kv[1]]) {
				properties[kv[0]] = finding[kv[1]]
			}
		}
		result := map[string]any{"ruleId": entry["rule_id"], "ruleIndex": index[entry["rule_id"].(string)],
			"message": map[string]any{"text": finding["message"]}, "level": lvl,
			"partialFingerprints": map[string]any{fmt.Sprint(entry["fingerprint_version"]): entry["fingerprint"]},
			"properties":          properties}
		unmapped := evidence["location_mapping"] == any("unvalidated")
		start, end := map[string]any{"line": finding["line"], "col": nil}, any(nil)
		if !unmapped {
			start["col"], end = finding["column"], evidence["end"]
		}
		loc, invalid := location(p, finding["path"], cache, start, end, finding["offset"], finding["length"], evidence["engine"] == any("opengrep"))
		if loc != nil {
			result["locations"] = []any{loc}
		}
		if invalid && pytext.Truthy(finding["path"]) {
			properties["limitations"] = append(properties["limitations"].([]any), "location-unvalidated")
		}
		if invalid || unmapped || loc == nil || loc["physicalLocation"].(map[string]any)["region"] == nil {
			properties["reportedLocation"] = map[string]any{"path": finding["path"], "line": finding["line"],
				"column": finding["column"], "offset": finding["offset"], "length": finding["length"]}
		}
		if flow, _ := entry["code_flow"].([]any); len(flow) > 0 {
			steps := []any{}
			for i, s := range flow {
				step := s.(map[string]any)
				stepStart, _ := step["start"].(map[string]any)
				loc, invalid := location(p, step["path"], cache, stepStart, step["end"], nil, nil, true)
				if invalid {
					return nil, errors.New("Validated code flow lost its source mapping")
				}
				steps = append(steps, map[string]any{"location": loc, "kinds": []any{step["role"]}, "executionOrder": i})
			}
			result["codeFlows"] = []any{map[string]any{"threadFlows": []any{map[string]any{"locations": steps}}}}
		}
		if entry["disposition"] == any("suppressed") {
			result["suppressions"] = []any{map[string]any{"kind": "external", "status": "accepted", "justification": entry["decision_reason"]}}
		}
		results = append(results, result)
	}
	slices.SortStableFunc(results, func(a, b any) int {
		pa, pb := a.(map[string]any)["properties"].(map[string]any), b.(map[string]any)["properties"].(map[string]any)
		if d := findings.SeverityRank[pa["effectiveSeverity"].(string)] - findings.SeverityRank[pb["effectiveSeverity"].(string)]; d != 0 {
			return d
		}
		return strings.Compare(fmt.Sprint(pa["id"]), fmt.Sprint(pb["id"]))
	})

	contextErrors, _ := doc["context_errors"].([]any)
	contextErrors = append([]any{}, contextErrors...)
	slices.SortFunc(contextErrors, func(a, b any) int { return strings.Compare(fmt.Sprint(a), fmt.Sprint(b)) })
	pkg, _ := correlation["package"].(map[string]any)
	digest := sha256.Sum256(opengrep.Rules)
	properties := map[string]any{
		"opengrepVersion": opengrep.Version, "policyVersion": correlate.PolicyVersion,
		"package":            map[string]any{"name": pkg["name"], "contentDigest": pkg["content_digest"], "digestVersion": pkg["digest_version"]},
		"capabilityContexts": correlation["capability_contexts"], "rulesetDigest": hex.EncodeToString(digest[:]),
		"coverage": correlation["coverage"], "contextLimitations": correlation["context_limitations"],
		"contextErrors": contextErrors, "rawScope": "emitted-results-before-reporting-deduplication",
		"rawCandidates": raw, "candidateLinks": links,
	}
	if usage, _ := doc["llm_usage"].(map[string]any); len(usage) > 0 { // the lane was on: the report says so even when it found nothing
		properties["llmUsage"] = map[string]any{"calls": usage["calls"], "failures": usage["failures"], "failureReason": usage["failure_reason"], "unavailable": usage["unavailable"],
			"provider": usage["provider"], "model": usage["model"], "advisoryEnabled": usage["advisory_enabled"],
			"judgeEnabled": usage["judge_enabled"], "applyEnabled": usage["apply_enabled"]}
	}
	if usage, _ := doc["llm_usage"].(map[string]any); pytext.Truthy(usage["judge_enabled"]) {
		key := "shadow"
		if r.ReviewMode {
			key = "dispositions"
		}
		decisions, _ := doc[key].([]any)
		audit, err := reviewAudit(r.ReviewMode, decisions, identities)
		if err != nil {
			return nil, err
		}
		properties["llmReview"] = audit
	}
	_, id := schema()
	run := map[string]any{
		"tool":        map[string]any{"driver": map[string]any{"name": "skill-xray", "version": metadata.Version, "rules": rules}},
		"columnKind":  "unicodeCodePoints",
		"results":     results,
		"invocations": []any{map[string]any{"executionSuccessful": correlation["execution_successful"]}},
		"properties":  properties,
	}
	return map[string]any{"version": "2.1.0", "$schema": id, "runs": []any{run}}, nil
}

// valueError is the panic Validate's checks raise; the recover names it as Python does.
type valueError struct{}

func check(ok bool) {
	if !ok {
		panic(valueError{})
	}
}

// strs is a list of str; anything else is a TypeError.
func strs(v any) []string {
	out := []string{}
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// toInt is the integer a JSON number carries, decoded as int (D7) or as a plain json.Unmarshal float64.
func toInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		check(x == float64(int(x)))
		return int(x)
	}
	panic(fmt.Sprintf("TypeError: %T", v))
}

// Validate is validate_sarif: the schema, then every cross-reference between results, raw
// candidates, links, capability contexts and the review audit. The error names the Python
// exception class: ValidationError for the schema, ValueError for a contract check, TypeError
// for a malformed shape (a failed type assertion or index), as `except Exception` collapses them.
func Validate(document any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			name := "TypeError"
			switch r.(type) {
			case valueError:
				name = "ValueError"
			case *jsonschema.ValidationError:
				name = "ValidationError"
			}
			err = fmt.Errorf("SARIF validation failed (%s)", name)
		}
	}()
	sch, _ := schema()
	if err := sch.Validate(document); err != nil {
		panic(err)
	}
	runs := document.(map[string]any)["runs"].([]any)
	check(len(runs) == 1)
	run := runs[0].(map[string]any)
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	props := run["properties"].(map[string]any)
	raw := props["rawCandidates"].([]any)
	links := props["candidateLinks"].([]any)
	results := run["results"].([]any)
	contexts, ok := props["capabilityContexts"].(map[string]any)
	check(ok)
	for key, c := range contexts {
		context, ok := c.(map[string]any)
		check(ok)
		manifest, _ := context["manifest"].(string)
		check((context["manifest"] == nil || context["manifest"] == any(manifest)) && manifest == key)
	}
	byCandidate, byResult := map[string]map[string]any{}, map[string]map[string]any{}
	for _, c := range raw {
		candidate := c.(map[string]any)
		byCandidate[candidate["candidate_id"].(string)] = candidate
	}
	for _, r := range results {
		result := r.(map[string]any)
		byResult[result["properties"].(map[string]any)["id"].(string)] = result
	}
	linked, primary, linkedIDs := map[string][]string{}, []string{}, map[string]bool{}
	for _, l := range links {
		link := l.(map[string]any)
		rid, cid := link["result_id"].(string), link["candidate_id"].(string)
		check(byResult[rid] != nil)
		if link["disposition"] != any("duplicate") {
			primary = append(primary, rid)
		}
		linked[rid] = append(linked[rid], cid)
		linkedIDs[cid] = true
	}
	ruleIDs := map[string]bool{}
	for _, r := range rules {
		ruleIDs[r.(map[string]any)["id"].(string)] = true
	}
	slices.Sort(primary)
	check(len(byCandidate) == len(raw) && len(byResult) == len(results) && len(links) == len(raw) &&
		maps.Equal(linkedIDs, pytext.Set(slices.Collect(maps.Keys(byCandidate))...)) &&
		slices.Equal(primary, slices.Sorted(maps.Keys(byResult))) && len(ruleIDs) == len(rules))
	if review, ok := props["llmReview"]; ok {
		validateReview(review.(map[string]any), raw)
	}
	for _, r := range results {
		result := r.(map[string]any)
		rp := result["properties"].(map[string]any)
		manifest, _ := rp["governingManifest"].(string)
		if contexts[manifest] == nil {
			check(rp["coverage"] == any("incomplete") && (rp["governingManifest"] == nil || pytext.Truthy(props["contextErrors"])))
		}
		effective, original := rp["effectiveSeverity"].(string), rp["originalSeverity"].(string)
		effRank, okE := findings.SeverityRank[effective]
		origRank, okO := findings.SeverityRank[original]
		check(okE && okO)
		candidateIDs := strs(rp["candidateIds"])
		check(rules[toInt(result["ruleIndex"])].(map[string]any)["id"] == result["ruleId"] && len(candidateIDs) > 0 &&
			pytext.Truthy(rp["reason"]) && pytext.Truthy(rp["policyVersion"]) &&
			slices.Contains([]any{"reported", "suppressed", "corrected"}, rp["disposition"]) &&
			slices.Equal(slices.Sorted(slices.Values(linked[rp["id"].(string)])), slices.Sorted(slices.Values(candidateIDs))) &&
			rp["id"] == any("finding-"+result["partialFingerprints"].(map[string]any)[correlate.FingerprintVersion].(string)) &&
			effRank >= origRank && result["level"] == any(level[effective]))
		if rp["coverage"] == any("incomplete") {
			check(props["coverage"] == any("incomplete"))
		}
		suppressed, corrected := rp["disposition"] == any("suppressed"), rp["disposition"] == any("corrected")
		check(corrected == (effective != original))
		if corrected {
			check(pytext.Truthy(rp["sxv"]) && slices.Contains([]any{"operator-policy", "llm-review-policy"}, rp["decisionProvenance"]) &&
				rp["coverage"] == any("no-reported-gap"))
		}
		if corrected && rp["decisionProvenance"] == any("llm-review-policy") {
			review, _ := props["llmReview"].(map[string]any)
			support, mechanical := false, false
			if review != nil {
				for _, d := range review["decisions"].([]any) {
					decision := d.(map[string]any)
					proposal, _ := decision["proposal"].(map[string]any)
					if slices.Contains(candidateIDs, decision["candidate_id"].(string)) && decision["disposition"] == any("llm-disputed") &&
						decision["status"] == any("proposed") && decision["proposal"] != nil &&
						proposal["verdict"] == any("propose_false_positive") && proposal["confidence"] == any("high") &&
						proposal["mechanism"] == any("not_supported") && proposal["intent"] == any("legitimate") {
						support = true
					}
				}
			}
			for _, cid := range candidateIDs {
				candidate := byCandidate[cid]
				check(candidate != nil)
				evidence, _ := candidate["finding"].(map[string]any)["evidence"].(map[string]any)
				mechanical = mechanical || candidate["analyzer"] == any("opengrep") || evidence["engine"] == any("opengrep")
			}
			check(review != nil && review["mode"] == any("annotated") && support && !mechanical &&
				correlate.LLMApplyVectors[rp["sxv"].(string)] && effective == "low" && rp["policyVersion"] == any(correlate.LLMApplyVersion))
		}
		suppressions, _ := result["suppressions"].([]any)
		check(suppressed == (len(suppressions) > 0))
		if suppressed {
			check(pytext.Truthy(rp["sxv"]) && rp["decisionProvenance"] == any("operator-policy") && rp["coverage"] == any("no-reported-gap") &&
				suppressions[0].(map[string]any)["justification"] == rp["reason"])
		}
		expected := map[string]bool{}
		for _, cid := range candidateIDs {
			candidate := byCandidate[cid]
			check(candidate != nil)
			evidence, present := candidate["finding"].(map[string]any)["evidence"]
			if !present {
				evidence = map[string]any{}
			}
			expected[pytext.Canonical(evidence)] = true
		}
		got := []string{}
		for _, e := range rp["evidence"].([]any) {
			got = append(got, pytext.Canonical(e))
		}
		check(slices.Equal(got, slices.Sorted(maps.Keys(expected))))
		for _, cid := range candidateIDs {
			finding := byCandidate[cid]["finding"].(map[string]any)
			rule, _ := finding["rule"].(string)
			if rule == "" {
				rule = "unknown-rule"
			}
			check(result["ruleId"] == any("skill-xray/"+pytext.Quote(rule, "-._")) && rp["category"] == any(category(finding)))
			for _, kv := range [][2]string{{"sxv", "vector"}, {"cwe", "cwe"}, {"tier", "tier"}} {
				check(pytext.Canonical(orNone(rp[kv[0]])) == pytext.Canonical(orNone(finding[kv[1]])))
			}
			check(finding["severity"] == rp["originalSeverity"])
		}
	}
	for _, l := range links {
		link := l.(map[string]any)
		rp := byResult[link["result_id"].(string)]["properties"].(map[string]any)
		check(slices.Contains(strs(rp["candidateIds"]), link["candidate_id"].(string)) && pytext.Truthy(link["reason"]) &&
			slices.Contains([]any{"duplicate", rp["disposition"]}, link["disposition"]))
	}
	return nil
}

// orNone is `value or None`.
func orNone(v any) any {
	if pytext.Truthy(v) {
		return v
	}
	return nil
}

// validateReview is _validate_review: the audit's structure; judgment belongs to the producer.
func validateReview(audit map[string]any, raw []any) {
	_, hasAuth := audit["authoritative"]
	check(len(audit) == 3 && hasAuth && slices.Contains([]any{"annotated", "shadow"}, audit["mode"]) && audit["authoritative"] == any(false))
	candidates, records := map[string]map[string]any{}, map[string]map[string]any{}
	for _, c := range raw {
		candidate := c.(map[string]any)
		if candidate["provenance"] != any("advisory-output") {
			candidates[candidate["candidate_id"].(string)] = candidate
		}
	}
	decisions := audit["decisions"].([]any)
	for _, d := range decisions {
		decision := d.(map[string]any)
		records[decision["candidate_id"].(string)] = decision
	}
	check(len(records) == len(decisions) && maps.EqualFunc(records, candidates, func(map[string]any, map[string]any) bool { return true }))
	annotated := audit["mode"] == any("annotated")
	policy := llm.ShadowPolicyVersion
	if annotated {
		policy = llm.ReviewPolicyVersion
	}
	bounded := func(v any) bool { // a non-blank str of at most 200 code points
		s, ok := v.(string)
		return ok && pytext.Strip(s) != "" && utf8.RuneCountInString(s) <= 200
	}
	for cid, decision := range records {
		for key := range decision {
			check(slices.Contains(reviewFields, key))
		}
		check(decision["policy_version"] == any(policy) &&
			slices.Contains([]any{"ineligible", "proposed", "duplicate-review", "budget", "unavailable", "incomplete-context", "invalid-response", "error"}, decision["status"]) &&
			slices.Contains([]any{"reported", "llm-disputed"}, decision["disposition"]) &&
			slices.Contains([]any{"deterministic-policy", "llm-review-policy", "llm-shadow"}, decision["provenance"]) &&
			(annotated || decision["disposition"] == any("reported")) &&
			bounded(decision["reason"]) && bounded(decision["policy_version"]) && bounded(decision["provenance"]))
		_, hasRequest := decision["request_sha256"]
		_, hasReviewer := decision["reviewer"]
		_, hasResponse := decision["response_sha256"]
		if hasRequest || hasReviewer || hasResponse {
			check(hasRequest && hasReviewer)
		}
		hashes := []any{}
		for _, key := range []string{"request_sha256", "response_sha256"} {
			if v, ok := decision[key]; ok {
				hashes = append(hashes, v)
			}
		}
		if hasReviewer {
			reviewer, ok := decision["reviewer"].(map[string]any)
			check(ok && len(reviewer) == 4)
			for _, key := range []string{"provider", "model"} {
				s, ok := reviewer[key].(string)
				check(ok && s != "" && utf8.RuneCountInString(s) <= 200 && s == pytext.Strip(s) && pytext.IsPrintable(s))
			}
			prompt, hasPrompt := reviewer["prompt_sha256"]
			schemaHash, hasSchema := reviewer["schema_sha256"]
			check(hasPrompt && hasSchema)
			hashes = append(hashes, prompt, schemaHash)
		}
		for _, h := range hashes {
			s, ok := h.(string)
			check(ok && hashRE.MatchString(s))
		}
		if reason, ok := decision["failure_reason"]; ok {
			check(bounded(reason))
		}
		if tags, ok := decision["tags"]; ok {
			want := []any{}
			if decision["disposition"] == any("llm-disputed") {
				want = []any{"llm-disputed"}
			}
			check(pytext.Canonical(tags) == pytext.Canonical(want))
		}
		proposal, hasProposal := decision["proposal"]
		check(hasProposal)
		if proposal != nil {
			check(hasReviewer && hasRequest && hasResponse)
			if err := responseSchema().Validate(proposal); err != nil {
				panic(err)
			}
			pm := proposal.(map[string]any)
			check(pm["candidate_id"] == any(cid) && decision["status"] == any("proposed") &&
				(pm["verdict"] != any("propose_false_positive") || pm["mechanism"] == any("not_supported") && pm["intent"] != any("malicious")))
		} else {
			check(decision["status"] != any("proposed"))
		}
		if original, _ := decision["reviewed_candidate_id"].(string); decision["reviewed_candidate_id"] != nil {
			prior := records[original]
			check(original != cid && prior != nil)
			_, priorReviewed := prior["reviewed_candidate_id"]
			check(!priorReviewed && proposal == nil &&
				pytext.Canonical(candidates[cid]["finding"]) == pytext.Canonical(candidates[original]["finding"]) &&
				decision["disposition"] == prior["disposition"])
			var hasPrior bool
			proposal, hasPrior = prior["proposal"]
			check(hasPrior)
			expected := prior["status"]
			if proposal != nil {
				expected = "duplicate-review"
			}
			check(decision["status"] == expected)
		} else {
			check(decision["status"] != any("duplicate-review"))
		}
		check(decision["disposition"] != any("llm-disputed") || proposal != nil)
	}
}

// Encode is encode_sarif: validate, then the canonical ASCII bytes plus a newline.
func Encode(document any) ([]byte, error) {
	if err := Validate(document); err != nil {
		return nil, err
	}
	data := []byte(pytext.Canonical(document) + "\n")
	if len(data) > maxReportBytes {
		return nil, errors.New("SARIF report exceeds 64 MiB; no partial report written")
	}
	return data, nil
}

// Resolve is Path.resolve(strict=False): the deepest existing prefix through its symlinks, with
// the rest appended lexically.
func Resolve(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rest := ""
	for {
		resolved, err := filepath.EvalSymlinks(path)
		if err == nil {
			return filepath.Join(resolved, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return filepath.Join(path, rest), nil
		}
		rest, path = filepath.Join(filepath.Base(path), rest), parent
	}
}

// IsWithinSource is is_within_source over resolved paths: lexically under root, or an existing
// ancestor with root's filesystem identity (case and Unicode aliases the lexical test misses).
func IsWithinSource(path, root string) bool {
	if rel, err := filepath.Rel(root, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		return false
	}
	for p := path; ; p = filepath.Dir(p) {
		if info, err := os.Stat(p); err == nil && os.SameFile(info, rootInfo) {
			return true
		}
		if filepath.Dir(p) == p {
			return false
		}
	}
}

// CheckTarget refuses a report path that is a symlink, lies inside any of the roots or names a
// special file, and returns it resolved. Write runs it over the scanned package; system-scan
// runs it over every discovered package before the first one is read, so a report inside a
// package is never scanned as part of it.
func CheckTarget(target string, roots ...string) (string, error) {
	if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("SARIF output must be outside the scanned package")
	}
	target, err := Resolve(target)
	if err != nil {
		return "", err
	}
	for _, root := range roots {
		root, err := Resolve(root)
		if err != nil {
			return "", err
		}
		if IsWithinSource(target, root) {
			return "", errors.New("SARIF output must be outside the scanned package")
		}
	}
	if info, err := os.Stat(target); err == nil && !info.Mode().IsRegular() {
		return "", errors.New("SARIF output must be a regular file")
	}
	if info, err := os.Stat(filepath.Dir(target)); err != nil || !info.IsDir() {
		return "", errors.New("SARIF output directory does not exist: " + filepath.Dir(target))
	}
	return target, nil
}

// Write is write_sarif: refuse a destination inside the scanned package, validate, then replace
// the target atomically through a temporary file in its directory.
func Write(document any, target, sourceRoot string) error {
	target, err := CheckTarget(target, sourceRoot)
	if err != nil {
		return err
	}
	data, err := Encode(document)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".skill-xray-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return rename(tmp.Name(), target)
}
