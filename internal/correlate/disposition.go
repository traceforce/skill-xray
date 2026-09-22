package correlate

import (
	"cmp"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/capability"
	"github.com/traceforce/skill-xray/internal/checks"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

const (
	PolicyVersion   = "skill-xray/scoped-policy/v1"
	LLMApplyVersion = "skill-xray/llm-apply/v1"
)

// LLMApplyVectors are the text-pattern directive vectors the review contracts cover; every
// mechanically anchored vector is never model-adjustable.
var LLMApplyVectors = map[string]bool{"SXV-028": true, "SXV-029": true, "SXV-030": true, "SXV-031": true}

// scope is (rule_id, path, fingerprint, context_digest): paths are exact IR identities.
type scope [4]string

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}\z`)

// policyEntries validates the whole operator policy before any decision applies.
func policyEntries(policy map[string]any) (map[scope]map[string]string, error) {
	if policy == nil {
		return nil, nil
	}
	decisions, ok := policy["decisions"].([]any)
	if len(policy) != 2 || policy["version"] != any(PolicyVersion) || !ok || len(decisions) > 512 {
		return nil, errors.New("Invalid operator policy")
	}
	entries := map[scope]map[string]string{}
	for _, item := range decisions {
		entry, isMap := item.(map[string]any)
		required := map[string]bool{"rule_id": true, "path": true, "fingerprint": true, "context_digest": true,
			"action": true, "reason": true}
		if isMap && entry["action"] == any("demote") {
			required["effective_severity"] = true
		}
		values, valid := map[string]string{}, isMap && len(entry) == len(required)
		for k, v := range entry {
			s, isStr := v.(string)
			if !required[k] || !isStr || pytext.Strip(s) == "" {
				valid = false
				break
			}
			values[k] = s
		}
		if !valid || values["action"] != "suppress" && values["action"] != "demote" ||
			utf8.RuneCountInString(values["reason"]) > 1024 ||
			!hexDigest.MatchString(values["fingerprint"]) || !hexDigest.MatchString(values["context_digest"]) ||
			strings.HasPrefix(values["path"], "/") || slices.Contains(strings.Split(values["path"], "/"), "..") ||
			findings.Rank(cmp.Or(values["effective_severity"], "low"), -1) < 0 {
			return nil, errors.New("Invalid operator policy decision")
		}
		key := scope{values["rule_id"], values["path"], values["fingerprint"], values["context_digest"]}
		if _, dup := entries[key]; dup {
			return nil, errors.New("Duplicate operator policy scope")
		}
		entries[key] = values
	}
	return entries, nil
}

// sourceKnown is true when the result's position is provable against a cleanly parsed artifact.
func sourceKnown(r *Result, p *parse.Package) bool {
	finding := r.Finding
	a := p.ByRel[str(finding, "path")]
	if a == nil || len(a.Diagnostics) > 0 {
		return false
	}
	if offset := finding["offset"]; offset != nil {
		o, okO := offset.(int)
		l, okL := finding["length"].(int)
		return a.Raw != nil && okO && o >= 0 && okL && l > 0 && o+l <= len(a.Raw)
	}
	var lines []string
	if a.Text != nil {
		lines = strings.Split(*a.Text, "\n")
	}
	line, ok := finding["line"].(int)
	if !ok || line < 1 || line > len(lines) {
		return false
	}
	start := map[string]any{"line": line, "col": 1}
	if column := finding["column"]; column != nil {
		start["col"] = column
	}
	ev, _ := finding["evidence"].(map[string]any)
	end := start
	if v, present := ev["end"]; present {
		end, _ = v.(map[string]any)
	}
	_, _, _, err := SourceRegion(a, start, end, ev["engine"] == any("opengrep"), lines)
	return err == nil
}

// materialLedgerEntry is a coverage gap that may hide cross-file context: anything outside the
// static phase, and any static skip that is neither benign nor an opaque asset.
func materialLedgerEntry(e ingest.LedgerEntry, p *parse.Package) bool {
	if cmp.Or(e.Phase, "static") != "static" {
		return true
	}
	reason, kind := cmp.Or(e.ReasonCode, "unknown"), ""
	if a := p.ByRel[e.Path]; a != nil {
		kind = a.Kind
	}
	return !ingest.BenignLedger[reason] && checks.StaticSeverity(reason, kind, e.Path) != ""
}

// triadMap is asdict(triad) with the evidence sorted by canonical form; a deep copy.
func triadMap(t *capability.Triad) map[string]any {
	evidence, _ := pytext.DeepCopy(t.Evidence).([]map[string]any)
	if evidence == nil {
		evidence = []map[string]any{}
	}
	slices.SortFunc(evidence, func(a, b map[string]any) int {
		return cmp.Compare(pytext.Canonical(a), pytext.Canonical(b))
	})
	var manifest any
	if t.Manifest != nil {
		manifest = *t.Manifest
	}
	return map[string]any{"manifest": manifest, "claimed": maps.Clone(t.Claimed), "declared": maps.Clone(t.Declared),
		"observed": maps.Clone(t.Observed), "evidence": evidence, "limitations": append([]string{}, t.Limitations...)}
}

// clone copies what the disposition phase rewrites (results, links); raw candidates, finding
// documents and evidence are shared, as no phase edits them.
func (c *Correlation) clone() *Correlation {
	out := *c
	out.Results = make([]*Result, len(c.Results))
	for i, r := range c.Results {
		copied := *r
		out.Results[i] = &copied
	}
	out.Links = slices.Clone(c.Links)
	return &out
}

// ApplyDispositions retains every result by default; only an exact operator scope may suppress
// or lower severity, and never while the package context is incomplete or the evidence is
// operational. Every result stays in the audit list. The error is the policy ValueError.
func ApplyDispositions(p *parse.Package, c *Correlation, triads map[string]*capability.Triad, policy map[string]any, contextErrors []string) (*Correlation, error) {
	entries, err := policyEntries(policy)
	if err != nil {
		return nil, err
	}
	final := c.clone()
	contexts, limits := map[string]map[string]any{}, []ContextLimit{}
	for _, key := range slices.Sorted(maps.Keys(triads)) {
		contexts[key] = triadMap(triads[key])
		if t := triads[key]; len(t.Limitations) > 0 {
			limits = append(limits, ContextLimit{key, slices.Sorted(slices.Values(t.Limitations))})
		}
	}
	packageGap := len(contextErrors) > 0 || len(limits) > 0 ||
		slices.ContainsFunc(p.LedgerExceptions, func(e ingest.LedgerEntry) bool { return materialLedgerEntry(e, p) }) ||
		slices.ContainsFunc(final.RawCandidates, func(c Candidate) bool {
			return (str(c.Finding, "vector") == "" || c.Coverage != "no-reported-gap") && !isInventoryNote(c.Finding)
		})
	byID := map[string]*Result{}
	for _, r := range final.Results {
		finding, manifestKey := r.Finding, ""
		if r.Manifest != nil {
			manifestKey = *r.Manifest
		}
		context, hasContext := contexts[manifestKey]
		incomplete := packageGap || r.Manifest == nil || !hasContext || len(context["limitations"].([]string)) > 0 ||
			!isInventoryNote(finding) && (len(r.Limitations) > 0 || !sourceKnown(r, p))
		protected := str(finding, "vector") == "" || slices.ContainsFunc(r.Provenance, func(pr Provenance) bool {
			return pr.Provenance != "deterministic-check-output"
		})
		severity := str(finding, "severity")
		d := &Decision{Disposition: "reported", DecisionReason: "Original deterministic evidence retained",
			DecisionProvenance: "deterministic-policy", PolicyVersion: PolicyVersion,
			OriginalSeverity: severity, EffectiveSeverity: severity, Coverage: "no-reported-gap"}
		entry := entries[scope{r.RuleID, str(finding, "path"), r.Fingerprint, r.ContextDigest}]
		switch {
		case incomplete || protected:
			d.DecisionReason = "Incomplete context or protected operational evidence; retained"
		case entry != nil:
			if entry["action"] == "suppress" {
				d.Disposition = "suppressed"
			} else if findings.SeverityRank[entry["effective_severity"]] > findings.Rank(severity, 99) {
				d.Disposition, d.EffectiveSeverity = "corrected", entry["effective_severity"]
			}
			if d.Disposition != "reported" {
				d.DecisionReason, d.DecisionProvenance = entry["reason"], "operator-policy"
			} else {
				d.DecisionReason = "Policy cannot raise severity or make a no-op correction; retained"
			}
		}
		if hasContext {
			d.CapabilityContext = triadMap(triads[manifestKey])
			delete(d.CapabilityContext, "evidence")
		}
		if incomplete {
			d.Coverage = "incomplete"
		}
		r.Decision = d
		byID[r.ID] = r
	}
	for i := range final.Links {
		link := &final.Links[i]
		r := byID[link.ResultID]
		if link.Disposition != "duplicate" {
			link.Disposition, link.Reason = r.Disposition, r.DecisionReason
		}
		link.LinkDecision = &LinkDecision{PolicyVersion: PolicyVersion, Provenance: r.DecisionProvenance}
		if link.Disposition == "duplicate" {
			link.Provenance = "deterministic-correlation"
		}
	}
	final.Applied = &Applied{CapabilityContexts: contexts, Coverage: "no-reported-gap", ContextLimitations: limits,
		ExecutionSuccessful: len(contextErrors) == 0 && !slices.ContainsFunc(final.RawCandidates, func(c Candidate) bool {
			sev := str(c.Finding, "severity")
			return str(c.Finding, "vector") == "" && (sev == "critical" || sev == "high")
		})}
	if packageGap || slices.ContainsFunc(final.Results, func(r *Result) bool { return r.Coverage == "incomplete" }) {
		final.Coverage = "incomplete"
	}
	return final, nil
}

// Review is what ApplyLLMReview reads of an llm.Decision (candidate_id, disposition, status,
// reason); llm imports this package, so the full type cannot be named here.
type Review struct {
	CandidateID, Disposition, Status, Reason string
}

// ApplyLLMReview demotes to "low" the one text-pattern result a validated "llm-disputed" review
// covers, in place: never a result the deterministic policy protected, never a suppression,
// never a raise. The result stays in the audit as "corrected" with "llm-review-policy".
func ApplyLLMReview(c *Correlation, decisions []Review) *Correlation {
	disputed := map[string]Review{}
	for _, d := range decisions {
		if d.Disposition == "llm-disputed" && d.Status == "proposed" {
			disputed[d.CandidateID] = d
		}
	}
	results := map[string]*Result{}
	for _, r := range c.Results {
		results[r.ID] = r
	}
	applied := 0
	for _, link := range c.Links {
		decision, ok := disputed[link.CandidateID]
		r := results[link.ResultID]
		if !ok || r == nil || r.LLMApplied {
			continue
		}
		if r.Disposition != "reported" || r.Coverage != "no-reported-gap" || !LLMApplyVectors[str(r.Finding, "vector")] ||
			slices.ContainsFunc(r.Provenance, func(p Provenance) bool {
				return p.Provenance != "deterministic-check-output" || p.Analyzer == "opengrep"
			}) || findings.SeverityRank["low"] <= findings.Rank(str(r.Finding, "severity"), 99) {
			continue
		}
		r.Disposition, r.EffectiveSeverity = "corrected", "low"
		r.DecisionReason = cmp.Or(decision.Reason, "LLM review disputed the finding")
		r.DecisionProvenance, r.PolicyVersion = "llm-review-policy", LLMApplyVersion
		r.LLMApplied, r.LLMCandidateID = true, link.CandidateID
		applied++
	}
	for i := range c.Links {
		link := &c.Links[i]
		if r := results[link.ResultID]; link.Disposition != "duplicate" && r.LLMApplied {
			link.Disposition, link.Reason = "corrected", r.DecisionReason
			link.LinkDecision = &LinkDecision{PolicyVersion: LLMApplyVersion, Provenance: "llm-review-policy"}
		}
	}
	c.LLMApplied = &applied
	return c
}
