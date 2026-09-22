// Package scan runs every check over a parsed package (Python scan.py): Scan returns the
// deduplicated findings; Report also numbers the emitted candidates, builds the capability
// context, correlates and dispositions them and runs the opt-in LLM passes, each stage isolated
// so a failure is a visible context error and never a clean verdict.
package scan

import (
	"errors"
	"fmt"
	"slices"

	"github.com/traceforce/skill-xray/internal/capability"
	"github.com/traceforce/skill-xray/internal/checks"
	"github.com/traceforce/skill-xray/internal/correlate"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/llm"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// The names the oracle's tests monkeypatch on the scan module, as package vars.
var (
	RunChecks         = checks.Run
	adjudicate        = llm.Adjudicate
	BuildTriads       = capability.Build
	correlateFn       = correlate.Correlate
	applyDispositions = correlate.ApplyDispositions
	judgeCandidates   = llm.Judge
	// advisory is _advisory: the adjudication pass, whose failure becomes one low llm-error note
	// so the deterministic findings stand.
	advisory = func(p *parse.Package, s *llm.Session) (out []findings.Finding) {
		defer func() {
			if r := recover(); r != nil {
				out = []findings.Finding{{Rule: "llm-error", Severity: "low",
					Message: fmt.Sprintf("LLM adjudication pass failed (%T); deterministic findings stand", r)}}
			}
		}()
		return adjudicate(p, s, 25) // adjudicate._MAX_FILES
	}
)

// Scan is scan(): every deterministic finding plus, when a client is configured, the advisory
// LLM pass, deduplicated and severity-ordered.
func Scan(p *parse.Package, client llm.Completer, opengrepExe string) []findings.Finding {
	fs := RunChecks(p, opengrepExe, nil)
	if client != nil {
		s, _ := llm.NewSession(client, 25, 1<<20) // fixed non-negative budgets never fail
		fs = slices.Concat(fs, advisory(p, s))
	}
	return findings.Dedupe(fs)
}

// Options are scan_report's keyword arguments.
type Options struct {
	Client            llm.Completer
	LLMShadow         bool
	LLMReview         bool
	LLMApply          bool           // requires LLMReview
	LLMAdditive       bool           // run the advisory pass even under review (--llm-additive)
	OpengrepExe       string         // "" resolves the pinned binary
	DispositionPolicy map[string]any // nil is no policy
}

// ScanReport is the enrichment report; candidate ids are scan-local, not baseline identities.
type ScanReport struct {
	Findings      []findings.Finding
	RawCandidates []correlate.Candidate
	Triads        map[string]*capability.Triad
	Shadow        []llm.Decision
	LLMUsage      map[string]any
	ContextErrors []string
	Dispositions  []llm.Decision
	ReviewMode    bool
	Correlation   *correlate.Correlation
}

// ToMap is to_dict: the generic, deep-copied JSON view with integral numbers as int (D7).
func (r *ScanReport) ToMap() map[string]any {
	doc := map[string]any{"schema_version": "context-shadow-v1", "findings": r.Findings,
		"raw_scope":      "emitted-check-results-before-reporting-deduplication",
		"raw_candidates": r.RawCandidates, "triads": r.Triads, "shadow": r.Shadow,
		"llm_usage": r.LLMUsage, "context_errors": r.ContextErrors, "correlation": r.Correlation}
	if r.ReviewMode {
		doc["review_mode"], doc["dispositions"], doc["final_findings"] = "annotated", r.Dispositions, r.Findings
	}
	return pytext.JSONView(doc).(map[string]any)
}

// attempt runs fn and names its failure as Python names the exception class: the dynamic type
// of a recovered panic, or "ValueError" for a returned error (the correlate functions return
// only their policy and candidate-identity ValueErrors). "" is success.
func attempt(fn func() error) (name string) {
	defer func() {
		if r := recover(); r != nil {
			name = fmt.Sprintf("%T", r)
		}
	}()
	if fn() != nil {
		return "ValueError"
	}
	return ""
}

// Report is scan_report. The error is one of its three argument ValueErrors.
func Report(p *parse.Package, o Options) (*ScanReport, error) {
	if o.LLMShadow && o.LLMReview {
		return nil, errors.New("Choose shadow or annotated LLM review, not both")
	}
	if o.LLMApply && !o.LLMReview {
		return nil, errors.New("LLM-applied demotion requires annotated LLM review")
	}
	reviewEnabled := o.LLMShadow || o.LLMReview
	if reviewEnabled && o.Client == nil {
		return nil, errors.New("LLM review requires an explicitly supplied client")
	}
	llmAdvisory := o.LLMAdditive || !reviewEnabled
	var session *llm.Session
	if o.Client != nil {
		session, _ = llm.NewSession(o.Client, 25, 1<<20) // fixed non-negative budgets never fail
	}
	observations := []map[string]any{}
	raw := RunChecks(p, o.OpengrepExe, &observations)
	candidates := correlate.Candidates(raw)
	errs := []string{}
	triads := map[string]*capability.Triad{}
	if name := attempt(func() error { triads = BuildTriads(p, observations, raw); return nil }); name != "" {
		errs = append(errs, "capability-context-error: "+name)
	}
	shadow, dispositions := []llm.Decision{}, []llm.Decision{}
	if reviewEnabled {
		var decisions []llm.Decision
		name := attempt(func() error {
			decisions = judgeCandidates(p, candidates, triads, session, o.LLMReview)
			if len(decisions) != len(candidates) {
				return errors.New("Review candidate identity mismatch")
			}
			for i, d := range decisions {
				if d.CandidateID != candidates[i].CandidateID {
					return errors.New("Review candidate identity mismatch")
				}
			}
			return nil
		})
		if name != "" {
			kind, version := "shadow", llm.ShadowPolicyVersion
			if o.LLMReview {
				kind, version = "llm", llm.ReviewPolicyVersion
			}
			errs = append(errs, kind+"-review-error: "+name)
			decisions = make([]llm.Decision, len(candidates))
			for i, c := range candidates {
				decisions[i] = llm.Decision{CandidateID: c.CandidateID, Disposition: "reported", Status: "error",
					Reason: "Review failed; retained", PolicyVersion: version, Provenance: "deterministic-policy"}
			}
		}
		if o.LLMReview {
			dispositions = decisions // model opinions never change finding membership or severity
		} else {
			shadow = decisions
		}
	}
	supplemental := []findings.Finding{}
	if session != nil && llmAdvisory {
		supplemental = advisory(p, session)
	}
	usage := map[string]any{}
	if session != nil {
		usage = session.Usage()
		usage["advisory_enabled"], usage["judge_enabled"], usage["apply_enabled"] = llmAdvisory, reviewEnabled, o.LLMApply
	}
	reportCandidates := slices.Clone(candidates)
	for i, f := range supplemental {
		c := correlate.Candidate{CandidateID: fmt.Sprintf("advisory-%06d", i), Analyzer: "llm",
			Provenance: "advisory-output", Coverage: "no-reported-gap"}
		c.Finding = pytext.DeepCopy(f.ToMap()).(map[string]any)
		if f.Vector == "" {
			c.Coverage = "incomplete"
		}
		reportCandidates = append(reportCandidates, c)
	}
	var correlation *correlate.Correlation
	if name := attempt(func() (err error) { correlation, err = correlateFn(p, reportCandidates); return err }); name != "" {
		errs = append(errs, "correlation-error: "+name)
		correlation = &correlate.Correlation{RawCandidates: reportCandidates, Results: []*correlate.Result{},
			Links: []correlate.Link{}, Errors: []string{errs[len(errs)-1]}}
	} else {
		name := attempt(func() error {
			final, err := applyDispositions(p, correlation, triads, o.DispositionPolicy, errs)
			if err != nil {
				errs = append(errs, "disposition-policy-error: ValueError")
				if final, err = applyDispositions(p, correlation, triads, nil, errs); err != nil {
					return err
				}
			}
			correlation = final
			if o.LLMApply {
				reviews := make([]correlate.Review, len(dispositions))
				for i, d := range dispositions {
					reviews[i] = correlate.Review{CandidateID: d.CandidateID, Disposition: d.Disposition, Status: d.Status, Reason: d.Reason}
				}
				correlation = correlate.ApplyLLMReview(correlation, reviews)
			}
			return nil
		})
		if name != "" {
			errs = append(errs, "disposition-error: "+name)
			correlation.Errors = []string{errs[len(errs)-1]}
		}
	}
	return &ScanReport{Findings: findings.Dedupe(slices.Concat(raw, supplemental)), RawCandidates: candidates,
		Triads: triads, Shadow: shadow, LLMUsage: usage, ContextErrors: errs, Dispositions: dispositions,
		ReviewMode: o.LLMReview, Correlation: correlation}, nil
}
