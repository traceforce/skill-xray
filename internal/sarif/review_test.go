package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/capability"
	"github.com/traceforce/skill-xray/internal/correlate"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/llm"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/scan"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// Fixtures are tests/test_llm_review.py::ANCHOR, BODY, Reviewer, fixture, finding, run.
const anchor, body = testutil.Anchor, testutil.Body

// reviewer disputes every candidate it is shown (per-field overrides in change), or answers a
// scripted reply, or fails; every reply it returned is kept for the provenance assertions.
type reviewer struct {
	change   map[string]any
	scripted *string
	err      error
	calls    int
	replies  []string
}

func (*reviewer) Identity() (provider, model string) { return "fixture", "fixture-1" }

func (r *reviewer) Complete(_, user string) (string, error) {
	r.calls++
	if r.err != nil {
		return "", r.err
	}
	var reply string
	if r.scripted != nil {
		reply = *r.scripted
	} else {
		var request map[string]any
		if err := json.Unmarshal([]byte(user), &request); err != nil {
			return "", err
		}
		candidate, ok := request["candidate"].(map[string]any)
		if !ok {
			return `{"prompt_injection": false}`, nil
		}
		fields := map[string]any{"candidate_id": candidate["candidate_id"], "verdict": "propose_false_positive",
			"confidence": "high", "mechanism": "not_supported", "intent": "legitimate",
			"reason": "The quoted archive record is not a live directive",
			"impact": "No instruction to override agent behavior", "evidence_quote": strings.TrimSpace(body)}
		for k, v := range r.change {
			fields[k] = v
		}
		out, err := json.Marshal(fields)
		if err != nil {
			return "", err
		}
		reply = string(out)
	}
	r.replies = append(r.replies, reply)
	return reply, nil
}

func scripted(reply string) *reviewer { return &reviewer{scripted: &reply} }

func transportError() error { return &llm.Error{Kind: llm.Transport} }

func fixture(t *testing.T, text string) *parse.Package {
	return parsePkg(t, map[string]string{"SKILL.md": "---\nname: demo\n---\n" + text})
}

func finding(mods ...mod) findings.Finding {
	f := testutil.Directive()
	for _, m := range mods {
		m(&f)
	}
	return f
}

// review is scan_report over fixed raw findings with an LLM review lane, wired through the same
// landed pieces scan.Report uses (its checks seam is unexported): Candidates, capability.Build,
// llm.Judge, Correlate, ApplyDispositions and, with apply, ApplyLLMReview. failJudge is the
// monkeypatched judge_candidates raising ValueError; advisory is a monkeypatched _advisory pass.
type review struct {
	mode      string // "annotated" or "shadow"
	apply     bool
	maxCalls  int
	client    *reviewer
	failJudge bool
	advisory  []findings.Finding
}

func (o review) report(t *testing.T, p *parse.Package, raw []findings.Finding) *scan.ScanReport {
	t.Helper()
	if o.client == nil {
		o.client = &reviewer{}
	}
	if o.maxCalls == 0 {
		o.maxCalls = 25
	} else if o.maxCalls < 0 {
		o.maxCalls = 0
	}
	annotated := o.mode != "shadow"
	candidates := correlate.Candidates(raw)
	triads := capability.Build(p, nil, raw)
	session, err := llm.NewSession(o.client, o.maxCalls, 1<<20)
	require.NoError(t, err)
	errs := []string{}
	var decisions []llm.Decision
	if o.failJudge {
		kind, version := "shadow", llm.ShadowPolicyVersion
		if annotated {
			kind, version = "llm", llm.ReviewPolicyVersion
		}
		errs = append(errs, kind+"-review-error: ValueError")
		for _, c := range candidates {
			decisions = append(decisions, llm.Decision{CandidateID: c.CandidateID, Disposition: "reported", Status: "error",
				Reason: "Review failed; retained", PolicyVersion: version, Provenance: "deterministic-policy"})
		}
	} else {
		decisions = llm.Judge(p, candidates, triads, session, annotated)
	}
	all := append([]correlate.Candidate{}, candidates...)
	for i, f := range o.advisory {
		all = append(all, correlate.Candidate{CandidateID: fmt.Sprintf("advisory-%06d", i), Finding: f.ToMap(),
			Analyzer: "llm", Provenance: "advisory-output", Coverage: "no-reported-gap"})
	}
	c, err := correlate.Correlate(p, all)
	require.NoError(t, err)
	c, err = correlate.ApplyDispositions(p, c, triads, nil, errs)
	require.NoError(t, err)
	if o.apply {
		reviews := []correlate.Review{}
		for _, d := range decisions {
			reviews = append(reviews, correlate.Review{CandidateID: d.CandidateID, Disposition: d.Disposition, Status: d.Status, Reason: d.Reason})
		}
		c = correlate.ApplyLLMReview(c, reviews)
	}
	usage := session.Usage()
	usage["advisory_enabled"], usage["judge_enabled"], usage["apply_enabled"] = len(o.advisory) > 0, true, o.apply
	r := &scan.ScanReport{Findings: findings.Dedupe(append(append([]findings.Finding{}, raw...), o.advisory...)),
		RawCandidates: candidates, Triads: triads, Shadow: []llm.Decision{}, Dispositions: []llm.Decision{},
		LLMUsage: usage, ContextErrors: errs, ReviewMode: annotated, Correlation: c}
	if annotated {
		r.Dispositions = decisions
	} else {
		r.Shadow = decisions
	}
	return r
}

// document is test_llm_sarif.document: the annotated report over one directive and its SARIF.
func document(t *testing.T, o review, raw ...findings.Finding) (*scan.ScanReport, map[string]any) {
	t.Helper()
	if raw == nil {
		raw = []findings.Finding{finding()}
	}
	p := fixture(t, body)
	report := o.report(t, p, raw)
	return report, build(t, p, report)
}

func audit(doc map[string]any) map[string]any { return m(runProps(doc)["llmReview"]) }
func decisions(doc map[string]any) []any      { return l(audit(doc)["decisions"]) }
func decision(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	require.Len(t, decisions(doc), 1)
	return m(decisions(doc)[0])
}
func modes() []string { return []string{"annotated", "shadow"} }

// test_llm_sarif.py::test_compact_audit_survives_written_sarif
func TestCompactAuditSurvivesWrittenSARIF(t *testing.T) {
	p := fixture(t, body)
	report := review{}.report(t, p, []findings.Finding{finding()})
	before := canon(report.ToMap())
	data := build(t, p, report)
	target := filepath.Join(filepath.Dir(p.Identity), "review.sarif")
	require.NoError(t, Write(data, target, p.Identity))
	raw, err := os.ReadFile(target)
	require.NoError(t, err)
	written := loads(t, raw)
	require.NoError(t, Validate(written))
	a := audit(written)
	assert.Equal(t, "annotated", a["mode"])
	assert.Equal(t, false, a["authoritative"])
	d := decision(t, written)
	result := only(t, written)
	assert.Equal(t, l(props(result)["candidateIds"])[0], d["candidate_id"])
	assert.Equal(t, d["candidate_id"], m(d["proposal"])["candidate_id"])
	assert.Equal(t, "llm-disputed", d["disposition"])
	assert.Equal(t, "high", m(d["proposal"])["confidence"])
	assert.Equal(t, strings.TrimSpace(body), m(d["proposal"])["evidence_quote"])
	assert.Equal(t, "fixture-1", m(d["reviewer"])["model"])
	assert.Equal(t, report.Dispositions[0].RequestSHA256, d["request_sha256"])
	assert.Equal(t, report.Dispositions[0].ResponseSHA256, d["response_sha256"])
	assert.NotEmpty(t, d["policy_version"])
	assert.NotEmpty(t, d["reason"])
	assert.NotEmpty(t, d["provenance"])
	assert.NotContains(t, d, "request")
	assert.NotContains(t, d, "source")
	assert.Equal(t, "reported", props(result)["disposition"])
	assert.NotContains(t, result, "suppressions")
	assert.Equal(t, "high", props(result)["originalSeverity"])
	assert.Equal(t, "high", props(result)["effectiveSeverity"])
	assert.Equal(t, before, canon(report.ToMap()))
	assert.Equal(t, encode(t, build(t, p, report)), raw)
}

// test_llm_sarif.py::test_serializer_does_not_rederive_judge_dispute_threshold (2 rows)
func TestSerializerDoesNotRederiveJudgeDisputeThreshold(t *testing.T) {
	for _, context := range []map[string]any{{"confidence": "medium"}, {"intent": "unknown"}} {
		_, data := document(t, review{})
		for k, v := range context {
			m(decision(t, data)["proposal"])[k] = v
		}
		require.NoError(t, Validate(data))
		result := only(t, data)
		assert.Equal(t, "reported", props(result)["disposition"])
		assert.Equal(t, props(result)["originalSeverity"], props(result)["effectiveSeverity"])
		assert.NotContains(t, result, "suppressions")
	}
}

// test_llm_sarif.py::test_dispute_requires_an_actual_review_proposal (2 rows)
func TestDisputeRequiresAnActualReviewProposal(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		raw := []findings.Finding{finding()}
		if duplicate {
			raw = append(raw, finding())
		}
		_, data := document(t, review{maxCalls: -1}, raw...)
		for _, d := range decisions(data) {
			assert.Nil(t, m(d)["proposal"])
			m(d)["disposition"], m(d)["tags"] = "llm-disputed", []any{"llm-disputed"}
		}
		assert.ErrorContains(t, Validate(data), "SARIF validation failed")
	}
}

// test_llm_sarif.py::test_duplicate_reviews_use_stable_links
func TestDuplicateReviewsUseStableLinks(t *testing.T) {
	client := &reviewer{}
	_, data := document(t, review{client: client}, finding(), finding())
	var first, duplicate map[string]any
	for _, d := range decisions(data) {
		if m(d)["status"] == "duplicate-review" {
			duplicate = m(d)
		} else {
			first = m(d)
		}
	}
	assert.Equal(t, 1, client.calls)
	result := only(t, data)
	assert.Equal(t, first["candidate_id"], duplicate["reviewed_candidate_id"])
	assert.Nil(t, duplicate["proposal"])
	assert.NotNil(t, first["proposal"])
	assert.ElementsMatch(t, []any{first["candidate_id"], duplicate["candidate_id"]}, l(props(result)["candidateIds"]))
	require.NoError(t, Validate(data))
}

// test_llm_sarif.py::test_judge_fail_safe_results_reach_sarif (5 rows)
func TestJudgeFailSafeResultsReachSARIF(t *testing.T) {
	for _, c := range []struct {
		change map[string]any
		status string
	}{
		{map[string]any{"verdict": "retain_finding", "mechanism": "supported"}, "proposed"},
		{map[string]any{"verdict": "insufficient_context", "mechanism": "unknown"}, "proposed"},
		{map[string]any{"candidate_id": "wrong"}, "invalid-response"},
		{map[string]any{"evidence_quote": "invented quote"}, "invalid-response"},
		{map[string]any{"confidence": "certain"}, "invalid-response"},
	} {
		_, data := document(t, review{client: &reviewer{change: c.change}})
		d := decision(t, data)
		assert.Equal(t, c.status, d["status"], canon(c.change))
		assert.Equal(t, "reported", d["disposition"])
		assert.Equal(t, "error", only(t, data)["level"])
		assert.NotContains(t, only(t, data), "suppressions")
		require.NoError(t, Validate(data))
	}
}

// test_llm_sarif.py::test_unreviewed_is_visible_not_a_clean_verdict (4 rows)
func TestUnreviewedIsVisibleNotACleanVerdict(t *testing.T) {
	for _, c := range []struct {
		options review
		text    string
		status  string
	}{
		{review{maxCalls: -1}, body, "budget"},
		{review{client: &reviewer{err: transportError()}}, body, "unavailable"},
		{review{}, body + strings.Repeat("x", 6100), "incomplete-context"},
		{review{}, body + "\n[external](https://example.invalid)", "incomplete-context"},
	} {
		p := fixture(t, c.text)
		data := build(t, p, c.options.report(t, p, []findings.Finding{finding()}))
		d := decision(t, data)
		assert.Equal(t, c.status, d["status"])
		assert.Nil(t, d["proposal"])
		assert.Equal(t, "reported", d["disposition"])
		require.NoError(t, Validate(data))
	}
}

// test_llm_sarif.py::test_error_and_mechanical_candidates_cannot_be_disputed
func TestErrorAndMechanicalCandidatesCannotBeDisputed(t *testing.T) {
	client := &reviewer{}
	_, data := document(t, review{client: client}, finding(ev(map[string]any{"engine": "opengrep"})),
		findings.Finding{Rule: "check-error", Severity: "high", Path: "SKILL.md", Message: "failed"})
	assert.Zero(t, client.calls)
	require.Len(t, decisions(data), 2)
	for _, d := range decisions(data) {
		assert.Equal(t, "ineligible", m(d)["status"])
		assert.Equal(t, "reported", m(d)["disposition"])
	}
	assert.Equal(t, false, m(l(run(data)["invocations"])[0])["executionSuccessful"])
	require.NoError(t, Validate(data))
}

// test_llm_sarif.py::test_empty_review_and_disabled_output (3 rows)
func TestEmptyReviewAndDisabledOutput(t *testing.T) {
	p := fixture(t, body)
	for _, mode := range []string{"off", "annotated", "shadow"} {
		var report *scan.ScanReport
		if mode == "off" {
			report = reportFor(t, p, candidates(), nil)
		} else {
			report = review{mode: mode}.report(t, p, []findings.Finding{})
		}
		data := build(t, p, report)
		if mode == "off" {
			assert.NotContains(t, runProps(data), "llmReview")
		} else {
			assert.Equal(t, map[string]any{"mode": mode, "authoritative": false, "decisions": []any{}}, runProps(data)["llmReview"])
		}
		require.NoError(t, Validate(data))
	}
}

// test_llm_sarif.py::test_shadow_proposal_remains_distinct
func TestShadowProposalRemainsDistinct(t *testing.T) {
	_, data := document(t, review{mode: "shadow"})
	a := audit(data)
	assert.Equal(t, "shadow", a["mode"])
	assert.Equal(t, false, a["authoritative"])
	assert.Equal(t, "propose_false_positive", m(decision(t, data)["proposal"])["verdict"])
	assert.Equal(t, "reported", decision(t, data)["disposition"])
	require.NoError(t, Validate(data))
}

// test_llm_sarif.py::test_redaction_bounds_preserve_report (2 x 2 x 3 rows)
func TestRedactionBoundsPreserveReport(t *testing.T) {
	for _, mode := range modes() {
		for _, field := range []string{"reason", "impact"} {
			for padding, valid := range map[int]bool{181: true, 182: false, 190: false} {
				raw := []findings.Finding{finding()}
				client := &reviewer{change: map[string]any{field: strings.Repeat("A", padding) + " api_key=a"}}
				p := fixture(t, body)
				report := review{mode: mode, client: client}.report(t, p, raw)
				ds := report.Dispositions
				if mode == "shadow" {
					ds = report.Shadow
				}
				require.Len(t, ds, 1)
				d := ds[0]
				assert.Equal(t, 1, client.calls)
				if valid {
					assert.Equal(t, "proposed", d.Status)
					value := map[string]string{"reason": d.Proposal.Reason, "impact": d.Proposal.Impact}[field]
					assert.Len(t, []rune(value), 200)
					assert.True(t, strings.HasSuffix(value, "api_key=[REDACTED]"))
				} else {
					assert.Equal(t, "invalid-response", d.Status)
					assert.Nil(t, d.Proposal)
					assert.Equal(t, "reported", d.Disposition)
					assert.Equal(t, "field-bounds", d.FailureReason)
				}
				data := loads(t, encode(t, build(t, p, report)))
				result := only(t, data)
				assert.Equal(t, "reported", props(result)["disposition"])
				assert.Equal(t, "high", props(result)["effectiveSeverity"])
				assert.Equal(t, raw, report.Findings)
				assert.Equal(t, canon(raw[0].ToMap()), canon(report.RawCandidates[0].Finding))
			}
		}
	}
}

// test_llm_sarif.py::test_malformed_or_truncated_response_is_retained (4 rows)
func TestMalformedOrTruncatedResponseIsRetained(t *testing.T) {
	for _, reply := range []string{"{", "[]", "{}", strings.Repeat("x", 16385)} {
		_, data := document(t, review{client: scripted(reply)})
		d := decision(t, data)
		assert.Equal(t, "invalid-response", d["status"])
		assert.Nil(t, d["proposal"])
		assert.Equal(t, "reported", props(only(t, data))["disposition"])
		require.NoError(t, Validate(data))
	}
}

// test_llm_sarif.py::test_review_failure_and_additive_output_remain_separate
func TestReviewFailureAndAdditiveOutputRemainSeparate(t *testing.T) {
	advisory := findings.Finding{Vector: "SXV-038", Rule: "semantic-prompt-injection", Severity: "medium", Path: "SKILL.md", Message: "advisory"}
	_, data := document(t, review{failJudge: true, advisory: []findings.Finding{advisory}})
	assert.Len(t, results(data), 2)
	assert.Len(t, l(runProps(data)["rawCandidates"]), 2)
	d := decision(t, data)
	assert.Equal(t, "error", d["status"])
	assert.Nil(t, d["proposal"])
	assert.Equal(t, []any{"llm-review-error: ValueError"}, runProps(data)["contextErrors"])
	require.NoError(t, Validate(data))
}

// test_llm_sarif.py::test_redaction_cannot_leak_whole_source_into_audit
func TestRedactionCannotLeakWholeSourceIntoAudit(t *testing.T) {
	client := &reviewer{}
	p := fixture(t, body+"\napi_key: \"a-sensitive-value\"\n")
	data := build(t, p, review{client: client}.report(t, p, []findings.Finding{finding()}))
	assert.Zero(t, client.calls)
	assert.Equal(t, "incomplete-context", decision(t, data)["status"])
	assert.NotContains(t, canon(audit(data)), "a-sensitive-value")
	require.NoError(t, Validate(data))
}

// test_llm_sarif.py::test_duplicate_review_cannot_reference_unrelated_evidence
func TestDuplicateReviewCannotReferenceUnrelatedEvidence(t *testing.T) {
	_, data := document(t, review{}, finding(), finding(message("different")))
	ds := decisions(data)
	require.Len(t, ds, 2)
	m(ds[1])["reviewed_candidate_id"], m(ds[1])["proposal"], m(ds[1])["status"] = m(ds[0])["candidate_id"], nil, "duplicate-review"
	assert.ErrorContains(t, Validate(data), "SARIF validation failed")
}

// test_llm_sarif.py::test_reused_review_preserves_original_outcome (3 rows)
func TestReusedReviewPreservesOriginalOutcome(t *testing.T) {
	for _, c := range []struct {
		priorFailed bool
		status      string
	}{{true, "duplicate-review"}, {false, "budget"}, {true, "error"}} {
		client := &reviewer{}
		if c.priorFailed {
			client.err = transportError()
		}
		_, data := document(t, review{client: client}, finding(), finding())
		require.NoError(t, Validate(data))
		for _, d := range decisions(data) {
			if _, ok := m(d)["reviewed_candidate_id"]; ok {
				m(d)["status"] = c.status
			}
		}
		assert.ErrorContains(t, Validate(data), "SARIF validation failed")
	}
}

// test_llm_sarif.py::test_returned_response_provenance_survives_even_invalid_json (2 x 2 rows)
func TestReturnedResponseProvenanceSurvivesEvenInvalidJSON(t *testing.T) {
	for _, mode := range modes() {
		for _, malformed := range []bool{false, true} {
			client := &reviewer{}
			if malformed {
				client = scripted("{")
			}
			p := fixture(t, body)
			data := build(t, p, review{mode: mode, client: client}.report(t, p, []findings.Finding{finding()}))
			d := decision(t, data)
			assert.Equal(t, "fixture-1", m(d["reviewer"])["model"])
			sum := sha256.Sum256([]byte(client.replies[0]))
			assert.Equal(t, hex.EncodeToString(sum[:]), d["response_sha256"])
			want := "proposed"
			if malformed {
				want = "invalid-response"
			}
			assert.Equal(t, want, d["status"])
			assert.NotContains(t, d, "response")
			require.NoError(t, Validate(data))
		}
	}
}

// test_llm_sarif.py::test_validation_rejects_broken_review_audit (23 rows)
func TestValidationRejectsBrokenReviewAudit(t *testing.T) {
	for _, mutation := range []string{"identity", "missing", "duplicate", "proposal-id", "duplicate-link", "authority",
		"disposition", "verdict", "confidence", "status", "missing-proposal", "shadow-dispute", "hidden-dispute",
		"audit-extra", "request-extra", "source-extra", "bad-hash", "reviewer-source", "reviewer-shape",
		"reviewer-model", "reviewer-hash", "failure-reason", "wrong-tags"} {
		t.Run(mutation, func(t *testing.T) {
			_, data := document(t, review{})
			a := audit(data)
			d := decision(t, data)
			leak := map[string]any{"source": "Whole input must not be exported"}
			switch mutation {
			case "identity":
				d["candidate_id"] = "unrelated"
			case "missing":
				a["decisions"] = []any{}
			case "duplicate":
				a["decisions"] = append(l(a["decisions"]), pytext.DeepCopy(d))
			case "proposal-id":
				m(d["proposal"])["candidate_id"] = "unrelated"
			case "duplicate-link":
				d["reviewed_candidate_id"] = d["candidate_id"]
			case "authority":
				a["authoritative"] = true
			case "disposition":
				d["disposition"] = "suppressed"
			case "verdict":
				m(d["proposal"])["verdict"] = "delete"
			case "confidence":
				m(d["proposal"])["confidence"] = 0.99
			case "missing-proposal":
				d["proposal"] = nil
			case "shadow-dispute":
				a["mode"] = "shadow"
			case "hidden-dispute":
				d["disposition"] = "reported"
			case "audit-extra":
				a["request"] = leak
			case "bad-hash":
				d["request_sha256"] = "not-a-hash"
			case "reviewer-source":
				m(d["reviewer"])["source"] = leak["source"]
			case "reviewer-shape":
				d["reviewer"] = []any{}
			case "reviewer-model":
				m(d["reviewer"])["model"] = leak
			case "reviewer-hash":
				m(d["reviewer"])["prompt_sha256"] = "not-a-hash"
			case "failure-reason":
				d["failure_reason"] = strings.Repeat("x", 201)
			case "wrong-tags":
				m(d["proposal"])["verdict"], m(d["proposal"])["mechanism"] = "retain_finding", "supported"
				d["disposition"] = "reported"
			case "request-extra", "source-extra":
				d[strings.TrimSuffix(mutation, "-extra")] = leak
			default:
				d["status"] = "approved"
			}
			assert.ErrorContains(t, Validate(data), "SARIF validation failed")
		})
	}
}

// test_llm_sarif.py::test_successful_review_requires_consistent_provenance (2 x 2 x 5 rows)
func TestSuccessfulReviewRequiresConsistentProvenance(t *testing.T) {
	for _, mode := range modes() {
		for _, verdict := range []string{"retain_finding", "insufficient_context"} {
			for _, mutation := range []string{"reviewer", "request_sha256", "response_sha256", "mode", "provenance"} {
				p := fixture(t, body)
				client := &reviewer{change: map[string]any{"verdict": verdict}}
				data := build(t, p, review{mode: mode, client: client}.report(t, p, []findings.Finding{finding(), finding()}))
				require.NoError(t, Validate(data))
				a := audit(data)
				var d map[string]any
				for _, x := range decisions(data) {
					if m(x)["status"] == "proposed" {
						d = m(x)
					}
				}
				require.NotNil(t, d)
				assert.Equal(t, "reported", d["disposition"])
				switch mutation {
				case "mode":
					a["mode"] = map[string]string{"annotated": "shadow", "shadow": "annotated"}[mode]
				case "provenance":
					d["provenance"] = "unknown-producer"
				default:
					delete(d, mutation)
				}
				assert.ErrorContains(t, Validate(data), "SARIF validation failed", mode+" "+verdict+" "+mutation)
			}
		}
	}
}

// test_llm_sarif.py::test_every_review_outcome_has_consistent_mode_and_policy (2 x 8 x 3 rows)
func TestEveryReviewOutcomeHasConsistentModeAndPolicy(t *testing.T) {
	for _, mode := range modes() {
		for _, outcome := range []string{"ineligible", "budget", "unavailable", "incomplete-context", "invalid-response",
			"error", "proposed", "duplicate-review"} {
			for _, mutation := range []string{"mode", "policy_version", "provenance"} {
				raw := []findings.Finding{finding(), finding()}
				if outcome == "ineligible" {
					raw = []findings.Finding{finding(ev(map[string]any{"engine": "opengrep"}))}
				}
				client := &reviewer{change: map[string]any{"verdict": "retain_finding"}}
				o := review{mode: mode, client: client}
				switch outcome {
				case "unavailable":
					client.err = transportError()
				case "invalid-response":
					client.change["candidate_id"] = "wrong"
				case "error":
					o.failJudge = true
				case "budget":
					o.maxCalls = -1
				}
				text := body
				if outcome == "incomplete-context" {
					text += strings.Repeat("x", 20001)
				}
				p := fixture(t, text)
				data := build(t, p, o.report(t, p, raw))
				require.NoError(t, Validate(data))
				a := audit(data)
				var d map[string]any
				for _, x := range decisions(data) {
					if m(x)["status"] == outcome {
						d = m(x)
					}
				}
				require.NotNil(t, d, mode+" "+outcome)
				if mutation == "mode" {
					a["mode"] = map[string]string{"annotated": "shadow", "shadow": "annotated"}[mode]
				} else {
					d[mutation] = "unrelated-policy"
				}
				assert.ErrorContains(t, Validate(data), "SARIF validation failed", mode+" "+outcome+" "+mutation)
			}
		}
	}
}

// test_llm_sarif.py::test_failed_review_hashes_keep_request_and_reviewer_together (2 x 7 rows)
func TestFailedReviewHashesKeepRequestAndReviewerTogether(t *testing.T) {
	for _, mode := range modes() {
		for _, c := range [][2]string{{"malformed", "request_sha256"}, {"malformed", "reviewer"}, {"malformed", "both"},
			{"oversized", "request_sha256"}, {"oversized", "reviewer"}, {"transport", "request_sha256"}, {"transport", "reviewer"}} {
			failure, missing := c[0], c[1]
			client := &reviewer{err: transportError()}
			switch failure {
			case "malformed":
				client = scripted("{")
			case "oversized":
				client = scripted(strings.Repeat("x", 16385))
			}
			p := fixture(t, body)
			data := build(t, p, review{mode: mode, client: client}.report(t, p, []findings.Finding{finding()}))
			require.NoError(t, Validate(data))
			d := decision(t, data)
			_, hasResponse := d["response_sha256"]
			assert.Equal(t, failure == "malformed", hasResponse, mode+" "+failure)
			keys := []string{missing}
			if missing == "both" {
				keys = []string{"request_sha256", "reviewer"}
			}
			for _, k := range keys {
				delete(d, k)
			}
			assert.ErrorContains(t, Validate(data), "SARIF validation failed", mode+" "+failure+" "+missing)
		}
	}
}

// test_llm_apply.py::test_applied_correction_passes_sarif_validation
func TestAppliedCorrectionPassesSARIFValidation(t *testing.T) {
	p := fixture(t, body)
	report := review{apply: true}.report(t, p, []findings.Finding{finding()})
	out := filepath.Join(filepath.Dir(p.Identity), "reports", "skill.sarif")
	require.NoError(t, os.Mkdir(filepath.Dir(out), 0o755))
	require.NoError(t, Write(build(t, p, report), out, p.Identity))
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	doc := loads(t, raw)
	pr := props(m(results(doc)[0]))
	assert.Equal(t, "corrected", pr["disposition"])
	assert.Equal(t, "llm-review-policy", pr["decisionProvenance"])
	assert.Equal(t, "high", pr["originalSeverity"])
	assert.Equal(t, "low", pr["effectiveSeverity"])
	assert.Nil(t, m(results(doc)[0])["suppressions"])
	require.NoError(t, Validate(doc))
	// the correction must stay bound to the dispute that justified it
	withoutReview := loads(t, raw)
	delete(runProps(withoutReview), "llmReview")
	assert.ErrorContains(t, Validate(withoutReview), "SARIF validation failed")
	weaken := func(field string, value any) {
		weak := loads(t, raw)
		for _, d := range decisions(weak) {
			if m(d)["disposition"] == "llm-disputed" {
				m(m(d)["proposal"])[field] = value
			}
		}
		assert.ErrorContains(t, Validate(weak), "SARIF validation failed", field)
	}
	weaken("verdict", "retain_finding")
	weaken("confidence", "medium")
	weaken("intent", "unknown")
}

// test_llm_apply.py::test_applied_correction_must_carry_the_apply_policy_version (2 rows)
func TestAppliedCorrectionMustCarryTheApplyPolicyVersion(t *testing.T) {
	for version, ok := range map[string]bool{correlate.LLMApplyVersion: true, "skill-xray/llm-apply/v0": false} {
		p := fixture(t, body)
		report := review{apply: true}.report(t, p, []findings.Finding{finding()})
		out := filepath.Join(filepath.Dir(p.Identity), "reports", "skill.sarif")
		require.NoError(t, os.Mkdir(filepath.Dir(out), 0o755))
		require.NoError(t, Write(build(t, p, report), out, p.Identity))
		raw, err := os.ReadFile(out)
		require.NoError(t, err)
		doc := loads(t, raw)
		pr := props(m(results(doc)[0]))
		assert.Equal(t, "corrected", pr["disposition"])
		pr["policyVersion"] = version
		if ok {
			require.NoError(t, Validate(doc))
		} else {
			assert.ErrorContains(t, Validate(doc), "SARIF validation failed")
		}
	}
}
