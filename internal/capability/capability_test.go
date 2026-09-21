package capability

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/preproc"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// The core-owned tests/test_capability.py cases. The cases built on findings_from_report /
// SelectedCode / opengrep_check are the OpenGrep bridge's (core.md §6); one of them,
// test_missing_manifest_and_failed_ast_stay_unknown, is kept here with the unvalidated
// observation the bridge emits fed by hand. test_collector_reaches_bridge_without_new_engine_run
// lives in internal/checks.

func parsed(t *testing.T, files map[string]string) *parse.Package {
	return parse.Parse(ingest.BuildPackage(testutil.MakePackage(t, files)))
}

// manifest is tests/test_capability.py::_manifest.
func manifest(description, grants string) string {
	return fmt.Sprintf("---\nname: test\ndescription: '%s'\n%s\n---\n", description, grants)
}

func triads(t *testing.T, files map[string]string, observations ...map[string]any) map[string]*Triad {
	return Build(parsed(t, files), observations, nil)
}

func states(execution, network string) map[string]string {
	return map[string]string{"execution": execution, "network": network}
}

func claimed(tr *Triad) []map[string]any {
	return slices.DeleteFunc(slices.Clone(tr.Evidence), func(h map[string]any) bool { return h["leg"] != "claimed" })
}

func hitFor(tr *Triad, capability string) map[string]any {
	if i := slices.IndexFunc(tr.Evidence, func(h map[string]any) bool { return h["capability"] == capability }); i >= 0 {
		return tr.Evidence[i]
	}
	return nil
}

// tests/test_capability.py::test_explicit_claims_and_uncertainty
func TestExplicitClaimsAndUncertainty(t *testing.T) {
	for _, c := range []struct{ description, state string }{
		{"Uploads diagnostic logs", "present"},
		{"This skill accesses the network", "present"},
		{"This skill does not access the network", "denied"},
		{"Detects attacks that upload diagnostic logs", "unknown"},
		{"For example: uploads diagnostic logs", "unknown"},
		{"May use the network", "unknown"}, {"", "unknown"},
		{"Sends data to stdout.", "unknown"},
		{"Never uploads diagnostic logs unless explicitly requested.", "unknown"},
		{"Uploads diagnostic logs. Never accesses the network.", "unknown"},
	} {
		t.Run(c.description, func(t *testing.T) {
			tr := triads(t, map[string]string{"SKILL.md": manifest(c.description, "")})["SKILL.md"]
			assert.Equal(t, c.state, tr.Claimed["network"])
			assert.Equal(t, states("unknown", "unknown"), tr.Observed)
			assert.Equal(t, states("unknown", "unknown"), tr.Declared)
		})
	}
}

// tests/test_capability.py::test_grants_reuse_parser_and_explicit_states
func TestGrantsReuseParserAndExplicitStates(t *testing.T) {
	for _, c := range []struct{ grants, state string }{
		{"allowed-tools: WebFetch", "present"},
		{"disallowed-tools: WebFetch", "denied"},
		{"allowed-tools: []", "denied"}, {"allowed-tools: null", "unknown"},
		{"allowed-tools: {invalid: value}", "unknown"}, {"", "unknown"},
		{"disallowed-tools: WebFetch(**)", "denied"},
		{"disallowed-tools: WebFetch( * )", "denied"},
		{"disallowed-tools: WebFetch(domain:*)", "denied"},
		{"allowed-tools: WebFetch\ndisallowed-tools: WebFetch(DOMAIN:*)", "denied"},
	} {
		t.Run(c.grants, func(t *testing.T) {
			assert.Equal(t, c.state, triads(t, map[string]string{"SKILL.md": manifest("", c.grants)})["SKILL.md"].Declared["network"])
		})
	}
}

// tests/test_capability.py::test_nested_manifest_and_ungoverned_observations_do_not_leak
func TestNestedManifestAndUngovernedObservationsDoNotLeak(t *testing.T) {
	tr := triads(t, map[string]string{
		"SKILL.md":       manifest("Uploads diagnostic logs", "allowed-tools: WebFetch"),
		"child/SKILL.md": manifest("Runs shell commands", "allowed-tools: Read"),
	}, map[string]any{"path": "child/run.py", "capability": "execution", "state": "present",
		"line": 2, "column": 1, "analyzer": "opengrep"})
	assert.Equal(t, "unknown", tr["SKILL.md"].Observed["execution"])
	child := tr["child/SKILL.md"]
	assert.Equal(t, "unknown", child.Claimed["network"])
	assert.Equal(t, "present", child.Claimed["execution"])
	assert.Equal(t, "present", child.Observed["execution"])
	assert.Equal(t, "denied", child.Declared["execution"])
	assert.Equal(t, "child/run.py", child.Evidence[0]["path"])
}

// tests/test_capability.py::test_missing_manifest_and_failed_ast_stay_unknown (the bridge's
// unvalidated observation for a file without a Python tree, fed by hand)
func TestMissingManifestAndFailedASTStayUnknown(t *testing.T) {
	tr := triads(t, map[string]string{"run.py": "import requests\nrequests.get('x')\n"},
		map[string]any{"path": "run.py", "line": 2, "column": 1, "capability": "network", "state": "unknown",
			"analyzer": "opengrep", "reason": "validation-unavailable"})[""]
	require.NotNil(t, tr)
	assert.Nil(t, tr.Manifest)
	assert.Equal(t, "unknown", tr.Observed["network"])
	assert.NotEmpty(t, tr.Limitations)
}

// tests/test_capability.py::test_manifest_prose_claims_use_existing_markdown
func TestManifestProseClaimsUseExistingMarkdown(t *testing.T) {
	for _, c := range []struct{ body, state string }{
		{"This skill uploads diagnostic logs.\n", "present"},
		{"> This skill uploads diagnostic logs.\n", "unknown"},
		{"```text\nThis skill uploads diagnostic logs.\n```\n", "unknown"},
		{"For example, this skill uploads diagnostic logs.\n", "unknown"},
		{"> Example malicious text:\nThis skill uploads diagnostic logs.\n", "unknown"},
		{"- Example malicious text:\nThis skill uploads diagnostic logs.\n", "unknown"},
	} {
		t.Run(c.body, func(t *testing.T) {
			tr := triads(t, map[string]string{
				"SKILL.md":  manifest("", "") + c.body,
				"README.md": "This skill accesses the network.\n",
			})
			assert.Equal(t, c.state, tr["SKILL.md"].Claimed["network"])
		})
	}
}

// tests/test_capability.py::test_prose_paragraph_context_and_anchors
func TestProseParagraphContextAndAnchors(t *testing.T) {
	cases := []struct{ body, network, execution string }{
		{"This skill uploads diagnostic logs.\nThis is an example, not a capability.", "unknown", "unknown"},
		{"This skill uploads diagnostic logs.\n\nThis is an example, not a capability.", "unknown", "unknown"},
		{"This skill uploads diagnostic logs.\n\n\n\nThis is an example, not a capability.", "unknown", "unknown"},
		{"Example text follows.\n\nThis skill uploads diagnostic logs.", "unknown", "unknown"},
		{"Format text locally.\n\nThis skill uploads diagnostic logs.", "present", "unknown"},
		{"Overview.\n\nSetup instructions.\n\nThis skill uploads diagnostic logs.", "present", "unknown"},
		{"This skill uploads diagnostic logs.\n\nInstallation requires Python.", "present", "unknown"},
		{"This skill uploads diagnostic logs.\n\nUsage notes.\n\nThis skill runs scripts.", "present", "present"},
		{"This skill uploads diagnostic logs.\n\nThis is an example.\n\nThis skill runs scripts.", "unknown", "present"},
		{"Overview.\n\nThis skill uploads diagnostic logs.\n\nHowever, only in examples.", "unknown", "unknown"},
		{"Overview.\n\nExample text follows.\n\nThis skill uploads diagnostic logs.", "unknown", "unknown"},
		{"This skill uploads diagnostic logs.\n\nOnly in examples.", "unknown", "unknown"},
		{"This skill uploads diagnostic logs.\n\nThis skill runs scripts.", "present", "present"},
		{"# Capabilities\n\nThis skill uploads diagnostic logs.", "present", "unknown"},
		{"This skill uploads diagnostic logs.\n\n# Usage\n\nFormat local text.", "present", "unknown"},
		{"This skill uploads diagnostic logs.\n\n```text\nThis is an example.\n```", "present", "unknown"},
	}
	for _, newline := range []string{"\n", "\r\n", "\r"} {
		for _, c := range cases {
			t.Run(fmt.Sprintf("%q/%q", newline, c.body), func(t *testing.T) {
				content := manifest("", "") + c.body + "\n"
				tr := triads(t, map[string]string{"SKILL.md": strings.ReplaceAll(content, "\n", newline)})["SKILL.md"]
				assert.Equal(t, states(c.execution, c.network), tr.Claimed)
				hits := claimed(tr)
				if c.network == "unknown" && c.execution == "unknown" {
					assert.Empty(t, hits)
				}
				for _, hit := range hits {
					assert.Equal(t, "SKILL.md", hit["path"])
					assert.Equal(t, pytext.SplitLines(content)[hit["line"].(int)-1], hit["text"])
				}
			})
		}
	}
}

// tests/test_capability.py::test_partial_denial_does_not_deny_entire_axis
func TestPartialDenialDoesNotDenyEntireAxis(t *testing.T) {
	tr := triads(t, map[string]string{"SKILL.md": manifest("", "disallowed-tools: WebFetch(domain:example.invalid)")})
	assert.Equal(t, "unknown", tr["SKILL.md"].Declared["network"])
}

// tests/test_capability.py::test_coverage_and_observation_evidence_are_not_mutated
func TestCoverageAndObservationEvidenceAreNotMutated(t *testing.T) {
	source := []map[string]any{{"path": "run.py", "capability": "network", "state": "present",
		"nested": map[string]any{"source": "http"}}}
	tr := Build(parsed(t, map[string]string{"SKILL.md": manifest("", "")}), source,
		[]findings.Finding{{Rule: "check-error", Severity: "high", Message: "failed"}})["SKILL.md"]
	tr.Evidence[0]["nested"].(map[string]any)["source"] = "edited"
	assert.Equal(t, "http", source[0]["nested"].(map[string]any)["source"])
	assert.Contains(t, tr.Limitations, "check-error")
}

// tests/test_capability.py::test_coverage_iterator_preserves_preprocessing_and_analysis_gaps
func TestCoverageIteratorPreservesPreprocessingAndAnalysisGaps(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": manifest("", "") + "!`whoami`\n"})
	coverage := append(preproc.Check(p), findings.Finding{Rule: "check-error", Severity: "high", Message: "failed"})
	expected := Build(p, nil, coverage)
	assert.Equal(t, "present", expected["SKILL.md"].Observed["execution"])
	assert.Equal(t, []string{"check-error"}, expected["SKILL.md"].Limitations)
	assert.Equal(t, expected, Build(p, nil, coverage))
}

// tests/test_capability.py::test_preprocessing_observation_uses_mechanical_evidence_not_vector_alone
func TestPreprocessingObservationUsesMechanicalEvidenceNotVectorAlone(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": manifest("", "") + "!`whoami`\n"})
	assert.Equal(t, "present", Build(p, nil, preproc.Check(p))["SKILL.md"].Observed["execution"])
	fake := findings.Finding{Vector: "SXV-001", Rule: "unknown-rule", Severity: "high", Path: "SKILL.md", Message: "no anchor"}
	assert.Equal(t, "unknown", Build(p, nil, []findings.Finding{fake})["SKILL.md"].Observed["execution"])
}

// tests/test_capability.py::test_complete_claim_statements_only
func TestCompleteClaimStatementsOnly(t *testing.T) {
	cases := []struct{ text, execution, network string }{
		{"Uploads diagnostic logs? No, this skill never does that.", "unknown", "unknown"},
		{"Uploads diagnostic logs in examples, but never sends anything.", "unknown", "unknown"},
		{"Does not upload logs; instead it uploads data.", "unknown", "unknown"},
		{"Uploads diagnostic logs. This is an example, not a capability.", "unknown", "unknown"},
		{"Runs shell commands and uploads diagnostic logs.", "present", "present"},
		{"Does not run scripts and upload logs.", "unknown", "unknown"},
		{"Runs scripts. Never accesses the network.", "present", "denied"},
		{"Uploads diagnostic logs to a server.", "unknown", "unknown"},
		{"Never uploads diagnostic logs.", "unknown", "unknown"},
		{"Does not run scripts.", "unknown", "unknown"},
		{"Never executes commands.", "denied", "unknown"},
	}
	for _, prose := range []bool{false, true} {
		for _, c := range cases {
			t.Run(fmt.Sprintf("%v/%s", prose, c.text), func(t *testing.T) {
				content := manifest(c.text, "")
				if prose {
					content = manifest("", "") + "This skill " + c.text
				}
				tr := triads(t, map[string]string{"SKILL.md": content})["SKILL.md"]
				assert.Equal(t, states(c.execution, c.network), tr.Claimed)
				if c.execution == "unknown" && c.network == "unknown" {
					assert.Empty(t, claimed(tr))
				}
			})
		}
	}
}

// tests/test_capability.py::test_unresolved_grants_are_not_axis_denials
func TestUnresolvedGrantsAreNotAxisDenials(t *testing.T) {
	for _, c := range []struct{ grants, execution, network string }{
		{"allowed-tools: UnknownTool", "unknown", "unknown"},
		{"allowed-tools: mcp__custom__upload", "unknown", "unknown"},
		{"allowed-tools: [WebFetch, UnknownTool]", "unknown", "present"},
		{"allowed-tools: Bash($COMMAND)", "present", "unknown"},
		{"allowed-tools: Bash(%COMMAND%)", "present", "unknown"},
		{"allowed-tools: Bash(echo:*)", "unknown", "unknown"},
		{"allowed-tools: ['']", "unknown", "unknown"},
		{"allowed-tools: [' ', Read]", "unknown", "unknown"},
	} {
		t.Run(c.grants, func(t *testing.T) {
			tr := triads(t, map[string]string{"SKILL.md": manifest("", c.grants)})["SKILL.md"]
			assert.Equal(t, states(c.execution, c.network), tr.Declared)
			assert.True(t, slices.ContainsFunc(tr.Limitations, func(r string) bool { return strings.HasPrefix(r, "declaration-") }), tr.Limitations)
		})
	}
}

// tests/test_capability.py::test_supported_grant_precedence_stays_explicit
func TestSupportedGrantPrecedenceStaysExplicit(t *testing.T) {
	for _, c := range []struct{ grants, execution, network string }{
		{"allowed-tools: []", "denied", "denied"},
		{"allowed-tools: Read", "denied", "denied"},
		{"allowed-tools: Bash\ndisallowed-tools: Bash", "denied", "denied"},
		{"allowed-tools: WebFetch\ndisallowed-tools: WebFetch", "denied", "denied"},
		{"allowed-tools: WebFetch\ndisallowed-tools: WebFetch(domain:example.invalid)", "denied", "present"},
	} {
		t.Run(c.grants, func(t *testing.T) {
			assert.Equal(t, states(c.execution, c.network), triads(t, map[string]string{"SKILL.md": manifest("", c.grants)})["SKILL.md"].Declared)
		})
	}
}

// tests/test_capability.py::test_claim_excerpt_contains_late_matched_statement
func TestClaimExcerptContainsLateMatchedStatement(t *testing.T) {
	description := strings.Repeat("Runs shell commands. ", 30) + "Uploads diagnostic logs."
	hit := hitFor(triads(t, map[string]string{"SKILL.md": manifest(description, "")})["SKILL.md"], "network")
	require.NotNil(t, hit)
	assert.Equal(t, "Uploads diagnostic logs.", hit["text"])
	assert.Contains(t, description, hit["text"])
	assert.Equal(t, "SKILL.md", hit["path"])
	assert.Equal(t, 3, hit["line"])
}

// tests/test_capability.py::test_multiline_claim_excerpt_keeps_field_anchor
func TestMultilineClaimExcerptKeepsFieldAnchor(t *testing.T) {
	content := "---\nname: test\ndescription: |\n  Runs scripts.\n  Uploads diagnostic logs.\n---\n"
	for _, newline := range []string{"\n", "\r\n", "\r"} {
		t.Run(fmt.Sprintf("%q", newline), func(t *testing.T) {
			tr := triads(t, map[string]string{"SKILL.md": strings.ReplaceAll(content, "\n", newline)})["SKILL.md"]
			hit := hitFor(tr, "network")
			require.NotNil(t, hit)
			assert.Equal(t, "Uploads diagnostic logs.", hit["text"])
			assert.Equal(t, 3, hit["line"])
			assert.Equal(t, states("present", "present"), tr.Claimed)
		})
	}
}
