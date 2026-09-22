package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/traceforce/skill-xray/internal/findings"
)

// A low note alone leaves a package CLEAN; a vector finding or a gap at medium or above is
// FINDINGS; a high or critical vector finding is BLOCKING.
func TestHeadlineIgnoresLowNotes(t *testing.T) {
	note := findings.Finding{Rule: "coverage-note", Severity: "low", Path: "assets/logo.svg"}
	gap := findings.Finding{Rule: "analysis-incomplete", Severity: "high", Path: "run.ps1"}
	lowVector := findings.Finding{Vector: "SXV-004", Rule: "over-broad-grant", Severity: "low", Path: "SKILL.md"}
	blocking := findings.Finding{Vector: "SXV-008", Rule: "command-injection", Severity: "critical", Path: "run.js"}
	assert.Equal(t, "CLEAN", headline(nil))
	assert.Equal(t, "CLEAN", headline([]findings.Finding{note}))
	assert.Equal(t, "FINDINGS", headline([]findings.Finding{note, gap}))
	assert.Equal(t, "FINDINGS", headline([]findings.Finding{lowVector}))
	assert.Equal(t, "BLOCKING", headline([]findings.Finding{note, blocking}))
}
