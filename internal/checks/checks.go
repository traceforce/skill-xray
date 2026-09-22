// Package checks runs every registered check over the parsed IR in the Python order
// (checks/__init__.py) and holds the two checks with no lane of their own: coverage.go turns
// ledger gaps into findings and metadata.go maps parser-proven unsafe YAML tags to SXV-034.
package checks

import (
	"fmt"

	"github.com/traceforce/skill-xray/internal/codelane"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/forensics"
	"github.com/traceforce/skill-xray/internal/grants"
	"github.com/traceforce/skill-xray/internal/hooks"
	"github.com/traceforce/skill-xray/internal/instruction"
	"github.com/traceforce/skill-xray/internal/obfuscation"
	"github.com/traceforce/skill-xray/internal/opengrep"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/persistence"
	"github.com/traceforce/skill-xray/internal/preproc"
	"github.com/traceforce/skill-xray/internal/supplychain"
)

// taint is checks/taint_engine.py: the OpenGrep lane over the selected code units with the
// lane notes folded in; observations are collected when the caller passes a slice. A var so
// tests can stand in for the bridge as the oracle monkeypatches taint_engine.opengrep_check.
var taint = func(p *parse.Package, exe string, units []codelane.Unit, notes []findings.Finding,
	observations *[]map[string]any) []findings.Finding {
	return opengrep.Check(p, opengrep.Options{Executable: exe, Units: units, LaneNotes: notes, Observations: observations})
}

type check struct {
	module string // the Python __module__ a check-error message names
	fn     func(*parse.Package) []findings.Finding
}

// registry is _CHECKS in order; taint_engine, last, takes the code lane and is dispatched by Run.
var registry = []check{
	{"skill_xray.analyze", forensics.AnalyzePackage},
	{"skill_xray.checks.coverage", Coverage},
	{"skill_xray.checks.grants", grants.Check},
	{"skill_xray.checks.hooks", hooks.Check},
	{"skill_xray.checks.instruction_exfil", instruction.Check},
	{"skill_xray.checks.metadata", metadata},
	{"skill_xray.checks.obfuscation", obfuscation.Check},
	{"skill_xray.checks.persistence", persistence.Check},
	{"skill_xray.checks.preproc", preproc.Check},
	{"skill_xray.checks.supply_chain", supplychain.Check},
	{"skill_xray.checks.taint_engine", nil},
}

// Run is run_checks: every registered check in order, each isolated, so a crashing check
// becomes a visible check-error finding instead of a clean verdict. A nil observations
// pointer is Python's absent kwarg.
func Run(p *parse.Package, opengrepExe string, observations *[]map[string]any) []findings.Finding {
	var units []codelane.Unit
	var notes []findings.Finding
	func() {
		defer func() {
			if r := recover(); r != nil {
				units, notes = []codelane.Unit{}, []findings.Finding{{Rule: "check-error", Severity: "high",
					Message: fmt.Sprintf("executable code selection failed: %T", r)}}
			}
		}()
		units, notes = codelane.Build(p)
	}()
	out := []findings.Finding{}
	for _, c := range registry {
		fn := c.fn
		if fn == nil {
			fn = func(p *parse.Package) []findings.Finding {
				return taint(p, opengrepExe, units, notes, observations)
			}
		}
		out = append(out, isolated(c.module, fn, p)...)
	}
	return out
}

func isolated(module string, fn func(*parse.Package) []findings.Finding, p *parse.Package) (out []findings.Finding) {
	defer func() {
		if r := recover(); r != nil {
			out = []findings.Finding{{Rule: "check-error", Severity: "high",
				Message: fmt.Sprintf("check %s failed: %T", module, r)}}
		}
	}()
	return fn(p)
}
