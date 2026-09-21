package checks

import (
	"cmp"
	"fmt"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// _LOW_PARSE and _LOW_STATIC: gaps that are notes rather than incomplete analysis.
var (
	lowParse = pytext.Set("config_parse_error", "dep_manifest_unparsed", "frontmatter_parse_error",
		"grants_unparsed_shape", "markdown_parse_error", "requirement_unparsed", "unmodeled_content", "unsupported_markup")
	lowStatic = ingest.BenignLedger
)

// IsInventoryNote is coverage.is_inventory_note over a finding's fields: the low static
// coverage-note for an excluded directory, which never counts as an analysis gap.
func IsInventoryNote(vector, rule, severity string, evidence map[string]any) bool {
	reason, _ := evidence["reason"].(string)
	return vector == "" && rule == "coverage-note" && severity == "low" &&
		evidence["phase"] == "static" && lowStatic[reason]
}

// StaticSeverity is coverage._static_severity; "" is None (binary content in an asset is not
// a gap) and kind is "" when the ledger path has no artifact.
func StaticSeverity(reason, kind string) string {
	switch {
	case lowStatic[reason]:
		return "low"
	case reason == "binary_content" && kind == "asset":
		return ""
	}
	return "high"
}

// Coverage is coverage.check: one finding per distinct (phase, reason, path) ledger gap, high
// as analysis-incomplete or low as coverage-note.
func Coverage(p *parse.Package) []findings.Finding {
	out := []findings.Finding{}
	seen := map[[3]string]bool{}
	for _, e := range p.LedgerExceptions {
		phase, reason := cmp.Or(e.Phase, "static"), cmp.Or(e.ReasonCode, "unknown")
		key := [3]string{phase, reason, e.Path}
		if seen[key] {
			continue
		}
		seen[key] = true
		severity := "high"
		if phase == "parse" {
			if lowParse[reason] {
				severity = "low"
			}
		} else {
			kind := ""
			if a := p.ByRel[e.Path]; a != nil {
				kind = a.Kind
			}
			severity = StaticSeverity(reason, kind)
		}
		if severity == "" {
			continue
		}
		rule := map[string]string{"high": "analysis-incomplete", "low": "coverage-note"}[severity]
		out = append(out, findings.Finding{Rule: rule, Severity: severity, Path: e.Path,
			Message:  fmt.Sprintf("%s analysis coverage is incomplete (%s).", phase, reason),
			Evidence: map[string]any{"phase": phase, "reason": reason}})
	}
	return out
}
