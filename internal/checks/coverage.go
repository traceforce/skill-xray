package checks

import (
	"cmp"
	"fmt"
	"path"
	"strings"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// _LOW_PARSE and _LOW_STATIC: gaps that are notes rather than incomplete analysis.
var (
	lowParse = pytext.Set("config_parse_error", "dep_manifest_unparsed", "frontmatter_parse_error",
		"grants_unparsed_shape", "markdown_parse_error", "raw_html_markup", "requirement_unparsed", "unmodeled_content",
		"unsupported_markup")
	lowStatic = ingest.BenignLedger
	// unanalyzedSource: source files no lane analyzes; an agent can be told to build or run them.
	unanalyzedSource = pytext.Set(".go", ".rs", ".php", ".java", ".kt", ".kts", ".swift", ".c", ".cc", ".cpp", ".cxx",
		".h", ".hpp", ".cs", ".lua", ".r", ".scala", ".dart", ".ex", ".exs", ".hs", ".m", ".mm", ".zig", ".nim", ".jl",
		".vb", ".fs", ".clj", ".erl", ".groovy", ".gradle", ".ksh", ".fish", ".csh", ".tcsh", ".awk", ".vbs", ".ahk", ".applescript")
)

// IsInventoryNote is coverage.is_inventory_note over a finding's fields: the low static
// coverage-note for an excluded directory, which never counts as an analysis gap.
func IsInventoryNote(vector, rule, severity string, evidence map[string]any) bool {
	reason, _ := evidence["reason"].(string)
	return vector == "" && rule == "coverage-note" && severity == "low" &&
		evidence["phase"] == "static" && lowStatic[reason]
}

// StaticSeverity grades a static ledger gap; "" is no gap (binary content in an asset) and
// kind is "" when the ledger path has no artifact. An SVG that could not be reviewed is a
// note: an agent never reads it as instructions and its bytes still pass the forensics lane.
// A PDF or a nested archive holds content an agent may be told to read or unpack, so those
// stay gaps.
func StaticSeverity(reason, kind, rel string) string {
	switch {
	case lowStatic[reason]:
		return "low"
	case reason == "binary_content" && kind == "asset":
		return ""
	case reason == "unreviewable_content" && kind == "active_asset" && strings.HasSuffix(pytext.Lower(rel), ".svg"):
		return "low"
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
		message := fmt.Sprintf("%s analysis coverage is incomplete (%s).", phase, reason)
		if phase == "parse" {
			if lowParse[reason] {
				severity = "low"
			}
			if reason == "unmodeled_content" && unanalyzedSource[strings.ToLower(path.Ext(e.Path))] {
				// shipped source an agent can be told to build or run, read but analyzed by no
				// lane: visible as FINDINGS on the console, not hidden under CLEAN
				severity = "medium"
				message = fmt.Sprintf("%s was read but not analyzed: no lane covers %s source.", e.Path, strings.TrimPrefix(path.Ext(e.Path), "."))
			}
		} else {
			kind := ""
			if a := p.ByRel[e.Path]; a != nil {
				kind = a.Kind
			}
			severity = StaticSeverity(reason, kind, e.Path)
		}
		if severity == "" {
			continue
		}
		rule := map[string]string{"high": "analysis-incomplete", "medium": "analysis-incomplete", "low": "coverage-note"}[severity]
		out = append(out, findings.Finding{Rule: rule, Severity: severity, Path: e.Path,
			Message:  message,
			Evidence: map[string]any{"phase": phase, "reason": reason}})
	}
	return out
}
