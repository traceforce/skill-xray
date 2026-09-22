package checks

import (
	"fmt"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
)

// metadata is metadata.check: SXV-034 for every parser-proven unsafe YAML tag in frontmatter.
func metadata(p *parse.Package) []findings.Finding {
	out := []findings.Finding{}
	for _, a := range p.Artifacts {
		for _, tag := range a.UnsafeYamlTags {
			out = append(out, findings.Finding{Vector: "SXV-034", Rule: "unsafe-yaml-tag", Severity: "critical",
				Path: a.Rel, Line: findings.Int(tag.Line), Column: findings.Int(tag.Column),
				Message:  fmt.Sprintf("frontmatter requests unsafe object construction (%s)", tag.Tag),
				Evidence: map[string]any{"tag": tag.Tag}})
		}
	}
	return findings.CapFindings(out)
}
