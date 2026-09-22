package opengrep

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/traceforce/skill-xray/internal/codelane"
	"github.com/traceforce/skill-xray/internal/parse"
)

// tests/test_js_lane.py::test_javascript_and_typescript_files_are_selected_without_a_coverage_gap:
// a script file keeps its own extension so the engine reads TSX as TSX.
func TestJavaScriptAndTypeScriptFilesAreSelectedWithoutACoverageGap(t *testing.T) {
	p := parsed(t, map[string]string{"SKILL.md": manifest, "scripts/x.js": "console.log(1);\n",
		"scripts/y.ts": "const n: number = 1;\n", "scripts/w.tsx": "export const A = () => <div/>;\n",
		"scripts/z.rb": "puts 1\n"})
	units, notes := codelane.Build(p)
	kinds := map[string]bool{}
	for _, u := range units {
		kinds[u.Kind] = true
	}
	assert.Equal(t, map[string]bool{"script_javascript": true, "script_typescript": true}, kinds)
	selected := map[[2]string]bool{}
	for _, s := range Select(p, units, []string{"javascript", "typescript"}) {
		selected[[2]string{s.Rel, s.Suffix}] = true
	}
	assert.Equal(t, map[[2]string]bool{{"scripts/x.js", ".js"}: true, {"scripts/y.ts", ".ts"}: true,
		{"scripts/w.tsx", ".tsx"}: true}, selected)
	assert.Empty(t, p.ByRel["scripts/x.js"].Diagnostics)
	assert.Empty(t, p.ByRel["scripts/y.ts"].Diagnostics)
	ruby := "ruby"
	assert.Contains(t, p.ByRel["scripts/z.rb"].Diagnostics, parse.Diagnostic{Code: "unsupported_language", Detail: &ruby})
	assert.Empty(t, notes)
}
