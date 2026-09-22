package codelane

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// tests/test_js_lane.py: JavaScript and TypeScript scripts become code units.
func TestJavaScriptAndTypeScriptFilesBecomeUnits(t *testing.T) {
	units, notes := build(t, map[string]string{"SKILL.md": "---\nname: t\n---\n", "scripts/x.js": "console.log(1);\n",
		"scripts/y.ts": "const n: number = 1;\n", "scripts/z.rb": "puts 1\n"})
	assert.ElementsMatch(t, []string{"script_javascript", "script_typescript"}, kinds(units))
	assert.Empty(t, notes)
}
