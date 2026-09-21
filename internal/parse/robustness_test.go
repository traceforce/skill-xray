package parse

// Posture-audit fixes (2026-09-19): inputs that CPython, markdown-it-py and tomllib handle in
// polynomial time but the Go libraries parse quadratically (or with quadratic memory) are refused
// fail-visibly before the library runs, and a single artifact can no longer outlive the package
// budget. Each refusal is an accepted divergence listed in 00-overview §7.

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/testutil"
)

func TestMarkdownTooComplexIsRefusedFailVisible(t *testing.T) {
	deep := skill + strings.Repeat("> ", mdMaxMarkers+1) + "quoted\n"
	p := parsePkg(t, map[string]string{"SKILL.md": deep})
	a := p.ByRel["SKILL.md"]
	assert.Nil(t, a.Markdown)
	require.Len(t, a.Diagnostics, 1)
	assert.Equal(t, "markdown_too_complex", a.Diagnostics[0].Code)
	assert.True(t, slices.ContainsFunc(p.LedgerExceptions, func(e ingest.LedgerEntry) bool {
		return e.Phase == "parse" && e.ReasonCode == "markdown_too_complex" && e.Path == "SKILL.md"
	}))

	// At the bound, and with the same markers inside prose, goldmark runs as before.
	for _, body := range []string{
		strings.Repeat("> ", mdMaxMarkers) + "quoted\n",
		"text " + strings.Repeat("> ", mdMaxMarkers+1) + "\n",
		strings.Repeat("[a](b) ", mdMaxMarkers) + "\n",
	} {
		p := parsePkg(t, map[string]string{"SKILL.md": skill + body})
		assert.NotNil(t, p.ByRel["SKILL.md"].Markdown)
		assert.Empty(t, p.ByRel["SKILL.md"].Diagnostics)
	}
	assert.Equal(t, 3, leadingMarkers("  > - 1. text > more"))
	assert.Equal(t, 2, leadingMarkers("* + text"))
	assert.Equal(t, 0, leadingMarkers("text > more"))
	assert.Equal(t, 0, leadingMarkers("2024 was > 2023"))
	assert.Equal(t, mdMaxMarkers+1, markdownTooComplex("fine\n"+strings.Repeat("](", mdMaxMarkers+1)+"\n"))
}

func TestTOMLKeyPathDepthIsBounded(t *testing.T) {
	deep := "[project]\nname = \"x\"\n" + strings.Repeat("a.", tomlMaxDepth+1) + "a = 1\n" // tomlMaxDepth+2 segments
	p := parsePkg(t, map[string]string{"SKILL.md": skill, "pyproject.toml": deep})
	a := p.ByRel["pyproject.toml"]
	require.Len(t, a.Diagnostics, 1)
	assert.Equal(t, "config_parse_error", a.Diagnostics[0].Code)

	ok := "[project]\nname = \"x\"\n" + strings.Repeat("a.", 50) + "a = 1\nb = { c = { d = 1 } }\n" +
		"s = \"a.b.c.d.e\"\n# a.b.c.d\nt = 'x.y.z'\n"
	p = parsePkg(t, map[string]string{"SKILL.md": skill, "pyproject.toml": ok})
	assert.Empty(t, p.ByRel["pyproject.toml"].Diagnostics)

	nested := "x = " + strings.Repeat("{ y = ", tomlMaxDepth+1) + "1" + strings.Repeat(" }", tomlMaxDepth+1) + "\n"
	assert.True(t, tomlTooDeep(nested))
	assert.False(t, tomlTooDeep("x = "+strings.Repeat("[", 5000)+strings.Repeat("]", 5000)+"\n"), "arrays add no key path")
	assert.False(t, tomlTooDeep("s = \""+strings.Repeat("a.", 2000)+"\"\n"), "dots inside a string are not a key")
}

func TestParseAbandonsAnArtifactThatOutlivesTheBudget(t *testing.T) {
	testutil.Swap(t, &pkgBudget, 50*time.Millisecond)
	testutil.Swap(t, &parseMD, func(a *Artifact, text string, stripFM bool) {
		time.Sleep(400 * time.Millisecond)
		a.Markdown = &Markdown{}
	})
	p := parsePkg(t, map[string]string{"SKILL.md": skill + "body\n"})
	a := p.ByRel["SKILL.md"]
	assert.Nil(t, a.Markdown)
	assert.Equal(t, []Diagnostic{{Code: "parse_budget_exceeded"}}, a.Diagnostics)
	assert.NotNil(t, a.Text, "the abandoned artifact keeps its text")
}
