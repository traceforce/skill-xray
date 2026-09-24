package parse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/pytext"
)

func str(s string) *string { return &s }

func TestCanonicalRendersDiagnosticAndSpanAsPairs(t *testing.T) {
	assert.Equal(t, `[["a",null],["b","x"]]`, pytext.Canonical([]Diagnostic{{Code: "a"}, {Code: "b", Detail: str("x")}}))
	assert.Equal(t, `[[7,9]]`, pytext.Canonical([]Span{{7, 9}}))
}

// Expectations derived by running the oracle's code_lane._parent/_manifest_index/
// _governing_manifest on the same artifact list.
func TestManifestIndexAndGoverningManifest(t *testing.T) {
	p := &Package{}
	for _, rk := range [][2]string{
		{"a/b/SKILL.md", "skill_manifest"}, {"SKILL.md", "skill_manifest"}, {"a/SKILL.md", "instruction"},
		{"a/b/other.md", "skill_manifest"}, {"c/SKILL.md", "skill_manifest"},
	} {
		p.Artifacts = append(p.Artifacts, &Artifact{Rel: rk[0], Kind: rk[1]})
	}
	index := ManifestIndex(p)
	got := map[string]string{}
	for dir, a := range index {
		got[dir] = a.Rel
	}
	assert.Equal(t, map[string]string{"a/b": "a/b/SKILL.md", "": "SKILL.md", "c": "c/SKILL.md"}, got)

	for rel, want := range map[string]string{
		"a/b/c/x.py": "a/b/SKILL.md", "a/b/x.py": "a/b/SKILL.md", "a/x.py": "SKILL.md",
		"x.py": "SKILL.md", "c/x.py": "c/SKILL.md", "c/d/x.py": "c/SKILL.md", "": "SKILL.md",
	} {
		require.NotNil(t, GoverningManifest(index, rel), rel)
		assert.Equal(t, want, GoverningManifest(index, rel).Rel, rel)
	}

	nested := ManifestIndex(&Package{Artifacts: []*Artifact{{Rel: "a/SKILL.md", Kind: "skill_manifest"}}})
	assert.Nil(t, GoverningManifest(nested, "x.py"))
	assert.Nil(t, GoverningManifest(nested, ""))
	assert.Equal(t, "a/SKILL.md", GoverningManifest(nested, "a/x.py").Rel)

	for rel, want := range map[string]string{"a/b/c": "a/b", "a": "", "": "", "x/": "x"} {
		assert.Equal(t, want, parent(rel), rel)
	}
}
