package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
)

func TestReadJSON(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		text string
		want map[string]any
	}{
		{`{"line": 3, "f": 1.5, "list": [7, "7"]}`, map[string]any{"line": 3, "f": 1.5, "list": []any{7, "7"}}},
		{"{\"a\": 1}\n{\"b\": 2}\n", map[string]any{"a": 1}}, // the first document only
		{"null", nil},
	} {
		path := filepath.Join(dir, "py.json")
		require.NoError(t, os.WriteFile(path, []byte(c.text), 0o644))
		assert.Equal(t, c.want, ReadJSON(t, path))
	}
}

func TestCachedRunsAreSortedAndPresent(t *testing.T) {
	runs := CachedRuns(t)
	assert.True(t, slices.IsSortedFunc(runs, func(a, b CachedRun) int { return strings.Compare(a.Dir, b.Dir) }))
	for _, run := range runs[:min(3, len(runs))] {
		assert.FileExists(t, filepath.Join(run.Dir, "meta.json"))
		assert.DirExists(t, run.Package)
	}
}

func TestFirstDiffOnDecodedFindings(t *testing.T) {
	base := map[string]any{"vector": "", "severity": "", "path": "", "message": ""}
	py := []any{map[string]any{"rule": "a", "line": 1.0}, map[string]any{"rule": "b"}}
	for _, f := range py {
		for k, v := range base {
			f.(map[string]any)[k] = v
		}
	}
	if i := firstDiffIndex(py, asJSON([]findings.Finding{{Rule: "a", Line: findings.Int(1)}, {Rule: "b"}})); i != -1 {
		t.Errorf("equal lists differ at %d", i)
	}
	if i := firstDiffIndex(py, asJSON([]findings.Finding{{Rule: "a", Line: findings.Int(2)}})); i != 0 {
		t.Errorf("first element differs, got %d", i)
	}
	if i := firstDiffIndex(py, asJSON([]findings.Finding{{Rule: "a", Line: findings.Int(1)}})); i != 1 {
		t.Errorf("shorter go list differs at 1, got %d", i)
	}
	if i := firstDiffIndex(nil, nil); i != -1 {
		t.Errorf("two empty lists differ at %d", i)
	}
}

func TestConstructQuotesTheSourceLine(t *testing.T) {
	dir := MakePackage(t, map[string]string{"SKILL.md": "# T\nsecond line\n"})
	got := construct(dir, "<absent>", map[string]any{"path": "SKILL.md", "line": 2.0})
	if got != "SKILL.md:2: second line" {
		t.Errorf("construct = %q", got)
	}
	if got := construct(dir, map[string]any{"path": "SKILL.md"}); got != "(no source position)" {
		t.Errorf("construct without line = %q", got)
	}
}

// The oracle's Finding.to_dict and findings.Finding.MarshalJSON decode to the same value, which
// is the whole basis of CheckParity; proven on skill_xray.checks.metadata over one package.
func TestPyDumpFindingsMatchesFindingJSON(t *testing.T) {
	dir := MakePackage(t, map[string]string{
		"SKILL.md": "---\nname: t\nx: !!python/object/apply:os.system [\"id\"]\n---\n# T\n"})
	out := dumpFindings(t, "metadata", []string{dir})
	var rec oracleRecord
	if err := json.Unmarshal(out, &rec); err != nil {
		t.Fatalf("%v in %s", err, out)
	}
	if rec.Package != dir || rec.Error != "" {
		t.Fatalf("record = %+v", rec)
	}
	tag := "tag:yaml.org,2002:python/object/apply:os.system"
	want := []findings.Finding{{Vector: "SXV-034", Rule: "unsafe-yaml-tag", Severity: "critical", Path: "SKILL.md",
		Message: "frontmatter requests unsafe object construction (" + tag + ")",
		Line:    findings.Int(3), Column: findings.Int(4), Evidence: map[string]any{"tag": tag}}}
	if i := firstDiffIndex(rec.Findings, asJSON(want)); i != -1 {
		t.Errorf("oracle and Go findings differ at %d: %s", i, out)
	}
}
