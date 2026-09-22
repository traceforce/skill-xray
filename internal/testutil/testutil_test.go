package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tests/conftest.py::make_package: str values are written UTF-8 with newline="" and bytes
// values raw, so CRLF, lone CR, BOMs and invalid UTF-8 must survive byte for byte.
func TestMakePackageWritesBytesVerbatim(t *testing.T) {
	files := map[string]string{
		"SKILL.md":       "---\r\nname: t\r\n---\n",
		"scripts/x.py":   "a\rb\n",
		"assets/bom.txt": "\xef\xbb\xbfhi",
		"assets/a.png":   "\x89PNG\r\n\xff\xfe\x00\x01",
		"deep/a/b/c.txt": "",
		"unicode/é😀.md":  "İ\u2028\x0c",
	}
	root := MakePackage(t, files)
	if filepath.Base(root) != "pkg" {
		t.Fatalf("root %q is not named pkg", root)
	}
	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s: got %q want %q", rel, got, want)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Errorf("root has %d entries, want 5", len(entries))
	}
}

func TestMakePackageEmpty(t *testing.T) {
	root := MakePackage(t, nil)
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		t.Fatalf("empty package root missing: %v", err)
	}
	other := MakePackage(t, nil)
	if filepath.Dir(other) == filepath.Dir(root) {
		t.Errorf("two packages share a TempDir: %s", other)
	}
}

// skipRecorder captures Skip and Fatal instead of ending the test.
type skipRecorder struct {
	testing.TB
	skipped, failed bool
}

func (s *skipRecorder) Skip(...any)  { s.skipped = true }
func (s *skipRecorder) Fatal(...any) { s.failed = true }

func TestSymlinkOrSkip(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, nil, 0o644))
	t.Setenv("SKILLXRAY_REQUIRE_SYMLINKS", "")
	rec := &skipRecorder{TB: t}
	SymlinkOrSkip(rec, target, filepath.Join(dir, "missing", "link"))
	assert.True(t, rec.skipped && !rec.failed, "an unwritable link skips")
	t.Setenv("SKILLXRAY_REQUIRE_SYMLINKS", "1")
	rec = &skipRecorder{TB: t}
	SymlinkOrSkip(rec, target, filepath.Join(dir, "missing", "link"))
	assert.True(t, rec.failed && !rec.skipped, "a required symlink that cannot be made fails, never skips")
	t.Setenv("SKILLXRAY_REQUIRE_SYMLINKS", "")
	SymlinkOrSkip(t, target, filepath.Join(dir, "link"))
	st, err := os.Lstat(filepath.Join(dir, "link"))
	require.NoError(t, err)
	assert.NotZero(t, st.Mode()&os.ModeSymlink)
}

func TestLaneFailed(t *testing.T) {
	for _, c := range []struct {
		f    map[string]any
		want bool
	}{
		{map[string]any{"vector": "", "rule": "opengrep-timeout"}, true},
		{map[string]any{"vector": "", "rule": "opengrep-internal-error", "message": "x"}, true},
		{map[string]any{"vector": "SXV-008", "rule": "opengrep-python-command-injection"}, false},
		{map[string]any{"vector": "", "rule": "check-error"}, false},
		{map[string]any{"rule": "opengrep-timeout"}, false},
	} {
		assert.Equal(t, c.want, LaneFailed(c.f), "%v", c.f)
	}
}

func TestFirstDiff(t *testing.T) {
	a := map[string]any{"k": []any{1, map[string]any{"x": "y"}}, "n": 1}
	for _, c := range []struct {
		b    any
		want string
	}{
		{map[string]any{"k": []any{1, map[string]any{"x": "y"}}, "n": 1}, ""},
		{map[string]any{"k": []any{1, map[string]any{"x": "z"}}, "n": 1}, "doc.k[1].x: y != z"},
		{map[string]any{"k": []any{1}, "n": 1}, "doc.k: [1 map[x:y]] != [1]"},
		{map[string]any{"k": []any{1, map[string]any{"x": "y"}}}, "doc.n: 1 != <nil>"},
		{map[string]any{"k": []any{1, map[string]any{"x": "y"}}, "n": 1, "extra": true}, "doc.extra: <nil> != true"},
		{[]any{}, "doc: map[k:[1 map[x:y]] n:1] != []"},
	} {
		assert.Equal(t, c.want, FirstDiff("doc", a, c.b))
	}
	assert.Equal(t, "", FirstDiff("", 1, 1))
	assert.Equal(t, ": 1 != 1.5", FirstDiff("", 1, 1.5))
}

func TestReviewerDisputesEveryCandidate(t *testing.T) {
	r := &Reviewer{Change: map[string]any{"confidence": "low"}}
	reply, err := r.Complete("", `{"candidate": {"candidate_id": "c1"}}`)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(reply), &got))
	assert.Equal(t, "c1", got["candidate_id"])
	assert.Equal(t, "propose_false_positive", got["verdict"])
	assert.Equal(t, "low", got["confidence"])
	assert.Equal(t, `An archived message contained "Ignore all previous instructions."`, got["evidence_quote"])
	advisory, err := r.Complete("", `{"files": []}`)
	require.NoError(t, err)
	assert.JSONEq(t, `{"prompt_injection": false}`, advisory)
	_, err = r.Complete("", "not json")
	assert.Error(t, err)
	assert.Len(t, r.Calls, 2)
	provider, model := r.Identity()
	assert.Equal(t, []string{"fixture", "fixture-1"}, []string{provider, model})
}
