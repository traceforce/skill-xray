// Package testutil holds the helpers every package's tests share: throwaway skill packages, a
// finding filter, a monkeypatch-style variable swap, the corpus-cache walkers and the fixture
// reviewer.
package testutil

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/traceforce/skill-xray/internal/findings"
)

// MakePackage mirrors tests/conftest.py::make_package: each value is written byte for byte
// (no newline translation) under <TempDir>/pkg/<rel>; the package root is returned.
func MakePackage(t testing.TB, files map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "pkg")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for rel, body := range files {
		dest := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// ByVector keeps the findings whose Vector is vector.
func ByVector(fs []findings.Finding, vector string) (out []findings.Finding) {
	for _, f := range fs {
		if f.Vector == vector {
			out = append(out, f)
		}
	}
	return out
}

// Swap replaces a package variable (a limit or a seam) for one test, like monkeypatch.setattr.
func Swap[T any](t testing.TB, p *T, v T) {
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// SymlinkOrSkip is the tests' `except OSError: pytest.skip("symlinks unavailable")`. With
// SKILLXRAY_REQUIRE_SYMLINKS=1 (a CI host that holds the privilege) the skip is a failure, so the
// symlink-refusal contract cannot go silently unexercised.
func SymlinkOrSkip(t testing.TB, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if os.Getenv("SKILLXRAY_REQUIRE_SYMLINKS") == "1" {
			t.Fatal("symlinks required by SKILLXRAY_REQUIRE_SYMLINKS but unavailable: " + err.Error())
		} else {
			t.Skip("symlinks unavailable: " + err.Error())
		}
	}
}

// LaneFailed reports a vector-less opengrep-* finding (its to_dict map): a timing-dependent engine
// failure, compared by message prefix only, that leaves no comparable taint evidence on either side
// (00-overview section 7).
func LaneFailed(f map[string]any) bool {
	rule, _ := f["rule"].(string)
	return f["vector"] == any("") && strings.HasPrefix(rule, "opengrep-")
}

// PresenceOnlyDiagnostic reports a finding whose evidence.reason is a presence-only parse
// diagnostic (parse.md R6): its detail text differs between the engines and feeds the artifact
// context digests, which the harness compares by presence (known_divergences.json), so the
// byte-for-byte gates skip the package.
func PresenceOnlyDiagnostic(f map[string]any) bool {
	ev, _ := f["evidence"].(map[string]any)
	reason, _ := ev["reason"].(string)
	return slices.Contains([]string{"config_parse_error", "shell_error_region", "parse_crash", "frontmatter_parse_error"}, reason)
}

// MessagePrefix is a failure-path message or context error up to its last ": ", the part before
// the Python exception class name the two sides never share (00-overview section 7).
func MessagePrefix(s string) string {
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[:i]
	}
	return s
}

// FirstDiff is the first differing JSON path between two generic documents, or "".
func FirstDiff(path string, a, b any) string {
	switch x := a.(type) {
	case map[string]any:
		if y, ok := b.(map[string]any); ok {
			keys := maps.Clone(x)
			maps.Copy(keys, y)
			for _, k := range slices.Sorted(maps.Keys(keys)) {
				if d := FirstDiff(path+"."+k, x[k], y[k]); d != "" {
					return d
				}
			}
			return ""
		}
	case []any:
		if y, ok := b.([]any); ok && len(x) == len(y) {
			for i := range x {
				if d := FirstDiff(fmt.Sprintf("%s[%d]", path, i), x[i], y[i]); d != "" {
					return d
				}
			}
			return ""
		}
	}
	if !reflect.DeepEqual(a, b) {
		return fmt.Sprintf("%s: %.200s != %.200s", path, fmt.Sprint(a), fmt.Sprint(b))
	}
	return ""
}

// Reviewer is tests/test_llm_apply.py::Reviewer: an LLM client that disputes every candidate it is
// shown (per-field overrides in Change) and answers an advisory request benignly; every parsed
// request is kept in Calls.
type Reviewer struct {
	Change map[string]any
	Calls  []map[string]any
}

// Identity is Reviewer.cfg = SimpleNamespace(provider="fixture", model="fixture-1").
func (*Reviewer) Identity() (provider, model string) { return "fixture", "fixture-1" }

func (r *Reviewer) Complete(_, user string) (string, error) {
	var request map[string]any
	if err := json.Unmarshal([]byte(user), &request); err != nil {
		return "", err
	}
	r.Calls = append(r.Calls, request)
	candidate, ok := request["candidate"].(map[string]any)
	if !ok {
		return `{"prompt_injection": false}`, nil
	}
	reply := map[string]any{"candidate_id": candidate["candidate_id"], "verdict": "propose_false_positive",
		"confidence": "high", "mechanism": "not_supported", "intent": "legitimate",
		"reason":         "The quoted archive record is not a live directive",
		"impact":         "No instruction to override agent behavior",
		"evidence_quote": `An archived message contained "Ignore all previous instructions."`}
	maps.Copy(reply, r.Change)
	out, err := json.Marshal(reply)
	return string(out), err
}
