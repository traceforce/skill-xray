// Package testutil holds the helpers every package's tests share: throwaway skill packages, a
// finding filter, a monkeypatch-style variable swap, the symlink helper and the fixture
// reviewer.
package testutil

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
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
