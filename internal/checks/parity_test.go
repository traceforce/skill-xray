package checks

import (
	"testing"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// Corpus parity against skill_xray.checks.coverage.check and metadata.check.
func TestCorpusParity(t *testing.T) {
	for _, tc := range []struct {
		module string
		check  func(*parse.Package) []findings.Finding
		known  []string
	}{
		// parse R1: tree-sitter-bash reports an error region in hooks/pre-rebase.sample that
		// mvdan/sh does not, so Python carries one more analysis-incomplete finding. This is the
		// only shell_error_region presence delta over the corpus (parse.md R1).
		{"coverage", Coverage, []string{"pytest/test_schema_packaging.py_test_git_checkout_preserves_pinned_bytes_with_autocrlf-2ecffc47/.git"}},
		{"metadata", metadata, nil},
	} {
		t.Run(tc.module, func(t *testing.T) {
			testutil.CheckParity(t, tc.module, func(dir string) []findings.Finding {
				return tc.check(parse.Parse(ingest.BuildPackage(dir)))
			}, tc.known...)
		})
	}
}
