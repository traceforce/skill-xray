package parse

// Two-engine fact diff for the frontmatter, grants, config, dependency, Python and diagnostic
// fields of the IR: every corpus artifact's irDoc against tools/parity/py_dump_ir.py run on the
// oracle, cached as corpus/ir-py/<source>/<slug>__<pkg>.jsonl (one document per artifact). The
// markdown fields belong to markdown_facts_test.go; refs depend on them and are left out here.

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/pytext"
)

const irCache = "../../corpus/ir-py"

var m2Fields = []string{"rel", "kind", "text_sha256", "raw_sha256", "frontmatter", "frontmatter_keys",
	"frontmatter_key_lines", "frontmatter_end_line", "unsafe_yaml_tags", "grants", "config", "manifest_kind",
	"deps", "diagnostics"}

// markdownDiags are the diagnostics the markdown engine decides; they are dropped from both
// sides before the list is compared.
var markdownDiags = map[string]bool{"markdown_parse_error": true, "raw_html": true}

func m2Diagnostics(v any) any {
	list, _ := v.([]any)
	out := []any{}
	for _, d := range list {
		pair, _ := d.([]any)
		if len(pair) == 2 && !markdownDiags[fmt.Sprint(pair[0])] {
			out = append(out, pair)
		}
	}
	return out
}

// knownFactDiffs are the two measured engine differences, keyed <source>/<cache file>:<artifact>
// with the one field that differs, so any other mismatch fails the test: yaml.v3 reports a
// parser-class frontmatter error on the document's first line where PyYAML names the offending
// line, and mvdan/sh parses a hook sample that tree-sitter marks with an ERROR (no
// shell_error_region, parse.md R1).
var knownFactDiffs = map[string]string{
	"pytest/test_metadata.py_test_invalid_frontmatter_with_observed_capability_fails_high-196d5308__pkg:SKILL.md":                   "diagnostics",
	"pytest/test_schema_packaging.py_test_git_checkout_preserves_pinned_bytes_with_autocrlf-2ecffc47__.git:hooks/pre-rebase.sample": "diagnostics",
}

func TestCorpusFactsMatchOracle(t *testing.T) {
	sources, err := os.ReadDir(irCache)
	if err != nil {
		t.Skipf("%s absent: run the oracle dump (tools/parity/py_dump_ir.py) over the corpus first", irCache)
	}
	type example struct{ where, py, go_ string }
	mismatches := map[string]int{}
	examples := map[string][]example{}
	known := map[string]bool{}
	packages, artifacts := 0, 0
	for _, src := range sources {
		files, _ := os.ReadDir(filepath.Join(irCache, src.Name()))
		for _, f := range files {
			name := strings.TrimSuffix(f.Name(), ".jsonl")
			pkgDir := filepath.Join("../../corpus", src.Name(), name)
			if i := strings.LastIndex(name, "__"); i >= 0 && src.Name() == "pytest" {
				pkgDir = filepath.Join("../../corpus", src.Name(), name[:i], name[i+2:])
			}
			if _, err := os.Stat(pkgDir); err != nil {
				continue
			}
			data, err := os.ReadFile(filepath.Join(irCache, src.Name(), f.Name()))
			if err != nil {
				t.Fatal(err)
			}
			py, err := oracleDocs(data)
			if err != nil {
				t.Fatal(f.Name(), err)
			}
			packages++
			p := Parse(ingest.BuildPackage(pkgDir))
			for _, a := range p.Artifacts {
				artifacts++
				want, ok := py[a.Rel]
				where := src.Name() + "/" + name + ":" + a.Rel
				if !ok {
					mismatches["artifact"]++
					examples["artifact"] = append(examples["artifact"], example{where, "present", "absent in oracle dump"})
					continue
				}
				got := irDoc(a, p.Refs)
				for _, field := range m2Fields {
					pv, gv := want[field], got[field]
					if field == "diagnostics" {
						pv, gv = m2Diagnostics(pv), m2Diagnostics(gv)
					}
					ps, gs := pytext.Canonical(pv), pytext.Canonical(gv)
					if ps == gs {
						continue
					}
					if knownFactDiffs[where] == field {
						known[where] = true
						continue
					}
					mismatches[field]++
					if len(examples[field]) < 10 {
						examples[field] = append(examples[field], example{where, pytext.Head(ps, 200), pytext.Head(gs, 200)})
					}
				}
			}
		}
	}
	fields := slices.Sorted(maps.Keys(mismatches))
	total := 0
	for _, f := range fields {
		total += mismatches[f]
	}
	t.Logf("packages %d, artifacts %d, facts %d (%d fields per artifact), known differences %d, other mismatching facts %d",
		packages, artifacts, artifacts*len(m2Fields), len(m2Fields), len(known), total)
	for _, f := range fields {
		t.Logf("%s: %d mismatches", f, mismatches[f])
		for _, e := range examples[f] {
			t.Logf("  %s\n    py: %s\n    go: %s", e.where, e.py, e.go_)
		}
	}
	if total > 0 {
		t.Errorf("%d facts differ from the oracle beyond knownFactDiffs", total)
	}
	for where := range knownFactDiffs {
		if !known[where] {
			t.Errorf("%s no longer differs from the oracle: drop it from knownFactDiffs", where)
		}
	}
}
