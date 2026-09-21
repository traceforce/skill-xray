package parse

// Two-engine fact diff for the markdown fields of the IR (parse.md R5): every markdown artifact
// of corpus/pytest and corpus/msb-test parsed by parse.Parse against tools/parity/py_dump_ir.py
// run on the oracle. Oracle dumps are cached as corpus/ir-py/<source>/<slug>__<pkg>.jsonl (the
// layout parse_facts_test.go reads); a package without a cached dump is dumped first with
// PYTHONPATH=<oracle>/src python tools/parity/py_dump_ir.py <pkg>.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/pytext"
)

var mdFields = []string{"fences", "fence_spans", "code_spans", "prose_spans", "reference_spans",
	"paragraph_spans", "links", "fallback_links", "html_comments", "html_prose", "html_uninspectable",
	"has_html", "has_uninspectable_html", "preprocessing", "preprocessing_counts", "refs"}

type corpusPackage struct{ source, rel, dir string }

// corpusPackages lists corpus/pytest (manifest order) and corpus/msb-test (directory order).
func corpusPackages() []corpusPackage {
	var out []corpusPackage
	if f, err := os.Open("../../corpus/pytest/manifest.jsonl"); err == nil {
		seen := map[string]bool{}
		for sc := bufio.NewScanner(f); sc.Scan(); {
			var row struct{ Package string }
			if json.Unmarshal(sc.Bytes(), &row) == nil && row.Package != "" && !seen[row.Package] {
				seen[row.Package] = true
				out = append(out, corpusPackage{"pytest", row.Package, filepath.Join("../../corpus/pytest", row.Package)})
			}
		}
		f.Close()
	}
	if entries, err := os.ReadDir("../../corpus/msb-test"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, corpusPackage{"msb-test", e.Name(), filepath.Join("../../corpus/msb-test", e.Name())})
			}
		}
	}
	return out
}

func (p corpusPackage) cachePath() string {
	return filepath.Join("../../corpus/ir-py", p.source, strings.ReplaceAll(p.rel, "/", "__")+".jsonl")
}

// oracleDump runs py_dump_ir.py on the package and caches its output; the cached bytes are returned.
func oracleDump(p corpusPackage) ([]byte, error) {
	if data, err := os.ReadFile(p.cachePath()); err == nil {
		return data, nil
	}
	oracle := os.Getenv("SKILLXRAY_ORACLE")
	if oracle == "" {
		oracle = "../../../_reference/skill-xray-oracle"
	}
	cmd := exec.Command("python", "../../tools/parity/py_dump_ir.py", p.dir)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(oracle, "src"))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %v", p.dir, err)
	}
	if err := os.MkdirAll(filepath.Dir(p.cachePath()), 0o755); err != nil {
		return nil, err
	}
	return out, os.WriteFile(p.cachePath(), out, 0o644)
}

func oracleDocs(data []byte) (map[string]map[string]any, error) {
	docs := map[string]map[string]any{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		dec := json.NewDecoder(strings.NewReader(sc.Text()))
		dec.UseNumber()
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			return nil, err
		}
		docs[fmt.Sprint(doc["rel"])] = doc
	}
	return docs, sc.Err()
}

// firstDiff locates the first differing element of two JSON lists and its "line" (0 when none),
// so the report can quote the source construct behind a mismatch.
func firstDiff(py, gov any) (int, string, string) {
	pl, pok := py.([]any)
	gl, gok := gov.([]any)
	if !pok || !gok {
		return 0, pytext.Canonical(py), pytext.Canonical(gov)
	}
	for i := 0; i < len(pl) || i < len(gl); i++ {
		var pv, gv any
		if i < len(pl) {
			pv = pl[i]
		}
		if i < len(gl) {
			gv = gl[i]
		}
		if ps, gs := pytext.Canonical(pv), pytext.Canonical(gv); ps != gs {
			line := 0
			for _, v := range []any{pv, gv} {
				switch x := v.(type) {
				case map[string]any:
					fmt.Sscan(fmt.Sprint(x["line"]), &line)
				case []any:
					if len(x) > 0 {
						fmt.Sscan(fmt.Sprint(x[0]), &line)
					}
				}
				if line > 0 {
					break
				}
			}
			return line, ps, gs
		}
	}
	return 0, "", ""
}

func TestMarkdownFactsMatchOracle(t *testing.T) {
	pkgs := corpusPackages()
	if len(pkgs) == 0 {
		t.Skip("corpus/pytest and corpus/msb-test absent (make corpus)")
	}
	dumps := make([][]byte, len(pkgs))
	errs := make([]error, len(pkgs))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				dumps[i], errs[i] = oracleDump(pkgs[i])
			}
		}()
	}
	for i := range pkgs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	type example struct{ where, construct, py, go_ string }
	var (
		files, facts, oracleErrors int
		perSource                  = map[string][2]int{} // files, mismatching files
		mismatches                 = map[string]int{}
		examples                   = map[string][]example{}
	)
	for i, p := range pkgs {
		if errs[i] != nil {
			oracleErrors++
			t.Logf("oracle dump failed: %v", errs[i])
			continue
		}
		want, err := oracleDocs(dumps[i])
		if err != nil {
			t.Fatalf("%s: %v", p.cachePath(), err)
		}
		parsed := Parse(ingest.BuildPackage(p.dir))
		for _, a := range parsed.Artifacts {
			if !markdownKinds[a.Kind] || a.Text == nil {
				continue
			}
			doc, ok := want[a.Rel]
			if !ok {
				continue
			}
			files++
			counts := perSource[p.source]
			counts[0]++
			got := irDoc(a, parsed.Refs)
			bad := false
			for _, field := range mdFields {
				facts++
				ps, gs := pytext.Canonical(doc[field]), pytext.Canonical(got[field])
				if ps == gs {
					continue
				}
				bad = true
				mismatches[field]++
				if len(examples[field]) < 10 {
					line, pv, gv := firstDiff(doc[field], got[field])
					construct := ""
					if lines := strings.Split(*a.Text, "\n"); line > 0 && line <= len(lines) {
						construct = fmt.Sprintf("L%d: %q", line, pytext.Head(lines[line-1], 160))
					}
					examples[field] = append(examples[field], example{p.source + "/" + p.rel + ":" + a.Rel, construct, pytext.Head(pv, 240), pytext.Head(gv, 240)})
				}
			}
			if bad {
				counts[1]++
			}
			perSource[p.source] = counts
		}
	}
	fields := make([]string, 0, len(mismatches))
	total := 0
	for f, n := range mismatches {
		fields = append(fields, f)
		total += n
	}
	sort.Strings(fields)
	t.Logf("packages %d (oracle errors %d), markdown files compared %d, facts compared %d (%d fields), mismatching facts %d",
		len(pkgs), oracleErrors, files, facts, len(mdFields), total)
	for _, s := range []string{"pytest", "msb-test"} {
		t.Logf("%s: %d files, %d with a mismatch", s, perSource[s][0], perSource[s][1])
	}
	for _, f := range fields {
		t.Logf("%s: %d mismatching files", f, mismatches[f])
		for _, e := range examples[f] {
			t.Logf("  %s %s\n    py: %s\n    go: %s", e.where, e.construct, e.py, e.go_)
		}
	}
	if total > 0 {
		t.Errorf("%d markdown facts differ from the oracle", total)
	}
}
