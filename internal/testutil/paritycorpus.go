package testutil

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// corpusRoot is corpus/ seen from any internal/<pkg> or tools/<tool> test directory.
const corpusRoot = "../../corpus"

// Pkg is one corpus package: Source is the name of the corpus directory (pytest, msb-test or
// extra), Path the package directory and Root the corpus root its identity is rewritten against.
type Pkg struct{ Source, Path, Root string }

// Rel is the slash path of the package under its corpus root.
func (p Pkg) Rel() string {
	rel, _ := filepath.Rel(p.Root, p.Path)
	return filepath.ToSlash(rel)
}

// ListCorpus reads root/manifest.jsonl (a pytest or msb dump: one row per package, deduplicated,
// a row whose directory is missing skipped with a warning) when present, else lists every
// subdirectory of root.
func ListCorpus(root string) ([]Pkg, error) {
	source := filepath.Base(root)
	manifest := filepath.Join(root, "manifest.jsonl")
	f, err := os.Open(manifest)
	if errors.Is(err, fs.ErrNotExist) {
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		var out []Pkg
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, Pkg{source, filepath.Join(root, e.Name()), root})
			}
		}
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Pkg
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row struct {
			Package string `json:"package"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("%s: %w", manifest, err)
		}
		if row.Package == "" || seen[row.Package] {
			continue
		}
		seen[row.Package] = true
		p := filepath.Join(root, filepath.FromSlash(row.Package))
		if st, err := os.Stat(p); err != nil || !st.IsDir() {
			fmt.Fprintf(os.Stderr, "corpus: manifest package missing on disk: %s\n", p)
			continue
		}
		out = append(out, Pkg{source, p, root})
	}
	return out, sc.Err()
}

// ReadJSON decodes the first JSON document in path with integral numbers as int (00-overview D7).
func ReadJSON(t testing.TB, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return pytext.Intify(doc).(map[string]any)
}

// CachedRun is one cached Python CLI run (tools/parity run fills corpus-cache): the scanned package
// directory and the cache directory holding meta.json, py.json and py.sarif.
type CachedRun struct{ Package, Dir string }

// CachedRuns is every cached run, sorted by key, whose package directory still exists; the test
// skips when the cache is absent.
func CachedRuns(t testing.TB) []CachedRun {
	t.Helper()
	metas, _ := filepath.Glob(filepath.Join("..", "..", "corpus-cache", "*", "meta.json"))
	if len(metas) == 0 {
		t.Skip("corpus-cache absent (go run ./tools/parity run)")
	}
	slices.Sort(metas)
	var runs []CachedRun
	missing := 0
	for _, path := range metas {
		var meta struct{ Package string }
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if _, err := os.Stat(meta.Package); err != nil {
			missing++
			continue
		}
		runs = append(runs, CachedRun{meta.Package, filepath.Dir(path)})
	}
	t.Logf("%d cached runs, %d package dirs missing", len(runs), missing)
	return runs
}

// OracleDir is the checkout holding the Python scanner ($SKILLXRAY_ORACLE, else this repository
// beside the module); the test skips when it, python or the scanner's dependencies are absent.
func OracleDir(t testing.TB) string {
	dir, _ := filepath.Abs(cmp.Or(os.Getenv("SKILLXRAY_ORACLE"), "../.."))
	if _, err := os.Stat(filepath.Join(dir, "src", "skill_xray", "cli.py")); err != nil {
		t.Skip("oracle worktree absent: " + dir)
	}
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("python not on PATH")
	}
	probe := exec.Command("python", "-c", "import skill_xray.analyze")
	probe.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(dir, "src"))
	if out, err := probe.CombinedOutput(); err != nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		t.Skip("python cannot import the scanner (pip install -r requirements.txt): " + lines[len(lines)-1])
	}
	return dir
}

func cachePath(module string, p Pkg) string {
	return filepath.Join(corpusRoot, "findings-py", module, p.Source, strings.ReplaceAll(p.Rel(), "/", "__")+".json")
}

// oracleRecord is one py_dump_findings.py line: the check's findings, or the exception it raised.
type oracleRecord struct {
	Package  string `json:"package"`
	Findings []any  `json:"findings"`
	Error    string `json:"error"`
}

// dumpFindings runs py_dump_findings.py for module over dirs and returns its JSON Lines.
func dumpFindings(t *testing.T, module string, dirs []string) []byte {
	cmd := exec.Command("python", filepath.Join("..", "..", "tools", "parity", "py_dump_findings.py"), module)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(OracleDir(t), "src"))
	cmd.Stdin = strings.NewReader(strings.Join(dirs, "\n") + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("py_dump_findings.py %s: %v\n%s", module, err, stderr.String())
	}
	return out
}

// fillCache runs py_dump_findings.py once over every package without a cached record.
func fillCache(t *testing.T, module string, missing []Pkg) {
	byDir := map[string]Pkg{}
	var dirs []string
	for _, p := range missing {
		byDir[p.Path] = p
		dirs = append(dirs, p.Path)
	}
	for _, line := range bytes.Split(dumpFindings(t, module, dirs), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec oracleRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("py_dump_findings.py %s: %v in %.200s", module, err, line)
		}
		p, ok := byDir[rec.Package]
		if !ok {
			t.Fatalf("py_dump_findings.py %s: unrequested package %q", module, rec.Package)
		}
		if err := os.MkdirAll(filepath.Dir(cachePath(module, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cachePath(module, p), line, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// asJSON round-trips findings through their JSON encoding (Finding.MarshalJSON, the to_dict
// shape) so both sides are compared as decoded JSON values.
func asJSON(fs []findings.Finding) []any {
	data, _ := json.Marshal(fs)
	var out []any
	json.Unmarshal(data, &out)
	return out
}

// js renders a decoded finding compactly with sorted keys.
func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// firstDiffIndex returns the index of the first differing finding, or -1 when the lists are equal.
func firstDiffIndex(py, gov []any) int {
	for i := 0; i < len(py) || i < len(gov); i++ {
		if i >= len(py) || i >= len(gov) || !reflect.DeepEqual(py[i], gov[i]) {
			return i
		}
	}
	return -1
}

// construct quotes the source line a finding points at (whichever side carries path and line).
func construct(dir string, sides ...any) string {
	for _, s := range sides {
		f, ok := s.(map[string]any)
		if !ok {
			continue
		}
		path, _ := f["path"].(string)
		line, _ := f["line"].(float64)
		if path == "" || line < 1 {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		if int(line) <= len(lines) {
			return fmt.Sprintf("%s:%d: %.160s", path, int(line), strings.TrimSpace(lines[int(line)-1]))
		}
	}
	return "(no source position)"
}

// d7 returns the path of the first evidence value outside the D7 set (00-overview), or "". Typed
// slices and maps survive JSON comparison but change the digests correlate derives from evidence.
func d7(where string, v any) string {
	switch x := v.(type) {
	case nil, string, bool, int, float64:
	case []any:
		for i, e := range x {
			if bad := d7(fmt.Sprintf("%s[%d]", where, i), e); bad != "" {
				return bad
			}
		}
	case map[string]any:
		for k, e := range x {
			if bad := d7(where+"."+k, e); bad != "" {
				return bad
			}
		}
	default:
		return fmt.Sprintf("%s is %T", where, v)
	}
	return ""
}

// CheckParity compares check's findings, as JSON, with py_dump_findings.py's output for module on
// every corpus/pytest and corpus/msb-test package; the oracle output is cached under
// corpus/findings-py/<module>.
// known lists "source/rel" packages whose divergence a spec erratum accepts; one that stops
// diverging fails, so the list cannot go stale.
func CheckParity(t *testing.T, module string, check func(pkgDir string) []findings.Finding, known ...string) {
	t.Helper()
	var pkgs []Pkg
	for _, source := range []string{"pytest", "msb-test"} {
		list, _ := ListCorpus(filepath.Join(corpusRoot, source)) // an absent corpus lists nothing
		pkgs = append(pkgs, list...)
	}
	if len(pkgs) == 0 {
		t.Skip("corpus/pytest and corpus/msb-test absent (make corpus)")
	}
	var missing []Pkg
	for _, p := range pkgs {
		if _, err := os.Stat(cachePath(module, p)); err != nil {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		fillCache(t, module, missing)
	}
	identical, accepted, divergent, typed := 0, 0, 0, 0
	for _, p := range pkgs {
		key := p.Source + "/" + p.Rel()
		data, err := os.ReadFile(cachePath(module, p))
		if err != nil {
			t.Fatal(err)
		}
		var rec oracleRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			t.Fatalf("%s: %v", cachePath(module, p), err)
		}
		fs := check(p.Path)
		for j := range fs {
			if bad := d7(fmt.Sprintf("finding[%d].evidence", j), fs[j].Evidence); bad != "" && typed < 5 {
				typed++
				t.Errorf("%s: %s violates D7", key, bad)
			}
		}
		gov := asJSON(fs)
		i := firstDiffIndex(rec.Findings, gov)
		if rec.Error == "" && i < 0 {
			if slices.Contains(known, key) {
				t.Errorf("%s: listed as a known divergence but identical", key)
			}
			identical++
			continue
		}
		if slices.Contains(known, key) {
			accepted++
			continue
		}
		divergent++
		if divergent > 10 {
			continue
		}
		if rec.Error != "" {
			t.Errorf("%s: oracle %s raised %s; go emitted %d findings", key, module, rec.Error, len(gov))
			continue
		}
		var py, gv any = "<absent>", "<absent>"
		if i < len(rec.Findings) {
			py = rec.Findings[i]
		}
		if i < len(gov) {
			gv = gov[i]
		}
		t.Errorf("%s: finding[%d] (py %d, go %d)\n  py %s\n  go %s\n  at %s", key, i,
			len(rec.Findings), len(gov), js(py), js(gv), construct(p.Path, py, gv))
	}
	t.Logf("%s corpus parity: %d packages, %d identical, %d known, %d divergent", module, len(pkgs), identical, accepted, divergent)
}
