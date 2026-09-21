// Command parity drives the Python oracle and the Go CLI over the corpus (00-overview section 6).
//
//	go run ./tools/parity run|dump-ir|attribute [flags]
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/opengrep"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "dump-ir":
		err = cmdDumpIR(os.Args[2:])
	case "attribute":
		err = cmdAttribute(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "parity:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: parity run|dump-ir|attribute [flags]")
	os.Exit(2)
}

// corpusFlags are shared by run and dump-ir.
type corpusFlags struct {
	corpora, extra []string
}

func (c *corpusFlags) bind(fs *flag.FlagSet) {
	fs.Func("corpus", "corpus directory (repeatable; default corpus/pytest and corpus/msb-test)",
		func(s string) error { c.corpora = append(c.corpora, s); return nil })
	fs.Func("extra", "extra package directory (repeatable)",
		func(s string) error { c.extra = append(c.extra, s); return nil })
}

// packages lists every package of the corpora (an absent corpus is skipped with one stderr line)
// and the extras; no package at all is an error, so the gate cannot pass vacuously.
func (c *corpusFlags) packages() ([]testutil.Pkg, error) {
	corpora := c.corpora
	if len(corpora) == 0 && len(c.extra) == 0 {
		corpora = []string{"corpus/pytest", "corpus/msb-test"}
	}
	var out []testutil.Pkg
	for _, dir := range corpora {
		root, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		list, err := testutil.ListCorpus(root)
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "parity: corpus %s absent, skipped\n", dir)
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, list...)
	}
	for _, dir := range c.extra {
		root, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		out = append(out, testutil.Pkg{Source: "extra", Path: root, Root: filepath.Dir(root)})
	}
	if len(out) == 0 {
		return nil, errors.New("no packages: every corpus is absent")
	}
	return out, nil
}

// oracleFlags locate the Python oracle and the interpreter.
type oracleFlags struct {
	oracle, python string
}

func (o *oracleFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&o.oracle, "oracle", ".", "checkout holding the Python scanner (src/ and tests/)")
	fs.StringVar(&o.python, "python", "python", "Python interpreter")
}

// env returns the process environment without SKILLXRAY_LLM_* and with the oracle on PYTHONPATH.
func (o *oracleFlags) env() []string {
	var out []string
	pythonPath := filepath.Join(o.oracle, "src")
	for _, kv := range os.Environ() {
		key, val, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(strings.ToUpper(key), "SKILLXRAY_LLM_"):
		case strings.EqualFold(key, "PYTHONPATH"):
			pythonPath += string(os.PathListSeparator) + val
		default:
			out = append(out, kv)
		}
	}
	return append(out, "PYTHONPATH="+pythonPath)
}

// pin records the oracle HEAD and porcelain status of src and tests.
func (o *oracleFlags) pin() (head string, dirty []string, err error) {
	out, err := exec.Command("git", "-C", o.oracle, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", nil, fmt.Errorf("oracle HEAD: %w", err)
	}
	head = strings.TrimSpace(string(out))
	out, err = exec.Command("git", "-C", o.oracle, "status", "--porcelain", "src", "tests").Output()
	if err != nil {
		return head, nil, fmt.Errorf("oracle status: %w", err)
	}
	dirty = strings.FieldsFunc(string(out), func(r rune) bool { return r == '\n' || r == '\r' })
	return head, dirty, nil
}

const versionsScript = `import sys, json, importlib.metadata as m
out = {"python": sys.version.split()[0]}
for d in ["markdown-it-py", "ruamel.yaml", "tree-sitter-bash", "packaging", "jsonschema", "python-bidi", "confusable-homoglyphs"]:
    try:
        out[d] = m.version(d)
    except Exception:
        out[d] = "absent"
print(json.dumps(out, sort_keys=True))`

func (o *oracleFlags) versions() string {
	cmd := exec.Command(o.python, "-c", versionsScript)
	cmd.Env = o.env()
	out, err := cmd.Output()
	if err != nil {
		return `{"error": "` + err.Error() + `"}`
	}
	return strings.TrimSpace(string(out))
}

// outcome is one command run with a timeout: everything the harness records.
type outcome struct {
	Stdout, Stderr []byte
	Exit           int
	TimedOut       bool
	Elapsed        time.Duration
}

func runCmd(timeout time.Duration, env []string, name string, args ...string) outcome {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	r := outcome{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Elapsed: time.Since(start)}
	var ee *exec.ExitError
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		r.Exit, r.TimedOut = -1, true
	case errors.As(err, &ee):
		r.Exit = ee.ExitCode()
	case err != nil:
		r.Exit = -1
		r.Stderr = append(r.Stderr, []byte("\nparity: "+err.Error())...)
	}
	return r
}

// treeDigest hashes every regular file (relative slash path + bytes) and symlink target under
// root in lexical order.
func treeDigest(root string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "L %s\x00%s\x00", rel, target)
		case d.Type().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "F %s\x00%d\x00", rel, len(data))
			h.Write(data)
		}
		return nil
	})
	return fmt.Sprintf("%x", h.Sum(nil)), err
}

// result is one corpus/parity.jsonl record.
type result struct {
	Source            string         `json:"source"`
	Package           string         `json:"package"`
	Key               string         `json:"key"`
	Cached            bool           `json:"cached"`
	PyExit            int            `json:"py_exit"`
	PyMs              int64          `json:"py_ms"`
	GoExit            *int           `json:"go_exit,omitempty"`
	GoMs              int64          `json:"go_ms,omitempty"`
	Status            string         `json:"status"` // identical, divergent, failed, go-absent, oracle-timeout, oracle-error
	Diffs             int            `json:"diffs"`
	Known             int            `json:"known"`
	FindingsIdentical bool           `json:"findings_identical"`
	TupleIdentical    bool           `json:"tuple_identical"`
	SarifIdentical    bool           `json:"sarif_identical"`
	Groups            map[string]int `json:"groups,omitempty"`
	First             *diff          `json:"first,omitempty"`
	Error             string         `json:"error,omitempty"`
}

// sides holds what each CLI produced for one package.
type sides struct {
	PyJSON, GoJSON   []byte
	PySarif, GoSarif []byte
	PyExit, GoExit   int
}

// comparePackage applies the section 6 normalisation and classification to one package.
func comparePackage(s sides, root string, known []divergence) (diffs []diff, findingsEq, tupleEq, sarifEq bool) {
	pyDoc, perr := parseJSON(s.PyJSON)
	goDoc, gerr := parseJSON(s.GoJSON)
	if perr != nil || gerr != nil {
		diffs = []diff{mk([]string{"$"}, fmt.Sprintf("json: %v", perr), fmt.Sprintf("json: %v", gerr))}
		classify(diffs, known, nil, nil)
		return diffs, false, false, bytes.Equal(s.PySarif, s.GoSarif)
	}
	pyDoc, goDoc = normalize(pyDoc, root, known), normalize(goDoc, root, known)
	compare(pyDoc, goDoc, nil, &diffs)
	findingsEq = !slices.ContainsFunc(diffs, func(d diff) bool { return len(d.Segs) > 0 && d.Segs[0] == "findings" })
	tupleEq = slices.Equal(findingTuples(pyDoc), findingTuples(goDoc))
	sarifEq = bytes.Equal(s.PySarif, s.GoSarif)
	if !sarifEq {
		ps, perr := parseJSON(s.PySarif)
		gs, gerr := parseJSON(s.GoSarif)
		if perr != nil || gerr != nil {
			diffs = append(diffs, mk([]string{"sarif:"}, fmt.Sprintf("json: %v", perr), fmt.Sprintf("json: %v", gerr)))
		} else {
			compare(ps, gs, []string{"sarif:"}, &diffs)
			if len(diffs) == 0 || diffs[len(diffs)-1].Segs[0] != "sarif:" {
				diffs = append(diffs, mk([]string{"sarif:"}, "bytes differ", "bytes differ"))
			}
		}
	}
	if s.PyExit != s.GoExit {
		diffs = append(diffs, mk([]string{"exit"}, s.PyExit, s.GoExit))
	}
	classify(diffs, known, pyDoc, goDoc)
	return diffs, findingsEq, tupleEq, sarifEq
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var cf corpusFlags
	var of oracleFlags
	cf.bind(fs)
	of.bind(fs)
	workers := fs.Int("j", 4, "parallel workers")
	goBin := fs.String("go-bin", defaultGoBin(), "Go CLI (skipped when absent)")
	opengrepBin := fs.String("opengrep-bin", defaultOpengrep(), "pinned OpenGrep binary passed to both CLIs")
	cache := fs.String("cache", "corpus-cache", "Python output cache")
	outDir := fs.String("out", "corpus", "where parity-report.md and parity.jsonl are written")
	knownPath := fs.String("known", "tools/parity/known_divergences.json", "accepted divergences")
	timeout := fs.Duration("timeout", 300*time.Second, "per-run timeout")
	fs.Parse(args)

	known, err := loadDivergences(*knownPath)
	if err != nil {
		return err
	}
	head, dirty, err := of.pin()
	if err != nil {
		return err
	}
	pkgs, err := cf.packages()
	if err != nil {
		return err
	}
	_, err = os.Stat(*goBin)
	haveGo := err == nil
	env := of.env()
	start := time.Now()
	results := make([]result, len(pkgs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(*workers, 1))
	for i := range pkgs {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			results[i] = runOne(pkgs[i], head, *cache, of.python, *goBin, haveGo, *opengrepBin, env, *timeout, known)
		})
	}
	wg.Wait()
	elapsed := time.Since(start)

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	var jl bytes.Buffer
	enc := json.NewEncoder(&jl)
	for _, r := range results {
		enc.Encode(r) // decoded-JSON values, ints and strings cannot fail to encode
	}
	if err := os.WriteFile(filepath.Join(*outDir, "parity.jsonl"), jl.Bytes(), 0o644); err != nil {
		return err
	}
	report := renderReport(head, dirty, of.versions(), *goBin, haveGo, results, elapsed)
	if err := os.WriteFile(filepath.Join(*outDir, "parity-report.md"), []byte(report), 0o644); err != nil {
		return err
	}
	fmt.Print(report)
	switch {
	case len(dirty) > 0:
		return errors.New("oracle: dirty")
	case !parityHolds(results, haveGo):
		return errors.New("parity does not hold")
	}
	return nil
}

func defaultGoBin() string {
	p := filepath.Join("bin", "skill-xray")
	if runtime.GOOS == "windows" {
		p += ".exe"
	}
	return p
}

// defaultOpengrep is the pinned binary when it is in the cache (the path opengrep.Resolve("")
// returns), else "" so neither CLI gets --opengrep-bin.
func defaultOpengrep() string {
	p := opengrep.CachedExecutable("")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

func cliArgs(pkgDir, sarif, opengrepBin string) []string {
	args := []string{pkgDir, "--analyze", "--enrich", "--json", "--sarif", sarif}
	if opengrepBin != "" {
		args = append(args, "--opengrep-bin", opengrepBin)
	}
	return args
}

// cacheKey is sha256(oracle HEAD, tree digest, corpus-relative path): package, identity and source
// name the directory, so identical trees under different names are different outputs.
// ponytail: two workers still share a key for the same relative path with the same bytes under two
// corpus roots (the same normalised output); no corpus has one. Serialise by key if one appears.
func cacheKey(head string, p testutil.Pkg) (string, error) {
	digest, err := treeDigest(p.Path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(head+"\n"+digest+"\n"+p.Rel()))), nil
}

func runOne(p testutil.Pkg, head, cache, python, goBin string, haveGo bool, opengrepBin string, env []string,
	timeout time.Duration, known []divergence) result {
	r := result{Source: p.Source, Package: filepath.ToSlash(p.Path)}
	key, err := cacheKey(head, p)
	if err != nil {
		r.Status, r.Error = "oracle-error", err.Error()
		return r
	}
	r.Key = key
	dir := filepath.Join(cache, r.Key)
	var s sides
	if data, err := os.ReadFile(filepath.Join(dir, "py.exit")); err == nil {
		r.Cached = true
		fmt.Sscan(string(data), &s.PyExit)
		s.PyJSON, _ = os.ReadFile(filepath.Join(dir, "py.json"))
		s.PySarif, _ = os.ReadFile(filepath.Join(dir, "py.sarif"))
	} else {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			r.Status, r.Error = "oracle-error", err.Error()
			return r
		}
		sarif := filepath.Join(dir, "py.sarif")
		args := append([]string{"-m", "skill_xray.cli"}, cliArgs(p.Path, sarif, opengrepBin)...)
		x := runCmd(timeout, env, python, args...)
		r.PyMs = x.Elapsed.Milliseconds()
		s.PyExit = x.Exit
		s.PyJSON = x.Stdout
		s.PySarif, _ = os.ReadFile(sarif)
		os.WriteFile(filepath.Join(dir, "py.json"), x.Stdout, 0o644)
		os.WriteFile(filepath.Join(dir, "py.stderr"), x.Stderr, 0o644)
		meta, _ := json.Marshal(map[string]any{"package": r.Package, "source": p.Source, "oracle_head": head,
			"py_ms": r.PyMs, "argv": append([]string{python}, args...), "timed_out": x.TimedOut})
		os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o644)
		if x.TimedOut {
			r.Status, r.PyExit = "oracle-timeout", x.Exit
			return r // no py.exit: the next run retries
		}
		os.WriteFile(filepath.Join(dir, "py.exit"), []byte(fmt.Sprint(x.Exit)), 0o644)
	}
	r.PyExit = s.PyExit
	if !haveGo {
		r.Status = "go-absent"
		return r
	}
	sarif := filepath.Join(dir, "go.sarif")
	x := runCmd(timeout, env, goBin, cliArgs(p.Path, sarif, opengrepBin)...)
	r.GoMs = x.Elapsed.Milliseconds()
	r.GoExit = &x.Exit
	if x.TimedOut {
		r.Status, r.Error = "failed", "go: timeout"
		return r
	}
	s.GoExit, s.GoJSON = x.Exit, x.Stdout
	s.GoSarif, _ = os.ReadFile(sarif)
	diffs, findingsEq, tupleEq, sarifEq := comparePackage(s, p.Root, known)
	r.Diffs, r.FindingsIdentical, r.TupleIdentical, r.SarifIdentical = len(diffs), findingsEq, tupleEq, sarifEq
	r.Groups = map[string]int{}
	r.Status = "identical"
	for i := range diffs {
		d := &diffs[i]
		if d.Known {
			r.Known++
			continue
		}
		r.Groups[d.Group]++
		if r.First == nil {
			r.First = d
		}
	}
	switch {
	case r.First != nil:
		r.Status = "failed"
	case r.Known > 0:
		r.Status = "divergent"
	}
	return r
}

// js renders a diff value for the report without HTML escaping ("<absent>" stays readable).
func js(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprint(v)
	}
	return strings.TrimSpace(b.String())
}

func parityHolds(results []result, haveGo bool) bool {
	return !slices.ContainsFunc(results, func(r result) bool {
		return r.Status != "identical" && r.Status != "divergent" && (r.Status != "go-absent" || haveGo)
	})
}

func renderReport(head string, dirty []string, versions, goBin string, haveGo bool, results []result, elapsed time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Parity report\n\n- oracle HEAD: `%s`\n", head)
	if len(dirty) > 0 {
		fmt.Fprintf(&b, "- oracle: dirty (%d entries)\n", len(dirty))
		for _, d := range dirty {
			fmt.Fprintf(&b, "  - `%s`\n", d)
		}
	} else {
		b.WriteString("- oracle: clean\n")
	}
	fmt.Fprintf(&b, "- versions: `%s`\n", versions)
	if haveGo {
		fmt.Fprintf(&b, "- go: `%s`\n", goBin)
	} else {
		fmt.Fprintf(&b, "- go: absent (`%s` not found; oracle-only mode)\n", goBin)
	}
	var pyTotal, goTotal int64
	cached := 0
	for _, r := range results {
		pyTotal += r.PyMs
		goTotal += r.GoMs
		if r.Cached {
			cached++
		}
	}
	fmt.Fprintf(&b, "- packages: %d, wall %s, python cpu-wall %s (%d cached), go cpu-wall %s\n\n",
		len(results), elapsed.Round(time.Millisecond), time.Duration(pyTotal)*time.Millisecond, cached,
		time.Duration(goTotal)*time.Millisecond)

	sources := map[string][]result{}
	for _, r := range results {
		sources[r.Source] = append(sources[r.Source], r)
	}
	b.WriteString("| source | packages | identical | findings_identical | tuple_identical | sarif_identical | divergent | failed | go-absent | oracle-timeout |\n|---|---|---|---|---|---|---|---|---|---|\n")
	groups := map[string]int{}
	for _, s := range slices.Sorted(maps.Keys(sources)) {
		var c struct{ ident, find, tuple, sarif, div, fail, absent, timeout int }
		for _, r := range sources[s] {
			switch r.Status {
			case "identical":
				c.ident++
			case "divergent":
				c.div++
			case "go-absent":
				c.absent++
			case "oracle-timeout":
				c.timeout++
			default:
				c.fail++
			}
			if r.FindingsIdentical {
				c.find++
			}
			if r.TupleIdentical {
				c.tuple++
			}
			if r.SarifIdentical {
				c.sarif++
			}
			for g, n := range r.Groups {
				groups[g] += n
			}
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d |\n", s, len(sources[s]),
			c.ident, c.find, c.tuple, c.sarif, c.div, c.fail, c.absent, c.timeout)
	}
	if len(groups) > 0 {
		b.WriteString("\n| group | unexplained diffs |\n|---|---|\n")
		for _, g := range slices.Sorted(maps.Keys(groups)) {
			fmt.Fprintf(&b, "| %s | %d |\n", g, groups[g])
		}
	}
	b.WriteString("\n## Failed packages\n\n")
	failed := 0
	for _, r := range results {
		if r.Status == "identical" || r.Status == "divergent" || r.Status == "go-absent" {
			continue
		}
		failed++
		fmt.Fprintf(&b, "- `%s` (%s) %s", r.Package, r.Source, r.Status)
		if r.Error != "" {
			fmt.Fprintf(&b, ": %s", r.Error)
		}
		if r.First != nil {
			fmt.Fprintf(&b, "\n  - `%s` -> %s: py `%s` go `%s`", r.First.Path, r.First.Group, js(r.First.Py), js(r.First.Go))
		}
		b.WriteString("\n")
	}
	if failed == 0 {
		b.WriteString("none\n")
	}
	return b.String()
}

func cmdDumpIR(args []string) error {
	fs := flag.NewFlagSet("dump-ir", flag.ExitOnError)
	var cf corpusFlags
	var of oracleFlags
	cf.bind(fs)
	of.bind(fs)
	script := fs.String("py-dump-ir", filepath.Join("tools", "parity", "py_dump_ir.py"), "Python IR dumper")
	outDir := fs.String("out", "corpus", "where ir-parity.jsonl is written")
	knownPath := fs.String("known", "tools/parity/known_divergences.json", "accepted divergences")
	timeout := fs.Duration("timeout", 300*time.Second, "per-run timeout")
	fs.Parse(args)
	known, err := loadDivergences(*knownPath)
	if err != nil {
		return err
	}
	pkgs, err := cf.packages()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	jl, err := os.Create(filepath.Join(*outDir, "ir-parity.jsonl"))
	if err != nil {
		return err
	}
	defer jl.Close()
	enc := json.NewEncoder(jl)
	env := of.env()
	failed := 0
	for _, p := range pkgs {
		rec := map[string]any{"source": p.Source, "package": filepath.ToSlash(p.Path)}
		x := runCmd(*timeout, env, of.python, *script, p.Path)
		rec["py_ms"] = x.Elapsed.Milliseconds()
		if x.Exit != 0 {
			rec["status"], rec["error"] = "oracle-error", strings.TrimSpace(string(x.Stderr))
			failed++
		} else {
			diffs, err := diffIR(x.Stdout, parse.DumpIR(parse.Parse(ingest.BuildPackage(p.Path))), known)
			if err != nil {
				return err
			}
			rec["diffs"] = diffs
			switch {
			case slices.ContainsFunc(diffs, func(d diff) bool { return !d.Known }):
				rec["status"] = "failed"
				failed++
			case len(diffs) > 0:
				rec["status"] = "divergent"
			default:
				rec["status"] = "identical"
			}
		}
		fmt.Fprintf(os.Stdout, "%s\t%s\t%v\n", rec["status"], rec["package"], rec["py_ms"])
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d packages failed", failed)
	}
	return nil
}

// diffIR compares two JSON Lines IR dumps artifact by artifact (keyed by rel); diff paths carry
// the "ir:" marker followed by the artifact rel.
func diffIR(py, gov []byte, known []divergence) ([]diff, error) {
	pyDocs, err := irDocs(py)
	if err != nil {
		return nil, err
	}
	goDocs, err := irDocs(gov)
	if err != nil {
		return nil, err
	}
	all := maps.Clone(pyDocs)
	maps.Copy(all, goDocs)
	var diffs []diff
	for _, rel := range slices.Sorted(maps.Keys(all)) {
		a, aok := pyDocs[rel]
		b, bok := goDocs[rel]
		switch {
		case !aok:
			diffs = append(diffs, mk([]string{"ir:", rel}, absent, "artifact"))
		case !bok:
			diffs = append(diffs, mk([]string{"ir:", rel}, "artifact", absent))
		default:
			compare(a, b, []string{"ir:", rel}, &diffs)
		}
	}
	classify(diffs, known, nil, nil)
	return diffs, nil
}

func irDocs(data []byte) (map[string]any, error) {
	out := map[string]any{}
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		doc, err := parseJSON(line)
		if err != nil {
			return nil, fmt.Errorf("ir dump: %w", err)
		}
		m, _ := doc.(map[string]any)
		out[fmt.Sprint(m["rel"])] = doc
	}
	return out, nil
}

func cmdAttribute(args []string) error {
	fs := flag.NewFlagSet("attribute", flag.ExitOnError)
	knownPath := fs.String("known", "tools/parity/known_divergences.json", "accepted divergences")
	root := fs.String("corpus-root", "", "corpus root rewritten to <corpus> in identity")
	fs.Parse(args)
	rest := fs.Args()
	if len(rest) != 2 && len(rest) != 4 {
		return errors.New("usage: attribute [--known f] [--corpus-root d] py.json go.json [py.sarif go.sarif]")
	}
	known, err := loadDivergences(*knownPath)
	if err != nil {
		return err
	}
	if *root != "" {
		if *root, err = filepath.Abs(*root); err != nil {
			return err
		}
	}
	var s sides
	files := []*[]byte{&s.PyJSON, &s.GoJSON, &s.PySarif, &s.GoSarif}
	for i, p := range rest {
		if *files[i], err = os.ReadFile(p); err != nil {
			return err
		}
	}
	diffs, findingsEq, tupleEq, sarifEq := comparePackage(s, *root, known)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	groups, checks := map[string]int{}, map[string]int{}
	for _, d := range diffs {
		state := "FAIL"
		if d.Known {
			state = "known"
		} else {
			groups[d.Group]++
			if d.Check != "" {
				checks[d.Check]++
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\tpy=%s\tgo=%s\n", state, d.Group, d.Check, d.Path, js(d.Py), js(d.Go))
	}
	fmt.Fprintf(w, "diffs=%d findings_identical=%v tuple_identical=%v sarif_identical=%v groups=%v checks=%v\n",
		len(diffs), findingsEq, tupleEq, sarifEq, groups, checks)
	return nil
}
