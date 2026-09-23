// Command bench runs the scanner over an export of ProtectSkills/MaliciousSkillBench and scores
// the rows.
//
//	go run ./tools/bench run --data <split.jsonl> --out <rows.jsonl> [--workers N] [--work DIR] [--opengrep-bin PATH]
//	go run ./tools/bench score [--md FILE] [--title TITLE] [--compare BASE.jsonl] [--exclude-vectors V,V] [--effective] <rows.jsonl>
//
// The export is one JSON object per record of the pinned revision's source-disjoint split with
// the keys benchmark_id, split, label, source_name, attack_categories and text (skill_text, else
// public_skill_text); run refuses a file whose sorted id list is not the pinned test or dev
// split. Each record is written as <work>/msb-work-*/<sanitised id>-<sha1 prefix>/SKILL.md,
// scanned in process with the deterministic checks and the pinned OpenGrep, then removed; nothing
// is executed. A record that errors, is oversize or leaves a file unread is recorded as such,
// never as clean. An interrupt stops the feed, lets the running scans finish and removes the
// scratch root; the rows written so far stay in the output file.
package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/scan"
)

// datasetRevision is the dataset commit the pinned id lists come from.
const datasetRevision = "d4b42ce5766a6e0359c987cf59c1007cb3795a90"

// pinnedSplits holds, per split, the SHA-256 of its sorted benchmark_id list joined by newlines,
// as the dataset's frozen manifest records it at datasetRevision. The pin fixes the identity list
// of a split; labels and texts come from the export as they are.
var pinnedSplits = map[string]string{
	"test": "3cf59383d752094a9d25022d8bd90890db8ad6d1b54620af8088ff1b8ae0b7bb",
	"dev":  "f01c122ea57d0a73c153cdbcc685a87a0af0be85f8a3115112253c6224b6e457",
}

// record is one exported dataset row.
type record struct {
	BenchmarkID      string   `json:"benchmark_id"`
	Split            string   `json:"split"`
	Label            int      `json:"label"`
	SourceName       string   `json:"source_name"`
	AttackCategories []string `json:"attack_categories"`
	Text             string   `json:"text"`
}

// row is one scanned record as run writes it and score reads it.
type row struct {
	BenchmarkID      string    `json:"benchmark_id"`
	Split            string    `json:"split"`
	Label            int       `json:"label"`
	SourceName       string    `json:"source_name"`
	AttackCategories []string  `json:"attack_categories"`
	TLen             int       `json:"tlen"`
	Oversize         bool      `json:"oversize"`
	Findings         []finding `json:"findings"`
	Error            *string   `json:"error"`
	LedgerSkipped    int       `json:"ledger_skipped"`
	Analyzed         int       `json:"analyzed"`
	ElapsedMs        int64     `json:"elapsed_ms"`
}

// finding is the scored view of one finding. The two effective fields come only from rows an
// LLM review wrote and are read under score --effective.
type finding struct {
	Vector            string  `json:"vector"`
	Rule              string  `json:"rule"`
	Severity          string  `json:"severity"`
	Tier              *string `json:"tier"`
	Line              *int    `json:"line"`
	EffectiveSeverity string  `json:"effective_severity,omitempty"`
	Disposition       string  `json:"disposition,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "score":
		err = cmdScore(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: bench run|score [flags]")
	os.Exit(2)
}

func cmdRun(args []string) (err error) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	data := fs.String("data", "", "the split export, one JSON record per line")
	out := fs.String("out", "", "where to write one JSON row per record")
	workers := fs.Int("workers", max(4, runtime.NumCPU()-1), "concurrent scans")
	work := fs.String("work", "", "parent of the scratch directory (default: the system temp dir)")
	opengrepBin := fs.String("opengrep-bin", "", "an explicit OpenGrep binary (default: the pinned one)")
	fs.Parse(args)
	if *data == "" || *out == "" {
		return errors.New("run needs --data and --out")
	}
	if *workers < 1 {
		return errors.New("run needs at least one worker")
	}
	records, err := loadRecords(*data)
	if err != nil {
		return err
	}
	split, ok := pinnedSplit(records)
	if !ok {
		return fmt.Errorf("the %d ids in %s are not a pinned split of MaliciousSkillBench %s", len(records), *data, datasetRevision[:12])
	}
	dir, err := os.MkdirTemp(*work, "msb-work-")
	if err != nil {
		return err
	}
	defer func() { // a staged text left on disk is a failed run, whatever the rows say
		if e := os.RemoveAll(dir); e != nil {
			err = errors.Join(err, fmt.Errorf("scratch directory %s was not removed: %w", dir, e))
		}
	}()
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	start := time.Now()
	var mu sync.Mutex
	var wg sync.WaitGroup
	done, failed := 0, 0
	var writeErr error
	next := make(chan record)
	for range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rec := range next {
				r := scanOne(dir, rec, *opengrepBin)
				line, _ := json.Marshal(r)
				mu.Lock()
				if _, err := f.Write(append(line, '\n')); err != nil && writeErr == nil {
					writeErr = err
				}
				done++
				if r.Error != nil {
					failed++
				}
				if done%250 == 0 || done == len(records) {
					fmt.Fprintf(os.Stderr, "  %d/%d  errors=%d  %.0fs\n", done, len(records), failed, time.Since(start).Seconds())
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, rec := range records {
		if ctx.Err() != nil {
			break // a ready send must not win the select over a finished context
		}
		select {
		case next <- rec:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	if err := f.Close(); err != nil && writeErr == nil {
		writeErr = err
	}
	if writeErr != nil {
		return writeErr
	}
	if ctx.Err() != nil {
		return fmt.Errorf("interrupted after %d of %d records; %s holds the rows written so far", done, len(records), *out)
	}
	fmt.Fprintf(os.Stderr, "done: split %s, %d records, %d errors, %.1fs, %s\n", split, len(records), failed, time.Since(start).Seconds(), *out)
	return nil
}

// loadRecords reads the export; a record without a label, or with a label other than 0 or 1,
// is refused rather than scored as benign.
func loadRecords(path string) ([]record, error) {
	var out []record
	err := decodeLines(path, func(dec *json.Decoder) error {
		var rec struct {
			record
			Label *int `json:"label"`
		}
		if err := dec.Decode(&rec); err != nil {
			return err
		}
		if err := checkLabel(rec.BenchmarkID, rec.Label); err != nil {
			return err
		}
		rec.record.Label = *rec.Label
		out = append(out, rec.record)
		return nil
	})
	return out, err
}

// loadRows reads the rows a run wrote, or rows an LLM review rewrote, with the same label check
// as loadRecords: a row without a label of 0 or 1 is refused, never counted as benign, and so is
// a repeated identity, which a score would count twice and a comparison only once.
func loadRows(path string) ([]row, error) {
	var out []row
	seen := map[string]bool{}
	err := decodeLines(path, func(dec *json.Decoder) error {
		var r struct {
			row
			Label *int `json:"label"`
		}
		if err := dec.Decode(&r); err != nil {
			return err
		}
		if err := checkLabel(r.BenchmarkID, r.Label); err != nil {
			return err
		}
		if seen[r.BenchmarkID] {
			return fmt.Errorf("benchmark_id %q appears twice", r.BenchmarkID)
		}
		seen[r.BenchmarkID] = true
		r.row.Label = *r.Label
		out = append(out, r.row)
		return nil
	})
	return out, err
}

func checkLabel(id string, label *int) error {
	if label == nil || (*label != 0 && *label != 1) {
		return fmt.Errorf("benchmark_id %q: label must be 0 or 1", id)
	}
	return nil
}

// decodeLines calls decode once per JSON value in the file, up to a clean end of input; any
// trailing content that is not a value is an error.
func decodeLines(path string, decode func(*json.Decoder) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for n := 1; ; n++ {
		switch err := decode(dec); {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return fmt.Errorf("%s: record %d: %w", path, n, err)
		}
	}
}

// pinnedSplit names the pinned split whose id list the records are, exactly. The list is joined
// by newlines, so an id that carries one can never match.
func pinnedSplit(records []record) (string, bool) {
	ids := make([]string, len(records))
	for i, r := range records {
		if strings.ContainsRune(r.BenchmarkID, '\n') {
			return "", false
		}
		ids[i] = r.BenchmarkID
	}
	slices.Sort(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	digest := hex.EncodeToString(sum[:])
	for name, want := range pinnedSplits {
		if digest == want {
			return name, true
		}
	}
	return "", false
}

var unsafeID = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// dirName keeps every record in its own child of the scratch root whatever its id contains:
// the id is data, not a path.
func dirName(id string) string {
	stem := unsafeID.ReplaceAllString(id, "_")
	if len(stem) > 40 {
		stem = stem[:40]
	}
	sum := sha1.Sum([]byte(id))
	return stem + "-" + hex.EncodeToString(sum[:])[:10]
}

func ptr(s string) *string { return &s }

// scanOne writes the record as <work>/<dirName>/SKILL.md, scans it and removes it. A failure
// is recorded on the row as its error, never dropped.
func scanOne(work string, rec record, opengrepExe string) (r row) {
	r = row{BenchmarkID: rec.BenchmarkID, Split: rec.Split, Label: rec.Label, SourceName: rec.SourceName,
		AttackCategories: rec.AttackCategories, TLen: utf8.RuneCountInString(rec.Text),
		Oversize: int64(len(rec.Text)) > ingest.MaxFileBytes, Findings: []finding{}}
	if r.AttackCategories == nil {
		r.AttackCategories = []string{}
	}
	if rec.Text == "" {
		r.Error = ptr("record has no text")
		return r
	}
	root := filepath.Join(work, dirName(rec.BenchmarkID))
	start := time.Now()
	defer func() {
		if p := recover(); p != nil {
			r.Error = ptr(fmt.Sprintf("%T: %.200v", p, p))
		}
		r.ElapsedMs = time.Since(start).Milliseconds()
		if err := os.RemoveAll(root); err != nil { // the text stayed on disk, so the row is not a clean one
			msg := "cleanup: " + err.Error()
			if r.Error != nil {
				msg = *r.Error + "; " + msg
			}
			r.Error = ptr(msg)
		}
	}()
	fail := func(err error) row {
		r.Error = ptr(err.Error())
		return r
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fail(err)
	}
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte(rec.Text), 0o644); err != nil {
		return fail(err)
	}
	if err := scanRoot(root, opengrepExe, &r); err != nil {
		return fail(err)
	}
	return r
}

// scanRoot scans the one-file package staged at root into r. Nothing read and nothing skipped
// means the file vanished after it was written, as an antivirus quarantine removes it; that is
// an error, not a clean scan.
func scanRoot(root, opengrepExe string, r *row) error {
	p := ingest.BuildPackage(root)
	ledger := ingest.BuildLedger(p)
	r.LedgerSkipped, r.Analyzed = ledger.ArtifactsSkipped, ledger.ArtifactsAnalyzed
	if r.Analyzed == 0 && r.LedgerSkipped == 0 {
		return errors.New("empty package: SKILL.md was not found")
	}
	for _, f := range scan.Scan(parse.Parse(p), nil, opengrepExe) {
		r.Findings = append(r.Findings, findingRow(f))
	}
	return nil
}

func findingRow(f findings.Finding) finding {
	out := finding{Vector: f.Vector, Rule: f.Rule, Severity: f.Severity, Line: f.Line}
	if m, ok := findings.Vectors[f.Vector]; ok {
		out.Tier = &m.Tier
	}
	return out
}
