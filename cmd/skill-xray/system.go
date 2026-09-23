package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/sarif"
	"github.com/traceforce/skill-xray/internal/scan"
)

type systemOptions struct {
	output, opengrepBin string
	roots               []string
}

func (s *systemOptions) bind(c *cobra.Command) {
	f := c.Flags()
	f.StringVarP(&s.output, "output", "o", defaultReport, "write one validated SARIF document here, with one run per package; the path must be outside every scanned package")
	f.StringVar(&s.opengrepBin, "opengrep-bin", "", "explicit pinned OpenGrep binary")
	f.StringArrayVar(&s.roots, "root", nil, "scan the packages under this directory instead of the known agent skill roots (repeatable)")
}

// headline is a package's one-word verdict: BLOCKING for a high or critical finding with a vector,
// FINDINGS for any other finding with a vector or a gap at medium or above, CLEAN otherwise; a low
// note stays in the ledger and the report without moving the verdict.
func headline(fs []findings.Finding) string {
	switch {
	case slices.ContainsFunc(fs, func(f findings.Finding) bool {
		return f.Vector != "" && (f.Severity == "critical" || f.Severity == "high")
	}):
		return "BLOCKING"
	case slices.ContainsFunc(fs, func(f findings.Finding) bool { return f.Vector != "" || f.Severity != "low" }):
		return "FINDINGS"
	}
	return "CLEAN"
}

// run is system-scan: every package under the roots, analyzed in turn as "scan" would, into one
// report with a run per package. The exit is 0 when every package was analyzed and discovery
// was complete, else 2.
func (s *systemOptions) run(changed func(string) bool, stdout, stderr io.Writer) (int, error) {
	if changed("output") && s.output == "" {
		return 2, errors.New("--output requires a non-empty path")
	}
	d := ingest.Discover(s.roots)
	rc := 0
	var sarifErr error
	var merged map[string]any
	counts := map[string]int{}
	for _, path := range d.Paths {
		p := ingest.BuildPackage(path)
		parsed := parse.Parse(p)
		report, err := scanReport(parsed, scan.Options{OpengrepExe: s.opengrepBin})
		if err != nil {
			panic(err) // no LLM options, so none of scan_report's argument errors
		}
		fs, v := report.Findings, headline(report.Findings)
		counts[v]++
		if incomplete(report, fs) {
			rc = 2
		}
		if sarifErr == nil {
			doc, err := buildSarif(parsed, report)
			if err == nil {
				err = sarif.Validate(doc)
			}
			switch {
			case err != nil:
				sarifErr = err
			case merged == nil:
				merged = doc
			default:
				merged["runs"] = append(merged["runs"].([]any), doc["runs"].([]any)...)
			}
		}
		verdictLine(stdout, v, ingest.BuildLedger(p), display(path))
	}
	if merged == nil {
		merged = map[string]any{"version": "2.1.0", "$schema": sarif.SchemaID(), "runs": []any{}}
	}
	if sarifErr == nil {
		sarifErr = writeRuns(merged, s.output, d.Paths)
	}
	if sarifErr != nil {
		fmt.Fprintf(stderr, "cannot write SARIF: %s\n", pytext.UnicodeEscape(sarifErr.Error()))
		rc = 2
	} else {
		fmt.Fprintf(stdout, "report: %s\n", s.output) // the operator's own path, printed as given
	}
	fmt.Fprintf(stdout, "packages: %d, blocking: %d, with findings: %d, clean: %d, discovery exceptions: %d\n",
		len(d.Paths), counts["BLOCKING"], counts["FINDINGS"], counts["CLEAN"], len(d.LedgerExceptions))
	if reportGaps(stderr, d) {
		rc = 2
	}
	return rc, nil
}

// writeRuns writes the merged document under sarif.Write's rules: the target is never a symlink,
// never inside any scanned package and never a special file, the encoding is canonical and
// capped at 64 MiB, and the target is replaced atomically through a temporary file beside it.
// Each run was validated on its own, since the validator reads a single-run document.
func writeRuns(doc map[string]any, target string, packageRoots []string) error {
	if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("SARIF output must be outside the scanned package")
	}
	target, err := sarif.Resolve(target)
	if err != nil {
		return err
	}
	for _, root := range packageRoots {
		root, err := sarif.Resolve(root)
		if err != nil {
			return err
		}
		if sarif.IsWithinSource(target, root) {
			return errors.New("SARIF output must be outside the scanned package")
		}
	}
	if info, err := os.Stat(target); err == nil && !info.Mode().IsRegular() {
		return errors.New("SARIF output must be a regular file")
	}
	data := []byte(pytext.Canonical(doc) + "\n")
	if len(data) > 64<<20 {
		return errors.New("SARIF report exceeds 64 MiB; no partial report written")
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".skill-xray-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), target)
}
