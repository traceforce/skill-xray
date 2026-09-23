package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/sarif"
	"github.com/traceforce/skill-xray/internal/scan"
)

type systemOptions struct {
	llmFlags
	output, opengrepBin string
	roots               []string
}

func (s *systemOptions) bind(c *cobra.Command) {
	f := c.Flags()
	f.StringVarP(&s.output, "output", "o", defaultReport, "write one validated SARIF document here, with one run per package; the path must be outside every scanned package")
	f.StringVar(&s.opengrepBin, "opengrep-bin", "", "explicit pinned OpenGrep binary")
	f.StringArrayVar(&s.roots, "root", nil, "scan the packages under this directory instead of the known agent skill roots (repeatable)")
	s.llmFlags.bind(c)
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

// reportHeadline is the verdict as the report states it: a result the operator policy or a
// validated review suppressed does not count, and a demoted one counts at its effective
// severity, so the console agrees with the dispositions in the report. When the correlation
// failed, the report has no results and the preserved findings stand, so an incomplete scan
// never reads as clean.
func reportHeadline(report *scan.ScanReport) string {
	if report.Correlation == nil || len(report.Correlation.Errors) > 0 {
		return headline(report.Findings)
	}
	var fs []findings.Finding
	for _, r := range report.Correlation.Results {
		if r.Decision != nil && r.Disposition == "suppressed" {
			continue
		}
		vector, _ := r.Finding["vector"].(string)
		severity, _ := r.Finding["severity"].(string)
		if r.Decision != nil && r.EffectiveSeverity != "" {
			severity = r.EffectiveSeverity
		}
		fs = append(fs, findings.Finding{Vector: vector, Severity: severity})
	}
	return headline(fs)
}

// run is system-scan: every package under the roots, analyzed in turn as "scan" would, into one
// report with a run per package. The exit is 0 when every package was analyzed and discovery
// was complete, else 2.
func (s *systemOptions) run(changed func(string) bool, stdout, stderr io.Writer) (int, error) {
	if changed("output") && s.output == "" {
		return 2, errors.New("--output requires a non-empty path")
	}
	client, err := s.client()
	if err != nil {
		return 2, err
	}
	d := ingest.Discover(s.roots)
	if _, err := sarif.CheckTarget(s.output, d.Paths...); err != nil { // before any package is read, so a report inside one is never scanned
		fmt.Fprintf(stderr, "cannot write SARIF: %s\n", pytext.UnicodeEscape(err.Error()))
		return 2, nil
	}
	rc := 0
	var sarifErr error
	var merged map[string]any
	counts := map[string]int{}
	var lane llmSummary
	for _, path := range d.Paths {
		p := ingest.BuildPackage(path)
		parsed := parse.Parse(p)
		report, err := scanReport(parsed, s.scanOptions(client, s.opengrepBin, nil))
		if err != nil {
			panic(err) // the flag checks in client exclude scan_report's argument errors
		}
		v := reportHeadline(report)
		counts[v]++
		if incomplete(report) {
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
		lane.add(report)
	}
	lane.line(stdout)
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
		fmt.Fprintf(stdout, "report: %s\n", console(s.output))
	}
	fmt.Fprintf(stdout, "packages: %d, blocking: %d, with findings: %d, clean: %d, discovery exceptions: %d\n",
		len(d.Paths), counts["BLOCKING"], counts["FINDINGS"], counts["CLEAN"], len(d.LedgerExceptions))
	if reportGaps(stderr, d) {
		rc = 2
	}
	return rc, nil
}

// writeRuns writes the merged document under sarif.Write's rules, sarif.CheckTarget first: the
// encoding is canonical and capped at 64 MiB, and the target is replaced atomically through a
// temporary file beside it. Each run was validated on its own, since the validator reads a
// single-run document.
func writeRuns(doc map[string]any, target string, packageRoots []string) error {
	target, err := sarif.CheckTarget(target, packageRoots...)
	if err != nil {
		return err
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

// display is a discovered package path as printed: under the home directory as "~/...", then
// with control characters escaped. Plugin layouts reuse folder names (access/configure), so the
// path, not the name, identifies a package. The prefix is guarded so "/home/al" does not
// abbreviate "/home/alice/x".
func display(p string) string {
	if home, _ := os.UserHomeDir(); home != "" && (p == home || strings.HasPrefix(p, home+string(os.PathSeparator))) {
		p = "~" + p[len(home):]
	}
	return console(p)
}

// reportGaps prints every traversal gap discovery hit and reports whether there was one.
func reportGaps(stderr io.Writer, d ingest.Discovery) bool {
	for _, e := range d.LedgerExceptions {
		fmt.Fprintf(stderr, "skill discovery incomplete (%s): %s\n", e.ReasonCode, pytext.UnicodeEscape(e.Path))
	}
	return len(d.LedgerExceptions) > 0
}
