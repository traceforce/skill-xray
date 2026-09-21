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
	"github.com/traceforce/skill-xray/internal/opengrep"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/sarif"
	"github.com/traceforce/skill-xray/internal/scan"
)

type systemOptions struct {
	json               bool
	sarif, opengrepBin string
	roots              []string
}

func (s *systemOptions) bind(c *cobra.Command) {
	f := c.Flags()
	f.BoolVar(&s.json, "json", false, "emit the results as JSON")
	f.StringVar(&s.sarif, "sarif", "", "write one validated SARIF document outside every scanned package")
	f.StringVar(&s.opengrepBin, "opengrep-bin", "", "explicit pinned OpenGrep binary")
	f.StringArrayVar(&s.roots, "root", nil, "scan the packages under this directory instead of the known agent skill roots (repeatable)")
}

// headline is a package's one-word verdict: BLOCKING for a high or critical finding with a vector,
// FINDINGS for anything else reported, CLEAN for nothing.
func headline(fs []findings.Finding) string {
	switch {
	case slices.ContainsFunc(fs, func(f findings.Finding) bool {
		return f.Vector != "" && (f.Severity == "critical" || f.Severity == "high")
	}):
		return "BLOCKING"
	case len(fs) > 0:
		return "FINDINGS"
	}
	return "CLEAN"
}

// run is system-scan: every package under the roots, analyzed in turn as "scan --analyze" would.
// The exit is 0 when every package was analyzed and discovery was complete, else 2.
func (s *systemOptions) run(changed func(string) bool, stdout, stderr io.Writer) (int, error) {
	if changed("sarif") && s.sarif == "" {
		return 2, errors.New("--sarif requires a non-empty path")
	}
	roots := s.roots
	if roots == nil {
		roots = ingest.KnownSkillRoots
	}
	d := ingest.Discover(s.roots)
	rc := 0
	var sarifErr error
	var merged map[string]any
	packages := make([]map[string]any, 0, len(d.Paths))
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
		if s.sarif != "" && sarifErr == nil {
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
		ledger := ingest.BuildLedger(p)
		if s.json {
			packages = append(packages, map[string]any{"package": p.Name, "path": path, "verdict": v, "ledger": ledger,
				"analysis": map[string]any{"opengrepVersion": opengrep.Version}, "findings": findings.ToMaps(fs)})
			continue
		}
		fmt.Fprintf(stdout, "%-8s  seen=%-3d analyzed=%-3d cov=%5.1f%%  %s\n",
			v, ledger.ArtifactsSeen, ledger.ArtifactsAnalyzed, float64(ledger.CoveragePercent), display(path))
		printFindings(stdout, p.Name, fs)
	}
	if s.sarif != "" {
		if merged == nil {
			merged = map[string]any{"version": "2.1.0", "$schema": sarif.SchemaID(), "runs": []any{}}
		}
		if sarifErr == nil {
			sarifErr = writeRuns(merged, s.sarif, d.Paths)
		}
		if sarifErr != nil {
			fmt.Fprintf(stderr, "cannot write SARIF: %s\n", pytext.UnicodeEscape(sarifErr.Error()))
			rc = 2
		}
	}
	if s.json {
		doc := map[string]any{"schema_version": "system-scan-v1", "roots": roots,
			"discovery": map[string]any{"paths": d.Paths, "ledgerExceptions": d.LedgerExceptions},
			"packages":  packages,
			"summary": map[string]any{"packages": len(d.Paths), "blocking": counts["BLOCKING"],
				"withFindings": counts["FINDINGS"], "clean": counts["CLEAN"]}}
		fmt.Fprint(stdout, pytext.Dumps(doc, 2)+"\n")
	} else {
		fmt.Fprintf(stdout, "packages: %d, blocking: %d, with findings: %d, clean: %d, discovery exceptions: %d\n",
			len(d.Paths), counts["BLOCKING"], counts["FINDINGS"], counts["CLEAN"], len(d.LedgerExceptions))
	}
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
