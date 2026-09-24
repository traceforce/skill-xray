// Command skill-xray scans agent skill packages (cli.py). "scan [package]" inventories a directory,
// file, .zip, https URL or git repository, or with --analyze runs the detection engines over it;
// --scan-known-skills is the inventory-only walk of the known agent skill roots. "system-scan"
// analyzes every package under those roots, "install-opengrep" fetches the pinned engine and
// "version" prints the version; the root still takes the legacy "[package] [flags]" form. Exit is
// 0 on a complete run, else 2: bad usage, a failed ingest or write, incomplete high-severity analysis.
//
//lint:file-ignore ST1005 the oracle's messages are printed verbatim
package main

import (
	"cmp"
	"encoding/json"
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
	"github.com/traceforce/skill-xray/internal/llm"
	"github.com/traceforce/skill-xray/internal/metadata"
	"github.com/traceforce/skill-xray/internal/opengrep"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/sarif"
	"github.com/traceforce/skill-xray/internal/scan"
)

// The names the oracle's tests monkeypatch on the cli module, as package vars.
var (
	llmFromEnv      = llm.FromEnv
	buildClient     = llm.BuildClient
	installOpengrep = opengrep.Install
	scanFn          = scan.Scan
	scanReport      = scan.Report
	buildSarif      = sarif.Build
	writeSarif      = sarif.Write
	resolveInput    = ingest.Resolve
	resolvePath     = sarif.Resolve
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type options struct {
	scanKnown, analyze, llm, enrich, llmShadow, llmReview, llmAdditive, llmApply, installOpengrep, json bool
	opengrepBin, sarif, policy                                                                          string
}

// run is cli.main: a usage error prints "skill-xray: error: <msg>" and exits 2, as argparse does.
// The root runs the legacy "skill-xray [package] [flags]" form through the same code as "scan".
func run(argv []string, stdout, stderr io.Writer) int {
	var o options
	var s systemOptions
	rc := 0
	scanRun := func(c *cobra.Command, args []string) (err error) {
		rc, err = o.main(c.Flags().Changed, cmp.Or(args...), stdout, stderr)
		return err
	}
	root := &cobra.Command{
		Use:           "skill-xray [package]",
		Short:         "Inventory and analyze agent skill packages.",
		Args:          cobra.MaximumNArgs(1),
		Version:       metadata.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          scanRun,
	}
	root.SetVersionTemplate("skill-xray {{.Version}}\n")
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(append([]string{}, argv...))
	o.bind(root)
	scan := &cobra.Command{
		Use:   "scan [package]",
		Short: "Inventory a skill package, or with --analyze run the detection engines over it.",
		Args:  cobra.MaximumNArgs(1),
		RunE:  scanRun,
	}
	o.bind(scan)
	system := &cobra.Command{
		Use:   "system-scan",
		Short: "Analyze every skill package under the known agent skill roots.",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) (err error) {
			rc, err = s.run(c.Flags().Changed, stdout, stderr)
			return err
		},
	}
	s.bind(system)
	root.AddCommand(scan, system,
		&cobra.Command{Use: "install-opengrep", Short: "Download and verify the pinned OpenGrep runtime.", Args: cobra.NoArgs,
			Run: func(*cobra.Command, []string) { rc = install(stdout, stderr) }},
		&cobra.Command{Use: "version", Short: "Print the tool version.", Args: cobra.NoArgs,
			Run: func(*cobra.Command, []string) { fmt.Fprintf(stdout, "skill-xray %s\n", metadata.Version) }})
	if err := root.Execute(); err != nil {
		fmt.Fprintf(stderr, "skill-xray: error: %s\n", err)
		return 2
	}
	return rc
}

// bind registers the scan flags on c; the root and "scan" carry the same set.
func (o *options) bind(c *cobra.Command) {
	f := c.Flags()
	f.BoolVar(&o.scanKnown, "scan-known-skills", false, "walk every package under the known agent skill roots")
	f.BoolVar(&o.analyze, "analyze", false, "run the detection engines and report findings instead of the inventory")
	f.StringVar(&o.opengrepBin, "opengrep-bin", "", "explicit pinned OpenGrep binary for --analyze")
	f.BoolVar(&o.llm, "llm", false, "also run the opt-in LLM adjudication pass (semantic prompt injection). "+
		"SENDS THE TEXT of the scanned skill files to the configured third-party LLM provider, so do not use "+
		"it on confidential packages. Requires SKILLXRAY_LLM_PROVIDER and an API key in the environment")
	f.BoolVar(&o.enrich, "enrich", false, "include capability context and raw candidates with --analyze --json")
	f.BoolVar(&o.llmShadow, "llm-shadow", false, "review static candidates only, without additive SXV-038 detection; requires --llm --json")
	f.BoolVar(&o.llmReview, "llm-review", false, "annotate disputed findings without removing or downgrading them; requires --llm --json")
	f.BoolVar(&o.llmAdditive, "llm-additive", false, "also run SXV-038 after LLM review, using the remaining shared budget")
	f.BoolVar(&o.llmApply, "llm-apply", false, "let a validated llm-disputed review demote that text-pattern finding to low "+
		"in the correlated results (audited as corrected, never removed); requires --llm-review")
	f.BoolVar(&o.installOpengrep, "install-opengrep", false, "download and verify the pinned OpenGrep runtime, then exit")
	f.BoolVar(&o.json, "json", false, "emit the inventory as JSON")
	f.StringVar(&o.sarif, "sarif", "", "write validated SARIF outside the scanned package")
	f.StringVar(&o.policy, "policy", "", "explicit scoped operator policy for --sarif")
}

// install is the --install-opengrep action and the "install-opengrep" subcommand.
func install(stdout, stderr io.Writer) int {
	installed, err := installOpengrep("", nil)
	if err != nil {
		fmt.Fprintf(stderr, "cannot install OpenGrep: %s\n", pytext.UnicodeEscape(err.Error()))
		return 2
	}
	fmt.Fprintf(stdout, "installed OpenGrep %s at %s\n", opengrep.Version, pytext.UnicodeEscape(installed))
	return 0
}

// incomplete is the exit-2 rule of an analysis: a context error, or a high or critical finding
// without a vector (a check or engine that could not run). Findings with a vector never trigger it.
func incomplete(report *scan.ScanReport, fs []findings.Finding) bool {
	return report != nil && len(report.ContextErrors) > 0 || slices.ContainsFunc(fs, func(f findings.Finding) bool {
		return f.Vector == "" && (f.Severity == "critical" || f.Severity == "high")
	})
}

// main is cli.main after argument parsing, in the oracle's order of checks; a returned error is
// a usage error.
func (o *options) main(changed func(string) bool, pkg string, stdout, stderr io.Writer) (int, error) {
	if changed("sarif") && o.sarif == "" || changed("policy") && o.policy == "" {
		return 2, errors.New("--sarif and --policy require non-empty paths")
	}
	reviewing := o.llmShadow || o.llmReview
	analysis := o.analyze || o.opengrepBin != "" || o.llm || o.enrich || o.llmShadow || o.llmAdditive ||
		o.llmReview || o.llmApply || o.sarif != "" || o.policy != ""
	if o.installOpengrep {
		if pkg != "" || o.scanKnown || o.json || analysis {
			return 2, errors.New("--install-opengrep is a standalone action")
		}
		return install(stdout, stderr), nil
	}
	if o.scanKnown {
		if pkg != "" {
			return 2, errors.New("--scan-known-skills takes no package argument")
		}
		if analysis {
			return 2, errors.New("--scan-known-skills does not accept analysis options")
		}
		return scanKnown(o.json, stdout, stderr), nil
	}
	switch {
	case pkg == "":
		return 2, errors.New("provide a package directory, or use --scan-known-skills")
	case o.opengrepBin != "" && !o.analyze:
		return 2, errors.New("--opengrep-bin requires --analyze")
	case o.sarif != "" && !o.analyze:
		return 2, errors.New("--sarif requires --analyze")
	case o.policy != "" && o.sarif == "":
		return 2, errors.New("--policy requires --sarif")
	case (o.enrich || reviewing) && !(o.analyze && o.json):
		return 2, errors.New("--enrich and LLM review require --analyze --json")
	case reviewing && !o.llm:
		return 2, errors.New("LLM review requires explicit --llm opt-in")
	case o.llmShadow && o.llmReview:
		return 2, errors.New("--llm-shadow and --llm-review are mutually exclusive")
	case o.llmAdditive && !reviewing:
		return 2, errors.New("--llm-additive requires --llm-shadow or --llm-review")
	case o.llmApply && !o.llmReview:
		return 2, errors.New("--llm-apply requires --llm-review")
	}

	// The opt-in LLM client is built up front so a misconfiguration fails before the scan runs.
	var client llm.Completer
	if o.llm {
		if !o.analyze {
			return 2, errors.New("--llm requires --analyze")
		}
		cfg, err := llmFromEnv(os.Getenv)
		if err != nil {
			return 2, err
		}
		if cfg == nil {
			return 2, errors.New("--llm needs SKILLXRAY_LLM_PROVIDER and an API key in the environment")
		}
		client = buildClient(*cfg)
	}

	r, cleanup, err := resolveInput(pkg)
	if err != nil {
		// The package argument and the error text can carry attacker-controlled names (zip
		// members, URLs); escape them like artifact paths.
		fmt.Fprintf(stderr, "cannot ingest %s: %s\n", pytext.UnicodeEscape(pkg), pytext.UnicodeEscape(err.Error()))
		return 2, nil
	}
	defer cleanup()
	var policy map[string]any
	if o.sarif != "" {
		if policy, err = o.preflight(pkg, r.Root); err != nil {
			fmt.Fprintf(stderr, "cannot prepare SARIF: %s\n", pytext.UnicodeEscape(err.Error()))
			return 2, nil
		}
	}
	p := ingest.BuildPackage(r.Root)
	p.Name = r.Name // friendly name; the root may be a temp dir
	ledger := ingest.BuildLedger(p)
	doc := map[string]any{"package": p.Name, "identity": p.Identity, "source": pkg, "kind": r.Kind, "ledger": ledger}
	switch {
	case o.analyze:
		parsed := parse.Parse(p)
		var report *scan.ScanReport
		var fs []findings.Finding
		if o.enrich || reviewing || o.sarif != "" {
			if report, err = scanReport(parsed, scan.Options{Client: client, LLMShadow: o.llmShadow, LLMReview: o.llmReview,
				LLMApply: o.llmApply, LLMAdditive: o.llmAdditive, OpengrepExe: o.opengrepBin, DispositionPolicy: policy}); err != nil {
				panic(err) // the flag checks above exclude scan_report's argument errors
			}
			fs = report.Findings
		} else {
			fs = scanFn(parsed, client, o.opengrepBin)
		}
		reportFailed := false
		if o.sarif != "" {
			sarifDoc, err := buildSarif(parsed, report)
			if err == nil {
				err = writeSarif(sarifDoc, o.sarif, r.Root)
			}
			if err != nil {
				fmt.Fprintf(stderr, "cannot write SARIF: %s\n", pytext.UnicodeEscape(err.Error()))
				reportFailed = true
			}
		}
		if o.json {
			analysis := map[string]any{"opengrepVersion": opengrep.Version}
			if client != nil {
				cov := llm.CoverageSummary(parsed, fs)
				if report != nil && report.LLMUsage["advisory_enabled"] == false {
					cov["enabled"], cov["checked"], cov["skipped"], cov["reason"] = false, 0, cov["eligible"], "Additive SXV-038 pass not requested"
				}
				analysis["llmCoverage"] = cov
			}
			doc["analysis"] = analysis
			if o.enrich || reviewing {
				enrichment := report.ToMap()
				doc["findings"], doc["enrichment"] = enrichment["findings"], enrichment
				delete(enrichment, "findings")
			} else {
				doc["findings"] = findings.ToMaps(fs)
			}
			fmt.Fprint(stdout, pytext.Dumps(doc, 2)+"\n")
		} else {
			printFindings(stdout, p.Name, fs)
			if client != nil {
				cov := llm.CoverageSummary(parsed, fs)
				fmt.Fprintf(stdout, "  LLM adjudication: %d eligible, %d checked, %d truncated, %d skipped, %d errored, %d flagged\n",
					cov["eligible"], cov["checked"], cov["truncated"], cov["skipped"], cov["errored"], cov["flagged"])
			}
		}
		if reportFailed || incomplete(report, fs) {
			return 2, nil
		}
	case o.json:
		doc["artifacts"] = artifactRows(p)
		fmt.Fprint(stdout, pytext.Dumps(doc, 2)+"\n")
	default:
		printOne(stdout, p, ledger)
	}
	return 0, nil
}

// preflight is the SARIF block of cli.main: the report must not overwrite its source or its
// operator policy, and the policy must be a regular JSON object of at most 512 KiB outside the
// scanned package. Every failure is reported before the scan starts.
func (o *options) preflight(pkg, root string) (map[string]any, error) {
	report, err := resolvePath(o.sarif)
	if err != nil {
		return nil, err
	}
	source, err := resolvePath(pkg)
	if err != nil {
		return nil, err
	}
	if report == source || sameFile(report, source) {
		return nil, errors.New("Report cannot overwrite its source")
	}
	if o.policy == "" {
		return nil, nil
	}
	policy, err := resolvePath(o.policy)
	if err != nil {
		return nil, err
	}
	if policy == report || sameFile(policy, report) {
		return nil, errors.New("Report cannot overwrite its operator policy")
	}
	if root, err = resolvePath(root); err != nil {
		return nil, err
	}
	if policy == source || sameFile(policy, source) || sarif.IsWithinSource(policy, root) {
		return nil, errors.New("Operator policy must be outside the scanned package")
	}
	if st, err := os.Stat(policy); err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("Operator policy must be a regular file")
	}
	f, err := os.Open(policy) // #nosec G304 -- the operator's policy path, checked by preflight before this read
	if err != nil {
		return nil, err
	}
	defer f.Close()
	contents, err := io.ReadAll(io.LimitReader(f, 512*1024+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > 512*1024 {
		return nil, errors.New("Operator policy exceeds 512 KiB")
	}
	var v any
	if err := json.Unmarshal(contents, &v); err != nil {
		return nil, err
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("Operator policy must be an object")
	}
	return doc, nil
}

// sameFile is a.exists() and b.exists() and a.samefile(b).
func sameFile(a, b string) bool {
	sa, ea := os.Stat(a)
	sb, eb := os.Stat(b)
	return ea == nil && eb == nil && os.SameFile(sa, sb)
}

func artifactRows(p *ingest.Package) []map[string]any {
	rows := make([]map[string]any, 0, len(p.Artifacts))
	for _, a := range p.Artifacts {
		var exception any
		if a.Exception != "" {
			exception = a.Exception
		}
		rows = append(rows, map[string]any{"rel": a.Rel, "role": a.Role, "kind": a.Kind, "read": a.Exception == "", "exception": exception})
	}
	return rows
}

// printOne is the human-readable inventory. Artifact paths are attacker-controlled, so every
// one is escaped: a control character could otherwise rewrite the on-screen inventory to hide a
// file, the one thing this tool must not allow.
func printOne(w io.Writer, p *ingest.Package, l ingest.Ledger) {
	fmt.Fprintf(w, "package: %s\n", pytext.UnicodeEscape(p.Name))
	fmt.Fprintf(w, "  seen=%d analyzed=%d skipped=%d coverage=%.1f%%\n",
		l.ArtifactsSeen, l.ArtifactsAnalyzed, l.ArtifactsSkipped, float64(l.CoveragePercent))
	rels := map[string]bool{}
	for _, a := range p.Artifacts {
		rels[a.Rel] = true
		mark, detail := "read ", ""
		if a.Exception != "" {
			mark, detail = "SKIP ", "  ("+a.Exception+")"
		}
		fmt.Fprintf(w, "  %s %-40s %s%s\n", mark, pytext.UnicodeEscape(a.Rel), a.Kind, detail)
	}
	for _, e := range l.Exceptions {
		if !rels[e.Path] { // directory-level skips: pruned dirs, symlinks, junctions
			fmt.Fprintf(w, "  SKIP  %-40s %s\n", pytext.UnicodeEscape(e.Path), e.ReasonCode)
		}
	}
}

func printFindings(w io.Writer, name string, fs []findings.Finding) {
	fmt.Fprintf(w, "package: %s\n", pytext.UnicodeEscape(name))
	if len(fs) == 0 {
		fmt.Fprint(w, "  no findings\n")
		return
	}
	for _, f := range fs {
		loc := ""
		switch {
		case f.Line != nil:
			loc = fmt.Sprintf("  L%d", *f.Line)
			if f.Column != nil {
				loc += fmt.Sprintf(":%d", *f.Column)
			}
		case f.Offset != nil:
			loc = fmt.Sprintf("  @%d", *f.Offset)
			if f.Length != nil {
				loc += fmt.Sprintf("+%d", *f.Length)
			}
		}
		fmt.Fprintf(w, "  [%-8s] %-8s %-20s %s: %s%s\n", strings.ToUpper(f.Severity), cmp.Or(f.Vector, "-"), f.Rule,
			pytext.UnicodeEscape(f.Path), pytext.UnicodeEscape(f.Message), loc)
	}
}

// scanKnown is _scan_known: every package under the known agent skill roots, ledger only.
func scanKnown(asJSON bool, stdout, stderr io.Writer) int {
	d := ingest.Discover(nil)
	if asJSON {
		rows := make([]map[string]any, len(d.Paths))
		for i, p := range d.Paths {
			rows[i] = map[string]any{"package": filepath.Base(p), "path": p, "ledger": ingest.BuildLedger(ingest.BuildPackage(p))}
		}
		fmt.Fprint(stdout, pytext.Dumps(rows, 2)+"\n")
	} else {
		fmt.Fprintf(stdout, "discovered %d skill package(s) under the known roots\n", len(d.Paths))
		for _, p := range d.Paths {
			l, flag := ingest.BuildLedger(ingest.BuildPackage(p)), ""
			if len(l.ShippedCompiledCode) > 0 {
				flag += fmt.Sprintf("  compiled=%d", len(l.ShippedCompiledCode))
			}
			if len(l.AgentIdentityFiles) > 0 {
				flag += fmt.Sprintf("  identity=%d", len(l.AgentIdentityFiles))
			}
			fmt.Fprintf(stdout, "  seen=%-3d analyzed=%-3d cov=%5.1f%%%s  %s\n",
				l.ArtifactsSeen, l.ArtifactsAnalyzed, float64(l.CoveragePercent), flag, display(p))
		}
	}
	if reportGaps(stderr, d) {
		return 2
	}
	return 0
}

// display is a discovered package path as printed: under the home directory as "~/...", then
// escaped like every attacker-controlled path. Plugin layouts reuse folder names
// (access/configure), so the path, not the name, identifies a package. The prefix is guarded so
// "/home/al" does not abbreviate "/home/alice/x".
func display(p string) string {
	if home, _ := os.UserHomeDir(); home != "" && (p == home || strings.HasPrefix(p, home+string(os.PathSeparator))) {
		p = "~" + p[len(home):]
	}
	return pytext.UnicodeEscape(p)
}

// reportGaps prints every traversal gap discovery hit and reports whether there was one.
func reportGaps(stderr io.Writer, d ingest.Discovery) bool {
	for _, e := range d.LedgerExceptions {
		fmt.Fprintf(stderr, "skill discovery incomplete (%s): %s\n", e.ReasonCode, pytext.UnicodeEscape(e.Path))
	}
	return len(d.LedgerExceptions) > 0
}
