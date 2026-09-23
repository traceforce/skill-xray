// Command skill-xray scans agent skill packages. "scan <package>" analyzes a directory, file,
// .zip, https URL or git repository and writes a SARIF report, the only output format, as MCP
// X-Ray does; "system-scan" does the same for every package under the known agent skill roots
// with one run per package; "install-opengrep" fetches the pinned engine and "version" prints the
// version. The console shows one verdict line per package and the report path. Exit is 0 on a
// complete run, else 2: bad usage, a failed ingest or write, incomplete high-severity analysis.
//
//lint:file-ignore ST1005 the oracle's messages are printed verbatim
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

// The seams the tests replace, as package vars.
var (
	llmFromEnv      = llm.FromEnv
	buildClient     = llm.BuildClient
	installOpengrep = opengrep.Install
	scanReport      = scan.Report
	buildSarif      = sarif.Build
	writeSarif      = sarif.Write
	resolveInput    = ingest.Resolve
	resolvePath     = sarif.Resolve
)

// defaultReport is where the report lands when --output is not given, in the working directory.
const defaultReport = "findings.sarif.json"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type options struct {
	llm, llmShadow, llmReview, llmAdditive, llmApply bool
	opengrepBin, output, policy                      string
}

// run is the command line: a usage error prints "skill-xray: error: <msg>" and exits 2.
func run(argv []string, stdout, stderr io.Writer) int {
	var o options
	var s systemOptions
	rc := 0
	root := &cobra.Command{
		Use:           "skill-xray",
		Short:         "Analyze agent skill packages and write SARIF reports.",
		Version:       metadata.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("skill-xray {{.Version}}\n")
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(append([]string{}, argv...))
	scan := &cobra.Command{
		Use:   "scan <package>",
		Short: "Analyze one skill package and write a SARIF report.",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) (err error) {
			rc, err = o.main(c.Flags().Changed, args[0], stdout, stderr)
			return err
		},
	}
	o.bind(scan)
	system := &cobra.Command{
		Use:   "system-scan",
		Short: "Analyze every skill package under the known agent skill roots into one SARIF report.",
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

// bind registers the scan flags.
func (o *options) bind(c *cobra.Command) {
	f := c.Flags()
	f.StringVarP(&o.output, "output", "o", defaultReport, "write the validated SARIF report here; the path must be outside the scanned package")
	f.StringVar(&o.policy, "policy", "", "explicit scoped operator policy applied to the report's dispositions")
	f.StringVar(&o.opengrepBin, "opengrep-bin", "", "explicit pinned OpenGrep binary")
	f.BoolVar(&o.llm, "llm", false, "also run the opt-in LLM adjudication pass (semantic prompt injection). "+
		"SENDS THE TEXT of the scanned skill files to the configured third-party LLM provider, so do not use "+
		"it on confidential packages. Requires SKILLXRAY_LLM_PROVIDER and an API key in the environment")
	f.BoolVar(&o.llmShadow, "llm-shadow", false, "review static candidates only, without additive SXV-038 detection; requires --llm")
	f.BoolVar(&o.llmReview, "llm-review", false, "annotate disputed findings without removing or downgrading them; requires --llm")
	f.BoolVar(&o.llmAdditive, "llm-additive", false, "also run SXV-038 after LLM review, using the remaining shared budget")
	f.BoolVar(&o.llmApply, "llm-apply", false, "let a validated llm-disputed review demote that text-pattern finding to low "+
		"in the correlated results (audited as corrected, never removed); requires --llm-review")
}

// install is the "install-opengrep" subcommand.
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

// verdictLine is the one console line per package: the verdict, the ledger counts and the name.
func verdictLine(w io.Writer, verdict string, l ingest.Ledger, name string) {
	fmt.Fprintf(w, "%-8s  seen=%-3d analyzed=%-3d cov=%5.1f%%  %s\n", verdict, l.ArtifactsSeen, l.ArtifactsAnalyzed, float64(l.CoveragePercent), name)
}

// main is "scan" after argument parsing; a returned error is a usage error.
func (o *options) main(changed func(string) bool, pkg string, stdout, stderr io.Writer) (int, error) {
	if changed("output") && o.output == "" || changed("policy") && o.policy == "" {
		return 2, errors.New("--output and --policy require non-empty paths")
	}
	reviewing := o.llmShadow || o.llmReview
	switch {
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
		cfg, err := llmFromEnv(os.Getenv)
		if err != nil {
			return 2, err
		}
		if cfg == nil {
			return 2, errors.New("--llm needs SKILLXRAY_LLM_PROVIDER and an API key in the environment")
		}
		client = buildClient(*cfg)
	}

	policy, err := o.preflight(pkg)
	if err != nil {
		fmt.Fprintf(stderr, "cannot prepare SARIF: %s\n", pytext.UnicodeEscape(err.Error()))
		return 2, nil
	}
	r, cleanup, err := resolveInput(pkg)
	if err != nil {
		// The package argument and the error text can carry attacker-controlled names (zip
		// members, URLs); escape them like artifact paths.
		fmt.Fprintf(stderr, "cannot ingest %s: %s\n", console(pkg), pytext.UnicodeEscape(err.Error()))
		return 2, nil
	}
	defer cleanup()
	if err := o.contained(r.Root); err != nil {
		fmt.Fprintf(stderr, "cannot prepare SARIF: %s\n", pytext.UnicodeEscape(err.Error()))
		return 2, nil
	}
	p := ingest.BuildPackage(r.Root)
	p.Name = r.Name // friendly name; the root may be a temp dir
	parsed := parse.Parse(p)
	report, err := scanReport(parsed, scan.Options{Client: client, LLMShadow: o.llmShadow, LLMReview: o.llmReview,
		LLMApply: o.llmApply, LLMAdditive: o.llmAdditive, OpengrepExe: o.opengrepBin, DispositionPolicy: policy})
	if err != nil {
		panic(err) // the flag checks above exclude scan_report's argument errors
	}
	fs := report.Findings
	rc := 0
	doc, err := buildSarif(parsed, report)
	if err == nil {
		err = writeSarif(doc, o.output, r.Root)
	}
	if err != nil {
		fmt.Fprintf(stderr, "cannot write SARIF: %s\n", pytext.UnicodeEscape(err.Error()))
		rc = 2
	}
	verdictLine(stdout, reportHeadline(report), ingest.BuildLedger(p), console(pkg))
	if rc == 0 {
		fmt.Fprintf(stdout, "report: %s\n", o.output) // the operator's own path, printed as given
	}
	if incomplete(report, fs) {
		rc = 2
	}
	return rc, nil
}

// preflight runs before the input is read or unpacked: the report must lie outside the package
// path and must not overwrite its source or its operator policy, and the policy must be a regular
// JSON object of at most 512 KiB outside the package path.
func (o *options) preflight(pkg string) (map[string]any, error) {
	report, err := resolvePath(o.output)
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
	if sarif.IsWithinSource(report, source) {
		return nil, errors.New("Report must be outside the scanned package")
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
	if policy == source || sameFile(policy, source) || sarif.IsWithinSource(policy, source) {
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

// contained repeats the two containment checks against the resolved package root once the input
// is materialised and before any file of it is read: an archive or a download unpacks to a root
// that is not the path the operator named.
func (o *options) contained(root string) error {
	root, err := resolvePath(root)
	if err != nil {
		return err
	}
	report, err := resolvePath(o.output)
	if err != nil {
		return err
	}
	if sarif.IsWithinSource(report, root) {
		return errors.New("Report must be outside the scanned package")
	}
	if o.policy == "" {
		return nil
	}
	policy, err := resolvePath(o.policy)
	if err != nil {
		return err
	}
	if sarif.IsWithinSource(policy, root) {
		return errors.New("Operator policy must be outside the scanned package")
	}
	return nil
}

// sameFile is a.exists() and b.exists() and a.samefile(b).
func sameFile(a, b string) bool {
	sa, ea := os.Stat(a)
	sb, eb := os.Stat(b)
	return ea == nil && eb == nil && os.SameFile(sa, sb)
}

// console is a path as the console prints it: every control character is shown as an escape,
// so a name cannot rewrite or hide a line, and everything else, backslashes included, stays as
// typed. Names inside a package still use the stricter pytext.UnicodeEscape.
func console(p string) string {
	var b strings.Builder
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			fmt.Fprintf(&b, `\x%02x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
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
