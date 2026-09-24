// Command skill-xray scans agent skill packages. "scan <package>" analyzes a directory, file,
// .zip, https URL or git repository and writes a SARIF report, the only output format, as MCP
// X-Ray does; "system-scan" does the same for every package under the known agent skill roots
// with one run per package; "install-opengrep" fetches the pinned engine and "version" prints the
// version. The console shows one verdict line per package and the report path. Exit is 0 on a
// complete run, else 2: bad usage, a failed ingest or write, incomplete high-severity analysis.
//
//lint:file-ignore ST1005 the CLI's messages are a documented contract
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/traceforce/skill-xray/internal/correlate"
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
	llmFlags
	opengrepBin, output, policy string
}

// llmFlags are the opt-in LLM lane switches, the same on scan and system-scan.
type llmFlags struct {
	llm, llmShadow, llmReview, llmAdditive, llmApply bool
}

// run is the command line: a usage error prints "skill-xray: error: <msg>" and exits 2.
func run(argv []string, stdout, stderr io.Writer) int {
	var o options
	var s systemOptions
	rc := 0
	root := &cobra.Command{
		Use:                "skill-xray",
		Short:              "Analyze agent skill packages and write SARIF reports.",
		Version:            metadata.Version,
		SilenceUsage:       true,
		SilenceErrors:      true,
		Args:               cobra.ArbitraryArgs,                          // so the retired root form gets a pointer to scan, not a bare unknown command
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true}, // its retired flags too
		RunE: func(c *cobra.Command, args []string) error {
			if i := slices.IndexFunc(argv, func(a string) bool { return !strings.HasPrefix(a, "-") }); len(args) == 0 && i >= 0 {
				args = argv[i:] // pflag swallowed the package as an unknown flag's value
			}
			switch {
			case len(args) > 0:
				return fmt.Errorf("unknown command \"%s\"; to analyze a package run: skill-xray scan <package>", console(args[0]))
			case len(argv) > 0: // cobra answered --help and --version itself, so only retired flags reach here
				return fmt.Errorf("unknown flags %s; run skill-xray --help", console(strings.Join(argv, " ")))
			}
			return c.Help()
		},
	}
	root.SetVersionTemplate("skill-xray {{.Version}}\n")
	root.CompletionOptions.DisableDefaultCmd = true // the README documents four subcommands; shell completion is not one of them
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
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.New("system-scan takes no positional argument; to scan the packages under a directory run: skill-xray system-scan --root <dir>")
			}
			return nil
		},
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
	f.StringVarP(&o.output, "output", "o", defaultReport, "write the validated SARIF report here; the path must be outside the scanned package and its directory must exist")
	f.StringVar(&o.policy, "policy", "", "scoped operator policy JSON (version skill-xray/scoped-policy/v1) that suppresses or demotes named results; a regular file outside the scanned package")
	f.StringVar(&o.opengrepBin, "opengrep-bin", "", "OpenGrep 1.29.0 executable for the code lane; it must match the pinned size and SHA-256, with no fallback to the cache")
	o.llmFlags.bind(c)
}

// bind registers the LLM flags on c.
func (l *llmFlags) bind(c *cobra.Command) {
	f := c.Flags()
	f.BoolVar(&l.llm, "llm", false, "also run the opt-in LLM adjudication pass (semantic prompt injection). "+
		"SENDS THE TEXT of the scanned skill files to the configured third-party LLM provider, so do not use "+
		"it on confidential packages. Requires SKILLXRAY_LLM_PROVIDER and an API key in the environment")
	f.BoolVar(&l.llmShadow, "llm-shadow", false, "review the static text-pattern candidates (SXV-028 to SXV-031) as shadow proposals only; requires --llm, excludes --llm-review, and turns the semantic SXV-038 check off unless --llm-additive is given")
	f.BoolVar(&l.llmReview, "llm-review", false, "review the static text-pattern candidates and annotate a validated dispute as llm-disputed without removing or downgrading it; requires --llm, excludes --llm-shadow, and turns the semantic SXV-038 check off unless --llm-additive is given")
	f.BoolVar(&l.llmAdditive, "llm-additive", false, "also run the semantic SXV-038 check after the review, within the same shared budget; requires --llm-shadow or --llm-review")
	f.BoolVar(&l.llmApply, "llm-apply", false, "let a validated llm-disputed review demote that text-pattern finding to low "+
		"in the correlated results (audited as corrected, never removed); requires --llm-review")
}

// client checks the flag combination and builds the opt-in client up front, so a misconfiguration
// fails before anything is read; a returned error is a usage error and a nil client means the
// lane is off.
func (l *llmFlags) client() (llm.Completer, error) {
	reviewing := l.llmShadow || l.llmReview
	switch {
	case reviewing && !l.llm:
		return nil, errors.New("LLM review requires explicit --llm opt-in")
	case l.llmShadow && l.llmReview:
		return nil, errors.New("--llm-shadow and --llm-review are mutually exclusive")
	case l.llmAdditive && !reviewing:
		return nil, errors.New("--llm-additive requires --llm-shadow or --llm-review")
	case l.llmApply && !l.llmReview:
		return nil, errors.New("--llm-apply requires --llm-review")
	case !l.llm:
		return nil, nil
	}
	cfg, err := llmFromEnv(os.Getenv)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New("--llm needs SKILLXRAY_LLM_PROVIDER and SKILLXRAY_LLM_API_KEY (or the vendor's own key variable) in the environment")
	}
	return buildClient(*cfg), nil
}

// scanOptions is the configuration of one package's scan under these flags.
func (l *llmFlags) scanOptions(client llm.Completer, exe string, policy map[string]any) scan.Options {
	return scan.Options{Client: client, LLMShadow: l.llmShadow, LLMReview: l.llmReview, LLMApply: l.llmApply,
		LLMAdditive: l.llmAdditive, OpengrepExe: exe, DispositionPolicy: policy}
}

// install is the "install-opengrep" subcommand.
func install(stdout, stderr io.Writer) int {
	installed, err := installOpengrep("", nil)
	if err != nil {
		fmt.Fprintf(stderr, "cannot install OpenGrep: %s\n", pytext.UnicodeEscape(err.Error()))
		return 2
	}
	fmt.Fprintf(stdout, "installed OpenGrep %s at %s\n", opengrep.Version, console(installed))
	return 0
}

// incomplete is the exit-2 rule of an analysis: a context error, or a high or critical finding
// without a vector (a check or engine that could not run). Findings with a vector never trigger it.
func incomplete(report *scan.ScanReport) bool {
	return len(report.ContextErrors) > 0 || slices.ContainsFunc(report.Findings, gap)
}

func gap(f findings.Finding) bool {
	return f.Vector == "" && (f.Severity == "critical" || f.Severity == "high")
}

// explainIncomplete names on stderr what kept an analysis from completing, one line per cause,
// so an exit 2 never arrives without a reason; it reports whether there was one.
func explainIncomplete(w io.Writer, name string, report *scan.ScanReport) bool {
	seen := map[string]bool{}
	say := func(line string) {
		if !seen[line] {
			seen[line] = true
			fmt.Fprintln(w, line)
		}
	}
	for _, e := range report.ContextErrors {
		say("analysis incomplete: " + name + ": " + pytext.UnicodeEscape(e))
	}
	for _, f := range report.Findings {
		if gap(f) {
			where := f.Rule
			if f.Path != "" {
				where += " " + pytext.UnicodeEscape(f.Path)
			}
			msg, _, _ := strings.Cut(f.Message, "\n") // the first line; an engine error can quote the source below it
			say("analysis incomplete: " + name + ": " + where + ": " + pytext.UnicodeEscape(pytext.Head(msg, 200)))
		}
	}
	return incomplete(report)
}

// llmSummary collects what the LLM lane did over the packages of one command for the one console
// line that says whether the model was reached: the calls made, whether the semantic pass ran,
// and the reviews sent or held back with the reason, so a run that never called the model cannot
// pass for one that did.
type llmSummary struct {
	configured, calls, failures, sent    int
	partial                              int // llm-truncated and llm-budget notes: files the model did not read whole
	unavailable, advisoryOn, advisoryOff bool
	judgeOn                              bool
	reason                               string // the first failure's reason seen
	held                                 map[string]int
}

func (s *llmSummary) add(report *scan.ScanReport) {
	u := report.LLMUsage
	if u == nil || !pytext.Truthy(u["advisory_enabled"]) && !pytext.Truthy(u["judge_enabled"]) {
		return // the lane was not requested
	}
	s.configured++
	s.calls += count(u["calls"])
	for _, f := range report.Findings {
		switch f.Rule {
		case "llm-truncated":
			s.partial++
		case "llm-budget": // one note stands for this file and every later one
			s.partial += max(1, count(f.Evidence["unchecked"]))
		}
	}
	s.failures += count(u["failures"])
	if r, _ := u["failure_reason"].(string); r != "" && s.reason == "" {
		s.reason = r
	}
	s.unavailable = s.unavailable || pytext.Truthy(u["unavailable"])
	s.advisoryOn = s.advisoryOn || pytext.Truthy(u["advisory_enabled"])
	s.advisoryOff = s.advisoryOff || !pytext.Truthy(u["advisory_enabled"])
	s.judgeOn = s.judgeOn || pytext.Truthy(u["judge_enabled"])
	decisions := report.Shadow
	if report.ReviewMode {
		decisions = report.Dispositions
	}
	for _, d := range decisions {
		switch {
		case d.Status == "ineligible":
		case d.RequestSHA256 != "": // a request left for the model
			s.sent++
		default:
			if s.held == nil {
				s.held = map[string]int{}
			}
			s.held[d.Status]++
		}
	}
}

func (s *llmSummary) line(w io.Writer) {
	if s.configured == 0 {
		return
	}
	fmt.Fprintf(w, "llm: %d model call%s", s.calls, plural(s.calls))
	if s.failures > 0 {
		fmt.Fprintf(w, ", %d failed", s.failures)
		if s.reason != "" {
			fmt.Fprintf(w, " (%s)", s.reason)
		}
	}
	if s.unavailable {
		fmt.Fprint(w, ", provider unavailable")
	}
	switch {
	case s.advisoryOff:
		fmt.Fprint(w, "; semantic check (SXV-038) skipped in review mode, add --llm-additive to run it")
	case s.advisoryOn && !s.unavailable:
		fmt.Fprint(w, "; semantic check (SXV-038) ran")
	}
	if s.partial > 0 {
		fmt.Fprintf(w, "; %d file%s not read whole by the model (size or budget), see the report", s.partial, plural(s.partial))
	}
	if s.judgeOn {
		fmt.Fprintf(w, "; reviews sent %d", s.sent)
		if s.sent == 0 && len(s.held) == 0 {
			fmt.Fprint(w, " (no eligible text-pattern candidates)")
		}
		if len(s.held) > 0 {
			parts, total := []string{}, 0
			for _, k := range slices.Sorted(maps.Keys(s.held)) {
				parts = append(parts, fmt.Sprintf("%s %d", k, s.held[k]))
				total += s.held[k]
			}
			fmt.Fprintf(w, ", held %d (%s)", total, strings.Join(parts, ", "))
		}
	}
	fmt.Fprintln(w)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// count reads a usage counter, which the session keeps as an int.
func count(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}

// verdictLine is the one console line per package: the verdict, the ledger counts and the name.
func verdictLine(w io.Writer, verdict string, l ingest.Ledger, name string) {
	fmt.Fprintf(w, "%-8s  seen=%-3d read=%-3d cov=%5.1f%%  %s\n", verdict, l.ArtifactsSeen, l.ArtifactsAnalyzed, float64(l.CoveragePercent), name)
}

// main is "scan" after argument parsing; a returned error is a usage error.
func (o *options) main(changed func(string) bool, pkg string, stdout, stderr io.Writer) (int, error) {
	if changed("output") && o.output == "" || changed("policy") && o.policy == "" {
		return 2, errors.New("--output and --policy require non-empty paths")
	}
	client, err := o.client()
	if err != nil {
		return 2, err
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
	report, err := scanReport(parsed, o.scanOptions(client, o.opengrepBin, policy))
	if err != nil {
		panic(err) // the flag checks above exclude scan_report's argument errors
	}
	rc := 0
	doc, err := buildSarif(parsed, report)
	if err == nil {
		err = writeSarif(doc, o.output, r.Root)
	}
	if err != nil {
		fmt.Fprintf(stderr, "cannot write SARIF: %s\n", pytext.UnicodeEscape(err.Error()))
		rc = 2
	}
	ledger := ingest.BuildLedger(p)
	verdictLine(stdout, reportHeadline(report), ledger, console(pkg))
	switch {
	case ledger.ArtifactsSeen == 0:
		fmt.Fprintf(stderr, "note: no files found under %s\n", console(pkg))
	case !slices.ContainsFunc(parsed.Artifacts, func(a *parse.Artifact) bool { return strings.EqualFold(filepath.Base(a.Rel), "SKILL.md") }):
		fmt.Fprintf(stderr, "note: no SKILL.md found under %s; nothing was evaluated as a skill manifest\n", console(pkg))
	}
	if o.policy != "" && report.Correlation != nil { // a CLEAN produced by a suppression is visible as such
		suppressed, demoted := 0, 0
		identities := map[[4]string]bool{}
		for _, r := range report.Correlation.Results {
			path, _ := r.Finding["path"].(string)
			identities[[4]string{r.RuleID, path, r.Fingerprint, r.ContextDigest}] = true
			if r.Decision != nil && r.DecisionProvenance == "operator-policy" {
				switch r.Disposition {
				case "suppressed":
					suppressed++
				case "corrected":
					demoted++
				}
			}
		}
		decisions, _ := policy["decisions"].([]any)
		unmatched := 0
		for _, d := range decisions { // a decision that names no result of this report did nothing
			m, _ := d.(map[string]any)
			key := [4]string{}
			for i, f := range []string{"rule_id", "path", "fingerprint", "context_digest"} {
				key[i], _ = m[f].(string)
			}
			if !identities[key] {
				unmatched++
			}
		}
		fmt.Fprintf(stdout, "policy: %d suppressed, %d demoted, %d of %d decisions matched no result\n", suppressed, demoted, unmatched, len(decisions))
	}
	var lane llmSummary
	lane.add(report)
	lane.line(stdout)
	if rc == 0 {
		fmt.Fprintf(stdout, "report: %s\n", console(o.output))
	}
	if explainIncomplete(stderr, console(pkg), report) {
		rc = 2
	}
	return rc, nil
}

// preflight runs before the input is read or unpacked: the report must lie outside the package
// path and must not overwrite its source or its operator policy, and the policy must be a regular
// JSON object of at most 512 KiB outside the package path. A URL or git address is no local
// path, so the comparisons against the source wait for contained on the unpacked root.
func (o *options) preflight(pkg string) (map[string]any, error) {
	report, err := resolvePath(o.output)
	if err != nil {
		return nil, err
	}
	if _, err := sarif.CheckTarget(o.output); err != nil { // a missing directory or a special file fails here, before the scan
		return nil, err
	}
	source := ""
	if _, err := os.Lstat(pkg); err == nil {
		if source, err = resolvePath(pkg); err != nil {
			return nil, err
		}
		if report == source || sameFile(report, source) {
			return nil, errors.New("Report cannot overwrite its source")
		}
		if sarif.IsWithinSource(report, source) {
			return nil, errors.New("Report must be outside the scanned package")
		}
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
	if source != "" && (policy == source || sameFile(policy, source) || sarif.IsWithinSource(policy, source)) {
		return nil, errors.New("Operator policy must be outside the scanned package")
	}
	st, err := os.Stat(policy)
	if err != nil {
		return nil, errors.New("Operator policy not found: " + filepath.ToSlash(o.policy))
	}
	if !st.Mode().IsRegular() {
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
		return nil, fmt.Errorf("Operator policy is not valid JSON: %w", err)
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("Operator policy must be an object")
	}
	if version, _ := doc["version"].(string); version != correlate.PolicyVersion { // before the scan, not as a context error after it
		return nil, fmt.Errorf("Operator policy version %q is not supported; expected %s", version, correlate.PolicyVersion)
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

// console is a path as the console prints it: every Unicode control character (the C0 and C1
// ranges and DEL) is shown as an escape, so a name cannot rewrite or hide a line, and everything
// else, backslashes included, stays as typed. Names inside a package still use the stricter
// pytext.UnicodeEscape.
func console(p string) string {
	var b strings.Builder
	for _, r := range p {
		switch {
		case unicode.IsControl(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		case r == '\u2028' || r == '\u2029': // the line and paragraph separators, which a terminal may break a line on
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
