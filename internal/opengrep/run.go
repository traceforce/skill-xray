package opengrep

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/traceforce/skill-xray/internal/codelane"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// Rules is rules/opengrep-phase1.yml, byte-identical to the oracle's (sha256 pinned in a test).
//
//go:embed rules/opengrep-phase1.yml
var Rules []byte

var maxReportBytes = 16 << 20 // _MAX_REPORT_BYTES; a var so a test can lower it

const maxTargetBytes = 5 << 20 // _MAX_TARGET_BYTES

// Options are the keyword arguments of opengrep_bridge.check / taint_engine.check.
type Options struct {
	Executable string        // --opengrep-bin or a test's injected binary; "" resolves the pinned one
	Rules      string        // explicit rule file; "" uses the embedded Rules
	Timeout    time.Duration // 0 is 45 s
	// Runner replaces subprocess.run: it runs argv in dir with env, stderr to the given file,
	// and returns the exit status; a ctx deadline error is the engine timeout. nil is os/exec.
	Runner       func(ctx context.Context, argv []string, dir string, env []string, stderr *os.File) (int, error)
	Units        []codelane.Unit    // nil builds the code lane; empty non-nil selects nothing
	LaneNotes    []findings.Finding // taint_engine lane_notes, retained once
	Languages    []string           // run default ("python"); Check always uses python, shell, javascript, typescript
	Observations *[]map[string]any  // nil does not collect capability observations
}

var suffixes = map[string]string{"script_python": ".py", "script_shell": ".sh",
	"script_javascript": ".js", "script_typescript": ".ts"}

// keepSuffix is _KEEP_SUFFIX: a script file keeps its own extension for the engine.
var keepSuffix = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".jsx": true,
	".ts": true, ".mts": true, ".cts": true, ".tsx": true}

// Select is select_executable_code: the units of the requested languages, shell only in a
// supported dialect.
func Select(p *parse.Package, units []codelane.Unit, languages []string) []Selected {
	if units == nil {
		units, _ = codelane.Build(p)
	}
	selected := []Selected{}
	for _, u := range units {
		suffix, ok := suffixes[u.Kind]
		if !ok || !slices.Contains(languages, strings.TrimPrefix(u.Kind, "script_")) ||
			u.Kind == "script_shell" && !codelane.SupportedShell[u.Dialect] {
			continue
		}
		_, ext := pytext.SplitExt(u.Rel)
		if ext = pytext.Lower(ext); u.Origin == "file" && keepSuffix[ext] {
			suffix = ext // OpenGrep reads JSX and TSX from the extension
		}
		selected = append(selected, Selected{u.Rel, u.Text, u.Origin, suffix})
	}
	return selected
}

// Check is taint_engine.check: the lane notes plus one OpenGrep run over Python and shell,
// with any panic reported as opengrep-internal-error.
func Check(p *parse.Package, o Options) (out []findings.Finding) {
	out = slices.Clone(o.LaneNotes)
	defer func() {
		if r := recover(); r != nil {
			out = append(out, findings.Finding{Rule: "opengrep-internal-error", Severity: "high",
				Message:  "OpenGrep analysis failed unexpectedly: RuntimeError", // type(exc).__name__ (code.md 5.9)
				Evidence: map[string]any{"engine": "opengrep"}})
		}
		out = findings.CapFindings(out)
	}()
	o.Languages = []string{"python", "shell", "javascript", "typescript"}
	return append(out, run(p, o)...)
}

func gap(rule, message string) []findings.Finding {
	return []findings.Finding{coverage(rule, message, "")}
}

// run is opengrep_bridge.check: write the selected code to a temporary tree, run the pinned
// engine over it once, and translate the report. Every failure is a high coverage finding.
func run(p *parse.Package, o Options) []findings.Finding {
	if o.Languages == nil {
		o.Languages = []string{"python"}
	}
	selected := Select(p, o.Units, o.Languages)
	if len(selected) == 0 {
		return []findings.Finding{}
	}
	binary := o.Executable
	if o.Runner == nil || binary == "" {
		var err error
		if binary, err = Resolve(o.Executable); err != nil {
			return gap("opengrep-unverified", err.Error())
		}
		if binary == "" {
			return gap("opengrep-unavailable", "Executable code was selected, but the OpenGrep binary is unavailable.")
		}
	}
	rules := Rules
	if o.Rules != "" {
		rulePath, _ := filepath.Abs(o.Rules)
		if info, err := os.Stat(rulePath); err != nil || !info.Mode().IsRegular() {
			return gap("opengrep-rules-unavailable", "Executable code was selected, but the local OpenGrep rules are unavailable.")
		}
		b, err := os.ReadFile(rulePath)
		if err != nil {
			return couldNotStart(err)
		}
		rules = b
	}
	root, err := os.MkdirTemp("", "skill-xray-opengrep-")
	if err != nil {
		return couldNotStart(err)
	}
	defer os.RemoveAll(root)
	sourceRoot := filepath.Join(root, "targets")
	reportPath := filepath.Join(root, "opengrep-report.json")
	targets := map[string]Selected{}
	if err := os.Mkdir(sourceRoot, 0o755); err != nil {
		return couldNotStart(err)
	}
	for i, item := range selected {
		name := fmt.Sprintf("%04d%s", i, item.Suffix)
		if err := os.WriteFile(filepath.Join(sourceRoot, name), []byte(item.Text), 0o644); err != nil {
			return couldNotStart(err)
		}
		targets[name] = item
	}
	// the engine prefixes rule ids with the config file's dotted directory path, so a rule file
	// run from its own path names that path in every engine error; a copy at the engine root
	// keeps the ids bare, for the embedded rules and an explicit file alike
	rulePath := filepath.Join(root, "rules.yml")
	if err := os.WriteFile(rulePath, rules, 0o644); err != nil {
		return couldNotStart(err)
	}
	argv := []string{binary, "scan", "--json", "--dataflow-traces",
		"--disable-version-check", "--disable-nosem", "--no-git-ignore",
		// ponytail: one worker bounds package memory; raise it only after runtime calibration.
		"--jobs=1", "--max-memory=512", fmt.Sprintf("--max-target-bytes=%d", maxTargetBytes),
		"--max-match-per-file=1000", "--timeout=5", "--timeout-threshold=1",
		"--output", reportPath, "--config", rulePath, sourceRoot}
	env, err := engineEnv(root)
	if err != nil {
		return couldNotStart(err)
	}
	stderr, err := os.Create(filepath.Join(root, "opengrep-stderr.txt"))
	if err != nil {
		return couldNotStart(err)
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	runner := o.Runner
	if runner == nil {
		runner = execRunner
	}
	status, err := runner(ctx, argv, root, env, stderr)
	stderr.Close()
	if errors.Is(err, context.DeadlineExceeded) {
		return gap("opengrep-timeout", "OpenGrep exceeded the package analysis deadline.")
	}
	if err != nil {
		return couldNotStart(err)
	}
	if status != 0 {
		captured, _ := os.ReadFile(stderr.Name())
		detail := strings.TrimSpace(pytext.Head(string(captured), 8192))
		if detail == "" {
			detail = "no diagnostic output"
		}
		detail = strings.ReplaceAll(strings.ReplaceAll(detail, root, "<temporary>"), rulePath, "<rules>")
		return gap("opengrep-execution-error", fmt.Sprintf("OpenGrep exited with status %d: %s", status, pytext.Head(detail, 500)))
	}
	info, err := os.Stat(reportPath)
	if err != nil {
		return gap("opengrep-invalid-output", "OpenGrep completed without producing its JSON report.")
	}
	if info.Size() > int64(maxReportBytes) {
		return gap("opengrep-output-limit", fmt.Sprintf("OpenGrep's JSON report exceeded the %d-byte limit.", maxReportBytes))
	}
	data, err := os.ReadFile(reportPath)
	var doc any
	if err == nil {
		doc, err = decodeReport(data)
	}
	if err != nil {
		return gap("opengrep-invalid-output", "OpenGrep completed without returning valid JSON.")
	}
	report, ok := doc.(map[string]any)
	if !ok {
		return gap("opengrep-invalid-output", "OpenGrep returned an unexpected JSON document.")
	}
	found := FindingsFromReport(report, targets, p, []string{root, rulePath, sourceRoot}, o.Observations)
	return findings.CapFindings(append(found, coverageFromReport(report, targets)...))
}

func couldNotStart(err error) []findings.Finding {
	return gap("opengrep-execution-error", "OpenGrep could not start: "+pytext.OSErrorName(err))
}

// execRunner is subprocess.run: stdout discarded, stderr to the file, no shell.
func execRunner(ctx context.Context, argv []string, dir string, env []string, stderr *os.File) (int, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir, cmd.Env, cmd.Stderr = dir, env, stderr
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	return 0, err
}

// coverageFromReport is _coverage_from_report: every selected target must appear in
// paths.scanned.
func coverageFromReport(report map[string]any, targets map[string]Selected) []findings.Finding {
	paths, _ := report["paths"].(map[string]any)
	scannedList, ok := paths["scanned"].([]any)
	if !ok {
		return gap("opengrep-invalid-output", "OpenGrep did not report which selected targets it scanned.")
	}
	scanned := map[string]bool{}
	for _, p := range scannedList {
		scanned[targetName(p)] = true
	}
	var missing []string
	for name := range targets {
		if !scanned[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	slices.Sort(missing)
	return []findings.Finding{coverage("opengrep-analysis-incomplete",
		fmt.Sprintf("OpenGrep skipped %d selected code target(s); the candidate result is incomplete.", len(missing)),
		targets[missing[0]].Rel)}
}

// engineEnv is _engine_env: an allow-listed copy of the environment with HOME, XDG, TEMP and
// the Semgrep settings pointed inside root, so user configuration never reaches the scan.
func engineEnv(root string) ([]string, error) {
	keep := []string{
		"ALLUSERSPROFILE", "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)",
		"COMMONPROGRAMW6432", "COMPUTERNAME", "COMSPEC", "DRIVERDATA", "LANG",
		"LC_ALL", "NUMBER_OF_PROCESSORS", "OS", "PATH", "PATHEXT",
		"PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL",
		"PROCESSOR_REVISION", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
		"PROGRAMW6432", "PUBLIC", "SYSTEMDRIVE", "SYSTEMROOT", "USERPROFILE", "WINDIR",
	}
	source := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			source[strings.ToUpper(k)] = v
		}
	}
	var env []string
	for _, k := range keep {
		if v, ok := source[k]; ok {
			env = append(env, k+"="+v)
		}
	}
	home := filepath.Join(root, "engine-home")
	temporary := filepath.Join(root, "engine-tmp")
	cache, config := filepath.Join(home, "cache"), filepath.Join(home, "config")
	dirs := []string{home, temporary, cache, config, filepath.Join(home, ".opengrep")}
	env = append(env, "HOME="+home, "XDG_CACHE_HOME="+cache, "XDG_CONFIG_HOME="+config,
		"SEMGREP_SETTINGS_FILE="+filepath.Join(config, "settings.yml"),
		"TEMP="+temporary, "TMP="+temporary, "TMPDIR="+temporary)
	if runtime.GOOS == "windows" {
		// The v1.29 launcher needs the inherited USERPROFILE to locate its embedded runtime;
		// explicit XDG/settings/log paths still keep user configuration out of the scan.
		roaming, local := filepath.Join(home, "AppData", "Roaming"), filepath.Join(home, "AppData", "Local")
		dirs = append(dirs, roaming, local)
		env = append(env, "APPDATA="+roaming, "LOCALAPPDATA="+local,
			"SEMGREP_LOG_FILE="+filepath.Join(root, "engine.log"),
			"SEMGREP_VERSION_CACHE_PATH="+filepath.Join(root, "version-cache"))
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	return env, nil
}
