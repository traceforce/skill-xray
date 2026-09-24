package parse

// Dispatch, config, dependency, Python, shell-guard, reference and package-level tests ported
// from tests/test_parse.py (each Go test names its pytest source), run through
// ingest.BuildPackage + Parse exactly as the pytest `_parsed` helper does.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/unicode/norm"

	"github.com/BurntSushi/toml"

	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/pytext"
	"github.com/traceforce/skill-xray/internal/testutil"
)

const skill = "---\nname: t\n---\n"

func parsePkg(t *testing.T, files map[string]string) *Package {
	t.Helper()
	return Parse(ingest.BuildPackage(testutil.MakePackage(t, files)))
}

func diag(a *Artifact, code string) (detail string, ok bool) {
	for _, d := range a.Diagnostics {
		if d.Code == code {
			if d.Detail != nil {
				detail = *d.Detail
			}
			return detail, true
		}
	}
	return "", false
}

func hasDiag(a *Artifact, code string) bool { _, ok := diag(a, code); return ok }

// test_manifest_classification; test_manifest_classification_precedence
func TestManifestClassification(t *testing.T) {
	for _, tc := range []struct {
		cfg  any
		want string
	}{
		{map[string]any{"mcpServers": map[string]any{}}, "mcp_servers"},
		{map[string]any{"mcp_servers": map[string]any{"x": map[string]any{"command": "sh"}}}, "mcp_servers"},
		{map[string]any{"srv": map[string]any{"command": "npx", "args": []any{"-y", "x@latest"}}}, "mcp_servers"},
		{map[string]any{"srv": map[string]any{"type": "http", "url": "https://h/mcp"}}, "mcp_servers"},
		{map[string]any{"homepage": map[string]any{"url": "https://x"}}, "generic"},
		{map[string]any{"build": map[string]any{"command": "make"}}, "generic"},
		{map[string]any{"hooks": map[string]any{"PreToolUse": []any{}}}, "hooks"},
		{map[string]any{"lockVersion": 1, "integrity": "sha256-x"}, "lockfile"},
		{map[string]any{"name": "p", "version": "1"}, "plugin"},
		{map[string]any{"skills": []any{}}, "plugin"},
		{map[string]any{"foo": 1}, "generic"},
		{"not a dict", ""},
		{map[string]any{"mcpServers": map[string]any{}, "hooks": map[string]any{"x": []any{}}}, "mcp_servers"},
		{map[string]any{"name": "p", "version": "1", "hooks": map[string]any{"x": []any{}}}, "hooks"},
		{map[string]any{"hooks": "x"}, "generic"},
		{map[string]any{"x": map[string]any{"type": "ws", "url": "u"}}, "generic"},
	} {
		assert.Equal(t, tc.want, classifyManifest(tc.cfg), tc.cfg)
	}
}

// test_agent_config_json_is_classified; test_malformed_config_fails_closed; test_json_config_rejects_nonstandard_constants
func TestJSONConfigs(t *testing.T) {
	a := parsePkg(t, map[string]string{"SKILL.md": skill, ".claude/settings.json": `{"hooks": {"PreToolUse": []}}`}).ByRel[".claude/settings.json"]
	assert.Equal(t, map[string]any{"hooks": map[string]any{"PreToolUse": []any{}}}, a.Config)
	assert.Equal(t, "hooks", a.ManifestKind)
	assert.Empty(t, a.Diagnostics)

	h := parsePkg(t, map[string]string{"SKILL.md": skill, "hooks.json": "{not json"}).ByRel["hooks.json"]
	assert.Nil(t, h.Config)
	assert.True(t, hasDiag(h, "config_parse_error"))

	for _, bad := range []string{"NaN", "Infinity", "-Infinity"} {
		cfg, err := loadStructured(`{"x": `+bad+`}`, "c.json")
		assert.Nil(t, cfg)
		assert.True(t, strings.HasPrefix(err, "json_parse_error"), err)
	}
	// json.loads shapes probed on the oracle: empty input, trailing data, non-object documents,
	// the 4300-digit int limit, duplicate keys (last wins), raw control characters
	for _, tc := range []struct{ text, want, err string }{
		{"", "", "json_parse_error"},
		{"{} x", "", "json_parse_error"},
		{"[1]", "[1]", ""},
		{`"s"`, `"s"`, ""},
		{strings.Repeat("1", 5000), "", "json_parse_error"},
		{`{"a":1,"a":2}`, `{"a":2}`, ""},
		{"{\"a\": \"x\ny\"}", "", "json_parse_error"},
		{" {} ", "{}", ""},
		{`{"n": 1.0, "e": 1e2, "i": -3}`, `{"e":100.0,"i":-3,"n":1.0}`, ""},
	} {
		cfg, err := loadStructured(tc.text, "c.json")
		if tc.err != "" {
			assert.Nil(t, cfg, tc.text)
			assert.True(t, strings.HasPrefix(err, tc.err), tc.text)
			continue
		}
		assert.Equal(t, "", err, tc.text)
		assert.Equal(t, tc.want, pytext.Canonical(cfg), tc.text)
	}
}

// test_toml_config_is_parsed
func TestTOMLConfigIsParsed(t *testing.T) {
	a := parsePkg(t, map[string]string{"SKILL.md": skill, "config.toml": "name = \"x\"\nversion = \"1\"\n"}).ByRel["config.toml"]
	assert.Equal(t, map[string]any{"name": "x", "version": "1"}, a.Config)
	assert.Equal(t, "plugin", a.ManifestKind)
}

// test_toml_oversized_int_fails_closed
func TestTOMLOversizedIntFailsClosed(t *testing.T) {
	a := parsePkg(t, map[string]string{"SKILL.md": skill, "pyproject.toml": "k = " + strings.Repeat("1", 6000)}).ByRel["pyproject.toml"]
	assert.True(t, hasDiag(a, "config_parse_error"))
	assert.False(t, hasDiag(a, "parse_crash"))
}

func depNames(deps []Dep) []string {
	names := []string{}
	for _, d := range deps {
		names = append(names, d.Name)
	}
	return names
}

func depByName(deps []Dep) map[string]Dep {
	m := map[string]Dep{}
	for _, d := range deps {
		m[d.Name] = d
	}
	return m
}

// test_requirements_deps_pinned; test_requirements_prefix_range_not_pinned;
// test_requirements_url_continuation_and_comment; test_requirements_trailing_backslash_not_dropped;
// test_requirements_vcs_and_local_surfaced
func TestRequirements(t *testing.T) {
	a := parsePkg(t, map[string]string{"SKILL.md": skill,
		"requirements.txt": "requests==2.32.3\nflask[async]>=3\n# comment\n-r other.txt\n"}).ByRel["requirements.txt"]
	d := depByName(a.Deps)
	assert.ElementsMatch(t, []string{"requests", "flask"}, depNames(a.Deps))
	assert.True(t, d["requests"].Pinned)
	assert.False(t, d["flask"].Pinned)
	assert.Equal(t, 1, *d["requests"].Line)
	det, ok := diag(a, "requirement_unparsed")
	assert.True(t, ok)
	assert.Equal(t, "-r other.txt", det)

	p := parsePkg(t, map[string]string{"SKILL.md": skill, "requirements.txt": "requests==2.*\n"}).ByRel["requirements.txt"]
	assert.False(t, p.Deps[0].Pinned)
	assert.Equal(t, "==2.*", p.Deps[0].Specifier)

	u := parsePkg(t, map[string]string{"SKILL.md": skill, "requirements.txt": "requests==2.32.3  # pin\n" +
		"pkg @ https://h/p.whl#sha256=abc\nflask==3.0.0 \\\n    --hash=sha256:deadbeef\n"}).ByRel["requirements.txt"]
	ud := depByName(u.Deps)
	assert.Subset(t, depNames(u.Deps), []string{"requests", "pkg", "flask"})
	assert.Contains(t, ud["pkg"].Raw, "://")
	assert.Equal(t, 3, *ud["flask"].Line)
	assert.Empty(t, u.Diagnostics)

	b := parsePkg(t, map[string]string{"SKILL.md": skill, "requirements.txt": "evil==1.0 \\"}).ByRel["requirements.txt"]
	assert.Equal(t, []string{"evil"}, depNames(b.Deps))

	v := parsePkg(t, map[string]string{"SKILL.md": skill, "requirements.txt": "git+https://h/r.git#egg=pkg\n./local\n"}).ByRel["requirements.txt"]
	assert.Equal(t, []Dep{}, v.Deps)
	det, _ = diag(v, "requirement_unparsed")
	assert.Equal(t, "git+https://h/r.git#egg=pkg;./local", det)

	// specifier spelling and trailer handling probed on the oracle
	deps, unhandled := parseRequirements("a>=1,<2\nb ==  1.0\nc[extra]==1; python_version>'3'\n-e .\n--index-url x\nd==2.*\n\nf --flag\ng #c\nh#d\ni\t#e\nj\u00a0#f\n")
	assert.Equal(t, []string{"-e .", "--index-url x", "h#d"}, unhandled)
	got := []string{}
	for _, d := range deps {
		got = append(got, d.Name+"|"+d.Specifier+"|"+d.Raw)
	}
	assert.Equal(t, []string{"a|<2,>=1|a>=1,<2", "b|==1.0|b ==  1.0", "c|==1|c[extra]==1; python_version>'3'", "d|==2.*|d==2.*", "f||f", "g||g", "i||i", "j||j"}, got)
	assert.Equal(t, 6, *deps[3].Line)
}

// test_requirements_continuation_is_linear
func TestRequirementsContinuationIsLinear(t *testing.T) {
	start := time.Now()
	deps, _ := parseRequirements(strings.Repeat("a\\\n", 200000))
	assert.Len(t, deps, 1)
	assert.Less(t, time.Since(start), time.Second)
}

// test_npm_floating_versions_not_pinned; test_npm_peer_dependencies_captured; test_npm_malformed_shape_not_silent;
// test_npm_semver_prerelease_build_is_pinned; test_non_string_dep_entries_flagged_not_coerced (npm half)
func TestNpmDeps(t *testing.T) {
	a := parsePkg(t, map[string]string{"SKILL.md": skill,
		"package.json": `{"dependencies": {"a": "1.2.3", "b": "^1.2.3", "c": "1.x"}}`}).ByRel["package.json"]
	d := depByName(a.Deps)
	assert.True(t, d["a"].Pinned)
	assert.False(t, d["b"].Pinned)
	assert.False(t, d["c"].Pinned)
	assert.Nil(t, d["a"].Line)
	assert.Equal(t, "a@1.2.3", d["a"].Raw)

	p := parsePkg(t, map[string]string{"SKILL.md": skill, "package.json": `{"peerDependencies": {"react": "^18"}}`}).ByRel["package.json"]
	assert.Equal(t, []string{"react"}, depNames(p.Deps))

	m := parsePkg(t, map[string]string{"SKILL.md": skill, "package.json": `{"dependencies": ["a", "b"]}`}).ByRel["package.json"]
	det, _ := diag(m, "requirement_unparsed")
	assert.Equal(t, "dependencies not an object", det)

	s := parsePkg(t, map[string]string{"SKILL.md": skill,
		"package.json": `{"dependencies": {"a": "1.2.3-alpha+001", "b": "1.2.3-alpha-1"}}`}).ByRel["package.json"]
	for _, dep := range s.Deps {
		assert.True(t, dep.Pinned, dep.Name)
	}

	n := parsePkg(t, map[string]string{"SKILL.md": skill, "package.json": `{"dependencies": {"a": 123}}`}).ByRel["package.json"]
	assert.Equal(t, []Dep{}, n.Deps)
	det, _ = diag(n, "requirement_unparsed")
	assert.Equal(t, "a non-string version", det)

	// document order, aliases, null and malformed sections probed on the oracle
	text := `{"dependencies": {"z": "1.2.3", "b": "npm:x@1.2.3", "c": "npm:@s/x@v1.0.0", "d": "=1.2.3", "e": "npm:x", "f": "npm:@1.2.3", "g": 5, "h": "1.2.3-a+b"}, "devDependencies": [], "peerDependencies": {"y": "^1"}, "optionalDependencies": null}`
	cfg, err := loadStructured(text, "package.json")
	require.Equal(t, "", err)
	deps, bad := npmDeps(cfg, text)
	assert.Equal(t, []string{"g non-string version", "devDependencies not an object"}, bad)
	got := []string{}
	for _, dep := range deps {
		got = append(got, dep.Raw+"|"+map[bool]string{true: "pinned", false: "floating"}[dep.Pinned])
	}
	assert.Equal(t, []string{"z@1.2.3|pinned", "b@npm:x@1.2.3|pinned", "c@npm:@s/x@v1.0.0|pinned", "d@=1.2.3|pinned",
		"e@npm:x|floating", "f@npm:@1.2.3|floating", "h@1.2.3-a+b|pinned", "y@^1|floating"}, got)
	deps, bad = npmDeps([]any{}, "[]")
	assert.Equal(t, []Dep{}, deps)
	assert.Equal(t, []string{"package.json is not a JSON object"}, bad)
}

// _pyproject_deps on the decoded tables of test_pyproject_deps_parsed, test_pyproject_build_system_requires_captured,
// test_pyproject_dependency_groups_captured, test_pyproject_dynamic_dependencies_flagged,
// test_pyproject_malformed_dep_surfaced_not_dropped, test_pyproject_optional_deps_malformed_not_silent,
// test_pyproject_optional_dependencies_collected, test_pyproject_non_list_dependencies_fails_safe,
// test_non_string_dep_entries_flagged_not_coerced (pyproject half), plus the message order probed on the oracle
func TestPyprojectDeps(t *testing.T) {
	deps, bad := pyprojectDeps(map[string]any{"project": map[string]any{"name": "x", "dependencies": []any{"requests==2.32.3", "flask>=3"}}}, toml.MetaData{})
	assert.Empty(t, bad)
	d := depByName(deps)
	assert.True(t, d["requests"].Pinned)
	assert.False(t, d["flask"].Pinned)
	assert.Nil(t, d["requests"].Line)

	deps, _ = pyprojectDeps(map[string]any{"build-system": map[string]any{"requires": []any{"setuptools", "poison==1"}}}, toml.MetaData{})
	assert.ElementsMatch(t, []string{"setuptools", "poison"}, depNames(deps))
	deps, _ = pyprojectDeps(map[string]any{"dependency-groups": map[string]any{"dev": []any{"pytest==8"}}}, toml.MetaData{})
	assert.Equal(t, []string{"pytest"}, depNames(deps))
	_, bad = pyprojectDeps(map[string]any{"project": map[string]any{"name": "x", "dynamic": []any{"dependencies"}}}, toml.MetaData{})
	assert.Equal(t, []string{"dependencies is dynamic"}, bad)
	deps, bad = pyprojectDeps(map[string]any{"project": map[string]any{"name": "x", "dependencies": "notalist"}}, toml.MetaData{})
	assert.Equal(t, []Dep{}, deps)
	assert.Equal(t, []string{"non-list dependency group"}, bad)
	_, bad = pyprojectDeps(map[string]any{"project": map[string]any{"name": "x", "optional-dependencies": []any{"a==1"}}}, toml.MetaData{})
	assert.Equal(t, []string{"optional-dependencies not a table"}, bad)
	deps, _ = pyprojectDeps(map[string]any{"project": map[string]any{"name": "x", "dependencies": []any{"requests>=2"},
		"optional-dependencies": map[string]any{"dev": []any{"pytest==8.0.0"}}}}, toml.MetaData{})
	assert.ElementsMatch(t, []string{"requests", "pytest"}, depNames(deps))
	deps, bad = pyprojectDeps(map[string]any{"project": map[string]any{"dependencies": []any{123}}}, toml.MetaData{})
	assert.Equal(t, []Dep{}, deps)
	assert.Equal(t, []string{"123"}, bad)

	deps, bad = pyprojectDeps(map[string]any{
		"project": map[string]any{"dependencies": []any{"a==1", 5, "bad dep!", map[string]any{"k": 1}, []any{1}, 1.5, true, nil},
			"optional-dependencies": map[string]any{"x": []any{"b>=2"}}, "dynamic": []any{"dependencies", 5}},
		"build-system": map[string]any{"requires": "notalist"}, "dependency-groups": []any{"x"}, "tool": map[string]any{"poetry": map[string]any{}}}, toml.MetaData{})
	assert.Equal(t, []string{"a", "b"}, depNames(deps))
	assert.Equal(t, []string{"dependencies is dynamic", "dynamic has a non-string entry", "tool.poetry dependencies not modeled",
		"dependency-groups not a table", "5", "bad dep!", "{'k': 1}", "[1]", "1.5", "True", "None", "non-list dependency group"}, bad)
	_, bad = pyprojectDeps(map[string]any{"project": 5, "build-system": 5}, toml.MetaData{})
	assert.Equal(t, []string{"project not a table"}, bad)
	deps, bad = pyprojectDeps(map[string]any{}, toml.MetaData{})
	assert.Equal(t, []Dep{}, deps)
	assert.Equal(t, []string{}, bad)
}

// test_pyproject_deps_parsed and the other pyproject pins through Parse (TOML decoder needed)
func TestPyprojectThroughParse(t *testing.T) {
	a := parsePkg(t, map[string]string{"SKILL.md": skill,
		"pyproject.toml": "[project]\nname = \"x\"\ndependencies = [\"requests==2.32.3\", \"flask>=3\"]\n"}).ByRel["pyproject.toml"]
	d := depByName(a.Deps)
	assert.True(t, d["requests"].Pinned)
	assert.False(t, d["flask"].Pinned)
	b := parsePkg(t, map[string]string{"SKILL.md": skill, "pyproject.toml": "[project]\nname = \"x\"\ndynamic = [\"dependencies\"]\n"}).ByRel["pyproject.toml"]
	assert.True(t, hasDiag(b, "requirement_unparsed"))
	c := parsePkg(t, map[string]string{"SKILL.md": skill, "pyproject.toml": "[project]\ndependencies = [123]\n"}).ByRel["pyproject.toml"]
	assert.Equal(t, []Dep{}, c.Deps)
	assert.True(t, hasDiag(c, "requirement_unparsed"))
}

// test_python_and_shell_scripts (Python half); test_python_syntax_error_is_a_diagnostic;
// test_python_oversize_flagged_not_parsed; test_python_ast_depth_is_platform_independent;
// test_untrusted_python_syntax_warnings_do_not_escape
func TestPythonScripts(t *testing.T) {
	pp := parsePkg(t, map[string]string{"SKILL.md": skill, "scripts/a.py": "def f():\n    return 1\n", "scripts/b.sh": "echo hi\n"})
	assert.NotNil(t, pp.ByRel["scripts/a.py"].PyTree)
	assert.Empty(t, pp.ByRel["scripts/a.py"].Diagnostics)
	assert.Empty(t, pp.ByRel["scripts/b.sh"].Diagnostics)

	b := parsePkg(t, map[string]string{"SKILL.md": skill, "scripts/b.py": "def (:\n"}).ByRel["scripts/b.py"]
	assert.Nil(t, b.PyTree)
	det, ok := diag(b, "python_syntax_error")
	assert.True(t, ok)
	assert.Equal(t, "line 1", det)

	big := parsePkg(t, map[string]string{"SKILL.md": skill, "scripts/big.py": strings.Repeat("x = 1\n", 100000)}).ByRel["scripts/big.py"]
	assert.Nil(t, big.PyTree)
	det, ok = diag(big, "python_oversize")
	assert.True(t, ok)
	assert.Equal(t, "600000", det)

	bomb := parsePkg(t, map[string]string{"SKILL.md": skill, "scripts/bomb.py": "x = " + strings.Repeat("\"a\"+", 2999) + "\"a\"\n"}).ByRel["scripts/bomb.py"]
	assert.Nil(t, bomb.PyTree)
	assert.True(t, hasDiag(bomb, "python_too_complex"))

	warn := parsePkg(t, map[string]string{"SKILL.md": skill, "scripts/warn.py": "x = \"\\W\"\n"}).ByRel["scripts/warn.py"]
	assert.NotNil(t, warn.PyTree)
	assert.Empty(t, warn.Diagnostics)
}

// test_parse_shell_dos_guard_is_at_the_public_boundary; test_shell_pipe_bomb_is_bounded_not_parsed
func TestShellPipeBombIsBoundedNotParsed(t *testing.T) {
	start := time.Now()
	a := parsePkg(t, map[string]string{"SKILL.md": skill, "s.sh": strings.Repeat("a|", 40000)}).ByRel["s.sh"]
	det, ok := diag(a, "shell_too_complex")
	assert.True(t, ok)
	assert.Equal(t, "80000", det)
	assert.Less(t, time.Since(start), time.Second)
	ok2 := parsePkg(t, map[string]string{"SKILL.md": skill, "s.sh": strings.Repeat("a||", 40000)}).ByRel["s.sh"]
	assert.False(t, hasDiag(ok2, "shell_too_complex"))
}

// test_shell_tree_sitter_cst; test_shell_error_region_recorded_not_dropped; test_shell_error_region_is_a_coverage_gap;
// test_shell_nested_error_region_is_covered; test_python_and_shell_scripts (shell half)
func TestShellErrorRegions(t *testing.T) {
	pp := parsePkg(t, map[string]string{"SKILL.md": skill, "ok.sh": "curl -k https://x | sh -s -- --yes", "b.sh": "echo hi\n",
		"bad.sh": "echo ok\nif then $( `", "scripts/bad.sh": "echo ok\nif then $( `\n", "scripts/b.sh": "echo ok\nfor x in; do $( `\ndone\n"})
	for _, rel := range []string{"ok.sh", "b.sh"} {
		assert.NotNil(t, pp.ByRel[rel].ShellTree, rel)
		assert.Empty(t, pp.ByRel[rel].Diagnostics, rel)
	}
	for _, rel := range []string{"bad.sh", "scripts/bad.sh"} {
		assert.Nil(t, pp.ByRel[rel].ShellTree, rel) // mvdan/sh keeps no partial tree
		assert.True(t, hasDiag(pp.ByRel[rel], "shell_error_region"), rel)
	}
	det, ok := diag(pp.ByRel["scripts/b.sh"], "shell_error_region")
	require.True(t, ok)
	count, spans, _ := strings.Cut(det, ":")
	assert.Equal(t, "1", count)
	var lo, hi int
	_, err := fmt.Sscanf(spans, "%d-%d", &lo, &hi)
	require.NoError(t, err)
	// mvdan/sh reports the line it stopped on (3), inside the tree-sitter ERROR span (lines 2-3) of
	// the malformed `for`.
	assert.True(t, lo == hi && 2 <= lo && lo <= 3, det)
}

// test_secret_material_carried_not_parsed; test_opaque_and_compiled_are_skipped;
// test_unmodeled_text_file_not_read_clean; test_unsupported_script_language_is_flagged
func TestKindDispatch(t *testing.T) {
	pp := parsePkg(t, map[string]string{"SKILL.md": skill, "keys/id_rsa": "-----BEGIN-----", "d.svg": "<svg/>", "lib/e.so": "\x7fELF",
		"config.yaml": "mcpServers:\n  x: {command: sh}\n", "scripts/x.ps1": "Write-Host hi\n", "scripts/y.js": "console.log(1)\n",
		"scripts/z.rb": "puts 1\n", "scripts/t.ts": "console.log(1 as number)\n",
		"scripts/w.tsx": "export const A = () => <div/>;\n", "scripts/v.jsx": "export const B = () => <div/>;\n",
		"scripts/u.mts": "export const c = 1;\n", "scripts/s.cts": "module.exports = 1;\n"})
	secret := pp.ByRel["keys/id_rsa"]
	assert.NotNil(t, secret.Text)
	assert.Nil(t, secret.Config)
	assert.Nil(t, secret.PyTree)
	assert.Empty(t, secret.Diagnostics)
	for _, rel := range []string{"d.svg", "lib/e.so"} {
		a := pp.ByRel[rel]
		assert.Nil(t, a.Text, rel)
		assert.Nil(t, a.Markdown, rel)
		assert.Empty(t, a.Diagnostics, rel)
		assert.NotNil(t, a.Raw, rel)
	}
	det, ok := diag(pp.ByRel["config.yaml"], "unmodeled_content")
	assert.True(t, ok)
	assert.Equal(t, "other", det)
	for rel, lang := range map[string]string{"scripts/x.ps1": "powershell", "scripts/z.rb": "ruby"} {
		a := pp.ByRel[rel]
		assert.NotNil(t, a.Text)
		assert.Equal(t, []Diagnostic{{Code: "unsupported_language", Detail: detail(lang)}}, a.Diagnostics)
	}
	for _, rel := range []string{"scripts/y.js", "scripts/t.ts", "scripts/w.tsx", "scripts/v.jsx", "scripts/u.mts", "scripts/s.cts"} { // the code lane runs OpenGrep on these
		assert.Empty(t, pp.ByRel[rel].Diagnostics, rel)
	}
	other := parsePkg(t, map[string]string{"SKILL.md": skill, "requirements-dev.txt": "x==1\n", "deps/other-requirements.txt": "y\n", "lock/requirements.lock": "z\n"})
	assert.Equal(t, []string{"x"}, depNames(other.ByRel["requirements-dev.txt"].Deps))
	assert.Equal(t, []string{"y"}, depNames(other.ByRel["deps/other-requirements.txt"].Deps))
	lock := other.ByRel["lock/requirements.lock"] // ingest classifies only *requirements*.txt as a manifest
	assert.Equal(t, "other", lock.Kind)
	assert.True(t, hasDiag(lock, "unmodeled_content"))
}

// test_deeply_nested_frontmatter_fails_closed; test_grants_non_list_str_shape_flagged;
// test_grant_non_string_element_flagged_not_stringified; test_one_hostile_manifest_does_not_abort_scan
func TestHostileFrontmatterThroughParse(t *testing.T) {
	a := parsePkg(t, map[string]string{"SKILL.md": "---\n" + strings.Repeat("[", 60000) + "\n---\n"}).ByRel["SKILL.md"]
	assert.Nil(t, a.Frontmatter)
	assert.True(t, hasDiag(a, "frontmatter_parse_error"))
	assert.Nil(t, a.Grants)

	m := parsePkg(t, map[string]string{"SKILL.md": "---\nname: t\nallowed-tools:\n  Bash: true\n---\n"}).ByRel["SKILL.md"]
	det, ok := diag(m, "grants_unparsed_shape")
	assert.True(t, ok)
	assert.Equal(t, "allowed-tools", det)
	assert.Equal(t, []Grant{}, m.Grants)

	e := parsePkg(t, map[string]string{"SKILL.md": "---\nname: t\nallowed-tools: [Read, {Bash: true}]\n---\n"}).ByRel["SKILL.md"]
	assert.Equal(t, [][3]any{{"Read", nil, true}}, grantTriples(e.Grants))
	assert.Equal(t, []Diagnostic{{Code: "grants_unparsed_shape", Detail: detail("allowed-tools")}}, e.Diagnostics)

	// an unparsed specifier flags its key once, whatever the shape check said
	u := parsePkg(t, map[string]string{"SKILL.md": "---\nname: t\nallowed-tools: Bash(curl:*))\ndisallowed-tools: [Read, 5, Tool(a)b]\n---\n"}).ByRel["SKILL.md"]
	assert.Equal(t, []Diagnostic{{Code: "grants_unparsed_shape", Detail: detail("allowed-tools")},
		{Code: "grants_unparsed_shape", Detail: detail("disallowed-tools")}}, u.Diagnostics)

	pp := parsePkg(t, map[string]string{"SKILL.md": "---\nx: !!bool notabool\n---\n", "scripts/clean.py": "x = 1\n"})
	det, ok = diag(pp.ByRel["SKILL.md"], "frontmatter_parse_error")
	assert.True(t, ok)
	assert.Equal(t, "yaml_error", det)
	assert.NotNil(t, pp.ByRel["scripts/clean.py"].PyTree)
}

// OpenClaw `metadata:` is a JSON flow mapping whose emoji is a JSON surrogate-pair escape inside
// a double-quoted scalar; ruamel parses it cleanly where yaml.v3 refuses the escape.
func TestOpenClawMetadataFlowMappingWithSurrogatePairEmojiEscapes(t *testing.T) {
	text := strings.Join([]string{"---", "name: t", "description: d", "metadata:", "  {", `    "openclaw": {`,
		`      "emoji": "\ud83e\uddea",`, `      "network": {"outbound": true}`, "    }", "  }", "user-invocable: true", "---", "# body", ""}, "\n")
	a := parsePkg(t, map[string]string{"SKILL.md": text}).ByRel["SKILL.md"]
	assert.Empty(t, a.Diagnostics)
	assert.Equal(t, []string{"name", "description", "metadata", "user-invocable"}, a.FrontmatterKeys)
	assert.Equal(t, map[string]int{"name": 2, "description": 3, "metadata": 4, "user-invocable": 11}, a.FrontmatterKeyLines)
	assert.Equal(t, 12, a.FrontmatterEndLine)
	assert.Equal(t, map[string]any{"openclaw": map[string]any{"emoji": "\U0001F9EA", "network": map[string]any{"outbound": true}}}, a.Frontmatter["metadata"])
}

// test_skill_manifest_frontmatter_grants_markdown; test_instruction_file_frontmatter_grants_parsed;
// test_doc_file_frontmatter_not_grant_parsed; test_frontmatter_dot_terminator_and_key_lines_wired;
// test_frontmatter_scalar_ampersand_star_not_alias; test_frontmatter_quoted_key_gets_line
func TestFrontmatterAndGrantsThroughParse(t *testing.T) {
	a := parsePkg(t, map[string]string{"SKILL.md": "---\nname: t\nallowed-tools: Bash\n---\n# H\nsee [r](r.md)\n", "r.md": "# r\n"}).ByRel["SKILL.md"]
	assert.Equal(t, "t", a.Frontmatter["name"])
	assert.Equal(t, [][3]any{{"Bash", nil, true}}, grantTriples(a.Grants))
	assert.Equal(t, 4, a.FrontmatterEndLine)
	// link line is offset past the frontmatter block (file line 6), not body line 2
	assert.Equal(t, []Link{{Href: "r.md", Label: "r", Line: 6}}, a.Markdown.Links)

	sub := parsePkg(t, map[string]string{"SKILL.md": skill, "sub.md": "---\nname: s\nallowed-tools: Bash\n---\n# s\n"}).ByRel["sub.md"]
	assert.Equal(t, "s", sub.Frontmatter["name"])
	assert.Equal(t, [][3]any{{"Bash", nil, true}}, grantTriples(sub.Grants))

	doc := parsePkg(t, map[string]string{"SKILL.md": skill, "README.md": "---\nallowed-tools: Bash\n---\n# r\n"}).ByRel["README.md"]
	assert.Nil(t, doc.Grants)
	assert.Nil(t, doc.Frontmatter)
	assert.Equal(t, 0, doc.FrontmatterEndLine)
	assert.NotNil(t, doc.Markdown)

	dot := parsePkg(t, map[string]string{"SKILL.md": "---\nname: t\nallowed-tools: Read\n...\n# body\n"}).ByRel["SKILL.md"]
	assert.Equal(t, "t", dot.Frontmatter["name"])
	assert.Equal(t, 3, dot.FrontmatterKeyLines["allowed-tools"])
	assert.Equal(t, 4, dot.FrontmatterEndLine)

	amp := parsePkg(t, map[string]string{"SKILL.md": "---\nname: t\ndescription: \"R&D and *args\"\nallowed-tools: Bash\n---\n"}).ByRel["SKILL.md"]
	assert.Equal(t, "t", amp.Frontmatter["name"])
	assert.Equal(t, [][3]any{{"Bash", nil, true}}, grantTriples(amp.Grants))

	q := parsePkg(t, map[string]string{"SKILL.md": "---\nname: t\n\"allowed-tools\": Bash\n---\n# h\n"}).ByRel["SKILL.md"]
	assert.Equal(t, 3, q.FrontmatterKeyLines["allowed-tools"])
	assert.Equal(t, [][3]any{{"Bash", nil, true}}, grantTriples(q.Grants))

	empty := parsePkg(t, map[string]string{"SKILL.md": "---\n---\nbody\n"}).ByRel["SKILL.md"]
	assert.Equal(t, map[string]any{}, empty.Frontmatter)
	assert.Nil(t, empty.Grants) // Python: `if fm:` is false for an empty block
	assert.Equal(t, 2, empty.FrontmatterEndLine)
	open := parsePkg(t, map[string]string{"SKILL.md": "---\nname: t\nbody\n"}).ByRel["SKILL.md"]
	assert.Equal(t, []Diagnostic{{Code: "frontmatter_parse_error", Detail: detail("frontmatter_unterminated")}}, open.Diagnostics)
	assert.Equal(t, 0, open.FrontmatterEndLine)
}

// test_rst_flagged_unsupported
func TestRstFlaggedUnsupported(t *testing.T) {
	a := parsePkg(t, map[string]string{"SKILL.md": skill, "guide.rst": "Title\n=====\n"}).ByRel["guide.rst"]
	assert.Equal(t, "unsupported_markup", a.Diagnostics[0].Code)
	assert.Equal(t, "rst", *a.Diagnostics[0].Detail)
}

// _resolve_refs over the link sets of test_refs_resolved_external_ignored, test_refs_nfc_matched_and_in_root_dotfile_kept,
// test_refs_parent_escape_dropped, test_refs_scheme_in_fragment_still_resolves, test_refs_query_string_stripped,
// test_refs_uri_scheme_not_resolved, independent of the markdown engine
func TestResolveRefs(t *testing.T) {
	nfd := norm.NFD.String("caf\u00e9.md")
	p := &Package{ByRel: map[string]*Artifact{}}
	add := func(rel string, links ...Link) {
		a := &Artifact{Rel: rel, Markdown: &Markdown{Links: links}}
		p.Artifacts = append(p.Artifacts, a)
		p.ByRel[rel] = a
	}
	add("SKILL.md",
		Link{Href: "refs/x.md", Line: 4}, Link{Href: "https://h/y", Line: 4}, Link{Href: nfd, Line: 5}, Link{Href: "..keep.md", Line: 6},
		Link{Href: "../secret.md", Line: 7}, Link{Href: "refs/x.md#see-http://z", Line: 8}, Link{Href: "refs/x.md?raw=1", Line: 9},
		Link{Href: "data:text/x,hi", Line: 10}, Link{Href: "file:///etc/passwd", Line: 11}, Link{Href: "", Line: 12}, Link{Href: "#frag", Line: 13},
		Link{Href: " refs/x.md ", Line: 14}, Link{Href: "refs/../refs/x.md", Line: 15}, Link{Href: "./SKILL.md", Line: 16}, Link{Href: ".", Line: 17},
		Link{Href: "refs/%78.md", Line: 18}, Link{Href: "/refs/x.md", Line: 19}, Link{Href: "MAILTO:x", Line: 20})
	add("refs/x.md", Link{Href: "../SKILL.md", Line: 1}, Link{Href: "x.md", Line: 2}, Link{Href: "../../SKILL.md", Line: 3}, Link{Href: "/SKILL.md", Line: 4})
	add("caf\u00e9.md")
	add("..keep.md")
	p.Artifacts = append(p.Artifacts, &Artifact{Rel: "a.py", Kind: "script_python"}) // no markdown: contributes nothing
	assert.Equal(t, []Ref{
		{"SKILL.md", "refs/x.md", 4}, {"SKILL.md", "caf\u00e9.md", 5}, {"SKILL.md", "..keep.md", 6}, {"SKILL.md", "refs/x.md", 8},
		{"SKILL.md", "refs/x.md", 9}, {"SKILL.md", "refs/x.md", 14}, {"SKILL.md", "refs/x.md", 15}, {"SKILL.md", "SKILL.md", 16},
		{"SKILL.md", "refs/x.md", 18},
		{"refs/x.md", "SKILL.md", 1}, {"refs/x.md", "refs/x.md", 2},
	}, resolveRefs(p))
	assert.Equal(t, []Ref{}, resolveRefs(&Package{}))
}

// test_refs_resolved_external_ignored; test_refs_nfc_matched_and_in_root_dotfile_kept; test_refs_parent_escape_dropped;
// test_refs_scheme_in_fragment_still_resolves; test_refs_query_string_stripped; test_refs_uri_scheme_not_resolved
func TestRefsThroughParse(t *testing.T) {
	nfd := norm.NFD.String("caf\u00e9.md")
	pp := parsePkg(t, map[string]string{
		"SKILL.md": "---\nname: t\n---\nsee [x](refs/x.md) and [ext](https://h/y)\n[a](" + nfd + ")\n[b](..keep.md)\n[e](../secret.md)\n" +
			"[f](refs/x.md#see-http://z)\n[q](refs/x.md?raw=1)\n[d](data:text/x,hi)\n[p](file:///etc/passwd)\n",
		"refs/x.md": "# x\n", "caf\u00e9.md": "# c\n", "..keep.md": "# k\n"})
	tos := map[string]int{}
	for _, r := range pp.Refs {
		assert.Equal(t, "SKILL.md", r.From)
		tos[r.To]++
	}
	assert.Equal(t, map[string]int{"refs/x.md": 3, "caf\u00e9.md": 1, "..keep.md": 1}, tos)
}

// test_diagnostics_mirrored_into_ledger; test_package_wall_clock_budget_flags_not_skips; test_parse_crash_isolation;
// test_parse_is_deterministic
func TestPackageLevel(t *testing.T) {
	pp := parsePkg(t, map[string]string{"SKILL.md": skill, "hooks.json": "{bad"})
	require.Len(t, pp.LedgerExceptions, 1)
	e := pp.LedgerExceptions[0]
	assert.Equal(t, "unresolved", e.Outcome)
	assert.Equal(t, "parse", e.Phase)
	assert.Equal(t, "config_parse_error", e.ReasonCode)
	assert.Equal(t, "hooks.json", e.Path)
	assert.True(t, strings.HasPrefix(*e.Detail, "json_parse_error:"))

	testutil.Swap(t, &pkgBudget, -time.Second)
	over := parsePkg(t, map[string]string{"SKILL.md": skill, "scripts/a.py": "x = 1\n"})
	for _, a := range over.Artifacts {
		assert.Equal(t, []Diagnostic{{Code: "parse_budget_exceeded"}}, a.Diagnostics, a.Rel)
	}
	testutil.Swap(t, &pkgBudget, 60*time.Second)

	testutil.Swap(t, &parseMD, func(*Artifact, string, bool) { panic("boom") })
	crash := parsePkg(t, map[string]string{"SKILL.md": skill, "scripts/a.py": "x = 1\n"})
	det, ok := diag(crash.ByRel["SKILL.md"], "parse_crash")
	assert.True(t, ok)
	assert.Equal(t, "string", det)
	assert.NotNil(t, crash.ByRel["scripts/a.py"].PyTree)

	files := map[string]string{"SKILL.md": "---\nname: t\nallowed-tools: Bash(x)\n---\n# H\n[r](r.md)\nrun !`id`\n",
		"r.md": "# r\n", "scripts/a.py": "x = 1\n", "hooks.json": `{"hooks": {}}`}
	pkg := ingest.BuildPackage(testutil.MakePackage(t, files))
	p1, p2 := Parse(pkg), Parse(pkg)
	rels := func(p *Package) []string {
		out := []string{}
		for _, a := range p.Artifacts {
			out = append(out, a.Rel)
		}
		return out
	}
	assert.Equal(t, []string{"SKILL.md", "hooks.json", "r.md", "scripts/a.py"}, rels(p1))
	assert.Equal(t, rels(p1), rels(p2))
	assert.Equal(t, p1.Refs, p2.Refs)
	assert.Equal(t, p1.LedgerExceptions, p2.LedgerExceptions)
	assert.Equal(t, pkg.Identity, p1.Identity)
	assert.Equal(t, pkg.Name, p1.Name)
	assert.Equal(t, "hooks", p1.ByRel["hooks.json"].ManifestKind)
}

// The CRLF/CR text is normalised once, and the raw bytes are carried untouched.
func TestTextIsNormalisedOnce(t *testing.T) {
	a := parsePkg(t, map[string]string{"SKILL.md": "---\r\nname: t\r\n---\r\nbody\rmore\r\n"}).ByRel["SKILL.md"]
	assert.Equal(t, "---\nname: t\n---\nbody\nmore\n", *a.Text)
	assert.Equal(t, []byte("---\r\nname: t\r\n---\r\nbody\rmore\r\n"), a.Raw)
	assert.Equal(t, 3, a.FrontmatterEndLine)
	assert.Equal(t, "body\nmore\n", func() string { b, _ := bodyAndOffset(*a.Text); return b }())
}
