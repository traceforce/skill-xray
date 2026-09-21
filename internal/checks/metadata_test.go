package checks

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
)

// The 14 SXV-034 cases of tests/test_metadata.py; the SXV-033 cases are the OpenGrep bridge's.

func none(fs []findings.Finding, vector string) bool {
	return !slices.ContainsFunc(fs, func(f findings.Finding) bool { return f.Vector == vector })
}

// tests/test_metadata.py::test_unsafe_object_tag_reports_exact_parser_location
func TestUnsafeObjectTagReportsExactParserLocation(t *testing.T) {
	for tag, expected := range map[string]string{
		"!!python/object/apply:os.system":      "tag:yaml.org,2002:python/object/apply:os.system",
		"!!python/object/new:subprocess.Popen": "tag:yaml.org,2002:python/object/new:subprocess.Popen",
		"!ruby/object:Gem::Requirement":        "!ruby/object:Gem::Requirement",
		"!!python/object:example.Payload":      "tag:yaml.org,2002:python/object:example.Payload",
		"!!python/name:os.system":              "tag:yaml.org,2002:python/name:os.system",
		"!!python/module:os":                   "tag:yaml.org,2002:python/module:os",
		"!ruby/hash:Example":                   "!ruby/hash:Example",
	} {
		t.Run(tag, func(t *testing.T) {
			fs := run(t, map[string]string{"SKILL.md": "---\nname: demo\npayload: " + tag + " [echo]\n---\nbody\n"})
			i := slices.IndexFunc(fs, func(f findings.Finding) bool { return f.Vector == "SXV-034" })
			require.NotEqual(t, -1, i)
			hit := fs[i]
			assert.Equal(t, findings.Finding{Vector: "SXV-034", Rule: "unsafe-yaml-tag", Severity: "critical", Path: "SKILL.md",
				Line: findings.Int(3), Column: findings.Int(10), Message: hit.Message, Evidence: map[string]any{"tag": expected}}, hit)
		})
	}
}

// tests/test_metadata.py::test_known_java_gadget_tag_reports_but_custom_namespace_does_not
func TestKnownJavaGadgetTagReportsButCustomNamespaceDoesNot(t *testing.T) {
	dangerous := "---\nname: demo\nallowed-tools: Read\nloader: !!javax.script.ScriptEngineManager []\n---\nbody\n"
	benign := "---\nname: demo\nallowed-tools: Read\nvalue: !!com.example.Value ordinary\n---\nbody\n"
	assert.False(t, none(run(t, map[string]string{"SKILL.md": dangerous}), "SXV-034"))
	assert.True(t, none(run(t, map[string]string{"SKILL.md": benign}), "SXV-034"))
}

// tests/test_metadata.py::test_python_object_prefix_lookalike_is_not_a_constructor_tag
func TestPythonObjectPrefixLookalikeIsNotAConstructorTag(t *testing.T) {
	assert.True(t, none(run(t, map[string]string{"SKILL.md": "---\nname: demo\nvalue: !!python/objective ordinary\n---\nbody\n"}), "SXV-034"))
}

// tests/test_metadata.py::test_dangerous_tag_in_malformed_yaml_is_incomplete_not_sxv034
func TestDangerousTagInMalformedYamlIsIncompleteNotSXV034(t *testing.T) {
	fs := run(t, map[string]string{"SKILL.md": "---\nname: demo\npayload: !!python/name:os.system\nbroken: [\n---\nbody\n"})
	assert.True(t, none(fs, "SXV-034"))
	assert.True(t, has(fs, "coverage-note", "", "", "frontmatter_parse_error"))
}

// tests/test_metadata.py::test_unsafe_tag_lookalikes_outside_yaml_tag_tokens_do_not_report
func TestUnsafeTagLookalikesOutsideYamlTagTokensDoNotReport(t *testing.T) {
	for _, text := range []string{
		"---\nname: demo\nnote: '!!python/object/apply:os.system'\n---\nbody\n",
		"---\nname: demo\n# !!python/object/apply:os.system\n---\nbody\n",
		"---\nname: demo\n---\nMention !!python/object/apply:os.system in prose.\n",
	} {
		assert.True(t, none(run(t, map[string]string{"SKILL.md": text}), "SXV-034"), text)
	}
}

// tests/test_metadata.py::test_unterminated_frontmatter_is_incomplete_not_asserted_unsafe
func TestUnterminatedFrontmatterIsIncompleteNotAssertedUnsafe(t *testing.T) {
	fs := run(t, map[string]string{"SKILL.md": "---\nname: demo\npayload: !!python/object/apply:os.system [echo]\n"})
	assert.True(t, none(fs, "SXV-034"))
	assert.True(t, has(fs, "coverage-note", "", "SKILL.md", ""))
}
