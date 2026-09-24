package parse

// Frontmatter and grant tests ported from tests/test_parse.py (each Go test names its pytest
// source) plus tables probed on the oracle (ruamel.yaml 0.18.15 through parse._fm_load).

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/pytext"
)

func fm(t *testing.T, text string) (*Artifact, string) {
	t.Helper()
	a := &Artifact{}
	return a, loadFrontmatter(a, text)
}

// test_frontmatter_description_shapes
func TestFrontmatterDescriptionShapes(t *testing.T) {
	for _, body := range []string{
		"---\nname: t\ndescription: plain\n---\n",
		"---\nname: t\ndescription: \"quoted, comma\"\n---\n",
		"---\nname: t\ndescription: |\n  literal\n  block\n---\n",
		"---\nname: t\ndescription: >-\n  folded block\n---\n",
	} {
		a, err := fm(t, body)
		assert.Equal(t, "", err)
		assert.Equal(t, "t", a.Frontmatter["name"])
		assert.Contains(t, a.Frontmatter, "description")
	}
}

// test_frontmatter_unsafe_python_tag_flagged; test_frontmatter_loader_is_per_artifact_isolated
func TestFrontmatterUnsafePythonTagFlagged(t *testing.T) {
	a, err := fm(t, "---\nx: !!python/object/apply:os.system [\"true\"]\n---\n")
	assert.Equal(t, "yaml_unsafe_tag", err)
	assert.Nil(t, a.Frontmatter)
	assert.Empty(t, a.FrontmatterKeyLines)
	assert.Equal(t, []YamlTag{{Tag: "tag:yaml.org,2002:python/object/apply:os.system", Line: 2, Column: 4}}, a.UnsafeYamlTags)

	b, err := fm(t, "---\nname: t\nallowed-tools: Bash\n---\n")
	assert.Equal(t, "", err)
	assert.Equal(t, map[string]any{"name": "t", "allowed-tools": "Bash"}, b.Frontmatter)
}

// test_metadata.py::test_unsafe_object_tag_reports_exact_parser_location
func TestUnsafeObjectTagReportsExactParserLocation(t *testing.T) {
	for tag, want := range map[string]string{
		"!!python/object/apply:os.system": "tag:yaml.org,2002:python/object/apply:os.system",
		"!ruby/hash:Example":              "!ruby/hash:Example",
	} {
		a, err := fm(t, "---\nname: demo\npayload: "+tag+" [echo]\n---\nbody\n")
		assert.Equal(t, "yaml_unsafe_tag", err)
		assert.Equal(t, []YamlTag{{Tag: want, Line: 3, Column: 10}}, a.UnsafeYamlTags)
	}
	// test_metadata.py::test_known_java_gadget_tag_reports_but_custom_namespace_does_not
	_, err := fm(t, "---\nname: demo\nloader: !!javax.script.ScriptEngineManager []\n---\n")
	assert.Equal(t, "yaml_unsafe_tag", err)
	a, err := fm(t, "---\nname: demo\nvalue: !!com.example.Value ordinary\n---\n")
	assert.Equal(t, "", err)
	assert.Equal(t, Opaque{"TaggedScalar", "ordinary"}, a.Frontmatter["value"])
}

// test_frontmatter_timestamp_value_error_fails_closed
func TestFrontmatterTimestampValueErrorFailsClosed(t *testing.T) {
	a, err := fm(t, "---\ndate: 2001-02-30\n---\n")
	assert.Nil(t, a.Frontmatter)
	assert.True(t, strings.HasPrefix(err, "yaml_error"), err)
}

// test_frontmatter_key_lines; test_frontmatter_quoted_key_gets_line
func TestFrontmatterKeyLines(t *testing.T) {
	a, err := fm(t, "---\nname: t\ndescription: d\n---\n")
	assert.Equal(t, "", err)
	assert.Equal(t, map[string]int{"name": 2, "description": 3}, a.FrontmatterKeyLines)
	assert.Equal(t, []string{"name", "description"}, a.FrontmatterKeys)
	assert.Equal(t, 4, a.FrontmatterEndLine)
	q, _ := fm(t, "---\nname: t\n\"allowed-tools\": Bash\n---\n# h\n")
	assert.Equal(t, 3, q.FrontmatterKeyLines["allowed-tools"])
}

// test_frontmatter_duplicate_key_rejected
func TestFrontmatterDuplicateKeyRejected(t *testing.T) {
	a, err := fm(t, "---\ncommand: safe\ncommand: rm -rf /\n---\n")
	assert.Nil(t, a.Frontmatter)
	assert.Equal(t, "yaml_duplicate_key", err)
}

// test_frontmatter_alias_budget_refused; test_frontmatter_alias_budget_counts_non_ascii_anchors;
// test_frontmatter_recursive_alias_refused
func TestFrontmatterAliasBudgetRefused(t *testing.T) {
	for _, name := range []string{"a", "\u00e9"} {
		var b strings.Builder
		b.WriteString("---\n")
		refs := make([]string, 70)
		for i := range 70 {
			fmt.Fprintf(&b, "  - &%s%d x\n", name, i)
			refs[i] = fmt.Sprintf("*%s%d", name, i)
		}
		fmt.Fprintf(&b, "refs: [%s]\n---\n", strings.Join(refs, ","))
		a, err := fm(t, b.String())
		assert.Nil(t, a.Frontmatter)
		assert.Equal(t, "yaml_alias_budget", err)
	}
	a, err := fm(t, "---\nx: &x [*x]\n---\n")
	assert.Nil(t, a.Frontmatter)
	assert.Equal(t, "yaml_alias_budget", err)
}

// test_frontmatter_inline_merge_without_alias_is_bounded
func TestFrontmatterInlineMergeWithoutAliasIsBounded(t *testing.T) {
	a, err := fm(t, "---\nx:\n  <<: {k: v}\n---\n")
	assert.Equal(t, "", err)
	assert.Equal(t, "v", a.Frontmatter["x"].(map[string]any)["k"])
}

// test_frontmatter_merge_bomb_defused_all_forms
func TestFrontmatterMergeBombDefusedAllForms(t *testing.T) {
	for _, form := range []string{"flow", "block", "explicit", "seqitem"} {
		lines := []string{"l0: &l0 {a: 1}"}
		for i := 1; i < 18; i++ {
			seq := fmt.Sprintf("[*l%d, *l%d]", i-1, i-1)
			switch form {
			case "flow":
				lines = append(lines, fmt.Sprintf("l%d: &l%d {<<: %s}", i, i, seq))
			case "block":
				lines = append(lines, fmt.Sprintf("l%d: &l%d\n  <<: %s", i, i, seq))
			case "explicit":
				lines = append(lines, fmt.Sprintf("l%d: &l%d\n  ? <<\n  : %s", i, i, seq))
			default:
				lines = append(lines, fmt.Sprintf("l%d: &l%d\n  - <<: %s", i, i, seq))
			}
		}
		start := time.Now()
		a, err := fm(t, "---\n"+strings.Join(lines, "\n")+"\ntop: {<<: *l17}\n---\n")
		assert.Nil(t, a.Frontmatter)
		assert.Equal(t, "yaml_alias_budget", err, form)
		assert.Less(t, time.Since(start), 3*time.Second) // linear vs quadratic: seconds apart, agents share the CPU
	}
}

// test_frontmatter_yaml_error_reports_true_file_line
func TestFrontmatterYamlErrorReportsTrueFileLine(t *testing.T) {
	a, err := fm(t, "---\nname: t\nbad: : :\n---\n")
	assert.Nil(t, a.Frontmatter)
	assert.Equal(t, "yaml_error:line 3", err)
}

// test_frontmatter_indented_delimiter_not_terminator
func TestFrontmatterIndentedDelimiterNotTerminator(t *testing.T) {
	a, err := fm(t, "---\ndescription: |\n  ---\nallowed-tools: Bash\n---\n")
	assert.Equal(t, "", err)
	assert.Equal(t, "Bash", a.Frontmatter["allowed-tools"])
	assert.Contains(t, a.Frontmatter, "description")
}

// test_frontmatter_bom_and_crlf
func TestFrontmatterBomAndCrlf(t *testing.T) {
	a, err := fm(t, "\ufeff---\r\nname: t\r\nallowed-tools: Bash\r\n---\r\n")
	assert.Equal(t, "", err)
	assert.Equal(t, map[string]any{"name": "t", "allowed-tools": "Bash"}, a.Frontmatter)
}

// test_frontmatter_no_phantom_key_from_flow_value; test_frontmatter_key_line_prefers_top_level
func TestFrontmatterKeyLinesAreTopLevelOnly(t *testing.T) {
	a, err := fm(t, "---\ndata: {\n\"x\": 1,\n\"y\": 2}\n---\n")
	assert.Equal(t, "", err)
	assert.Equal(t, map[string]int{"data": 2}, a.FrontmatterKeyLines)
	b, err := fm(t, "---\nname: top\ndata: {\n\"name\": nested}\n---\n")
	assert.Equal(t, "", err)
	assert.Equal(t, 2, b.FrontmatterKeyLines["name"])
}

// test_deeply_nested_frontmatter_fails_closed (unit half); test_frontmatter_depth_guard_ignores_quoted_brackets;
// test_frontmatter_depth_guard_honors_escaped_quote_no_grant_evasion; test_frontmatter_deep_flow_rejected;
// test_depth_guard_not_fooled_by_bare_closes; test_depth_guard_ignores_block_and_plain_scalar_brackets;
// test_frontmatter_multiline_plain_scalar_keeps_grant; test_depth_guard_not_bypassed_by_node_property;
// test_depth_guard_hash_is_comment_only_when_spaced; test_depth_guard_delimiters_inside_scalars_are_data
func TestFrontmatterDepthGuard(t *testing.T) {
	open70 := strings.Repeat("[", 70)
	for _, tc := range []struct {
		text, err, grant string
	}{
		{"---\n" + strings.Repeat("[", 60000) + "\n---\n", "frontmatter_too_large", ""},
		{"---\ndescription: \"" + open70 + "\"\nname: t\n---\n", "", ""},
		{"---\nd: \"x\\\"" + open70 + "\"\nallowed-tools: Bash\n---\n", "", "Bash"},
		{"---\nx: " + strings.Repeat("[", 5000) + "\n---\n", "frontmatter_too_deep", ""},
		{"---\na: [1]\nb: " + strings.Repeat("[", 5000) + "\n---\n", "frontmatter_too_deep", ""},
		{"---\ndesc: |\n  use " + open70 + " here\nallowed-tools: Bash\n---\n", "", "Bash"},
		{"---\nx: use " + open70 + "\nallowed-tools: Read\n---\n", "", "Read"},
		{"---\ndescription: text\n  " + open70 + "\nallowed-tools: Bash\n---\n", "", "Bash"},
		{"---\nx: [foo#bar, " + strings.Repeat("[", 8000) + "\n---\n", "frontmatter_too_deep", ""},
		{"---\nx: a, b, " + open70 + "\nallowed-tools: Bash\n---\n", "", "Bash"},
		{"---\nx: a-b-" + open70 + "\nallowed-tools: Bash\n---\n", "", "Bash"},
		{"---\nx: a:" + open70 + "\nallowed-tools: Bash\n---\n", "", "Bash"},
		{"---\nt:\n  - " + strings.Repeat("[", 8000) + "\n---\n", "frontmatter_too_deep", ""},
	} {
		a, err := fm(t, tc.text)
		assert.Equal(t, tc.err, err, tc.text[:min(40, len(tc.text))])
		if tc.grant != "" {
			assert.Equal(t, tc.grant, a.Frontmatter["allowed-tools"])
		}
	}
	a, err := fm(t, "---\ndescription: \""+open70+"\"\nname: t\n---\n")
	assert.Equal(t, "", err)
	assert.Equal(t, map[string]int{"description": 2, "name": 3}, a.FrontmatterKeyLines)
	_, err = fm(t, "---\nx: "+strings.Repeat("}", 200)+strings.Repeat("{", 70)+"\n---\n")
	assert.NotEqual(t, "", err)
	for _, prop := range []string{"!!seq ", "!foo ", "&a "} {
		_, err := fm(t, "---\nx: "+prop+strings.Repeat("[", 8000)+"\n---\n")
		assert.Contains(t, []string{"frontmatter_too_deep", "yaml_alias_budget"}, err)
	}
}

// Values, keys, key lines and error codes probed on the oracle (parse._fm_load, ruamel 0.18.15);
// the block is the text between the --- lines, values are rendered through pytext.Canonical
// (Opaque scalars as [type, str]).
func TestFrontmatterValuesMatchRuamel(t *testing.T) {
	for _, tc := range []struct{ block, err, values, keys string }{
		{"name: t\nbad: : :", "yaml_error:line 3", "", ""},
		{"a:\n\tb: 1", "yaml_error:line 3", "", ""},
		{"a: [1,", "yaml_error:line 2", "", ""},
		{"a: b: c", "yaml_error:line 2", "", ""},
		{"a: 'x", "yaml_error:line 2", "", ""},
		{"a: \"x\\z\"", "yaml_error:line 2", "", ""},
		// surrogate escapes: ruamel keeps chr() of each half ('\ud83e\uddea', '\ud83e', '\uddea',
		// '\ud83e' for \U0000D83E, 'foo bar \ud83e'), Go pairs the halves and holds a lone half as
		// U+FFFD; single-quoted and plain forms are literal text on both sides
		{"a: \"\\ud83e\\uddea\"\nb: \"\\ud83d\\uddc4\\ufe0f\"", "", `{"a":"\ud83e\uddea","b":"\ud83d\uddc4\ufe0f"}`, `["a","b"]`},
		{"a: \"\\ud83e\"\nb: \"\\uddea\"\nc: \"\\uddea\\ud83e\"\nd: \"\\U0000D83E\"", "", `{"a":"\ufffd","b":"\ufffd","c":"\ufffd\ufffd","d":"\ufffd"}`, `["a","b","c","d"]`},
		{"a: '\\ud83e\\uddea'\nb: \\ud83e\\uddea\nc: {s: 'lit \\ud83e', d: \"\\ud83e\\uddea\"}", "", `{"a":"\\ud83e\\uddea","b":"\\ud83e\\uddea","c":{"d":"\ud83e\uddea","s":"lit \\ud83e"}}`, `["a","b","c"]`},
		{"a: \"foo\n  bar \\ud83e\"\nb: 1", "", `{"a":"foo bar \ufffd","b":1}`, `["a","b"]`},
		{"\"\\ud83e\": 1", "", `{"\ufffd":1}`, `["\ufffd"]`},
		{"a: \"\\U00110000\"", "yaml_error", "", ""},
		{"a: -", "yaml_error:line 2", "", ""},
		{"\ta: 1", "yaml_error:line 2", "", ""},
		{"a: 1\n  b: 2", "yaml_error:line 3", "", ""},
		{"a: !!seq abc\nb: [", "yaml_error:line 3", "", ""},
		{"a: 1\n--- foo\nb: 2", "yaml_error:line 4", "", ""},
		{"&a x: 1", "yaml_alias_budget", "", ""},
		{"a: *b", "yaml_alias_budget", "", ""},
		{"a: !!bool notabool", "yaml_error", "", ""},
		{"x: !!int abc", "yaml_error", "", ""},
		{"x: 2001-02-03T99:00:00Z", "yaml_error", "", ""},
		{"x: 2001-13-01", "yaml_error", "", ""},
		{"x: !!timestamp abc", "yaml_error:line 2", "", ""},
		{"x: !!map abc", "yaml_error:line 2", "", ""},
		{"x: !!seq abc", "yaml_error:line 2", "", ""},
		{"x:\n  <<: 5", "yaml_error:line 3", "", ""},
		{"x:\n  <<: [1]", "yaml_error:line 3", "", ""},
		{"a: 1\na: 2", "yaml_duplicate_key", "", ""},
		{"a:\n  b: 1\n  b: 2", "yaml_duplicate_key", "", ""},
		{"a: 1\n\"a\": 2", "yaml_duplicate_key", "", ""},
		{"\"x\": 1\n'x': 2", "yaml_duplicate_key", "", ""},
		{"5", "frontmatter_not_a_mapping", "", ""},
		{"[1, 2]", "frontmatter_not_a_mapping", "", ""},
		{"", "", "{}", "[]"},
		{"# only comment", "", "{}", "[]"},
		{"~", "", "{}", "[]"},
		{"null", "", "{}", "[]"},
		{"x: !!null abc", "", `{"x":null}`, `["x"]`},
		{"x: !!str [1]", "", `{"x":[1]}`, `["x"]`},
		{"x: !!str 5", "", `{"x":["TaggedScalar","5"]}`, `["x"]`},
		{"x: !foo bar", "", `{"x":["TaggedScalar","bar"]}`, `["x"]`},
		{"y: !foo [1,2]\nz: !bar {a: 1}", "", `{"y":[1,2],"z":{"a":1}}`, `["y","z"]`},
		{"x: !!float 1\ny: !!bool yes\nz: !!int 0x10", "", `{"x":1.0,"y":true,"z":16}`, `["x","y","z"]`},
		{"1: a\n\"1\": b", "", `{"1":"b"}`, `["1"]`},
		{"a: [1, 1]", "", `{"a":[1,1]}`, `["a"]`},
		{"x:\n  <<: {k: v}\n  a: 1\nb: 2", "", `{"b":2,"x":{"a":1,"k":"v"}}`, `["x","b"]`},
		{"d: 2001-02-03", "", `{"d":["date","2001-02-03"]}`, `["d"]`},
		{"d: 2001-02-03T04:05:06Z", "", `{"d":["TimeStamp","2001-02-03T04:05:06+00:00"]}`, `["d"]`},
		{"d: 2001-02-03 04:05:06.5 +02:00", "", `{"d":["TimeStamp","2001-02-03 04:05:06.500000+02:00"]}`, `["d"]`},
		{"d: 2001-02-03t04:05:06-01:30", "", `{"d":["TimeStamp","2001-02-03T04:05:06-01:30"]}`, `["d"]`},
		{"d: 2001-02-03 04:05:06", "", `{"d":["datetime","2001-02-03 04:05:06"]}`, `["d"]`},
		{"d: 2001-02-03 04:05:06Z", "", `{"d":["datetime","2001-02-03 04:05:06+00:00"]}`, `["d"]`},
		{"d: 2001-02-03 04:05:06 -5", "", `{"d":["TimeStamp","2001-02-03 04:05:06-05:00"]}`, `["d"]`},
		{"d: 2001-02-03T04:05:06.123456789Z", "", `{"d":["TimeStamp","2001-02-03T04:05:06.123457+00:00"]}`, `["d"]`},
		{"d: 2001-02-03 04:05:06.1", "", `{"d":["datetime","2001-02-03 04:05:06.100000"]}`, `["d"]`},
		{"d: 2001-1-2 3:04:05", "", `{"d":["datetime","2001-01-02 03:04:05"]}`, `["d"]`},
		{"d: 2001-02-03 04:05:06.", "", `{"d":["datetime","2001-02-03 04:05:06"]}`, `["d"]`},
		{"d: 2001-02-03T04:05:06+5:30", "", `{"d":["TimeStamp","2001-02-03T04:05:06+05:30"]}`, `["d"]`},
		{"d: 2001-2-3\ne: 12:30:00\nf: 2001-02-03 4:5:6", "", `{"d":"2001-2-3","e":"12:30:00","f":"2001-02-03 4:5:6"}`, `["d","e","f"]`},
		{"x: !!timestamp 2001-2-3", "", `{"x":["date","2001-02-03"]}`, `["x"]`},
		{"a: 014\nb: 0777\nc: 08\nd: 010\ne: 1_000\nf: 0o14\ng: 0x1f\nh: 0b101\ni: 1_\nj: -0\nk: +1", "",
			`{"a":14,"b":777,"c":8,"d":10,"e":1000,"f":12,"g":31,"h":5,"i":1,"j":0,"k":1}`, `["a","b","c","d","e","f","g","h","i","j","k"]`},
		{"a: 12345678901234567890\nb: 9223372036854775808", "", `{"a":12345678901234567890,"b":9223372036854775808}`, `["a","b"]`},
		{"a: yes\nb: on\nc: Yes\nd: TRUE\ne: True_\nf: NULL\ng: 1:30\nh: 08:30\ni: 123abc\nj: 1.5e\nk: _1\nl: 0x\nm: 0b2", "",
			`{"a":"yes","b":"on","c":"Yes","d":true,"e":"True_","f":null,"g":"1:30","h":"08:30","i":"123abc","j":"1.5e","k":"_1","l":"0x","m":"0b2"}`,
			`["a","b","c","d","e","f","g","h","i","j","k","l","m"]`},
		{"a: 1e3\nb: 5.\nc: -.5\nd: .5\ne: 1_0.5\nf: 0.\ng: 1.0_0\nh: 3_.5\ni: -_1", "",
			`{"a":1000.0,"b":5.0,"c":-0.5,"d":0.5,"e":10.5,"f":0.0,"g":1.0,"h":3.5,"i":-1}`, `["a","b","c","d","e","f","g","h","i"]`},
		{"?", "", `{"None":null}`, `["None"]`},
		{"a:\nb: ''\nc: 'null'\nd: +\ne: 1.2.3", "", `{"a":null,"b":"","c":"null","d":"+","e":"1.2.3"}`, `["a","b","c","d","e"]`},
		{"1: a\n~: c\n1.5: d\n2001-02-03: e\n1e3: f\n0x10: j", "", `{"1":"a","1.5":"d","1000.0":"f","16":"j","2001-02-03":"e","None":"c"}`,
			`["1","None","1.5","2001-02-03","1000.0","16"]`},
		{"a: |\n  x\n  y\nb: >-\n  x\n  y\nc:\n  - 1\n  - 2", "", `{"a":"x\ny\n","b":"x y","c":[1,2]}`, `["a","b","c"]`},
	} {
		a, err := fm(t, "---\n"+tc.block+"\n---\n")
		assert.Equal(t, tc.err, err, tc.block)
		if tc.err != "" {
			assert.Nil(t, a.Frontmatter, tc.block)
			continue
		}
		require.NotNil(t, a.Frontmatter, tc.block)
		assert.Equal(t, tc.values, pytext.Canonical(a.Frontmatter), tc.block)
		assert.Equal(t, tc.keys, pytext.Canonical(a.FrontmatterKeys), tc.block)
	}
	a, _ := fm(t, "---\n1: a\n~: c\n---\n")
	assert.Equal(t, map[string]int{"1": 2, "None": 3}, a.FrontmatterKeyLines)
}

// --- grants ---

func grantTriples(gs []Grant) [][3]any {
	out := [][3]any{}
	for _, g := range gs {
		var p any
		if g.Pattern != nil {
			p = *g.Pattern
		}
		out = append(out, [3]any{g.Tool, p, g.Parsed})
	}
	return out
}

// test_grants_specifier_vs_bare_broad
func TestGrantsSpecifierVsBareBroad(t *testing.T) {
	grants := map[string]Grant{}
	for _, g := range parseGrants(map[string]any{"allowed-tools": "Read, Bash(python scripts/fetch.py:*), Bash"}) {
		grants[g.Raw] = g
	}
	assert.True(t, grants["Read"].Broad)
	assert.Nil(t, grants["Read"].Pattern)
	spec := grants["Bash(python scripts/fetch.py:*)"]
	assert.Equal(t, "Bash", spec.Tool)
	assert.Equal(t, "python scripts/fetch.py:*", *spec.Pattern)
	assert.False(t, spec.Broad)
	assert.True(t, grants["Bash"].Broad)
}

// test_grants_list_form_and_disallowed
func TestGrantsListFormAndDisallowed(t *testing.T) {
	grants := parseGrants(map[string]any{"allowed-tools": []any{"Read", "Write"}, "disallowed-tools": []any{"Bash"}})
	allowed := 0
	denied := false
	for _, g := range grants {
		if g.Allowed {
			allowed++
		}
		denied = denied || (g.Tool == "Bash" && !g.Allowed)
	}
	assert.True(t, denied)
	assert.Equal(t, 2, allowed)
}

// test_grants_comma_inside_parens_not_split; test_grants_space_separated_specifiers_are_independent;
// test_grant_keeps_whitespace_before_pattern_parenthesis; test_unbalanced_grant_parentheses_remain_unparsed;
// test_quoted_parenthesis_does_not_absorb_following_grant; plus rows probed on the oracle
func TestGrantSplitting(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  [][3]any
	}{
		{"Bash(a, b), Read", [][3]any{{"Bash", "a, b", true}, {"Read", nil, true}}},
		{"Bash(curl:*) Bash(jq:*)", [][3]any{{"Bash", "curl:*", true}, {"Bash", "jq:*", true}}},
		{"Bash (curl:*) Read", [][3]any{{"Bash", "curl:*", true}, {"Read", nil, true}}},
		{"Bash(curl:*))", [][3]any{{"Bash(curl:*))", nil, false}}},
		{"Bash((curl:*)", [][3]any{{"Bash((curl:*)", nil, false}}},
		{"Bash(echo \"(\":*) Read", [][3]any{{"Bash", "echo \"(\":*", true}, {"Read", nil, true}}},
		{"Bash(\"unterminated)", [][3]any{{"Bash(\"unterminated)", nil, false}}},
		{"Bash('a b') Read, Write(x)", [][3]any{{"Bash", "'a b'", true}, {"Read", nil, true}, {"Write", "x", true}}},
		{"Bash( * ) , , Read", [][3]any{{"Bash", " * ", true}, {"Read", nil, true}}},
		{"Bash(a\\,b) mcp__x.y-z", [][3]any{{"Bash", "a\\,b", true}, {"mcp__x.y-z", nil, true}}},
		{"Bash(\"a) b\") Read", [][3]any{{"Bash", "\"a) b\"", true}, {"Read", nil, true}}},
		{"Bash(\\)) Read", [][3]any{{"Bash", "\\)", true}, {"Read", nil, true}}},
		{"Bash(x)\u00a0Read\u2003Write", [][3]any{{"Bash", "x", true}, {"Read", nil, true}, {"Write", nil, true}}},
		{"Tool(a)b", [][3]any{{"Tool(a)b", nil, false}}},
		{"Tool()", [][3]any{{"Tool", "", true}}},
		{"9tool Bash", [][3]any{{"9tool", nil, false}, {"Bash", nil, true}}},
		{"Bash\n(x)", [][3]any{{"Bash", "x", true}}},
		{"Bash(\"x\") 'quoted' \"dq\"", [][3]any{{"Bash", "\"x\"", true}, {"'quoted'", nil, false}, {"\"dq\"", nil, false}}},
	} {
		assert.Equal(t, tc.want, grantTriples(parseGrants(map[string]any{"allowed-tools": tc.value})), tc.value)
	}
	for _, spec := range []string{"Bash(curl:*))", "Bash((curl:*)"} {
		g := parseGrants(map[string]any{"allowed-tools": spec})[0]
		assert.Equal(t, spec, g.Raw)
		assert.False(t, g.Parsed)
		assert.True(t, g.Broad)
	}
	// non-string forms: a mapping yields no specifiers, non-string list elements are dropped
	assert.Equal(t, [][3]any{{"Read", nil, true}, {"Bash", "x", true}},
		grantTriples(parseGrants(map[string]any{"allowed-tools": []any{"  Read  ", 5, "Bash(x)"}, "disallowed-tools": map[string]any{"a": 1}})))
	assert.Equal(t, []Grant{}, parseGrants(map[string]any{}))
}

// test_grant_whitespace_before_parenthesis_is_linear; test_grant_specifier_padding_no_redos
func TestGrantParsingIsLinear(t *testing.T) {
	// A quadratic scan of 400k spaces runs for minutes; a linear one finishes in milliseconds
	// even on a loaded CI runner, so the bound only separates those two.
	start := time.Now()
	grants := parseGrants(map[string]any{"allowed-tools": "Bash" + strings.Repeat(" ", 160000) + "(curl:*)"})
	assert.Equal(t, [][3]any{{"Bash", "curl:*", true}}, grantTriples(grants))
	grants = parseGrants(map[string]any{"allowed-tools": "Bash" + strings.Repeat(" ", 400000) + "x"})
	require.NotEmpty(t, grants)
	assert.True(t, grants[0].Broad)
	assert.Less(t, time.Since(start), 30*time.Second)
}
