package pytext

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every golden under testdata/ is written by tools/parity/gen_goldens.py from CPython 3.13.2.

func load(t *testing.T, name string, v any) {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name+".json"))
	require.NoError(t, err)
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.UseNumber()
	require.NoError(t, dec.Decode(v))
}

type strCase struct {
	Input    string `json:"input"`
	InputHex string `json:"input_hex"`
	Output   string `json:"output"`
	Safe     string `json:"safe"`
}

func (c strCase) in(t *testing.T) string {
	if c.InputHex != "" {
		b, err := hex.DecodeString(c.InputHex)
		require.NoError(t, err)
		return string(b)
	}
	return c.Input
}

// Unicode 15.1 (CPython) assigned these; Go 1.26's tables are 15.0 (00-overview D1,
// obfuscation §4.1). They are the only accepted property divergence.
var unicode151 = [][2]rune{{0x2FFC, 0x2FFF}, {0x31EF, 0x31EF}, {0x2EBF0, 0x2EE5D}}

func skipRune(r rune) bool { return 0xD800 <= r && r <= 0xDFFF || inRanges(unicode151, r) }

func inRanges(ranges [][2]rune, r rune) bool {
	for _, rg := range ranges {
		if rg[0] <= r && r <= rg[1] {
			return true
		}
	}
	return false
}

func checkProperty(t *testing.T, name string, pred func(rune) bool) {
	var g struct{ Ranges [][2]rune }
	load(t, name, &g)
	var bad []string
	for r := rune(0); r <= 0x10FFFF && len(bad) < 20; r++ {
		if !skipRune(r) && pred(r) != inRanges(g.Ranges, r) {
			bad = append(bad, fmt.Sprintf("U+%04X", r))
		}
	}
	assert.Empty(t, bad, name)
}

func TestIsSpace(t *testing.T) {
	checkProperty(t, "isspace", IsSpace)
	re := regexp.MustCompile("^" + Space + "$")
	not := regexp.MustCompile("^" + NotSpace + "$")
	embedded := regexp.MustCompile("^[x" + SpaceBody + "]$")
	for r := rune(0); r <= 0x10FFFF; r++ {
		if skipRune(r) {
			continue
		}
		s := string(r)
		if IsSpace(r) != re.MatchString(s) || IsSpace(r) == not.MatchString(s) || (IsSpace(r) || r == 'x') != embedded.MatchString(s) {
			t.Fatalf("Space class disagrees with IsSpace at U+%04X", r)
		}
	}
}

func TestIsWord(t *testing.T) { checkProperty(t, "isword", IsWord) }

func TestSet(t *testing.T) {
	assert.Equal(t, map[string]bool{"a": true, "b": true}, Set("a", "b", "a"))
	assert.Equal(t, map[int]bool{}, Set[int]())
}

func TestIsPrintable(t *testing.T) {
	checkProperty(t, "nonprintable", func(r rune) bool { return !IsPrintable(string(r)) })
	var cases []struct {
		Input  string
		Output bool
	}
	load(t, "isprintable", &cases)
	for _, c := range cases {
		assert.Equal(t, c.Output, IsPrintable(c.Input), "%q", c.Input)
	}
	assert.False(t, IsPrintable("a\xffb"), "an undecodable byte is a lone surrogate, category Cs")
}

func checkCaseMap(t *testing.T, name string, fn func(string) string) {
	var g struct {
		Chars   [][2]any
		Strings []strCase
	}
	load(t, name, &g)
	mapped := map[rune]string{}
	for _, c := range g.Chars {
		cp, err := c[0].(json.Number).Int64()
		require.NoError(t, err)
		mapped[rune(cp)] = c[1].(string)
	}
	var bad []string
	for r := rune(0); r <= 0x10FFFF && len(bad) < 20; r++ {
		if skipRune(r) {
			continue
		}
		want, ok := mapped[r]
		if !ok {
			want = string(r)
		}
		if got := fn(string(r)); got != want {
			bad = append(bad, fmt.Sprintf("U+%04X: %q != %q", r, got, want))
		}
	}
	assert.Empty(t, bad, name)
	for _, c := range g.Strings {
		assert.Equal(t, c.Output, fn(c.Input), "%q", c.Input)
	}
}

func TestLower(t *testing.T)    { checkCaseMap(t, "lower", Lower) }
func TestCaseFold(t *testing.T) { checkCaseMap(t, "casefold", CaseFold) }

func TestSplitLines(t *testing.T) {
	var cases []struct {
		Input  string
		Output []string
	}
	load(t, "splitlines", &cases)
	for _, c := range cases {
		assert.Equal(t, c.Output, SplitLines(c.Input), "%q", c.Input)
	}
}

func TestStripFields(t *testing.T) {
	var cases []struct {
		Input, Strip, LStrip, RStrip string
		Fields                       []string
	}
	load(t, "strip", &cases)
	for _, c := range cases {
		assert.Equal(t, c.Strip, Strip(c.Input), "strip %q", c.Input)
		assert.Equal(t, c.LStrip, LStrip(c.Input), "lstrip %q", c.Input)
		assert.Equal(t, c.RStrip, RStrip(c.Input), "rstrip %q", c.Input)
		assert.Equal(t, c.Fields, Fields(c.Input), "split %q", c.Input)
	}
}

func TestHead(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{{"héllo", 3, "hél"}, {"héllo", 5, "héllo"}} {
		assert.Equal(t, c.want, Head(c.in, c.n))
	}
}

func testStrings(t *testing.T, name string, fn func(string) string) {
	var cases []strCase
	load(t, name, &cases)
	for _, c := range cases {
		in := c.in(t)
		assert.Equal(t, c.Output, fn(in), "%q", in)
	}
}

func TestRepr(t *testing.T)          { testStrings(t, "repr", Repr) }
func TestUnicodeEscape(t *testing.T) { testStrings(t, "unicode_escape", UnicodeEscape) }
func TestUnquote(t *testing.T)       { testStrings(t, "unquote", Unquote) }
func TestBasename(t *testing.T)      { testStrings(t, "basename", Basename) }

func TestQuote(t *testing.T) {
	var cases []strCase
	load(t, "quote", &cases)
	for _, c := range cases {
		in := c.in(t)
		assert.Equal(t, c.Output, Quote(in, c.Safe), "%q safe=%q", in, c.Safe)
	}
}

func TestSplitExt(t *testing.T) {
	var cases []struct{ Input, Root, Ext string }
	load(t, "splitext", &cases)
	for _, c := range cases {
		root, ext := SplitExt(c.Input)
		assert.Equal(t, []string{c.Root, c.Ext}, []string{root, ext}, "%q", c.Input)
	}
}

func TestURLSplit(t *testing.T) {
	var cases []struct {
		Input, Scheme, Netloc, Path, Query, Fragment string
		Error, Hostname                              *string
		Port                                         any
	}
	load(t, "urlsplit", &cases)
	for _, c := range cases {
		u, err := URLSplit(c.Input)
		if c.Error != nil {
			assert.EqualError(t, err, *c.Error, "%q", c.Input)
			continue
		}
		require.NoError(t, err, "%q", c.Input)
		assert.Equal(t, URL{c.Scheme, c.Netloc, c.Path, c.Query, c.Fragment}, u, "%q", c.Input)
		hostname := ""
		if c.Hostname != nil {
			hostname = *c.Hostname
		}
		assert.Equal(t, hostname, u.Hostname(), "hostname %q", c.Input)
		port, err := u.Port()
		switch want := c.Port.(type) {
		case nil:
			assert.NoError(t, err, "port %q", c.Input)
			assert.Nil(t, port, "port %q", c.Input)
		case string:
			assert.Error(t, err, "port %q", c.Input)
		case json.Number:
			require.NoError(t, err, "port %q", c.Input)
			require.NotNil(t, port, "port %q", c.Input)
			assert.Equal(t, want.String(), strconv.Itoa(*port), "port %q", c.Input)
		}
	}
}

func TestURLUnsplit(t *testing.T) {
	var cases []struct {
		Parts  []string
		Output string
	}
	load(t, "urlunsplit", &cases)
	for _, c := range cases {
		p := c.Parts
		assert.Equal(t, c.Output, URLUnsplit(p[0], p[1], p[2], p[3], p[4]), "%q", p)
	}
}

func TestShlex(t *testing.T) {
	var cases []struct {
		Input, Punctuation, Whitespace string
		Posix                          bool
		Tokens                         []string
		Error                          *string
	}
	load(t, "shlex", &cases)
	for _, c := range cases {
		got, err := ShlexTokens(c.Input, c.Posix, c.Punctuation, c.Whitespace)
		if c.Error != nil {
			assert.EqualError(t, err, *c.Error, "%q", c.Input)
			continue
		}
		require.NoError(t, err, "%q", c.Input)
		assert.Equal(t, c.Tokens, got, "%q posix=%v punct=%q", c.Input, c.Posix, c.Punctuation)
		if c.Posix && c.Punctuation == "" && c.Whitespace == " \t\r\n" {
			split, err := ShlexSplit(c.Input)
			require.NoError(t, err)
			assert.Equal(t, c.Tokens, split)
		}
	}
}

func TestCanonical(t *testing.T) {
	var cases []struct {
		Input    any
		InputHex string `json:"input_hex"`
		Output   string
	}
	load(t, "canonical", &cases)
	for _, c := range cases {
		in := Intify(c.Input)
		if c.InputHex != "" {
			b, err := hex.DecodeString(c.InputHex)
			require.NoError(t, err)
			in = string(b)
		}
		assert.Equal(t, c.Output, Canonical(in), "%#v", in)
	}
	assert.Panics(t, func() { Canonical(math.NaN()) }, "allow_nan=False")
	assert.Panics(t, func() { Canonical([]any{math.Inf(1)}) }, "allow_nan=False")
}

func TestDumps(t *testing.T) {
	var cases []struct {
		Input  any
		Indent *int
		Output string
	}
	load(t, "dumps", &cases)
	for _, c := range cases {
		indent := 0
		if c.Indent != nil {
			indent = *c.Indent
		}
		assert.Equal(t, c.Output, Dumps(Intify(c.Input), indent), "%#v indent=%d", c.Input, indent)
	}
	assert.Equal(t, "[NaN, Infinity, -Infinity]", Dumps([]any{math.NaN(), math.Inf(1), math.Inf(-1)}, 0))
}

func TestEncodeGoShapes(t *testing.T) {
	type row struct {
		B []string        `json:"b"`
		A map[string]int  `json:"a"`
		R json.RawMessage `json:"r"` // a MarshalJSON type carrying float literals
	}
	type ratio float64
	n := 7
	v := map[string]any{
		"strings": []string{"x", "é"},
		"maps":    []map[string]any{{"k": int64(1)}, {}},
		"ptr":     &n,
		"nilptr":  (*int)(nil),
		"struct":  row{B: []string{"y"}, A: map[string]int{"z": 2, "a": 1}, R: json.RawMessage(`{"z":1e2,"b":1.0,"c":-0}`)},
		"number":  json.Number("100.0"),
		"u8":      uint8(3),
		"ratio":   ratio(1e21), // a named float: Marshal writes 1e+21
	}
	want := `{"maps":[{"k":1},{}],"nilptr":null,"number":100.0,"ptr":7,"ratio":1e+21,"strings":["x","\u00e9"],"struct":{"a":{"a":1,"z":2},"b":["y"],"r":{"b":1.0,"c":0,"z":100.0}},"u8":3}`
	assert.Equal(t, want, Canonical(v))
}

func TestFindAllBounded(t *testing.T) {
	var cases []struct {
		Pattern, Input string
		Spans          [][2]int
	}
	load(t, "bounded", &cases)
	notWord := func(r rune) bool { return r < 0 || !IsWord(r) }
	for _, c := range cases {
		re := regexp.MustCompile(c.Pattern)
		got := [][2]int{}
		for _, m := range FindAllBounded(re, c.Input, notWord, notWord) {
			got = append(got, [2]int{utf8.RuneCountInString(c.Input[:m[0]]), utf8.RuneCountInString(c.Input[:m[1]])})
		}
		want := c.Spans
		if want == nil {
			want = [][2]int{}
		}
		assert.Equal(t, want, got, "%q on %q", c.Pattern, c.Input)
	}
	// Left-only rules skip the right check; nil accepts everything; submatches are absolute.
	re := regexp.MustCompile(`(a)(b)?`)
	got := FindAllBounded(re, "xab ab", func(r rune) bool { return r == ' ' }, nil)
	assert.Equal(t, [][]int{{4, 6, 4, 5, 5, 6}}, got)
	assert.Equal(t, [][]int{{0, 0, -1, -1}, {2, 2, -1, -1}, {3, 3, -1, -1}}, FindAllBounded(regexp.MustCompile(`(x)?`), "éa", nil, nil), "empty matches advance one code point (é is two bytes)")
}

func TestFindAllIf(t *testing.T) {
	all := func([]int) bool { return true }
	none := func([]int) bool { return false }
	notAtZero := func(m []int) bool { return m[0] > 0 }
	for _, c := range []struct {
		name, pattern, input string
		accept               func([]int) bool
		want                 [][]int
	}{
		{"an accepted match resumes after it", `a.`, "aaa", all, [][]int{{0, 2}}},
		{"a rejected candidate resumes one code point later and may overlap it", `a.`, "aaa", notAtZero, [][]int{{1, 3}}},
		{"a rejected multibyte candidate resumes after the whole code point", `.`, "éa", notAtZero, [][]int{{2, 3}}},
		{"an accepted empty match at the end of s still advances", `(x)?`, "éa", all, [][]int{{0, 0, -1, -1}, {2, 2, -1, -1}, {3, 3, -1, -1}}},
		{"a rejected empty match at the end of s still advances", `(x)?`, "éa", none, nil},
		{"empty input", `(x)?`, "", none, nil},
	} {
		assert.Equal(t, c.want, FindAllIf(regexp.MustCompile(c.pattern), c.input, c.accept), c.name)
	}
}

func TestOSErrorName(t *testing.T) {
	cases := map[string]error{
		"PermissionError":        &fs.PathError{Op: "open", Path: "x", Err: fs.ErrPermission},
		"FileNotFoundError":      &fs.PathError{Op: "open", Path: "x", Err: syscall.ENOENT},
		"FileExistsError":        fs.ErrExist,
		"NotADirectoryError":     &fs.PathError{Op: "open", Path: "x", Err: notADirectory()[len(notADirectory())-1]},
		"IsADirectoryError":      syscall.EISDIR,
		"TimeoutError":           syscall.ETIMEDOUT,
		"InterruptedError":       syscall.EINTR,
		"BlockingIOError":        syscall.EAGAIN,
		"BrokenPipeError":        syscall.EPIPE,
		"ConnectionRefusedError": syscall.ECONNREFUSED,
		"ConnectionResetError":   syscall.ECONNRESET,
		"ConnectionAbortedError": syscall.ECONNABORTED,
		"OSError":                errors.New("something else"),
	}
	for want, err := range cases {
		assert.Equal(t, want, OSErrorName(err), "%v", err)
	}
	assert.Equal(t, "OSError", OSErrorName(syscall.ELOOP), "O_NOFOLLOW on a symlink")
	assert.Equal(t, "FileNotFoundError", OSErrorName(&exec.Error{Name: "opengrep", Err: exec.ErrNotFound}), "missing binary")
}

// D7 (00-overview): an integral json.Number is int, any other number float64, through maps and lists.
func TestFloatRepr(t *testing.T) {
	for f, want := range map[float64]string{1e16: "1e+16", 1e15: "1000000000000000.0", 1e-5: "1e-05", 1e-4: "0.0001",
		100: "100.0", 66.67: "66.67", 0: "0.0", math.Inf(1): "inf", math.Inf(-1): "-inf"} {
		assert.Equal(t, want, FloatRepr(f))
	}
	assert.Equal(t, "nan", FloatRepr(math.NaN()))
	assert.Equal(t, "-0.0", FloatRepr(math.Copysign(0, -1)))
}

func TestIntify(t *testing.T) {
	for _, c := range []struct{ in, want any }{
		{json.Number("2"), 2}, {json.Number("-9223372036854775808"), math.MinInt64},
		{json.Number("1.0"), 1.0}, {json.Number("1e3"), 1000.0}, {json.Number("9223372036854775808"), 9.223372036854776e18},
		{map[string]any{"line": json.Number("3"), "list": []any{json.Number("0.5"), json.Number("7"), "7"}},
			map[string]any{"line": 3, "list": []any{0.5, 7, "7"}}},
		{"7", "7"}, {nil, nil}, {true, true},
	} {
		assert.Equal(t, c.want, Intify(c.in))
	}
}

// JSONView is the to_dict shape: structs and typed slices become generic maps and lists with D7
// numbers, and the view never aliases its input.
func TestJSONView(t *testing.T) {
	type row struct {
		Line *int     `json:"line"`
		Tags []string `json:"tags"`
	}
	one := 1
	for _, c := range []struct{ in, want any }{
		{row{Line: &one, Tags: []string{"a"}}, map[string]any{"line": 1, "tags": []any{"a"}}},
		{[]row{{Tags: []string{}}}, []any{map[string]any{"line": nil, "tags": []any{}}}},
		{map[string]any{"f": 1.5, "n": json.Number("7"), "big": json.Number("9223372036854775808")},
			map[string]any{"f": 1.5, "n": 7, "big": 9.223372036854776e18}},
		{nil, nil}, {"s", "s"}, {true, true},
	} {
		assert.Equal(t, c.want, JSONView(c.in))
	}
	src := map[string]any{"list": []any{1}}
	JSONView(src).(map[string]any)["list"].([]any)[0] = 2
	assert.Equal(t, 1, src["list"].([]any)[0])
	assert.Panics(t, func() { JSONView(math.NaN()) })
}

func TestDeepCopy(t *testing.T) {
	src := map[string]any{
		"list":     []any{1, map[string]any{"k": "v"}},
		"evidence": []map[string]any{{"path": "a"}},
		"tags":     []string{"x"},
		"nil":      nil,
		"nilslice": []any(nil),
	}
	got := DeepCopy(src).(map[string]any)
	assert.Equal(t, src, got)
	got["list"].([]any)[1].(map[string]any)["k"] = "changed"
	got["evidence"].([]map[string]any)[0]["path"] = "b"
	got["tags"].([]string)[0] = "y"
	assert.Equal(t, "v", src["list"].([]any)[1].(map[string]any)["k"])
	assert.Equal(t, "a", src["evidence"].([]map[string]any)[0]["path"])
	assert.Equal(t, "x", src["tags"].([]string)[0])
	assert.Nil(t, got["nilslice"])
}

func TestTruthy(t *testing.T) {
	for _, v := range []any{nil, false, 0, 0.0, "", []any{}, map[string]any{}} {
		assert.False(t, Truthy(v), "%#v", v)
	}
	for _, v := range []any{true, 1, -0.5, "x", []any{nil}, map[string]any{"k": nil}, struct{}{}} {
		assert.True(t, Truthy(v), "%#v", v)
	}
}

// unicodedata.normalize("NFC", ...) on a surrogate-escaped name: the undecodable byte stays a
// byte while the runs around it compose.
func TestJSONViewKeepsUndecodableBytes(t *testing.T) {
	type inner struct {
		Path string `json:"path"`
	}
	type doc struct {
		Items []inner        `json:"items"`
		ByRel map[string]any `json:"by_rel"`
		Note  string         `json:"note"`
		Plain any            `json:"plain"`
	}
	name := "raw-\xff/SKILL.md"
	m := JSONView(&doc{Items: []inner{{name}}, ByRel: map[string]any{name: 1},
		Note: "\uF8FF marker \uFFFD", Plain: []any{name}}).(map[string]any)
	item := m["items"].([]any)[0].(map[string]any)
	assert.Equal(t, name, item["path"], "the byte survives a struct field")
	assert.Equal(t, 1, m["by_rel"].(map[string]any)[name], "the byte survives a map key")
	assert.Equal(t, name, m["plain"].([]any)[0], "the byte survives an interface value")
	assert.Equal(t, "\uF8FF marker \uFFFD", m["note"], "a literal marker or replacement character is untouched")
	assert.Equal(t, `"raw-\udcff/SKILL.md"`, Canonical(item["path"]), "written as Python writes the surrogate")
	assert.Equal(t, map[string]any{"a": 1}, JSONView(map[string]int{"a": 1}), "the fast path is the plain round trip")
	only := JSONView(map[string]any{"p": name}).(map[string]any)
	assert.Equal(t, name, only["p"], "detected without a genuine replacement character in the document")
	// the toolchain's encoder writes the rewritten byte as the escape or as the character; the
	// view detects both
	marshalled, err := json.Marshal(name)
	require.NoError(t, err)
	assert.True(t, bytes.Contains(marshalled, []byte(`\ufffd`)) || bytes.Contains(marshalled, []byte("\uFFFD")),
		"the encoder writes the rewritten byte in a form the view detects: %q", marshalled)
}

func TestNFCKeepsUndecodableBytes(t *testing.T) {
	assert.Equal(t, "raw-ÿ/é", NFC("raw-ÿ/é"))
	assert.Equal(t, "ÿþ", NFC("ÿþ"))
	assert.Equal(t, "é", NFC("é"))
	assert.Equal(t, "�", NFC("�"))
}
