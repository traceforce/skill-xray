package pyast

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// corpusDir is the captured ast.parse input set (git-ignored, see docs/spec/pyast-decision.md).
const corpusDir = "../../corpus/pyast"

// golden is the refused-input record gen_ast_goldens.py writes after its "error" line
// (accepted inputs hold "ok" and the ast.dump text instead).
type golden struct {
	Class  string `json:"class"`
	Msg    string `json:"msg"`
	Lineno int    `json:"lineno"` // JSON null leaves the zero value
	Offset int    `json:"offset"`
}

// dumpDiff returns a window around the first differing byte of two dumps.
func dumpDiff(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	lo := max(0, i-60)
	return "want ..." + a[lo:min(len(a), i+80)] + "\n got ..." + b[lo:min(len(b), i+80)]
}

// TestCorpusParity drives every captured input through Parse and compares the dump (or the
// SyntaxError class, message, line and offset) with CPython 3.13.2's.
func TestCorpusParity(t *testing.T) {
	if _, err := os.Stat(filepath.Join(corpusDir, "expected")); err != nil {
		t.Skip("corpus/pyast/expected absent: run tools/parity/gen_ast_goldens.py over corpus/pyast first")
	}
	var acceptedEqual, refusedEqual, missing int
	var mismatches []string
	for _, sub := range []string{"pytest", "msb"} {
		entries, err := os.ReadDir(filepath.Join(corpusDir, sub))
		require.NoError(t, err)
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".py") {
				continue
			}
			sha := strings.TrimSuffix(e.Name(), ".py")
			src, err := os.ReadFile(filepath.Join(corpusDir, sub, e.Name()))
			require.NoError(t, err)
			want, err := os.ReadFile(filepath.Join(corpusDir, "expected", sha+".txt"))
			if err != nil {
				missing++
				continue
			}
			mod, perr := Parse(string(src))
			header, body, _ := strings.Cut(string(want), "\n")
			var got string
			ok := false
			if header == "error" {
				var g golden
				require.NoError(t, json.Unmarshal([]byte(body), &g), sha)
				if perr != nil {
					se := perr.(*SyntaxError)
					got = se.Error()
					ok = se.Kind == g.Class && se.Msg == g.Msg && se.Line == g.Lineno && se.Offset == g.Offset
				} else {
					d := dump(mod, true)
					got = "accepted: " + d[:min(200, len(d))]
				}
				if ok {
					refusedEqual++
				} else {
					mismatches = append(mismatches, sub+"/"+sha+"\n want "+body+"\n got  "+got)
				}
				continue
			}
			require.Equal(t, "ok", header, sha)
			if perr != nil {
				mismatches = append(mismatches, sub+"/"+sha+"\n want accepted\n got  "+perr.Error())
				continue
			}
			got = dump(mod, true)
			if got == body {
				acceptedEqual++
			} else {
				mismatches = append(mismatches, sub+"/"+sha+"\n "+dumpDiff(body, got))
			}
		}
	}
	t.Logf("parity: accepted equal %d, refused equal %d, mismatches %d, goldens missing %d", acceptedEqual, refusedEqual, len(mismatches), missing)
	for i, m := range mismatches {
		if i == 10 {
			break
		}
		t.Log(m)
	}
	assert.Empty(t, mismatches, "%d corpus inputs differ from CPython (first ten logged)", len(mismatches))
}

func mustParse(t *testing.T, src string) *Module {
	t.Helper()
	m, err := Parse(src)
	require.NoError(t, err)
	return m
}

func TestWalkIsBreadthFirst(t *testing.T) {
	m := mustParse(t, "x = f(a, b.c)\n")
	var kinds []string
	for n := range Walk(m) {
		kinds = append(kinds, planOf(reflect.TypeOf(n).Elem()).class)
	}
	assert.Equal(t, []string{"Module", "Assign", "Name", "Call", "Store", "Name", "Name", "Attribute", "Load", "Load", "Name", "Load", "Load"}, kinds)
}

func TestIterChildNodesSkipsNone(t *testing.T) {
	m := mustParse(t, "{**a}\n")
	d := m.Body[0].(*ExprStmt).Value.(*Dict)
	assert.Len(t, d.Keys, 1)
	assert.Nil(t, d.Keys[0])
	assert.Len(t, IterChildNodes(d), 1)
}

// tests/test_parse.py::test_python_ast_depth_is_platform_independent and
// tests/test_opengrep_parity.py: bomb.py (3,000 terms) is refused with the RecursionError
// class while deep.py (300 terms) parses at depth 305.
func TestRecursionCeilingAndDepth(t *testing.T) {
	bomb := "x = " + strings.Repeat("\"a\"+", 2999) + "\"a\"\n"
	_, err := Parse(bomb)
	require.Error(t, err)
	assert.Equal(t, "RecursionError", err.(*SyntaxError).Kind)
	deep := "import os, sys\ncmd = sys.argv[1]" + strings.Repeat(" + 'a'", 300) + "\nos.system(cmd)\n"
	m := mustParse(t, deep)
	assert.Equal(t, 305, Depth(m))
	ok := "x = " + strings.Repeat("\"a\"+", 2994) + "\"a\"\n"
	_, err = Parse(ok)
	assert.NoError(t, err)
}

func TestLiteralEval(t *testing.T) {
	eval := func(src string) (any, bool) {
		m := mustParse(t, src)
		return LiteralEval(m.Body[0].(*ExprStmt).Value)
	}
	v, ok := eval("(1, -2.5, 'a', b'b', None, True, ...)\n")
	require.True(t, ok)
	assert.Equal(t, TupleValue{int64(1), -2.5, "a", []byte("b"), nil, true, ellipsis}, v)
	v, ok = eval("{'k': [1, {2}], 3: 1+2j}\n")
	require.True(t, ok)
	assert.Equal(t, DictValue{Keys: []any{"k", int64(3)}, Values: []any{[]any{int64(1), SetValue{int64(2)}}, complex(1, 2)}}, v)
	_, ok = eval("f(1)\n")
	assert.False(t, ok)
	_, ok = eval("{**a}\n")
	assert.False(t, ok)
	_, ok = eval("1 + 2\n")
	assert.False(t, ok)
	v, ok = eval("set()\n")
	require.True(t, ok)
	assert.Equal(t, SetValue{}, v)
}

func TestDotted(t *testing.T) {
	m := mustParse(t, "os.path.join(a)\nf().x\n")
	call := m.Body[0].(*ExprStmt).Value.(*Call)
	assert.Equal(t, "os.path.join", Dotted(call.Func))
	assert.Equal(t, "", Dotted(m.Body[1].(*ExprStmt).Value))
}

func TestNullByteAndEmpty(t *testing.T) {
	_, err := Parse("x = 1\x00")
	require.Error(t, err)
	assert.Equal(t, "source code string cannot contain null bytes", err.(*SyntaxError).Msg)
	assert.Equal(t, 0, err.(*SyntaxError).Line)
	m := mustParse(t, "")
	assert.Equal(t, "Module()", dump(m, true))
}

func TestReprs(t *testing.T) {
	assert.Equal(t, "2j", repr(complex(0, 2)))
	assert.Equal(t, "1e+22j", repr(complex(0, 1e22)))
	assert.Equal(t, "(1+2j)", repr(complex(1, 2)))
	assert.Equal(t, `b"a\x00\\'"`, repr([]byte("a\x00\\'")))
	assert.Equal(t, `b'\'"'`, repr([]byte(`'"`)))
}
