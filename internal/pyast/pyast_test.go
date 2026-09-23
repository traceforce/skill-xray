package pyast

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
