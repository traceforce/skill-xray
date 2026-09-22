package pyast

import (
	"strings"
	"testing"
)

// FuzzParse drives ast.parse on arbitrary source and then walks whatever came back the way
// parse._parse_python and the code lane do: Depth, Walk, Dotted, LiteralEval and the dump.
// It fails only on a panic, a hang, or a broken contract (an error that is not *SyntaxError).
var parseSeeds = []string{
	"",
	"x = 1\n",
	"import os, sys\ncmd = sys.argv[1] + 'a'\nos.system(cmd)\n",
	"def f(a, /, b=2, *args, c, **kw):\n    return (yield from g(a, *args, **kw))\n",
	"class A(B, metaclass=M):\n    @property\n    def x(self) -> int: ...\n",
	"async def f():\n    async with a as b, c:\n        await x\n    async for i in y:\n        pass\n",
	"x = f'{a!r:>{w}} {b:{c}} {{literal}} {d=}'\n",
	"match p:\n    case [1, 2, *rest] | {'k': v, **kw} if v > 0:\n        pass\n    case Point(x=0, y=_):\n        pass\n    case _:\n        pass\n",
	"try:\n    pass\nexcept* (ValueError, TypeError) as e:\n    raise\nelse:\n    pass\nfinally:\n    pass\n",
	"type Alias[T: int, *Ts, **P] = dict[T, Callable[P, tuple[*Ts]]]\n",
	"x = [i for i in range(3) if i async for j in k]\ny = {a: b for a, b in c}\nz = lambda *, k=1: k\n",
	"x = 0x_ff + 0o17 + 0b1 + 1_000.5e-3j + 1__0\n",
	"s = b'\\x00' rb'\\d' u'\\N{BULLET}' '''multi\nline''' \"\"\"other\"\"\"\n",
	"if a:\n  if b:\n     pass\n  else:\n    pass\nelif c:\n    pass\n",
	"x = a if b else c; del x[1:2, ::3]; global g; nonlocal n\n",
	"with (open(a) as f, open(b) as g):\n    pass\n",
	"x = (yield)\nprint >> sys.stderr, 'x'\n",
	"def f():\n\treturn 1\n        x = 2\n",
	// Depth 60 once took hours (unmemoised star_target re-parse); the memo keeps it linear.
	"x = " + strings.Repeat("(", 60) + "1" + strings.Repeat(")", 60) + "\n",
	"x = " + strings.Repeat("\"a\"+", 400) + "\"a\"\n",
	"f'{f'{f'{1}'}'}'\n",
	"x = 1\x00\n",
	"\ufeffx = 1\n",
	"x = '\\\n'\n",
	"@d1\n@d2(x)\nclass C: pass\n",
	"lambda: (yield)\n",
	"*a, = b\n",
	"a[b:c:d, e]\n",
	"not not not x\n",
	"x: int = 1; y: list[int]\n",
	"from . import a as b, c\nfrom ...pkg.mod import *\n",
	"assert x, 'msg'\nraise E from cause\n",
	"while x:\n    break\nelse:\n    continue\n",
	"for x, *y in z:\n    pass\n",
	"print('hello' 'world' f'{x}')\n",
	"x = {**a, 'b': 1, **c}\ny = {*a, 1}\n",
	"1 if 2 else 3 if 4 else 5\n",
	"a < b <= c == d != e > f >= g is h is not i in j not in k\n",
	"x = a @ b ** -c // d % e << f >> g & h ^ i | j\n",
	"# comment only\n\n\n",
	"    indented first line\n",
	"x = (\n  1,\n  2\n)\n",
	"if x:\npass\n",
	"def f(:\n",
	"x = 1 +\n",
	"'''unterminated\n",
	"f'{'\n",
	"x = 1 if 2\n",
	"import\n",
}

func FuzzParse(f *testing.F) {
	for _, s := range parseSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		// Invalid UTF-8 never reaches Parse from ingest (CP-1252 fallback), but the recorded
		// crasher d7ef8cdaaa60bda5 ("00\xc4") panicked the tokenizer, so it stays in the corpus.
		m, err := Parse(src)
		if err != nil {
			se, ok := err.(*SyntaxError)
			if !ok {
				t.Fatalf("Parse error is %T, not *SyntaxError: %v", err, err)
			}
			if se.Kind == "" {
				t.Fatalf("SyntaxError with empty Kind: %+v", se)
			}
			_ = se.Error()
			if m != nil {
				t.Fatalf("Parse returned both a module and an error")
			}
			return
		}
		if m == nil {
			t.Fatal("Parse returned nil module and nil error")
		}
		_ = Depth(m)
		n := 0
		for node := range Walk(m) {
			n++
			_ = Dotted(node)
			if e, ok := node.(Expr); ok {
				_, _ = LiteralEval(e)
			}
		}
		_ = dump(m, true)
		_ = dump(m, false)
	})
}
