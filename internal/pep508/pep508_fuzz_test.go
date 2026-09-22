package pep508

import "testing"

// FuzzParse drives the hand-ported packaging tokenizer/parser; it fails on a panic that is not
// the parser's own syntaxError bail, on a hang, or on a valid requirement without a name.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"requests==2.32.3",
		"flask[async]>=3",
		"pkg @ https://example.com/pkg-1.0-py3-none-any.whl ; python_version >= '3.8'",
		"name[extra1, extra2] (>=1.0, <2.0) ; os_name == 'nt' and (sys_platform != 'win32' or extra == 'x')",
		"a===arbitrary",
		"a~=1.4.2",
		"a==1.0.*",
		"a==1.0+local.1",
		"a>=1!2.0rc1.post3.dev4",
		"a == 1.0 ; python_version >= '3' and python_version < '4' or implementation_name == 'cpython'",
		"a ; 'x' in 'y'",
		"a ; not python_version >= '3'",
		"a ; python_version in '2.7 3.6'",
		"a>=1,<2,!=1.5,~=1.4,===x,==1.*",
		"a @ git+https://github.com/x/y.git@0123456789abcdef0123456789abcdef01234567#egg=a",
		"a @ file:///C:/x/y.whl",
		"",
		"  ",
		"[x]",
		"a b",
		"a;",
		"a @ ",
		"a @ url extra",
		"a (",
		"a[",
		"a >= ",
		"a==",
		"a == 1.0 ; python_version",
		"a == 1.0 ; python_version >= ",
		"a == 1.0 ; (((python_version >= '3')))",
		"a == 1.0 ; python_version >= '3' and",
		"a[,]",
		"a[x y]",
		"a (>=1.0",
		"a >= 1.0)",
		"a == 'quoted'",
		"a == 1.0 ; extra == \"double\"",
		"a\n",
		"a\nb",
		"-e .",
		"./local/path",
		"a==1.0 --hash=sha256:abc",
		"a == v1.0",
		"a == 1.0.post",
		"a == 1.0.dev",
		"a == 1.0a",
		"a == 1.0-1",
		"a == 1_0",
		"a == 01.0",
		"a === ",
		"a == 1.0.*.*",
		"a == *",
		"a ~= 1",
		"a < 1.0.*",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Parse(s)
		if err != nil {
			if r.Name != "" || r.URL != "" || len(r.Specifiers) != 0 {
				t.Fatalf("error with non-zero requirement: %+v", r)
			}
			_ = err.Error()
			return
		}
		if r.Name == "" {
			t.Fatalf("valid requirement without a name: %q", s)
		}
		_ = IsExactPin("pip", s)
		_ = IsExactPin("uv", s)
	})
}
