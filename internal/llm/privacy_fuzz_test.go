package llm

import (
	"strings"
	"testing"
)

// FuzzRedact checks the one contract Redact promises: every replacement re-emits the newlines it
// consumed, so the redacted text has exactly as many "\n" as the input. Panics and hangs (the
// regexp2 pattern backtracks) fail as well.
func FuzzRedact(f *testing.F) {
	seeds := []string{
		"token: abc\nx",
		"api_key = \"sk-live-abcdefghijklmnopqrstuvwxyz0123456789\"\n",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nunterminated\n",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\n",
		"curl https://user:pass@example.com/path?x=1#frag\n",
		"git+https://token@github.com/x/y.git\n",
		"password: |\n  multi\n  line\n  value\nnext: 1\n",
		"SECRET_TOKEN=\"\"\"\ntriple\nquoted\n\"\"\"\n",
		"secret = '''\n\n'''\n",
		"ghp_16C7e42F292c6912E7710c838347Ae178B4a\n",
		"AKIAIOSFODNN7EXAMPLE\nAKIAABCDEFGHIJKLMNOP\n",
		"xoxb-0000000000-0000000000000-abc\nxoxb-1234567890-1234567890123-abcdefghijklmnop\n",
		"token: !secret &anchor value\n",
		"- password: 'it''s'\n",
		"\"token\": \"x\",\n\"other\": \"y\"\n",
		"token:\n\n  \n  deep\n",
		"env:\n  API_KEY:\n    value\n  OTHER: 1\n",
		"authorization = Basic dXNlcjpwYXNz\n",
		"my-api-key: x\nmy_api_key: y\napikey: z\n",
		"passwd:x\n",
		"the token: is 'quoted \\' with escape'\n",
		"token=\"unterminated\n",
		"token='unterminated\nnext: line\n",
		"tokens: not a credential?\n",
		"TOKEN\t=\tval\n",
		"\"token\"=\"v\"\r\n",
		"token: a\ntoken: b\ntoken: c\n",
		"a: https://x.y/z\nb: http://u:p@h:8080/p?q\nc: ftp://h\nd: git+ssh://git@h/x\n",
		"https://[::1]:8080/path\nhttps://h:99999/\nhttps://h:abc/\n",
		"token: a b\n",
		"\n\n\n",
		"",
		strings.Repeat("token: x\n", 50),
		strings.Repeat("a-", 200) + "token: v\n",
		strings.Repeat("\"", 100) + "\n",
		strings.Repeat("'", 100) + "\n",
		"token: " + strings.Repeat("!x ", 5) + "v\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Redact(s)
		if got, want := strings.Count(out, "\n"), strings.Count(s, "\n"); got != want {
			t.Fatalf("newline count changed: %d -> %d\nin:  %q\nout: %q", want, got, s, out)
		}
	})
}
