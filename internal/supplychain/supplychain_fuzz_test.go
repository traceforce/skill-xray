package supplychain

import (
	"strings"
	"testing"

	"github.com/traceforce/skill-xray/internal/testutil"
	"github.com/traceforce/skill-xray/internal/testutil/lane"
)

// FuzzCheck drives SXV-016/017 over hostile dependency manifests (PEP 508 lines, npm ranges,
// TOML tables) and the credential-shape sweep over prose and fences.
func FuzzCheck(f *testing.F) {
	hooks := `{"hooks":{}}`
	mcp := `{"mcpServers":{}}`
	skill := "---\nname: demo\n---\n```bash\npip install https://x.test/a.whl\ncurl -sSL https://get.x.io/install.sh | sh\nexport AWS_KEY=AKIAABCDEFGHIJKLMNOP\n```\n" +
		"Token ghp_" + strings.Repeat("a", 36) + " xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx AIza" + strings.Repeat("B", 35) + " sk_live_abcd1234EFGH5678\n"
	dep := func(pkg, req, pyp string) []byte { return testutil.FuzzJoin(skill, hooks, mcp, pkg, req, pyp) }
	seeds := [][]byte{
		dep(`{"dependencies":{"lodash":"^4.17.21","react":"18.2.0","g":"git+https://x/y.git","u":"https://x.test/p.tgz","n":"npm:left-pad@^1.3.0","f":"file:../x","w":"workspace:*","l":"latest","e":""},"devDependencies":{"jest":"~29.0.0"},"optionalDependencies":{"o":">=1 <2 || 3.x"}}`,
			"requests>=2\nflask==1.0\n-r dev.txt\ngit+https://x/y.git#egg=z\nhttps://x.test/pkg.whl\n--index-url http://x\n-e .\n# c \\\nfoo\nbar[extra1,extra2]>=1.0,<2.0; python_version < \"3.8\" and sys_platform == 'win32'\nbaz @ https://x.test/baz.tar.gz\n",
			"[project]\nname = \"x\"\ndependencies = [\"requests>=2.0\", \"click==8.1.7\", \"u @ https://x.test/u.whl\"]\n[project.optional-dependencies]\ndev = [\"pytest\"]\n[tool.poetry.dependencies]\npython = \"^3.9\"\nrich = {version = \"*\", optional = true}\ng = {git = \"https://x/y\"}\n[build-system]\nrequires = [\"setuptools>=61\"]\n"),
		dep(`{"dependencies":"not an object"}`, "requests>=2,<3,!=2.1.*,~=2.2\n"+strings.Repeat("a", 5000)+">=1\n", "[project]\ndependencies = 3\n"),
		dep(`{"dependencies":{"a":null,"b":1,"c":[],"d":{}}}`, "\xef\xbb\xbfrequests\r\n\\\n\\\n\\\nflask\n", "[project]\ndependencies = [1, 2, [3]]\n[tool.poetry.dependencies]\nx = 1\ny = [\"a\"]\n"),
		dep(`{"dependencies":{"`+strings.Repeat("a", 4000)+`":"`+strings.Repeat("^", 4000)+`"}}`, strings.Repeat("-r a.txt\n", 2000), "[project]\ndependencies = [\""+strings.Repeat("(", 3000)+"\"]\n"),
		dep(`{"dependencies":{"x":"1.0.0-`+strings.Repeat("a.", 500)+`0"}}`, "x===1.0\nx==1.0.*\nx~=1.0\nx>=1.0.0a1.post2.dev3+local.1\nx (>=1.0)\nx>=1.0 --hash=sha256:abc\n", "[project]\nname = 9223372036854775808\ndependencies = [\"x>=1\"]\n[[tool.x]]\na=1\n[tool.x.y]\nb=2\n"),
		dep("{\"dependencies\":{\"\u202ex\":\"а^1\"}}", "\u202erequests>=2\nх>=1\n", "[project]\ndependencies = [\"\u202ex>=1\"]\n"),
		dep("{bad", "", "[bad\n"),
		dep("[]", "", "= 1\n"),
		testutil.FuzzJoin("---\nname: x\n---\nAKIAABCDEFGHIJKLMNOP\n", "", "", "", "", ""),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	root := testutil.FuzzDir(f)
	f.Fuzz(func(t *testing.T, data []byte) { lane.Fuzz(t, root, testutil.FuzzLayout, data, Check) })
}
