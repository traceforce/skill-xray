package supplychain

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// tests/test_supply_chain.py, every case, through the real ingest + parse pipeline as _check does.

const fm = "---\nname: t\n---\n"

var (
	aws    = "AKIAABCDEFGHIJKLMNOP"
	ghp    = "ghp_" + strings.Repeat("a", 36)
	slack  = "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"
	aiza   = "AIza" + strings.Repeat("B", 35)
	stripe = "sk_live_abcd1234EFGH5678"
)

func check(t *testing.T, files map[string]string) []findings.Finding {
	all := map[string]string{"SKILL.md": fm}
	maps.Copy(all, files)
	return Check(parse.Parse(ingest.BuildPackage(testutil.MakePackage(t, all))))
}

func byRule(fs []findings.Finding, vector, rule string) (out []findings.Finding) {
	for _, f := range testutil.ByVector(fs, vector) {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func hasVector(fs []findings.Finding, vector string) bool {
	return len(testutil.ByVector(fs, vector)) > 0
}

func evidenceSet(fs []findings.Finding, key string) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		out[f.Evidence[key].(string)] = true
	}
	return out
}

func capped(fs []findings.Finding) (n int) {
	for _, f := range fs {
		if f.Rule == "findings-capped" {
			n++
		}
	}
	return n
}

func rendered(f findings.Finding) string { return f.Message + fmt.Sprint(f.Evidence) }

func TestUnpinnedDependencies(t *testing.T) {
	// test_requirements_unpinned_fires_pinned_is_silent
	f := testutil.ByVector(check(t, map[string]string{"requirements.txt": "requests==2.32.3\nflask>=2.0\n-r dev.txt\n"}), "SXV-016")
	require.Len(t, f, 1)
	assert.Equal(t, "low", f[0].Severity)
	assert.Equal(t, 2, *f[0].Line)
	assert.Equal(t, map[string]any{"ecosystem": "PyPI", "package": "flask", "pin_state": "unpinned"}, f[0].Evidence)

	// test_requirements_variant_is_scanned
	assert.True(t, hasVector(check(t, map[string]string{"requirements-dev.txt": "requests>=2\n"}), "SXV-016"))

	// test_package_json_ranges_are_unpinned_exact_is_silent
	f = testutil.ByVector(check(t, map[string]string{"package.json": "{\"dependencies\": {\"lodash\": \"^4.17.21\", \"react\": \"18.2.0\"},\n \"devDependencies\": {\"jest\": \"~29.0.0\"}}\n"}), "SXV-016")
	assert.Equal(t, map[string]bool{"lodash": true, "jest": true}, evidenceSet(f, "package"))
	for _, x := range f {
		assert.Equal(t, []any{"npm", "low"}, []any{x.Evidence["ecosystem"], x.Severity})
	}

	// test_pyproject_unpinned_is_pypi
	f = testutil.ByVector(check(t, map[string]string{"pyproject.toml": "[project]\nname = \"x\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2.0\", \"click==8.1.7\"]\n"}), "SXV-016")
	require.Len(t, f, 1)
	assert.Equal(t, map[string]any{"ecosystem": "PyPI", "package": "requests", "pin_state": "unpinned"}, f[0].Evidence)

	// test_all_pinned_manifest_is_clean
	assert.Empty(t, testutil.ByVector(check(t, map[string]string{"requirements.txt": "requests==2.32.3\nurllib3==2.2.2\n"}), "SXV-016"))

	// test_malformed_manifest_neither_crashes_nor_fabricates
	assert.Empty(t, testutil.ByVector(check(t, map[string]string{"package.json": "{not json,,,"}), "SXV-016"))

	// test_npm_alias_exact_pin_is_silent
	assert.False(t, hasVector(check(t, map[string]string{"package.json": `{"dependencies": {"realname": "npm:left-pad@1.3.0"}}`}), "SXV-016"))
	assert.True(t, hasVector(check(t, map[string]string{"package.json": `{"dependencies": {"realname": "npm:left-pad@^1.3.0"}}`}), "SXV-016"))

	// test_backslash_comment_does_not_swallow_next_dependency
	f = testutil.ByVector(check(t, map[string]string{"requirements.txt": "# install the following \\\nrequests\nflask>=2.0\n"}), "SXV-016")
	assert.Equal(t, map[string]bool{"requests": true, "flask": true}, evidenceSet(f, "package"))

	// test_dependency_findings_are_capped_per_file
	deps := map[string]string{}
	for i := range findings.Cap + 3 {
		deps[fmt.Sprintf("dep-%d", i)] = "*"
	}
	pkg, _ := json.Marshal(map[string]any{"dependencies": deps})
	fs := check(t, map[string]string{"package.json": string(pkg)})
	assert.Len(t, testutil.ByVector(fs, "SXV-016"), findings.Cap)
	assert.Equal(t, 1, capped(fs))
}

func TestInstallFromURL(t *testing.T) {
	install := func(files map[string]string) []findings.Finding {
		return byRule(check(t, files), "SXV-016", "install-from-url")
	}

	// test_vcs_url_install_source_fires
	// test_pyproject_metadata_url_is_not_an_install_source (requirements half)
	req := "requests==2.31.0\ngit+https://evil.example.com/backdoor.git#egg=backdoor\n"
	assert.NotEmpty(t, install(map[string]string{"requirements.txt": req}))

	// test_vcs_install_covers_all_sdist_extensions
	assert.Len(t, install(map[string]string{"requirements.txt": "https://example.com/a-1.0.tar.bz2\nhttps://example.com/b.tar\nhttps://example.com/c-1.0.tar.xz\n"}), 3)

	// test_npm_host_shorthand_and_git_dep_are_install_from_url
	fs := testutil.ByVector(check(t, map[string]string{"package.json": `{"dependencies":{"evil":"github:attacker/evil","ref":"git+https://github.com/attacker/ref.git","ok":"1.2.3"}}`}), "SXV-016")
	inst := byRule(fs, "SXV-016", "install-from-url")
	require.Len(t, inst, 2)
	for _, x := range inst {
		assert.NotContains(t, x.Evidence["install_source"], "}")
	}
	assert.Empty(t, byRule(fs, "SXV-016", "unpinned-dependency"))

	// test_repository_metadata_url_is_not_an_install_source
	assert.Empty(t, install(map[string]string{"package.json": `{"name":"mypkg","version":"1.0.0","repository":"git+https://github.com/me/mypkg.git","homepage":"https://me.example.com","dependencies":{"lodash":"4.17.21"}}`}))

	// test_pep508_direct_url_reference_fires
	f := install(map[string]string{"requirements.txt": "internal-lib @ https://artifacts.corp.example.com/internal-lib/latest\nrequests==2.31.0\n"})
	require.Len(t, f, 1)
	assert.Contains(t, f[0].Message, "internal-lib")

	// test_npm_scp_git_source_is_medium_direct_install
	f = testutil.ByVector(check(t, map[string]string{"package.json": `{"dependencies":{"plugin":"git@github.com:attacker/plugin.git#main"}}`}), "SXV-016")
	require.Len(t, f, 1)
	assert.Equal(t, []string{"install-from-url", "medium"}, []string{f[0].Rule, f[0].Severity})

	// test_direct_install_url_credentials_are_redacted
	r := rendered(testutil.ByVector(check(t, map[string]string{"requirements.txt": "pkg @ https://user:super-secret@example.com/pkg.whl?token=query-secret#fragment\n"}), "SXV-016")[0])
	for _, leak := range []string{"super-secret", "query-secret", "user:"} {
		assert.NotContains(t, r, leak)
	}

	// test_direct_install_path_credentials_are_redacted
	token := "ghp_" + strings.Repeat("z", 36)
	r = rendered(testutil.ByVector(check(t, map[string]string{"requirements.txt": "pkg @ https://host/" + token + "/pkg.whl\n"}), "SXV-016")[0])
	assert.NotContains(t, r, token)

	// test_malformed_direct_url_still_redacts_all_opaque_values
	r = rendered(testutil.ByVector(check(t, map[string]string{"requirements.txt": "pkg @ https://user:secret@[bad/pkg.whl?token=query-secret#fragment\n"}), "SXV-016")[0])
	for _, leak := range []string{"secret", "query-secret", "fragment"} {
		assert.NotContains(t, r, leak)
	}

	// test_bare_url_does_not_use_credentials_as_dependency_name
	f = testutil.ByVector(check(t, map[string]string{"requirements.txt": "https://user:secret@example.com/pkg.whl\n"}), "SXV-016")
	require.NotEmpty(t, f)
	assert.Contains(t, f[0].Message, "Dependency `dependency`")
	assert.NotContains(t, f[0].Message, "user")
	assert.NotContains(t, f[0].Message, "secret")

	// test_distinct_pyproject_dependencies_sharing_url_are_both_reported
	f = testutil.ByVector(check(t, map[string]string{"pyproject.toml": "[project]\nname = \"x\"\nversion = \"1\"\ndependencies = [\"a @ https://host/shared.whl\", \"b @ https://host/shared.whl\"]\n"}), "SXV-016")
	require.Len(t, f, 2)
	assert.Contains(t, f[0].Message+f[1].Message, "Dependency `a`")
	assert.Contains(t, f[0].Message+f[1].Message, "Dependency `b`")

	// test_physical_and_continued_dependencies_sharing_url_are_not_conflated
	f = testutil.ByVector(check(t, map[string]string{"requirements.txt": "a @ https://host/shared.whl\nb @ https\\\n://host/shared.whl\n"}), "SXV-016")
	require.Len(t, f, 2)
	assert.Contains(t, f[0].Message+f[1].Message, "Dependency `a`")
	assert.Contains(t, f[0].Message+f[1].Message, "Dependency `b`")

	// test_pyproject_metadata_url_is_not_an_install_source (pyproject half)
	assert.Empty(t, install(map[string]string{"pyproject.toml": "[project]\nname = \"x\"\nversion = \"1.0\"\ndescription = \"download from https://data.example.org/corpus.tar.gz first\"\ndependencies = [\"requests==2.31.0\", \"click==8.1.7\"]\n[project.urls]\nHomepage = \"https://example.org\"\n"}))

	// test_pep508_direct_ref_reported_once_not_also_low_unpinned
	f = testutil.ByVector(check(t, map[string]string{"requirements.txt": "requests==2.31.0\nmylib @ https://example.com/mylib-1.0.tar.gz\n"}), "SXV-016")
	require.Len(t, f, 1)
	assert.Equal(t, []string{"install-from-url", "medium"}, []string{f[0].Rule, f[0].Severity})

	// test_pyproject_direct_ref_is_install_from_url_not_low
	f = testutil.ByVector(check(t, map[string]string{"pyproject.toml": "[project]\nname = \"x\"\nversion = \"1\"\ndependencies = [\"mylib @ https://example.com/mylib-1.0.tar.gz\"]\n"}), "SXV-016")
	require.Len(t, f, 1)
	assert.Equal(t, "install-from-url", f[0].Rule)

	// test_backslash_split_direct_ref_is_still_install_from_url
	f = testutil.ByVector(check(t, map[string]string{"requirements.txt": "bar @ git+https\\\n://host/repo\n"}), "SXV-016")
	require.Len(t, f, 1)
	assert.Equal(t, []string{"install-from-url", "medium"}, []string{f[0].Rule, f[0].Severity})

	// test_backslash_split_legacy_vcs_url_is_still_install_from_url
	f = install(map[string]string{"requirements.txt": "git+https\\\n://evil.example/repo.git#egg=x\n"})
	require.Len(t, f, 1)
	assert.Equal(t, 1, *f[0].Line)

	// test_pip_option_line_is_not_a_dependency
	assert.Empty(t, install(map[string]string{"requirements.txt": "flask==2.1.0\n--find-links=https://example.com/mypkg-1.0-py3-none-any.whl\n"}))

	// test_pep508_extras_do_not_duplicate_direct_reference
	f = testutil.ByVector(check(t, map[string]string{"requirements.txt": "requests[socks] @ https://host/pkg.whl\n"}), "SXV-016")
	require.Len(t, f, 1)
	assert.Equal(t, []any{"install-from-url", "medium", 1}, []any{f[0].Rule, f[0].Severity, *f[0].Line})

	// test_npm_direct_reference_does_not_invent_a_location
	pkg, _ := json.MarshalIndent(map[string]any{"dependencies": map[string]string{"library": "https://host/package.tgz"}}, "", "  ")
	f = testutil.ByVector(check(t, map[string]string{"package.json": string(pkg)}), "SXV-016")
	require.Len(t, f, 1)
	assert.Equal(t, "package.json", f[0].Path)
	assert.Nil(t, f[0].Line)
	assert.Nil(t, f[0].Column)

	// test_credential_shaped_dependency_names_are_redacted
	for _, spec := range []string{"*", "https://host/package.tgz"} {
		pkg, _ := json.Marshal(map[string]any{"dependencies": map[string]string{ghp: spec}})
		fs := check(t, map[string]string{"package.json": string(pkg)})
		assert.True(t, hasVector(fs, "SXV-016") && hasVector(fs, "SXV-017"), spec)
		dump, _ := json.Marshal(fs)
		assert.NotContains(t, string(dump), ghp)
	}
}

func TestCredentialShapes(t *testing.T) {
	// test_each_real_credential_shape_fires
	body := fmt.Sprintf("aws = '%s'\ngh = '%s'\nslack = '%s'\ngoog = '%s'\nstripe = '%s'\n-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END RSA PRIVATE KEY-----\n", aws, ghp, slack, aiza, stripe)
	f := testutil.ByVector(check(t, map[string]string{"scripts/x.py": body}), "SXV-017")
	assert.Equal(t, map[string]bool{"aws-access-key-id": true, "github-pat": true, "slack-token": true,
		"google-api-key": true, "stripe-secret": true, "private-key": true}, evidenceSet(f, "rule"))
	for _, x := range f {
		assert.Equal(t, "high", x.Severity)
	}

	// test_credential_is_redacted_never_echoed
	// test_secret_in_script_is_not_demoted
	f = testutil.ByVector(check(t, map[string]string{"scripts/x.py": "k = '" + aws + "'\n"}), "SXV-017")
	require.Len(t, f, 1)
	assert.Equal(t, "AKIA"+strings.Repeat("*", len(aws)-8)+aws[len(aws)-4:], f[0].Evidence["redacted"])
	assert.NotContains(t, f[0].Message, aws)
	assert.Equal(t, "high", f[0].Severity)

	// test_example_key_is_suppressed
	assert.Empty(t, testutil.ByVector(check(t, map[string]string{"scripts/x.py": "k = 'AKIAIOSFODNN7EXAMPLE'\n"}), "SXV-017"))

	// test_real_shape_with_adjacent_annotation_still_fires
	for _, line := range []string{"aws_key = '" + aws + "'  # <YOUR_KEY>\n", "AWS_ACCESS_KEY_ID=" + aws + "  # cdn.example.com\n"} {
		assert.True(t, hasVector(check(t, map[string]string{".env": line}), "SXV-017"), line)
	}

	// test_git_sha_is_not_a_secret
	assert.Empty(t, testutil.ByVector(check(t, map[string]string{"scripts/x.py": "commit = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'\n"}), "SXV-017"))

	// test_ellipsis_cannot_suppress_a_complete_credential_shape
	for _, doc := range []string{"| Slack | `xoxb-` | `xoxb-123-456-abcdefghij...` |\n", "look for a github token like ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8 ...\n"} {
		assert.True(t, hasVector(check(t, map[string]string{"PATTERNS.md": doc}), "SXV-017"), doc)
	}
	assert.True(t, hasVector(check(t, map[string]string{"config.py": "TOKEN = 'xoxb-123-456-abcdefghij'\n"}), "SXV-017"))

	// test_encrypted_and_dsa_private_keys_fire
	for _, label := range []string{"ENCRYPTED PRIVATE KEY", "DSA PRIVATE KEY", "PRIVATE KEY"} {
		pem := fmt.Sprintf("-----BEGIN %s-----\nMIIBODUMMYINERTBODY\n-----END %s-----\n", label, label)
		assert.True(t, hasVector(check(t, map[string]string{"server.pem": pem}), "SXV-017"), label)
	}

	// test_private_key_header_requires_a_complete_block
	assert.Empty(t, testutil.ByVector(check(t, map[string]string{"README.txt": "-----BEGIN PRIVATE KEY-----\nnot a key\n"}), "SXV-017"))
	f = testutil.ByVector(check(t, map[string]string{"secret.pem": "-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n"}), "SXV-017")
	require.Len(t, f, 1)
	assert.Equal(t, "private-key", f[0].Evidence["rule"])

	// test_github_published_example_token_is_not_a_leak
	assert.False(t, hasVector(check(t, map[string]string{"README.txt": "token form ghp_16C7e42F292c6912E7710c838347Ae178B4a in the docs\n"}), "SXV-017"))
	assert.True(t, hasVector(check(t, map[string]string{".env": "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n"}), "SXV-017"))

	// test_finegrained_github_pat_fires
	assert.True(t, hasVector(check(t, map[string]string{"config.py": "GITHUB_TOKEN = 'github_pat_11ABCDE7Y0aBcDeFgHiJkL_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ0123456789aBcDeF'\n"}), "SXV-017"))

	// test_slack_placeholder_token_is_suppressed
	assert.False(t, hasVector(check(t, map[string]string{"settings.yaml": "slack_bot_token: xoxb-your-token-here\n"}), "SXV-017"))

	// test_slack_app_level_and_refresh_tokens_fire
	f = testutil.ByVector(check(t, map[string]string{"config.py": "app = 'xapp-1-A0123456789-1234567890123-abcdefabcdefabcdefabcdef'\nref = 'xoxe-1-My0-1234567890-abcdefghijklmnop'\n"}), "SXV-017")
	require.Len(t, f, 2)
	for _, x := range f {
		assert.Equal(t, []any{"slack-token", "high"}, []any{x.Evidence["rule"], x.Severity})
	}

	// test_npm_pypi_azure_credentials_fire
	body = "NPM_TOKEN = 'npm_" + strings.Repeat("a1B2c3", 6) + "'\n" +
		"PYPI_TOKEN = 'pypi-AgEIcHlwaS5vcmcCJDReAlInErTtOkEn1234567890abcdefABCDEF'\n" +
		"AZURE = 'AccountKey=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMw==;'\n"
	rules := evidenceSet(testutil.ByVector(check(t, map[string]string{"config.py": body}), "SXV-017"), "rule")
	for _, r := range []string{"npm-token", "pypi-token", "azure-storage-key"} {
		assert.True(t, rules[r], r)
	}

	// test_azurite_development_key_is_not_a_leak
	azurite := "AzureWebJobsStorage=DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;\n"
	assert.False(t, hasVector(check(t, map[string]string{"local.settings.json": azurite}), "SXV-017"))
	assert.True(t, hasVector(check(t, map[string]string{"cfg.py": "AccountKey=RmFrZUtleUZvclRlc3RpbmcxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnc=\n"}), "SXV-017"))

	// test_cosmos_emulator_key_is_not_a_leak
	assert.False(t, hasVector(check(t, map[string]string{"appsettings.json": "{\"ConnectionStrings\":{\"CosmosDb\":\"AccountEndpoint=https://localhost:8081/;AccountKey=C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==;\"}}\n"}), "SXV-017"))

	// test_slack_placeholder_and_prose_are_not_leaks_but_real_token_fires
	assert.False(t, hasVector(check(t, map[string]string{".env.example": "SLACK_BOT_TOKEN=xoxb-0000000000-0000000000000-abcdefghijklmnopqrstuvwx\n"}), "SXV-017"))
	assert.False(t, hasVector(check(t, map[string]string{"README.md": "The value looks like xoxb-not-really-a-token-just-words in the docs.\n"}), "SXV-017"))
	assert.True(t, hasVector(check(t, map[string]string{"config.py": "TOKEN = '" + slack + "'\n"}), "SXV-017"))

	// test_placeholder_words_inside_opaque_credentials_do_not_suppress
	tokens := []string{"ghp_" + strings.Repeat("a", 32) + "here", "AIza" + strings.Repeat("B", 29) + "sample", "npm_" + strings.Repeat("a", 31) + "dummy"}
	assert.Len(t, testutil.ByVector(check(t, map[string]string{"config.py": strings.Join(tokens, "\n")}), "SXV-017"), len(tokens))

	// test_google_key_may_end_in_hyphen_but_not_continue
	valid := "AIza" + strings.Repeat("A", 34) + "-"
	f = testutil.ByVector(check(t, map[string]string{"config.py": "KEY = '" + valid + "'\n"}), "SXV-017")
	require.Len(t, f, 1)
	assert.Equal(t, "google-api-key", f[0].Evidence["rule"])
	assert.Empty(t, testutil.ByVector(check(t, map[string]string{"config.py": "KEY = '" + valid + "A'\n"}), "SXV-017"))

	// test_long_private_keys_and_boundary_isolation
	for _, label := range []string{"OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK"} {
		header, footer := "-----BEGIN "+label+"-----", "-----END "+label+"-----"
		body := header + "\n" + strings.Repeat("QUJDREVGR0hJSktMTU5PUA==\n", 240)
		f := testutil.ByVector(check(t, map[string]string{"secret.pem": body + footer}), "SXV-017")
		require.Len(t, f, 1, label)
		assert.Equal(t, []any{"secret.pem", 1, (*int)(nil), "high"}, []any{f[0].Path, *f[0].Line, f[0].Column, f[0].Severity})
		assert.Equal(t, []any{"private-key", false}, []any{f[0].Evidence["rule"], f[0].Evidence["fenced_example"]})
		for _, broken := range []string{body, body + "-----END RSA PRIVATE KEY-----", body + header + "\n" + footer} {
			assert.Empty(t, testutil.ByVector(check(t, map[string]string{"secret.pem": broken}), "SXV-017"))
		}
	}
}

func TestFenceDemotionAndCaps(t *testing.T) {
	// test_fenced_example_is_demoted_not_dropped
	f := testutil.ByVector(check(t, map[string]string{"GUIDE.md": "# Guide\n\nHere is a key:\n\n```\n" + aws + "\n```\n"}), "SXV-017")
	require.Len(t, f, 1)
	assert.Equal(t, []any{"medium", true}, []any{f[0].Severity, f[0].Evidence["fenced_example"]})

	// test_unfenced_markdown_key_stays_high
	f = testutil.ByVector(check(t, map[string]string{"GUIDE.md": "# Guide\n\nThe key is " + aws + " right here.\n"}), "SXV-017")
	require.Len(t, f, 1)
	assert.Equal(t, []any{"high", false}, []any{f[0].Severity, f[0].Evidence["fenced_example"]})

	// test_indented_code_does_not_demote_following_prose_secret
	f = testutil.ByVector(check(t, map[string]string{"GUIDE.md": "    example command\n\nThe live key is " + aws + "\n"}), "SXV-017")
	require.Len(t, f, 1)
	assert.Equal(t, []any{"high", false}, []any{f[0].Severity, f[0].Evidence["fenced_example"]})

	// test_tilde_crlf_and_unclosed_fences_keep_exact_secret_context
	f = testutil.ByVector(check(t, map[string]string{"GUIDE.md": "~~~text\r\n" + aws + "\r\n~~~\r\n" + ghp + "\r\n"}), "SXV-017")
	sev := map[string]string{}
	for _, x := range f {
		sev[x.Evidence["rule"].(string)] = x.Severity
	}
	assert.Equal(t, map[string]string{"aws-access-key-id": "medium", "github-pat": "high"}, sev)
	f = testutil.ByVector(check(t, map[string]string{"GUIDE.md": "```text\n" + aws + "\n"}), "SXV-017")
	require.Len(t, f, 1)
	assert.Equal(t, "medium", f[0].Severity)

	// test_agent_identity_fence_demotes_secret
	f = testutil.ByVector(check(t, map[string]string{"CLAUDE.md": "```text\n" + aws + "\n```\n"}), "SXV-017")
	require.Len(t, f, 1)
	assert.Equal(t, "medium", f[0].Severity)

	// test_committed_credentials_are_capped_per_file
	var lines []string
	for i := range findings.Cap + 3 {
		lines = append(lines, fmt.Sprintf("ghp_%036d", i))
	}
	fs := check(t, map[string]string{"secrets.txt": strings.Join(lines, "\n")})
	assert.Len(t, testutil.ByVector(fs, "SXV-017"), findings.Cap)
	assert.Equal(t, 1, capped(fs))

	// test_credential_cap_retains_high_severity_after_fenced_examples
	examples := strings.Join(lines[:findings.Cap+2], "\n")
	for _, c := range []struct {
		body string
		line int
	}{{"```\n" + examples + "\n```\n" + aws, findings.Cap + 5}, {aws + "\n```\n" + examples + "\n```", 1}} {
		fs := check(t, map[string]string{"GUIDE.md": c.body})
		hits := testutil.ByVector(fs, "SXV-017")
		assert.Len(t, hits, findings.Cap)
		var high []findings.Finding
		for _, h := range hits {
			if h.Severity == "high" {
				high = append(high, h)
			}
		}
		require.Len(t, high, 1)
		assert.Equal(t, []any{"aws-access-key-id", c.line}, []any{high[0].Evidence["rule"], *high[0].Line})
		assert.Equal(t, 1, capped(fs))
	}
}

// finditer replays Python's backtracking at the \b/lookaround ends the RE2 pattern lacks; the
// spans were recorded from the oracle's re.finditer on these edge tokens.
func TestFinditerMatchesPythonRe(t *testing.T) {
	rules := map[string]secretRule{}
	for _, r := range secretRules {
		rules[r.ID] = r
	}
	a := strings.Repeat
	cases := []struct {
		rule, text string
		want       [][2]int
	}{
		{"slack-token", "xoxb-1234567890-1234567890123-abcdefghij-", [][2]int{{0, 40}}},
		{"slack-token", "xoxb-1234567890-1234567890123-abcdefghij-_", [][2]int{{0, 41}}},
		{"slack-token", "xoxb-1234567890-xoxb-1234567890-abc_", [][2]int{{0, 32}}},
		{"slack-token", "xoxb-1234567890-1234567890123-abcdefghij--- next", [][2]int{{0, 40}}},
		{"aws-access-key-id", "éAKIAABCDEFGHIJKLMNOP", nil},
		{"aws-access-key-id", "AKIAABCDEFGHIJKLMNOPé", nil},
		{"aws-access-key-id", "_AKIAABCDEFGHIJKLMNOP AKIAABCDEFGHIJKLMNOP.", [][2]int{{22, 42}}},
		{"google-api-key", "éAIza" + a("B", 35) + "é", [][2]int{{2, 41}}},
		{"google-api-key", "AIza" + a("A", 34) + "-A", nil},
		{"github-pat", "ghp_" + a("a", 36) + "é", nil},
		{"github-pat", "ghp_" + a("a", 40) + " ghp_" + a("b", 36) + "_", [][2]int{{0, 44}}},
		{"azure-storage-key", "AccountKey=" + a("A", 32) + "===x", [][2]int{{0, 45}}},
		{"pypi-token", "xpypi-AgEIcHlwaS5vcmc" + a("a", 16) + " pypi-AgEIcHlwaS5vcmc" + a("b", 16) + "é", [][2]int{{38, 74}}},
		{"private-key", "-----BEGIN RSA PRIVATE KEY----- -----BEGIN PRIVATE KEY BLOCK-----", [][2]int{{0, 31}, {32, 65}}},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, rules[c.rule].finditer(c.text), "%s %q", c.rule, c.text)
	}
}
