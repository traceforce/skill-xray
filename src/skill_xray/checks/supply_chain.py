"""Supply-chain hygiene over the IR's dependency manifests and committed text.

Two sibling detections that share this module, both reading the parsed IR only:

  - SXV-016 (unpinned dependency): a dependency declared without an exact pin
    (a range, caret, tilde, or bare name) in a shipped manifest -- the code that
    actually installs is not the code that was reviewed. This is a hygiene
    signal, so it is deliberately LOW severity: over-weighting it drowns real
    findings, because almost every real project ships some unpinned range.
  - SXV-017 (committed credential): a live credential (AWS key id, GitHub PAT,
    Slack token, PEM/OpenSSH/PGP private-key header, Google API key, Stripe live
    key) committed into any non-asset text file. A hit inside a fenced markdown
    example is demoted HIGH->MEDIUM rather than dropped, so a documented sample
    is still surfaced but cannot fail the clean-fixture bar the T1 engines hold.

Precision is carried by structure, not entropy: only prefix/shape-verifiable
credential rules fire (a bare 40-hex git SHA is intentionally NOT a rule), and a
small set of exact published examples and family-specific placeholder shapes is
suppressed. The network OSV/advisory arm is outside this offline, ledger-free
`check` contract, so a pinned dependency contributes no finding."""

from __future__ import annotations

import re
from bisect import bisect_right
from heapq import nsmallest
from urllib.parse import urlsplit, urlunsplit

from ..findings import FINDING_CAP, SEVERITY_RANK, Finding, cap_findings

# Severity strings the IR uses (lowercase).
_HIGH = "high"
_MEDIUM = "medium"
_LOW = "low"

# --- SXV-016: dependency ecosystem -------------------------------------------
# Ecosystem is derived from the manifest basename, since the IR dep dict carries
# no ecosystem. package.json is npm; requirements.txt / pyproject.toml are PyPI.
_NPM_MANIFEST = "package.json"


def _is_requirements_manifest(base):
    """A pip requirements file (line-oriented, one requirement per line), by basename: the exact
    `requirements.txt` or a `*requirements*.txt` variant (requirements-dev.txt, dev-requirements
    .txt). NOT pyproject.toml/setup.py/.cfg, which mix dependencies with free-text metadata."""
    return base.endswith(".txt") and "requirements" in base


# --- SXV-017: credential rules -----------------------------------------------
# Only patterns with a verifiable prefix or structure. A bare "40 hex chars" rule
# matches every git SHA in a lockfile -- the exact false positive that made
# another scanner unusable -- so it is deliberately absent (do not add entropy).
_SECRET_RULES = (
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), _HIGH),
    ("github-pat",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"), _HIGH),
    # bot/user/app-config/refresh/legacy (xox[abeprs]-) plus the app-level Socket-Mode family
    # (xapp-1-...). A real token's first segment is a numeric ID, so require a digit right after
    # `xox?-`: that rejects hyphenated prose (`xoxb-not-really-a-token`) while matching real tokens.
    ("slack-token",
     re.compile(r"\b(?:xox[abeprs]-\d[A-Za-z0-9-]{9,}|xapp-[0-9]-[A-Za-z0-9-]{10,})\b"), _HIGH),
    # any PEM private-key label: bare PKCS#8, RSA/EC/DSA/DH, ENCRYPTED, OPENSSH, or PGP ... BLOCK.
    ("private-key",
     re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"), _HIGH),
    ("google-api-key",
     re.compile(r"(?<![0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"), _HIGH),
    ("stripe-secret", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b"), _HIGH),
    # npm automation token (npm_ + 36 base62); PyPI upload token (pypi- + the fixed base64 of
    # "pypi.org", AgEIcHlwaS5vcmc, then the macaroon); Azure Storage/Service-Bus shared key
    # (AccountKey=/SharedAccessKey= + a long base64). Each has a verifiable prefix.
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), _HIGH),
    ("pypi-token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{16,}"), _HIGH),
    ("azure-storage-key",
     re.compile(r"\b(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/]{32,}={0,2}"), _HIGH),
)

_SLACK_ZERO_PLACEHOLDER = re.compile(
    r"^xox[abeprs]-0{10}-0{13}-[A-Za-z0-9-]+$"
)

# Well-known PUBLISHED example credentials (docs/tutorials copy these verbatim); they carry no
# in-token placeholder marker but are not live. An attacker uses a real key, never these.
_KNOWN_EXAMPLE = frozenset({
    "AKIAIOSFODNN7EXAMPLE",                       # AWS documentation key ID
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",   # GitHub's canonical PAT-format example
    # the Azurite / Azure Storage Emulator development key: a single global public constant baked
    # into every install and every Azure Functions sample's local.settings.json (devstoreaccount1).
    "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/"
    "K1SZFPTOtr/KBHBeksoGMGw==",
    # the Azure Cosmos DB Emulator well-known primary key: the sibling emulator constant, printed
    # verbatim in Microsoft's docs and every Cosmos sample's appsettings.json (localhost:8081).
    "AccountKey=C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy"
    "67XIw/Jw==",
})

# Markdown-lane kinds carry a fence predicate (fenced hits demote to MEDIUM); a
# script, config, or raw secret_material file has no fence context (all HIGH).
_MARKDOWN_LANE = {"skill_manifest", "instruction", "doc", "agent_identity"}


def _ecosystem(rel):
    """Ecosystem for a dep manifest from its basename: npm for package.json, else PyPI."""
    base = rel.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return "npm" if base == _NPM_MANIFEST else "PyPI"


def _redact(secret):
    """Never echo a live credential into a report that gets shared."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return "%s%s%s" % (secret[:4], "*" * (len(secret) - 8), secret[-4:])


def _fence_predicate(markdown):
    """Return a predicate over exact fenced-block source spans."""
    spans = tuple(markdown.fence_spans)
    starts = tuple(start for start, _end in spans)

    def contains(line):
        index = bisect_right(starts, line) - 1
        return index >= 0 and line <= spans[index][1]

    return contains


def _is_placeholder(rule_id, token):
    return rule_id == "slack-token" and bool(_SLACK_ZERO_PLACEHOLDER.fullmatch(token))


# A credential-shaped token that a test under the package's own test directory hands to an
# assertion or a redaction call ("test/sanitize.test.js": assert.ok(redactString('ghp_...'))) is a
# fixture the tests need, not a secret the skill uses: reported, but at medium, like a fenced
# example. The path alone is not enough; a token a script under tests/ sends somewhere stays high.
_TEST_PATH_RE = re.compile(r"(?:^|/)(?:tests?|__tests__|spec)/", re.I)
_FIXTURE_CALLEE_RE = re.compile(
    r"(?:^|\.)(?:assert(?:\.\w+)?|expect|redact\w*|sanitiz\w*|mask\w*|scrub\w*)$", re.I)
# a closed string literal or a comment before the token is not code ('const s = "assert("; ...')
_NOT_CODE_RE = re.compile(
    r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|/\*.*?\*/|//.*|#.*")


def _fixture_call(line, col):
    """The innermost call still open at col is an assertion or redaction call."""
    prefix = _NOT_CODE_RE.sub(lambda m: " " * len(m.group(0)), line[:col])
    opens = []
    for i, ch in enumerate(prefix):
        if ch == "(":
            opens.append(i)
        elif ch == ")" and opens:
            opens.pop()
    callee = re.search(r"([\w.]+)\s*$", prefix[:opens[-1]]) if opens else None
    return callee is not None and _FIXTURE_CALLEE_RE.search(callee.group(1)) is not None


def _reported(hit, lines, fixture_path):
    """The severity a hit is reported at: medium for a token inside an assertion or redaction call
    in a file under the package's own tests."""
    rule_id, lineno, col, matched, sev = hit
    if sev != "high" or not fixture_path:
        return sev
    return _MEDIUM if _fixture_call(lines[lineno - 1], col) else sev


def _scan_secrets(text, in_fence):
    """Yield credential shapes, retaining only one pending private-key boundary."""
    pending, saw_encoded = None, False
    for lineno, line in enumerate(text.split("\n"), 1):
        for rule_id, rx, sev in _SECRET_RULES:
            for m in rx.finditer(line):
                token = m.group(0)
                if token in _KNOWN_EXAMPLE or _is_placeholder(rule_id, token):
                    continue                        # published example / placeholder token
                if rule_id == "private-key":
                    pending = (lineno, m.start(), token,
                               token.replace("-----BEGIN ", "-----END ", 1))
                    saw_encoded = False
                    continue
                fenced = bool(in_fence and in_fence(lineno))
                yield rule_id, lineno, m.start(), token, (_MEDIUM if fenced else sev)
        if pending and lineno > pending[0]:
            if pending[3] in line:
                if saw_encoded:
                    start, col, token, _end = pending
                    fenced = bool(in_fence and in_fence(start))
                    yield "private-key", start, col, token, (_MEDIUM if fenced else _HIGH)
                pending = None
            elif len(line.strip()) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=]+", line.strip()):
                saw_encoded = True


def _sca_findings(parsed):
    """SXV-016: one LOW finding per unpinned dependency across every dep manifest.

    A parse failure leaves .deps None; there is no finding channel for an
    unresolvable here (the parent's coverage ledger records that separately), so
    such a manifest simply contributes nothing rather than reading as clean."""
    out = []
    for p in parsed.artifacts:
        if p.kind != "dep_manifest" or p.deps is None:
            continue
        eco = _ecosystem(p.rel)
        for dep in p.deps:
            if dep.get("pinned"):
                continue                            # an exact pin is what we want; not a finding
            if eco == "npm" and _npm_install_source(dep.get("specifier") or ""):
                continue                            # reported as install-from-url (medium), not low
            if eco == "PyPI" and _VCS_INSTALL_RE.search(dep.get("raw") or ""):
                continue                            # a `name @ url` direct ref: medium, not low
            name = _redact_source_secrets(dep.get("name") or "dependency")
            out.append(Finding(
                vector="SXV-016", rule="unpinned-dependency", severity=_LOW,
                path=p.rel,
                message=("Dependency `%s` is declared without an exact version, so the "
                         "code installed is not the code reviewed." % name),
                line=dep.get("line"), offset=None, length=None,
                evidence={"ecosystem": eco, "package": name, "pin_state": "unpinned"}))
    return out


def _secret_findings(parsed):
    """SXV-017: one finding per committed credential in any non-asset text file."""
    out = []
    for p in parsed.artifacts:
        if p.text is None or p.kind == "asset":
            continue                                # binary/native kinds have no .text either
        in_fence = None
        if p.kind in _MARKDOWN_LANE and p.markdown is not None:
            in_fence = _fence_predicate(p.markdown)
        # Keep memory bounded without letting early fenced examples or test fixtures hide later
        # credentials: the cap sorts by the severity each hit will be reported at.
        lines = p.text.split("\n")
        fixture_path = _TEST_PATH_RE.search(p.rel) is not None
        selected = nsmallest(FINDING_CAP + 1, _scan_secrets(p.text, in_fence),
                             key=lambda hit: (SEVERITY_RANK[_reported(hit, lines, fixture_path)],
                                              hit[1]))
        for hit in selected[:FINDING_CAP]:
            rule_id, lineno, _col, matched, sev = hit
            redacted = _redact(matched)
            evidence = {"rule": rule_id, "redacted": redacted, "fenced_example": sev == _MEDIUM}
            if _reported(hit, lines, fixture_path) != sev:
                sev, evidence["test_fixture"] = _MEDIUM, True
            out.append(Finding(
                vector="SXV-017", rule="committed-credential", severity=sev,
                path=p.rel,
                message=("Credential matching `%s` is committed in the package (%s)."
                         % (rule_id, redacted)),
                line=lineno, offset=None, length=None,
                evidence=evidence))
        if len(selected) > FINDING_CAP:
            out.append(Finding(
                vector="", rule="findings-capped", severity=_LOW, path=p.rel,
                message=("Additional committed-credential findings were suppressed after "
                         "the per-file limit of %d." % FINDING_CAP)))
    return out


# A dependency installed straight from a VCS/URL rather than a pinned registry release: the
# fetched code is neither reviewed nor version-locked. In a requirements file the Requirement
# parser drops these lines as "unparseable", so they are scanned from the raw manifest text;
# npm specifiers are classified from the parsed IR instead (see _npm_install_source).
_VCS_INSTALL_RE = re.compile(
    r"(?:git|hg|svn|bzr)\+\w+://\S+|"
    r"@\s*[a-z][a-z0-9]*(?:\+[a-z0-9]+)?://\S+|"      # PEP 508 direct ref: `name @ scheme://...`
    r"(?:^|\s|=)https?://\S+?\.(?:git|zip|tar(?:\.(?:gz|bz2|xz))?|tgz|whl)\b|"
    r"(?:-e|--editable)\s+\S*://\S+", re.I)

_NPM_SHORTHAND_RE = re.compile(r"^(?:github|gitlab|bitbucket|gist):", re.I)
_NPM_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9][\w.-]*/[\w.-]+(?:#.+)?$")
_NPM_SCP_RE = re.compile(r"^git@[^:\s]+:[^\s]+$", re.I)


def _npm_install_source(spec):
    """The install-source string if an npm dependency specifier installs from a VCS/URL/host
    shorthand (`git+https://...`, any `scheme://`, `github:owner/repo`, bare `owner/repo`), else
    None. Judged on the PARSED specifier, never on raw manifest text, so a `repository`/`homepage`
    metadata URL -- which is not a dependency -- is never mistaken for an install channel."""
    s = (spec or "").strip()
    if not s:
        return None
    if "://" in s:                                   # git+https://, https://, ssh://, git://
        return s
    if _NPM_SHORTHAND_RE.match(s):                    # github:/gitlab:/bitbucket:/gist: shorthand
        return s
    if _NPM_OWNER_REPO_RE.match(s):                   # bare owner/repo GitHub shorthand
        return s                                      # (a version/range/tag/file: spec has no '/')
    if _NPM_SCP_RE.match(s):                          # git@github.com:owner/repo.git
        return s
    return None


def _sanitize_source(source):
    """Remove URL credentials and opaque query/fragment values from report output."""
    prefix = ""
    candidate = source
    if candidate.startswith("git+"):
        prefix, candidate = "git+", candidate[4:]
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        parsed = None
    if parsed and parsed.scheme and parsed.netloc:
        host = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is not None:
            host = "%s:%d" % (host, port)
        safe = prefix + urlunsplit((parsed.scheme, host, parsed.path, "", ""))
        return _redact_source_secrets(safe)
    # Even malformed URLs must not retain opaque values in reports. Split these before the
    # conservative userinfo fallback because urlsplit can reject malformed IPv6 authorities.
    candidate = candidate.split("#", 1)[0].split("?", 1)[0]
    candidate = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@", r"\1***@", candidate)
    return _redact_source_secrets(prefix + candidate)


def _redact_source_secrets(source):
    for _rule_id, pattern, _severity in _SECRET_RULES:
        source = pattern.sub(lambda match: _redact(match.group(0)), source)
    return source


def _install_finding(rel, name, source, line):
    safe_source = _sanitize_source(source)
    name = _redact_source_secrets(name or "dependency")
    return Finding(
        vector="SXV-016", rule="install-from-url", severity=_MEDIUM, path=rel,
        message=("Dependency `%s` installs directly from a VCS/URL source (`%s`): the code "
                 "fetched is not a reviewed, pinned registry release."
                 % (name, safe_source[:120])),
        line=line, offset=None, length=None,
        evidence={"install_source": safe_source[:200], "pin_state": "vcs_or_url"})


def _logical_requirement_lines(text):
    """Yield pip continuation-joined lines with their first physical line."""
    buf = ""
    start = None
    for number, raw in enumerate(text.split("\n") + [""], 1):
        stripped = raw.rstrip()
        if stripped.endswith("\\") and not stripped.lstrip().startswith("#"):
            start = start or number
            buf += stripped[:-1]
            continue
        yield start or number, buf + raw
        buf = ""
        start = None


def _vcs_install_findings(parsed):
    """SXV-016: a dependency that installs from a VCS or URL source (git+https://..., a bare
    archive URL, a PEP 508 `name @ url` direct reference, an npm host shorthand, `-e <url>`) --
    an unreviewed, unpinned install channel."""
    out = []
    for p in parsed.artifacts:
        if p.kind != "dep_manifest":
            continue
        base = p.rel.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if base == _NPM_MANIFEST and p.deps is not None:
            # package.json: classify each PARSED specifier, so a repository/homepage/bugs URL in
            # the manifest metadata (not a dependency) cannot false-positive, and no greedy raw
            # match leaks trailing JSON delimiters into the evidence.
            for dep in p.deps:
                source = _npm_install_source(dep.get("specifier") or "")
                if source:
                    out.append(_install_finding(p.rel, dep.get("name"), source, dep.get("line")))
            continue
        seen = set()
        if _is_requirements_manifest(base) and p.text:
            # Raw-scan logical pip lines for a bare archive URL, `-e <url>`, or a git+... line the
            # parser drops. Preserve the first physical line across continuations. Skip
            # a pip GLOBAL OPTION line (--find-links / --index-url / -r / ...): it is configuration,
            # not a dependency -- only -e/--editable is an install directive.
            for n, raw in _logical_requirement_lines(p.text):
                line = re.split(r"\s#", raw.strip(), maxsplit=1)[0].strip()   # drop inline comment
                if not line or line.startswith("#"):
                    continue
                if line.startswith("-") and not re.match(r"(?:-e|--editable)\b", line):
                    continue
                m = _VCS_INSTALL_RE.search(line)
                if m:
                    src = m.group(0).lstrip("@ ")
                    before = line[:m.start()].strip()
                    name = re.split(r"[\s@<>=!~;\[]", before, maxsplit=1)[0]
                    if not name or name in {"-e", "--editable"}:
                        name = "dependency"
                    seen.add((name, src))
                    out.append(_install_finding(p.rel, name, src, n))
        # Classify PARSED deps (requirements AND pyproject): a PEP 508 `name @ url` direct ref
        # parses into .deps with dep.raw = the JOINED requirement (pip backslash-continuations
        # reassembled), so this catches a continuation-split ref the physical scan cannot see. Sound
        # for pyproject too -- a metadata description/urls URL is never a parsed dependency.
        for dep in (p.deps or []):
            m = _VCS_INSTALL_RE.search(dep.get("raw") or "")
            if m:
                src = m.group(0).lstrip("@ ")
                if (dep.get("name"), src) not in seen:
                    out.append(_install_finding(
                        p.rel, dep.get("name"), src, dep.get("line")
                    ))
    return out


def check(parsed) -> list:
    """Run supply-chain hygiene over the IR: unpinned deps (SXV-016) and committed
    credentials (SXV-017). Reads the parsed IR only -- no filesystem, no re-parse,
    no network."""
    dependencies = cap_findings(_sca_findings(parsed) + _vcs_install_findings(parsed))
    return dependencies + _secret_findings(parsed)
