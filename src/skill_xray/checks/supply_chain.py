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
whole line that reads as a placeholder (`AKIA...EXAMPLE`, `<YOUR_KEY>`, `xxxx`)
suppresses the hit. The network OSV/advisory arm is outside this offline,
ledger-free `check` contract, so a pinned dependency contributes no finding."""

from __future__ import annotations

import re

from ..findings import Finding

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
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), _HIGH),
    ("stripe-secret", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b"), _HIGH),
    # npm automation token (npm_ + 36 base62); PyPI upload token (pypi- + the fixed base64 of
    # "pypi.org", AgEIcHlwaS5vcmc, then the macaroon); Azure Storage/Service-Bus shared key
    # (AccountKey=/SharedAccessKey= + a long base64). Each has a verifiable prefix.
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), _HIGH),
    ("pypi-token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{16,}"), _HIGH),
    ("azure-storage-key",
     re.compile(r"\b(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/]{32,}={0,2}"), _HIGH),
)

# A value that is obviously a placeholder is documentation, not a leak. Matched against the
# TOKEN, not the whole line: the giveaway is INSIDE the token (AKIAIOSFODNN7EXAMPLE is AWS's
# own doc key with no break before "EXAMPLE"). Line-scoping was wrong -- an unrelated "example"
# in a trailing comment (`AKIA...  # cdn.example.com`) silently dropped a real credential.
_PLACEHOLDER = re.compile(
    r"(?i)(?:example|sample|dummy|placeholder|your[_-]?\w+|xxx+|redacted|"
    r"replace[_-]?me|changeme|test[_-]?token|here\b|<[^>]+>|\.\.\.|(\d)\1{7,})"
    # (\d)\1{7,}: a run of 8+ identical digits (0000000000, 1111...) is the numeric-zero
    # placeholder convention (e.g. a xoxb-0000000000-... fake in a .env.example), never a real key.
)
# A credential-shaped token written as a truncated pattern example -- `ghp_abc...`,
# `xoxb-1-2-abc...` in a reference table or docs -- is illustrative, never a live secret (a real
# committed key is written whole so it works). Matched on the bytes right AFTER the token: an
# ellipsis (`...` or the unicode `…`, past optional spaces) marks the truncation.
_TRUNCATED = re.compile(r"\s*(?:\.\.\.|\u2026)")

# Well-known PUBLISHED example credentials (docs/tutorials copy these verbatim); they carry no
# in-token placeholder marker but are not live. An attacker uses a real key, never these.
_KNOWN_EXAMPLE = frozenset({
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
_MARKDOWN_LANE = {"skill_manifest", "instruction", "doc"}


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
    """Reconstruct in_fence(lineno)->bool from markdown.fences.

    Each fence tuple is (info, content, line) with `line` the opening delimiter
    (file-relative, 1-based, already offset past frontmatter -- matching the
    line numbering used to scan the full .text). The opening marker, the body,
    AND the closing marker are in-fence, so cover `line .. line + content.count
    ('\\n') + 1` inclusive for each fence."""
    fenced = set()
    for _info, content, line in (markdown.fences or []):
        if not isinstance(line, int) or line < 1:
            continue                                # a mapless token has line 0: not a real fence
        body_lines = (content or "").count("\n")
        # opening (line) + body_lines + closing (one more) are all in-fence.
        for n in range(line, line + body_lines + 2):
            fenced.add(n)
    return fenced.__contains__


def _scan_secrets(text, in_fence):
    """Yield (rule_id, lineno, matched, severity) for each committed credential.

    A whole-line placeholder match suppresses the hit; a fenced hit is demoted to
    MEDIUM rather than dropped. `in_fence` is None (no demotion) or a predicate."""
    for lineno, line in enumerate(text.split("\n"), 1):
        for rule_id, rx, sev in _SECRET_RULES:
            for m in rx.finditer(line):
                token = m.group(0)
                if token in _KNOWN_EXAMPLE or _PLACEHOLDER.search(token):
                    continue                        # published example / placeholder token
                if _TRUNCATED.match(line[m.end():]):
                    continue                        # truncated pattern example (`ghp_abc...`): docs
                fenced = bool(in_fence and in_fence(lineno))
                yield rule_id, lineno, token, (_MEDIUM if fenced else sev)


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
            name = dep.get("name")
            out.append(Finding(
                vector="SXV-016", rule="unpinned-dependency", severity=_LOW,
                path=p.rel,
                message=("Dependency `%s` is declared without an exact version, so the "
                         "code installed is not the code reviewed." % name),
                line=1, offset=None, length=None,
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
        for rule_id, lineno, matched, sev in _scan_secrets(p.text, in_fence):
            redacted = _redact(matched)
            out.append(Finding(
                vector="SXV-017", rule="committed-credential", severity=sev,
                path=p.rel,
                message=("Credential matching `%s` is committed in the package (%s)."
                         % (rule_id, redacted)),
                line=lineno, offset=None, length=None,
                evidence={"rule": rule_id, "redacted": redacted,
                          "fenced_example": sev == _MEDIUM}))
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
    return None


def _install_finding(rel, name, source, line):
    return Finding(
        vector="SXV-016", rule="install-from-url", severity=_MEDIUM, path=rel,
        message=("Dependency `%s` installs directly from a VCS/URL source (`%s`): the code "
                 "fetched is not a reviewed, pinned registry release." % (name, source[:120])),
        line=line, offset=None, length=None,
        evidence={"install_source": source[:200], "pin_state": "vcs_or_url"})


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
                    out.append(_install_finding(p.rel, dep.get("name"), source, 1))
            continue
        seen = set()
        if _is_requirements_manifest(base) and p.text:
            # A pip requirements file is line-oriented: raw-scan physical lines (accurate line
            # numbers) for a bare archive URL, `-e <url>`, or a git+... line the parser drops. Skip
            # a pip GLOBAL OPTION line (--find-links / --index-url / -r / ...): it is configuration,
            # not a dependency -- only -e/--editable is an install directive.
            for n, raw in enumerate(p.text.split("\n"), 1):
                line = re.split(r"\s#", raw.strip(), maxsplit=1)[0].strip()   # drop inline comment
                if not line or line.startswith("#"):
                    continue
                if line.startswith("-") and not re.match(r"(?:-e|--editable)\b", line):
                    continue
                m = _VCS_INSTALL_RE.search(line)
                if m:
                    src = m.group(0).lstrip("@ ")
                    seen.add(src)
                    name = re.split(r"[\s@<>=!~;]", line, maxsplit=1)[0] or "dependency"
                    out.append(_install_finding(p.rel, name, src, n))
        # Classify PARSED deps (requirements AND pyproject): a PEP 508 `name @ url` direct ref
        # parses into .deps with dep.raw = the JOINED requirement (pip backslash-continuations
        # reassembled), so this catches a continuation-split ref the physical scan cannot see. Sound
        # for pyproject too -- a metadata description/urls URL is never a parsed dependency.
        for dep in (p.deps or []):
            m = _VCS_INSTALL_RE.search(dep.get("raw") or "")
            if m:
                src = m.group(0).lstrip("@ ")
                if src not in seen:
                    out.append(_install_finding(p.rel, dep.get("name"), src, 1))
                    seen.add(src)
    return out


def check(parsed) -> list:
    """Run supply-chain hygiene over the IR: unpinned deps (SXV-016) and committed
    credentials (SXV-017). Reads the parsed IR only -- no filesystem, no re-parse,
    no network."""
    return _sca_findings(parsed) + _vcs_install_findings(parsed) + _secret_findings(parsed)
