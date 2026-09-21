"""Read a skill package directory into a file inventory and a coverage ledger.

Walks the package, decodes each text file, classifies every file by role, and
records every file it does not read. It does not run anything and does not read
any file outside the package root. It does not parse file contents (frontmatter,
markdown, shell, Python); classification is by name and extension only. Standard
library only, no network.

The package may be malicious, so the walker:
  - does not follow a symlink or an NTFS junction out of the directory;
  - does not open a FIFO, device or socket;
  - caps per-file size, directory/file count and total bytes read;
  - opens each file with O_NOFOLLOW and O_NONBLOCK where the platform provides
    them (POSIX), so a symlink or FIFO put in place after the walk cannot be
    followed or block the read; on Windows it relies on the walk-time lstat and
    the post-open fstat regular-file check instead;
  - inventories shipped compiled and native code (.pyc/.pyo/.pyd, .so/.dll/.exe,
    .jar/.class/.node) instead of dropping it, since compiled code whose source is
    absent hides behaviour from a source-only scan;
  - records every skipped file with a reason, and counts a skipped file against
    coverage unless it is a binary asset, a compiled artifact, or an excluded
    cache directory.
"""

from __future__ import annotations

import collections
import os
import re
import stat
import unicodedata

__all__ = [
    "Artifact", "Package", "build_package", "build_ledger", "discover_skill_packages",
]

# ---------------------------------------------------------------------------
# artifact classification
# ---------------------------------------------------------------------------

SCRIPT_EXT = {".py": "python", ".pyw": "python", ".sh": "shell", ".bash": "shell",
              ".zsh": "shell", ".command": "shell", ".bat": "batch", ".cmd": "batch",
              ".ps1": "powershell", ".js": "javascript", ".mjs": "javascript",
              ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript",
              ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
              ".rb": "ruby", ".pl": "perl"}

# Shipped compiled or native code a text scanner cannot read: Python bytecode,
# native extensions, and platform binaries (incl. JVM .jar/.class and Node .node).
# A .pyc whose .py source is absent, or a bundled .so/.dll, runs the same but is
# invisible to a source-only scan, so these are inventoried and surfaced, never
# dropped. Versioned shared objects (libfoo.so.1) are caught by _SO_VERSIONED.
COMPILED_EXT = {".pyc": "python_bytecode", ".pyo": "python_bytecode",
                ".pyd": "python_extension", ".so": "native_code",
                ".dylib": "native_code", ".dll": "native_code",
                ".exe": "native_code", ".wasm": "native_code",
                ".node": "native_code", ".jar": "native_code",
                ".war": "native_code", ".class": "native_code",
                ".o": "native_code", ".a": "native_code"}
_SO_VERSIONED = re.compile(r"\.so(\.\d+)+$")     # libfoo.so.1 / libfoo.so.1.2.3

DOC_ONLY_MD = {"readme.md", "changelog.md", "contributing.md", "license.md",
               "security.md", "code_of_conduct.md", "notice.md"}

# Instruction-bearing text: markdown, Cursor .mdc rule files, reStructuredText.
INSTRUCTION_EXT = {".md", ".mdc", ".markdown", ".rst"}

# Inert binary assets (icon, font, video): not text, not code, safe to leave out
# of the coverage denominator.
ASSET_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
             ".ttf", ".mp4", ".webp"}
# Not plain text but NOT inert: an SVG can carry <script>, a PDF can embed
# JavaScript, and a nested archive hides a whole subtree the scanner does not
# recurse into. These are surfaced AND lower coverage -- they must not sit
# silently behind a 100% number the way an icon can.
ACTIVE_ASSET_EXT = {".svg", ".pdf"}
NESTED_ARCHIVE_EXT = {".zip", ".gz", ".tar", ".tgz", ".whl", ".bz2", ".xz",
                      ".rar", ".7z"}

# Build caches and VCS metadata that are not part of the shipped skill and are
# coverage-benign. __pycache__ is deliberately absent: shipped .pyc is inventoried
# via COMPILED_EXT, not silently pruned with the directory.
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", ".mypy_cache",
             ".pytest_cache", ".idea", ".tox", ".ruff_cache"}
# Bundled build output / vendored dependencies. Pruned like SKIP_DIRS (walking a
# node_modules tree is pointless and costly), but NOT coverage-benign: a skill
# that ships build/, dist/ or node_modules/ is itself a signal, and code an agent
# could run may hide there, so these are surfaced and lower coverage.
BUNDLED_DIRS = {"node_modules", "dist", "build", "vendor", "target"}

ROOT_CONFIG = {"hooks.json": "hooks_config", ".mcp.json": "mcp_config",
               "plugin.json": "plugin_manifest", ".app.json": "app_manifest",
               "plugin.lock.json": "plugin_lock"}

# Agent / hook / MCP configuration that is not a root manifest but wires up command
# execution or MCP servers -- the highest-value surface for a later check, so it is
# classified rather than left as `other`. (Basename match; the nested-vs-root
# distinction is the checks stage's job.)
AGENT_CONFIG_FILES = {
    "settings.json", "settings.local.json",          # Claude Code / editor settings (hooks)
    "mcp.json", "claude_desktop_config.json",         # MCP server wiring
    "config.toml",                                    # Codex config
}

# Files whose mere presence in a skill is a signal: shipping a private key or a
# credentials file is not normal. Classified so a later check can flag them.
SECRET_FILES = {".env", ".netrc", ".npmrc", ".pypirc", "credentials",
                "credentials.json", ".credentials.json", "secrets.json",
                "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
SECRET_EXT = {".pem", ".key", ".pfx", ".p12", ".keystore"}

# Agent identity / memory files. An agent loads these as standing instructions,
# and a skill that writes to one (e.g. ~/.claude/CLAUDE.md) persists after the
# skill is removed, so they are tagged as a distinct class rather than folded in
# with ordinary instruction files, letting a later check target them directly.
IDENTITY_FILES = {
    "claude.md", "agents.md", "agent.md", "gemini.md", "soul.md", "memory.md",
    "identity.md", ".cursorrules", ".windsurfrules", ".clinerules", ".roorules",
    "copilot-instructions.md",
}

# ---------------------------------------------------------------------------
# Read limits. A skill package is small (a large SKILL.md is ~125 KB). Past these
# caps a file, or the package, is skipped and recorded rather than read into
# memory. Per-file memory is bounded by MAX_FILE_BYTES; total bytes read across
# the walk is bounded by AGGREGATE_MAX_BYTES.
# ---------------------------------------------------------------------------

MAX_FILE_BYTES = 1_048_576              # 1 MiB per file
MAX_FILES = 5000                        # walk stops past this many files
MAX_DIRS = 5000                         # walk visits at most this many directories
AGGREGATE_MAX_BYTES = 256 * 1024 * 1024  # 256 MiB total read into memory
MAX_DISCOVERY_DIRS = 20000              # --scan-known-skills visits at most this many dirs
MAX_DISCOVERY_ENTRIES = 100000          # and inspects at most this many directory entries


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------

def posix(p: str) -> str:
    # Translate only the OS separator. On POSIX a backslash is a legal filename
    # byte; rewriting it would collapse "a\b.py" onto a real "a/b.py" -- a ledger
    # key collision that can hide a refused symlink-escape behind 100% coverage.
    return p.replace(os.sep, "/")


def _relpath(abspath: str, root: str) -> str:
    """Package-relative POSIX path, NFC-normalised. macOS returns filenames
    NFD-decomposed and Linux stores them NFC; without this, the same logical
    filename produces a different ledger key on each OS."""
    return unicodedata.normalize("NFC", posix(os.path.relpath(abspath, root)))


def _portable_name(name: str) -> str:
    return unicodedata.normalize("NFC", name).rstrip(" .").casefold()


def install_identity(package_root: str) -> str:
    """Stable identity for an install, keyed on the package's CANONICAL path.

    realpath() resolves symlink aliases, so two symlinked install locations that
    point at the same target share one identity -- matching how discovery dedups by
    realpath. Deliberately NOT a content hash: a corpus has byte-identical SKILL.md
    copies, and a content key would collapse them, destroying alert state in a
    consumer that tracks findings per install.
    """
    real = os.path.realpath(package_root)
    real = posix(os.path.abspath(real))
    if len(real) > 1 and real[1] == ":":
        real = real[0].lower() + real[1:]
    real = real.rstrip("/")
    if len(real) == 2 and real[1] == ":":   # drive root: "c:" -> "c:/"
        real += "/"
    return real or "/"                       # posix root survived the strip


def read_bytes(path: str, limit: int | None = None, *, expected_stat=None):
    """Return (raw bytes, failure, bytes read) without exceeding either byte limit.

    O_NOFOLLOW/O_NONBLOCK and fstat reject path swaps and special files where the
    platform supports them. An expected walk-time stat identity also rejects a
    regular-file replacement; the post-read size check catches a growing file.
    """
    limit = MAX_FILE_BYTES if limit is None else max(0, min(limit, MAX_FILE_BYTES))
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        return None, "unreadable:%s" % type(exc).__name__, 0
    with os.fdopen(fd, "rb", closefd=True) as fh:
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None, "not_regular_file", 0
            if expected_stat is not None and (
                    stat.S_IFMT(st.st_mode) != stat.S_IFMT(expected_stat.st_mode)
                    or (st.st_dev, st.st_ino) != (expected_stat.st_dev, expected_stat.st_ino)):
                return None, "file_changed", 0
            if st.st_size > MAX_FILE_BYTES:
                return None, "too_large", 0
            if st.st_size > limit:
                return None, "total_budget_exhausted", 0
            raw = fh.read(limit)
            final_size = os.fstat(fd).st_size
        except OSError as exc:
            return None, "unreadable:%s" % type(exc).__name__, 0
    nbytes = len(raw)
    if final_size > MAX_FILE_BYTES:
        return None, "too_large", nbytes
    if final_size > limit:
        return None, "total_budget_exhausted", nbytes
    return raw, None, nbytes


def _decode(raw: bytes):
    """Raw bytes -> (text|None, exception_reason|None). A buffer with a NUL byte is
    treated as binary; a buffer that decodes as neither UTF-8 nor CP-1252 is
    undecodable. Pure (no I/O), so the decode decision is testable off a byte string."""
    if b"\x00" in raw:
        return None, "binary_content"
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(enc), None
        except UnicodeDecodeError:
            continue
    return None, "undecodable_text"


# ---------------------------------------------------------------------------
# package graph
# ---------------------------------------------------------------------------

class Artifact:
    def __init__(self, rel, role, kind):
        self.rel = rel
        self.role = role
        self.kind = kind
        self.text = None
        self.exception = None
        # Retained for byte-level checks; None means no successful bounded read.
        self.raw = None


class Package:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.identity = install_identity(root)
        self.name = os.path.basename(self.root.rstrip("\\/"))
        self.artifacts = []
        self.ledger_exceptions = []

    def add(self, art):
        self.artifacts.append(art)


def _skip(pkg, reason, rel, target=None):
    entry = {"outcome": "skipped", "phase": "static", "reasonCode": reason, "path": rel}
    if target is not None:
        # A refused symlink's target: symlink->/etc/shadow and symlink->./foo must
        # not look identical in the ledger. Attacker-controlled, so a consumer that
        # prints it must escape it (the CLI routes paths through _display).
        entry["target"] = target
    pkg.ledger_exceptions.append(entry)


def _reject_special(st_mode):
    """Reason to skip a directory entry that is not a plain file, or None to read
    it. A symlink is not followed (a SKILL.md symlinked to /etc/passwd would
    otherwise be read from outside the package); a FIFO, device or socket is not
    opened (a read() on a FIFO blocks forever)."""
    if stat.S_ISLNK(st_mode):
        return "symlink"
    if not stat.S_ISREG(st_mode):
        return "not_regular_file"
    return None


def _is_reparse(path):
    """True for a junction or directory symlink. os.walk(followlinks=False) skips a
    POSIX dir symlink but STILL descends an NTFS junction (os.path.islink is False for
    one), so a package could escape its own directory via `mklink /J` without admin.
    Prune these. os.path.isjunction (3.12+) is required for the junction case; the
    package floor is 3.12.4 (also for CVE-2024-4032 in ipaddress, see pyproject)."""
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction and isjunction(path))


def _classify(filename: str):
    """Map a filename to (kind, role) by name and extension only. No content read."""
    low = filename.lower()
    ext = os.path.splitext(filename)[1].lower()
    if low == "skill.md":
        return "skill_manifest", "instruction_primary"
    if low in IDENTITY_FILES:
        return "agent_identity", "identity"
    if low in ROOT_CONFIG:
        return ROOT_CONFIG[low], "root_config"
    if low in AGENT_CONFIG_FILES:
        return "agent_config", "config"
    if low in SECRET_FILES or ext in SECRET_EXT:
        return "secret_material", "secret"
    if ext in INSTRUCTION_EXT:
        if low in DOC_ONLY_MD:
            return "doc", "documentation"
        return "instruction", "instruction_secondary"
    if ext in SCRIPT_EXT:
        return "script_" + SCRIPT_EXT[ext], "script"
    if ext in COMPILED_EXT or _SO_VERSIONED.search(low):
        return COMPILED_EXT.get(ext, "native_code"), "compiled"
    if low in ("package.json", "pyproject.toml") or (
            low.endswith(".txt") and "requirements" in low):
        return "dep_manifest", "dependency_manifest"
    if ext in NESTED_ARCHIVE_EXT:
        return "nested_archive", "opaque"
    if ext in ACTIVE_ASSET_EXT:
        return "active_asset", "opaque"
    if ext in ASSET_EXT:
        return "asset", "asset"
    return "other", "other"


def _classify_shebang(text: str):
    first = text.split("\n", 1)[0][:256]
    match = re.match(
        r"^#!\s*(?:\S*/env(?:\s+-S)?\s+|\S*/)?"
        r"(python(?:\d+(?:\.\d+)*)?|bash|sh|zsh|dash|ksh|fish|"
        r"pwsh|powershell|node|deno|bun|ruby|perl)(?:\s|$)",
        first,
        re.I,
    )
    if not match:
        return None
    name = match.group(1).lower()
    if name.startswith("python"):
        language = "python"
    elif name in {"bash", "sh", "zsh", "dash", "ksh", "fish"}:
        language = "shell"
    elif name in {"pwsh", "powershell"}:
        language = "powershell"
    elif name in {"node", "deno", "bun"}:
        language = "javascript"
    else:
        language = name
    return "script_" + language, "script"


def build_package(root: str) -> Package:
    """Walk the package and inventory every artifact. No parsing, no execution."""
    pkg = Package(root)
    walk_errors = []

    seen = 0
    seen_dirs = 0
    pending = [pkg.root]
    total_read = 0
    truncated = False
    dirs_truncated = False
    while pending:
        dirpath = pending.pop()
        seen_dirs += 1
        entries = []
        files_here = dirs_here = 0
        try:
            with os.scandir(dirpath) as iterator:
                for entry in iterator:
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        is_dir = False
                    files_here += not is_dir
                    dirs_here += is_dir
                    if seen + files_here > MAX_FILES:
                        truncated = True
                        break
                    if seen_dirs + len(pending) + dirs_here > MAX_DIRS:
                        dirs_truncated = True
                        break
                    entries.append((entry.name, is_dir))
        except OSError as exc:
            target = getattr(exc, "filename", None) or dirpath
            walk_errors.append(("walk_error:%s" % type(exc).__name__,
                                _relpath(target, pkg.root)))
            continue
        if truncated or dirs_truncated:
            break

        dirnames = [name for name, is_dir in entries if is_dir]
        filenames = [name for name, is_dir in entries if not is_dir]
        groups = collections.defaultdict(list)
        for name in dirnames + filenames:
            groups[_portable_name(name)].append(name)
        collisions = {
            name for group in groups.values() if len(group) > 1 for name in group
        }
        kept = []
        for d in dirnames:
            dp = os.path.join(dirpath, d)
            drel = _relpath(dp, pkg.root)
            if d in collisions:
                _skip(pkg, "portable_path_collision", drel)
            elif d in SKIP_DIRS:
                _skip(pkg, "excluded_dir", drel)
            elif d in BUNDLED_DIRS:
                _skip(pkg, "bundled_dir", drel)          # pruned, but lowers coverage
            elif _is_reparse(dp):
                _skip(pkg, "reparse_point", drel)
            else:
                kept.append(d)
        pending.extend(os.path.join(dirpath, name) for name in reversed(sorted(kept)))
        for fn in sorted(filenames):
            seen += 1
            ap = os.path.join(dirpath, fn)
            rel = _relpath(ap, pkg.root)
            if fn in collisions:
                kind, role = _classify(fn)
                art = Artifact(rel, role, kind)
                art.exception = "portable_path_collision"
                _skip(pkg, "portable_path_collision", rel)
                pkg.add(art)
                continue
            try:
                st = os.lstat(ap)
            except OSError as exc:
                _skip(pkg, "unreadable:%s" % type(exc).__name__, rel)
                continue
            reject = _reject_special(st.st_mode)
            if reject:
                target = None
                if reject == "symlink":
                    try:
                        target = os.readlink(ap)
                    except OSError:
                        pass
                _skip(pkg, reject, rel, target)
                continue
            kind, role = _classify(fn)
            art = Artifact(rel, role, kind)
            # One read serves decoding and byte checks and is charged to the hard cap.
            read_reason = None
            remaining = max(0, AGGREGATE_MAX_BYTES - total_read)
            budget_hit = remaining == 0
            if not budget_hit:
                art.raw, read_reason, nbytes = read_bytes(
                    ap, remaining, expected_stat=st,
                )
                total_read += nbytes
            if budget_hit:
                art.exception = "total_budget_exhausted"
                _skip(pkg, "total_budget_exhausted", rel)
            elif read_reason is not None:
                art.exception = read_reason
                _skip(pkg, read_reason, rel)
            elif kind == "asset":
                art.exception = "binary_content"
                _skip(pkg, "binary_content", rel)
            elif role == "opaque":
                # Active content (SVG/PDF) or a nested archive: unreviewable, so it
                # is surfaced and counts against coverage, not excused like an icon.
                art.exception = "unreviewable_content"
                _skip(pkg, "unreviewable_content", rel)
            elif role == "compiled":
                art.exception = "shipped_compiled"
                _skip(pkg, "shipped_compiled", rel)
            else:
                art.text, art.exception = _decode(art.raw)
                if art.exception:
                    _skip(pkg, art.exception, rel)
                elif art.kind == "other":
                    classified = _classify_shebang(art.text)
                    if classified:
                        art.kind, art.role = classified
            pkg.add(art)

    if truncated:
        _skip(pkg, "walk_truncated", "(more than %d files)" % MAX_FILES)
    if dirs_truncated:
        _skip(pkg, "walk_truncated", "(more than %d directories)" % MAX_DIRS)
    for reason, rel in walk_errors:
        _skip(pkg, reason, rel)
    return pkg


# ---------------------------------------------------------------------------
# discovery -- the known locations agents load skills from
# ---------------------------------------------------------------------------

# The directories the widely used agents load skills from, per their own docs.
# `~` entries are user-level; the bare entries are project-level (relative to the
# working directory). Mirrors mcp-xray's KnownMCPConfigs / --scan-known-configs:
# single-target by default, this whole set only when the caller opts in.
KNOWN_SKILL_ROOTS = (
    "~/.claude/skills", "~/.claude/plugins",              # Claude Code + plugins
    "~/.config/opencode/skills", ".opencode/skills",      # OpenCode
    "~/.cursor/skills", ".cursor/skills",                 # Cursor
    "~/.gemini/skills", ".gemini/skills",                 # Gemini CLI
    "~/.codex/skills", ".codex/skills",                   # Codex
    "~/.copilot/skills", ".github/skills",                # Copilot
    "~/.agents/skills", ".agents/skills",                 # interoperable alias
    ".claude/skills",                                     # project Claude
)

# A directory is a package ROOT if it holds a SKILL.md or any of these markers. A
# plugin keeps its exec surface (hooks / MCP / plugin manifest) at the root with
# its skills nested under skills/*/, so discovery must return the root -- not the
# leaf SKILL.md dir -- or build_package never sees the root's .mcp.json/hooks.json.
_PKG_MARKERS = {".claude-plugin", ".codex-plugin",          # plugin root dirs
                "plugin.json", ".mcp.json", "hooks.json"}    # plugin root files


class _DiscoveryResult(list):
    """List-compatible discovered paths plus fail-visible traversal gaps."""

    def __init__(self, paths=(), ledger_exceptions=()):
        super().__init__(paths)
        self.ledger_exceptions = list(ledger_exceptions)


def _discovery_truncated(exceptions, unit, limit):
    exceptions.append({
        "outcome": "skipped", "phase": "static", "reasonCode": "walk_truncated",
        "path": "(more than %d discovery %s)" % (limit, unit),
    })


def _discovery_error(exceptions, exc, path):
    exceptions.append({
        "outcome": "skipped", "phase": "static",
        "reasonCode": "walk_error:%s" % type(exc).__name__,
        "path": posix(os.path.abspath(path)),
    })


def discover_skill_packages(roots=None):
    """Return the skill package roots found under the known skill roots. A root is a
    directory holding a SKILL.md or a plugin marker (_PKG_MARKERS); once found it is
    recorded and its subtree pruned, so a plugin is returned as its root -- not the
    leaf skills/*/ dir -- and its nested skills are covered by build_package walking
    the whole root (which also sees the root's hooks.json/.mcp.json). A symlinked
    ROOT (a dotfiles setup, ~/.claude/skills/x -> ~/dotfiles/x) is followed, nested
    symlinks are NOT, hard directory and entry budgets stop a symlink pointing at
    "/" or one very wide directory from exhausting the scan, and a root reachable
    more than once is returned once. The return value is a list subclass whose
    ``ledger_exceptions`` uses the package-ledger shape when discovery truncates."""
    if roots is None:
        roots = KNOWN_SKILL_ROOTS
    found = {}
    seen = set()
    exceptions = []
    scanned_dirs = 0
    seen_entries = 0
    truncated = False
    for root in roots:
        base = os.path.abspath(os.path.expanduser(root))
        try:
            root_stat = os.stat(base)
        except FileNotFoundError:
            continue
        except OSError as exc:
            _discovery_error(exceptions, exc, base)
            continue
        if not stat.S_ISDIR(root_stat.st_mode):
            continue
        # Stream entries instead of os.walk(), which materializes every name in a
        # wide directory before yielding and therefore cannot enforce this boundary.
        pending = [(base, True)]
        while pending:
            dirpath, allow_root_links = pending.pop()
            real = os.path.realpath(dirpath)
            if real in seen:                         # loop / alias already walked
                continue
            if scanned_dirs >= MAX_DISCOVERY_DIRS:
                _discovery_truncated(exceptions, "directories", MAX_DISCOVERY_DIRS)
                truncated = True
                break
            seen.add(real)
            scanned_dirs += 1
            children = []
            marker = False
            entry_limit_hit = False
            try:
                with os.scandir(dirpath) as entries:
                    for entry in entries:
                        seen_entries += 1
                        if seen_entries > MAX_DISCOVERY_ENTRIES:
                            entry_limit_hit = True
                            break
                        low = entry.name.lower()
                        try:
                            is_link = entry.is_symlink()
                            link_dir = is_link and entry.is_dir()
                            is_dir = entry.is_dir(follow_symlinks=False)
                            reparse = is_dir and _is_reparse(entry.path)
                        except OSError as exc:
                            _discovery_error(exceptions, exc, entry.path)
                            continue
                        if link_dir:
                            if allow_root_links:       # direct dotfiles package link
                                children.append((entry.path, False))
                            continue                  # never follow a nested directory link
                        if not is_dir:
                            marker |= low == "skill.md" or low in _PKG_MARKERS
                            continue
                        if (entry.name in SKIP_DIRS or entry.name in BUNDLED_DIRS
                                or reparse):
                            continue
                        marker |= low == "skill.md" or low in _PKG_MARKERS
                        children.append((entry.path, False))
            except OSError as exc:
                _discovery_error(exceptions, exc, dirpath)
                continue
            if entry_limit_hit:
                _discovery_truncated(
                    exceptions, "entries", MAX_DISCOVERY_ENTRIES,
                )
                truncated = True
                break
            if marker:
                found[real] = dirpath
                continue                  # this package owns its nested skill directories
            pending.extend(reversed(sorted(children)))
        if truncated:
            break
    return _DiscoveryResult((found[k] for k in sorted(found)), exceptions)


# ---------------------------------------------------------------------------
# coverage ledger
# ---------------------------------------------------------------------------

# Directory-level skips that are recorded but do not lower coverage: an excluded
# cache directory is not part of the skill.
_BENIGN_LEDGER = {"excluded_dir"}


def _role_counts(artifacts):
    return dict(sorted(collections.Counter(a.role for a in artifacts).items()))


def build_ledger(pkg: Package) -> dict:
    """Return the coverage ledger: files seen, files analysed, and why the rest
    were not read.

    An inert binary asset (icon, font) and a compiled/native artifact (.pyc, .so)
    are not text, so both leave the text-coverage denominator and do not lower
    coveragePercent -- but the compiled ones are ALSO listed in shippedCompiledCode
    so 100% coverage can never hide shipped, unreviewable executable code. Active or
    opaque content (SVG, PDF, a nested archive) is NOT excused: it is listed in
    opaqueContent AND counts against coverage, because it can hide a payload an icon
    cannot. Shipped secrets and agent/MCP config are surfaced in secretMaterial and
    agentConfig. Every other unread file -- a NUL-carrying script, a size or budget
    skip, an unreadable file, a bundled build dir, and the directory-level skips
    (symlink, junction, walk error, truncation) -- counts against coverage.
    """
    artifacts = pkg.artifacts
    artifact_exceptions = collections.Counter(
        (artifact.rel, artifact.exception)
        for artifact in artifacts if artifact.exception is not None
    )
    pre_skips = []
    for entry in pkg.ledger_exceptions:
        key = entry["path"], entry["reasonCode"]
        if artifact_exceptions[key]:
            artifact_exceptions[key] -= 1
        elif entry["reasonCode"] not in _BENIGN_LEDGER:
            pre_skips.append(entry)

    analyzed = sum(1 for a in artifacts if a.exception is None)
    compiled = sorted(a.rel for a in artifacts if a.role == "compiled")
    identity = sorted(a.rel for a in artifacts if a.role == "identity")
    opaque = sorted(a.rel for a in artifacts if a.role == "opaque")
    secrets = sorted(a.rel for a in artifacts if a.role == "secret")
    configs = sorted(a.rel for a in artifacts if a.role in ("config", "root_config"))
    not_inspectable = sum(
        (a.kind == "asset" and a.exception == "binary_content")
        or (a.role == "compiled" and a.exception == "shipped_compiled")
        for a in artifacts
    )
    failed = (sum(
        a.exception is not None
        and not (
            (a.kind == "asset" and a.exception == "binary_content")
            or (a.role == "compiled" and a.exception == "shipped_compiled")
        )
        for a in artifacts
    ) + len(pre_skips))
    seen = analyzed + not_inspectable + failed
    denom = analyzed + failed
    return {
        "artifactsSeen": seen,
        "artifactsAnalyzed": analyzed,
        "artifactsSkipped": not_inspectable + failed,
        "artifactsNotInspectable": not_inspectable,
        "artifactsFailedRead": failed,
        "shippedCompiledCode": compiled,
        "agentIdentityFiles": identity,
        "opaqueContent": opaque,
        "secretMaterial": secrets,
        "agentConfig": configs,
        "inspectableDenominator": denom,
        # An all-binary or empty package has nothing to read, so coverage is
        # 100%, not 0%.
        "coveragePercent": round(100.0 * analyzed / denom, 2) if denom else 100.0,
        "byRole": _role_counts(artifacts),
        "exceptions": sorted(pkg.ledger_exceptions,
                             key=lambda e: (e["path"], e["reasonCode"])),
    }
