"""Read a skill package directory into a file inventory and a coverage ledger.

Walks the package, decodes each text file, classifies every file by role, and
records every file it does not read. It does not run anything and does not read
any file outside the package root. It does not parse file contents (frontmatter,
markdown, shell, Python); classification is by name and extension only. Standard
library only, no network.

The package may be malicious, so the walker:
  - does not follow a symlink or an NTFS junction out of the directory;
  - does not open a FIFO, device or socket;
  - caps per-file size, file count and total bytes read;
  - opens each file with O_NOFOLLOW and O_NONBLOCK, so a symlink or FIFO put in
    place after the walk cannot be followed or block the read;
  - inventories shipped compiled code (.pyc/.pyo/.pyd) instead of dropping it
    with its __pycache__ directory, since compiled code whose source is absent
    hides behaviour from a source-only scan;
  - records every skipped file with a reason, and counts a skipped file against
    coverage unless it is a binary asset, a compiled artifact, or an excluded
    cache directory.
"""

from __future__ import annotations

import os
import stat
import unicodedata

__all__ = [
    "Artifact", "Package", "build_package", "build_ledger", "discover_skill_packages",
]

# ---------------------------------------------------------------------------
# artifact classification
# ---------------------------------------------------------------------------

SCRIPT_EXT = {".py": "python", ".sh": "shell", ".bash": "shell", ".zsh": "shell",
              ".ps1": "powershell", ".js": "javascript", ".ts": "typescript",
              ".rb": "ruby", ".pl": "perl"}

# Shipped compiled Python: bytecode a text scanner cannot read. A .pyc whose .py
# source is absent (or does not match it) runs the same but is invisible to a
# source-only scan, so these are inventoried and surfaced, never dropped. Whether
# to raise a finding is the checks stage's call, not ingest's.
COMPILED_EXT = {".pyc": "python_bytecode", ".pyo": "python_bytecode",
                ".pyd": "python_extension"}

DOC_ONLY_MD = {"readme.md", "changelog.md", "contributing.md", "license.md",
               "security.md", "code_of_conduct.md", "notice.md"}

BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip",
              ".gz", ".tar", ".whl", ".woff", ".woff2", ".ttf", ".mp4", ".webp"}

# Build caches and VCS metadata that are not part of the shipped skill. Note that
# __pycache__ is deliberately absent: shipped .pyc bytecode is inventoried via
# COMPILED_EXT, not silently pruned with the directory.
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", ".mypy_cache",
             ".pytest_cache", "dist", "build", ".idea", ".tox"}

ROOT_CONFIG = {"hooks.json": "hooks_config", ".mcp.json": "mcp_config",
               "plugin.json": "plugin_manifest", ".app.json": "app_manifest",
               "plugin.lock.json": "plugin_lock"}

# Agent identity / memory files. An agent loads these as standing instructions,
# and a skill that writes to one (e.g. ~/.claude/CLAUDE.md) persists after the
# skill is removed, so they are tagged as a distinct class rather than folded in
# with ordinary instruction files, letting a later check target them directly.
IDENTITY_FILES = {
    "claude.md", "agents.md", "gemini.md", "soul.md", "memory.md",
    "identity.md", ".cursorrules", "copilot-instructions.md",
}

# ---------------------------------------------------------------------------
# Read limits. A skill package is small (a large SKILL.md is ~125 KB). Past these
# caps a file, or the package, is skipped and recorded rather than read into
# memory. Per-file memory is bounded by MAX_FILE_BYTES; total bytes read across
# the walk is bounded by AGGREGATE_MAX_BYTES.
# ---------------------------------------------------------------------------

MAX_FILE_BYTES = 1_048_576              # 1 MiB per file
MAX_FILES = 5000                        # walk stops past this many files
AGGREGATE_MAX_BYTES = 256 * 1024 * 1024  # 256 MiB total read into memory


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------

def posix(p: str) -> str:
    return p.replace("\\", "/")


def _relpath(abspath: str, root: str) -> str:
    """Package-relative POSIX path, NFC-normalised. macOS returns filenames
    NFD-decomposed and Linux stores them NFC; without this, the same logical
    filename produces a different ledger key on each OS."""
    return unicodedata.normalize("NFC", posix(os.path.relpath(abspath, root)))


def install_identity(package_root: str) -> str:
    """Injective over INSTALL LOCATION, not content.

    Deliberately NOT a content hash: a corpus contains byte-identical SKILL.md
    copies, and a content-keyed identity would collapse them onto one value,
    destroying alert state in any consumer that tracks findings per install.
    """
    real = os.path.realpath(package_root)
    real = posix(os.path.abspath(real))
    if len(real) > 1 and real[1] == ":":
        real = real[0].lower() + real[1:]
    real = real.rstrip("/")
    if len(real) == 2 and real[1] == ":":   # drive root: "c:" -> "c:/"
        real += "/"
    return real or "/"                       # posix root survived the strip


def read_text(path: str):
    """Return (text, exception_reason, bytes_read). Never raises, never blocks.

    Opens with O_NOFOLLOW and O_NONBLOCK so that if the entry was replaced by a
    symlink or a FIFO between the walk's lstat and this open, the open fails or
    fstat rejects it rather than reading outside the package or waiting forever.
    bytes_read is the number of bytes actually read from this fd, so the caller's
    memory budget is charged for what was read, not a pre-read lstat size that a
    TOCTOU swap could understate. The read itself is bounded to MAX_FILE_BYTES, so
    a file that grows after fstat cannot be read unbounded into memory. A buffer
    containing a NUL byte is treated as binary; a buffer that decodes as neither
    UTF-8 nor CP-1252 is undecodable.
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXT:
        return None, "binary_content", 0
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
            if st.st_size > MAX_FILE_BYTES:
                return None, "too_large", 0
            # Bound the read itself: a file that grew after fstat cannot be read
            # unbounded into memory. Read one byte past the cap to detect overflow.
            raw = fh.read(MAX_FILE_BYTES + 1)
        except OSError as exc:
            return None, "unreadable:%s" % type(exc).__name__, 0
    # Bytes were read, so every outcome below charges the budget for len(raw),
    # decoded or not: a package of undecodable or NUL-carrying files cannot read
    # past the aggregate budget by simply failing to decode.
    nbytes = len(raw)
    if nbytes > MAX_FILE_BYTES:
        return None, "too_large", nbytes
    if b"\x00" in raw:
        return None, "binary_content", nbytes
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(enc), None, nbytes
        except UnicodeDecodeError:
            continue
    return None, "undecodable_text", nbytes


# ---------------------------------------------------------------------------
# package graph
# ---------------------------------------------------------------------------

class Artifact:
    def __init__(self, rel, abspath, role, kind):
        self.rel = rel
        self.abs = abspath
        self.role = role
        self.kind = kind
        self.text = None
        self.exception = None


class Package:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.identity = install_identity(root)
        self.name = os.path.basename(self.root.rstrip("\\/"))
        self.artifacts = []
        self.ledger_exceptions = []

    def add(self, art):
        self.artifacts.append(art)


def _skip(pkg, reason, rel):
    pkg.ledger_exceptions.append(
        {"outcome": "skipped", "phase": "static", "reasonCode": reason, "path": rel})


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
    Prune these. os.path.isjunction is required for the junction case and is why the
    package floor is Python 3.12."""
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
    if ext == ".md":
        if low in DOC_ONLY_MD:
            return "doc", "documentation"
        return "instruction", "instruction_secondary"
    if ext in SCRIPT_EXT:
        return "script_" + SCRIPT_EXT[ext], "script"
    if ext in COMPILED_EXT:
        return COMPILED_EXT[ext], "compiled"
    if low in ("requirements.txt", "package.json", "pyproject.toml", "setup.py"):
        return "dep_manifest", "dependency_manifest"
    if ext in BINARY_EXT:
        return "asset", "asset"
    return "other", "other"


def build_package(root: str) -> Package:
    """Walk the package and inventory every artifact. No parsing, no execution."""
    pkg = Package(root)
    walk_errors = []

    def _on_error(exc):
        # os.walk hides an unreadable directory by default; record it so a
        # subtree we could not enter is visible rather than silently absent.
        target = getattr(exc, "filename", None) or pkg.root
        walk_errors.append(("walk_error:%s" % type(exc).__name__,
                            _relpath(target, pkg.root)))

    seen = 0
    total_read = 0
    truncated = False
    for dirpath, dirnames, filenames in os.walk(pkg.root, onerror=_on_error):
        kept = []
        for d in dirnames:
            dp = os.path.join(dirpath, d)
            drel = _relpath(dp, pkg.root)
            if d in SKIP_DIRS:
                _skip(pkg, "excluded_dir", drel)
            elif _is_reparse(dp):
                _skip(pkg, "reparse_point", drel)
            else:
                kept.append(d)
        dirnames[:] = sorted(kept)
        for fn in sorted(filenames):
            if seen >= MAX_FILES:
                truncated = True
                break
            seen += 1
            ap = os.path.join(dirpath, fn)
            rel = _relpath(ap, pkg.root)
            try:
                st = os.lstat(ap)
            except OSError as exc:
                _skip(pkg, "unreadable:%s" % type(exc).__name__, rel)
                continue
            reject = _reject_special(st.st_mode)
            if reject:
                _skip(pkg, reject, rel)
                continue
            kind, role = _classify(fn)
            art = Artifact(rel, ap, role, kind)
            if kind == "asset":
                art.exception = "binary_content"
                _skip(pkg, "binary_content", rel)
            elif role == "compiled":
                art.exception = "shipped_bytecode"
                _skip(pkg, "shipped_bytecode", rel)
            elif total_read >= AGGREGATE_MAX_BYTES:
                art.exception = "total_budget_exhausted"
                _skip(pkg, "total_budget_exhausted", rel)
            else:
                art.text, art.exception, nbytes = read_text(ap)
                total_read += nbytes   # charge for bytes read, decoded or not
                if art.exception:
                    _skip(pkg, art.exception, rel)
            pkg.add(art)
        if truncated:
            break

    if truncated:
        _skip(pkg, "walk_truncated", "(more than %d files)" % MAX_FILES)
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


def discover_skill_packages(roots=None):
    """Return the skill package directories (each holding a SKILL.md) found under
    the known skill roots. Roots are searched recursively, so nested and plugin
    layouts are found, and a package reachable from more than one root (an alias
    or a symlink target) is returned once."""
    if roots is None:
        roots = KNOWN_SKILL_ROOTS
    found = {}
    for root in roots:
        base = os.path.abspath(os.path.expanduser(root))
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                                 and not _is_reparse(os.path.join(dirpath, d)))
            if "SKILL.md" in filenames:
                found[os.path.realpath(dirpath)] = dirpath
    return [found[k] for k in sorted(found)]


# ---------------------------------------------------------------------------
# coverage ledger
# ---------------------------------------------------------------------------

# Directory-level skips that are recorded but do not lower coverage: an excluded
# cache directory is not part of the skill.
_BENIGN_LEDGER = {"excluded_dir"}


def _role_counts(artifacts):
    return {r: sum(1 for a in artifacts if a.role == r)
            for r in sorted({a.role for a in artifacts})}


def build_ledger(pkg: Package) -> dict:
    """Return the coverage ledger: files seen, files analysed, and why the rest
    were not read.

    Neither a binary asset (icon, font) nor a compiled artifact (.pyc) is text,
    so both leave the text-coverage denominator and do not lower coveragePercent.
    Compiled artifacts are ALSO listed on their own in shippedBytecode, so a 100%
    text coverage can never hide shipped, unreviewable executable code. Every
    other unread file -- a NUL-carrying script, a size or budget skip, an
    unreadable file, and the directory-level skips (symlink, junction, walk
    error, count truncation) -- is counted against coverage.
    """
    artifacts = pkg.artifacts
    art_paths = {a.rel for a in artifacts}
    pre_skips = [e for e in pkg.ledger_exceptions
                 if e["path"] not in art_paths and e["reasonCode"] not in _BENIGN_LEDGER]

    analyzed = sum(1 for a in artifacts if a.exception is None)
    compiled = sorted(a.rel for a in artifacts if a.role == "compiled")
    identity = sorted(a.rel for a in artifacts if a.role == "identity")
    not_inspectable = sum(1 for a in artifacts if a.kind == "asset") + len(compiled)
    failed = (sum(1 for a in artifacts
                  if a.exception is not None and a.kind != "asset" and a.role != "compiled")
              + len(pre_skips))
    seen = analyzed + not_inspectable + failed
    denom = analyzed + failed
    return {
        "artifactsSeen": seen,
        "artifactsAnalyzed": analyzed,
        "artifactsSkipped": not_inspectable + failed,
        "artifactsNotInspectable": not_inspectable,
        "artifactsFailedRead": failed,
        "shippedBytecode": compiled,
        "agentIdentityFiles": identity,
        "inspectableDenominator": denom,
        # An all-binary or empty package has nothing to read, so coverage is
        # 100%, not 0%.
        "coveragePercent": round(100.0 * analyzed / denom, 2) if denom else 100.0,
        "byRole": _role_counts(artifacts),
        "exceptions": sorted(pkg.ledger_exceptions,
                             key=lambda e: (e["path"], e["reasonCode"])),
    }
