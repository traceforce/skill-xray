"""Turn a scan target into a local directory to walk.

A target may be a directory, a single file, a .zip archive, an https URL, or a
git repository (an https .git URL). Directories and files are used or copied in
place; archives, URLs and git repos are materialised into a temporary directory
the caller removes via the context manager. A download, a zip bomb, and a
zip-slip archive are each bounded and cannot write outside the extract dir.
Failures fail closed.

Two residuals are accepted and stated here rather than hidden:
  - git clone is bounded by a timeout and a post-clone size check, so a fast
    internal mirror could write past the limit briefly before the check runs;
  - a URL download connects to the exact IP that was validated, so it is not
    subject to DNS rebinding, but git clone shells out to the git binary, which
    resolves the host itself, so the git adapter can still be rebound.

Only the URL and git adapters touch the network, and both refuse a host that
resolves to a non-public address at check time.
"""

from __future__ import annotations

import collections
import contextlib
import http.client
import ipaddress
import os
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import zipfile

__all__ = ["resolved_input", "Resolved", "IngestLimitExceededError", "UnsafeInputError"]

# Aggregate limits, mirroring mcp-xray / SkillSpector ingest caps. A breach fails
# closed. They bound the download, the total uncompressed size of an archive, and
# the on-disk size of a clone -- not any single file, which the walker caps.
INGEST_MAX_BYTES = 100 * 1024 * 1024        # 100 MiB
INGEST_MAX_ZIP_MEMBERS = 10_000
URL_TIMEOUT_SECONDS = 30                     # per-operation socket timeout
URL_DEADLINE_SECONDS = 120                   # wall-clock cap on the whole download
GIT_TIMEOUT_SECONDS = 120
_CHUNK = 65536
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
# Single-file inputs that are archives skill-xray does not extract. Copied in as
# one opaque asset they would report 100% coverage with contents never inspected,
# so they are refused (zip is handled separately). tarfile.is_tarfile catches
# tar/tar.gz/tar.bz2/tar.xz by content; the extension list catches the rest.
_ARCHIVE_EXTS = (".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz",
                 ".rar", ".7z", ".lz", ".lzma", ".zst")


class IngestLimitExceededError(Exception):
    """A size or count limit was exceeded; ingest fails closed."""


class UnsafeInputError(Exception):
    """The target is malformed, unreachable, or points somewhere unsafe."""


Resolved = collections.namedtuple("Resolved", ["root", "name", "kind"])


def _rmtree(path):
    """Remove a temp tree. git marks its pack/object files read-only, and on
    Windows shutil.rmtree would then raise and (with ignore_errors) silently leak
    the whole clone; clear the read-only bit and retry so cleanup actually runs."""
    def _clear_readonly(func, p, _exc):
        try:
            # Never chmod a symlink: os.stat/os.chmod follow it and would change the
            # permissions of its target OUTSIDE the temp tree (a git clone can carry
            # symlinks). Only a real file/dir needs the read-only bit cleared; a
            # symlink just needs unlinking, which needs write on its parent, not it.
            # OR owner rwx onto the existing mode (via lstat, no follow); don't
            # clobber to write-only, which on POSIX would strip +x and leave a
            # directory retry failing. On Windows this clears the read-only bit.
            if not os.path.islink(p):
                os.chmod(p, os.lstat(p).st_mode | stat.S_IRWXU)
            func(p)
        except OSError:
            pass
    shutil.rmtree(path, onexc=_clear_readonly)


@contextlib.contextmanager
def resolved_input(target: str):
    """Yield a Resolved(root, name, kind) for the target, removing any temporary
    directory afterwards. `kind` is one of directory, file, zip, url, git."""
    root, cleanup, kind, name = _resolve(target)
    try:
        yield Resolved(root, name, kind)
    finally:
        if cleanup:
            _rmtree(cleanup)


def _resolve(target):
    # Local paths are checked first, so a directory or file named `foo.git` is
    # treated as what it is on disk, not routed to the git adapter.
    if os.path.isdir(target):
        abspath = os.path.abspath(target)
        return abspath, None, "directory", os.path.basename(abspath.rstrip("/\\")) or abspath
    if os.path.isfile(target):
        if os.path.islink(target):
            # Refuse before the zip check: a symlink to a zip would otherwise be
            # extracted, pulling the target's contents in and defeating the
            # single-file symlink refusal.
            raise UnsafeInputError("single-file input is a symlink; refused: %s" % target)
        if _looks_like_zip(target):
            tmp = tempfile.mkdtemp(prefix="skillxray-")
            try:
                _extract_zip(target, tmp)
            except (UnsafeInputError, IngestLimitExceededError):
                _rmtree(tmp)
                raise
            except Exception as exc:
                # A malformed zip (bad CRC, colliding member order -> FileExistsError,
                # an FS-rejected name -> OSError) must fail closed like the URL path,
                # not crash with a raw traceback and exit 1.
                _rmtree(tmp)
                raise UnsafeInputError("cannot read zip %s: %s" % (target, exc)) from None
            except BaseException:
                _rmtree(tmp)
                raise
            return tmp, tmp, "zip", _strip_zip_ext(os.path.basename(target))
        if _is_unsupported_archive(target):
            raise UnsafeInputError(
                "%s is an archive skill-xray does not extract; unpack it and scan "
                "the directory" % os.path.basename(target))
        tmp = _wrap_single_file(target)          # temp dir must be cleaned up by the caller
        return tmp, tmp, "file", os.path.basename(target)
    if _looks_like_git(target):
        tmp, name = _git_clone(target)
        return tmp, tmp, "git", name
    if _looks_like_url(target):
        root, cleanup, name = _fetch_url(target)
        return root, cleanup, "url", name
    raise UnsafeInputError("not a directory, file, .zip, URL or git repo: %s" % target)


def _looks_like_git(target):
    t = target.strip().lower()               # scheme and .git suffix are case-insensitive
    return t.endswith(".git") or t.startswith(("git@", "git://", "ssh://"))


def _looks_like_url(target):
    return target.strip().lower().startswith("https://")


def _strip_zip_ext(name):
    return name[:-4] if name.lower().endswith(".zip") else name


def _is_unsupported_archive(path, name=None):
    """True if the file is a tar/other archive skill-xray does not extract, so it
    is refused rather than ingested as one opaque asset with a false 100%."""
    if tarfile.is_tarfile(path):
        return True
    return (name or path).lower().endswith(_ARCHIVE_EXTS)


def _zip_member_extracts(info):
    """True only for a member that _extract_zip would write as a file: not a
    directory, and a name that does not normalize to the extraction root. Mirrors the
    out == dest_real skip in _extract_zip, so a '.' or 'a/..' member -- is_dir() False
    yet extracted to nothing -- is not mistaken for content."""
    if info.is_dir():
        return False
    return os.path.normpath(info.filename) != "."


def _looks_like_zip(path):
    """A zip only if it BEGINS with a local file header AND the central directory
    lists a member that would actually extract to a file. zipfile.is_zipfile scans
    backwards for the end-of-central-directory record, so a 22-byte empty EOCD
    appended to any file -- even one first padded with a fake PK\\x03\\x04 magic --
    reads as a valid zip; and a lone '.' member passes is_dir() yet _extract_zip skips
    it as the root. Both leave an empty package at 100%, so route anything without a
    real extractable member to the single-file path where its bytes are inventoried.
    Byte-based, not the filename (_fetch_url names its download 'download')."""
    try:
        with open(path, "rb") as fh:
            if fh.read(4) != b"PK\x03\x04":
                return False
    except OSError:
        return False
    try:
        with zipfile.ZipFile(path) as zf:
            return any(_zip_member_extracts(info) for info in zf.infolist())
    except (zipfile.BadZipFile, OSError):
        return False


# ---------------------------------------------------------------------------
# offline adapters: single file, zip
# ---------------------------------------------------------------------------

def _wrap_single_file(path):
    # The symlink refusal is done in _resolve before this runs (it also covers the
    # zip path). Copy in bounded chunks rather than a pre-copy size check: a file
    # that grows after the check (TOCTOU) must still not write more than
    # INGEST_MAX_BYTES into the temp dir.
    tmp = tempfile.mkdtemp(prefix="skillxray-")
    dest = os.path.join(tmp, os.path.basename(path))
    try:
        written = 0
        with open(path, "rb") as src, open(dest, "wb") as dst:
            while True:
                chunk = src.read(_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > INGEST_MAX_BYTES:
                    raise IngestLimitExceededError("file exceeds %d bytes" % INGEST_MAX_BYTES)
                dst.write(chunk)
    except (UnsafeInputError, IngestLimitExceededError):
        _rmtree(tmp)
        raise
    except Exception as exc:
        _rmtree(tmp)
        raise UnsafeInputError("cannot read file %s: %s" % (path, exc)) from None
    except BaseException:
        _rmtree(tmp)
        raise
    return tmp


def _extract_zip(zip_path, dest):
    """Extract a zip into dest, refusing zip-slip, symlink members, too many
    members, and more than INGEST_MAX_BYTES of actually-extracted bytes."""
    dest_real = os.path.realpath(dest)
    written = 0
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > INGEST_MAX_ZIP_MEMBERS:
            raise IngestLimitExceededError(
                "zip has %d members (max %d)" % (len(infos), INGEST_MAX_ZIP_MEMBERS))
        for info in infos:
            out = os.path.realpath(os.path.join(dest, info.filename))
            if out != dest_real and not out.startswith(dest_real + os.sep):
                raise UnsafeInputError("zip member escapes the extract dir: %s" % info.filename)
            if out == dest_real:
                continue                      # degenerate member ("", ".") -> the root
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise UnsafeInputError("zip contains a symlink: %s" % info.filename)
            if info.is_dir():
                os.makedirs(out, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with zf.open(info) as src, open(out, "wb") as dst:
                while True:
                    chunk = src.read(_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > INGEST_MAX_BYTES:
                        raise IngestLimitExceededError(
                            "zip uncompressed size exceeds %d bytes" % INGEST_MAX_BYTES)
                    dst.write(chunk)


# ---------------------------------------------------------------------------
# network adapters: url, git
# ---------------------------------------------------------------------------

def _embedded_ipv4(ip):
    """The IPv4 address embedded in an IPv4-mapped (::ffff:a.b.c.d) or NAT64
    (64:ff9b::/96) IPv6 address, or None. ipaddress.is_global does not look
    through either, so a v6 literal can smuggle a link-local IPv4 (e.g. cloud
    metadata 169.254.169.254) past the guard; the embedded address is checked too."""
    if ip.version != 6:
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64_PREFIX:
        return ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
    return None


def _resolve_public_ip(host, port):
    """Resolve host and return the first address, refusing if ANY resolved
    address (or an IPv4 it embeds) is non-public."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise UnsafeInputError("cannot resolve host: %s" % host) from None
    if not infos:
        raise UnsafeInputError("host did not resolve: %s" % host)
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            # getaddrinfo can hand back a form ipaddress cannot parse (e.g. a
            # scoped IPv6 "fe80::1%lo0"); fail closed rather than raise a traceback.
            raise UnsafeInputError(
                "host resolved to an unparseable address (%s); refused" % info[4][0]) from None
        embedded = _embedded_ipv4(ip)
        # not-global covers private, loopback, link-local (incl. cloud metadata),
        # CGNAT (100.64/10), reserved, multicast and unspecified in one check; the
        # embedded test stops an IPv4-mapped or NAT64 v6 literal wrapping a bad IPv4.
        if not ip.is_global or (embedded is not None and not embedded.is_global):
            raise UnsafeInputError("host resolves to a non-public address (%s); refused" % ip)
    return infos[0][4][0]


def _check_url_host(url):
    """Validate scheme, port and host, returning (host, port, target, ip). Also
    used by the git adapter to validate a repository host. https only, matching the
    git adapter: a cleartext http fetch of an untrusted package is MITM-able. A
    malformed URL (bad IPv6 literal, invalid port) fails closed as UnsafeInputError
    rather than a raw ValueError, so the CLI exits 2 instead of a traceback."""
    try:
        parts = urllib.parse.urlparse(url)
        if parts.scheme.lower() != "https":
            raise UnsafeInputError("only https URLs are allowed")
        if "@" in parts.netloc:
            # userinfo (user:pass@host) would leak credentials in error output and
            # enables host confusion; refuse without echoing the URL back.
            raise UnsafeInputError("URL with embedded credentials is refused")
        host = parts.hostname
        if not host:
            raise UnsafeInputError("no host in URL")
        port = parts.port or 443
    except ValueError:
        # Do not echo the raw URL: it can carry userinfo or a query token that
        # would leak into error output / logs.
        raise UnsafeInputError("malformed URL") from None
    ip = _resolve_public_ip(host, port)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    return host, port, target, ip


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, ip, port):
        super().__init__(host, port, timeout=URL_TIMEOUT_SECONDS)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _download_capped(host, port, target, ip, dest):
    conn = _PinnedHTTPSConnection(host, ip, port)
    try:
        # No explicit Host header: http.client builds a correct one (with the port
        # and bracketed IPv6) from the hostname; the socket is still IP-pinned.
        conn.request("GET", target, headers={"User-Agent": "skill-xray"})
        resp = conn.getresponse()
        if resp.status in _REDIRECT_STATUSES:
            raise UnsafeInputError(
                "URL redirected (HTTP %d); pass the final URL directly" % resp.status)
        if resp.status != 200:
            raise UnsafeInputError("URL returned HTTP %d" % resp.status)
        written = 0
        # Wall-clock deadline across the whole read: the per-operation socket
        # timeout never trips on a slowloris that trickles one byte before it, so
        # only this bounds the total transfer time (below the 100 MiB size cap).
        deadline = time.monotonic() + URL_DEADLINE_SECONDS
        with open(dest, "wb") as fh:
            while True:
                if time.monotonic() > deadline:
                    raise IngestLimitExceededError(
                        "download exceeded the %ds deadline" % URL_DEADLINE_SECONDS)
                chunk = resp.read(_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > INGEST_MAX_BYTES:
                    raise IngestLimitExceededError("download exceeds %d bytes" % INGEST_MAX_BYTES)
                fh.write(chunk)
    finally:
        conn.close()


def _fetch_url(url):
    host, port, target, ip = _check_url_host(url)
    tmp = tempfile.mkdtemp(prefix="skillxray-")
    try:
        download = os.path.join(tmp, "download")
        _download_capped(host, port, target, ip, download)
        name = os.path.basename(urllib.parse.urlparse(url).path)
        if name in ("", ".", ".."):
            name = "download"
        if _looks_like_zip(download):
            extract = os.path.join(tmp, "extracted")
            os.makedirs(extract)
            _extract_zip(download, extract)
            os.remove(download)
            return extract, tmp, _strip_zip_ext(name)
        if _is_unsupported_archive(download, name):
            raise UnsafeInputError(
                "downloaded file is an archive skill-xray does not extract; fetch "
                "and unpack it, then scan the directory")
        dest = os.path.join(tmp, name)
        if dest != download:                 # a rename-to-self raises on Windows
            os.rename(download, dest)
        return tmp, tmp, name
    except (UnsafeInputError, IngestLimitExceededError):
        _rmtree(tmp)
        raise
    except Exception as exc:
        _rmtree(tmp)
        raise UnsafeInputError("failed to fetch URL: %s" % exc) from None
    except BaseException:
        _rmtree(tmp)          # Ctrl-C / SystemExit during download must not leak the temp dir
        raise


def _check_git_remote(url):
    # https only: a validated public IP is enforced, and git/ssh schemes cannot be
    # SSRF-checked the same way. This blocks git://internal, ssh://internal, and a
    # plain http repo, and validates the host of an https .git URL.
    if not url.lower().startswith("https://"):
        raise UnsafeInputError("git ingest supports https:// repository URLs only")
    _check_url_host(url)


def _git_clone(url):
    _check_git_remote(url)
    tmp = tempfile.mkdtemp(prefix="skillxray-")
    # No GIT_ASKPASS: `true` is not a program on Windows, and GIT_TERMINAL_PROMPT=0
    # already stops git from prompting, so an unauthenticated clone fails cleanly.
    # GIT_CONFIG_NOSYSTEM + GIT_CONFIG_GLOBAL=os.devnull neutralise a system- or
    # user-level url.*.insteadOf / http.proxy / core.hooksPath rewrite that could
    # redirect the clone off the validated host; http.followRedirects=false stops
    # git following a 302 from the validated host to an internal one.
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never",
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    # Strip proxy vars and force http.proxy empty: a *_PROXY (env or config) could
    # route the clone through an internal proxy even though the host resolved to a
    # public IP, which would defeat the SSRF check.
    for _var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                 "http_proxy", "https_proxy", "all_proxy"):
        env.pop(_var, None)
    try:
        subprocess.run(
            ["git", "-c", "http.followRedirects=false", "-c", "http.proxy=",
             "clone", "--depth", "1", "--single-branch", "--no-tags", url, tmp],
            check=True, capture_output=True, timeout=GIT_TIMEOUT_SECONDS, env=env)
        _enforce_tree_size(tmp)
    except FileNotFoundError:
        _rmtree(tmp)
        raise UnsafeInputError("git is not installed") from None
    except subprocess.TimeoutExpired:
        _rmtree(tmp)
        raise IngestLimitExceededError(
            "git clone timed out after %ds" % GIT_TIMEOUT_SECONDS) from None
    except subprocess.CalledProcessError as exc:
        _rmtree(tmp)
        detail = (exc.stderr or b"").decode("utf-8", "replace").strip()[:200]
        raise UnsafeInputError("git clone failed: %s" % detail) from None
    except BaseException:
        _rmtree(tmp)
        raise
    name = os.path.basename(url.rstrip("/"))
    return tmp, name[:-4] if name.lower().endswith(".git") else name


def _enforce_tree_size(root):
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, fn)).st_size
            except OSError:
                continue
            if total > INGEST_MAX_BYTES:
                raise IngestLimitExceededError("cloned tree exceeds %d bytes" % INGEST_MAX_BYTES)
