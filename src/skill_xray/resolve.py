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
import subprocess
import tempfile
import urllib.parse
import zipfile

__all__ = ["resolved_input", "Resolved", "IngestLimitExceededError", "UnsafeInputError"]

# Aggregate limits, mirroring mcp-xray / SkillSpector ingest caps. A breach fails
# closed. They bound the download, the total uncompressed size of an archive, and
# the on-disk size of a clone -- not any single file, which the walker caps.
INGEST_MAX_BYTES = 100 * 1024 * 1024        # 100 MiB
INGEST_MAX_ZIP_MEMBERS = 10_000
URL_TIMEOUT_SECONDS = 30
GIT_TIMEOUT_SECONDS = 120
_CHUNK = 65536
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class IngestLimitExceededError(Exception):
    """A size or count limit was exceeded; ingest fails closed."""


class UnsafeInputError(Exception):
    """The target is malformed, unreachable, or points somewhere unsafe."""


Resolved = collections.namedtuple("Resolved", ["root", "name", "kind"])


@contextlib.contextmanager
def resolved_input(target: str):
    """Yield a Resolved(root, name, kind) for the target, removing any temporary
    directory afterwards. `kind` is one of directory, file, zip, url, git."""
    root, cleanup, kind, name = _resolve(target)
    try:
        yield Resolved(root, name, kind)
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


def _resolve(target):
    # Local paths are checked first, so a directory or file named `foo.git` is
    # treated as what it is on disk, not routed to the git adapter.
    if os.path.isdir(target):
        abspath = os.path.abspath(target)
        return target, None, "directory", os.path.basename(abspath.rstrip("/\\")) or abspath
    if os.path.isfile(target):
        if zipfile.is_zipfile(target):
            tmp = tempfile.mkdtemp(prefix="skillxray-")
            try:
                _extract_zip(target, tmp)
            except BaseException:
                shutil.rmtree(tmp, ignore_errors=True)
                raise
            return tmp, tmp, "zip", _strip_zip_ext(os.path.basename(target))
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
    t = target.strip()
    return t.endswith(".git") or t.startswith(("git@", "git://", "ssh://"))


def _looks_like_url(target):
    return target.strip().startswith(("http://", "https://"))


def _strip_zip_ext(name):
    return name[:-4] if name.lower().endswith(".zip") else name


# ---------------------------------------------------------------------------
# offline adapters: single file, zip
# ---------------------------------------------------------------------------

def _wrap_single_file(path):
    if os.path.getsize(path) > INGEST_MAX_BYTES:
        raise IngestLimitExceededError("file exceeds %d bytes" % INGEST_MAX_BYTES)
    tmp = tempfile.mkdtemp(prefix="skillxray-")
    try:
        shutil.copy2(path, os.path.join(tmp, os.path.basename(path)))
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
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

def _resolve_public_ip(host, port):
    """Resolve host and return the first address, refusing if ANY resolved
    address is non-public."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise UnsafeInputError("cannot resolve host: %s" % host) from None
    if not infos:
        raise UnsafeInputError("host did not resolve: %s" % host)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        # not-global covers private, loopback, link-local (incl. cloud metadata),
        # CGNAT (100.64/10), reserved, multicast and unspecified in one check.
        if not ip.is_global:
            raise UnsafeInputError("host resolves to a non-public address (%s); refused" % ip)
    return infos[0][4][0]


def _check_url_host(url):
    """Validate scheme, port and host, returning (scheme, host, port, target, ip).
    Also used by the git adapter to validate a repository host."""
    parts = urllib.parse.urlparse(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeInputError("only http/https URLs are allowed")
    host = parts.hostname
    if not host:
        raise UnsafeInputError("no host in URL")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise UnsafeInputError("invalid port in URL") from None
    ip = _resolve_public_ip(host, port)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    return parts.scheme, host, port, target, ip


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, ip, port):
        super().__init__(host, port, timeout=URL_TIMEOUT_SECONDS)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, ip, port):
        super().__init__(host, port, timeout=URL_TIMEOUT_SECONDS)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def _pinned_connection(scheme, host, port, ip):
    if scheme == "https":
        return _PinnedHTTPSConnection(host, ip, port)
    return _PinnedHTTPConnection(host, ip, port)


def _download_capped(scheme, host, port, target, ip, dest):
    conn = _pinned_connection(scheme, host, port, ip)
    try:
        conn.request("GET", target, headers={"User-Agent": "skill-xray", "Host": host})
        resp = conn.getresponse()
        if resp.status in _REDIRECT_STATUSES:
            raise UnsafeInputError(
                "URL redirected (HTTP %d); pass the final URL directly" % resp.status)
        if resp.status != 200:
            raise UnsafeInputError("URL returned HTTP %d" % resp.status)
        written = 0
        with open(dest, "wb") as fh:
            while True:
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
    scheme, host, port, target, ip = _check_url_host(url)
    tmp = tempfile.mkdtemp(prefix="skillxray-")
    try:
        download = os.path.join(tmp, "download")
        _download_capped(scheme, host, port, target, ip, download)
        name = os.path.basename(urllib.parse.urlparse(url).path)
        if name in ("", ".", ".."):
            name = "download"
        if zipfile.is_zipfile(download):
            extract = os.path.join(tmp, "extracted")
            os.makedirs(extract)
            _extract_zip(download, extract)
            os.remove(download)
            return extract, tmp, _strip_zip_ext(name)
        os.rename(download, os.path.join(tmp, name))
        return tmp, tmp, name
    except (UnsafeInputError, IngestLimitExceededError):
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    except Exception as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        raise UnsafeInputError("failed to fetch URL: %s" % exc) from None


def _check_git_remote(url):
    # https only: a validated public IP is enforced, and git/ssh schemes cannot be
    # SSRF-checked the same way. This blocks git://internal, ssh://internal, and a
    # plain http repo, and validates the host of an https .git URL.
    if not url.startswith("https://"):
        raise UnsafeInputError("git ingest supports https:// repository URLs only")
    _check_url_host(url)


def _git_clone(url):
    _check_git_remote(url)
    tmp = tempfile.mkdtemp(prefix="skillxray-")
    # No GIT_ASKPASS: `true` is not a program on Windows, and GIT_TERMINAL_PROMPT=0
    # already stops git from prompting, so an unauthenticated clone fails cleanly.
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", url, tmp],
            check=True, capture_output=True, timeout=GIT_TIMEOUT_SECONDS, env=env)
        _enforce_tree_size(tmp)
    except FileNotFoundError:
        shutil.rmtree(tmp, ignore_errors=True)
        raise UnsafeInputError("git is not installed") from None
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp, ignore_errors=True)
        raise IngestLimitExceededError(
            "git clone timed out after %ds" % GIT_TIMEOUT_SECONDS) from None
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        detail = (exc.stderr or b"").decode("utf-8", "replace").strip()[:200]
        raise UnsafeInputError("git clone failed: %s" % detail) from None
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    name = os.path.basename(url.rstrip("/"))
    return tmp, name[:-4] if name.endswith(".git") else name


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
