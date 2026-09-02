"""Pinned OpenGrep runtime discovery, verification and explicit installation."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.request import Request, urlopen

VERSION = "1.29.0"
_RELEASE = "https://github.com/opengrep/opengrep/releases/download/v%s" % VERSION
_MAX_DOWNLOAD = 64 * 1024 * 1024
_ENV_BINARY = "SKILL_XRAY_OPENGREP_BIN"


class OpenGrepRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class OpenGrepAsset:
    name: str
    size: int
    sha256: str

    @property
    def url(self) -> str:
        return "%s/%s" % (_RELEASE, self.name)


_ASSETS = {
    ("windows", "x86_64"): OpenGrepAsset(
        "opengrep_windows_x86.exe", 53_536_256,
        "ee485b31912704dc6410bc43f04b5c6ad896697db56e360a98204abf95fa1025",
    ),
    ("linux", "x86_64"): OpenGrepAsset(
        "opengrep_manylinux_x86", 46_442_664,
        "3365ef49d04893e01338d85d9bbd49b2bd5261ad4c9c0df0a6a0f8d44232ae13",
    ),
    ("linux", "aarch64"): OpenGrepAsset(
        "opengrep_manylinux_aarch64", 47_916_824,
        "db3cda6e6e53251a3874e62b7c8493c281508480b3f3b4db554be41583b21174",
    ),
    ("darwin", "x86_64"): OpenGrepAsset(
        "opengrep_osx_x86", 48_310_144,
        "7173bd701491b58e1d1f62c24470ca0be124ecd63885c4d6293cbf71fd706508",
    ),
    ("darwin", "aarch64"): OpenGrepAsset(
        "opengrep_osx_arm64", 47_281_712,
        "dacc12a24e95b22c8b1ab55be1777b6eb877a922c5571a95b9a8de30f3963438",
    ),
}


def _platform_key(system: str | None = None, machine: str | None = None):
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    if machine in ("amd64", "x64", "x86_64"):
        machine = "x86_64"
    elif machine in ("arm64", "aarch64"):
        machine = "aarch64"
    return system, machine


def platform_asset(system: str | None = None, machine: str | None = None) -> OpenGrepAsset:
    key = _platform_key(system, machine)
    try:
        return _ASSETS[key]
    except KeyError as exc:
        raise OpenGrepRuntimeError(
            "OpenGrep v%s is not pinned for %s/%s" % (VERSION, key[0], key[1])
        ) from exc


def default_cache_dir() -> Path:
    system = platform.system().lower()
    if system == "windows" and os.environ.get("LOCALAPPDATA"):
        root = Path(os.environ["LOCALAPPDATA"])
    elif system == "darwin":
        root = Path.home() / "Library" / "Caches"
    else:
        root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return root / "skill-xray" / "opengrep" / VERSION


def cached_executable(cache_dir: str | Path | None = None) -> Path:
    root = Path(cache_dir) if cache_dir else default_cache_dir()
    return root / ("opengrep.exe" if platform.system().lower() == "windows" else "opengrep")


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


@lru_cache(maxsize=8)
def _digest_cached(path: str, identity: tuple[int, ...]) -> str:
    return _digest(Path(path))


def verify_executable(path: str | Path, asset: OpenGrepAsset | None = None) -> Path:
    candidate = Path(path)
    asset = asset or platform_asset()
    try:
        stat_result = candidate.stat()
        size = stat_result.st_size
    except OSError as exc:
        raise OpenGrepRuntimeError("OpenGrep executable is unavailable: %s" % candidate) from exc
    if not candidate.is_file() or size != asset.size:
        raise OpenGrepRuntimeError(
            "OpenGrep executable does not match pinned v%s asset: %s" % (VERSION, candidate)
        )
    identity = (
        stat_result.st_size,
        stat_result.st_mtime_ns,
        stat_result.st_ctime_ns,
        getattr(stat_result, "st_ino", 0),
        getattr(stat_result, "st_dev", 0),
    )
    digest = _digest_cached(str(candidate.resolve()), identity)
    if digest != asset.sha256:
        raise OpenGrepRuntimeError(
            "OpenGrep executable does not match pinned v%s asset: %s" % (VERSION, candidate)
        )
    return candidate


def resolve_opengrep(explicit: str | Path | None = None) -> Path | None:
    configured = explicit or os.environ.get(_ENV_BINARY)
    if configured:
        return verify_executable(configured)
    cached = cached_executable()
    if cached.exists():
        return verify_executable(cached)
    discovered = shutil.which("opengrep")
    return verify_executable(discovered) if discovered else None


def install_opengrep(
    cache_dir: str | Path | None = None,
    *,
    opener=urlopen,
    timeout: float = 60.0,
) -> Path:
    """Download and verify the pinned asset after an explicit user action."""
    asset = platform_asset()
    destination = cached_executable(cache_dir)
    if destination.exists():
        try:
            return verify_executable(destination, asset)
        except OpenGrepRuntimeError:
            pass
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = Request(asset.url, headers={"User-Agent": "skill-xray/%s" % VERSION})
    temporary = None
    try:
        with opener(request, timeout=timeout) as response:
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > _MAX_DOWNLOAD:
                raise OpenGrepRuntimeError("OpenGrep download exceeds the safety limit")
            with tempfile.NamedTemporaryFile(
                dir=destination.parent, prefix=".opengrep-", delete=False
            ) as handle:
                temporary = Path(handle.name)
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > _MAX_DOWNLOAD:
                        raise OpenGrepRuntimeError("OpenGrep download exceeds the safety limit")
                    handle.write(chunk)
        verify_executable(temporary, asset)
        temporary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        os.replace(temporary, destination)
        temporary = None
        return verify_executable(destination, asset)
    except (OSError, ValueError) as exc:
        raise OpenGrepRuntimeError("OpenGrep installation failed: %s" % type(exc).__name__) from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
