"""Prepare pinned upstream package data explicitly; builds and scans never download it."""

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import HTTPRedirectHandler, build_opener

ASSET = Path("src/skill_xray/schemas/sarif-schema-2.1.0.json")
URL = ("https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
       "sarif-schema-2.1.0.json")
SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
MAX_BYTES = 256 * 1024


def checked(data):
    if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("Invalid SARIF schema; run python dev/prepare_sarif_schema.py "
                         "with a verified --cache file")
    return data


def verified_bytes(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or unsafe SARIF schema; run python dev/prepare_sarif_schema.py")
    with path.open("rb") as stream:
        return checked(stream.read(MAX_BYTES + 1))


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("SARIF schema download refused a redirect")


def download():
    with build_opener(NoRedirect()).open(URL, timeout=10) as response:
        return checked(response.read(MAX_BYTES + 1))


def prepare(root, cache):
    target = root / ASSET
    if target.exists() or target.is_symlink():
        verified_bytes(target)
        return target
    if cache.exists() or cache.is_symlink():
        data = verified_bytes(cache)
    else:
        # A separate worker bounds total time, including a slowly trickling response.
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--download"],
                                stdout=subprocess.PIPE, timeout=30, check=True)
        data = checked(result.stdout)
        atomic_write(cache, data)
    atomic_write(target, data)
    return target


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=root / "build/schema-cache" / ASSET.name)
    parser.add_argument("--download", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.download:
            sys.stdout.buffer.write(download())
        else:
            print(prepare(root, args.cache))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("Cannot prepare SARIF schema: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
