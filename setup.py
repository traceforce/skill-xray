"""Refuse incomplete source builds without making build-time network requests."""

import hashlib
from pathlib import Path

from setuptools import setup

root = Path(__file__).resolve().parent
schema = root / "src/skill_xray/schemas/sarif-schema-2.1.0.json"
expected = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
if (schema.is_symlink() or not schema.is_file() or schema.stat().st_size > 256 * 1024
        or hashlib.sha256(schema.read_bytes()).hexdigest() != expected):
    raise ValueError("Restore the vendored SARIF schema from a trusted checkout")
setup()
