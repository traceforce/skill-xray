"""Refuse incomplete source builds without making build-time network requests."""

from pathlib import Path
from runpy import run_path

from setuptools import setup

root = Path(__file__).resolve().parent
schema = run_path(str(root / "dev/prepare_sarif_schema.py"))
schema["verified_bytes"](root / schema["ASSET"])
setup()
