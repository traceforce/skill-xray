"""Shared test fixtures for skill-xray."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from skill_xray.opengrep_runtime import OpenGrepRuntimeError, resolve_opengrep


@pytest.fixture
def make_package(tmp_path: Path):
    """make_package({"SKILL.md": "...", "scripts/x.py": "..."}) -> Path.

    Values may be str (written UTF-8, newlines preserved byte for byte) or bytes
    (written raw, for BOM / CRLF / encoding cases).
    """

    def _make(files: dict, name: str = "pkg") -> Path:
        root = tmp_path / name
        root.mkdir(parents=True, exist_ok=True)
        for rel, body in files.items():
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(body, bytes):
                dest.write_bytes(body)
            else:
                with open(dest, "w", encoding="utf-8", newline="") as fh:
                    fh.write(body)
        return root

    return _make


@pytest.fixture
def live_opengrep():
    """The pinned OpenGrep executable: required in CI, otherwise the test is skipped."""
    try:
        executable = resolve_opengrep(os.environ.get("SKILL_XRAY_OPENGREP_BIN"))
    except OpenGrepRuntimeError as exc:
        pytest.fail(str(exc))
    if executable is None:
        if os.environ.get("CI"):
            pytest.fail("pinned OpenGrep is required in CI")
        pytest.skip("pinned OpenGrep is not installed")
    return executable
