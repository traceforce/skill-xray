"""Freeze the shell-only PR7 contract against pinned OpenGrep."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

import pytest

from skill_xray import ingest, parse
from skill_xray.opengrep_bridge import check as opengrep_check
from skill_xray.opengrep_runtime import OpenGrepRuntimeError, resolve_opengrep


def _contract():
    path = Path(__file__).with_name("opengrep_shell_contract.jsonl")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _live_executable():
    try:
        executable = resolve_opengrep(os.environ.get("SKILL_XRAY_OPENGREP_BIN"))
    except OpenGrepRuntimeError as exc:
        pytest.fail(str(exc))
    if executable is None:
        if os.environ.get("CI"):
            pytest.fail("pinned OpenGrep is required in CI")
        pytest.skip("pinned OpenGrep is not installed")
    return executable


def test_shell_contract_has_unique_shell_only_cases():
    cases = _contract()
    assert len(cases) == 57
    assert len({case["name"] for case in cases}) == len(cases)
    assert {case["ext"] for case in cases} <= {"", "sh"}


def test_live_opengrep_matches_shell_contract_exactly(make_package):
    cases = _contract()
    files = {
        "%03d_%s%s" % (index, case["name"], ".sh" if case["ext"] else ""):
        case["source"]
        for index, case in enumerate(cases)
    }
    parsed = parse.parse_package(ingest.build_package(str(make_package(files))))
    expected = Counter(
        (path, vector)
        for path, case in zip(files, cases, strict=True)
        for vector in case["expect"]
    )

    findings = opengrep_check(
        parsed, executable=_live_executable(), languages=("shell",), timeout=90,
    )

    assert not [finding for finding in findings if not finding.vector]
    assert Counter((finding.path, finding.vector) for finding in findings) == expected
