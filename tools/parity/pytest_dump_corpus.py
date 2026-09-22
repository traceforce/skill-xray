"""pytest plugin: copy every package a test materialises under tmp_path into a corpus directory.

    PYTHONPATH=tools/parity;<oracle>/src python -m pytest <oracle>/tests -q \
        -p pytest_dump_corpus --dump-corpus corpus/pytest

After each test, every directory directly under its tmp_path that holds at least one regular file
is copied to <dump>/<nodeid slug>/<dirname> (symlinks recreated, NTFS junctions left out) and a
row {nodeid, package, outcome, files, bytes} is appended to <dump>/manifest.jsonl. A tree over
MAX_FILES files or MAX_BYTES bytes (the DoS-bound tests) is not copied; its row carries a
"skipped" reason instead. The manifest is truncated at session start.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time

import pytest

MAX_FILES = 500
MAX_BYTES = 50 * 2**20

_STATE = pytest.StashKey()
_OUTCOME = pytest.StashKey()


def slug(nodeid):
    """Filesystem-safe, short and collision-free name for a test nodeid."""
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", nodeid.removeprefix("tests/")).strip("_")
    return "%s-%s" % (text[:80], hashlib.sha1(nodeid.encode("utf-8")).hexdigest()[:8])


def measure(root):
    """(regular files, bytes) under root; symlinks and junctions are not entered."""
    files = size = 0
    stack = [root]
    while stack:
        with os.scandir(stack.pop()) as it:
            for entry in it:
                if entry.is_symlink() or os.path.isjunction(entry.path):
                    continue
                elif entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    files += 1
                    size += entry.stat(follow_symlinks=False).st_size
    return files, size


def copy_tree(src, dst):
    shutil.copytree(src, dst, symlinks=True,
                    ignore=lambda d, names: [n for n in names
                                             if os.path.isjunction(os.path.join(d, n))])


def pytest_addoption(parser):
    parser.addoption("--dump-corpus", metavar="DIR",
                     help="copy every package a test builds under tmp_path into DIR")


def pytest_configure(config):
    dump = config.getoption("--dump-corpus")
    if not dump:
        return
    os.makedirs(dump, exist_ok=True)
    config.stash[_STATE] = {
        "dir": dump, "manifest": open(os.path.join(dump, "manifest.jsonl"), "w", encoding="utf-8"),
        "packages": 0, "files": 0, "bytes": 0, "skipped": 0, "t0": time.perf_counter()}


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    report = (yield).get_result()
    if report.when == "call" or report.outcome != "passed":
        item.stash[_OUTCOME] = report.outcome


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_teardown(item, nextitem):
    state = item.config.stash.get(_STATE, None)
    if state is None:
        return
    try:
        _dump_item(item, state)
    except Exception as exc:  # a test that patched os.* to fail still has the patch active here
        state["skipped"] += 1
        state["manifest"].write(json.dumps({"nodeid": item.nodeid, "package": slug(item.nodeid),
                                            "outcome": item.stash.get(_OUTCOME, "unknown"),
                                            "files": 0, "bytes": 0,
                                            "skipped": ("fixture patched os: %s"
                                                        % type(exc).__name__)},
                                           ensure_ascii=True) + "\n")
        state["manifest"].flush()


_REAL_OS = (os.scandir, os.listdir, os.walk, os.path.isdir)


def _dump_item(item, state):
    if (os.scandir, os.listdir, os.walk, os.path.isdir) != _REAL_OS:
        raise RuntimeError("os is patched")   # a fake listing would be walked, not the package
    tmp = getattr(item, "funcargs", {}).get("tmp_path")
    if tmp is None or not os.path.isdir(tmp):
        return
    for entry in sorted(os.scandir(tmp), key=lambda e: e.name):
        if not entry.is_dir(follow_symlinks=False) or os.path.isjunction(entry.path):
            continue
        files, size = measure(entry.path)
        if files == 0:
            continue
        package = "%s/%s" % (slug(item.nodeid), entry.name)
        row = {"nodeid": item.nodeid, "package": package,
               "outcome": item.stash.get(_OUTCOME, "unknown"), "files": files, "bytes": size}
        dest = os.path.join(state["dir"], *package.split("/"))
        shutil.rmtree(dest, ignore_errors=True)
        if files > MAX_FILES or size > MAX_BYTES:
            row["skipped"] = "over %d files or %d bytes" % (MAX_FILES, MAX_BYTES)
        else:
            try:
                copy_tree(entry.path, dest)
            except OSError as exc:
                shutil.rmtree(dest, ignore_errors=True)
                row["skipped"] = "copy failed: %s" % type(exc).__name__
        if "skipped" in row:
            state["skipped"] += 1
        else:
            state["packages"] += 1
            state["files"] += files
            state["bytes"] += size
        state["manifest"].write(json.dumps(row, ensure_ascii=True) + "\n")
        state["manifest"].flush()


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    state = config.stash.get(_STATE, None)
    if state is None:
        return
    state["manifest"].close()
    terminalreporter.write_line(
        "dump-corpus: %d packages, %d files, %d bytes, %d skipped trees, %.1fs -> %s" % (
            state["packages"], state["files"], state["bytes"], state["skipped"],
            time.perf_counter() - state["t0"], state["dir"]))
