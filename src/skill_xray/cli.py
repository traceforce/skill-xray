#!/usr/bin/env python3
"""Inventory a skill package and print its coverage ledger.

The target may be a directory, a single file, a .zip, an https URL, or an https
git repository; or use --scan-known-skills to walk every package under the
locations the common agents load skills from. Exit is 0 on a successful walk and
2 on bad usage or a refused/failed ingest.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .ingest import build_ledger, build_package, discover_skill_packages
from .resolve import IngestLimitExceededError, UnsafeInputError, resolved_input


def _artifact_rows(pkg):
    return [{"rel": a.rel, "role": a.role, "kind": a.kind,
             "read": a.text is not None, "exception": a.exception}
            for a in pkg.artifacts]


def _print_one(pkg, ledger):
    sys.stdout.write("package: %s\n" % pkg.name)
    sys.stdout.write("  seen=%d analyzed=%d skipped=%d coverage=%.1f%%\n" % (
        ledger["artifactsSeen"], ledger["artifactsAnalyzed"],
        ledger["artifactsSkipped"], ledger["coveragePercent"]))
    for a in pkg.artifacts:
        mark = "read " if a.text is not None else "SKIP "
        detail = "" if a.text is not None else "  (%s)" % a.exception
        sys.stdout.write("  %s %-40s %s%s\n" % (mark, a.rel, a.kind, detail))
    art_rels = {a.rel for a in pkg.artifacts}
    for e in ledger["exceptions"]:
        if e["path"] not in art_rels:   # directory-level skips: pruned dirs, symlinks, junctions
            sys.stdout.write("  SKIP  %-40s %s\n" % (e["path"], e["reasonCode"]))


def _scan_known(as_json) -> int:
    paths = discover_skill_packages()
    results = [(p, build_ledger(build_package(p))) for p in paths]
    if as_json:
        sys.stdout.write(json.dumps(
            [{"package": os.path.basename(p), "path": p, "ledger": led}
             for p, led in results], indent=2) + "\n")
        return 0
    home = os.path.expanduser("~")
    sys.stdout.write("discovered %d skill package(s) under the known roots\n" % len(results))
    for p, led in results:
        bc = len(led["shippedBytecode"])
        flag = "  bytecode=%d" % bc if bc else ""
        # plugin layouts reuse folder names (access/configure), so show the path
        shown = ("~" + p[len(home):]) if p.startswith(home) else p
        sys.stdout.write("  seen=%-3d analyzed=%-3d cov=%5.1f%%%s  %s\n" % (
            led["artifactsSeen"], led["artifactsAnalyzed"],
            led["coveragePercent"], flag, shown))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="skill-xray",
        description="Inventory a skill package and report its coverage ledger.")
    ap.add_argument("package", nargs="?",
                    help="a directory, file, .zip, https URL, or https git repository")
    ap.add_argument("--scan-known-skills", action="store_true",
                    help="walk every package under the known agent skill roots")
    ap.add_argument("--json", action="store_true", help="emit the inventory as JSON")
    ap.add_argument("--version", action="version", version="skill-xray %s" % __version__)
    args = ap.parse_args(argv)

    if args.scan_known_skills:
        return _scan_known(args.json)

    if not args.package:
        ap.error("provide a package directory, or use --scan-known-skills")

    try:
        with resolved_input(args.package) as r:
            pkg = build_package(r.root)
            pkg.name = r.name          # friendly name; the root may be a temp dir
            ledger = build_ledger(pkg)
            if args.json:
                sys.stdout.write(json.dumps({
                    "package": pkg.name, "identity": pkg.identity,
                    "source": args.package, "kind": r.kind,
                    "artifacts": _artifact_rows(pkg), "ledger": ledger,
                }, indent=2) + "\n")
            else:
                _print_one(pkg, ledger)
    except (UnsafeInputError, IngestLimitExceededError) as exc:
        sys.stderr.write("cannot ingest %s: %s\n" % (args.package, exc))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
