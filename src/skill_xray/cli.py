#!/usr/bin/env python3
"""Inventory a skill package and print its coverage ledger.

The target may be a directory, a single file, a .zip, an https URL, or an https
git repository; or use --scan-known-skills to walk every package under the
locations the common agents load skills from. Exit is 0 on a complete walk and
2 on bad usage, a refused/failed ingest, or incomplete high-severity analysis.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .findings import findings_to_dicts
from .ingest import build_ledger, build_package, discover_skill_packages
from .llm import LLMConfigError, build_client, coverage_summary
from .llm import from_env as llm_from_env
from .opengrep_runtime import VERSION as OPENGREP_VERSION
from .opengrep_runtime import OpenGrepRuntimeError, install_opengrep
from .parse import parse_package
from .resolve import IngestLimitExceededError, UnsafeInputError, resolved_input
from .scan import scan, scan_report


def _artifact_rows(pkg):
    return [{"rel": a.rel, "role": a.role, "kind": a.kind,
             "read": a.text is not None, "exception": a.exception}
            for a in pkg.artifacts]


def _display(rel):
    # Artifact paths are attacker-controlled: escape control chars (which could
    # rewrite the on-screen inventory to hide a file, the one thing this tool must
    # not allow) and lone surrogates (which crash the write to a strict-UTF-8
    # stdout). The --json path is already safe via ensure_ascii.
    return rel.encode("unicode_escape").decode("ascii")


def _print_one(pkg, ledger):
    sys.stdout.write("package: %s\n" % _display(pkg.name))
    sys.stdout.write("  seen=%d analyzed=%d skipped=%d coverage=%.1f%%\n" % (
        ledger["artifactsSeen"], ledger["artifactsAnalyzed"],
        ledger["artifactsSkipped"], ledger["coveragePercent"]))
    for a in pkg.artifacts:
        mark = "read " if a.text is not None else "SKIP "
        detail = "" if a.text is not None else "  (%s)" % a.exception
        sys.stdout.write("  %s %-40s %s%s\n" % (mark, _display(a.rel), a.kind, detail))
    art_rels = {a.rel for a in pkg.artifacts}
    for e in ledger["exceptions"]:
        if e["path"] not in art_rels:   # directory-level skips: pruned dirs, symlinks, junctions
            sys.stdout.write("  SKIP  %-40s %s\n" % (_display(e["path"]), e["reasonCode"]))


def _print_findings(pkg, findings) -> None:
    sys.stdout.write("package: %s\n" % _display(pkg.name))
    if not findings:
        sys.stdout.write("  no findings\n")
        return
    for f in findings:
        loc = ""
        if f.line is not None:
            loc = "  L%d" % f.line
            if f.column is not None:
                loc += ":%d" % f.column
        elif f.offset is not None:
            loc = "  @%d" % f.offset + ("+%d" % f.length if f.length is not None else "")
        sys.stdout.write("  [%-8s] %-8s %-20s %s: %s%s\n" % (
            f.severity.upper(), f.vector or "-", f.rule, _display(f.path),
            _display(f.message), loc))


def _scan_known(as_json) -> int:
    paths = discover_skill_packages()
    results = [(p, build_ledger(build_package(p))) for p in paths]
    if as_json:
        sys.stdout.write(json.dumps(
            [{"package": os.path.basename(p), "path": p, "ledger": led}
             for p, led in results], indent=2) + "\n")
    else:
        home = os.path.expanduser("~")
        sys.stdout.write("discovered %d skill package(s) under the known roots\n" % len(results))
        for p, led in results:
            flag = ""
            if led["shippedCompiledCode"]:
                flag += "  compiled=%d" % len(led["shippedCompiledCode"])
            if led["agentIdentityFiles"]:
                flag += "  identity=%d" % len(led["agentIdentityFiles"])
            # plugin layouts reuse folder names (access/configure), so show the path.
            # Guard the prefix so "/home/al" does not abbreviate "/home/alice/x".
            shown = ("~" + p[len(home):]) if (p == home or p.startswith(home + os.sep)) else p
            sys.stdout.write("  seen=%-3d analyzed=%-3d cov=%5.1f%%%s  %s\n" % (
                led["artifactsSeen"], led["artifactsAnalyzed"],
                led["coveragePercent"], flag, _display(shown)))
    for entry in paths.ledger_exceptions:
        sys.stderr.write("skill discovery incomplete (%s): %s\n" % (
            entry["reasonCode"], _display(entry["path"])))
    return 2 if paths.ledger_exceptions else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="skill-xray",
        description="Inventory a skill package and report its coverage ledger.")
    ap.add_argument("package", nargs="?",
                    help="a directory, file, .zip, https URL, or https git repository")
    ap.add_argument("--scan-known-skills", action="store_true",
                    help="walk every package under the known agent skill roots")
    ap.add_argument("--analyze", action="store_true",
                    help="run the detection engines and report findings instead of the inventory")
    ap.add_argument("--opengrep-bin", metavar="PATH",
                    help="explicit pinned OpenGrep binary for --analyze")
    ap.add_argument("--llm", action="store_true",
                    help="also run the opt-in LLM adjudication pass (semantic prompt injection). "
                         "SENDS THE TEXT of the scanned skill files to the configured third-party "
                         "LLM provider, so do not use it on confidential packages. Requires "
                         "SKILLXRAY_LLM_PROVIDER and an API key in the environment")
    ap.add_argument("--enrich", action="store_true",
                    help="include capability context and raw candidates with --analyze --json")
    ap.add_argument("--llm-shadow", action="store_true",
                    help="review static candidates only, without additive SXV-038 detection; "
                         "requires --llm --json")
    ap.add_argument("--llm-review", action="store_true",
                    help="annotate disputed findings without removing or downgrading them; "
                         "requires --llm --json")
    ap.add_argument("--llm-additive", action="store_true",
                    help="also run SXV-038 after LLM review, using the remaining shared budget")
    ap.add_argument("--install-opengrep", action="store_true",
                    help="download and verify the pinned OpenGrep runtime, then exit")
    ap.add_argument("--json", action="store_true", help="emit the inventory as JSON")
    ap.add_argument("--version", action="version", version="skill-xray %s" % __version__)
    args = ap.parse_args(argv)
    reviewing = args.llm_shadow or args.llm_review

    if args.install_opengrep:
        if (args.package or args.scan_known_skills or args.analyze
                or args.json or args.opengrep_bin or args.llm or args.enrich or args.llm_shadow
                or args.llm_additive or args.llm_review):
            ap.error("--install-opengrep is a standalone action")
        try:
            installed = install_opengrep()
        except OpenGrepRuntimeError as exc:
            sys.stderr.write("cannot install OpenGrep: %s\n" % _display(str(exc)))
            return 2
        sys.stdout.write("installed OpenGrep %s at %s\n" % (
            OPENGREP_VERSION, _display(str(installed))))
        return 0

    if args.scan_known_skills:
        if args.package:
            ap.error("--scan-known-skills takes no package argument")
        if (args.analyze or args.opengrep_bin or args.llm or args.enrich or args.llm_shadow
                or args.llm_additive or args.llm_review):
            ap.error("--scan-known-skills does not accept analysis options")
        return _scan_known(args.json)

    if not args.package:
        ap.error("provide a package directory, or use --scan-known-skills")

    if args.opengrep_bin and not args.analyze:
        ap.error("--opengrep-bin requires --analyze")
    if (args.enrich or reviewing) and not (args.analyze and args.json):
        ap.error("--enrich and LLM review require --analyze --json")
    if reviewing and not args.llm:
        ap.error("LLM review requires explicit --llm opt-in")
    if args.llm_shadow and args.llm_review:
        ap.error("--llm-shadow and --llm-review are mutually exclusive")
    if args.llm_additive and not reviewing:
        ap.error("--llm-additive requires --llm-shadow or --llm-review")

    # Build the opt-in LLM client up front so a misconfiguration fails before the scan runs.
    client = None
    if args.llm:
        if not args.analyze:
            ap.error("--llm requires --analyze")
        try:
            cfg = llm_from_env()
        except LLMConfigError as exc:
            ap.error(str(exc))
        if cfg is None:
            ap.error("--llm needs SKILLXRAY_LLM_PROVIDER and an API key in the environment")
        client = build_client(cfg)

    try:
        with resolved_input(args.package) as r:
            pkg = build_package(r.root)
            pkg.name = r.name          # friendly name; the root may be a temp dir
            ledger = build_ledger(pkg)
            if args.analyze:
                parsed = parse_package(pkg)
                result = (scan_report if args.enrich or reviewing else scan)(
                    parsed,
                    client=client,
                    opengrep_executable=args.opengrep_bin,
                    **({"llm_shadow": args.llm_shadow,
                        "llm_review": args.llm_review,
                        "llm_advisory": args.llm_additive or not reviewing}
                       if args.enrich or reviewing else {}),
                )
                report = result if args.enrich or reviewing else None
                findings = report.findings if report else result
                if args.json:
                    enrichment = report.to_dict() if report else {}
                    analysis = {"opengrepVersion": OPENGREP_VERSION}
                    if client is not None:
                        analysis["llmCoverage"] = coverage_summary(parsed, findings)
                        if report and not report.llm_usage["advisory_enabled"]:
                            cov = analysis["llmCoverage"]
                            cov.update(enabled=False, checked=0, skipped=cov["eligible"],
                                       reason="Additive SXV-038 pass not requested")
                    sys.stdout.write(json.dumps({
                        "package": pkg.name, "identity": pkg.identity,
                        "source": args.package, "kind": r.kind,
                        "analysis": analysis,
                        "findings": (enrichment.pop("findings") if report
                                     else findings_to_dicts(findings)), "ledger": ledger,
                        **({"enrichment": enrichment} if report else {}),
                    }, indent=2) + "\n")
                else:
                    _print_findings(pkg, findings)
                    if client is not None:
                        cov = coverage_summary(parsed, findings)
                        sys.stdout.write(
                            "  LLM adjudication: %d eligible, %d checked, %d truncated, "
                            "%d skipped, %d errored, %d flagged\n" % (
                                cov["eligible"], cov["checked"], cov["truncated"],
                                cov["skipped"], cov["errored"], cov["flagged"]))
                if (report and report.context_errors) or any(
                    not finding.vector and finding.severity in {"critical", "high"}
                    for finding in findings
                ):
                    return 2
            elif args.json:
                sys.stdout.write(json.dumps({
                    "package": pkg.name, "identity": pkg.identity,
                    "source": args.package, "kind": r.kind,
                    "artifacts": _artifact_rows(pkg), "ledger": ledger,
                }, indent=2) + "\n")
            else:
                _print_one(pkg, ledger)
    except (UnsafeInputError, IngestLimitExceededError) as exc:
        # args.package and the error text can carry attacker-controlled names
        # (zip members, URLs); escape them like artifact paths.
        sys.stderr.write("cannot ingest %s: %s\n" % (_display(args.package), _display(str(exc))))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
