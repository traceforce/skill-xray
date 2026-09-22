"""Dump one check's findings for skill packages as JSON Lines, one record per package.

    PYTHONPATH=<oracle>/src python tools/parity/py_dump_findings.py <module> [<package dir> ...]

<module> is a name under skill_xray.checks (grants, hooks, instruction_exfil, metadata,
obfuscation, persistence, preproc, supply_chain, coverage), "analyze" for
skill_xray.analyze.analyze_package, or "code_lane" for build_code_lane's units and notes.
Package directories come from the arguments, or one per line
on stdin when none are given (the Go side batches a whole corpus that way). Each record is
{"package": <dir as given>, "findings": [Finding.to_dict() ...]} in check order, or
{"package": ..., "error": <exception class name>} when the check raised.
"""

import importlib
import json
import sys

from skill_xray import ingest, parse


def load_check(module):
    if module == "analyze":
        return importlib.import_module("skill_xray.analyze").analyze_package
    return importlib.import_module("skill_xray.checks." + module).check


def _code_lane_records(parsed):
    """build_code_lane's units then notes as Finding-shaped dicts. A unit is encoded as a
    finding (rule "code-unit", its fields under evidence, dialect None -> null) so both sides
    compare through the same JSON as the Go codelane parity test."""
    build_code_lane = importlib.import_module("skill_xray.checks.code_lane").build_code_lane
    units, notes = build_code_lane(parsed)
    records = [{"vector": "", "rule": "code-unit", "severity": "", "path": u.rel, "message": "",
                "evidence": {"kind": u.kind, "origin": u.origin, "dialect": u.dialect,
                             "text": u.text}}
               for u in units]
    records += [n.to_dict() for n in notes]
    return records


def dump(module, root):
    parsed = parse.parse_package(ingest.build_package(root))
    if module == "code_lane":
        return _code_lane_records(parsed)
    return [f.to_dict() for f in load_check(module)(parsed) or []]


def main(argv):
    if len(argv) < 1:
        sys.stderr.write(__doc__)
        return 2
    module = argv[0]
    dirs = argv[1:] or [line.rstrip("\r\n") for line in sys.stdin if line.strip()]
    for root in dirs:
        try:
            rec = {"package": root, "findings": dump(module, root)}
        except Exception as exc:  # the check raised: run_checks would report check-error
            rec = {"package": root, "error": type(exc).__name__}
        sys.stdout.write(json.dumps(rec, sort_keys=True, ensure_ascii=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
