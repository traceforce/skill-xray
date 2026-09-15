"""Native OpenGrep integration over the existing frozen six-package microcorpus."""

import json
from time import perf_counter

import pytest
from test_postdetect_microcorpus import _CASES, MANIFEST_SHA256

from skill_xray import ingest, parse, scan, scan_report
from skill_xray.correlate import correlate


@pytest.mark.parametrize("name", _CASES)
def test_every_microcorpus_candidate_has_a_result(make_package, name):
    parsed = parse.parse_package(ingest.build_package(make_package(_CASES[name])))
    report = scan_report(parsed)
    start = perf_counter()
    correlated = correlate(parsed, report.raw_candidates)
    elapsed = perf_counter() - start
    raw_ids = {item["candidate_id"] for item in report.raw_candidates}
    assert {item["candidate_id"] for item in correlated["links"]} == raw_ids
    results = {item["id"]: item for item in correlated["results"]}
    assert len(results) == len(correlated["results"])
    for link in correlated["links"]:
        assert link["candidate_id"] in results[link["result_id"]]["candidate_ids"]
    assert correlated["raw_candidates"] == report.raw_candidates
    if name == "tainted_execution":
        assert any(item["code_flow"] for item in results.values()
                   if item["finding"]["vector"] == "SXV-008")
    print(json.dumps({"sample": name, "manifest_sha256": MANIFEST_SHA256,
                      "raw": len(raw_ids), "results": len(results), "lost": 0,
                      "duplicates": sum(link["disposition"] == "duplicate"
                                        for link in correlated["links"]),
                      "correlation_seconds": elapsed}))


def test_native_line_shifts_keep_fingerprints_and_scan_contract(make_package):
    runs = []
    for prefix in ("", "\n\n"):
        files = dict(_CASES["tainted_execution"])
        files["run.py"] = prefix + files["run.py"]
        parsed = parse.parse_package(ingest.build_package(make_package(files)))
        report = scan_report(parsed)
        runs.append(correlate(parsed, report.raw_candidates))
        assert {(f.vector, f.rule, f.path, f.line, f.severity) for f in scan(parsed)} == {
            (f.vector, f.rule, f.path, f.line, f.severity) for f in report.findings}
    assert [r["fingerprint"] for r in runs[0]["results"]] == [
        r["fingerprint"] for r in runs[1]["results"]]
    assert [r["context_digest"] for r in runs[0]["results"]] != [
        r["context_digest"] for r in runs[1]["results"]]
