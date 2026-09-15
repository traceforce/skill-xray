"""Frozen native microcorpus through reporting; fixtures are never executed."""

import json
import sys
import tracemalloc
from time import perf_counter

import pytest
from test_postdetect_microcorpus import _CASES, MANIFEST_SHA256

from skill_xray import ingest, parse, scan, scan_report
from skill_xray.sarif import build_sarif, encode_sarif

scanmod = sys.modules["skill_xray.scan"]


@pytest.mark.parametrize("name", _CASES)
def test_native_sarif_accounts_for_every_candidate(make_package, name, monkeypatch):
    outputs = []
    durations = []
    captured = []
    original = scanmod.run_checks
    def recording(*args, **kwargs):
        findings = list(original(*args, **kwargs))
        captured[:] = findings
        return findings
    monkeypatch.setattr(scanmod, "run_checks", recording)
    tracemalloc.start()
    try:
        for _ in range(2):
            started = perf_counter()
            parsed = parse.parse_package(ingest.build_package(make_package(_CASES[name])))
            report = scan_report(parsed)
            output = build_sarif(parsed, report)
            outputs.append(encode_sarif(output))
            durations.append(perf_counter() - started)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert outputs[0] == outputs[1]
    monkeypatch.setattr(scanmod, "run_checks", lambda *_a, **_kw: captured)
    assert scan(parsed) == report.findings
    run = output["runs"][0]
    raw, links = run["properties"]["rawCandidates"], run["properties"]["candidateLinks"]
    assert len(raw) == len(report.raw_candidates) == len(links)
    assert {c["candidate_id"] for c in raw} == {link["candidate_id"] for link in links}
    assert all(r["properties"]["disposition"] == "reported" for r in run["results"])
    assert not report.context_errors
    print(json.dumps({"sample": name, "manifest_sha256": MANIFEST_SHA256,
                      "raw": len(raw), "results": len(run["results"]), "sarif": len(run["results"]),
                      "duplicates": sum(link["disposition"] == "duplicate" for link in links),
                      "suppressed": 0, "changed_severity": 0, "lost": 0,
                      "raw_incomplete": sum(not c["finding"]["vector"] for c in raw),
                      "context_incomplete": sum(r["properties"]["coverage"] == "incomplete"
                                                for r in run["results"]),
                      "schema_errors": 0, "seconds": durations, "python_peak_bytes": peak,
                      "sarif_bytes": len(outputs[0])}))
