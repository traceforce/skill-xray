"""A benign record whose LLM lane did not run is unanalyzed, not a verified true negative."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "benchmark"))

import msb_score  # noqa: E402


def _row(label, findings=()):
    return {"benchmark_id": "b0", "label": label, "findings": list(findings)}


def _note(rule):
    return {"vector": "", "rule": rule, "severity": "low", "tier": None}


@pytest.mark.parametrize("findings, expect_incomplete, expect_tn, expect_unanalyzed", [
    ((_note("llm-error"),), True, 0, 1),
    ((_note("llm-unavailable"),), True, 0, 1),
    ((_note("llm-budget"),), True, 0, 1),
    ((_note("llm-unparseable"),), True, 0, 1),
    ((_note("llm-truncated"),), False, 1, 0),
    ((), False, 1, 0),
])
def test_llm_lane_failure_marks_benign_row_unanalyzed(findings, expect_incomplete, expect_tn,
                                                       expect_unanalyzed):
    row = _row(0, findings)
    assert msb_score.incomplete(row) is expect_incomplete
    m = msb_score.metrics([row], msb_score.VERDICTS["any finding"])
    assert (m["TN"], m["unanalyzed_benign"], m["FP"]) == (expect_tn, expect_unanalyzed, 0)
