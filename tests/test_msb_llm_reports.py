"""The LLM attribution and reproducibility reports state their scope instead of implying it."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "benchmark"))

import msb_llm_attrib  # noqa: E402
import msb_llm_repro  # noqa: E402

_NO_LANES = {"review": False, "additive": False}


def _row(bid, label, findings=()):
    return {"benchmark_id": bid, "label": label, "findings": list(findings)}


def _hit038():
    return {"vector": "SXV-038", "rule": "llm-semantic", "severity": "medium", "tier": "T3"}


@pytest.mark.parametrize("n", [0, 1, 3])
def test_verdict_section_states_record_population(n):
    rows = [_row("b%d" % i, 0) for i in range(n)]
    out = msb_llm_attrib._verdict_section(rows, _NO_LANES)
    assert out[2] == ("Rates are over the %d records in this file; an --only-flagged run is a "
                      "subset of the split." % n)


@pytest.mark.parametrize("findings, expect_note, expect_jaccard", [
    ((), True, False),
    ((_hit038(),), False, True),
])
def test_repro_empty_union_prints_note_not_jaccard(findings, expect_note, expect_jaccard):
    a = {"x": _row("x", 1, findings), "y": _row("y", 0)}
    b = {"x": _row("x", 1, findings), "y": _row("y", 0)}
    text = "\n".join(msb_llm_repro.compare("a.jsonl", a, "b.jsonl", b))
    note = "SXV-038 hit sets: no packages hit this set in either run."
    jaccard = "Jaccard agreement of the SXV-038 hit sets: **1.0000**"
    assert (note in text) is expect_note
    assert (jaccard in text) is expect_jaccard
