# MaliciousSkillBench harness

Runs skill-xray over `ProtectSkills/MaliciousSkillBench` (pinned revision
`d4b42ce5766a6e0359c987cf59c1007cb3795a90`, the one Cisco skill-scanner's tuning PR pins).
The scanner is static; nothing in the corpus is executed.

## Get the data (35 MB, Parquet)

```python
from huggingface_hub import hf_hub_download
REV = "d4b42ce5766a6e0359c987cf59c1007cb3795a90"
for f in ("primary.parquet", "splits/source_disjoint.parquet", "attack_taxonomy.parquet",
          "metadata.parquet"):
    hf_hub_download("ProtectSkills/MaliciousSkillBench", f, repo_type="dataset",
                    revision=REV, local_dir="msb")
```

## Deterministic run and score

```bash
python benchmark/msb_run.py --data msb --split test --out out/test.jsonl
python benchmark/msb_score.py out/test.jsonl --md out/test.md
```

`--split test` is the 1,384-record source-disjoint held-out split (identical to Cisco's);
`--split dev` is train+validation (8,348). Each identity is written as a one-file package
(`SKILL.md` = `skill_text`) into a scratch dir, scanned in-process, and deleted. Rows record
findings with vector/rule/severity/tier, per-record errors and oversize texts (ingest skips
files over 1 MiB), so nothing unanalyzed is counted as clean.

The headline verdict is **T1/T2 vector at high/critical** (Cisco's HIGH/CRITICAL blocking
threshold plus the attack tiers). MEDIUM+ and any-finding are reported alongside. T3
capability/hygiene findings never count as a malicious verdict.

Before/after on the same identities (a per-record diff, exact because detection is additive
and deterministic):

```bash
python benchmark/msb_score.py out/after.jsonl --compare out/before.jsonl --md out/delta.md
python benchmark/msb_score.py out/after.jsonl --exclude-vectors SXV-042   # rebuild pre-detector view
```

## LLM experiments (opt-in, sends skill text to your provider)

Set the provider in the environment first (the harness refuses to start without it):

```bash
export SKILLXRAY_LLM_PROVIDER=anthropic          # or openai | openai-compatible
export SKILLXRAY_LLM_API_KEY=...                 # ANTHROPIC_API_KEY / OPENAI_API_KEY also work
                                                 # on the vendor's own default host
export SKILLXRAY_LLM_MODEL=...                   # optional; per-provider default otherwise
export SKILLXRAY_LLM_BASE_URL=https://...        # required for openai-compatible, https only
```

The client pins `temperature: 0` (plus OpenAI's best-effort `seed`) for every model that accepts
them; reasoning models reject the fields. Measure agreement between two runs with
`benchmark/msb_llm_repro.py run_a.jsonl run_b.jsonl` rather than assuming it, and prefer a
non-reasoning model: hidden reasoning can exhaust the output cap and truncate the JSON.

Then:

```bash
# precision experiment: annotated review + --llm-apply demotion, only on records the
# deterministic run flagged (cheap; a validated dispute lowers effective severity)
python benchmark/msb_run.py --data msb --split test --llm-mode review \
    --only-flagged out/test.jsonl --out out/test_review.jsonl
python benchmark/msb_score.py out/test_review.jsonl --effective --compare out/test.jsonl

# recall experiment: the SXV-038 semantic pass on every record (severity-capped at medium,
# so it can only move the MEDIUM+ view, never the HIGH/CRITICAL verdict)
python benchmark/msb_run.py --data msb --split test --llm-mode additive --out out/test_add.jsonl
python benchmark/msb_score.py out/test_add.jsonl --effective --compare out/test.jsonl
```

`--llm-mode both` runs review + apply and then the additive pass on the remaining shared
budget (25 logical calls per scan). LLM modes default to 4 workers to respect rate limits.
`--fake-llm` exercises the same code path with a canned in-process client for plumbing checks
only; never report its numbers.

Cost guide: review mode makes one call per eligible directive candidate (few); additive mode
makes about one call per record (1,384 on test, 8,348 on dev).

### Attribute what the LLM changed

```bash
python benchmark/msb_llm_attrib.py out/test_both.jsonl --base out/test.jsonl --md out/test_llm.md
```

Recomputes every package verdict four ways from the same rows (deterministic, review only,
additive only, both) at the blocking, HIGH+ and MEDIUM+ thresholds, so each verdict flip is
attributed to exactly one lane. It also reports judge quality from the per-decision records
the harness writes in LLM modes (`review_decisions`: vector, status, `failure_reason` such as
`inconsistent-verdict` or `evidence-quote`, and the proposal's verdict/confidence/mechanism/
intent), every dispute the judge raised on a *malicious* package, SXV-038 hits by label and
severity, the fail-closed `llm-*` coverage notes, and an order-of-magnitude spend estimate
(`--price-in/--price-out`, USD per million tokens; defaults are gpt-4.1-mini list prices).
