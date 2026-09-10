# skill-xray

A static security scanner for AI skill packages: the folders (a `SKILL.md` file
plus bundled `scripts/`, `references/`, `hooks.json`, `.mcp.json`) that agents
load and act on. A skill's instructions enter the agent's context and its
scripts run with the agent's privileges, so a skill can read data or run code on
the machine it is installed on. skill-xray reads the package before install and
does not execute it.

It is the counterpart of `mcp-xray`, which does the same for MCP servers.

## Status

Ingest builds an inventory and coverage ledger. Parsing produces the shared IR;
`--analyze` runs deterministic checks, including the pinned OpenGrep code lane.
Analysis gaps remain visible in the findings. The scanner does not execute the
package. SARIF output is not implemented.

The walker reads a package it does not trust, so:

- it caps per-file size, file count, and total bytes read, so a crafted package
  cannot make it hang or run out of memory;
- it does not follow a symlink or an NTFS junction out of the package directory;
- it does not open a FIFO, device, or socket (a `read()` on a FIFO never
  returns);
- it inventories shipped compiled and native code (`.pyc`/`.pyo`/`.pyd`,
  `.so`/`.dylib`/`.dll`/`.exe`/`.wasm`, `.jar`/`.class`/`.node`, and versioned
  `.so.N`) instead of dropping it, and lists it under `shippedCompiledCode`, so a
  full text-coverage number can never hide unreviewable executable code;
- it surfaces active or opaque content (`.svg`, `.pdf`, nested archives) under
  `opaqueContent` and counts it against coverage, and surfaces shipped secrets and
  agent/MCP config under `secretMaterial` and `agentConfig`;
- it records every file it does not read, with a reason, and a skipped file lowers
  the reported coverage unless it is an inert asset, compiled code, or an excluded
  cache directory (a bundled `node_modules`/`dist`/`build` does lower it).

## Use

```bash
pip install -e .
skill-xray <package-dir>            # a directory
skill-xray <path>/SKILL.md          # a single file
skill-xray <path>/skill.zip         # a .zip archive
skill-xray https://host/skill.zip   # an https URL
skill-xray https://github.com/u/r.git   # a git repository
skill-xray --scan-known-skills      # find and scan every skill under the known agent roots
skill-xray <target> --json          # JSON output
```

Directory, file and zip are fully offline. URL and git are the only inputs that
use the network; each enforces size, count and SSRF limits and fails closed.

### Capability context and LLM review

`skill-xray <target> --analyze --json --enrich` adds manifest-scoped
claimed/declared/observed execution and network context. Unknown does not mean
denied or safe. Claims require complete supported English statements in descriptions
or self-referential manifest prose; ambiguous wording stays unknown. Observations
reuse OpenGrep validation and mechanical preprocessing findings, not a new detector.
Claims and grants never authorize a finding's behavior.

Add `--llm --llm-shadow` to request non-authoritative review of supported
SXV-028/029/030/031 text-pattern findings using the configured LLM client.
Shadow mode sends static candidates only; no candidates means no model calls.
It supplies the rule's security condition, matched evidence, nearby source and
the governing description. Descriptions remain untrusted, not authorization.
Identical findings share a review within the scan; each raw candidate remains available.
Verdicts are `retain_finding`, `propose_false_positive` or `insufficient_context`.
A false-positive proposal must identify a missing rule condition; contradictory
mechanism/intent fields are rejected. This validates the response contract, not
the truth of the model's reasoning. No proposal changes deterministic findings.
Other rule types remain explicitly ineligible, not adjudicated or cleared.

`--llm --llm-review` annotates qualifying false-positive proposals as `llm-disputed`.
It never removes a finding or changes its severity: attacker-controlled skill text may
mislead the reviewer. A dispute requires high confidence, an unsupported rule mechanism,
legitimate context, a configured model and complete bounded source context. Uncertain,
redacted, linked-outside-context, failed, capped or oversized cases receive no dispute.
Raw candidates and final findings remain intact. `dispositions` records tags, reasons,
policy, configured provider/model, sanitized requests and prompt/schema/response hashes.
Exact duplicates share a review. Mechanical findings and coverage/error notes cannot be disputed.
Confidence is the model's assessment, not calibration. Review annotations do not improve
the precision of the unchanged finding set; real-model dispute quality remains unvalidated.
Do not automatically suppress or downgrade findings based on a dispute tag in downstream CI.
Shadow and annotated review modes are mutually exclusive; the existing `scan()` API is unchanged.

`--llm` without either review flag keeps the existing additive SXV-038 behavior.
To run both, add `--llm-additive`; SXV-038 then uses the budget left after candidate
review. Both share 25 logical calls and 1 MiB of input per scan; HTTP retries
remain separately bounded. Candidate review does not adjudicate SXV-038 outputs.

The JSON `enrichment` object preserves emitted raw candidates, scoped context,
proposals, sanitized request snapshots and budget/error information. Candidate
IDs are local to one scan, not stable baseline identities. Upstream analyzer
caps and deduplication still apply and their coverage notes remain visible.
The Python `scan()` API is unchanged; `scan_report()` provides enrichment.
`raw_candidates` contains deterministic results only; additive LLM findings and
error notes remain in `findings`.

LLM use sends skill text to the configured provider. Credential redaction is
best-effort, not a guarantee; do not send confidential packages on that assumption.
Mock tests establish integration behavior, not real-model precision or recall.

## Develop

Requires Python 3.12.4 or newer: the junction check uses `os.path.isjunction`
(added in 3.12), and the SSRF guard relies on the `ipaddress.is_global` fix for
IPv4-mapped addresses shipped in 3.12.4 (CVE-2024-4032).

```bash
python -m ruff check .        # lint
python dev/deadcode.py src    # unused top-level symbols
python -m pytest tests        # tests
```

CI runs on Linux, macOS, and Windows. Each OS runs a different part: the symlink
tests run on Linux and macOS, the NTFS junction test runs on Windows, and macOS
is where filenames arrive in a different Unicode form (NFD vs NFC).

## Layout

```
src/skill_xray/
  ingest.py   walk, decode, classify, and build the ledger
  parse.py    parse each artifact once into one shared IR (real parser per format), fail closed
  resolve.py  turn a directory/file/zip/URL/git target into a local dir, with caps
  cli.py      inventory a target and print the ledger
tests/
  test_ingest.py   walker tests, including the symlink, junction, and FIFO cases
  test_parse.py    parse-layer tests: markdown, frontmatter, grants, shell, deps, refs, hardening
  test_resolve.py  input-resolver tests: zip-slip, zip-bomb, SSRF, git guard
  test_cli.py      CLI tests
dev/
  deadcode.py      unused-symbol check, also run in CI
```
