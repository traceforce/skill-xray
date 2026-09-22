# Skill X-Ray

## Overview

Skill X-Ray is a static security scanner for AI skill packages: the folders (a `SKILL.md` manifest plus bundled `scripts/`, `references/`, `hooks.json` and `.mcp.json`) that coding agents load and act on. A skill's instructions enter the agent's context and its scripts run with the agent's privileges, so a skill can read data or run code on the machine it is installed on. Skill X-Ray reads a package before it is installed and never executes it.

The product is the Go binary built from `cmd/skill-xray`. It is the counterpart of [MCP X-Ray](https://github.com/traceforce/mcp-xray), which does the same for MCP servers. Every scan builds a coverage ledger that records each file it read and each file it did not, with a reason. `--analyze` runs deterministic checks, including a pinned [OpenGrep](https://github.com/opengrep/opengrep) code lane over bundled Python, shell, JavaScript and TypeScript, and can write a validated [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) report. The tool is report-only: it writes to stdout or to the file you name and uploads nothing.

The binary was ported from a Python scanner and, before that code was retired in pull request 46, proved to produce the same findings, the same JSON and the same SARIF bytes across its fixture corpus and the benchmark test split (pull request 42); the detection contract it implements is written down in `docs/spec`.

## Installation

### Prerequisites

- [Go 1.26](https://go.dev/dl/); the module pins the `go1.26.6` toolchain and fetches it when needed
- `git` on the PATH, only when scanning a git repository target
- OpenGrep 1.29.0, only for the code lane under `--analyze`; `skill-xray install-opengrep` fetches the pinned build

### Download a release

Each tag `v<version>` publishes archives for Linux (amd64, arm64), macOS (amd64, arm64) and Windows (amd64) with their SHA-256 sums on the [Releases](https://github.com/traceforce/skill-xray/releases) page. Verify the archive against `SHA256SUMS`, unpack it and put the binary on the PATH; `skill-xray install-opengrep` then fetches the pinned engine for `--analyze`.

### Build from Source

```bash
git clone https://github.com/traceforce/skill-xray
cd skill-xray

# Build the binary into bin/ (bin/skill-xray, or bin/skill-xray.exe on Windows)
make all

# Optional: download and verify the pinned OpenGrep runtime
make install-opengrep
```

Without make, `go build -o bin/ ./cmd/skill-xray` from the repository root does what `make all` does. `make help` lists every target; they are also listed under [Develop](#develop).

## Usage

The root command also accepts the legacy `skill-xray [package] [flags]` form, which runs the same code as `scan` and keeps the legacy flags `--scan-known-skills`, `--install-opengrep` and `--version`. The two commands below produce identical output; the rest of this document uses the subcommand form.

```bash
./bin/skill-xray scan ./my-skill --analyze
./bin/skill-xray ./my-skill --analyze
```

### scan

Inventory one skill package, or analyze it with `--analyze`.

```bash
# Inventory and coverage ledger
./bin/skill-xray scan ./my-skill

# Findings from the deterministic checks and the OpenGrep code lane
./bin/skill-xray scan ./my-skill --analyze

# JSON, with capability context and raw candidates
./bin/skill-xray scan ./my-skill --analyze --json --enrich

# SARIF outside the scanned package, with an operator policy
./bin/skill-xray scan ./my-skill --analyze --sarif ../reports/my-skill.sarif --policy ../reviewed-policy.json
```

The target may be a directory, a single file such as `SKILL.md`, a `.zip` archive, an `https://` URL, or a git repository (a `.git` suffix, or a `git@`, `git://` or `ssh://` address). Directory, file and zip inputs are fully offline. URL and git inputs are the only ones that use the network; each enforces size, count and SSRF limits and fails closed. Tar archives are refused; unpack them and scan the directory.

| flag | effect |
|---|---|
| `--analyze` | run the detection engines and report findings instead of the inventory |
| `--json` | emit JSON instead of text |
| `--enrich` | add capability context and raw candidates; requires `--analyze --json` |
| `--sarif <path>` | write a validated SARIF report; requires `--analyze`; the path must be outside the scanned package |
| `--policy <path>` | a scoped operator policy applied to the SARIF dispositions; requires `--sarif` |
| `--opengrep-bin <path>` | an explicit OpenGrep binary; requires `--analyze` and must still match the pinned size and SHA-256 |
| `--llm` | the opt-in LLM adjudication pass; sends skill text to the configured provider (see [Configuration](#configuration)); requires `--analyze` |
| `--llm-shadow`, `--llm-review`, `--llm-apply`, `--llm-additive` | LLM review modes; all require `--llm --analyze --json`, `--llm-apply` also requires `--llm-review`, and `--llm-additive` requires `--llm-shadow` or `--llm-review` |

Exit code 0 means the scan and any report completed, even with critical findings; there is no severity gate. Exit code 2 means a usage error, a refused or failed ingest, a failed SARIF validation or write, a context error, or a high-severity analysis gap such as an unavailable OpenGrep binary when the package ships executable code.

### system-scan

Discover every skill package under the roots the common coding agents load skills from, analyze each one as `scan --analyze` would, and print a verdict per package: `BLOCKING` for a high or critical finding with a vector, `FINDINGS` for anything else reported, `CLEAN` for nothing.

```bash
./bin/skill-xray system-scan
./bin/skill-xray system-scan --json
./bin/skill-xray system-scan --sarif ../reports/installed-skills.sarif

# Scan the packages under one or more directories instead of the known roots
./bin/skill-xray system-scan --root ./vendored-skills --root ~/.claude/skills --json
```

| flag | effect |
|---|---|
| `--root <dir>` | scan the packages under this directory instead of the known roots; repeatable |
| `--json` | emit one JSON object instead of text (see [Output Format](#output-format)) |
| `--sarif <path>` | write one validated SARIF document with one run per package; the path must be outside every scanned package |
| `--opengrep-bin <path>` | an explicit OpenGrep binary; it must still match the pinned size and SHA-256 |

The roots are `~/.claude/skills`, `~/.claude/plugins`, `~/.config/opencode/skills`, `~/.cursor/skills`, `~/.gemini/skills`, `~/.codex/skills`, `~/.copilot/skills`, `~/.agents/skills` and the project-local `.claude/skills`, `.opencode/skills`, `.cursor/skills`, `.gemini/skills`, `.codex/skills`, `.github/skills` and `.agents/skills`. A package is a directory holding a `SKILL.md` or a plugin marker; once found, its subtree is not searched further. Discovery follows a symlinked root but no nested symlink, and stops at fixed directory and entry budgets. A root that does not exist, or is not a directory, is skipped; a root that could not be walked is reported on stderr and the exit code is 2. Exit code 0 means every package was analyzed completely and discovery was complete, whatever the verdicts; exit code 2 means a usage error, a failed SARIF write, a discovery gap, or an incomplete analysis of any package.

`skill-xray --scan-known-skills [--json]` is the legacy inventory-only walk of the same roots: it prints one line per package with its ledger counts and runs no detection engine; `--json` carries each package's full ledger.

### install-opengrep

Download the pinned OpenGrep 1.29.0 release for this platform from the OpenGrep GitHub releases, check its size and SHA-256 against the values built into the binary, and place it in the cache.

```bash
./bin/skill-xray install-opengrep
# installed OpenGrep 1.29.0 at <cache path>
```

Pinned builds exist for Windows x86_64, Linux x86_64 and aarch64, and macOS x86_64 and arm64. The cache is `%LOCALAPPDATA%\skill-xray\opengrep\1.29.0` on Windows, `~/Library/Caches/skill-xray/opengrep/1.29.0` on macOS, and `$XDG_CACHE_HOME` or `~/.cache` followed by `skill-xray/opengrep/1.29.0` elsewhere. `make install-opengrep` builds the binary and runs this subcommand. The legacy form is `skill-xray --install-opengrep`.

Under `--analyze` the code lane resolves the engine in this order: `--opengrep-bin`, then `SKILL_XRAY_OPENGREP_BIN`, then the cache, then `opengrep` on the PATH. Every candidate must match the pinned size and SHA-256. When none resolves and the package ships executable code, the scan still runs and reports a high-severity `opengrep-unavailable` coverage gap; an explicit candidate that is missing or fails verification reports `opengrep-unverified`.

### version

```bash
./bin/skill-xray version
# skill-xray 0.1.0
```

The legacy form is `skill-xray --version`.

## Output Format

### Text

Text output is the default. The inventory prints `package: <name>`, one line with the ledger counts (`seen`, `analyzed`, `skipped`, `coverage`), and one line per artifact marked `read` or `SKIP` with its kind and, for a skip, the reason. With `--analyze` the package line is followed by one line per finding, `[SEVERITY ] vector  rule path: message  Lline:column`, with the severity padded to eight characters and the location omitted when it is unknown, or by the single line `no findings`. `system-scan` prints one line per package, `VERDICT  seen=N analyzed=N cov=P%  path`, then `package: <name>` followed by that package's findings or `no findings`, and ends with a summary line of the package, blocking, with-findings, clean and discovery-exception counts. Attacker-controlled names such as paths are escaped before printing so a control character cannot hide a file.

### JSON

`--json` emits one object with `package`, `identity`, `source`, `kind` (`directory`, `file`, `zip`, `url` or `git`) and `ledger`. The ledger carries `artifactsSeen`, `artifactsAnalyzed`, `artifactsSkipped`, `artifactsNotInspectable`, `artifactsFailedRead`, `inspectableDenominator`, `coveragePercent`, `byRole`, the lists `shippedCompiledCode`, `agentIdentityFiles`, `opaqueContent`, `secretMaterial` and `agentConfig`, and `exceptions`: one record per file or directory it did not read, with `outcome`, `phase`, `reasonCode` and `path`. Without `--analyze` the object also carries `artifacts`, one row per file with `rel`, `role`, `kind`, `read` and `exception`.

With `--analyze` the object carries `analysis` (`opengrepVersion`, plus `llmCoverage` when `--llm` is set) and `findings`, each with `vector`, `rule`, `severity`, `path`, `message` and, when known, `line`, `column`, `offset`, `length` and `evidence`. A finding with an empty `vector` is a coverage or scanner diagnostic, not a detected vulnerability. `--enrich` adds `enrichment`: raw candidates, correlated results, capability contexts, dispositions and LLM audit data. IDs inside `enrichment` are scan-local, not baseline identities.

`system-scan --json` emits one object with `schema_version` (`system-scan-v1`), `roots`, `discovery` (the `paths` found and any `ledgerExceptions`), `packages` (one row per package with `package`, `path`, `verdict`, `ledger`, `analysis` and `findings`) and `summary` (`packages`, `blocking`, `withFindings`, `clean`). The legacy `--scan-known-skills --json` emits an array of `{package, path, ledger}` rows.

### SARIF

`--sarif <path>` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) document validated against the OASIS schema embedded in the binary before a byte is written. No schema download or preparation step is needed. `scan` writes one run; `system-scan` writes one file with one run per discovered package. Each run names the driver `skill-xray` with its version and rules, uses `columnKind: unicodeCodePoints`, and carries run properties for `opengrepVersion`, `rulesetDigest`, `policyVersion`, `package` (name and content digest), `coverage`, `contextErrors`, `capabilityContexts`, `rawCandidates`, `candidateLinks` and, when LLM review ran, `llmReview`. Each result has a readable rule ID, a stable fingerprint, a severity, bounded evidence, source locations and a `properties.category` of `security-finding` or `analysis-diagnostic`. Results suppressed or demoted by an operator policy stay in the report under native `suppressions` with the reason.

The report and the operator policy must be outside the scanned package, and the report's parent directory must exist. The writer validates, then replaces the target atomically through a temporary file in the same directory; a failed validation or write leaves any previous report untouched and exits 2. Reports over 64 MiB fail instead of truncating. Output is canonical ASCII JSON with sorted keys, so with the LLM layer off identical inputs and configuration produce byte-identical reports. Source evidence can contain credentials; treat reports as sensitive.

An operator policy is a JSON object of at most 512 KiB with `"version": "skill-xray/scoped-policy/v1"` and a `decisions` list. Each decision names one result by `rule_id`, `path`, `fingerprint` and `context_digest` and either suppresses it or demotes it to a lower `effective_severity`, with a `reason`. All four identity fields must match; there is no vector-wide ignore and no wildcard. [docs/reporting.md](docs/reporting.md) describes result identity, the decision format and the failure semantics.

## Examples

```bash
# Inventory a directory
./bin/skill-xray scan ./demo-skill
# package: demo-skill
#   seen=2 analyzed=2 skipped=0 coverage=100.0%
#   read  SKILL.md                                 skill_manifest
#   read  scripts/setup.sh                         script_shell

# Analyze it
./bin/skill-xray scan ./demo-skill --analyze
# package: demo-skill
#   [HIGH    ] SXV-023  opengrep-credential-read scripts/setup.sh: Shell code reads a private credential file.  L2:1

# Analyze a zip, an https URL and a git repository
./bin/skill-xray scan ./demo-skill.zip --analyze
./bin/skill-xray scan https://example.com/demo-skill.zip --analyze --json
./bin/skill-xray scan https://github.com/example/demo-skill.git --analyze

# SARIF for CI, with a reviewed policy kept outside the package
./bin/skill-xray scan ./demo-skill --analyze --sarif ../reports/demo-skill.sarif --policy ../policy.json

# Every skill installed on this machine
./bin/skill-xray system-scan --sarif ../reports/installed-skills.sarif
```

## Configuration

### Environment Variables

The LLM layer runs only when `--llm` is passed with `SKILLXRAY_LLM_PROVIDER` and an API key set in the environment; `--llm` without them is a usage error, and without `--llm` the layer is off whatever the environment holds. It sends the text of the scanned skill files to the configured provider, so do not use it on confidential packages. Its verdicts are advisory and capped at medium severity; the deterministic verdict is unchanged.

| variable | meaning |
|---|---|
| `SKILLXRAY_LLM_PROVIDER` | `anthropic`, `openai` or `openai-compatible` |
| `SKILLXRAY_LLM_API_KEY` | the API key; on a vendor's own default endpoint `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is the fallback, never on a custom base URL |
| `SKILLXRAY_LLM_MODEL` | the model; defaults to `claude-haiku-4-5` for anthropic and `gpt-5-mini` for openai; required for openai-compatible |
| `SKILLXRAY_LLM_BASE_URL` | an https endpoint origin with no userinfo, query or fragment; defaults to the vendor endpoint; required for openai-compatible |
| `SKILL_XRAY_OPENGREP_BIN` | an OpenGrep binary to use instead of the cache; it must still match the pinned size and SHA-256 |

```bash
export SKILLXRAY_LLM_PROVIDER=anthropic
export SKILLXRAY_LLM_API_KEY=your-api-key
./bin/skill-xray scan ./my-skill --analyze --json --llm --llm-review
```

## Detection vectors

Each deterministic finding names a vector (`SXV-nnn`), a rule and a severity. The deterministic verdict is byte-for-byte reproducible. Analysis gaps stay visible as findings with an empty vector rather than disappearing. These rules keep "risky" apart from "malicious" in the deterministic lanes:

| vector | reports | severity |
|---|---|---|
| SXV-009 / SXV-041 | an installer-shaped HTTPS fetch (`curl -fsSL https://cli.vendor.com/install.sh \| sh`: one URL, a named installer path or bare host, no `user@`, no TLS bypass, no IP, no paste/tunnel/shortener or placeholder host, no shell substitution in the fetch) as an unpinned remote install | medium |
| SXV-032 | a read of the skill's own install directory under an agent's skills tree (`ls ~/.claude/skills/<its own name>/...`), which is its own files, not another agent's state | medium |
| SXV-033 | permission understatement, a T3 capability-consistency signal | medium |
| SXV-042 | a prose directive to run a script shipped with the skill, framed as hidden from the user (`covert-bundled-script-run`) or as an unconditional precondition of every task (`coerced-bundled-preflight`) | high; medium with a single coercion cue |
| SXV-043 | a prose directive to obtain the user's data and send it to an e-mail address or URL hard-coded in the skill text | high |
| SXV-044 | a shipped JavaScript or TypeScript script that is one machine-generated line: an obfuscator's hex identifiers and escaped string tables (`obfuscated-script`), or a minifier's output outside a declared `.min.js` (`minified-script`); vendor and build directories are excluded upstream | high; medium when only minified |

### Capability context and LLM review

`scan <target> --analyze --json --enrich` adds manifest-scoped claimed/declared/observed execution and network context. Claims recognize complete supported English statements in descriptions or self-referential manifest prose. Observations reuse validated OpenGrep and preprocessing evidence. Unknown is not denied or safe; claims and grants never authorize behavior.

`--llm --llm-shadow` reviews supported SXV-028/029/030/031 text-pattern candidates with their rule contract, evidence, nearby source and untrusted governing description. No candidates means no calls; identical evidence shares a review. Verdicts are `retain_finding`, `propose_false_positive` or `insufficient_context`. False-positive proposals must identify a missing rule condition; contradictory responses are rejected. This validates the response contract, not model reasoning. Other rules stay ineligible.

`--llm --llm-review` annotates qualifying false-positive proposals as `llm-disputed`. A dispute requires high confidence, an unsupported mechanism, legitimate context, a configured model and complete bounded source. Redacted, oversized or externally linked context blocks disputes, as do source/manifest/global failures and semantic limitations. Unrelated file failures remain visible but do not block intact candidates. Mechanical findings and coverage notes cannot be disputed. Neither mode removes or downgrades findings by default; attacker-controlled text can mislead the model. Do not suppress disputed findings in CI. Confidence is uncalibrated, real-model quality is unvalidated, and unchanged findings have unchanged precision. Shadow and annotated modes are mutually exclusive.

`--llm --llm-review --llm-apply` is a further opt-in that lets a validated dispute demote the one SXV-028/029/030/031 result it covers to `low`, recorded as `corrected` with `llm-review-policy` provenance. It never suppresses, never raises and never touches a mechanically anchored or protected result; see [docs/reporting.md](docs/reporting.md).

`--llm` without either review flag keeps the additive SXV-038 behavior. Add `--llm-additive` to run it after candidate review. Both share 25 logical calls and 1 MiB of input per scan; HTTP retries are separately bounded. SXV-038 is not reviewed. The client pins `temperature: 0` (and OpenAI's best-effort `seed`) where the model accepts them. That removes one source of variance, not all of it, so the LLM verdict stays advisory and medium-capped.

JSON `enrichment` preserves emitted raw candidates, context, proposals, dispositions, tags/reasons/policy, provider/model, sanitized requests, prompt/schema/response hashes and budget/error information. Analyzer caps and deduplication still apply; coverage notes remain visible. Raw candidates are deterministic only; additive findings and error notes remain in `findings`.

LLM use sends skill text to the configured provider. Credential redaction is best-effort, not a guarantee; do not send confidential packages on that assumption. Mock tests establish integration behavior, not real-model precision or recall.

## Coverage ledger

The walker reads a package it does not trust, so:

- it caps per-file size, file count, and total bytes read, so a crafted package cannot make it hang or run out of memory;
- it does not follow a symlink or an NTFS junction out of the package directory;
- it does not open a FIFO, device, or socket (a `read()` on a FIFO never returns);
- it inventories shipped compiled and native code (`.pyc`/`.pyo`/`.pyd`, `.so`/`.dylib`/`.dll`/`.exe`/`.wasm`, `.jar`/`.class`/`.node`, and versioned `.so.N`) instead of dropping it, and lists it under `shippedCompiledCode`, so a full text-coverage number can never hide unreviewable executable code;
- it surfaces active or opaque content (`.svg`, `.pdf`, nested archives) under `opaqueContent` and counts it against coverage, and surfaces shipped secrets and agent/MCP config under `secretMaterial` and `agentConfig`;
- it records every file it does not read, with a reason, and a skipped file lowers the reported coverage unless it is an inert asset, compiled code, or an excluded cache directory (a bundled `node_modules`/`dist`/`build` does lower it).

The ledger with its counts and exception records is printed by every inventory and carried in every `--json` object; every SARIF run carries the coverage status under `coverage`, `no-reported-gap` or `incomplete`, and each analysis gap is a result of its own, so a report can never look complete while files went unread.

## Develop

```bash
make ci        # what CI runs: go build ./..., go vet ./..., go test ./...
make test      # go test ./...
make lint      # go vet plus staticcheck
make fuzz      # every fuzz target for FUZZTIME (default 30s); a crasher lands in <pkg>/testdata/fuzz/
make clean     # remove bin/
```

A pushed tag `v<version>` runs the release workflow: it checks that the tag names the version in `internal/metadata`, builds the five platform archives and publishes them with their checksums. CI runs the Go job on Linux, macOS and Windows. Each OS exercises a different part: the symlink tests run on Linux and macOS, the NTFS junction test runs on Windows, and macOS is where filenames arrive in a different Unicode form (NFD instead of NFC).

## Layout

```
cmd/skill-xray/          the CLI: main.go (root command, scan, install-opengrep, version), system.go (system-scan)
internal/
  ingest                 walk, decode, classify, and build the coverage ledger
  parse                  the parsed intermediate representation every check reads
  checks                 the check registry plus the coverage and metadata notes
  preproc, grants, hooks, persistence, supplychain, forensics, instruction, obfuscation
                         one package per deterministic detection lane
  codelane, opengrep     select the executable code and drive the pinned OpenGrep engine over it
  capability             manifest-scoped capability context
  correlate              link equivalent candidates into one result and apply dispositions
  findings               the finding type and the per-scan caps
  llm                    the opt-in LLM layer: configuration, HTTP client, review policy
  sarif                  SARIF 2.1.0 writer with the embedded OASIS schema
  scan                   run every check over a parsed package
  metadata               the tool version
  pytext, pyast, pep508, uba
                         Python, CPython AST, PEP 508 and Unicode bidi semantics the port reproduces
  testutil               helpers shared by every package's tests
docs/spec/               the detection specification, one file per group; 00-overview.md is the binding contract
docs/reporting.md        result identity, operator decisions and SARIF semantics
Makefile                 all, build, install-opengrep, test, lint, vuln, ci, fuzz, clean, help
```

## Contributing

Contributions are welcome. Please ensure that:

1. `make ci` passes: it builds, vets and tests every package.
2. `make lint` passes: `go vet` plus staticcheck.
3. Detection behaviour follows `docs/spec`. A change to detection lands with its tests and the matching spec update, and says what it did to the benchmark.
4. Documentation is updated.

## References

- [MCP X-Ray](https://github.com/traceforce/mcp-xray)
- [Reporting guide](docs/reporting.md)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [OpenGrep](https://github.com/opengrep/opengrep)
