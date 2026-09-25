# Skill X-Ray

## Overview

Skill X-Ray is a static security scanner for AI agent skill packages. A skill package is a folder with a `SKILL.md` manifest and, often, bundled `scripts/`, `references/`, a `hooks.json` or a `.mcp.json`. Coding agents such as Claude Code, Cursor, Codex, Gemini CLI and OpenCode load these folders and act on them: the instructions go straight into the agent's context and the scripts run with the agent's privileges, so a bad skill can read your data or run code on your machine. Skill X-Ray reads a package before you install it and never executes anything in it.

It is the sibling of [MCP X-Ray](https://github.com/traceforce/mcp-xray), which does the same job for MCP servers; if an MCP server is what you need to scan, use that one. Like MCP X-Ray it writes a [SARIF](https://sarifweb.azurewebsites.net/) report that SARIF-aware tools and CI pipelines can read, and it can scan one skill or every skill in the folders the common coding agents load from, in one go.

The scanner works offline with deterministic rules. A pinned [OpenGrep](https://github.com/opengrep/opengrep) engine, called the code engine in this file, covers bundled Python, POSIX shell (bash, sh, dash), JavaScript and TypeScript. An optional LLM pass, called the LLM lane in this file and in the report, adds a semantic check on top. It is off unless you ask for it, and when it is on it sends the skill text to the provider you configure.

## Installation

### Prerequisites

- A released binary runs on its own. The code engine is a separate download, described below.
- Building from source needs [Go 1.26](https://go.dev/dl/); the module pins the `go1.26.6` toolchain and fetches it when needed. The clone below uses `git`, and `make` only wraps `go build`.
- Scanning a git repository URL needs `git` on the PATH.

### Download a release

Each release `v<version>` on the [Releases](https://github.com/traceforce/skill-xray/releases) page has archives for Linux (amd64, arm64), macOS (amd64, arm64) and Windows (amd64), plus a `SHA256SUMS` file. Check the sum, unpack the archive and put `skill-xray` on your PATH. Then install the code engine. Running the command again is safe: it keeps a cached copy that passes the size and SHA-256 check and sits in a directory only you or an administrator can change, and downloads again otherwise.

```bash
skill-xray install-opengrep
```

The command downloads OpenGrep 1.29.0 for your platform, checks its size and SHA-256 against the values built into the binary, and stores it in the user cache. Without an engine the scanner still runs, but a package that ships code gets a high `opengrep-unavailable` gap in its report and exit code 2. An engine you point at explicitly that is missing, does not match the pin or sits in a directory another user could change gives the same kind of gap under the name `opengrep-unverified`. A gap is a result that records what could not be checked; [Exit codes](#exit-codes) says what exit code 2 means.

Pinned builds exist for Windows x86_64, Linux x86_64 and aarch64, and macOS x86_64 and arm64. The cache is `%LOCALAPPDATA%\skill-xray\opengrep\1.29.0` on Windows, `~/Library/Caches/skill-xray/opengrep/1.29.0` on macOS, and `$XDG_CACHE_HOME` or `~/.cache` followed by `skill-xray/opengrep/1.29.0` elsewhere. The scanner looks for the code engine in this order: `--opengrep-bin`, then `SKILL_XRAY_OPENGREP_BIN`, then the cache, then `opengrep` on the PATH; every candidate must match the pinned size and SHA-256 and sit in a directory only you or an administrator can change.

### Build from source

```bash
git clone https://github.com/traceforce/skill-xray
cd skill-xray

# Build bin/skill-xray (bin/skill-xray.exe on Windows)
make all

# Download and verify the pinned OpenGrep engine
make install-opengrep
```

Without make, `go build -o bin/ ./cmd/skill-xray` does the same as `make all`. The examples below assume `skill-xray` is on your PATH; from a source build use `./bin/skill-xray` instead.

## Usage

There are four commands. `scan` analyzes one skill package, `system-scan` analyzes every skill installed on the machine, `install-opengrep` fetches the code engine, and `version` prints the version. Both scans write one SARIF report and print one verdict line per package. The two `scan` options most people need, the LLM lane and a reviewed policy, have their own subsections below.

On Windows the same commands run from PowerShell or cmd. Write `$env:SKILLXRAY_LLM_PROVIDER = "anthropic"` where a bash example says `export SKILLXRAY_LLM_PROVIDER=anthropic`, and give `scan` a full path such as `$HOME\Downloads\deploy-helper` rather than `~/Downloads/deploy-helper`, because PowerShell does not expand `~` in that position. `--root ~/.claude/skills` works as written, since the tool expands `~` in roots itself.

### Scan one skill

Point `scan` at the skill's folder. The report lands in the working directory as `findings.sarif.json`.

```bash
# Scan the skill in ./my-skill
skill-xray scan ./my-skill

# Put the report somewhere else
skill-xray scan ./my-skill --output reports/my-skill.sarif

# A zip archive, a downloadable zip, or a git repository over https
skill-xray scan ./my-skill.zip
skill-xray scan https://example.com/my-skill.zip
skill-xray scan https://github.com/example/my-skill.git
```

| flag | what it does |
|---|---|
| `-o`, `--output <path>` | where the report is written; default `findings.sarif.json`; see [Output format](#output-format) for where it may go |
| `--policy <path>` | apply a reviewed operator policy that suppresses or demotes named results; see [Apply a reviewed policy](#apply-a-reviewed-policy) |
| `--opengrep-bin <path>` | use this OpenGrep binary instead of the cached one; it must match the pinned OpenGrep 1.29.0 size and SHA-256 and sit in a directory only you or an administrator can change |
| `--llm` | also run the LLM lane; see [Scan with the LLM lane](#scan-with-the-llm-lane) |

What it looks for: prompt-injection patterns and directives to run a bundled script covertly or as a forced precondition; directives to send your data to an address written into the skill; unpinned remote installs; obfuscated or minified scripts; permission understatement; writes that persist into agent configuration; and every analysis gap, kept visible as a result. The full list with severities is under [Detection vectors](#detection-vectors).

The target can be a directory, a single file such as `SKILL.md`, a `.zip` archive, an `https://` URL to a zip or to a single file, or a git repository given as an `https://` address ending in `.git`. `ssh://`, `git@` and `git://` addresses are refused with `git ingest supports https:// repository URLs only`. A plain `http://` address is refused as `not a directory, file, .zip, URL or git repo`, because only `https://` counts as a URL. Tar archives are refused with `unpack it and scan the directory`, so unpack those first.

Directory, file and zip scans never touch the network unless `--llm` is on, which sends the skill text to the configured provider. URL and git scans do, and they stop with exit code 2 rather than carry on when the URL redirects, the download is too large, holds too many files, or resolves to a private or local address. Give a URL that points directly at the file: a GitHub archive link such as `.../archive/refs/heads/main.zip` redirects and is refused, while its target `https://codeload.github.com/<owner>/<repo>/zip/refs/heads/main` downloads.

`scan` treats whatever you point it at as one package. A folder that holds several skills becomes one merged run named after that folder, so use `system-scan --root` for a folder of skills. A folder with no `SKILL.md` still scans and can read `CLEAN`; stderr then says `note: no SKILL.md found under <path>; nothing was evaluated as a skill manifest`, so look for that line before trusting a `CLEAN` on something you unpacked by hand.

The console shows one line per package and the report path:

```
BLOCKING  seen=4   read=4   cov=100.0%  ./my-skill
report: findings.sarif.json
```

`seen` is the number of files found, `read` the number read as text, and `cov` the share that was read. A vector is the class of behavior a rule detects (`SXV-nnn`, listed under [Detection vectors](#detection-vectors)); an analysis gap is a result with no vector that records what could not be checked (see [Coverage ledger](#coverage-ledger)). The verdict word means:

- `BLOCKING`: at least one high or critical finding that names a vector;
- `FINDINGS`: any other finding that names a vector, or an analysis gap at medium severity or above;
- `CLEAN`: neither.

The findings themselves are in the report, not on the console. Control characters and line or paragraph separators in a printed path are shown as escapes, so a file name cannot hide or split a console line.

### Scan with the LLM lane

The LLM lane is off by default. To turn it on, set a provider and an API key in the environment and pass `--llm`. It sends the text of the skill files to that provider, so do not use it on confidential packages.

```bash
# Anthropic
export SKILLXRAY_LLM_PROVIDER=anthropic
export SKILLXRAY_LLM_API_KEY=<your key>
skill-xray scan ./my-skill --llm

# OpenAI
export SKILLXRAY_LLM_PROVIDER=openai
export SKILLXRAY_LLM_API_KEY=<your key>
skill-xray scan ./my-skill --llm

# Any OpenAI-compatible endpoint needs the model and the base URL too
export SKILLXRAY_LLM_PROVIDER=openai-compatible
export SKILLXRAY_LLM_API_KEY=<your key>
export SKILLXRAY_LLM_MODEL=<model name>
export SKILLXRAY_LLM_BASE_URL=https://llm.example.com/v1
skill-xray scan ./my-skill --llm
```

With `--llm` alone the lane runs a semantic prompt-injection check (SXV-038). Its results are advisory and capped at medium severity: they can move a clean package to `FINDINGS` but not to `BLOCKING`, and they do not remove or lower a deterministic finding. If the provider is down or rejects the key, the deterministic scan still completes and the failure does not change the exit code on its own: the `llm:` console line names it, and the report records it under `llmUsage`.

The console adds one line for the lane, for example:

```
llm: 3 model calls; semantic check (SXV-038) ran
```

Three more flags turn the lane into a reviewer of the static text-pattern findings (SXV-028 to SXV-031), and a fourth keeps the semantic check running alongside the review:

| flags | effect |
|---|---|
| `--llm --llm-shadow` | the model reviews the text-pattern findings and its proposals are recorded in the report; nothing changes |
| `--llm --llm-review` | as shadow, but a validated false-positive proposal is annotated as `llm-disputed`; nothing is removed or downgraded |
| `--llm --llm-review --llm-apply` | a validated dispute may demote that one finding to `low`, recorded as `corrected`; the finding is not suppressed and its severity is not raised |
| `--llm --llm-shadow --llm-additive` or `--llm --llm-review --llm-additive` | also run the semantic SXV-038 check after the review; without it, shadow and review turn that check off. The flag needs one of the two review flags |

`--llm-shadow` and `--llm-review` exclude each other. A scan makes at most 25 model calls and sends at most 1 MiB of text per package, and `system-scan` spends that budget again for every package it finds. Do not gate CI on a disputed finding. The text the model reads while it reviews is written by the skill's author, and an author who wants a finding dismissed can write prose that argues for dismissing it.

In shadow and review mode the model sees a text-pattern candidate together with its rule contract, evidence, nearby source and the untrusted description that governs it, and answers `retain_finding`, `propose_false_positive` or `insufficient_context`. A false-positive proposal has to name the rule condition that is missing. It is accepted only with high confidence and complete, bounded source; redacted, oversized or externally linked context blocks it, and mechanical findings and coverage notes cannot be disputed at all. The client pins `temperature: 0`, and OpenAI's best-effort `seed`, where the model accepts them. That removes one source of variance, not all of it, which is why the lane stays advisory and medium-capped. Credential redaction before sending is best effort, not a guarantee.

The run properties keep the audit: `rawCandidates` holds the emitted candidates, `candidateLinks` ties each to the result that retained it, `capabilityContexts` holds the capability evidence once per manifest, and `llmReview` records each review decision with its disposition, status, reason, tags, policy version, provenance, proposal, and request and response hashes.

### Scan every skill installed on this machine

`system-scan` finds every skill package under the folders the common coding agents load skills from, scans each one as `scan` would, and writes one report with one run per package. It detects the same things as `scan`, for each package.

```bash
# Every skill installed for Claude Code, Cursor, Codex, Gemini CLI, OpenCode, Copilot and the project-local folders
skill-xray system-scan

# The same, with the report somewhere else
skill-xray system-scan --output reports/installed-skills.sarif

# Only the packages under these folders, instead of the known roots (repeatable)
skill-xray system-scan --root ./vendored-skills --root ~/.claude/skills

# With the LLM lane, for every package found
skill-xray system-scan --llm
```

The known roots are `~/.claude/skills`, `~/.claude/plugins`, `~/.config/opencode/skills`, `~/.cursor/skills`, `~/.gemini/skills`, `~/.codex/skills`, `~/.copilot/skills`, `~/.agents/skills`, and in the current project `.claude/skills`, `.opencode/skills`, `.cursor/skills`, `.gemini/skills`, `.codex/skills`, `.github/skills` and `.agents/skills`. A known root that does not exist is skipped.

A package is a directory holding a `SKILL.md` or one of the plugin markers `.claude-plugin`, `.codex-plugin`, `plugin.json`, `.mcp.json` or `hooks.json`; once found, its subtree is not searched further.

A `--root` you name must exist and be a directory. A mistyped one is not refused up front: the run continues over the other roots, the report is still written, the summary counts it under `discovery exceptions`, stderr prints `skill discovery incomplete (root_missing): <path>`, and the exit code is 2. A typo therefore never passes as a clean run.

The console shows one verdict line per package, then the report path and a summary:

```
CLEAN     seen=3   read=3   cov=100.0%  /home/me/.claude/skills/notes
BLOCKING  seen=6   read=6   cov=100.0%  /home/me/.claude/skills/deploy-helper
report: findings.sarif.json
packages: 2, blocking: 1, with findings: 0, clean: 1, incomplete: 0, discovery exceptions: 0
```

On a Windows machine the first `system-scan` will often exit 2: a skill that ships a PowerShell, batch, zsh, Ruby or Perl script is read but not analyzed, and each such file is a high `analysis-incomplete` gap named on stderr. See [Exit codes](#exit-codes).

| flag | what it does |
|---|---|
| `--root <dir>` | scan the packages under this directory instead of the known roots; repeatable; must exist and be a directory |
| `-o`, `--output <path>` | where the report is written; default `findings.sarif.json`; must be outside every scanned package |
| `--opengrep-bin <path>` | as for `scan` |
| `--llm`, `--llm-shadow`, `--llm-review`, `--llm-apply`, `--llm-additive` | the same LLM lane as `scan`, applied to every package found |

`system-scan` has no `--policy` flag. To quiet a reviewed result in an installed skill, run `scan` on that one folder with the policy.

### Apply a reviewed policy

When you have reviewed a finding and decided it is a false positive for this package, you can suppress or demote it without touching the skill. Write a JSON policy file, keep it outside the package, and pass it to `scan` with `--policy`:

```bash
skill-xray scan ./my-skill --output reports/my-skill.sarif --policy reviews/my-skill-policy.json
```

A policy is a JSON file with a `version` of `skill-xray/scoped-policy/v1` and a `decisions` list. Each decision names one result by four fields copied from the report:

| policy field | copied from the result |
|---|---|
| `rule_id` | `ruleId` |
| `path` | `locations[0].physicalLocation.artifactLocation.uri`, percent-decoded: `dir/a%20b.py` in the report is `dir/a b.py` in the policy |
| `fingerprint` | `partialFingerprints["skill-xray/evidence/v1"]` |
| `context_digest` | `properties.contextDigest` |

`action` is `suppress`, or `demote` with a lower `effective_severity`; `reason` is free text kept in the report.

```json
{
  "version": "skill-xray/scoped-policy/v1",
  "decisions": [
    {
      "rule_id": "skill-xray/opengrep-shell-fetch-pipe-exec",
      "path": "scripts/setup.sh",
      "fingerprint": "<the result's partialFingerprints value>",
      "context_digest": "<the result's properties.contextDigest value>",
      "action": "suppress",
      "reason": "installs the vendor CLI from its documented URL; reviewed 2026-09-24"
    }
  ]
}
```

The console then adds a line such as `policy: 1 suppressed, 0 demoted, 0 of 1 decisions matched no result`. That line is how you tell a `CLEAN` that came from a suppression apart from a `CLEAN` that came from a clean package, and its last count shows when a decision no longer matches anything.

There is no vector-wide ignore and no wildcard, and any edit to the package invalidates the decision. Suppressed results stay in the report under `suppressions`; demoted ones keep the lower `level` with `properties.disposition` set to `corrected`. [docs/reporting.md](docs/reporting.md) has the full format.

### Install the code engine

`install-opengrep` downloads the pinned OpenGrep build for your platform, verifies it and stores it in the user cache. It is safe to run again.

```bash
skill-xray install-opengrep
# installed OpenGrep 1.29.0 at <cache path>
```

The platforms, the cache path and the order in which the scanner looks for an engine are under [Download a release](#download-a-release).

### Print the version

`version` prints the scanner's version; `skill-xray --version` prints the same line.

```bash
skill-xray version
# skill-xray 0.1.0
```

## Exit codes

| code | meaning |
|---|---|
| 0 | the scan and the report completed. Findings, even critical ones, do not change the exit code; read the verdict or the report for those |
| 2 | something did not complete: a usage error, a refused or failed input, a report that could not be written, a package whose analysis hit an internal error, a high-severity analysis gap, or for `system-scan` a root that could not be walked |

Every exit 2 comes with a reason on stderr: an `analysis incomplete:` line naming the package, the diagnostic and the file for each gap; a `skill discovery incomplete (<reason>):` line for a `system-scan` root that could not be walked; a `no SARIF run for <package>:` line when one package's run could not be built; or a `cannot ...` or `skill-xray: error:` line for everything else. A package whose analysis hit an internal error is reported as `FINDINGS`, not as `CLEAN`.

A script the scanner recognises but no lane can analyze, which means one in PowerShell, batch, zsh, Ruby or Perl, or an unparseable Python code fence, appears as a high `analysis-incomplete` result in the report and sets exit code 2 like any other high gap. It was read, so it does not lower the coverage number. A source file in any other language, such as Go, PHP, Rust, ksh or fish, is not treated as a script: the report records it as a low `coverage-note` with the reason `unmodeled_content`, it does not set exit code 2, and the package can still read `CLEAN` on the console. Read the report's coverage notes before trusting a `CLEAN` on a package that ships such files.

The code engine gets 45 seconds per package. A package whose code takes longer, for example one shipping more than a thousand scripts, gets a high `opengrep-timeout` gap and exit code 2 in place of its code findings, so a package can read `FINDINGS` on a slow machine where a fast one reads `BLOCKING`.

## Output format

`scan` and `system-scan` write one [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) document, validated against the OASIS schema embedded in the binary before anything is written. `scan` writes one run; `system-scan` writes one file with one run per package. Each result carries a readable rule ID, a stable fingerprint, a severity, bounded evidence, source locations, and a `properties.category` of `security-finding` or `analysis-diagnostic`. Each run also records, under its properties, what it ran with and what it saw: the OpenGrep version and ruleset digest, the package name and content digest, the coverage status, the capability context, the raw candidates and how they became results, and, with the LLM lane on, `llmUsage`, plus `llmReview` in shadow or review mode. [docs/reporting.md](docs/reporting.md) describes each field.

Where the report may go:

- The report and the policy file must be outside the scanned package, and the report's directory must exist. `scan` checks both before any file of the package is read and refuses with `cannot prepare SARIF: Report directory is missing or not a directory: <path>` or `cannot prepare SARIF: Report must be outside the scanned package`; a report path that is itself a symlink gets the second message. `system-scan` reports the second as `cannot write SARIF: ...` after discovery.
- A directory you cannot write to is found out only when the report is written, after the scan, as `cannot write SARIF: ...`.
- A policy that is missing, inside the package or not valid JSON is refused the same way, with `Operator policy ...` in place of `Report ...`.
- Nothing is written on a refusal and the exit code is 2.
- The writer validates the document first, then replaces the target through a temporary file in the same directory, so a failed run leaves an earlier report untouched. Reports over 64 MiB fail instead of being truncated.
- A scan you interrupt writes no report and can leave the engine's working directory, `skill-xray-opengrep-*`, in the system temp folder.

Output is canonical ASCII JSON with sorted keys, so with the LLM lane off the same input and configuration produce a byte-identical report; the Windows and Linux builds were compared and agree. The one known exception is a zip whose member names end in a space or a dot, which Windows renames on extraction. Source evidence can contain credentials, so treat reports as sensitive.

## Examples

```bash
# A skill you downloaded and are about to install
skill-xray scan ~/Downloads/deploy-helper
# BLOCKING  seen=3   read=3   cov=100.0%  /home/me/Downloads/deploy-helper
# report: findings.sarif.json

# A CI job: the report goes next to the checkout, a reviewed policy quiets one known false positive
skill-xray scan ./skills/release-notes --output ../reports/release-notes.sarif --policy ./reviews/release-notes.json
```

Sample reports are in [examples/findings](examples/findings/): `deploy-helper.sarif.json` is the BLOCKING scan of a small skill that ships a fetch-and-run installer, a credential-reading script and instructions to send credentials elsewhere, and `notes.sarif.json` is the CLEAN scan of a manifest-only skill. [examples/policy.json](examples/policy.json) suppresses the installer result of the first one.

## Configuration

### Environment variables

| variable | meaning |
|---|---|
| `SKILLXRAY_LLM_PROVIDER` | `anthropic`, `openai` or `openai-compatible`; required for `--llm` |
| `SKILLXRAY_LLM_API_KEY` | the API key; on a vendor's own endpoint `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is accepted as a fallback, but not on a custom base URL |
| `SKILLXRAY_LLM_MODEL` | the model; defaults to `claude-haiku-4-5` for anthropic and `gpt-4.1-mini` for openai; required for openai-compatible |
| `SKILLXRAY_LLM_BASE_URL` | an https endpoint origin, with no userinfo, query or fragment; defaults to the vendor endpoint; required for openai-compatible |
| `SKILL_XRAY_OPENGREP_BIN` | an OpenGrep binary to use instead of the cache; it must match the pinned size and SHA-256 and sit in a directory only you or an administrator can change. Note the underscore after `SKILL`, unlike the `SKILLXRAY_LLM_*` variables |

Without `--llm` the LLM variables are ignored. `--llm` without a provider and a key is a usage error.

### Supported providers

| provider | `SKILLXRAY_LLM_PROVIDER` | default model | needs |
|---|---|---|---|
| Anthropic | `anthropic` | `claude-haiku-4-5` | `SKILLXRAY_LLM_API_KEY`, or `ANTHROPIC_API_KEY` as a fallback |
| OpenAI | `openai` | `gpt-4.1-mini` | `SKILLXRAY_LLM_API_KEY`, or `OPENAI_API_KEY` as a fallback |
| Any OpenAI-compatible endpoint | `openai-compatible` | none, set `SKILLXRAY_LLM_MODEL` | `SKILLXRAY_LLM_API_KEY`, `SKILLXRAY_LLM_MODEL` and `SKILLXRAY_LLM_BASE_URL` |

The commands for each provider are under [Scan with the LLM lane](#scan-with-the-llm-lane).

### If the `llm:` line says `HTTP 404`

The model or the endpoint was not found; the line says so and points at `SKILLXRAY_LLM_MODEL` and `SKILLXRAY_LLM_BASE_URL`. On a vendor's own endpoint, pick a model the key can call. On a custom base URL, check the path as well.

## Detection vectors

Each deterministic finding names a vector (`SXV-nnn`, the class of behavior it detects), a rule and a severity. Analysis gaps stay visible as findings with an empty vector rather than disappearing. A few of the rules, chosen because they show where the line between risky and malicious is drawn:

| vector | reports | severity |
|---|---|---|
| SXV-009 / SXV-041 | an installer-style fetch piped to a shell, such as `curl -fsSL https://cli.vendor.com/install.sh \| sh`, reported as an unpinned remote install. Only the plain vendor shape matches: one HTTPS URL to a named installer path or bare host, with no credentials in the URL, no TLS bypass, no raw IP, no paste site, tunnel, shortener or placeholder host, and no shell substitution inside the fetch | medium |
| SXV-032 | a read of the skill's own install directory under an agent's skills tree, which is its own files, not another agent's state | medium |
| SXV-033 | the skill's description claims less permission than its files use (permission understatement); a capability signal, not on its own a malicious one | medium |
| SXV-042 | a prose directive to run a script shipped with the skill, framed as hidden from the user (`covert-bundled-script-run`) or as an unconditional precondition of every task (`coerced-bundled-preflight`) | high; medium with a single coercion cue |
| SXV-043 | a prose directive to obtain the user's data and send it to an e-mail address or URL hard-coded in the skill text | high |
| SXV-044 | a shipped JavaScript or TypeScript script that is one machine-generated line: an obfuscator's hex identifiers and escaped string tables (`obfuscated-script`), or a minifier's output outside a declared `.min.js` (`minified-script`) | high; medium when only minified |

### Capability context

Every report records what the package claims about its execution and network needs, what its manifest declares, and what its code was observed doing. Unknown is not treated as safe, and a claim or a grant never authorizes behavior.

## Coverage ledger

The file walker, the part of the scanner that reads the package off disk, treats every package as hostile, so:

- it caps per-file size (1 MiB), file count (5000) and total bytes read (256 MiB), so a crafted package cannot make it run out of memory. The walker and the text lanes have no time limit of their own: a Markdown file at the 1 MiB cap takes between ten seconds and a minute to analyze depending on its shape, so give a scan of a very large package a CI timeout. The code engine's 45 second deadline (see [Exit codes](#exit-codes)) and the 120 second deadline on a URL or git download cover only those steps;
- it does not follow a symlink or NTFS junction inside the package, wherever it points; each is recorded in the ledger as unread. The package root you name may itself be a symlink;
- it does not open a FIFO, device or socket;
- it inventories shipped compiled and native code (`.pyc`, `.pyo`, `.pyd`, `.so`, versioned `.so.N`, `.dylib`, `.dll`, `.exe`, `.wasm`, `.jar`, `.war`, `.class`, `.node`, `.o`, `.a`) as one `analysis-incomplete` result per file with the reason `shipped_compiled`, so a full coverage number does not hide compiled code;
- it reports content it cannot review with the reason `unreviewable_content`. An `.svg` is a low `coverage-note`, because an agent never reads it as instructions. A `.pdf` or a nested archive is a high `analysis-incomplete` gap with exit code 2, because an agent may be told to read or unpack it;
- raw HTML inside a Markdown file is a high `analysis-incomplete` gap with the reason `raw_html` when it carries text or a link label, or when it could not be read whole. Markup with no text, such as a centered image block, is a low note;
- it records every file it does not read, with a reason. A skipped file lowers the reported coverage unless it is an inert asset, compiled code or an excluded directory (`.git`, `.hg`, `.svn`, `.venv`, `venv`, `.mypy_cache`, `.pytest_cache`, `.idea`, `.tox`, `.ruff_cache`); a bundled `node_modules`, `dist`, `build`, `vendor` or `target` is pruned too and does lower it.

Every run carries the coverage status, `no-reported-gap` or `incomplete`, and each gap is a result of its own. The status also reads `incomplete` when a result carries a limitation, for example a code-engine taint trace the scanner could not validate, so a run can be `incomplete` with every file read; the `cov=` number on the verdict line counts files only.

## Develop

```bash
make ci        # what CI runs: go build ./..., go vet ./..., go test -timeout 30m ./...
make test      # go test -timeout 30m ./...
make lint      # go vet plus staticcheck
make sec       # gosec over the product code at medium severity and confidence
make fuzz      # every fuzz target for FUZZTIME (default 30s); a crasher lands in <pkg>/testdata/fuzz/
make clean     # remove bin/
```

CI runs the Go job on Linux, macOS and Windows. The symlink tests run on Linux and macOS, the NTFS junction tests on Windows, and macOS is the platform whose filesystem hands back accented file names in decomposed Unicode (NFD), so that is where the name-normalization tests matter. A pushed tag `v<version>` runs the release workflow: it checks that the tag names the version in `internal/metadata`, runs the CI matrix on the tagged commit, and only then builds the five platform archives and publishes them with their checksums.

### Benchmark

`tools/bench` runs the scanner over an export of [MaliciousSkillBench](https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench) (revision `d4b42ce5766a`) and scores the rows. The headline score counts a record as detected only when a high or critical finding names a vector from the two behavior tiers (T1 and T2); capability-only signals (T3) are not counted, so a benign skill that merely asks for a lot is not a false positive (each vector's tier is set in `internal/findings/vectors.go`). Looser views (any high or above, any medium or above, any finding at all) are reported next to it, and a benign record whose scan did not complete is never counted as a true negative.

```bash
go run ./tools/bench run --data msb/test.jsonl --out out/test.jsonl
go run ./tools/bench score --md out/test.md out/test.jsonl
go run ./tools/bench score --compare out/before.jsonl out/after.jsonl
```

The export is one JSON object per record of the source-disjoint split with `benchmark_id`, `split`, `label` (1 for malicious, 0 for benign), `source_name`, `attack_categories` and `text`; `run` refuses a file whose id list is not the pinned test or dev split. Each record is scanned as a one-file package in a scratch directory and removed; nothing is executed.

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
                         Python text, CPython AST, PEP 508 and Unicode bidi semantics reproduced in Go
  testutil               helpers shared by every package's tests
tools/bench/             the benchmark runner and scorer
docs/reporting.md        result identity, operator decisions and SARIF semantics
Makefile                 all, build, install-opengrep, test, lint, vuln, sec, ci, fuzz, clean, help
```

## Contributing

Contributions are welcome. Before opening a pull request:

1. `make ci` passes: it builds, vets and tests every package.
2. `make lint` passes: `go vet` plus staticcheck.
3. A change to detection lands with its tests and says what it did to the benchmark.
4. The documentation matches the change.

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## References

- [MCP X-Ray](https://github.com/traceforce/mcp-xray)
- [Reporting guide](docs/reporting.md)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [OpenGrep](https://github.com/opengrep/opengrep)
