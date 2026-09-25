# Skill X-Ray

## Overview

Skill X-Ray is a static security scanner for AI agent skill packages. A skill package is a folder with a `SKILL.md` manifest and, often, bundled `scripts/`, `references/`, a `hooks.json` or a `.mcp.json`. Coding agents such as Claude Code, Cursor, Codex, Gemini CLI and OpenCode load these folders and act on them: the instructions go straight into the agent's context and the scripts run with the agent's privileges, so a bad skill can read your data or run code on your machine. Skill X-Ray reads a package before you install it, reports what it finds in its instructions and scripts, and never executes anything in it.

It is the sibling of [MCP X-Ray](https://github.com/traceforce/mcp-xray), which does the same job for MCP servers; if an MCP server is what you need to scan, use that one. Like MCP X-Ray it writes a [SARIF](https://sarifweb.azurewebsites.net/) report that SARIF-aware tools and CI pipelines can read, and it can scan one skill or every skill in the folders the common coding agents load from, in one go.

The scanner works offline with deterministic rules. A pinned [OpenGrep](https://github.com/opengrep/opengrep) engine, called the code engine below, covers bundled Python, POSIX shell (bash, sh, dash), JavaScript and TypeScript. An optional LLM pass, called the LLM lane below, adds a semantic check on top. It is off unless you ask for it, and when it is on it sends the skill text to the provider you configure.

## Installation

### Prerequisites

- A released binary runs on its own. The code engine is a separate download, described below.
- Building from source needs [Go 1.26](https://go.dev/dl/); the module pins the `go1.26.6` toolchain and fetches it when needed.
- Scanning a git repository URL needs `git` on the PATH.

### Download a release

Each release on the [Releases](https://github.com/traceforce/skill-xray/releases) page has archives for Linux (amd64, arm64), macOS (amd64, arm64) and Windows (amd64), plus a `SHA256SUMS` file. Check the sum, unpack the archive, put `skill-xray` on your PATH, then install the code engine:

```bash
skill-xray install-opengrep
```

This downloads OpenGrep 1.29.0 for your platform, checks its size and SHA-256 against the values built into the binary, and stores it in the user cache. It is safe to run again. Without an engine the scanner still runs, but a package that ships code gets a high `opengrep-unavailable` gap in its report and exit code 2. The cache paths, the order in which the scanner looks for an engine, and what happens when an engine you point at fails the check are in [docs/cli.md](docs/cli.md#code-engine).

### Build from source

```bash
git clone https://github.com/traceforce/skill-xray
cd skill-xray
make all                # builds bin/skill-xray (bin/skill-xray.exe on Windows)
make install-opengrep   # downloads and verifies the pinned code engine
```

Without make, `go build -o bin/ ./cmd/skill-xray` does the same as `make all`. The examples below assume `skill-xray` is on your PATH; from a source build use `./bin/skill-xray`.

## Usage

There are four commands. `scan` analyzes one skill package, `system-scan` analyzes every skill installed on the machine, `install-opengrep` fetches the code engine, and `version` prints the version. Both scans write one SARIF report and print one verdict line per package.

On Windows the same commands run from PowerShell. Write `$env:SKILLXRAY_LLM_PROVIDER = "anthropic"` where a bash example says `export SKILLXRAY_LLM_PROVIDER=anthropic`, and give `scan` a full path such as `$HOME\Downloads\deploy-helper` rather than `~/Downloads/deploy-helper`, because PowerShell does not expand `~` in that position. `--root ~/.claude/skills` works as written, since the tool expands `~` in roots itself.

### Scan one skill

```bash
# Scan the skill in ./my-skill; the report lands in the working directory as findings.sarif.json
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
| `-o`, `--output <path>` | where the report is written; default `findings.sarif.json`; must be outside the scanned package |
| `--policy <path>` | apply a reviewed policy that suppresses or demotes named results; see [Apply a reviewed policy](#apply-a-reviewed-policy) |
| `--opengrep-bin <path>` | use this OpenGrep binary instead of the cached one; it must match the pinned size and SHA-256 and sit in a directory only you or an administrator can change |
| `--llm` | also run the LLM lane; see [Scan with the LLM lane](#scan-with-the-llm-lane) |

**Detects:**

- Prompt-injection patterns, and directives to run a bundled script covertly or as a forced precondition
- Directives to send your data to an address written into the skill
- Unpinned remote installs, obfuscated or minified scripts, permission understatement, and writes that persist into agent configuration
- Every analysis gap, kept visible as a result rather than dropped

Examples with their severities are under [Detection vectors](#detection-vectors); the complete list of vectors is in `internal/findings/vectors.go`.

The console shows one line per package and the report path:

```
BLOCKING  seen=4   read=4   cov=100.0%  ./my-skill
report: findings.sarif.json
```

`seen` is the number of files found (a pruned directory such as `node_modules` counts as one), `read` the number read as text, and `cov` the share of the inspectable files that was read; inert assets such as images and fonts, and compiled files, are outside that share. It is read coverage, not detection coverage: a file counts as read whether or not a lane could analyze it. `BLOCKING` means at least one high or critical finding that names a vector, the class of behavior a rule detects. `FINDINGS` means any other finding that names a vector, or an analysis gap (a file or a part of one the scanner could not analyze) at medium severity or above. `CLEAN` means neither. The findings themselves are in the report, not on the console.

A folder with no `SKILL.md` still scans and can read `CLEAN`; stderr then says `note: no SKILL.md found`, so look for that line before trusting a `CLEAN` on something you unpacked by hand. A folder that holds several skills becomes one merged run, so use `system-scan --root` for a folder of skills.

Directory, file and zip scans never touch the network unless `--llm` is on. URL and git scans stop with exit code 2 when the URL redirects, the download is too large or holds too many files, or the host resolves to a private or local address. Only `https://` URLs count; `http://`, `ssh://` and tar archives are refused. [docs/cli.md](docs/cli.md#targets) lists every accepted target and refusal message.

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

With `--llm` alone the lane runs a semantic prompt-injection check (SXV-038). Its results are advisory and capped at medium severity: they can move a clean package to `FINDINGS` but not to `BLOCKING`, and they do not remove or lower a deterministic finding. The `llm:` console line says what the lane did, for example:

```
llm: 3 model calls; semantic check (SXV-038) ran
```

If the provider is down or rejects the key, the deterministic scan still completes, that line names the failure, and the exit code is unchanged.

Three more flags turn the lane into a reviewer of the static text-pattern findings (SXV-028 to SXV-031), and a fourth keeps the semantic check running alongside the review:

| flags | effect |
|---|---|
| `--llm --llm-shadow` | the model reviews the text-pattern findings; the report records its proposals and every result stays as it is |
| `--llm --llm-review` | as shadow, but a validated false-positive proposal is annotated as `llm-disputed`; nothing is removed or downgraded |
| `--llm --llm-review --llm-apply` | a validated dispute may demote that one finding to `low`, recorded as `corrected`; the finding is not suppressed and its severity is not raised |
| `--llm --llm-shadow --llm-additive` or `--llm --llm-review --llm-additive` | also run the semantic SXV-038 check after the review; without it, shadow and review turn that check off |

`--llm-shadow` and `--llm-review` exclude each other. A scan makes at most 25 model calls and sends at most 1 MiB of text per package, and `system-scan` spends that budget again for every package it finds. Do not gate CI on a disputed finding: the text the model reads while it reviews is written by the skill's author, who can write prose that argues for dismissing a finding. How a review decision is made and audited is in [docs/cli.md](docs/cli.md#llm-review).

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

The known roots are the skill folders of Claude Code, Cursor, Codex, Gemini CLI, OpenCode and Copilot under your home directory, the shared `~/.agents/skills`, and the project-local ones; [docs/cli.md](docs/cli.md#discovery) lists the paths and the plugin markers that make a folder a package.

```
CLEAN     seen=3   read=3   cov=100.0%  /home/me/.claude/skills/notes
BLOCKING  seen=6   read=6   cov=100.0%  /home/me/.claude/skills/deploy-helper
report: findings.sarif.json
packages: 2, blocking: 1, with findings: 0, clean: 1, incomplete: 0, discovery exceptions: 0
```

| flag | what it does |
|---|---|
| `--root <dir>` | scan the packages under this directory instead of the known roots; repeatable; must exist and be a directory |
| `-o`, `--output <path>` | where the report is written; default `findings.sarif.json`; must be outside every scanned package |
| `--opengrep-bin <path>` | as for `scan` |
| `--llm`, `--llm-shadow`, `--llm-review`, `--llm-apply`, `--llm-additive` | the same LLM lane as `scan`, applied to every package found |

`system-scan` has no `--policy` flag; to quiet a reviewed result in an installed skill, run `scan` on that one folder with the policy. A mistyped `--root` is counted under `discovery exceptions` and sets exit code 2, so a typo never passes as a clean run.

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

The console then adds a line such as `policy: 1 suppressed, 0 demoted, 0 of 1 decisions matched no result`, which is how you tell a `CLEAN` that came from a suppression apart from a `CLEAN` that came from a clean package. There is no wildcard, and any edit to the package invalidates the decision. [docs/reporting.md](docs/reporting.md) has the full format.

### Install the code engine

The same command as under [Download a release](#download-a-release); safe to run again.

```bash
skill-xray install-opengrep
# installed OpenGrep 1.29.0 at <cache path>
```

### Print the version

```bash
skill-xray version
# skill-xray 0.1.0
```

`skill-xray --version` prints the same line.

## Exit codes

| code | meaning |
|---|---|
| 0 | the scan and the report completed. Findings, even critical ones, do not change the exit code; read the verdict or the report for those |
| 2 | something did not complete: a usage error, a refused or failed input, a report that could not be written, a package whose analysis hit an internal error, a high-severity analysis gap, or for `system-scan` a root that could not be walked |

Every exit 2 comes with a reason on stderr. A script the scanner recognizes but cannot analyze is a high `analysis-incomplete` result and sets exit code 2: one in PowerShell, batch, Ruby or Perl, a shell script whose shebang or `.zsh` suffix names zsh, ksh or fish, or an unparseable Python code fence. A source file in any other language, such as Go, PHP or Rust, is a medium `analysis-incomplete` result: it was read but not analyzed, the package reads `FINDINGS`, and the exit code stays 0. The code engine gets 45 seconds per package; a package whose code takes longer gets a high `opengrep-timeout` gap and exit code 2 in place of its code findings.

## Output format

`scan` and `system-scan` write one [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) document, validated against the OASIS schema embedded in the binary before anything is written. `scan` writes one run; `system-scan` writes one file with one run per package. Each result carries a readable rule ID, a stable fingerprint, a severity, bounded evidence, source locations, and a `properties.category` of `security-finding` or `analysis-diagnostic`. [docs/reporting.md](docs/reporting.md) describes each field.

- The report and the policy file must be outside the scanned package, and the report's directory must exist. `scan` checks both before any file of the package is read; nothing is written on a refusal and the exit code is 2.
- The writer validates the document first, then replaces the target through a temporary file in the same directory, so a failed run leaves an earlier report untouched.
- Output is canonical ASCII JSON with sorted keys, so with the LLM lane off the same input and configuration produce a byte-identical report. Source evidence can contain credentials, so treat reports as sensitive.

The placement rules in full, with each refusal message, are in [docs/cli.md](docs/cli.md#report-placement).

## Examples

```bash
# A skill you downloaded and are about to install
skill-xray scan ~/Downloads/deploy-helper
# BLOCKING  seen=3   read=3   cov=100.0%  /home/me/Downloads/deploy-helper
# report: findings.sarif.json

# A CI job: the report goes next to the checkout, a reviewed policy quiets one known false positive
skill-xray scan ./skills/release-notes --output ../reports/release-notes.sarif --policy ./reviews/release-notes.json
```

Sample reports are in [examples/findings](examples/findings/): `deploy-helper.sarif.json` is the BLOCKING scan of a small skill whose instructions pipe an installer download into a shell, make a bundled script a precondition of every task and tell the agent to send credentials elsewhere, and whose scripts read a credential file and pass input to a shell command; `notes.sarif.json` is the CLEAN scan of a manifest-only skill. [examples/policy.json](examples/policy.json) suppresses the installer result of the first one.

## Configuration

### Environment variables

| variable | meaning |
|---|---|
| `SKILLXRAY_LLM_PROVIDER` | `anthropic`, `openai` or `openai-compatible`; required for `--llm` |
| `SKILLXRAY_LLM_API_KEY` | the API key; the vendor variables named under Supported providers are accepted as a fallback on the vendor's own endpoint, but not on a custom base URL |
| `SKILLXRAY_LLM_MODEL` | the model; the defaults are under Supported providers; required for openai-compatible |
| `SKILLXRAY_LLM_BASE_URL` | an https endpoint origin, with no userinfo, query or fragment; defaults to the vendor endpoint; required for openai-compatible |
| `SKILL_XRAY_OPENGREP_BIN` | an OpenGrep binary to use instead of the cache; it must match the pinned size and SHA-256 and sit in a directory only you or an administrator can change. Note the underscore after `SKILL`, unlike the `SKILLXRAY_LLM_*` variables |

Without `--llm` the LLM variables are ignored. `--llm` without a provider and a key is a usage error. If the `llm:` line says `HTTP 404`, the model or the endpoint was not found: on a vendor's own endpoint pick a model the key can call, and on a custom base URL check the path as well.

### Supported providers

| provider | `SKILLXRAY_LLM_PROVIDER` | default model | needs |
|---|---|---|---|
| Anthropic | `anthropic` | `claude-haiku-4-5` | `SKILLXRAY_LLM_API_KEY`, or `ANTHROPIC_API_KEY` as a fallback |
| OpenAI | `openai` | `gpt-4.1-mini` | `SKILLXRAY_LLM_API_KEY`, or `OPENAI_API_KEY` as a fallback |
| Any OpenAI-compatible endpoint | `openai-compatible` | none, set `SKILLXRAY_LLM_MODEL` | `SKILLXRAY_LLM_API_KEY`, `SKILLXRAY_LLM_MODEL` and `SKILLXRAY_LLM_BASE_URL` |

## Detection vectors

Each deterministic finding names a vector (`SXV-nnn`, the class of behavior it detects), a rule and a severity. Analysis gaps stay visible as findings with an empty vector rather than disappearing. A few of the rules, chosen because they show where the line between risky and malicious is drawn:

| vector | reports | severity |
|---|---|---|
| SXV-009 / SXV-041 | an installer-style fetch piped to a shell, such as `curl -fsSL https://cli.vendor.com/install.sh \| sh`, reported as an unpinned remote install; only the plain vendor shape matches, one HTTPS URL to an installer path or a bare vendor host, with no credentials, TLS bypass, raw IP, paste site or shell substitution in the fetch | medium |
| SXV-032 | a read of the skill's own install directory under an agent's skills tree, which is its own files, not another agent's state | medium |
| SXV-033 | the skill's manifest declares less permission than its code was observed to use (permission understatement, declared against observed); a capability signal, not on its own a malicious one | medium |
| SXV-042 | a prose directive to run a script shipped with the skill, framed as hidden from the user (`covert-bundled-script-run`) or as an unconditional precondition of every task (`coerced-bundled-preflight`) | high; medium with a single coercion cue |
| SXV-043 | a prose directive to obtain the user's data and send it to an e-mail address or URL hard-coded in the skill text | high |
| SXV-044 | a shipped JavaScript or TypeScript script that is one machine-generated line: an obfuscator's hex identifiers and escaped string tables (`obfuscated-script`), or a minifier's output outside a declared `.min.js` (`minified-script`) | high; medium when only minified |

Every report also records what the package claims about its execution and network needs, what its manifest declares, and what its code was observed doing. Unknown is not treated as safe, and neither a claim in the description nor a permission grant in the manifest authorizes behavior.

## Coverage limits

The deterministic lane reads prose for meaning and shipped code through the code engine. Measured on this release, it does not read for meaning:

- text inside a fenced or four-space-indented code block whose language the code engine does not cover, and the natural-language comments inside code it does cover;
- HTML comments beyond the hidden-comment check, HTML blocks with tags the prose model does not know, and the title attribute of a Markdown link;
- the prompt and handler strings of a `hooks.json` or `.mcp.json`, which are checked for structure only;
- a directive quoted after a colon, or held in a quoted frontmatter value, which the example guard treats as a citation;
- a script path or address that lives in another file of the package, and a run cue and its script placed in different sections.

It also reports a quoted description of a past attack as a live instruction when the quote is an override sentence, and a shipped source file in a language no lane covers as a medium gap rather than analyzing it. The LLM lane's review mode can dispute only the text-pattern findings SXV-028 to SXV-031. These limits are the follow-up work; the report and the console say what was not analyzed.

## Coverage

The file walker treats every package as hostile. It caps per-file size (1 MiB), file count (5000) and total bytes read (256 MiB), so a crafted package cannot make it run out of memory; time is not capped the same way, and a Markdown file at the 1 MiB cap takes between ten seconds and a minute to analyze, so give a scan of a very large package a CI timeout. It does not follow a symlink or NTFS junction inside the package and does not open a FIFO, device or socket; each is recorded as unread. Shipped compiled code, a `.pdf`, a nested archive, and raw HTML inside Markdown that carries text in a tag the prose model cannot project are each reported as a gap, and every run carries a coverage status, `no-reported-gap` or `incomplete`, with each gap a result of its own. The full ledger rules are in [docs/cli.md](docs/cli.md#coverage-ledger).

## Develop

```bash
make ci        # what CI runs: go build ./..., go vet ./..., go test -timeout 30m ./...
make test      # go test -timeout 30m ./...
make lint      # go vet plus staticcheck
make sec       # gosec over the product code at medium severity and confidence
make fuzz      # every fuzz target for FUZZTIME (default 30s); a crasher lands in <pkg>/testdata/fuzz/
make clean     # remove bin/
```

CI runs on Linux, macOS and Windows, and a pushed tag `v<version>` runs the release workflow ([docs/cli.md](docs/cli.md#ci-and-release)).

`tools/bench` runs the scanner over an export of [MaliciousSkillBench](https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench) and scores the rows; the headline score counts a record as detected only when a high or critical finding names a behavior vector (something the skill does), not a capability declaration (something it asks for), so a benign skill that merely asks for a lot is not a false positive. The benchmark commands are in [docs/cli.md](docs/cli.md#benchmark) and the package layout in [docs/cli.md](docs/cli.md#layout).

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
- [Command reference](docs/cli.md)
- [Reporting guide](docs/reporting.md)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [OpenGrep](https://github.com/opengrep/opengrep)
