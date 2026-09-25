# Command reference

The details behind the README, checked against the 0.1.0 binary: what each command accepts and refuses, what the console prints, how the LLM review decides, where a report may go, what the coverage ledger records, and how the repository is laid out.

## Targets

`scan` treats whatever you point it at as one package. The target can be a directory, a single file such as `SKILL.md`, a `.zip` archive, an `https://` URL to a zip or to a single file, or a git repository given as an `https://` address ending in `.git`. `ssh://`, `git@` and `git://` addresses are refused with `git ingest supports https:// repository URLs only`. A plain `http://` address is refused as `not a directory, file, .zip, URL or git repo`, because only `https://` counts as a URL. Tar archives are refused with `unpack it and scan the directory`, so unpack those first.

Directory, file and zip scans never touch the network unless `--llm` is on, which sends the skill text to the configured provider. URL and git scans do, and they stop with exit code 2 rather than carry on when the URL redirects, the download is too large, holds too many files, or resolves to a private or local address. Give a URL that points directly at the file: a GitHub archive link such as `.../archive/refs/heads/main.zip` redirects and is refused, while its target `https://codeload.github.com/<owner>/<repo>/zip/refs/heads/main` downloads. A URL or git download has a 120 second deadline.

A folder that holds several skills becomes one merged run named after that folder, so use `system-scan --root` for a folder of skills. A folder with no `SKILL.md` still scans and can read `CLEAN`; stderr then says `note: no SKILL.md found under <path>; nothing was evaluated as a skill manifest`, so look for that line before trusting a `CLEAN` on something you unpacked by hand.

## Console output

The console shows one line per package and the report path:

```
BLOCKING  seen=4   read=4   cov=100.0%  ./my-skill
report: findings.sarif.json
```

`seen` is the number of files found (a pruned directory such as `node_modules` counts as one), `read` the number read as text, and `cov` the share of the inspectable files that was read; inert assets such as images and fonts, and compiled files, are outside that share. It is read coverage, not detection coverage. A vector is the class of behavior a rule detects (`SXV-nnn`); an analysis gap is a result with no vector that records what could not be checked. The verdict word means:

- `BLOCKING`: at least one high or critical finding that names a vector;
- `FINDINGS`: any other finding that names a vector, or an analysis gap at medium severity or above;
- `CLEAN`: neither.

The findings themselves are in the report, not on the console. Control characters and line or paragraph separators in a printed path are shown as escapes, so a file name cannot hide or split a console line.

`system-scan` prints one verdict line per package, then the report path and a summary line: `packages: 2, blocking: 1, with findings: 0, clean: 1, incomplete: 0, discovery exceptions: 0`.

With `--policy`, the console adds a line such as `policy: 1 suppressed, 0 demoted, 0 of 1 decisions matched no result`. That line is how you tell a `CLEAN` that came from a suppression apart from a `CLEAN` that came from a clean package, and its last count shows when a decision no longer matches anything.

With `--llm`, the console adds one line for the lane, for example `llm: 3 model calls; semantic check (SXV-038) ran`. If the provider is down or rejects the key, the deterministic scan still completes and the failure does not change the exit code on its own: the `llm:` line names it, and the report records it under `llmUsage`. If the line says `HTTP 404`, the model or the endpoint was not found; the line points at `SKILLXRAY_LLM_MODEL` and `SKILLXRAY_LLM_BASE_URL`. On a vendor's own endpoint, pick a model the key can call. On a custom base URL, check the path as well.

## Exit code reasons

Every exit 2 comes with a reason on stderr: an `analysis incomplete:` line naming the package, the diagnostic and the file for each gap; a `skill discovery incomplete (<reason>):` line for a `system-scan` root that could not be walked; a `no SARIF run for <package>:` line when one package's run could not be built; or a `cannot ...` or `skill-xray: error:` line for everything else. A package whose analysis hit an internal error is reported as `FINDINGS`, not as `CLEAN`.

A script the scanner recognizes but no lane can analyze appears as a high `analysis-incomplete` result in the report and sets exit code 2 like any other high gap: one in PowerShell, batch, Ruby or Perl, a shell script whose shebang or `.zsh` suffix names zsh, ksh or fish, or an unparseable Python code fence. It was read, so it does not lower the coverage number. A source file with one of these extensions is not analyzed by any lane and is recorded as a medium `analysis-incomplete` result ("was read but not analyzed: no lane covers Go."); the package reads `FINDINGS` and the exit code stays 0: `.go .rs .php .java .kt .kts .swift .c .h .cc .cpp .cxx .hpp .cs .lua .r .scala .dart .ex .exs .hs .m .mm .zig .nim .jl .vb .vbs .fs .fsx .clj .erl .groovy .gradle .ksh .fish .csh .tcsh .awk .ahk .applescript .ml .pas .f90 .cr .rkt .lisp .d .nix .tf .cmake .pyx .psm1 .v .elm`. Any other file the parser does not model, including a script with no extension and a shebang no lane covers, or schema and licence text, stays a low `coverage-note` with the reason `unmodeled_content`. Read the report's coverage notes before trusting a `CLEAN` on a package that ships such files. On a Windows machine the first `system-scan` will often exit 2 for shipped PowerShell scripts.

The code engine gets 45 seconds per package. A package whose code takes longer, for example one shipping more than a thousand scripts, gets a high `opengrep-timeout` gap and exit code 2 in place of its code findings, so a package can read `FINDINGS` on a slow machine where a fast one reads `BLOCKING`.

## Code engine

`install-opengrep` downloads OpenGrep 1.29.0 for your platform, checks its size and SHA-256 against the values built into the binary, and stores it in the user cache. Running it again is safe: it keeps a cached copy that passes the size and SHA-256 check and sits in a directory only you or an administrator can change, and downloads again otherwise.

Pinned builds exist for Windows x86_64, Linux x86_64 and aarch64, and macOS x86_64 and arm64. The cache is `%LOCALAPPDATA%\skill-xray\opengrep\1.29.0` on Windows, `~/Library/Caches/skill-xray/opengrep/1.29.0` on macOS, and `$XDG_CACHE_HOME` or `~/.cache` followed by `skill-xray/opengrep/1.29.0` elsewhere. The scanner looks for the code engine in this order: `--opengrep-bin`, then `SKILL_XRAY_OPENGREP_BIN`, then the cache, then `opengrep` on the PATH; every candidate must match the pinned size and SHA-256 and sit in a directory only you or an administrator can change. Without an engine the scanner still runs, but a package that ships code gets a high `opengrep-unavailable` gap in its report and exit code 2. An engine you point at explicitly that is missing, does not match the pin or sits in a directory another user could change gives the same kind of gap under the name `opengrep-unverified`.

## LLM review

In shadow and review mode the model sees a text-pattern candidate together with its rule contract, evidence, nearby source and the skill's own description, which is untrusted, and answers `retain_finding`, `propose_false_positive` or `insufficient_context`. A false-positive proposal has to name the rule condition that is missing. It is accepted only with high confidence and complete, bounded source; redacted, oversized or externally linked context blocks it, and mechanical findings and coverage notes cannot be disputed at all. The client pins `temperature: 0`, and OpenAI's best-effort `seed`, where the model accepts them. That removes one source of variance, not all of it, which is why the lane stays advisory and medium-capped. The text the model reads is written by the skill's author, who can write prose that argues for dismissing a finding. Credential redaction before sending is best effort, not a guarantee.

`--llm-additive` needs `--llm-shadow` or `--llm-review`; on its own it is a usage error. `--llm-shadow` and `--llm-review` exclude each other. A scan makes at most 25 model calls and sends at most 1 MiB of text per package, and `system-scan` spends that budget again for every package it finds.

The run properties keep the audit: `rawCandidates` holds the emitted candidates, `candidateLinks` ties each to the result that retained it, `capabilityContexts` holds the capability evidence once per manifest, and `llmReview` records each review decision with its disposition, status, reason, tags, policy version, provenance, proposal, and request and response hashes.

## Discovery

`system-scan` searches the known roots: `~/.claude/skills`, `~/.claude/plugins`, `~/.config/opencode/skills`, `~/.cursor/skills`, `~/.gemini/skills`, `~/.codex/skills`, `~/.copilot/skills`, `~/.agents/skills`, and in the current project `.claude/skills`, `.opencode/skills`, `.cursor/skills`, `.gemini/skills`, `.codex/skills`, `.github/skills` and `.agents/skills`. A known root that does not exist is skipped.

A package is a directory holding a `SKILL.md` or one of the plugin markers `.claude-plugin`, `.codex-plugin`, `plugin.json`, `.mcp.json` or `hooks.json`; once found, its subtree is not searched further.

A `--root` you name must exist and be a directory. A mistyped one is not refused up front: the run continues over the other roots, the report is still written, the summary counts it under `discovery exceptions`, stderr prints `skill discovery incomplete (root_missing): <path>`, and the exit code is 2. A typo therefore never passes as a clean run.

`system-scan` has no `--policy` flag. To quiet a reviewed result in an installed skill, run `scan` on that one folder with the policy.

## Policy

There is no vector-wide ignore and no wildcard, and any edit to the package invalidates the decision. Suppressed results stay in the report under `suppressions`; demoted ones keep the lower `level` with `properties.disposition` set to `corrected`. A policy that is missing, inside the package, over 512 KiB, not valid JSON, not an object, or of another version is refused before the scan; an invalid decision is reported as a context error in the report and sets exit code 2. [reporting.md](reporting.md) has the full format.

## Report placement

- The report and the policy file must be outside the scanned package, and the report's directory must exist. `scan` checks both before any file of the package is read and refuses with `cannot prepare SARIF: Report directory is missing or not a directory: <path>` or `cannot prepare SARIF: Report must be outside the scanned package`; a report path that is itself a symlink gets the second message. `system-scan` reports the second as `cannot write SARIF: ...` after discovery.
- A directory you cannot write to is found out only when the report is written, after the scan, as `cannot write SARIF: ...`.
- A policy that is missing, inside the package or not valid JSON is refused the same way, with `Operator policy ...` in place of `Report ...`.
- Nothing is written on a refusal and the exit code is 2.
- The writer validates the document first, then replaces the target through a temporary file in the same directory, so a failed run leaves an earlier report untouched. Reports over 64 MiB fail instead of being truncated.
- A scan you interrupt writes no report and can leave the engine's working directory, `skill-xray-opengrep-*`, in the system temp folder.

Each run records, under its properties, what it ran with and what it saw: the OpenGrep version and ruleset digest, the package name and content digest, the coverage status, the capability context, the raw candidates and how they became results, and, with the LLM lane on, `llmUsage`, plus `llmReview` in shadow or review mode.

Output is canonical ASCII JSON with sorted keys, so with the LLM lane off the same input and configuration produce a byte-identical report; the Windows and Linux builds were compared and agree. The one known exception is a zip whose member names end in a space or a dot, which Windows renames on extraction.

## Coverage ledger

The file walker, the part of the scanner that reads the package off disk, treats every package as hostile, so:

- it caps per-file size (1 MiB), file count (5000) and total bytes read (256 MiB), so a crafted package cannot make it run out of memory. The walker and the text lanes have no time limit of their own: a Markdown file at the 1 MiB cap takes between ten seconds and a minute to analyze depending on its shape, so give a scan of a very large package a CI timeout. The code engine's 45 second deadline and the 120 second deadline on a URL or git download cover only those steps;
- it does not follow a symlink or NTFS junction inside the package, wherever it points; each is recorded in the ledger as unread. The package root you name may itself be a symlink;
- it does not open a FIFO, device or socket;
- it inventories shipped compiled and native code (`.pyc`, `.pyo`, `.pyd`, `.so`, versioned `.so.N`, `.dylib`, `.dll`, `.exe`, `.wasm`, `.jar`, `.war`, `.class`, `.node`, `.o`, `.a`) as one `analysis-incomplete` result per file with the reason `shipped_compiled`, so a full coverage number does not hide compiled code;
- it reports content it cannot review with the reason `unreviewable_content`. An `.svg` is a low `coverage-note`, because an agent never reads it as instructions. A `.pdf` or a nested archive is a high `analysis-incomplete` gap with exit code 2, because an agent may be told to read or unpack it;
- raw HTML inside a Markdown file is a high `analysis-incomplete` gap with the reason `raw_html` when it carries text or a link label in a tag or attribute the prose model cannot project, or when it could not be read whole; presentational tags such as `<div>`, `<a>`, `<img>` and `<details>` with their standard attributes are read as prose. Markup with no text, such as a centered image block, is a low note;
- it records every file it does not read, with a reason. A skipped file lowers the reported coverage unless it is an inert asset, compiled code or an excluded directory (`.git`, `.hg`, `.svn`, `.venv`, `venv`, `.mypy_cache`, `.pytest_cache`, `.idea`, `.tox`, `.ruff_cache`); a bundled `node_modules`, `dist`, `build`, `vendor` or `target` directory is also pruned, and that one does lower the coverage number.

Every run carries the coverage status, `no-reported-gap` or `incomplete`, and each gap is a result of its own. The status also reads `incomplete` when a result carries a limitation, for example a code-engine taint trace the scanner could not validate, so a run can be `incomplete` with every file read; the `cov=` number on the verdict line counts files only.

## Benchmark

`tools/bench` runs the scanner over an export of [MaliciousSkillBench](https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench) (revision `d4b42ce5766a`) and scores the rows. The headline score counts a record as detected only when a high or critical finding names a vector from the two behavior tiers (T1 and T2); capability-only signals (T3) are not counted, so a benign skill that merely asks for a lot is not a false positive (each vector's tier is set in `internal/findings/vectors.go`). Looser views (any high or above, any medium or above, any finding at all) are reported next to it, and a benign record whose scan did not complete is never counted as a true negative.

```bash
go run ./tools/bench run --data msb/test.jsonl --out out/test.jsonl
go run ./tools/bench score --md out/test.md out/test.jsonl
go run ./tools/bench score --compare out/before.jsonl out/after.jsonl
```

The export is one JSON object per record of the source-disjoint split with `benchmark_id`, `split`, `label` (1 for malicious, 0 for benign), `source_name`, `attack_categories` and `text`; `run` refuses a file whose id list is not the pinned test or dev split. Each record is scanned as a one-file package in a scratch directory and removed; nothing is executed.

## CI and release

CI runs the Go job on Linux, macOS and Windows. The symlink tests run on Linux and macOS, the NTFS junction tests on Windows, and macOS is the platform whose filesystem hands back accented file names in decomposed Unicode (NFD), so that is where the name-normalization tests matter. A pushed tag `v<version>` runs the release workflow: it checks that the tag names the version in `internal/metadata`, runs the CI matrix on the tagged commit, and only then builds the five platform archives and publishes them with their checksums.

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
