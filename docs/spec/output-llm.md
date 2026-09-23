# Porting specification: group `output-llm`

> **Errata (00-overview).** Read this spec with these substitutions; `00-overview.md` is binding.
> - `pyjson.*` and `pyre.*` are one package, `internal/pytext` (`pytext.Canonical`, `pytext.Dumps`,
>   `pytext.Quote/QuoteBytes`, `pytext.Space`, `pytext.IsSpace`, `pytext.Strip`, `pytext.URLSplit`,
>   `pytext.Unquote`).
> - `scan.Report` is `scan.ScanReport`; its `Correlation` field is the typed `*correlate.Correlation`, and
>   `sarif.Build` reads the generic view through `(*scan.ScanReport).ToMap()["correlation"]`.
>   `scan.Candidate` is `correlate.Candidate`. `Finding.ToDict` is `Finding.ToMap`; `findings.VectorMeta(v)`
>   is `findings.MetaOf(v) (findings.Meta, bool)`. `disposition.*` constants are `correlate.PolicyVersion`,
>   `correlate.LLMApplyVersion`, `correlate.LLMApplyVectors`. `skillxray.Version` is `metadata.Version`.
>   `codelane.ManifestIndex/GoverningManifest` are `parse.ManifestIndex/GoverningManifest`.
> - `capability.Triad.Evidence` is `[]map[string]any`; `correlate.SourceRegion` takes `start, end
>   map[string]any`; `CoverageSummary` returns `map[string]any` (the CLI adds `enabled`/`reason`).
> - `supplychain.SecretRules []SecretRule{ID string; Pattern *regexp.Regexp; Left, Right bool; Severity string}`
>   uses a boundary scanner, so `redact()` step 2 is `supplychain.ReplaceSecrets(text, func(string) string {
>   return "[REDACTED]" })`, not nine `sub` calls.
> - `parse.Artifact.Config` is `map[string]any`/`[]any`/scalars (key order not preserved); R6 is decided as
>   an accepted LLM-lane divergence (sorted keys in `_config_prompt_text`).
> - Oracle: §2.3 (thinking-family `output_config`, `reasoning_effort`, the 4096 floor) describes
>   `llm/client.py` as merged by PR #39 into upstream `main`, one change past the parity pin
>   `33f057e` (00-overview Gaps 1).
> - Toolchain: `go 1.26.0` as this spec assumed; `omitzero` is available.

Python sources (1,555 lines): `src/skill_xray/sarif.py` (424), `src/skill_xray/schemas/` (vendored
SARIF 2.1.0 schema + README), `src/skill_xray/llm/__init__.py` (25), `llm/config.py` (111),
`llm/client.py` (247), `llm/session.py` (63), `llm/privacy.py` (51), `llm/judge.py` (304),
`llm/adjudicate.py` (330). 44 functions/methods, 8 compiled regexes in-group (plus the 9
`_SECRET_RULES` patterns applied from the code group).

Go packages: `internal/sarif` (build, validate, encode, write, IsWithinSource; embeds
`schemas/sarif-schema-2.1.0.json` and `schemas/README.md`) and `internal/llm` (config.go,
client.go, session.go, privacy.go, judge.go, adjudicate.go). No new module dependencies: the
two this group needs, `github.com/dlclark/regexp2` and `github.com/santhosh-tekuri/jsonschema/v6`,
are already declared in `port-to-go/go.mod`. `github.com/owenrumney/go-sarif/v2` is declared
there too but this group does NOT use it: the document is emitted through the canonical
(sorted-key, ASCII-escaped) encoder the fingerprints already need, and go-sarif's typed structs add
nothing the validator can consume.

Conventions carried over from mcp-xray: `internal/<pkg>`, testify `assert`/`require`, `t.Run`
subtests, fixtures under `testdata/`, no cgo. Go 1.26 per go.mod (so `omitzero` is available).

---

## 1. Public surface

### 1.1 `sarif.py` -> `internal/sarif`

Importers: `cli.py` (`build_sarif`, `is_within_source`, `write_sarif`); tests import
`build_sarif, encode_sarif, validate_sarif, write_sarif` and reach `sarif._validator()`,
`sarif.os.replace`, `sarif.encode_sarif` via monkeypatch (Python-only ceremony, not ported).

| Python | Go | Notes |
|---|---|---|
| `build_sarif(parsed, report) -> dict` | `func Build(p *parse.Package, r *scan.ScanReport) (map[string]any, error)` | returns the document as generic JSON (see 1.4 why). `ValueError` -> error. |
| `validate_sarif(document)` | `func Validate(doc any) error` | error text `"SARIF validation failed (<Name>)"`, Name in {`ValidationError`, `ValueError`, `KeyError`, `TypeError`, `IndexError`}; only the first two matter (stderr text, not parity). |
| `encode_sarif(document) -> bytes` | `func Encode(doc any) ([]byte, error)` | validate, canonical JSON + `"\n"`, ASCII bytes, 64 MiB cap. |
| `write_sarif(document, target, *, source_root)` | `func Write(doc any, target, sourceRoot string) error` | atomic temp-file replace. |
| `is_within_source(path, root) -> bool` | `func IsWithinSource(path, root string) bool` | both arguments already resolved (cli resolves; `Write` resolves root itself). |
| `_SCHEMA`, `_validator()` | `//go:embed schemas/sarif-schema-2.1.0.json` + `var schema = sync.OnceValues(compile)` | schema `id` is the `$schema` value: `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`. Embedded bytes must hash to `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` (pin in a test). |
| `_LEVEL` | `var level = map[string]string{"critical":"error","high":"error","medium":"warning","low":"note"}` | |
| `_MAX_REPORT_BYTES` | `const maxReportBytes = 64 << 20` | |
| `_REVIEW_FIELDS` | `var reviewFields = [...]string{...}` (13 names) | order irrelevant |

### 1.2 `llm/config.py` -> `internal/llm/config.go`

Importers: `cli.py` (`LLMConfigError`, `build_client`, `from_env`); `llm/client.py` (`LLMConfig`).

| Python | Go |
|---|---|
| `class LLMConfig(provider, model, api_key, base_url, max_tokens=1024, timeout=30)` frozen, validated in `__post_init__` | `type Config struct { Provider, Model, APIKey, BaseURL string; MaxTokens int; Timeout time.Duration }` + `func NewConfig(provider, model, apiKey, baseURL string) (Config, error)` (validates, lower-cases/strips provider, rstrips `/` from base_url, MaxTokens 1024, Timeout 30s). `func (c Config) String() string` omits APIKey (Python `repr=False`; `%v` must never print the key). |
| `LLMConfigError` | `type ConfigError struct{ Msg string }`; `Error()` returns Msg verbatim (cli prints it after `error:`). |
| `from_env(env=None) -> LLMConfig | None` | `func FromEnv(getenv func(string) string) (*Config, error)`; `nil, nil` when `SKILLXRAY_LLM_PROVIDER` is blank. CLI passes `os.Getenv`; tests pass a map closure. |
| `_PROVIDERS`, `_DEFAULT_MODEL`, `_DEFAULT_BASE`, `_KEY_FALLBACK` | package maps with identical values (`claude-haiku-4-5`, `gpt-4.1-mini`, `https://api.anthropic.com`, `https://api.openai.com/v1`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` for both openai and openai-compatible). |

### 1.3 `llm/client.py`, `llm/session.py` -> `internal/llm/client.go`, `session.go`

| Python | Go |
|---|---|
| `class LLMClient` (`complete(system, user) -> str`) | `type Completer interface { Complete(system, user string) (string, error) }` |
| optional `complete_structured(system, user, schema)` | `type structuredCompleter interface { CompleteStructured(system, user string, schema any) (string, error) }` (session checks with a type assertion) |
| optional `.cfg.provider / .cfg.model` | `type identified interface { Identity() (provider, model string) }`; `*HTTPClient` implements it. |
| `LLMError`, `LLMResponseError(LLMError)`, `LLMBudgetError(LLMError)` | one type `type Error struct { Kind Kind; Msg string }`, `type Kind int` (`Transport`, `Response`, `Budget`), `func (k Kind) PyName() string` -> `"LLMError"`, `"LLMResponseError"`, `"LLMBudgetError"` (class names reach finding messages, 2.7). `func ErrName(err error) string`: `*Error` -> PyName, else `"Exception"`. One struct with a kind: Go has no subclassing and every consumer is a three-way switch. |
| `HTTPLLMClient(config)` | `type HTTPClient struct { cfg Config; http *http.Client }`; `func NewHTTPClient(cfg Config) *HTTPClient` |
| `build_client(config)` | `func BuildClient(cfg Config) Completer { return NewHTTPClient(cfg) }` |
| `_NoRedirectHandler` | `http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}` |
| `_MAX_RESPONSE_BYTES`, `_READ_CHUNK`, `_RETRY_STATUS`, `_MAX_RETRIES`, `_MAX_BACKOFF`, `_REASONING_MIN_OUTPUT`, `_REASONING_EFFORT` | `const maxResponseBytes = 1 << 20` (no chunk constant: one `io.LimitReader`), `var retryStatus = map[int]bool{429:true,502:true,503:true,504:true,529:true}`, `const maxRetries = 3`, `const maxBackoff = 8 * time.Second`, `const reasoningMinOutput = 4096`, `const reasoningEffort = "low"`. `var sleep = time.Sleep` (tests replace it). |
| `LLMSession(client, max_calls=25, max_bytes=1<<20)` | `type Session struct { Client Completer; MaxCalls, MaxBytes int; Calls, InputBytes, Failures int; Unavailable bool }`; `func NewSession(c Completer, maxCalls, maxBytes int) (*Session, error)` (negative -> error `"LLM budgets must be non-negative integers"`). |
| `session.complete(system, user, *, response_schema=None)` | `func (s *Session) Complete(system, user string) (string, error)` (satisfies `Completer`, so `Adjudicate` takes the session) and `func (s *Session) CompleteSchema(system, user string, schema any) (string, error)`. |
| `session.usage() -> dict` | `func (s *Session) Usage() map[string]any` keys `calls, input_bytes, provider, model, failures, unavailable, max_calls, max_input_bytes, unit` (reach `--json` `enrichment.llm_usage`). |

### 1.4 `llm/privacy.py`, `llm/judge.py`, `llm/adjudicate.py`

| Python | Go |
|---|---|
| `redact(text) -> str` | `func Redact(text string) string` |
| `judge.POLICY_VERSION = "directive-shadow-v3"` | `const ShadowPolicyVersion = "directive-shadow-v3"` |
| `judge.REVIEW_POLICY_VERSION = "directive-review-v2"` | `const ReviewPolicyVersion = "directive-review-v2"` |
| `judge.RESPONSE_SCHEMA` | `var ResponseSchema map[string]any` unmarshalled once from `const responseSchemaCompact` (section 2.6 gives both required serialisations verbatim). |
| `judge._SYSTEM`, `_FIELDS`, `_CONTRACTS` | `const judgeSystem` (verbatim; sha256 pinned), `var fields = [8]string{...}`, `var contracts = map[[2]string][2]string` keyed (vector, rule). |
| `judge_candidates(parsed, candidates, triads, session, *, apply_review=False) -> list[dict]` | `func Judge(p *parse.Package, candidates []correlate.Candidate, triads map[string]*capability.Triad, s *Session, applyReview bool) []Decision` |
| decision dict | `type Decision struct { CandidateID string \`json:"candidate_id"\`; Disposition string \`json:"disposition"\`; Status string \`json:"status"\`; Reason string \`json:"reason"\`; PolicyVersion string \`json:"policy_version"\`; Provenance string \`json:"provenance"\`; Proposal *Proposal \`json:"proposal"\` (always emitted, `null` when nil); ReviewedCandidateID string \`json:"reviewed_candidate_id,omitempty"\`; FailureReason string \`json:"failure_reason,omitempty"\`; Tags []string \`json:"tags,omitzero"\` (nil = absent, `[]string{}` = `[]`); Request map[string]any \`json:"request,omitzero"\`; RequestSHA256 string \`json:"request_sha256,omitempty"\`; Reviewer *Reviewer \`json:"reviewer,omitempty"\`; ResponseSHA256 string \`json:"response_sha256,omitempty"\` }` |
| proposal dict | `type Proposal struct { CandidateID \`json:"candidate_id"\`, Verdict, Confidence, Mechanism, Intent, Reason, Impact, EvidenceQuote \`json:"evidence_quote"\` string }` |
| reviewer dict | `type Reviewer struct { Provider, Model string; PromptSHA256 \`json:"prompt_sha256"\`; SchemaSHA256 \`json:"schema_sha256"\` string }` |
| `adjudicate.INSTRUCTION_KINDS` | `var InstructionKinds = map[string]bool{"skill_manifest","instruction","agent_identity","doc"}` |
| `adjudicate(parsed, client, max_files=25) -> list[Finding]` | `func Adjudicate(p *parse.Package, c Completer, maxFiles int) []findings.Finding` |
| `coverage_summary(parsed, findings) -> dict` | `func CoverageSummary(p *parse.Package, fs []findings.Finding) map[string]any` keys `eligible, checked, truncated, skipped, errored, flagged` (cli adds `enabled`/`reason` in shadow mode; core). |
| `_MAX_CHARS`, `_MAX_FILES`, `_MAX_PARSE_ATTEMPTS`, `_CONFIG_KINDS`, `_PROMPT_KEYS`, `_KIND_ORDER`, `_SKIP_RULES`, `_ERROR_RULES`, `_SYSTEM_TEMPLATE` | same names unexported; template verbatim (sha256 `ce58f3d72c8a6544acc1da23ab21e6732a05c54653a941eac4ca13cdc4853a80`, 1,245 chars). |

Why `Build` returns `map[string]any`: `Validate` must run on generic decoded JSON anyway (the CLI
tests re-validate written files; tests mutate arbitrary paths), and the document passes through
core's generic dicts (evidence, raw candidates, capability contexts) verbatim; a typed intermediate
would only be marshalled and decoded back.

### 1.5 Data shapes consumed from other groups (contract this group depends on)

- `findings.Finding` (core): `Vector, Rule, Severity, Path, Message string; Line, Column, Offset, Length *int; Evidence map[string]any`; `ToMap() map[string]any` emitting `vector, rule, severity, path, message, [line], [column], [offset], [length], [evidence], [title, cwe, tier]` exactly like `Finding.to_dict()`. `findings.SeverityRank map[string]int`, `findings.MetaOf(vector) (findings.Meta, bool)`.
- `correlate.Candidate` (core): `{"candidate_id", "finding", "analyzer", "provenance", "coverage"}`.
- `scan.ScanReport` (core): `Correlation *correlate.Correlation` (read as generic JSON through `(*scan.ScanReport).ToMap()["correlation"]`), `ReviewMode bool`, `Dispositions, Shadow []llm.Decision`, `LLMUsage map[string]any`, `ContextErrors []string`. `correlation` keys read here: `errors` (optional), `links` (`{candidate_id, result_id, stable_candidate_id, disposition, reason, policy_version, provenance}`), `raw_candidates`, `results`, `execution_successful`, `package{name, content_digest, digest_version}`, `capability_contexts`, `coverage`, `context_limitations`. Result keys read: `id, rule_id, fingerprint, fingerprint_version, context_digest, finding, manifest, candidate_ids, provenance, evidence, code_flow, limitations, disposition, decision_reason, decision_provenance, policy_version, original_severity, effective_severity, coverage`.
- `correlate.FingerprintVersion = "skill-xray/evidence/v1"`, `correlate.Canonical` (= `pytext.Canonical`), `correlate.SourceRegion(artifact *parse.Artifact, start, end map[string]any, byteColumns bool, lines []string) (text string, startCol, endCol int, err error)`.
- `correlate.PolicyVersion = "skill-xray/scoped-policy/v1"`, `correlate.LLMApplyVersion = "skill-xray/llm-apply/v1"`, `correlate.LLMApplyVectors` = {SXV-028, SXV-029, SXV-030, SXV-031}.
- `opengrep.Version = "1.29.0"` and embedded rule bytes `opengrep.Rules []byte` (sarif hashes them for `rulesetDigest`; today `db281f275ffc49df77832c8d51ca9a6021b5b1bc5270bbd87515032b1f2cf88b`, do not pin: it changes with the rule file).
- `metadata.Version = "0.1.0"`.
- `parse.Package`: `Name, Identity string; Artifacts []*Artifact; ByRel map[string]*Artifact; Refs []Ref{From, To string; Line int}`. `parse.Artifact`: `Rel, Kind string; Text *string (nil = unread); Raw []byte (nil = unread); Frontmatter map[string]any; FrontmatterKeyLines map[string]int; Markdown *Markdown{Links []Link{Href, Label string; Line int}; ProseSpans []Span (1-based inclusive)}; FallbackLinks []Link; Config any (map[string]any; key order is not preserved, R6 accepted)`.
- `capability.Triad`: `Manifest *string; Claimed, Declared, Observed map[string]string; Evidence []map[string]any; Limitations []string`.
- `parse.ManifestIndex(p) map[string]*parse.Artifact`, `parse.GoverningManifest(index, rel) *parse.Artifact` (parse package; Python `code_lane`).
- `instruction.FlattenProse(text string) string`, `instruction.SourcePosition(text string, startLine, pos int) (line, col int)` (instruction group; code-point semantics, see 2.5).
- `supplychain.SecretRules []SecretRule{ID string; Pattern *regexp.Regexp; Left, Right bool; Severity string}`, `supplychain.ReplaceSecrets(text, repl func(string) string) string`, `supplychain.SanitizeSource(string) string` (code group).
- `pytext.Canonical(v any) string` (= `json.dumps(sort_keys=True, ensure_ascii=True, separators=(",",":"), allow_nan=False)`), `pytext.Dumps(v any, sortKeys bool, indent int) string` (Python default separators `", "`/`": "`; with indent, item separator `","` + newline), `pytext.Quote(s, safe string) string` and `pytext.QuoteBytes(b []byte, safe string) string` (urllib `quote`/`quote_from_bytes`) — one Python-compatible JSON/URL encoder, owned by core.
- `pytext.Space` (Python `\s` as an RE2 class body), `pytext.IsSpace(rune) bool`, `pytext.Strip/LStrip/RStrip(string) string` (Python `str.strip()` semantics) — shared, owned by core.

---

## 2. Behaviour inventory

Line/offset arithmetic conventions used throughout: Python indexes strings by code point; every
`len(text)`, `text[:n]`, `text[i:]`, `text.split("\n")` below is over code points, so the Go code
works on `[]rune` (or `utf8.RuneCountInString`) wherever an index reaches output or a comparison.
Byte columns appear only where marked.

### 2.1 `sarif.py`

**`_validator()`** — loads the embedded schema, `Draft4Validator.check_schema`, caches. Go:
`jsonschema/v6` compiler with draft 4 and format assertions OFF (Python passes no
`format_checker`, so `format: uri` etc. are never asserted); compile once. The `id` of the schema
is read from the JSON (`schema["id"]`) for `$schema`.

**`_location(parsed, path, line_cache, start, end, offset, length, byte_columns)`** returns
`(location | None, invalid: bool)`.
1. `artifact = parsed.by_rel.get(path)` when `path` is a str.
2. Reject (return `None, True`) when: not a str; empty; `PurePosixPath(path).is_absolute()`
   (starts with `/`); `".."` is one of `path.split("/")`; or artifact is None and
   (`PureWindowsPath(path).drive` non-empty — `X:` prefix or `\\host\share` UNC — or `"\\"` in path).
   Tests: `test_sarif.py::test_unsafe_paths_are_not_emitted_as_source_uris` (`../outside.py`,
   `/tmp/file.py`, `C:/temp/file.py`, `\\host\file`), `test_relative_paths_are_uri_encoded`
   (`C:\run.py`, `C:run.py` ARE emitted when the artifact exists).
3. `physical = {"artifactLocation": {"uri": quote_from_bytes(os.fsencode(path), safe="/")}}`:
   UTF-8 bytes, every byte outside `A-Za-z0-9_.-~/` becomes `%XX` uppercase.
   `dir/a b#é.py` -> `dir/a%20b%23%C3%A9.py`, `dir/a%20.py` -> `dir/a%2520.py`, `C:run.py` ->
   `C%3Arun.py` (`test_relative_paths_are_uri_encoded`). Go: `pytext.QuoteBytes([]byte(path), "/")`.
4. Region, inside a try that maps `ValueError|TypeError|AttributeError` to
   `({"physicalLocation": physical}, True)`:
   - `offset is not None`: require artifact with `raw`, `type(offset) is int`, `offset >= 0`,
     `type(length) is int`, `length > 0`, `offset+length <= len(raw)` else error. Region
     `{"byteOffset": offset, "byteLength": length}` (`test_unicode_columns_crlf_and_byte_regions`).
   - elif `start and start.get("line") is not None`: if `end is not None and end.get("col") is None`
     -> error ("incomplete end boundary"; test with `evidence.end={"line":2}` yields region None).
     `line_cache[path] = artifact.text.split("\n")` on first use (one split per artifact per build:
     `test_supported_code_flow_only_and_order_preserved` counts splits == 1; artifact None ->
     AttributeError -> invalid). For `position in (start, end or start)`:
     `point = {"line": line, "col": 1 if col is None else col}`;
     `_, character, _ = source_region(artifact, point, point, byte_columns, lines)`;
     record `(line, None if col is None else character)`. `source_region` (core) raises on
     non-int line/col, line out of `1..len(lines)`, col out of `1..len(line)+1` (bytes when
     `byte_columns`, else code points), and — Go must replicate — on a byte column that splits a
     UTF-8 sequence (`encoded[:col-1].decode()` raises). It returns the 1-based CODE-POINT column.
     Then `if (last, last_col or 1) < (line, col or 1): error`. Region: `{"startLine": line}`,
     plus `startColumn` when col given, plus `endLine`/`endColumn` when `end` given.
     `test_unicode_columns_crlf_and_byte_regions`: text `é = 1\r\nos.system('x')\r\n` (parse
     normalises to `\n`), opengrep byte column 4 -> `startColumn 3`.
     `test_sarif_release.py::test_verified_location_is_not_duplicated_but_original_coordinates_survive`.
   - Return `({"physicalLocation": physical}, artifact is None)`.

**`_raw_view(candidate, stable_id)`** — deep copy, `candidate_id = stable_id`; if
`analyzer == "opengrep"` or `finding.evidence.engine == "opengrep"`, drop
`evidence["fingerprint"]` (`test_canonical_output_removes_volatile_engine_ids_and_scan_local_order`).

**`_review_audit(report, identities)`** — decisions = `report.dispositions` if `review_mode` else
`report.shadow`. For each: copy only `_REVIEW_FIELDS` present (never `request`/`response`:
`test_llm_sarif.py::test_compact_audit_survives_written_sarif`); map `candidate_id` and
`reviewed_candidate_id` through `identities` (unknown -> `ValueError("Unknown LLM review
candidate")`); if `proposal` present, its `candidate_id` must equal the decision's scan-local id
(else `ValueError`) and is rewritten to the stable id. Result
`{"mode": "annotated"|"shadow", "authoritative": False, "decisions": sorted by candidate_id}`.
In Go, `Decision` is a struct: build the record as `map[string]any` from the struct (omit
nil/absent fields exactly as the Python `if key in decision` does: `Tags` nil -> absent,
`Reviewer` nil -> absent, `Proposal` nil -> present as `null`).

**`_validate_review(audit, raw)`** — every check raises `ValueError`; the Go port is a straight
transcription over `map[string]any` (type-assert everything; a wrong type is a `TypeError`/
`KeyError`, still a failure). Ordered checks:
1. keys of audit == {mode, authoritative, decisions}; mode in {annotated, shadow};
   `authoritative is False` (bool false, not falsy).
2. `candidates` = raw candidates with `provenance != "advisory-output"` keyed by id; `records` =
   decisions keyed by candidate_id; reject duplicates and any id set mismatch.
3. policy = ReviewPolicyVersion if annotated else ShadowPolicyVersion. Per decision: keys subset of
   `_REVIEW_FIELDS`; `policy_version == policy`; status in {ineligible, proposed,
   duplicate-review, budget, unavailable, incomplete-context, invalid-response, error};
   disposition in {reported, llm-disputed}; provenance in {deterministic-policy,
   llm-review-policy, llm-shadow}; shadow mode forbids llm-disputed; `reason`, `policy_version`,
   `provenance` are non-blank strings of len <= 200 (code points; `strip()` Unicode).
4. If any of {request_sha256, reviewer, response_sha256} present then {request_sha256, reviewer}
   must both be present (`test_failed_review_hashes_keep_request_and_reviewer_together`).
5. `reviewer` if present: dict with exactly {provider, model, prompt_sha256, schema_sha256};
   provider/model non-empty str, <= 200, `== strip()`, `isprintable()`.
6. All hashes (`request_sha256`, `response_sha256`, reviewer's two) fullmatch `[0-9a-f]{64}`.
7. `failure_reason` if present: non-blank str <= 200.
8. `tags` if present must equal `["llm-disputed"]` iff disposition is llm-disputed else `[]`.
9. `proposal` (key must exist; `decision["proposal"]` KeyError otherwise): if not None, decision
   must have reviewer+both hashes; validate against `RESPONSE_SCHEMA` (Draft 4: type object, no
   additional props, all 8 required, enums, `minLength`/`maxLength` in code points); then
   `candidate_id == cid`, `status == "proposed"`, and a `propose_false_positive` verdict requires
   `mechanism == "not_supported"` and `intent != "malicious"`. If None and status is proposed ->
   error.
10. `reviewed_candidate_id` if not None: != cid; in records; the original has no
    `reviewed_candidate_id`; this decision has no proposal; `candidates[cid]["finding"] ==
    candidates[original]["finding"]` (deep equality of the finding dicts); same disposition as the
    original; expected status = `duplicate-review` if original has a proposal else the original's
    status (`test_reused_review_preserves_original_outcome`). Absent while status is
    duplicate-review -> error.
11. llm-disputed with proposal None -> error.
Pinned by `test_llm_sarif.py::test_validation_rejects_broken_review_audit` (23 mutations),
`test_successful_review_requires_consistent_provenance`,
`test_every_review_outcome_has_consistent_mode_and_policy`,
`test_duplicate_review_cannot_reference_unrelated_evidence`,
`test_dispute_requires_an_actual_review_proposal`.

**`build_sarif(parsed, report)`**
1. `correlation.get("errors")` non-empty -> `ValueError("Cannot emit final SARIF after correlation
   failure; raw report retained")` (cli prints "cannot write SARIF: ..." and exits 2:
   `test_sarif_release.py::test_report_failure_preserves_findings_output[correlation]`).
2. `identities[link.candidate_id] = link.get("stable_candidate_id", link.candidate_id)`.
3. `raw` = `_raw_view` of each raw candidate, sorted by (stable) `candidate_id`.
4. `links` = copies with `candidate_id` mapped, `stable_candidate_id` popped, sorted by candidate_id.
5. `rule_ids = sorted({rule_id})`; `titles[rule_id]` = set of `finding.get("title") or
   finding["rule"]`; `rules = [{"id", "shortDescription": {"text": min(titles)}}]` (min = smallest
   string by code point: `test_native_rule_title_uses_existing_registry_title`); `indexes` by
   position.
6. Per result entry: `properties` = {`id`, `title` (title or rule), `category`
   (`security-finding` if vector else `analysis-diagnostic`), `originalSeverity`,
   `effectiveSeverity`, `evidence` (list), `disposition`, `reason` (decision_reason),
   `policyVersion`, `decisionProvenance`, `candidateIds` (sorted mapped ids), `provenance`,
   `contextDigest`, `coverage`, `governingManifest` (str or null), `limitations` (copy of list)};
   add `sxv`/`cwe`/`tier` from finding `vector`/`cwe`/`tier` only when truthy
   (`test_diagnostics_are_explicit_without_empty_security_classification`).
   result = {`ruleId`, `ruleIndex`, `message: {text: finding.message}`, `level`,
   `partialFingerprints: {fingerprint_version: fingerprint}`, `properties`}.
7. `unmapped = evidence.get("location_mapping") == "unvalidated"`; call `_location` with
   `start={"line": finding.line, "col": None if unmapped else finding.column}`,
   `end = None if unmapped else evidence.get("end")`, `offset`, `length`, `byte_columns =
   evidence.engine == "opengrep"`. If location -> `result["locations"] = [location]`. If `invalid
   and finding.path` -> append `"location-unvalidated"` to `properties["limitations"]`
   (unconditionally; may duplicate the correlate-added one). If `invalid or unmapped or not
   location or no region` -> `properties["reportedLocation"] = {path, line, column, offset,
   length}` with `null` for absent (`test_unverified_location_stays_available_with_raw_evidence`).
8. `code_flow` non-empty: each step -> `_location(parsed, step.path, cache, step.start,
   step.end, byte_columns=True)`; invalid -> `ValueError("Validated code flow lost its source
   mapping")`; steps `{"location", "kinds": [role], "executionOrder": i}`;
   `result["codeFlows"] = [{"threadFlows": [{"locations": steps}]}]`
   (`test_supported_code_flow_only_and_order_preserved`).
9. disposition suppressed -> `result["suppressions"] = [{"kind": "external", "status":
   "accepted", "justification": decision_reason}]`.
10. `results.sort(key=(SEVERITY_RANK[effectiveSeverity], properties.id))` — stable
    (`sort.SliceStable`).
11. `run` = {`tool.driver`: {name `skill-xray`, version, rules}, `columnKind:
    "unicodeCodePoints"`, `results`, `invocations: [{executionSuccessful}]`, `properties`:
    {`opengrepVersion`, `policyVersion` (disposition.POLICY_VERSION), `package{name,
    contentDigest, digestVersion}`, `capabilityContexts`, `rulesetDigest` (sha256 hex of the rule
    file bytes), `coverage`, `contextLimitations`, `contextErrors: sorted(report.context_errors)`,
    `rawScope: "emitted-results-before-reporting-deduplication"`, `rawCandidates`,
    `candidateLinks`}}. If `report.llm_usage.get("judge_enabled")` truthy ->
    `properties["llmReview"] = _review_audit(...)` (`test_empty_review_and_disabled_output`).
12. Return `{"version": "2.1.0", "$schema": schema id, "runs": [run]}`.
Ordering: `rawCandidates`/`candidateLinks`/`candidateIds`/`contextErrors`/rules sorted; results by
(rank, id). Byte-identical output across candidate-id renumbering and observation order is pinned
by `test_canonical_output_removes_volatile_engine_ids_and_scan_local_order`,
`test_observation_order_does_not_change_canonical_sarif`, `test_sarif_integration.py`.

**`validate_sarif(document)`** — wrap everything; any exception -> `ValueError("SARIF validation
failed (%s)" % type(exc).__name__)`. Steps:
1. schema validation; `run, = runs` (exactly one).
2. `capabilityContexts` must be a dict whose every value is a dict with
   `(context.get("manifest") or "") == key`.
3. `by_candidate`, `by_result` (by `properties.id`), `linked[result_id] += candidate_id`,
   `primary = [link.result_id for non-duplicate links]`. Reject if duplicate candidate ids,
   duplicate result ids, `len(links) != len(raw)`, link candidate set != raw set,
   `sorted(primary) != sorted(result ids)` (each result exactly one primary link), duplicate
   rule ids.
4. `llmReview` present -> `_validate_review`.
5. Per result: `context = contexts.get(manifest or "")`; None allowed only if `coverage ==
   "incomplete"` and (`manifest is None` or `contextErrors` non-empty)
   (`test_compact_result_cannot_contradict_raw_classification_or_lose_context[manifest]`,
   `test_failed_context_keeps_findings_without_inventing_a_context`). Then all of:
   `rules[ruleIndex].id == ruleId`; `candidateIds`, `reason`, `policyVersion` truthy;
   disposition in {reported, suppressed, corrected}; `sorted(linked[id]) ==
   sorted(candidateIds)`; `id == "finding-" + partialFingerprints[FINGERPRINT_VERSION]`;
   `rank(effective) >= rank(original)` (never raised); `level == _LEVEL[effective]`.
   `coverage == incomplete` requires run coverage incomplete. `corrected == (effective !=
   original)`; corrected additionally requires `sxv`, provenance in {operator-policy,
   llm-review-policy}, `coverage == "no-reported-gap"`
   (`test_validator_rejects_inconsistent_decisions`). llm-review-policy correction requires:
   review present, mode annotated, a supporting decision (candidate in candidateIds, disposition
   llm-disputed, status proposed, proposal verdict propose_false_positive, confidence high,
   mechanism not_supported, intent legitimate), no candidate with opengrep analyzer/engine,
   `sxv` in LLM_APPLY_VECTORS, effective == "low", `policyVersion == LLM_APPLY_VERSION`
   (`test_llm_apply.py::test_applied_correction_passes_sarif_validation`,
   `test_applied_correction_must_carry_the_apply_policy_version`). `suppressed ==
   bool(suppressions)`; suppressed requires sxv, operator-policy, no-reported-gap, and
   `suppressions[0].justification == reason`. `[canonical(e) for e in properties.evidence] ==
   sorted({canonical(candidate.finding.evidence or {})})` (`empty-evidence`, `forged-evidence`
   mutations). For each candidate: category matches its vector; `ruleId == "skill-xray/" +
   quote(rule or "unknown-rule", safe="-._")`; `sxv/cwe/tier` equal (`or None` on both sides);
   `finding.severity == originalSeverity`.
6. Per link: candidate in that result's candidateIds; `reason` truthy; disposition in
   {"duplicate", result disposition}.
Pinned by `test_sarif.py::test_schema_and_cross_reference_validation_fail_visibly` (12
mutations), `test_result_without_its_own_candidate_links_is_rejected`,
`test_unknown_disposition_is_not_a_valid_final_report`,
`test_manifest_contexts_are_isolated_and_references_validated`.

**`encode_sarif`** — validate; `canonical(document) + "\n"` as ASCII bytes; `> 64 MiB` ->
`ValueError("SARIF report exceeds 64 MiB; no partial report written")`.

**`is_within_source(path, root)`** — `path.is_relative_to(root)` (lexical, on resolved paths)
OR any of `path, *path.parents` exists and `samefile(root)` (`os.SameFile` on `os.Stat` of each
ancestor up to the filesystem root). Pinned: `test_writer_rejects_filesystem_alias_before_encoding`,
`test_sarif_release.py::test_source_and_policy_protection_uses_filesystem_identity`.

**`write_sarif(document, target, *, source_root)`**
1. `source_root = Path(source_root).resolve()`; `if target.is_symlink(): ValueError("SARIF output
   must be outside the scanned package")` (`test_cli_sarif.py::test_symlink_output_is_not_accepted_from_source`);
   `target = target.resolve()` (Python `resolve(strict=False)`: resolve the longest existing prefix
   through symlinks, append the rest; Go: `filepath.EvalSymlinks` on the deepest existing
   ancestor, then `filepath.Join` the remainder, then `filepath.Abs`).
2. `is_within_source(target, source_root)` -> same ValueError. `target.exists() and not
   target.is_file()` -> `ValueError("SARIF output must be a regular file")`.
3. `data = encode_sarif(document)` (validation happens AFTER the path checks and BEFORE any write:
   `test_atomic_write_validates_before_replacement`, `test_writer_resolves_parent_before_validation`).
4. `os.CreateTemp(filepath.Dir(target), ".skill-xray-*")`, write, `Sync`, close, `os.Rename(tmp,
   target)`; always `os.Remove(tmp)` ignoring not-exist. Rename failure leaves the previous file
   intact and no temp file behind (`test_atomic_write_validates_before_replacement`; on Windows
   `os.Rename` replaces an existing file). Missing parent dir -> the CreateTemp error propagates
   (`test_cli_bad_paths_and_policy_fail_without_overwrite[missing-parent]`).

### 2.2 `llm/config.py`

**`_validate_base_url(base_url, label)`** — `urlsplit`; ValueError (bad IPv6 bracket,
non-numeric port, port > 65535) -> `LLMConfigError("%s is not a valid URL" % label)`. Then reject
unless `scheme == "https"` (urlsplit lower-cases the scheme), hostname non-empty, `port != 0`,
no username/password, and the RAW string contains no `?` or `#`
(`test_base_url_with_bare_query_or_fragment_is_rejected`). Message: `"%s must be an https URL with a
host, no userinfo, and no query/fragment"`. Returns `base_url.rstrip("/")`
(`test_llmconfig_rejects_query_and_normalizes_trailing_slash`). Go: `net/url.Parse` then: error ->
"not a valid URL"; `u.Scheme != "https"` (Go lower-cases too); `u.Hostname() == ""`
(`https://:443` -> Python hostname None -> rejected); `u.User != nil`; port string present ->
`strconv.Atoi` must succeed and be in 1..65535 (Go does not range-check ports: `https://host:70000`
parses); `strings.ContainsAny(raw, "?#")`. Divergence: Go rejects hosts Python accepts (space or
other invalid host chars) — operator config, not parity, accept. Tests:
`test_from_env_rejects_invalid_authority` (`https://:443`, `https://host:notaport`,
`https://host:70000`, `https://user@host`), `test_from_env_rejects_malformed_url` (`https://[`),
`test_from_env_rejects_hostless_base_url`, `test_from_env_rejects_base_url_with_query`,
`test_from_env_rejects_cleartext_base_url`.

**`LLMConfig.__post_init__`** — provider `(provider or "").strip().lower()` must be in
`_PROVIDERS` else `LLMConfigError("LLMConfig.provider must be one of anthropic, openai,
openai-compatible (got %r)")`; base_url validated with label `LLMConfig.base_url`
(`test_llmconfig_rejects_unknown_provider`, `test_llmconfig_rejects_non_https_base_url`,
`test_llmconfig_rejects_hostless_base_url`, `test_llmconfig_repr_hides_api_key`).

**`from_env(env)`** — provider = `(env.get("SKILLXRAY_LLM_PROVIDER") or "").strip().lower()`;
empty -> None. Not in `_PROVIDERS` -> error `"SKILLXRAY_LLM_PROVIDER must be one of ..."`.
`base_url = (env BASE_URL or default or "").strip()`; empty -> `"openai-compatible needs
SKILLXRAY_LLM_BASE_URL (the endpoint origin)"`; validate with label `SKILLXRAY_LLM_BASE_URL`.
`api_key = (env API_KEY or "").strip()`; if empty and `base_url == default_base.rstrip("/")` for
this provider, fall back to `env[_KEY_FALLBACK[provider]]` stripped; still empty -> `"no API key:
set SKILLXRAY_LLM_API_KEY (the %s fallback applies only to the vendor's own host, not a custom
SKILLXRAY_LLM_BASE_URL)"`. `model = (env MODEL or default or "").strip()`; empty -> `"set
SKILLXRAY_LLM_MODEL (no default for this provider)"`. Tests: `test_from_env_*` (14 tests in
`test_llm.py`, lines 86-177). `strip()` here is Python Unicode strip — use `pytext.Strip`.

### 2.3 `llm/client.py`

**`_openai_token_field(cfg)`** — `"max_completion_tokens"` iff provider is `openai` and
`_OPENAI_REASONING_RE.match(model.lower())`, else `"max_tokens"`
(`test_openai_reasoning_model_uses_completion_tokens`, `test_compatible_endpoint_keeps_max_tokens_for_reasoning_name`,
`test_reasoning_regex_matches_dotted_gpt5`).

**`HTTPLLMClient.complete(system, user)`** -> `_complete(system, user, None)`.
**`complete_structured(system, user, schema)`** -> `_complete(system, user, schema if provider ==
"openai" else None)` (`test_judge_response_contract.py::test_judge_response_schema_reaches_transport_without_changing_legacy`).
The `_ORIGINAL_HTTP_COMPLETE` interceptor guard is monkeypatch ceremony: drop it
(`test_existing_complete_interceptor_cannot_be_bypassed` is not ported).

**`_complete`** — request shaping (wire bytes are not parity output; shape is pinned by tests):
- anthropic: URL `base_url + "/v1/messages"`; headers `x-api-key`, `anthropic-version:
  2023-06-01`, `content-type: application/json`; body `{"model", "max_tokens": 1024, "system",
  "messages": [{"role": "user", "content": user}]}`; if `_ANTHROPIC_THINKING_FAMILY_RE` matches
  `model.lower()`: `max_tokens = max(1024, 4096)`, `output_config = {"effort": "low"}`; else
  `temperature = 0`, never `seed` (`test_complete_anthropic_shapes_request`,
  `test_anthropic_thinking_family_omits_sampling_and_keeps_effort_low`,
  `test_anthropic_older_family_keeps_greedy_temperature`). Extract shape `anthropic`.
- openai / openai-compatible: URL `base_url + "/chat/completions"`; headers `authorization:
  Bearer <key>`, `content-type`; body `{"model", <token_field>: 1024, "messages": [system,
  user]}`; if token_field is `max_tokens`: `temperature = 0` and, provider openai only, `seed = 0`;
  else `max_completion_tokens = 4096`, `reasoning_effort = "low"`; if schema given:
  `response_format = {"type": "json_schema", "json_schema": {"name": "finding_review", "strict":
  true, "schema": schema}}` (`test_complete_openai_shapes_request`,
  `test_openai_classic_model_pins_temperature_and_seed`,
  `test_openai_reasoning_model_omits_temperature_and_seed`,
  `test_compatible_endpoint_pins_temperature_without_seed`). Extract shape `openai`.

**`_read_bounded(req)`** — whole-request wall-clock deadline `cfg.timeout` covering connect,
headers and body; body read in <= 64 KiB chunks until EOF or `total >= 1 MiB` (then
`LLMResponseError("LLM response exceeded byte budget")` — a body of exactly 1 MiB is an error).
Go: `http.NewRequestWithContext(ctx with cfg.Timeout)`, `io.ReadAll(io.LimitReader(body,
maxResponseBytes))`, `len == maxResponseBytes` -> Response error. Deadline hit anywhere ->
Transport error (`test_read_bounded_enforces_deadline_after_blocking_read`; the `read1`/socket
`settimeout` mechanics are CPython plumbing — not ported). Pinned:
`test_complete_bounds_response_body_size`, `test_llm_review_core.py::test_byte_budget_and_response_overflow_are_explicit`.

**`_retry_delay(exc, attempt)`** — `Retry-After` header parsed as int in `0..60` -> that many
seconds; else `min(0.5 * 2**attempt, 8.0)`. Go: `strconv.Atoi(strings.TrimSpace(h))` (Python
`int()` also accepts `5_0`; ignore).

**`_post(url, headers, body)`** — up to 4 attempts. Non-2xx status: in `_RETRY_STATUS` ->
remember code, sleep, retry (or break after the 3rd retry); otherwise
`LLMError("LLM endpoint returned HTTP %s" % code)` immediately (500 is NOT retried:
`test_500_is_not_retried`; a refused 3xx arrives here as its status code:
`test_complete_refuses_redirect_to_protect_key`). Any transport failure (URLError, timeout, OSError,
HTTPException, ValueError such as a non-latin-1 header, RecursionError) ->
`LLMError("LLM endpoint unreachable: <ExcName>")` — in Go any error from `http.Client.Do` or the
body read (Go's `net/http` rejects a non-ASCII header value at `Do`:
`test_non_latin1_key_becomes_llmerror`). 2xx body -> `json.loads`; failure (incl.
RecursionError on 100,000-deep arrays; Go's decoder fails past depth 10,000) ->
`LLMResponseError("LLM response was not JSON: <ExcName>")`
(`test_deeply_nested_json_body_is_response_error_not_crash`). Retries exhausted ->
`LLMError("LLM endpoint returned HTTP %s (after %d retries)")`
(`test_429_is_retried_then_succeeds`, `test_persistent_429_exhausts_retries_and_fails_closed`,
`test_anthropic_529_overloaded_is_retried_then_succeeds`). Error messages must never contain the
key or the response body (asserted by `"supersecretkey" not in str(exc)`).

**`_extract(payload, shape)`** — anthropic: `stop_reason == "max_tokens"` -> Response error
"truncated"; `text = "".join(p.get("text", "") for p in payload["content"] if isinstance(p, dict))`.
openai: `choices[0].get("finish_reason") in {"length", "content_filter"}` -> Response error;
`text = choices[0]["message"]["content"]`. KeyError/IndexError/TypeError/AttributeError (payload
is a list, `choices: ["wrong-shape"]`, missing keys) -> `LLMResponseError("bad LLM response
shape: <Name>")`; non-str text -> Response error. Go: navigate `any` with type assertions; every
failed assertion is a Response error (`test_extract_*` x4,
`test_llm_review_core.py::test_provider_truncation_cannot_look_complete`,
`test_wrong_provider_shapes_remain_response_errors`).

### 2.4 `llm/session.py`

**`LLMSession.__init__`** — `max_calls`/`max_bytes` must be non-negative ints.
**`complete(system, user, *, response_schema=None)`**:
1. `unavailable` -> `LLMError("session unavailable")`.
2. `size = utf8len(system) + utf8len(user)`; with schema `+ len(json.dumps(schema,
   sort_keys=True, ensure_ascii=False).encode())` — for `RESPONSE_SCHEMA` that is exactly **791**
   bytes (`test_judge_response_contract.py::test_shared_budget_counts_structured_schema_bytes`
   uses its own 30-char schema, so Go needs `pytext.Dumps(schema, sortKeys=true, indent=0)` with
   Python default separators, not a constant).
3. `calls >= max_calls or input_bytes + size > max_bytes` -> `LLMBudgetError("shared LLM budget
   exhausted")` before counting (`test_byte_budget_and_response_overflow_are_explicit`: with
   `max_bytes=1` the client is never called).
4. `calls += 1; input_bytes += size`; call `complete_structured` when a schema is given and the
   client has it, else `complete`. Reply must be a str with utf-8 length <= 16384 else
   `LLMResponseError("response exceeds text budget")`.
5. Exceptions: Response -> `failures += 1`, re-raise; `LLMError` or `OSError` -> `failures += 1`,
   `unavailable = True`, raise `LLMError("session transport failure")` (message replaced: a
   credential in the original text never propagates — `test_llm_shadow.py::test_transport_failure_shared_between_lanes`
   with `TimeoutError(token)`); anything else -> `failures += 1`, re-raise unchanged
   (`test_per_file_client_error_does_not_disable_later_calls`,
   `test_wrong_provider_shapes_remain_response_errors`: `unavailable` stays False). Go: `*Error`
   Kind Response -> return as is; Kind Transport or Budget, or an OS-level error (`net.Error`,
   `*os.PathError`, `syscall.Errno`, `context.DeadlineExceeded`) -> mark unavailable and return
   `&Error{Transport, "session transport failure"}`; other errors -> return unchanged.
**`usage()`** — provider default `"custom"`, model default `"unknown"` when the client has no
identity; a value is kept only if it is a str, `0 < len <= 200`, `== value.strip()` and
`isprintable()`, else `"unknown"` (`test_session_provenance_is_bounded_json_without_coercion`,
`test_session_provenance_does_not_serialize_objects_or_propagate_properties`: the missing-cfg
case gives `custom`/`unknown`, the broken-cfg cases give `unknown`/`unknown`; in Go the
`identified` interface returns strings, so only the length/strip/printable checks remain). Go
`unicode.IsPrint` matches Python `isprintable` (both exclude Cc, Cf, Cs, Co, Cn, Zl, Zp and every
Zs except U+0020). Output keys and the literal `"unit": "logical-completions; transport retries
remain separately bounded"`.

### 2.5 `llm/privacy.py` — `redact(text)`

Line count is invariant: every replacement re-emits the newlines it consumed, so line numbers in
the redacted text equal the original's (`test_named_multiline_redaction_preserves_source_locations`,
`test_yaml_block_redaction_preserves_source_locations`, and every `redacted.count("\n") ==
source.count("\n")` assertion). Steps, in order:
1. `_PEM.sub(m -> "[REDACTED]" + "\n" * m[0].count("\n"))`.
2. `text = supplychain.ReplaceSecrets(text, func(string) string { return "[REDACTED]" })` (the 9 `_SECRET_RULES` with their boundary scanner, code group).
3. `_AUTH.sub(...)` same newline-preserving replacement (never contains `\n`).
4. `_NAMED` loop over code-point indices (`pos` starts 0; `m = _NAMED.search(text, pos)`):
   - `prefix = text[text.rfind("\n", 0, m.start()) + 1 : m.start()].rstrip("\"'")`;
     `indent = len(prefix)` if `prefix.strip(" \t-") == ""` else `len(prefix) -
     len(prefix.lstrip())` (`lstrip()` = Unicode whitespace);
   - `value_prefix = text[text.rfind("\n", 0, m.start(2)) + 1 : m.start(2)]`;
   - if `"\n" in text[m.start():m.start(2)]` and `len(value_prefix) <= indent`: the "value" is a
     sibling key on a later line — emit `text[pos:m.start(2)]`, `pos = m.start(2)`, continue
     (`test_llm.py::test_redaction_keeps_following_unindented_instructions` with `password:\n`,
     `password: !!str\n`, `password:\n\n` prefixes: the instruction line survives);
   - `end = m.end()`; if the value (`m[2]`) does not start with `"` or `'`: while the text at
     `end` is `\n` + `([ \t]*)` + `([^\n]*)`: stop if group 2 is non-empty and `len(group1) <=
     indent`, else `end` = end of that line (blank lines and deeper-indented lines are absorbed:
     YAML block scalars `|`, `>-`, plain multi-line scalars);
   - emit `text[pos:m.start()]`, `m[1]` (key, separator and gap, verbatim), `"[REDACTED]"`,
     `"\n" * text[m.end(1):end].count("\n")`; `pos = end`.
   Then `text = "".join(parts) + text[pos:]`.
5. `_URL.sub(m -> supplychain._sanitize_source(m[0]))` — strips userinfo/query/fragment and
   masks embedded secrets (code group).
Pinned by the 378-case matrix `test_decorated_named_yaml_secret_is_fully_redacted`,
`test_plain_yaml_credential_is_fully_redacted_before_transmission`,
`test_escaped_quoted_secret_is_fully_removed`, `test_yaml_single_quote_escaping_is_redacted_without_losing_lines`,
`test_redaction_keeps_large_nonsecret_tokens_intact` (20k `x` + 10k `x-`: unchanged),
`test_repeated_credential_keywords_do_not_cause_quadratic_redaction` (< 1 s on 20k chars),
`test_decorated_multiline_redaction_is_bounded_and_keeps_following_text`,
`test_llm_shadow.py::test_both_llm_paths_redact_before_transmission`.
Go: run the `_NAMED` loop on `[]rune` with regexp2 (rune indices == code points, and
`FindRunesMatchStartingAt` lets lookbehind see before `pos` exactly like `re.search(text, pos)`).

### 2.6 `llm/judge.py`

Constants that reach output and must be byte-identical (pin each with a sha256 test):
- `_SYSTEM` (2,355 chars, copied verbatim from judge.py lines 53-74 with the compact schema
  appended): sha256 `6845601e243f1eba459259b8619878d972ea48ce51b5a859a90c8365fa396941` =
  `reviewer.prompt_sha256` in every decision and SARIF audit.
- `json.dumps(RESPONSE_SCHEMA, separators=(",", ":"))` (insertion order, compact) — the suffix of
  `_SYSTEM`:
  `{"type":"object","additionalProperties":false,"properties":{"candidate_id":{"type":"string","minLength":1,"maxLength":200},"verdict":{"type":"string","enum":["retain_finding","propose_false_positive","insufficient_context"]},"confidence":{"type":"string","enum":["low","medium","high"]},"mechanism":{"type":"string","enum":["supported","not_supported","unknown"]},"intent":{"type":"string","enum":["malicious","legitimate","unknown"]},"reason":{"type":"string","minLength":1,"maxLength":200},"impact":{"type":"string","minLength":1,"maxLength":200},"evidence_quote":{"type":"string","minLength":1,"maxLength":160}},"required":["candidate_id","verdict","confidence","mechanism","intent","reason","impact","evidence_quote"]}`
- `json.dumps(RESPONSE_SCHEMA, sort_keys=True)` (default separators) hashed for
  `reviewer.schema_sha256` = `47e5a2bb3e0a02fb08b1f3a0115fdd115cf2ebdabfa38b05cef3db5f3317ed47`;
  its UTF-8 length 791 is what the session budget charges per structured call.
  (`test_judge_response_contract.py::test_prompt_has_separate_reason_and_impact_fields` checks the
  schema embedded in the prompt equals RESPONSE_SCHEMA and `required` == all 8 property names.)

**`_unsubmitted_links(artifact, included)`** — links = `markdown.links` if markdown else
`fallback_links`; for each `(href, _, _)`: `urlsplit(href.strip())` ValueError -> True; scheme or
netloc -> True; if path: `posixpath.normpath(posixpath.join(dirname(artifact.rel),
NFC(unquote(path))))` not in `included` -> True. Else False. Go: do NOT use `net/url.Parse` (it
errors on inputs Python accepts, e.g. `%zz` or control chars, which would flip False to True);
write `pyURLSplit`: scheme = `^[A-Za-z][A-Za-z0-9+.-]*:` prefix; netloc = after `//` up to
`/?#`; error only on an unbalanced `[`/`]` in netloc; cut `#` then `?`; `unquote` decodes valid
`%XX` only, leaves invalid sequences, UTF-8 with replacement; `norm.NFC`; join: if path starts
with `/` it replaces the base, else `path.Join`-style `Clean` (Python keeps a leading `//`, Go
collapses it; neither is ever in `included`, so equal). Tests:
`test_llm_review.py::test_unresolved_interpretation_links_retain` (`runtime.md`, `../runtime.md`,
`https://...` retain; `#archive`, `SKILL.md` do not), `test_link_context_only_uses_included_endpoints`,
`test_malformed_html_link_preserves_other_reviews` (`http://[` -> incomplete-context for that
file only).

**`_unique(pairs)`** / **`_proposal(reply, candidate_id, snippet)`** — failure codes (fixed
strings, reach SARIF `failure_reason`), checked in this order:
1. not a str or utf-8 length > 16384 -> `response-size`.
2. `json.loads` with duplicate-key detection: any duplicate key at any depth -> `duplicate-key`;
   invalid JSON (including trailing data, empty string) -> `invalid-json`. Go: `json.Decoder` on
   the reply; top-level must be `{`; walk tokens: key, then `Decode(&json.RawMessage)`; duplicate
   top-level key -> `duplicate-key`; after `}` require EOF (`dec.More()` false and next `Token()`
   is `io.EOF`) else `invalid-json`; any decode error -> `invalid-json`. Values are then
   unmarshalled from RawMessage into `any`. Known divergences: Python accepts `NaN`/`Infinity`
   literals (then fails `field-bounds`), Go fails `invalid-json`; a duplicate key nested inside a
   non-string value is `duplicate-key` in Python, `field-bounds` in Go. Both paths end in
   `invalid-response`; only `failure_reason` differs (risk R4).
3. not an object or key set != the 8 fields -> `field-set`.
4. any value not a str, blank after Unicode strip, or > 200 code points -> `field-bounds`.
5. `candidate_id` mismatch or any enum violation (verdict/confidence/mechanism/intent) ->
   `identity-or-enum`.
6. `propose_false_positive` with `mechanism != "not_supported"` or `intent == "malicious"` ->
   `inconsistent-verdict`.
7. `evidence_quote`: > 160 code points, or not a substring of `snippet`, or blank after removing
   `[REDACTED]` and stripping -> `evidence-quote` (`test_verified_quote_is_preserved_exactly`:
   `password=[REDACTED]` is a valid quote when the snippet contains it).
8. `reason`, `mechanism`, `intent`, `impact` are `redact()`ed; any result > 200 -> `field-bounds`
   (`test_llm_sarif.py::test_redaction_bounds_preserve_report`: 181 `A` + ` api_key=a` -> 200
   chars ending `api_key=[REDACTED]`; 182 -> `field-bounds`).
Pinned: `test_judge_response_contract.py::test_invalid_responses_have_safe_diagnostic_codes` (7),
`test_llm_shadow.py::test_strict_shadow_response_failure_retains` (14),
`test_judge_precision_contract.py::test_ambiguous_or_contradictory_response_retains` (7).

**`_directive_quote(lines, line, column, anchor)`** — `column` must be an int in
`1..len(lines[line-1])` (code points) else None. `source = "\n".join(lines[line-1:])[column-1:]`;
require `source.startswith(anchor[:1])` and `_flatten_prose(source).startswith(anchor)`;
`end_line, end_column = _source_position(source, 1, len(anchor) - 1)`; `parts =
source.split("\n")`; `quote = "\n".join(parts[:end_line-1] + [parts[end_line-1][:end_column]])`;
return quote iff `_flatten_prose(quote) == anchor`. All slicing by code points.
`_flatten_prose(text)` = `re.sub(r"[ \t]*\n[ \t]*", " ", text).strip()` (Unicode strip);
`_source_position` walks lines using `len(source) - len(source.lstrip())` and
`len(source.strip())` (both Unicode-aware, code points). Pinned by the 252-case matrix
`test_llm_review_core.py::test_native_review_uses_parser_lines_and_exact_quotes` (CRLF/CR
sources, ` `/` `/`\x85`/`\v`/`\f` inside a line, soft-wrapped anchors, non-ASCII
paths; a column off by one yields `proposal is None` with no call).

**`judge_candidates(parsed, candidates, triads, session, *, apply_review)`** — one decision per
candidate, same order (scan asserts the id sequence matches). Per candidate, decision starts as
`{candidate_id, disposition: "reported", status: "ineligible", reason: "No eligible text-pattern
evidence", policy_version: REVIEW if apply_review else SHADOW, provenance:
"deterministic-policy", proposal: None}` and is then mutated; the ordered gates:
1. `contract = _CONTRACTS[(vector, rule)]`; none, or `evidence.engine` truthy, or
   `evidence.dataflow_trace` truthy -> stays ineligible
   (`test_llm_review.py::test_protected_unknown_or_wrong_occurrence_never_excluded`).
2. `anchor = evidence.directive_text` must be a non-blank str.
3. `identity = canonical-ish json.dumps(finding)`; seen before -> copy the prior outcome:
   `status = "duplicate-review"` if prior status is proposed else prior status, `reason =
   "Identical evidence; reuse prior outcome"`, `reviewed_candidate_id = prior.candidate_id`,
   `failure_reason` copied if present; with apply_review also `disposition`, `provenance`,
   `tags = list(prior.tags or [])` (`test_identical_evidence_is_not_reviewed_twice`,
   `test_duplicate_failed_attempt_does_not_claim_success`, `test_duplicate_reviews_use_stable_links`).
   Findings differing only in `evidence.destination` are NOT duplicates
   (`test_different_security_evidence_is_not_reused`).
4. `session.unavailable` -> `status "unavailable"`, reason `"LLM unavailable; retained"`.
5. `session.calls >= session.max_calls` -> `status "budget"`, reason `"Shared LLM budget
   exhausted; retained"` (`test_one_budget_for_additive_and_shadow[0]`).
6. Context: `artifact = by_rel.get(path)`; `manifest = _governing_manifest(index, path)`;
   `context = triads.get(manifest.rel if manifest else "")`; `text = artifact.text`;
   `source_lines = text.split("\n")` only if text is a str of <= 20000 code points, else `[]`.
   Set `status "incomplete-context"`, reason `"Missing or incomplete source context"`, and stop
   here when: context None, text not a str, `line` not an int in `1..len(source_lines)`,
   `len(text) > 20000`, a coverage gap (`""` or `path` or the manifest's rel is in `gaps` =
   paths of vector-less candidates), or `evidence.truncated` truthy
   (`test_review_gaps_are_scoped_and_protected_findings_retained` (30),
   `test_same_file_coverage_gap_and_source_truncation_retain`,
   `test_mechanical_coverage_unknown_or_missing_context_not_sent`).
7. `column = finding.get("column", evidence.get("col"))` (absent key -> evidence `col`; a present
   None stays None); `quote = _directive_quote(...)`
   (`test_evidence_column_fallback_and_unknown_model`).
8. apply_review only: model identity — `reviewer.model` must be a str whose `strip().lower()` is
   not in `{"", "unknown"}` else reason `"Configured model identity unavailable; retained"`
   (`test_missing_configured_model_retains_without_call`); then `set(context.limitations) -
   gap_rules` non-empty (gap_rules = rules of vector-less candidates) or `quote is None` -> stop
   (status stays incomplete-context).
9. `redacted_source = redact(text)`; apply_review and `redacted_source != text` -> reason
   `"Redaction removed source context; retained"` (`test_redaction_cannot_leak_whole_source_into_audit`).
10. Window: `lines = redacted_source.split("\n")`; `start, end = max(0, line-9), min(len(lines),
    line+8)`; for each markdown prose span `(lo, hi)` with `lo <= line <= hi`: `start = min(start,
    lo-1)`, `end = max(end, hi)`; apply_review -> `0, len(lines)`. `snippet =
    "\n".join(lines[start:end])`; `len(snippet) > 6000` or `redact(anchor) not in
    _flatten_prose(snippet)` -> stop (`test_review_never_uses_partial_source`,
    `test_redacted_live_anchor_cannot_reuse_benign_quote`).
11. `description = redact(manifest.frontmatter["description"])` if a str else None; > 2000 ->
    stop. `manifest_source = redact(manifest.text or "")` if manifest else `""`; apply_review
    requires non-empty and <= 6000. apply_review: `manifest_source != manifest.text` -> reason
    `"Redaction removed manifest context; retained"`; `included = {path, manifest.rel}`;
    `_unsubmitted_links(artifact)` or `_unsubmitted_links(manifest)` or any `parsed.refs` edge
    with exactly one endpoint in `included` -> reason `"Linked context is outside the review;
    retained"` (`test_missing_security_context_retains_without_call`).
12. Request (all keys sorted on serialisation): `candidate: {vector, rule, severity, path:
    redact(path), line, candidate_id, column, title: vector_meta(vector)["title"], evidence:
    {directive_text: redact(anchor), [directive_source: redact(quote) if quote]}}`,
    `rule_contract: {detects, false_positive_requires}`, `snippet`, `source: {kind:
    artifact.kind, start_line: start+1, end_line: end, partial_file: start > 0 or end <
    len(lines)}`, `manifest: {path: redact(manifest.rel) or None, description,
    description_line: frontmatter_key_lines.get("description") or None, [source:
    manifest_source if apply_review]}`, `context_limitations: limitations[:20]`,
    `context_limitations_truncated`, `capabilities: {claimed, declared, observed}`.
    `user = json.dumps(request, sort_keys=True, ensure_ascii=True)` (Python default separators);
    `decision.request = request`, `request_sha256 = sha256(user)`, `reviewer = {provider, model,
    prompt_sha256, schema_sha256}` (`test_contract_and_source_context_are_supplied`,
    `test_outbound_paths_are_redacted_without_changing_raw_identity`,
    `test_source_secrets_and_manifest_secrets_are_redacted`).
13. `reply = session.complete(_SYSTEM, user, response_schema=RESPONSE_SCHEMA)`;
    `response_sha256 = sha256(reply)` recorded BEFORE `_proposal` (survives an invalid reply:
    `test_returned_response_provenance_survives_even_invalid_json`; absent on transport failure:
    `test_failed_review_hashes_keep_request_and_reviewer_together`). Outcomes: Budget ->
    `budget`; `_ProposalError` -> `invalid-response`, reason `"Unusable review response;
    retained"`, `failure_reason = code`; Response error (or the ValueError/RecursionError/TypeError
    family) -> `invalid-response` with `failure_reason "response-unusable"`; Transport ->
    `unavailable`; any other error -> `error`, `"Review failed; retained"`; success -> `status
    "proposed"`, reason `"Shadow proposal only; finding retained"`, `provenance "llm-shadow"`,
    `proposal`. apply_review then: `disputed = verdict == propose_false_positive and confidence
    == high and mechanism == not_supported and intent == legitimate`; `disposition =
    "llm-disputed"|"reported"`, `tags = ["llm-disputed"]|[]`, `reason = proposal.reason |
    "Finding retained without dispute"`, `provenance = "llm-review-policy"`
    (`test_review_disputes_without_changing_findings_or_severity`,
    `test_ambiguous_or_invalid_proposals_retain`, `test_native_vector_review_modes`).
14. `reviewed[identity] = decision` (only reached after the context gates, so ineligible/
    unavailable/budget/incomplete decisions are never reused as "prior").

### 2.7 `llm/adjudicate.py`

**`_target_text(p)`** — `p.text is None` -> None; kind in `INSTRUCTION_KINDS` -> text; kind in
`_CONFIG_KINDS` -> `_config_prompt_text(p.config)`; else None
(`test_adjudicate_skips_non_instruction_artifacts`, `test_doc_kind_is_adjudicated`).

**`_config_prompt_text(config)`** — depth-first over dict/list in insertion order (the reversed
push onto a stack makes pops come out in original order): for each dict item, `normalized =
"".join(ch for ch in str(key).lower() if ch.isalnum())`; if in `_PROMPT_KEYS` and the value is a
non-blank str -> append `"%s: %s" % (key, child)`; elif container -> descend. Returns
`"\n".join(found) or None` (`test_adjudicate_checks_only_prompt_bearing_config_fields`,
`test_adjudicate_skips_config_without_prompt_bearing_fields`). Go: `unicode.IsLetter ||
unicode.IsNumber` for isalnum; requires ordered config (risk R6).

**`_wrap(text, open, close)`** — `truncated = len(text) > 20000` (code points); returns
`open + "\n" + text[:20000] + "\n" + close`.

**`_parse(resp)`** — non-str -> None. Scan from each `{`: `raw_decode(resp, i)` (one JSON value
starting at `i`); failure (incl. RecursionError) -> next `{` after `i`; a dict with
`prompt_injection`: positive `_verdict` -> return it immediately (a positive anywhere wins), else
remember the first as `verdict`; a dict without the key -> first one is `fallback`; continue after
the decoded object's end. Attempt cap 200: if the loop stopped with `i != -1` -> None
(`test_parse_cap_hit_is_inconclusive_not_silent_clean`, `test_adjudicate_bounds_parse_attempts_on_brace_flood`).
Return `verdict` else `fallback`. Duplicate `prompt_injection` keys in one object force the value
to None (`test_duplicate_verdict_key_is_inconclusive_not_clean`). Go: `json.Decoder` over
`resp[i:]`, top-level token walk as in `_proposal` (top-level duplicate detection suffices here),
`InputOffset()` for the end; depth > 1000 -> treat as decode failure (Python's RecursionError;
`// ponytail:` the exact CPython limit is not reproducible, 1000 is the documented default). Tests:
`test_adjudicate_parses_verdict_with_trailing_prose`, `test_adjudicate_skips_stray_leading_object`,
`test_adjudicate_positive_verdict_wins_over_embedded_clean`, `test_adjudicate_deeply_nested_reply_does_not_crash`.

**`_verdict(v)`** — bool -> itself; int/float -> `v != 0` (NaN is truthy); str ->
`strip().lower()` in {true, yes, 1} / {false, no, 0}; else None
(`test_adjudicate_string_false_is_not_a_finding`, `test_adjudicate_string_true_fires`,
`test_adjudicate_malformed_verdict_is_inconclusive_not_clean`). JSON numbers decode to float64 in
Go; same truthiness.

**`_severity(raw)`** — `"low"` iff raw is a str whose `lower()` is `"low"`, else `"medium"`
(`str(raw).lower()` can only equal `"low"` for a str) (`test_adjudicate_flags_injection_capped_medium`,
`test_adjudicate_low_severity_stays_low`).

**`adjudicate(parsed, client, max_files)`** — targets = artifacts with a target text, sorted by
`(_KIND_ORDER.get(kind, 9), rel)` (`test_adjudicate_checks_manifest_before_generic_instruction`).
Per target `idx`:
1. `calls >= max_files` -> Finding(`""`, `llm-budget`, low, path, `"LLM adjudication file budget
   (%d) reached; %s and any later instruction files were not LLM-checked" % (max_files, rel)`,
   evidence `{"unchecked": len(targets) - idx}`); break.
2. `calls += 1`; `redacted = redact(text)`; nonce = `rand.Text()` from `crypto/rand`;
   delimiters `<<<SKILL_%s>>>` / `<<<END_%s>>>`; `user, truncated = _wrap(redacted, ...)`;
   system = `_SYSTEM_TEMPLATE % (open, close)`.
3. `reply = client.complete(system, user)`; a str reply of utf-8 length > 16384 raises
   `LLMResponseError`. Exceptions: Budget -> Finding(`llm-budget`, `"Shared LLM budget exhausted;
   remaining instruction files unchecked"`, evidence unchecked count), break; Response ->
   Finding(`llm-error`, `"LLM adjudication response was unusable (%s); this file was not
   LLM-checked" % ErrName`), continue; Transport -> Finding(`llm-unavailable`, `"LLM adjudication
   did not complete (%s); deterministic findings stand and this file and any later instruction
   files were not LLM-checked" % ErrName`, evidence unchecked count), break; other ->
   Finding(`llm-error`, `"LLM adjudication errored on this file (%s); it was not LLM-checked" %
   ErrName`), continue. `ErrName` yields `LLMError`/`LLMResponseError`/`LLMBudgetError` for
   `*Error`, `Exception` otherwise (Python emits the raising class's name; in production only the
   three LLM names occur because the session normalises everything else).
4. `truncated` -> Finding(`llm-truncated`, `"skill text exceeded 20000 chars; only the first
   20000 were LLM-checked and the tail was not analysed"`) (emitted before the verdict is parsed).
5. `verdict = _parse(reply)`; None -> Finding(`llm-unparseable`, `"LLM adjudication returned an
   unparseable verdict; this file was not LLM-checked (deterministic findings stand)"`), continue.
6. `flagged = _verdict(verdict.get("prompt_injection"))`; None -> Finding(`llm-inconclusive`,
   `"LLM verdict lacked a clear prompt_injection boolean; this file's result is inconclusive and
   is not read as clean"`), continue; False -> nothing.
7. `quote = raw_quote[:160]` if str else `""`; `verified = quote.replace("[REDACTED]",
   "").strip() != "" and quote in redacted[:20000] and quote in text`
   (`test_advisory_quote_requires_original_and_transmitted_text`, `test_quote_from_truncated_tail_is_not_verified`);
   `reason = redact(raw_reason)[:200]` if str else `""`. Finding(`SXV-038`,
   `semantic-prompt-injection`, `_severity(...)`, path, `"LLM classifier flags likely prompt
   injection, covert exfiltration, or user-manipulation in this skill text (advisory): %s" %
   reason`, evidence `{"classifier_reason": reason, "quoted_span": quote if verified else "",
   "quote_verified": verified, "oracle": "llm"}`). All SXV-038 findings have no line/column.
All 20000/160/200 limits are code points. Pinned by ~40 `test_adjudicate_*` tests in
`test_llm.py` (lines 183-473, 835-875) and `test_llm_shadow.py::test_additive_redacts_before_cutoff_and_returned_explanations`.

**`coverage_summary(parsed, findings)`** — `eligible` = artifacts with a target text; `truncated`
= count rule `llm-truncated`; `flagged` = count vector SXV-038; `skipped` = sum of
`evidence["unchecked"]` over rules in `_SKIP_RULES`; `errored` = count rules in `_ERROR_RULES`;
`checked = max(0, eligible - skipped - errored)`; if any `llm-error` finding has an empty path
(scan-level abort) -> `checked, errored = 0, eligible`
(`test_coverage_summary_counts_budget_skips_accurately`,
`test_coverage_summary_whole_pass_abort_counts_every_eligible_as_errored`).

---

## 3. Regex inventory

8 compiled patterns in the group. 7 go to stdlib `regexp` (RE2); 1 (`_NAMED`) goes through
`dlclark/regexp2`. The 9 `_SECRET_RULES` patterns `redact()` applies belong to the code group
(supply_chain) and are inventoried there; this group only calls them.

| # | File:line | Pattern (Python) | RE2 verdict | Go form / notes |
|---|---|---|---|---|
| 1 | sarif.py:149 | `re.fullmatch(r"[0-9a-f]{64}", value)` | unchanged | `^[0-9a-f]{64}$` (Go `$` without `m` is end-of-text, same as `fullmatch`). |
| 2 | client.py:40 | `(?:o[1-9]\|gpt-5)(?:[-.]\|$)` used with `.match()` (anchored at start) | unchanged | `^(?:o[1-9]\|gpt-5)(?:[-.]\|$)`. Python `$` also matches before a trailing `\n`; model ids are stripped, so no effect. |
| 3 | client.py:51 | `^claude-(?:opus-(?:4-[7-9]\|5)\|sonnet-5\|fable\|mythos)` `.match()` | unchanged | same text. ASCII only. |
| 4 | privacy.py:143 | `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----\|\Z)` DOTALL | unchanged (`\Z`->`\z`) | `(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----\|\z)`. RE2 leftmost-first gives the same lazy extent. |
| 5 | privacy.py:146 | `\b(?:Bearer\|Basic)[ \t]+[A-Za-z0-9._~+/=-]+` IGNORECASE | rewrite (`\b` differs) | Python `\b` is Unicode (`\w` = alnum + `_`); Go `\b` is ASCII, so `éBearer x` is redacted by Go and not by Python. Redaction feeds the apply-review gate `redacted_source != text`, so match exactly: `(?i)(^\|[^\pL\pN_])((?:Bearer\|Basic)[ \t]+[A-Za-z0-9._~+/=-]+)` and re-emit group 1 in the replacement. Adjacent matches stay equivalent because the token class never consumes the boundary char. |
| 6 | privacy.py:148 | `_NAMED` (see below) | **regexp2** | 1 lookbehind, 3 lookaheads, search-from-position semantics with lookbehind visibility. |
| 7 | privacy.py:157 | `\n([ \t]*)([^\n]*)` with `.match(text, end)` | unchanged, but not needed | Anchored match at a known index: implement as 3 lines of slicing (`text[end]=='\n'`, run of `[ \t]`, rest of line). Ponytail rung 6. |
| 8 | privacy.py:158 | `(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://[^\s<>"']+` IGNORECASE | rewrite | `(?i)(^\|[^a-z0-9+.-])([a-z][a-z0-9+.-]*://[^<>"'` + `pytext.Space` + `]+)`; replacement `g1 + SanitizeSource(g2)`. Equivalent: the body class stops only on whitespace/`<>"'`, none of which is in the lookbehind class, so the boundary char is always available as the prefix. `\s` must be the Python class (`\t\n\v\f\r \x1c-\x1f\x85` plus `\p{Z}`), because Go `\s` is `[\t\n\f\r ]` (no `\v`, no NBSP/U+2028) and a URL followed by NBSP would otherwise swallow the next word. |

`_NAMED` (privacy.py:148-156), flags `(?ims)`:
```
((?<![\w-])(?=[\w-]*(?:token|password|passwd|secret|api[_-]?key|authorization))[\w-]+["']?[ \t]*[:=]GAP)
(?:[!&][^\s]*GAP){0,2}
("""(?:\\.|(?!""").)*(?:"""|\Z)|'''(?:\\.|(?!''').)*(?:'''|\Z)|"(?:\\.|[^"\\])*(?:"|\Z)|'(?:''|\\.|[^'\\])*(?:'|\Z)|[^\n]+)
GAP = [ \t]*(?:\n(?:[ \t]*\n)*[ \t]+)?
```
Decision: regexp2, because (a) the lookbehind must see the character before the search start
(`_NAMED.search(text, pos)` after `pos = m.start(2)`), which a prefix-capture rewrite cannot do
without two pattern variants and slice bookkeeping; (b) the two negative lookaheads guarding the
triple-quote bodies have an unterminated-string edge case (`"""a"` at EOF) where every RE2
rewrite I checked changes the match extent; (c) the CLAUDE.md rule allows regexp2 for exactly
this. Go text: same pattern with `\Z` -> `\z` (regexp2's `\Z` is .NET's, which also matches
before a final newline), drop `m` (no `^`/`$` in the pattern), keep `(?is)`, compile with
`regexp2.None`, run on `[]rune` via `FindRunesMatchStartingAt(runes, pos)` (rune indices =
Python code-point indices; lookbehind sees `runes[pos-1]`). Carry the one-line comment
`// regexp2: lookbehind must see the char before the search start; three lookaheads`. No
`MatchTimeout` (Python has none; the pattern is linear on the 20k-repeat test because the
lookbehind fails at every position after the first). `\w` and `\s` divergences: regexp2 `\w` =
.NET (L, Mn, Nd, Pc) vs Python (L, N, `_`): a key containing a combining mark or `²` shifts
the word boundary; `[^\s]` is Unicode in both. Accept (secret keys in real skills are ASCII
identifiers) and note in R5.

Case-insensitivity: Go `(?i)[a-z]` also matches U+017F and U+212A; Python additionally matches
U+0130 and U+0131. Only patterns 5 and 8 apply `(?i)` to Unicode input; the divergence needs a
Turkish dotted I glued to `earer`/a URL scheme — accept.

---

## 4. Third-party replacements

| Python | Used for | Go |
|---|---|---|
| `jsonschema.Draft4Validator` (`jsonschema==4.26.0`) | schema-check + validate the SARIF document; validate each review `proposal` against `RESPONSE_SCHEMA` | `github.com/santhosh-tekuri/jsonschema/v6` (already in go.mod, mcp-xray uses it transitively): `Compiler` with `Draft4`, `AssertFormat = false` (Python asserts no formats), `AddResource(id, bytes)`, `Compile(id)`, `Schema.Validate(any)`. Compile both schemas once (`sync.OnceValues`). The `RESPONSE_SCHEMA` `maxLength` is code points in both libraries (JSON Schema mandates it; verify with a test containing `é`). API surface needed: `NewCompiler`, `Compiler.DefaultDraft(Draft4)`, `Compiler.AssertFormat`, `Compiler.AddResource`, `Compiler.Compile`, `Schema.Validate`, `*ValidationError`. |
| `urllib.parse.quote` / `quote_from_bytes` | rule ids, artifact URIs | `pytext.Quote`/`QuoteBytes` (core; a 6-line loop: keep `A-Za-z0-9_.-~` and the `safe` set, else `%XX` uppercase). `net/url.PathEscape` keeps `:@&=+$,;` and is wrong here. |
| `urllib.parse.urlsplit` | base-url validation (config), link classification (judge) | config: `net/url.Parse` plus manual port range check (section 2.2). judge: hand-written `pyURLSplit` (section 2.6) — `net/url` errors on inputs Python parses. |
| `urllib.parse.unquote` | link paths | tiny decoder: valid `%XX` only, others literal, UTF-8 with U+FFFD replacement (`url.PathUnescape` errors on `%zz`). |
| `unicodedata.normalize("NFC")` | link path normalisation | `golang.org/x/text/unicode/norm` `norm.NFC.String` (already in go.mod). |
| `posixpath.join/normpath/dirname` | link resolution | `path.Dir`, `path.Clean`, with the Python rule that an absolute second operand replaces the base (section 2.6). |
| `urllib.request` / `http.client` | HTTP client | `net/http` with `CheckRedirect` returning `http.ErrUseLastResponse`, `context.WithTimeout(cfg.Timeout)`, `io.LimitReader`. No vendor SDK (Python deliberately avoids them; mcp-xray's `anthropic-sdk-go`/`openai-go` are not needed). |
| `json` (`loads` with `object_pairs_hook`, `JSONDecoder.raw_decode`, `dumps` variants) | verdict parsing, request/prompt serialisation, canonical output | `encoding/json` `Decoder` (`Token`, `Decode(&json.RawMessage)`, `InputOffset`, `UseNumber`) for parsing; `pytext.Dumps`/`pytext.Canonical` (core) for every serialisation whose bytes are hashed or written (request text, schema text, SARIF). |
| `hashlib.sha256` | audit hashes, ruleset digest | `crypto/sha256` + `hex.EncodeToString`. |
| `secrets.token_hex(8)` | prompt delimiters | `crypto/rand.Read(8 bytes)` + hex. |
| `tempfile.NamedTemporaryFile`, `os.replace`, `os.fsync` | atomic write | `os.CreateTemp(dir, ".skill-xray-*")`, `File.Sync`, `os.Rename`. |
| `pathlib.Path.resolve/is_symlink/samefile/is_relative_to/parents` | output-path safety | `filepath.EvalSymlinks` (on the deepest existing ancestor), `os.Lstat` + `ModeSymlink`, `os.SameFile`, `filepath.Rel` without `..` prefix, ancestor loop via `filepath.Dir`. |
| `PurePosixPath.is_absolute`, `PureWindowsPath.drive` | reject unsafe artifact paths | `strings.HasPrefix(p, "/")`; drive = `len>=2 && p[1]==':' && isASCIILetter(p[0])` or UNC prefix `\\`/`//` followed by `host\share` (Python's `PureWindowsPath("//host/share").drive` is `\\host\share`; `"\\\\host\\file"` also has a drive). The test inputs are `C:/temp/file.py`, `\\host\file`, `C:\run.py`, `C:run.py`. |
| `copy.deepcopy` | never mutate report/candidates | build fresh maps; the Go code never aliases input maps into the document (tests assert `report.to_dict()` unchanged after `build_sarif`). |
| `functools.lru_cache` | validator cache | `sync.OnceValues`. |
| `dataclasses` | `LLMConfig` | plain struct + constructor. |
| `time.monotonic/sleep` | deadline, backoff | `context` deadline; `var sleep = time.Sleep`. |
| markdown_it, tree_sitter, ruamel, packaging, tomllib, html, shlex, ipaddress, zipfile/tarfile, bisect, heapq | not used by this group | — (the group consumes parse results only: `Markdown.links`, `Markdown.prose_spans`, `frontmatter`, `frontmatter_key_lines`, `config`). |

---

## 5. Python semantics that do not translate

| Python use | Where | Go handling |
|---|---|---|
| `str.strip()/lstrip()/rstrip()` with no args (Unicode whitespace = `\t\n\v\f\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000`) | config env values; judge `anchor.strip()`, `v.strip()` in `_proposal`, `quote.replace(...).strip()`; adjudicate `child.strip()`, `_verdict`; session `value == value.strip()`; sarif `decision[key].strip()`, `reviewer[key].strip()`; privacy `prefix.lstrip()`; `_flatten_prose`/`_source_position` (instruction group) | `strings.TrimSpace` is close but not equal (Go `unicode.IsSpace` lacks `\x1c-\x1f` and includes nothing extra). Use `pytext.Strip` etc. built on the exact set above (core-owned). |
| `str.strip(" \t-")`, `rstrip("\"'")` | privacy indent logic | `strings.Trim(s, " \t-")`, `strings.TrimRight(s, "\"'")` — exact. |
| `str.lower()` | provider, model, `_verdict`, `_severity`, `_config_prompt_text` keys | `strings.ToLower` (Unicode simple mapping; Python uses full mapping, e.g. `İ` -> `i̇`). Irrelevant for the enum/keyword comparisons involved. |
| `str.isalnum()` | `_config_prompt_text` key normalisation | `unicode.IsLetter(r) \|\| unicode.IsNumber(r)` (Python: L*, Nd, Nl, No). |
| `str.isprintable()` | session identity, sarif reviewer identity | `unicode.IsPrint` for every rune — same category set. |
| `len(str)`, slicing `[:n]` | every 200/160/6000/20000 limit, `_wrap`, quote/reason truncation, column math | `utf8.RuneCountInString`, `[]rune` slicing. |
| `len(s.encode("utf-8"))` | session byte budget, 16384 reply cap, `_proposal` size | `len(s)` on a Go string (bytes). |
| dict insertion order | decisions, request, `_config_prompt_text`, `titles` sets | Decisions/requests: struct field order (irrelevant where sorted or compared as parsed JSON). `_config_prompt_text`: needs an ordered `Config` (R6). |
| `json.dumps(sort_keys=True, ensure_ascii=True)` default separators `", "`/`": "`; `ensure_ascii` escapes every rune > U+007E **including U+007F** as `\u007f`, non-BMP as UTF-16 surrogate pairs `\ud83d\ude00`, lowercase hex; short escapes `\" \\ \n \r \t \b \f`, other C0 as `\u00XX`; `True`->`true`, `None`->`null` | request text hashed into `request_sha256`; schema text hashed into `schema_sha256` | `pytext.Dumps(v, sortKeys=true, indent=0)` must reproduce this byte-for-byte (core). Go's `encoding/json` escapes `<>&` and emits UTF-8 — do not use it for hashed text. |
| `json.dumps(separators=(",",":"))` unsorted | prompt suffix | a string constant (section 2.6), pinned by sha256. |
| `float` repr in `json.dumps` (`1e+16`, `1e-05`, `100.0`, `1.2345678901234568e+17`; exponent form when `exp < -4 or exp >= 16`) | any float inside evidence/capability contexts that reaches SARIF | `pyjson` float formatting: `strconv.FormatFloat(f, 'r'...)` does not exist — use shortest-roundtrip digits (`'g', -1`) and re-layout to Python's rule (fixed with `.0` when integral and `< 1e16`, else `e+XX`/`e-XX` with at least two exponent digits). No float is produced by this group itself; core owns the encoder. |
| `json.loads` leniency: accepts `NaN`/`Infinity`, rejects trailing data, big ints exact | `_proposal`, `_parse`, `_post` | Go rejects `NaN`/`Infinity` (R4); trailing-data check must be added explicitly (`dec.More()`/EOF); numbers into `any` become float64 (truthiness preserved). |
| `json.JSONDecoder.raw_decode(s, i)` | `_parse` | `json.NewDecoder(strings.NewReader(s[i:]))` + `InputOffset()`; `s[i:]` must be sliced at a byte index of the `{` (ASCII, so rune/byte agree at that point; compute code-point offsets only where they reach output — they do not here). |
| `RecursionError` on ~1000-deep JSON | `_parse`, `_post`, `_proposal` | Go's decoder fails at depth 10,000; `_parse` additionally caps at 1000 (section 2.7); the others just map any decode error the same way Python does. |
| `%` formatting (`%s`, `%d`, `%r`) | all finding messages and error strings | `fmt.Sprintf` with `%s`/`%d`; `%r` only in a config error (`got %r` -> `%q`). |
| `sorted()` stability, tuple keys `(rank, id)`, `(line, col or 1)` tuple comparison | sarif results sort, region inversion check, `_review_audit` sort | `sort.SliceStable` with an explicit comparator; write the tuple comparison out. |
| `min(set_of_str)` | rule titles | `slices.Min` over the collected titles (byte order == code-point order). |
| `type(x) is int` (rejects bool) | offsets, lines, columns, budgets | JSON-decoded ints arrive as float64/json.Number in generic documents and as `*int` in typed findings; a Go `bool` never satisfies an int assertion, matching Python. Treat a float64 with a fractional part as "not int". |
| `isinstance(v, bool)` before `isinstance(v, (int, float))` | `_verdict` | Go type switch `case bool` before `case float64`. |
| `getattr(obj, name, default)` duck typing | session identity, `complete_structured` | optional interfaces (`identified`, `structuredCompleter`). |
| exception class names in messages (`type(exc).__name__`) | adjudicate coverage notes, `validate_sarif` wrapper, client errors | `Kind.PyName()` / `ErrName` (section 1.3); `ValidationError` vs `ValueError` in the SARIF wrapper. |
| `Path.resolve(strict=False)` on a non-existent target | `write_sarif` | EvalSymlinks on the deepest existing ancestor + join. |
| `os.fsencode` (surrogateescape) | artifact URI | Go strings already hold the raw bytes if core keeps undecodable filename bytes verbatim (R7). |
| `shlex`, `posixpath` beyond join/normpath, `html.unescape`, `bisect`, `heapq`, `unicodedata.category`, `str.casefold`, `str.split()` on arbitrary whitespace | not used in this group | — |

---

## 6. Test port plan

Counts are `pytest --collect-only` on main (parametrized expansions included).

| pytest file | collected | covers | fixtures read | Go test |
|---|---|---|---|---|
| `tests/test_sarif.py` | 44 | build/validate/encode/write, URI encoding, regions, code flows, canonical stability, 12 validator mutations | `make_package` (tmp dir from inline dict), `test_correlate.candidate/loc/package`, `test_disposition.policy_for` | `internal/sarif/sarif_test.go` |
| `tests/test_sarif_release.py` | 48 | diagnostics classification, reportedLocation, validator decision consistency, writer symlink/case-alias safety, capability-context size bound, CLI policy protection (5 CLI cases -> core) | same helpers | `internal/sarif/release_test.go` (CLI-driven cases move to `cmd/skill-xray` tests) |
| `tests/test_sarif_integration.py` | 6 | frozen micro-corpus through `scan_report` + `build_sarif`, byte-identical across two runs | `test_postdetect_microcorpus._CASES` | `internal/sarif/integration_test.go` reading the same corpus the core group exports as `testdata` |
| `tests/test_cli_sarif.py` | 28 | `--sarif`/`--policy` CLI semantics, exit codes, atomic failure | inline | owned by core (`cmd/skill-xray`); this group supplies `Validate` for the assertions |
| `tests/test_llm.py` | 101 | `from_env` (16), `adjudicate` (~45), client extraction/shaping/retry/redirect/bounds (~40) | none (in-memory fake artifacts and fake clients; `monkeypatch(c._opener.open)` -> `httptest.Server` or an `http.RoundTripper` stub) | `internal/llm/config_test.go`, `adjudicate_test.go`, `client_test.go` |
| `tests/test_llm_review_core.py` | 669 | 252-case native review matrix (parser lines, exact quotes, CRLF/CR, non-ASCII paths), 378-case decorated YAML secret matrix, redaction line-preservation, session provenance, provider truncation | `make_package`, `review_helpers.Reviewer` | `internal/llm/judge_test.go`, `privacy_test.go`, `session_test.go` as table tests generated from the same parameter lists |
| `tests/test_llm_review.py` | 73 | annotated review policy, gaps (30), links, model identity, CLI wiring (3 -> core) | `make_package` | `judge_test.go` |
| `tests/test_llm_sarif.py` | 154 | `llmReview` audit export + 23 audit mutations + provenance/mode/policy matrices (2x8x3, 2x2x5, 2x7) + CLI full pipeline (2 -> core) | `test_llm_review` helpers | `internal/sarif/review_test.go` |
| `tests/test_llm_shadow.py` | 48 | shadow mode, 14 strict response failures, redaction before transmission (9 secrets), shared budget/transport | `make_package` | `judge_test.go`, `privacy_test.go` |
| `tests/test_llm_apply.py` | 20 | `--llm-apply` demotion; 4 tests touch this group (`test_applied_correction_passes_sarif_validation`, `..._must_carry_the_apply_policy_version` x2, `test_apply_demotes...` via judge); the rest is `disposition.apply_llm_review` (core) | `make_package` | split: 4 here, 16 core |
| `tests/test_judge_precision_contract.py` | 23 | shadow spend rules, contract text, dedupe, budget sharing, CLI coverage claims (3 -> core) | `review_helpers` | `judge_test.go` |
| `tests/test_judge_response_contract.py` | 18 | prompt/schema identity, structured `response_format` per provider, schema byte budget, 7 diagnostic codes, structured failure statuses; 3 monkeypatch-interceptor cases are not portable | `review_helpers.direct_review` | `judge_test.go`, `client_test.go` |
| `tests/test_schema_packaging.py` | 9 | vendored schema bytes; 8 are Python build/wheel tests (not ported), 1 pins the sha256 | `src/skill_xray/schemas/sarif-schema-2.1.0.json` | `internal/sarif/schema_test.go`: embedded bytes sha256 == `c3b4bb...`; README embedded verbatim |
| Partial coverage elsewhere | `test_cli.py` (3 llm tests), `test_cli_analyze.py` (5), `test_scan.py` (1), `test_disposition.py` (1), `test_report.py` (1), `test_fence_locations.py` (3 `build_sarif`/`validate_sarif` calls) | core-owned; they exercise `FromEnv`, `BuildClient`, `CoverageSummary`, `Build`, `Validate` through the CLI | — |
| Not this group | `test_url_deadline.py` (27: `resolve._download_capped`, core ingest), `test_msb_llm_reports.py` (5: `benchmark/` scripts) | — | — |

Total to port for this group: **1,232** collected cases (44+48+6+101+669+73+154+48+23+18 plus 4
from `test_llm_apply.py`, minus the 3 interceptor cases) + 1 schema-hash test; the 28 CLI SARIF
cases and 5 CLI review cases are ported by core against this group's API.

How the Go tests are written:
- Table tests keyed by the same parameter tuples as the `@pytest.mark.parametrize` lists (copy
  the lists, do not re-derive them); the two large matrices in `test_llm_review_core.py` become
  nested `for` loops over the same slices with `t.Run` names built from the parameters.
- Package fixtures are built exactly like `make_package`: a `testdata`-free helper
  `writePackage(t, map[string]string)` into `t.TempDir()` (the Python fixtures are inline dicts,
  there are no fixture files to read for this group except the schema and the shared
  micro-corpus, which core exports under `internal/scan/testdata/microcorpus/` and this group
  reads by path).
- Fake clients: `Reviewer{changes map[string]any}` and `FakeClient{reply string; err error}`
  implementing `Completer`; `Reviewer` also implements `identified` returning
  `("fixture", "fixture-1")`. The Python `SimpleNamespace(cfg=...)` invalid-identity cases collapse
  to the three string checks (length/strip/printable).
- HTTP client tests use `httptest.NewTLSServer`? No: `Config` requires `https` and the test server
  certificate is untrusted. Use an `http.RoundTripper` stub injected through an unexported
  `newHTTPClient(cfg, rt)` constructor (the Python tests monkeypatch `c._opener.open`, the same
  seam). `sleep` is replaced with a no-op recorder.
- Pinned constants: prompt sha256, schema sha256, schema budget 791, template sha256, schema
  file sha256 — one `TestConstants`.
- Byte-identity assertions (`encode_sarif(a) == encode_sarif(b)`, written file == `Encode`) stay
  as `assert.Equal` on `[]byte`.

---

## 7. Parity hooks

Fields this group writes, for `tools/parity` attribution:

- **SARIF file** (`--sarif PATH`): the whole document is produced here and is canonical
  (sorted keys, ASCII, `\n`-terminated), so the parity tool can compare bytes. Attribution
  inside the document: `runs[0].results[*].locations` / `codeFlows` / `properties.limitations`
  (`location-unvalidated` appended here) / `properties.reportedLocation` -> `_location`;
  `runs[0].tool.driver.rules` (ids, `shortDescription.text` = min title) and `results[*].ruleIndex`,
  `level`, `properties.{category,title,sxv,cwe,tier}`, `suppressions`, result order ->
  `build_sarif`; `runs[0].properties.{opengrepVersion, policyVersion, rulesetDigest, rawScope,
  contextErrors, rawCandidates (stable ids, opengrep fingerprint dropped), candidateLinks
  (stable ids, no stable_candidate_id)}` -> this group; `package`, `capabilityContexts`,
  `coverage`, `contextLimitations`, `executionSuccessful`, fingerprints, `contextDigest`,
  dispositions -> core (copied verbatim here); `runs[0].properties.llmReview` -> `_review_audit`
  over judge decisions.
- **`--json` output**: `findings[*]` with `vector == "SXV-038"` or `rule` in {`llm-budget`,
  `llm-unavailable`, `llm-error`, `llm-truncated`, `llm-unparseable`, `llm-inconclusive`}
  (message text, `evidence.{classifier_reason, quoted_span, quote_verified, oracle, unchecked}`)
  -> `adjudicate`; `analysis.llmCoverage.{eligible, checked, truncated, skipped, errored,
  flagged}` -> `coverage_summary`; `enrichment.shadow[*]` and `enrichment.dispositions[*]` (every
  key incl. `request`, `request_sha256`, `response_sha256`, `reviewer`, `failure_reason`, `tags`)
  -> `judge_candidates`; `enrichment.llm_usage.{calls, input_bytes, provider, model, failures,
  unavailable, max_calls, max_input_bytes, unit}` -> `LLMSession.usage` (the three `*_enabled`
  keys are scan's).
- **stderr / exit code**: `cannot write SARIF: <msg>` and exit 2 come from `Build`/`Write`
  errors; `error: <LLMConfigError msg>` from `FromEnv`/`NewConfig`.
- Deterministic parity (LLM off) covers the SARIF path completely on the golden corpus and the
  frozen MaliciousSkillBench split. The LLM lane is not machine-comparable against a live model;
  its parity is the ported fake-client suites above. Recommendation: `tools/parity` compares
  `--json` as parsed JSON (key order of Python dicts vs Go structs differs and is not semantic)
  and SARIF as bytes.

---

## 8. Risks and open questions

- **R1 Python-compatible JSON encoder is load-bearing.** `request_sha256`, `schema_sha256` and
  the SARIF bytes all hash `json.dumps` output with Python's exact escaping (`` included),
  separators and float repr. Recommendation: core ships `pyjson` with golden tests generated from
  CPython for strings (`é`, U+1F600, `\x7f`, `\x1f`, `<>&/`), nested sort order, and floats; this
  group's constant tests (791 bytes, both sha256s) act as an integration check.
- **R2 Draft-4 validation library behaviour.** `santhosh-tekuri/jsonschema/v6` must be configured
  with format assertions off and must count `maxLength` in code points; `uniqueItems` and local
  `$ref`s are used by the SARIF schema. Recommendation: keep the library (already a dependency),
  add tests that a `format: uri`-violating `$schema` string still validates and that a 201-rune
  non-ASCII `reason` fails.
- **R3 `_NAMED` through regexp2.** Decided (section 3). Residual risk: regexp2 `\w` (.NET) vs
  Python `\w` on combining marks / `Nl`/`No` digits, and `\z` must replace `\Z`. Recommendation:
  port the 378-case redaction matrix first; it exercises every alternative of the pattern.
- **R4 `json` leniency.** Go rejects `NaN`/`Infinity` and nested duplicate keys differently, so a
  hostile reply may record `failure_reason: invalid-json` where Python records `field-bounds` or
  `duplicate-key`; the parse-depth boundary (~1000) is approximate. Both end in
  `invalid-response`/coverage notes; hashes are identical. Recommendation: accept; document in the
  Go test as an intentional divergence and do not emulate CPython's recursion limit.
- **R5 Unicode `\b`, `\s`, `strip()`.** Handled by prefix-capture (`_AUTH`, `_URL`), `pytext.Space`
  and `pytext.Strip`; residual: `(?i)` on Turkish dotted I and regexp2's `\w`. Accept.
- **R6 Config key order.** `_config_prompt_text` walks parsed JSON/YAML/TOML in insertion order;
  the text sent to the model (and therefore truncation at 20,000 chars and `quote in text`)
  depends on it. Recommendation: the parse group represents `Config` with an order-preserving
  type (`yaml.v3` `*yaml.Node`, or a `[]KV` tree); if it ships `map[string]any`, this group
  sorts keys and records the divergence (only the LLM lane, never deterministic findings).
- **R7 Non-UTF-8 filenames.** Python carries them as surrogate-escaped `str` and `os.fsencode`
  restores the bytes for the URI; `json.dumps(ensure_ascii)` emits `\udcff`. Go has no lone
  surrogates. Recommendation (core): keep undecodable bytes verbatim in the rel string; this
  group's URI encoder then produces `%FF` as Python does, and `pyjson` must escape invalid UTF-8
  bytes as `\udcXX` (surrogateescape) to hash identically. Linux-only test
  (`raw-\udcff/SKILL.md`), skip elsewhere.
- **R8 `source_region` byte-column decoding.** `_location` relies on core's `SourceRegion`
  raising when a byte column splits a multibyte sequence (Python `bytes.decode` raises). Go's
  `utf8.RuneCount` does not; core must check `utf8.Valid` and return an error, otherwise a
  region is emitted where Python emits none.
- **R9 Error names in messages.** `type(exc).__name__` reaches finding messages and
  `contextErrors`. Recommendation: `llm.ErrName` returns the three Python class names for
  `*llm.Error` and `"Exception"` otherwise; core's scan wrapper uses the same helper so the
  `llm-review-error: <Name>` text agrees. In production only the three names occur.
- **R10 Duplicate `location-unvalidated`.** `build_sarif` appends the limitation even when
  correlate already added it (missing artifact + unvalidated mapping). Port as-is; do not
  "fix" it or the SARIF bytes diverge.
- **R11 Atomic write on Windows.** `os.Rename` replaces an existing file on Windows (Go uses
  `MoveFileEx(MOVEFILE_REPLACE_EXISTING)`), matching `os.replace`; a target open in another
  process fails in both. `is_symlink` needs `os.Lstat`; junction targets are not symlinks in
  Python either. No action beyond the existing tests.
- **R12 Go version.** go.mod says 1.26; `omitzero` (1.24+) is relied on for `tags: []`. If the
  toolchain is pinned lower, use `*[]string` instead.
- **Open question (decided here): typed vs generic SARIF document.** Generic `map[string]any`
  (section 1.4). Revisit only if core ends up with fully typed correlation results, in which case
  `Build` still emits generic JSON and only its inputs change.

