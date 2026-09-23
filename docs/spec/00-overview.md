# Port overview: shared contract, dependencies, build order, parity

Status: this specification was written for the port of the Python scanner to Go and is the binding description of the detection behaviour the Go binary implements. The Python implementation, its tests, its benchmark harness, its dev tooling and the parity harness (`src/`, `tests/`, `benchmark/`, `dev/`, `tools/parity`) were removed once the port was proved identical to them; where this document refers to them, it describes the repository at the merge of pull request 42, which git history keeps.

This file is the binding cross-group contract. Where a group spec (`core.md`, `parse.md`,
`instruction.md`, `code.md`, `obfuscation.md`, `output-llm.md`) names a Go identifier or type
differently, this file wins; each group spec carries an "Errata (00-overview)" block just under its
title listing the names it must read differently. Everything else in the group specs (behaviour,
regexes, tests, risks) stands.

Oracle: `C:/Users/kumar/Desktop/Skills-Xray/skill-xray`, branch `main`,
HEAD `10143bc` (the merge of PR #41 into `origin/main`, on top of `6885be9`), Python 3.13.2
(Unicode 15.1), markdown-it-py 4.0.0, ruamel.yaml 0.18.15, tree-sitter-bash 0.25.1, packaging 24.2,
jsonschema 4.25.1, python-bidi 0.6.6, confusable-homoglyphs 3.3.1, OpenGrep 1.29.0 (cached at
`%LOCALAPPDATA%\skill-xray\opengrep\1.29.0\opengrep.exe`). The pin moved from `33f057e` on 2026-09-20
with the detection build (see "Wave 9" below) and from `77a031f` to `10143bc` on 2026-09-21 with the
errata that close that section; the worktree `_reference/skill-xray-oracle` is checked out at the pin.
The rule file is `-text` in both repositories, so a Windows checkout keeps it LF and the SARIF
`rulesetDigest` equals the blob digest that `runtime_test.go` pins.

## 1. Decisions that bind every group

| # | Decision | Reason |
|---|---|---|
| D1 | `go.mod` stays `go 1.26.0`. | `golang.org/x/text v0.42.0` and `mvdan.cc/sh/v3 v3.14.1` both declare `go 1.26.0`; `GOTOOLCHAIN=auto` has already fetched `go1.26.0` into the module cache (`go version` in this module prints go1.26.0; `GOTOOLCHAIN=local` is 1.24.1). Under 1.26 `unicode.Version == "15.0.0"` and x/text selects its 15.0.0 tables, which is what `obfuscation.md` assumes. Every "pin 1.24/1.25" line in the group specs is superseded. Never move to go1.27 (x/text switches to Unicode 17 tables) while the oracle is on 15.1. Patch releases are fine and expected: `toolchain go1.26.6` (2026-09-20, govulncheck clean; `unicode.Version` still 15.0.0) picks up the standard-library fixes without moving the language or table version. |
| D2 | The parsed IR lives in `internal/parse`. There is no `internal/ir`. | Every check imports `parse` anyway; a separate package would only re-export. `parse.ManifestIndex` / `parse.GoverningManifest` (Python `code_lane._manifest_index/_governing_manifest`) live here because capability, correlate, llm and codelane all consume them and they read only the IR. |
| D3 | Python `None` on a field that also has a valid empty value is a Go pointer or nil slice, never a sentinel or a `HasX` bool. | `Finding.Line/Column/Offset/Length *int` (offset 0 is real), `Artifact.Text *string` ("" is a read empty file), `Grant.Pattern *string`, `Diagnostic.Detail *string`, `Dep.Line *int`, `Triad.Manifest *string`; `Raw []byte`, `Grants []Grant`, `Deps []Dep` use nil for `None`. Line numbers that are never 0 (`FrontmatterEndLine`) are plain `int` with 0 = `None`. |
| D4 | One check package per Python check module; `internal/checks` holds only the registry (`Run`), `coverage.go` and `metadata.go`. | The group specs each own their package (`preproc`, `grants`, `supplychain`, `codelane`, `opengrep`, `forensics`, `instruction`, `obfuscation`); core's "one flat checks package" is withdrawn. |
| D5 | One shared Python-semantics package: `internal/pytext`. | Absorbs core's `pytext`, code's `pystr`, output-llm's `pyre` and `pyjson`, instruction's `pyshlex`, and obfuscation's `pyIsSpace`. Owner: core. Contents in §3.1. |
| D6 | One PEP 508 requirement parser: `internal/pep508`, validating versions with `github.com/aquasecurity/go-pep440-version`. | Used by `parse._req_dep` and `hooks._is_exact_pin`; the library's version regex is a port of packaging's `VERSION_PATTERN` (same groups), so parse's hand-port of PEP 440 is dropped. |
| D7 | Evidence values are `string`, `bool`, `int`, `float64` (never in practice), `nil`, `[]any`, `map[string]any`. No `json.Number` reaches evidence. | `correlate`, `disposition`, `findings._engine_occurrence`, `sarif._location` all test `type(x) is int`. The code group normalises the OpenGrep JSON tree once after `UseNumber` decoding (`json.Number` whose text has no `.`/`e`/`E` and fits int64 -> `int`; otherwise `float64`). |
| D8 | Every slice that reaches JSON is non-nil; every map used as a set/dict that is iterated for output keeps a parallel key slice for Python insertion order. | Go `null` vs Python `[]`; Go map iteration is random. |
| D9 | Observations are `map[string]any` records with keys `path, line, column, capability, state, analyzer, rule, vector, engine_rule, origin, reason(optional), command_sha256(optional)`. | `capability.Build` deep-copies them into `Triad.Evidence []map[string]any`; a struct would need a `ToMap` on both sides for nothing. |
| D10 | The tool version is `internal/metadata.Version = "0.1.0"` (as mcp-xray). | `cmd/skill-xray` (`--version`) and `internal/sarif` (`tool.driver.version`) both need it; `main` cannot be imported. |
| D11 | `--json` parity compares parsed JSON; SARIF parity compares bytes. | Python emits `evidence`/dict keys in insertion order and `100.0`; Go structs/maps sort or spell numbers differently. SARIF is canonical on both sides (sorted keys, `ensure_ascii`), so bytes must match. |
| D12 | Test helper: `internal/testutil.MakePackage(t testing.TB, files map[string]string) string` writes the files (strings are raw bytes, newlines preserved) into `t.TempDir()/pkg` and returns the root. It imports nothing from the module. | Mirrors `tests/conftest.py::make_package`; a helper that imported `parse` could not be used from `parse`'s or `ingest`'s own tests (Go forbids test import cycles). Each test then calls `parse.Parse(ingest.BuildPackage(root))` itself. |
| D13 | `FlattenProse` and `SourcePosition` are exported from `internal/instruction` and reused by `obfuscation` and `llm`. | The three Python copies are identical; one implementation, one 252-case test matrix. |
| D14 | Frontmatter is `map[string]any` (keys are `str(k)` at every depth, as `parse._plain` does) plus `FrontmatterKeys []string` (top-level keys in document order). `Config` is `map[string]any`/`[]any`/scalars decoded with `UseNumber` and normalised as in D7. | obfuscation needs frontmatter document order for deterministic finding order; `hooks` needs no non-string keys (`7:` becomes `"7"` in Python too). Config order matters only to the LLM prompt (`_config_prompt_text`), an accepted divergence (output-llm R6). |

## 2. Package map and import graph

```
cmd/skill-xray           cobra root; run(argv, stdout, stderr) int
internal/metadata        Version
internal/pytext          Python string / regex-class / shlex / URL / JSON semantics      (core)
internal/findings        Finding, Meta, Vectors, Sort, Dedupe, CapFindings, ToMaps        (core)
internal/ingest          ingest.go, resolve.go, ingest_windows.go, ingest_unix.go         (core)
internal/pyast           Python 3.13 parser: Parse, Walk, IterChildNodes, LiteralEval, Depth (code)
internal/pep508          Requirement parser (packaging grammar) + go-pep440-version        (parse)
internal/parse           IR types, Parse, ManifestIndex, GoverningManifest                 (parse)
internal/preproc         SXV-001/002                                                        (parse)
internal/codelane        Build, Unit, InstallerIdiom, DropHostRE, SupportedShell            (code)
internal/grants          SXV-003/004, Effective, Declared, Denied, ExecutionTools, NetworkTools (code)
internal/supplychain     SXV-016/017, SecretRules, ReplaceSecrets, SanitizeSource           (code)
internal/opengrep        runtime.go, bridge, Check, Run, embedded rules/opengrep-phase1.yml (code)
internal/forensics       SXV-035/036/037                                                    (code)
internal/instruction     exfil.go, persistence.go, hooks.go, FlattenProse, SourcePosition   (instruction)
internal/uba             vendored x/text unicode/bidi core.go + bracket.go                  (obfuscation)
internal/obfuscation     SXV-007/014/015                                                    (obfuscation)
internal/checks          Run (registry), coverage.go, metadata.go                           (core)
internal/capability      Triad, Build                                                       (core)
internal/correlate       Correlate, ApplyDispositions, ApplyLLMReview, constants            (core)
internal/llm             config, client, session, privacy, judge, adjudicate                (output-llm)
internal/sarif           Build, Validate, Encode, Write, IsWithinSource, embedded schema    (output-llm)
internal/scan            Scan, Report, ScanReport, Options                                  (core)
internal/testutil        MakePackage                                                        (core)
tools/parity             harness (Go) + pytest corpus-dump plugin + MSB materialiser (Python)
```

Imports (arrows point at the dependency; no cycles):
`pytext` <- everything. `findings` <- every check, correlate, capability, scan, sarif, llm.
`ingest` <- parse, instruction (IdentityFiles), correlate (BenignLedger), cmd.
`pyast` <- parse, codelane, opengrep. `pep508` <- parse, instruction.
`parse` <- preproc, codelane, grants, supplychain, opengrep, forensics, instruction, obfuscation,
checks, capability, correlate, llm, sarif, scan. `codelane` <- opengrep, instruction.
`grants` <- opengrep, capability. `supplychain` <- llm. `instruction` <- obfuscation, llm.
`checks` <- scan. `capability` <- correlate, llm, scan. `correlate` <- llm, sarif, scan.
`llm` <- scan, sarif, cmd. `scan` <- sarif, cmd. `opengrep` <- checks, sarif (Version, Rules), cmd.

## 3. Shared Go types (JSON tags are the Python `to_dict`/dict keys)

### 3.1 `internal/pytext` (no project imports; ~400 lines total)

`IsSpace(r rune) bool` (Python `str.isspace`: `unicode.IsSpace || 0x1C..0x1F`), `Space`/`NotSpace`
(RE2 class bodies `\t\n\v\f\r\x1c-\x1f \x85\p{Z}` and its negation), `IsWord(r)` (L*, N*, `_`),
`Fields`, `Strip/LStrip/RStrip`, `SplitLines` (the 12 Python line boundaries, trailing empty
dropped), `Lower` (`İ` -> `i̇`, final sigma), `CaseFold` (x/text `cases.Fold`), `SplitExt`,
`Basename`, `IsPrintable`, `Repr` (Python `repr(str)`), `UnicodeEscape` (`unicode_escape` codec),
`Quote(s, safe)`/`QuoteBytes(b, safe)` (urllib `quote`/`quote_from_bytes`), `Unquote` (valid `%XX`
only, U+FFFD per invalid byte), `URLSplit` (CPython `urlsplit` incl. `_checknetloc`), `ShlexSplit`
(POSIX), `ShlexTokens(s, punctuation, whitespaceSplit bool)` (non-POSIX configurations used by
grants, parse and hooks), `FindAllBounded(re, s, left, right func(rune) bool)` (Unicode `\b`
emulation), `OSErrorName(err)`, `Canonical(v any) string` (`json.dumps(sort_keys, ensure_ascii,
separators=(",",":"), allow_nan=False)`), `Dumps(v any, sortKeys bool, indent int) string` (Python
default separators, `ensure_ascii`, Python float repr), `DeepCopy(v any) any` (JSON values).

### 3.2 `internal/findings`

```go
type Finding struct {
    Vector   string         `json:"vector"`
    Rule     string         `json:"rule"`
    Severity string         `json:"severity"`
    Path     string         `json:"path"`
    Message  string         `json:"message"`
    Line     *int           `json:"line,omitempty"`
    Column   *int           `json:"column,omitempty"`
    Offset   *int           `json:"offset,omitempty"`
    Length   *int           `json:"length,omitempty"`
    Evidence map[string]any `json:"evidence,omitempty"` // nil or empty == Python {}
}
// ToMap adds title/cwe/tier when Vectors[Vector] exists; MarshalJSON emits ToMap in Python key order.
func (f Finding) ToMap() map[string]any
func Int(v int) *int

type Meta struct {
    Title string   `json:"title"`
    CWE   []string `json:"cwe"`
    Tier  string   `json:"tier"`
}
var Vectors map[string]Meta                   // 43 entries SXV-001..043
func MetaOf(vector string) (Meta, bool)
const Cap = 25
var SeverityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
func Rank(sev string, missing int) int
func Sort(fs []Finding) []Finding             // stable, Python _sort_key
func Dedupe(fs []Finding) []Finding
func CapFindings(fs []Finding) []Finding      // Python cap_findings (dedupe, per (path, vector-or-rule) cap 25, notes)
func ToMaps(fs []Finding) []map[string]any    // sorted
```

### 3.3 `internal/ingest`

```go
type Artifact struct {           // inventory record; CLI --json artifacts[*]
    Rel       string `json:"rel"`
    Role      string `json:"role"`
    Kind      string `json:"kind"`
    Text      string `json:"-"`   // valid only when Exception == ""
    Exception string `json:"exception"` // "" == None; CLI emits null
    Raw       []byte `json:"-"`   // nil == None; []byte{} is a read empty file
}
// CLI rows are {"rel","role","kind","read": Exception == "","exception": Exception or null}.

type LedgerEntry struct {
    Outcome    string  `json:"outcome"`          // "skipped" | "unresolved"
    Phase      string  `json:"phase"`            // "static" | "parse"
    ReasonCode string  `json:"reasonCode"`
    Path       string  `json:"path"`
    Target     *string `json:"target,omitempty"` // refused symlink target only
    Detail     *string `json:"detail,omitempty"` // parse phase only (key always present there; nil == null)
}
// The CLI ledger is built from the ingest Package before parsing (cli.py:239-241) and
// parse.Parse copies the list, so parse-phase entries never reach `ledger.exceptions` in
// --json output; they reach the coverage check and the correlate context digest only.

type Package struct {
    Root, Identity, Name string
    Artifacts            []*Artifact
    LedgerExceptions     []LedgerEntry
}

type Ledger struct { /* 14 fields as core.md §1.2, json keys artifactsSeen ... exceptions */ }
type Discovery struct { Paths []string; LedgerExceptions []LedgerEntry }
type Resolved struct { Root, Name, Kind string }
type UnsafeInputError struct{ Msg string }
type IngestLimitExceededError struct{ Msg string }

func BuildPackage(root string) *Package
func BuildLedger(p *Package) Ledger
func Discover(roots []string) Discovery
func Resolve(target string) (Resolved, func(), error)
var IdentityFiles, BenignLedger map[string]bool
var KnownSkillRoots []string
```

### 3.4 `internal/parse` (the IR)

```go
type Package struct {
    Identity, Name   string
    Artifacts        []*Artifact           // ingest order (drives every check's finding order)
    ByRel            map[string]*Artifact
    Refs             []Ref
    LedgerExceptions []ingest.LedgerEntry  // copy of ingest's + one parse entry per diagnostic
}
type Ref struct { From string `json:"from"`; To string `json:"to"`; Line int `json:"line"` }

type Artifact struct {
    Rel, Kind           string
    Text                *string          // nil == None; CRLF/CR normalised once
    Raw                 []byte           // nil == None
    Frontmatter         map[string]any   // nil == None; keys str(k) at every depth; {} for an empty block
    FrontmatterKeys     []string         // top-level keys, document order
    FrontmatterKeyLines map[string]int   // 1-based
    FrontmatterEndLine  int              // 1-based line of the closing ---/...; 0 == None
    UnsafeYamlTags      []YamlTag
    Grants              []Grant          // nil == None
    Markdown            *Markdown        // nil == None
    FallbackLinks       []Link
    Preprocessing       []Preproc
    PreprocessingCounts PreprocCounts
    PyTree              *pyast.Module    // nil == None
    ShellTree           *syntax.File     // nil == None (mvdan.cc/sh/v3/syntax)
    Config              any              // map[string]any | []any | scalar; nil == None
    ManifestKind        string           // "" == None
    Deps                []Dep            // nil == None
    Diagnostics         []Diagnostic
}
type Diagnostic struct { Code string; Detail *string }   // Canonical renders [code, detail-or-null]
type Span struct { Start, End int }                        // 1-based inclusive line span
type Fence struct { Info, Content string; Line int }       // Line = opener line; Info "" for indented code
type Link struct { Href, Label string; Line int }
type HTMLComment struct { Body string; Line, Column int }
type HTMLProse struct { Text string; Line int }            // width- and newline-preserving projection
type HTMLFragment struct { Text string; Line, Column int } // html_uninspectable
type HTMLTag struct { Name string; Line, Column int; Closing bool; Attrs [][2]string }
type Markdown struct {
    Links                []Link
    Fences               []Fence
    FenceSpans           []Span   // ```/~~~ fences only
    CodeSpans            []Span   // fences + indented code
    ProseSpans           []Span   // inline tokens without html_inline children
    ReferenceSpans       []Span
    ParagraphSpans       []Span   // top-level paragraphs (capability)
    Preproc              []Preproc
    PreprocCounts        PreprocCounts
    HTMLComments         []HTMLComment
    HTMLTags             []HTMLTag
    HTMLProse            []HTMLProse
    HTMLUninspectable    []HTMLFragment
    HasHTML, HasUninspectableHTML bool
}
type Preproc struct { Kind, Code string; Line, Column int; Runs bool; Info string }
type PreprocCounts struct { Inline, Fenced int }
type YamlTag struct { Tag string; Line, Column int }
type Grant struct { Tool string; Pattern *string; Raw string; Allowed, Broad, Parsed bool }
type Dep struct { Name, Specifier string; Pinned bool; Raw string; Line *int }

func Parse(pkg *ingest.Package) *Package          // Python parse_package
func ManifestIndex(p *Package) map[string]*Artifact              // parent dir ("" = root) -> first skill_manifest
func GoverningManifest(index map[string]*Artifact, rel string) *Artifact
const MaxPyChars = 524288
const MaxPreprocTokens = findings.Cap
var PkgBudget = 60 * time.Second
```

### 3.5 `internal/checks`, `internal/capability`

```go
// checks
func Run(p *parse.Package, opengrepExe string, observations *[]map[string]any) []findings.Finding
// registry order and check-error module names (Python strings):
// skill_xray.analyze -> forensics.AnalyzePackage; skill_xray.checks.coverage -> checks.Coverage;
// .grants -> grants.Check; .hooks -> instruction.CheckHooks; .instruction_exfil -> instruction.CheckExfil;
// .metadata -> checks.Metadata; .obfuscation -> obfuscation.Check; .persistence -> instruction.CheckPersistence;
// .preproc -> preproc.Check; .supply_chain -> supplychain.Check;
// .taint_engine -> opengrep.Check(p, opengrep.Options{Executable, Units, LaneNotes, Observations})
// codelane.Build runs first under recover; a panic yields units == nil plus the
// "executable code selection failed: %s" check-error note.

// capability
var Axes = []string{"execution", "network"}
type Triad struct {
    Manifest    *string           `json:"manifest"`
    Claimed     map[string]string `json:"claimed"`
    Declared    map[string]string `json:"declared"`
    Observed    map[string]string `json:"observed"`
    Evidence    []map[string]any  `json:"evidence"`
    Limitations []string          `json:"limitations"`
}
func Build(p *parse.Package, observations []map[string]any, coverage []findings.Finding) map[string]*Triad
```

### 3.6 `internal/correlate`

```go
const FingerprintVersion = "skill-xray/evidence/v1"
const ContextVersion     = "skill-xray/context/v1"
const PolicyVersion      = "skill-xray/scoped-policy/v1"
const LLMApplyVersion    = "skill-xray/llm-apply/v1"
var   LLMApplyVectors    = map[string]bool{"SXV-028": true, "SXV-029": true, "SXV-030": true, "SXV-031": true}

func Digest(v any) string                     // sha256 hex of pytext.Canonical(v)
func SourceRegion(a *parse.Artifact, start, end map[string]any, byteColumns bool, lines []string) (text string, startCol, endCol int, err error)

type Candidate struct {
    CandidateID string         `json:"candidate_id"`
    Finding     map[string]any `json:"finding"`     // findings.Finding.ToMap()
    Analyzer    string         `json:"analyzer"`
    Provenance  string         `json:"provenance"`
    Coverage    string         `json:"coverage"`
}
type FlowStep struct {
    Role    string         `json:"role"`
    Path    string         `json:"path"`
    Start   map[string]any `json:"start"`
    End     map[string]any `json:"end"`
    Content string         `json:"content"`
}
type Provenance struct {
    Analyzer   string  `json:"analyzer"`
    Provenance string  `json:"provenance"`
    EngineRule *string `json:"engine_rule"`
}
type Result struct {
    ID                 string           `json:"id"`
    RuleID             string           `json:"rule_id"`
    Fingerprint        string           `json:"fingerprint"`
    FingerprintVersion string           `json:"fingerprint_version"`
    ContextDigest      string           `json:"context_digest"`
    Finding            map[string]any   `json:"finding"`
    Manifest           *string          `json:"manifest"`
    CandidateIDs       []string         `json:"candidate_ids"`
    Provenance         []Provenance     `json:"provenance"`
    Evidence           []map[string]any `json:"evidence"`
    CodeFlow           []FlowStep       `json:"code_flow"`
    Limitations        []string         `json:"limitations"`
    *Decision                            // nil until ApplyDispositions
}
type Decision struct {                    // disposition phase, inlined into Result
    Disposition        string         `json:"disposition"`
    DecisionReason     string         `json:"decision_reason"`
    DecisionProvenance string         `json:"decision_provenance"`
    PolicyVersion      string         `json:"policy_version"`
    OriginalSeverity   string         `json:"original_severity"`
    EffectiveSeverity  string         `json:"effective_severity"`
    CapabilityContext  map[string]any `json:"capability_context"` // triad minus evidence; nil == null
    Coverage           string         `json:"coverage"`
    LLMApplied         bool           `json:"llm_applied,omitempty"`
    LLMCandidateID     string         `json:"llm_candidate_id,omitempty"`
}
type Link struct {
    CandidateID       string `json:"candidate_id"`
    ResultID          string `json:"result_id"`
    StableCandidateID string `json:"stable_candidate_id"`
    Disposition       string `json:"disposition"`
    Reason            string `json:"reason"`
    *LinkDecision            // nil until ApplyDispositions
}
type LinkDecision struct {
    PolicyVersion string `json:"policy_version"`
    Provenance    string `json:"provenance"`
}
type PackageInfo struct {
    Name          string `json:"name"`
    ContentDigest string `json:"content_digest"`
    DigestVersion string `json:"digest_version"`
}
type ContextLimit struct {
    Manifest    string   `json:"manifest"`
    Limitations []string `json:"limitations"`
}
type Applied struct {
    CapabilityContexts  map[string]map[string]any `json:"capability_contexts"`
    Coverage            string                    `json:"coverage"`
    ContextLimitations  []ContextLimit            `json:"context_limitations"`
    ExecutionSuccessful bool                      `json:"execution_successful"`
    LLMApplied          *int                      `json:"llm_applied,omitempty"`
}
type Correlation struct {
    RawCandidates []Candidate  `json:"raw_candidates"`
    Results       []*Result    `json:"results"`
    Package       *PackageInfo `json:"package,omitempty"` // absent on the scan fallback value
    Links         []Link       `json:"links"`
    Errors        []string     `json:"errors,omitempty"`
    *Applied                    // nil until ApplyDispositions
}
func (c *Correlation) ToMap() map[string]any   // generic JSON view (sarif consumes this)
func Correlate(p *parse.Package, candidates []Candidate) (*Correlation, error)
func ApplyDispositions(p *parse.Package, c *Correlation, triads map[string]*capability.Triad, policy map[string]any, contextErrors []string) (*Correlation, error)
func ApplyLLMReview(c *Correlation, decisions []llm.Decision) *Correlation
```

### 3.7 `internal/llm`

```go
type Completer interface{ Complete(system, user string) (string, error) }
type Kind int; const ( Transport Kind = iota; Response; Budget )
type Error struct{ Kind Kind; Msg string }     // PyName: LLMError | LLMResponseError | LLMBudgetError
func ErrName(err error) string                 // PyName or "Exception"
type Config struct{ Provider, Model, APIKey, BaseURL string; MaxTokens int; Timeout time.Duration }
type ConfigError struct{ Msg string }
func FromEnv(getenv func(string) string) (*Config, error)   // nil, nil when provider unset
func BuildClient(cfg Config) Completer
type Session struct{ Client Completer; MaxCalls, MaxBytes, Calls, InputBytes, Failures int; Unavailable bool }
func NewSession(c Completer, maxCalls, maxBytes int) (*Session, error)
func (s *Session) Usage() map[string]any
func Redact(text string) string
const ShadowPolicyVersion = "directive-shadow-v3"
const ReviewPolicyVersion = "directive-review-v2"

type Decision struct {
    CandidateID         string         `json:"candidate_id"`
    Disposition         string         `json:"disposition"`
    Status              string         `json:"status"`
    Reason              string         `json:"reason"`
    PolicyVersion       string         `json:"policy_version"`
    Provenance          string         `json:"provenance"`
    Proposal            *Proposal      `json:"proposal"`                      // always present; null when nil
    ReviewedCandidateID string         `json:"reviewed_candidate_id,omitempty"`
    FailureReason       string         `json:"failure_reason,omitempty"`
    Tags                []string       `json:"tags,omitzero"`                  // nil absent, []string{} -> []
    Request             map[string]any `json:"request,omitzero"`
    RequestSHA256       string         `json:"request_sha256,omitempty"`
    Reviewer            *Reviewer      `json:"reviewer,omitempty"`
    ResponseSHA256      string         `json:"response_sha256,omitempty"`
}
type Proposal struct {
    CandidateID   string `json:"candidate_id"`
    Verdict       string `json:"verdict"`
    Confidence    string `json:"confidence"`
    Mechanism     string `json:"mechanism"`
    Intent        string `json:"intent"`
    Reason        string `json:"reason"`
    Impact        string `json:"impact"`
    EvidenceQuote string `json:"evidence_quote"`
}
type Reviewer struct {
    Provider     string `json:"provider"`
    Model        string `json:"model"`
    PromptSHA256 string `json:"prompt_sha256"`
    SchemaSHA256 string `json:"schema_sha256"`
}
func Judge(p *parse.Package, candidates []correlate.Candidate, triads map[string]*capability.Triad, s *Session, applyReview bool) []Decision
func Adjudicate(p *parse.Package, c Completer, maxFiles int) []findings.Finding
func CoverageSummary(p *parse.Package, fs []findings.Finding) map[string]any // ints; cli adds enabled/reason
```

### 3.8 `internal/scan`, `internal/sarif`, `cmd`

```go
type Options struct {
    Client            llm.Completer
    LLMShadow, LLMReview, LLMApply bool
    OpengrepExe       string
    MaxLLMCalls       int            // 0 -> 25
    LLMAdvisory       *bool          // nil -> !reviewEnabled
    DispositionPolicy map[string]any // nil == None
}
type ScanReport struct {
    Findings      []findings.Finding
    RawCandidates []correlate.Candidate
    Triads        map[string]*capability.Triad
    Shadow        []llm.Decision
    LLMUsage      map[string]any
    ContextErrors []string
    Dispositions  []llm.Decision
    ReviewMode    bool
    Correlation   *correlate.Correlation
}
func (r *ScanReport) ToMap() map[string]any  // schema_version, findings, raw_scope, raw_candidates, triads,
                                             // shadow, llm_usage, context_errors, correlation[, review_mode,
                                             // dispositions, final_findings]; deep copies
func Scan(p *parse.Package, client llm.Completer, opengrepExe string) []findings.Finding
func Report(p *parse.Package, o Options) (*ScanReport, error)

// sarif
func Build(p *parse.Package, r *scan.ScanReport) (map[string]any, error) // reads r.ToMap()["correlation"] etc.
func Validate(doc any) error
func Encode(doc any) ([]byte, error)
func Write(doc any, target, sourceRoot string) error
func IsWithinSource(path, root string) bool

// cmd/skill-xray
func run(argv []string, stdout, stderr io.Writer) int
```

### 3.9 Cross-group identifiers (canonical name; the spec that named it differently)

| Canonical | Owner | Consumers | Renamed from |
|---|---|---|---|
| `parse.Package`, `parse.Artifact`, `parse.Markdown`, `parse.Span`, `parse.Parse` | parse | all | core/code/obfuscation `ir.*`; parse `ParsedPackage`, `ParsedArtifact`, `MarkdownIR`, `LineSpan`, function `parse.Package` |
| `parse.Artifact.Text *string` | parse | all | code/instruction `Text string; HasText bool` |
| `parse.Grant.Pattern *string` | parse | grants, instruction, capability | code/instruction `Pattern string; HasPattern bool` |
| `parse.Link.Label`, `parse.HTMLComment.Body`, `parse.HTMLProse{Text; Line}` | parse | instruction, obfuscation, llm | parse `Link.Text`, `HTMLComment.Data`, `HTMLProse []HTMLFragment` |
| `parse.Diagnostic.Detail *string`, `parse.Dep.Line *int` | parse | core, code, supplychain | code `Detail string`, `Line int; HasLine bool` |
| `parse.ManifestIndex`, `parse.GoverningManifest` | parse (Python code_lane) | codelane, opengrep, capability, correlate, llm | code/output-llm `codelane.*`, core `ir.*` |
| `findings.CapFindings` | core | preproc, grants, supplychain, opengrep, instruction, checks | core `CapPerPath` |
| `findings.MetaOf`, `Finding.ToMap` | core | sarif, llm | output-llm `VectorMeta`, `ToDict` |
| `checks.Run` | core | scan, tests | instruction `checks.RunChecks` |
| `codelane.Build(p) ([]Unit, []findings.Finding)` | code | checks, opengrep | core `checks.BuildCodeLane(...) error` |
| `codelane.DropHostRE.MatchString(host)` (exported `*regexp.Regexp`), `codelane.SupportedShell map[string]bool` | code | instruction, opengrep | code `IsDropHost(host) bool`, `SupportedShell(d string) bool` wrappers |
| `grants.ExecutionTools`, `grants.NetworkTools map[string]bool` | code | capability | core `checks.ExecutionTools`; missing from code §1.1 |
| `opengrep.Check(p, opengrep.Options)` | code | checks | core `checks.Taint(...)` |
| `opengrep.Install(cacheDir string, client *http.Client) (string, error)` | code | cmd (`Install("", nil)`) | core `opengrep.Install()` |
| `forensics.AnalyzePackage` | code | checks | core `analyze.Package` |
| `supplychain.SecretRules []SecretRule{ID string; Pattern *regexp.Regexp; Left, Right bool; Severity string}`, `supplychain.ReplaceSecrets(text string, repl func(string) string) string`, `SanitizeSource` | code | llm/privacy | output-llm `SecretRule{ID; Re; Severity}` + per-pattern `sub` |
| `instruction.FlattenProse`, `instruction.SourcePosition` | instruction | obfuscation, llm | obfuscation local copies |
| `llm.Decision`, `llm.Judge`, `llm.ShadowPolicyVersion`, `llm.ReviewPolicyVersion`, `llm.Completer`, `llm.NewSession(c, calls, bytes)`, `llm.Adjudicate(p, c, maxFiles)`, `llm.FromEnv(getenv)`, `llm.CoverageSummary -> map[string]any` | output-llm | scan, cmd, sarif, correlate | core `judge.Decision`, `judge.Candidates(...) error`, `judge.POLICY_VERSION`, `llm.Client`, `NewSession(c, calls)`, `Adjudicate(p, s)`, `FromEnv()`; output-llm `map[string]int` |
| `scan.ScanReport`, `correlate.Candidate` | core | sarif, llm | output-llm `scan.Report`, `scan.Candidate` |
| `correlate.PolicyVersion`, `correlate.LLMApplyVersion`, `correlate.LLMApplyVectors` | core | sarif | output-llm `disposition.*` |
| `correlate.SourceRegion(a, start, end map[string]any, ...)` | core | sarif | output-llm `Point` |
| `capability.Triad.Evidence []map[string]any` | core | llm, sarif | output-llm `[]any` |
| `metadata.Version` | core | cmd, sarif | core `main.Version`, output-llm `skillxray.Version` |
| `pytext.*` | core | all | code `pystr`, output-llm `pyre`/`pyjson`, instruction `pyshlex`, obfuscation `pyIsSpace` |
| `pytext.Canonical`, `pytext.Dumps` | core | correlate, sarif, llm | core `correlate.Canonical`, output-llm `pyjson.*` |
| `pep508.Parse(s) (Requirement, error)` with `Requirement{Name, URL string; Extras []string; Specifiers []Specifier{Op, Version string}; Marker string}` and `(Requirement).SpecifierString()` (sorted `op+version` joined by `,`) | parse | instruction | parse hand-port in `parse`, instruction `internal/pep508` |
| `testutil.MakePackage(t, map[string]string) string` | core | all tests | core `(t, map[string][]byte, name)`, obfuscation `*ir.Package` return, instruction `makePackage` |
| Observations `map[string]any` | core | opengrep, capability | code `Observation` struct |

## 4. Dependencies (final)

| Module | Version | Used by | Ladder rung / justification |
|---|---|---|---|
| `github.com/spf13/cobra` | v1.10.2 | cmd | CLAUDE.md default (CLI). |
| `github.com/stretchr/testify` | v1.12.1 | tests | CLAUDE.md default. |
| `gopkg.in/yaml.v3` | v3.0.1 | parse (frontmatter node tree, positions, tags), opengrep test (rule file) | CLAUDE.md default; only YAML library. |
| `github.com/yuin/goldmark` | v1.8.6 | parse | CLAUDE.md default; CommonMark 0.31.2 like markdown-it-py 4.0; fenced-code block parser copied (~120 lines) to record opener/closer lines. Only markdown library. |
| `mvdan.cc/sh/v3` | v3.14.1 | parse (`ShellTree`, `shell_error_region`) | CLAUDE.md default; only bash parser; no check reads the tree (parse R1). Requires go 1.26. |
| `github.com/dlclark/regexp2` | v1.12.0 | instruction (3 patterns), llm/privacy (1 pattern) | CLAUDE.md default for lookaround; the other 4 groups rewrite theirs as RE2 + a few lines. Only regex fallback. |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | sarif (SARIF 2.1.0 Draft 4; `RESPONSE_SCHEMA`) | CLAUDE.md default; only schema validator; `AssertFormat=false`. |
| `github.com/BurntSushi/toml` | v1.6.0 | parse (configs, pyproject) | CLAUDE.md default. |
| `github.com/aquasecurity/go-pep440-version` (+ `go-version`) | v0.0.1 | pep508 (version validation) | CLAUDE.md default; its regex is packaging's `VERSION_PATTERN`; requirement grammar (PEP 508) has no Go library and is hand-ported in `internal/pep508`. |
| `golang.org/x/text` | v0.42.0 | pytext (`cases.Fold`, `encoding/charmap`), parse/llm (`unicode/norm`), obfuscation (`unicode/bidi.LookupRune`, `unicode/runenames`) | CLAUDE.md default for normalisation; already required. Requires go 1.26. |
| `golang.org/x/net` | v0.55.0 (cached, go 1.25) | parse (`html` tokenizer with `Raw()` offsets replacing `html.parser`) | New. Rung 3 fails (no stdlib HTML tokenizer); rung 5: x/net is the maintained tokenizer with byte-accurate `Raw()`; hand-writing a tolerant tokenizer is ~300 lines with its own edge cases. |

Vendored source (not a module): `internal/uba` = x/text `unicode/bidi/core.go` + `bracket.go`
(BSD-3; add the x/text LICENSE to `THIRD_PARTY_NOTICES`), because the public `Paragraph.Order()`
cannot force base level 0 nor apply L2 (obfuscation §4.2).

Removed from `go.mod` (`go mod tidy` will drop them): `github.com/owenrumney/go-sarif/v2` (the
document is emitted through `pytext.Canonical` because SARIF bytes must equal Python's
`json.dumps(sort_keys, ensure_ascii)`; typed structs add a marshal/decode round trip and nothing the
validator consumes; output-llm §1.1). Not added despite CLAUDE.md's LLM row: `anthropic-sdk-go`,
`openai-go` (the Python client shapes requests by hand and the tests pin those exact bodies,
headers, the 1 MiB body cap, refused redirects and the 429/502/503/504/529 retry set; an SDK would
have to be fought on every one of them; output-llm §2.3/§4). OpenGrep stays an external binary
(`internal/opengrep/runtime.go`, pinned v1.29.0 with per-platform SHA-256).

Toolchain: `go 1.26.0` (D1). `go.mod` must list the direct dependencies above without `// indirect`
once code imports them; run `go mod tidy` after the first package lands.

## 5. Build order

Each step lists what it unblocks. Steps on one line can proceed in parallel.

1. **`go.mod` tidy, `internal/metadata`, `internal/pytext`, `internal/findings`, `internal/testutil`** (core). `pytext` needs Python-generated goldens first: `tools/parity/gen_goldens.py` writes `internal/pytext/testdata/{canonical,dumps,repr,quote,splitlines,strip,shlex,urlsplit}.jsonl` from the oracle interpreter. Unblocks every other package.
2. **`internal/pyast`** (code) with `ast.dump` parity fixtures generated once by CPython for the 258 contract programs, the bridge-test snippets and every `.py`/python fence in the corpus; **`internal/ingest`** (core); **`internal/pep508`** (parse). `pyast` is the critical path (3.5-4.5k lines): start it on day one; `parse` can begin against the `pyast.Parse`/`Depth` signatures with a stub that returns "not a module" while the real parser lands.
3. **`internal/parse`** (parse): IR types first (one commit, every group compiles against them), then `Parse` with the two-engine markdown fact diff (`markdown_facts_test.go`, parse R5) and the IR dump (`tools/parity dump-ir`). Unblocks every check.
4. In parallel: **`internal/preproc`** (parse); **`internal/codelane`, `internal/grants`, `internal/supplychain`, `internal/forensics`** (code); **`internal/instruction`** (needs `codelane.InstallerIdiom/DropHostRE` and `pep508`); **`internal/uba`, `internal/obfuscation`** (needs `instruction.FlattenProse/SourcePosition`).
5. **`internal/opengrep`** (code; needs `pyast`, `codelane`, `grants`, the pinned binary for the 22 live tests) and **`internal/checks`, `internal/capability`, `internal/correlate`** (core; `correlate` needs the `pytext.Canonical` golden and a hand-built IR fixture for the context digest).
6. **`internal/llm`** (output-llm; needs `correlate`, `capability`, `instruction`, `supplychain`) and **`internal/scan`** (core; needs every check, `capability`, `correlate`, `llm`).
7. **`internal/sarif`** (output-llm; needs `scan`, `correlate`, `opengrep.Version/Rules`, `metadata`) and **`cmd/skill-xray`** (core; needs everything). Then the 28 `test_cli_sarif` + 5 CLI review cases.
8. **`tools/parity`** can be built from step 1 (it runs the Python side and the corpus dump without any Go product code) and gates every step from 3 onward: IR dump parity after step 3, findings parity per group as each check lands, SARIF byte parity after step 7. `make parity` is the definition of done.

## 6. `tools/parity` design

Layout (module `skillxray`, all Go code under `tools/parity`, Python helpers beside it; nothing
under `skill-xray/` is modified):

```
tools/parity/main.go                 subcommands: corpus, run, dump-ir, attribute
tools/parity/pytest_dump_corpus.py   pytest plugin: copies every package a test built
tools/parity/msb_materialize.py      writes the frozen MaliciousSkillBench split as packages
tools/parity/py_dump_ir.py           Python IR dump (imports skill_xray.parse; no CLI change)
tools/parity/gen_goldens.py          pytext/canonical goldens from the oracle interpreter
tools/parity/known_divergences.json  the only allowed differences, each citing a spec section
Makefile                             build test lint parity (lint = go vet + staticcheck via go run)
```

**Oracle pin.** `run` records `git -C skill-xray rev-parse HEAD` and `git status --porcelain
src tests`; a dirty oracle tree marks the whole report `oracle: dirty` and exits 1 (results are
still written). The report header also records the Python and package versions listed at the top
of this file.

**Corpus (three sources, all materialised as directories under `port-to-go/corpus/`, git-ignored).**

1. `corpus/pytest/<nodeid-slug>/<pkgdir>/`: `python -m pytest tests -q -p pytest_dump_corpus
   --dump-corpus <dir>` with `PYTHONPATH=port-to-go/tools/parity`. The plugin's
   `pytest_runtest_teardown` (tryfirst) copies every directory directly under
   `item.funcargs["tmp_path"]` that contains a regular file (`shutil.copytree(symlinks=True)`),
   skipping trees with more than 500 files or 50 MiB (the DoS-bound tests), and appends
   `{nodeid, package, outcome, files, bytes}` to `corpus/pytest/manifest.jsonl`. This captures every
   inline `make_package` package (about 3,000 across 54 test files, including the six
   `test_postdetect_microcorpus._CASES` packages) without translating a single fixture.
   Packages from tests that monkeypatch limits (`MAX_FILES`, `_PKG_BUDGET`, `_MD.parse`) are
   still valid inputs: both CLIs run them with production limits.
2. `corpus/msb-test/<benchmark_id>/SKILL.md`: `msb_materialize.py --data <snapshot dir>
   --split test`. Reads `primary.parquet` (`benchmark_id`, `text`) and
   `splits/source_disjoint.parquet` exactly as `benchmark/msb_run.py` does, checks the snapshot
   against `benchmark-reports/frozen-dataset/MSB_FROZEN.json` (`id_list_sha256.test` =
   `3cf59383…0b7bb`, 1,384 ids from `msb_frozen_ids.json`), writes each text with
   `encoding="utf-8", errors="surrogatepass", newline=""` into a directory named like
   `msb_run.scan_one` does (`<sanitized id>-<sha1[:10]>`). `--split dev` (8,348) and `all`
   (9,740) are the full-corpus modes the obfuscation and parse groups asked for. The snapshot is
   external (HF `ProtectSkills/MaliciousSkillBench` @ `d4b42ce…`); when `--data` is absent the
   MSB stage is reported as skipped, never as passed.
3. Any extra directory passed on the command line (`--extra <dir>`), for ad-hoc inputs.

**Running the two CLIs.** For each package directory `P` (worker pool, `-j N`):

```
python -m skill_xray.cli P --analyze --enrich --json --sarif <out>/py.sarif --opengrep-bin <bin>
<go binary>            P --analyze --enrich --json --sarif <out>/go.sarif --opengrep-bin <bin>
```

with an environment stripped of every `SKILLXRAY_LLM_*` variable (LLM lane off on both sides), the
same pinned OpenGrep binary (`opengrep.Resolve("")` on the Go side must return the same path), and a
per-run timeout of 300 s. stdout, stderr and exit code are captured. Python outputs are cached under
`corpus-cache/<sha256(oracle HEAD + package tree digest)>/` so the oracle runs once per package
revision.

**Normalisation of `--json`.** Both documents are parsed. Then: `source` is dropped (argv path);
`identity` is compared after replacing the corpus root prefix with `<corpus>`; every number is
compared numerically (`100.0 == 100`); object key order is ignored; `findings` is compared as an
ordered list (order is a core contract) and each finding as the full dict (`vector, rule, severity,
path, message, line, column, offset, length, evidence, title, cwe, tier`); `enrichment.raw_candidates`
by `candidate_id` (an order diff is an emission-order bug in the emitting group); `results` and
`links` by `id`/`candidate_id`; `ledger` in full. Messages of the failure-path rules that embed a
Python exception class name (`check-error`, `analyzer-error`, `opengrep-execution-error`,
`opengrep-internal-error`, `llm-error`, `llm-unavailable`) and the `enrichment.context_errors`
strings are compared by rule/prefix only; these are the only entries in `known_divergences.json`
that match on message text.

**Normalisation of SARIF.** None: both files are canonical JSON + `\n`; compare bytes. On a
mismatch, parse both and report the first differing JSON path so the diff is attributable.

**IR dump (`dump-ir`).** Before findings are compared for a package, `py_dump_ir.py P` and
`skill-xray-parity dump-ir P` each write one JSON document per artifact with sorted keys:
`rel, kind, text_sha256, raw_sha256, frontmatter, frontmatter_keys, frontmatter_key_lines,
frontmatter_end_line, unsafe_yaml_tags, grants, fences, fence_spans, code_spans, prose_spans,
reference_spans, paragraph_spans, links, fallback_links, html_comments, html_prose,
html_uninspectable, has_html, has_uninspectable_html, preprocessing, preprocessing_counts,
config (with a per-value type tag), manifest_kind, deps, diagnostics (code + detail presence),
refs`. The dumps are diffed first; a findings diff with an identical IR belongs to the consuming
group, an IR diff belongs to parse. `Diagnostics` details for `config_parse_error`,
`shell_error_region` and `parse_crash` are compared as presence-only (parse R6).

**Attribution.** `attribute` maps every differing finding to a group using the §7 rules of the
six specs, in this order: `vector` in a group's vector set (parse: 001/002; code: 003/004/016/017/
035-037 and every OpenGrep vector; instruction: 005/006/011-013/027-031/041-043; obfuscation:
007/014/015; output-llm: 038); else `rule` in a group's rule set (code: the `opengrep-*` slugs and
`analysis-incomplete` with a code reason; output-llm: `llm-*`); else message prefix (`further
SXV-007 `, `unicode scan of `, `obfuscation skipped ` -> obfuscation; `instruction_exfil skipped `,
`hook/MCP configuration analysis is incomplete` -> instruction; `%d more <vector> findings` -> the
vector's group; `check <module> failed` -> the module's group); else evidence keys (`engine ==
"opengrep"`, `installer_idiom`, `understated_capability`, `fenced_example`, `pin_state`,
`breadth_class`, `variable_name`, `detail` -> code; `phase` -> core coverage); else core.
Enrichment diffs attribute to core (`correlate`/`capability`/`scan`) unless the underlying finding
differs, and SARIF-only diffs to output-llm.

**What "parity" means numerically.** Over the whole corpus (pytest packages + the frozen MSB test
split), the harness reports, per source and per group:

- `packages`: total run; `identical`: `--json` (after normalisation) equal, SARIF bytes equal, exit
  code equal; `ir_identical`; `findings_identical` (the ordered list of full finding dicts);
  `tuple_identical` (the CLAUDE.md minimum: `vector, rule, severity, tier, path, line` as a
  multiset); `sarif_identical`; `divergent` (only differences whitelisted in
  `known_divergences.json`); `failed` (anything else).
- **Parity holds when `failed == 0` on every source and `identical + divergent == packages`.** A
  whitelisted divergence must name the spec section that accepts it (parse R6/R7, core R4/R14/R17,
  code §5.9, output-llm R4/R9) and is counted separately so it can never hide a regression.
  Intermediate gates while groups land: `tuple_identical == packages` first (it is the brief's
  definition), then `findings_identical`, then `identical`.
- For the MSB split the harness additionally projects the Python and Go findings to the frozen
  record shape `{vector, rule, severity, tier, line}` and compares each against
  `test_final.jsonl` (records with `error != null` or `oversize` are excluded; the split has 0 of
  either). The Python-vs-frozen comparison validates the materialisation before the Go side is
  trusted; the Go-vs-frozen comparison is the published-figure check (P/R/FPR in
  `test_final_score.md` must be reproduced by `benchmark/msb_score.py` fed with the Go output).

Output: `corpus/parity-report.md` (tables above, then every failed package with its first
differing JSON path, the attributed group and both values) and `corpus/parity.jsonl` (one record
per package). Exit 0 only when parity holds.

**Makefile.** `build` (`go build -o skill-xray ./cmd/skill-xray`), `test` (`go test ./...`; the 22
live OpenGrep tests skip without the binary and fail under `CI=1`), `lint` (`go vet ./...` and
`go run honnef.co/go/tools/cmd/staticcheck@2025.1 ./...`; staticcheck is not installed on this
machine), `parity` (`build`, then `corpus` if `corpus/pytest/manifest.jsonl` is missing, then
`run --corpus corpus/pytest --corpus corpus/msb-test -j 4`).

## 7. Accepted divergences (the initial `known_divergences.json`)

Each entry: `{group, where, why, spec}`. Anything not listed here is a failure.

- Python exception class names in failure-path messages (`check-error`, `analyzer-error`,
  `opengrep-execution-error`, `opengrep-internal-error`, `llm-*-error`, `context_errors`): compared
  by rule/prefix. core §5.14, code §5.9, output-llm R9.
- Ledger `detail` text for `config_parse_error` (tomllib/encoding-json vs BurntSushi/encoding/json
  messages), `parse_crash` (exception type name), `shell_error_region` (`count:spans` vs `1:L-L`):
  presence-only, IR dump only (never in `--json`). parse R1/R6.
- `shell_error_region` presence (parse R1): mvdan/sh parses the bare top-level heredoc that
  tree-sitter-bash rejects, so the oracle alone emits the `analysis-incomplete` finding and every
  value derived from it (candidate ids, digests, links, SARIF) in that package; measured at 1 of
  3,612 corpus packages (`hooks/pre-rebase.sample` of the autocrlf `.git` package), accepted whole
  only when the oracle carries a `shell_error_region` finding the Go side lacks; mvdan/sh stays.
- `markdown_parse_error` can never fire in Go (goldmark cannot fail). parse R4.
- `python_syntax_error` presence follows `internal/pyast`; any delta against CPython is a bug in
  `pyast`, not a divergence, except the recursion ceiling near 1,000 nesting levels. code R2.
- `markdown_too_complex` (Go only; posture audit 2026-09-19): a body line with more than 10,000
  leading container markers (`>`, list bullets) or `](` link openers is refused before goldmark,
  which parses those quadratically (1 MiB of `>` never finishes; markdown-it-py takes 4 s). The
  artifact carries the diagnostic and no IR, so the package reports `analysis-incomplete`. parse §5.
- `config_parse_error` for a TOML key path deeper than 1,000 segments (dotted keys or nested
  inline tables; posture audit 2026-09-19): BurntSushi/toml records every key with its full path,
  O(n²) memory (12 GB at 30k segments), where tomllib decodes it slowly. The detail is presence-only
  as before; the refusal itself is Go-only. parse §5.
- `parse_budget_exceeded` also marks an artifact whose own parse outlived what was left of the
  60 s package budget: Go abandons that parse (no IR), Python checks the budget only between
  artifacts. Unreachable on the corpora; the pyast, exfil and conceal lanes are polynomial after
  the same audit. parse §5.
- JSON nesting between 1,000 and 10,000 levels; YAML alias-then-syntax-error; duplicate YAML keys
  under Python numeric equality (`1`/`true`/`1.0`); `İ` in scheme checks. parse R7.
- LLM lane only (never compared: LLM is off in the harness): `failure_reason` for `NaN`/`Infinity`
  or nested-duplicate-key replies; `_config_prompt_text` key order. output-llm R4/R6.
- Unicode 15.1 vs 15.0: CJK Extension I (U+2EBF0-U+2EE5D) letters/printability. obfuscation §4.1;
  the harness greps the corpus for that range and reports the count.
- Digest cache identity for the OpenGrep binary (`ctime/ino/dev` vs `path,size,mtime`): not
  observable in output. code R10.
- `--scan-known-skills`, URL, git and zip inputs are not in the corpus (local directories only);
  their behaviour is pinned by the ported pytest cases. core R10.

## 8. Gaps (larger than a spec edit; decide before coding)

1. **Oracle pin behind main.** The parity oracle is `33f057e`; upstream `main` (`6885be9`) adds
   PR #39, the Anthropic thinking-family `output_config`/`reasoning_effort` request shaping in
   `llm/client.py` (+48/-3 lines with its tests). `internal/llm` implements #39 and ports its two
   tests; nothing else differs between the pin and `main`. Not a parity risk (the LLM lane is off
   in every parity run). Move the pin when the next non-LLM change lands upstream.
2. **`internal/pyast`** is a 3.5-4.5k-line CPython-3.13-exact parser on the critical path of both
   parse (`python_*` diagnostics, `py_tree`) and code (fence lifting, every taint post-filter).
   Staff it first; ship its `ast.dump` parity fixtures before writing checks against it.
3. **MaliciousSkillBench snapshot** is not in this repository; the harness needs the HF snapshot
   directory (`primary.parquet`, `splits/`). Obtain it (the WSL clone noted in memory is a
   `blob:none` partial clone that had to be completed once already) and record its location in
   `Makefile` (`MSB_DATA`).
4. **mvdan/sh vs tree-sitter-bash presence delta** (parse R1) flips a high coverage finding and
   the package disposition; it can only be measured once `parse` exists and the MSB corpus is
   available. The fallback (tree-sitter-bash as wasm under wazero) is a new dependency and must be
   decided from the measurement, not before.
5. **goldmark fidelity** (parse R5): reference-definition spans with multi-line titles and setext
   heading spans are the two known approximations; the two-engine fact diff must run over the
   corpus before instruction/obfuscation compare findings.
6. **UBA N0 bracket pairing** is inert in the vendored x/text core while the Rust oracle implements
   it (obfuscation R1); probes pass, corpus incidence unknown until the harness runs.
7. **Non-UTF-8 filenames** (output-llm R7): Python's surrogateescape has no Go equivalent unless
   `ingest` keeps raw bytes in `Rel` and `pytext.Canonical` emits `\udcXX` for invalid bytes.
   Linux-only; decide whether to support it at all (the corpus has none).

## Errata from wave 1 (binding; supersede the sections they name)

- pytext.ShlexTokens(s string, posix bool, punctuation, whitespace string) (whitespace_split always
  true) plus ShlexSplit(s). Configurations: hooks._tokens posix=true, ";&|<>", " \t\r\n";
  grants._command_tokens posix=false, ";&|\n", " \t\r"; parse.py:1001 posix=false, "", " \t\r\n";
  code_lane uses ShlexSplit. shlex.split quotes both ' and ".
- pytext.Unquote emits one U+FFFD per maximal invalid UTF-8 subsequence (CPython 'replace'), not per byte.
- pytext exports Space ("[...]"), NotSpace ("[^...]") and SpaceBody (bare class body for embedding).
- Names follow §3.1 (Lower, Space, SplitExt, Basename), not the Py-prefixed variants in core.md §5.
- Invalid UTF-8 bytes in file names are carried as surrogateescape code points and escaped \udcNN by
  UnicodeEscape, Repr, Canonical and Dumps (matches str.encode('unicode_escape') on the oracle).
- Windows errno table includes ERROR_DIRECTORY (267) for NotADirectoryError; ENOTDIR on Windows is
  ERROR_PATH_NOT_FOUND, classified FileNotFoundError by both runtimes.
- x/text cases.Fold differs from str.casefold on the 86 Cherokee capitals; pytext.CaseFold patches them.
- URL port parsing follows CPython _hostinfo: partition on the first ':' after the host.
- SplitLines has 11 distinct boundaries (\n \r \r\n \v \f \x1c \x1d \x1e \x85 U+2028 U+2029).
- pytext.Dumps(v any, indent int) (wave-3 cut: the sortKeys parameter is gone); map keys are always
  emitted sorted (Go maps have no insertion order) and nothing hashed depends on unsorted dumps.
- internal/pep508: github.com/aquasecurity/go-pep440-version is used only for canonicalize_version in
  the SpecifierSet frozenset dedupe; the Specifier grammar is the ported per-operator regex (16 RE2
  patterns). API: Parse(s) (Requirement, error); Requirement{Name, URL, Specifiers} (wave-3 cut: Extras
  and Marker are validated by the grammar but not returned; no consumer reads them; §3.9 row superseded);
  SpecifierString(); Pinned(); IsExactPin(runner, spec) carries every branch of hooks._is_exact_pin.
- findings: positions are *int built with findings.Int; Sort/Dedupe/CapFindings are the only
  ordering primitives (do not re-sort downstream); the 43-entry vector registry is generated from
  the oracle's _VECTORS.
- findings.MetaOf is gone (wave-3 cut; §3.2 and the §3.9 row superseded): callers write
  `m, ok := findings.Vectors[v]`; ToMap already does.
- testutil.MakePackage(t, files) creates one t.TempDir() per call and always names the root `pkg`
  (wave-3 cut: MakePackageNamed is gone; a test wanting another name renames the root with os.Rename);
  a test that needs two packages under one parent (test_cli KNOWN_SKILL_ROOTS) builds them by hand.
- Tests may use testify now (go.sum fixed by go mod tidy); do not convert the wave-1 stdlib tests.
- Python-AST decision (docs/spec/pyast-decision.md): hand-written CPython-3.13-exact internal/pyast
  (option c); gpython refuses 34.6% of accepted inputs, tree-sitter accepts 44% of refused ones (303
  flips, 164 MSB records, 16 in the test split). Fixture corpus: 12,007 inputs captured by wrapping
  ast.parse in the oracle suite plus all MSB fences (corpus/pyast/, git-ignored; regenerate as the
  decision doc describes).
- Unexported after the closing audit (no importer outside the package): opengrep.run/asset/runtimeError/
  platformAsset/defaultCacheDir/verifyExecutable, checks.taint/metadata, correlate.contextVersion/digest,
  capability.axes, llm.errName/newConfig; the exported spellings in §3 and the group specs are superseded.

## Process record

The wave briefs (`docs/WAVE1.md` to `docs/WAVE6.md`, `docs/PLAN_BRIEF.md`) and the review output that
shaped this tree (`docs/ponytail-review-*.json`) were removed from the working tree after the closing
audit: they carried machine paths and file:line findings that no longer match the code. `git log --all --
docs/WAVE1.md` (or any of those paths) reaches the last committed version of each; the closing audit's own
findings were applied in the same change and its output was not kept. This file and the group specs are
the tree's documentation.
- Lint: staticcheck via `GOTOOLCHAIN=go1.26.6 go run honnef.co/go/tools/cmd/staticcheck@2025.1 ./...`.

## Wave 9: the detection build (2026-09-20)

Measured on the frozen benchmark (GAP-ANALYSIS.md) and on the ClawHub sweep (399 packages, 13
false positives in six classes, two VirusTotal-malicious packages in the JavaScript blind spot),
landed in Python first (`9b7960f`, then `77a031f`, merged as `10143bc`) and mirrored here in two
steps, the second being the errata that close this section. No new accepted divergence.

- **JavaScript and TypeScript code lane.** `script_javascript` and `script_typescript` artifacts
  become code units (`codelane.scriptKinds`), the bridge maps them to `.js`/`.ts` targets and
  `Check` runs OpenGrep over python, shell, javascript and typescript. Ten rules join the embedded
  rule file (digest `616191e8…`, now `f39f777a…`): SXV-018 remote payload execution, SXV-008 command injection,
  SXV-040 reverse shell, SXV-023 credential read, SXV-026 environment harvest, SXV-019 decoded
  payload execution, SXV-021 cloud metadata, SXV-009 fetch-pipe-exec, and two SXV-033 capability
  observation rules (network, execution). `parse` records no `unsupported_language` for these two
  kinds: they build no IR, but the code lane covers them. JavaScript fences are not lifted (files
  only); a follow-up.
- **SXV-044 obfuscated or minified shipped script** (`obfuscation.checkObfuscatedScript`): a
  `script_*` artifact of at least 32 Ki characters whose longest line is at least 16 Ki characters;
  high `obfuscated-script` when it carries 20 or more distinct `_0x…` identifiers or 200 or more
  `\x` escapes, else medium `minified-script` unless the file is a declared `*.min.js`. Vendor and
  build directories are excluded by ingest before this runs.
- **SXV-028 guards.** A match that opens a quotation framed as a citation (`quoted`: a list marker
  and a space, a verb of saying, like/such as, a noun for phrases, or another quoted fragment before
  the quote; a quoted order with no frame is still an order), conditional reported speech whose
  clause reaches the saying verb (`reportedSpeechRE`: "if a user asks you to …", never "I want you
  to …" nor "If you understand this, I want you to …"), a verb followed directly by a bare weak noun
  (`bareWeakNounRE`: "ignore rules", "reset commands"), and a `|` between a model name and
  "developer mode" (a requirements table row) are not directives. The quotation guard applies to
  every directive vector and to the SXV-042 covert cue.
- **SXV-042.** The frontmatter block never sets `previous`, so a quoted `description:` scalar no
  longer excuses the first body block (`inFrontmatter`, also applied in the directive and exfil
  loops); seven coercion cues from the injected-benchmark corpus join `coercedRunCueRE`.
- **Antipattern fences**: excluding labelled fences from the code lane was built, then reverted in
  review: a planted `# never run this` above a live exfil fence hid it from OpenGrep. The instruction
  lane's original `_ANTIPATTERN_RE` (SXV-011 only) is unchanged. Follow-up: demote, never drop.
- **SXV-017** handed to an assertion or redaction call under the package's own test directory
  (`supplychain.testPathRE` and `testFixtureRE`, evidence `test_fixture`) is medium; the path alone
  is not enough. **SXV-014** zero-width runs inside a detection rule's own `"regex": "…"` value in
  a JSON, YAML or TOML file, with the value still open, are low `zero_width_pattern_data`.
  **SXV-031** is T2; **SXV-032** rules are high, demoted to medium only when every agent-config path
  on the matched line is the skill's own install directory (`codelane.OwnInstallPath`); the shell
  base64 decoder flag is matched case-insensitively (`-D`).
- Tests: `internal/instruction/wild_test.go`, `internal/obfuscation/obfuscated_test.go`,
  `internal/supplychain/testpath_test.go`, `internal/codelane/jslane_test.go` and
  `owninstall_test.go`, `internal/parse/parse_test.go` (`TestKindDispatch`),
  `internal/opengrep/jslane_test.go`, `jslane_live_test.go` and `live_test.go` mirror
  `tests/test_wild_precision.py`, `tests/test_js_lane.py` and the own-path bridge test.

## Errata from the `10143bc` mirror (2026-09-21; supersede Wave 9 where they differ)

The pin is the merge of PR #41 into `origin/main`. The mirror now includes the JavaScript lane sinks
bound to `child_process` through anchored rule blocks (rule digest `f39f777a…`, still 73 rules; a `.jsx`
or `.tsx` file reaches the engine under its own extension), SXV-044 limited to JavaScript and TypeScript
with the generated line reported, the quotation and refusal guards in the instruction lane, secret hits
carrying their column, the literal-only own-install path, and the ingest extensions `.jsx` `.tsx` `.mts`
`.cts`. The `corpus/` oracle cache predates `10143bc`; regenerate it before `TestCorpusParity` or `tools/parity`.
