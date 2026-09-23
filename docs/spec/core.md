# Porting specification: group `core`

> **Errata (00-overview).** Read this spec with these substitutions; `00-overview.md` is binding.
> - Toolchain: `go.mod` stays `go 1.26.0` (x/text v0.42.0 and mvdan.cc/sh v3.14.1 require it; the
>   toolchain is already in the module cache). R1 is superseded.
> - The parsed IR is `internal/parse` (`parse.Package`, `parse.Artifact`, `parse.Diagnostic{Code string;
>   Detail *string}`); there is no `internal/ir`. `ManifestIndex`/`GoverningManifest` live in `parse`.
> - `internal/checks` holds only `checks.go` (`Run`), `coverage.go`, `metadata.go`; every other check is its
>   own package (`preproc`, `grants`, `supplychain`, `codelane`, `opengrep`, `forensics`, `instruction`,
>   `obfuscation`). The registry maps the Python module string to the package function (00-overview §3.5).
> - Shared helpers: `internal/pytext` also carries `Canonical`, `Dumps`, `Quote`, `URLSplit`, `Shlex*`,
>   `Repr`; `correlate.Digest(v) = sha256hex(pytext.Canonical(v))`. `Version` is `internal/metadata.Version`.
> - `findings.CapFindings` is the Python `cap_findings`; `llm.Decision`, `llm.Judge`, `llm.Completer`,
>   `llm.NewSession(c, maxCalls, maxBytes) (*Session, error)`, `llm.Adjudicate(p, session, 25)`,
>   `llm.FromEnv(os.Getenv)`, `llm.ShadowPolicyVersion`/`llm.ReviewPolicyVersion` replace the `judge.*` and
>   `llm.Client` names below. `llm.Judge` returns `[]llm.Decision` only; scan recovers a panic and checks
>   the id sequence itself.
> - Code group names: `codelane.Build(p) ([]codelane.Unit, []findings.Finding)` (no error; `Run` recovers a
>   panic), `opengrep.Check(p, opengrep.Options{Executable, Units, LaneNotes, Observations})`,
>   `forensics.AnalyzePackage(p)`, `opengrep.Install("", nil)`, `grants.ExecutionTools`/`grants.NetworkTools`,
>   `grants.Declared`/`grants.Denied`/`grants.Effective`. Observations are `map[string]any` (00-overview D9).
> - `testutil.MakePackage(t, files map[string]string) string` has no project imports (test import cycles);
>   the `candidate()`/`loc()`/`package()` helpers stay beside the tests that use them (`correlate` tests that
>   share them are external `package correlate_test`).
> - `Frontmatter` gains `FrontmatterKeys []string` (document order); Config is `map[string]any` (D14).

Python modules: `ingest.py` (708 lines), `resolve.py` (551), `findings.py` (242), `scan.py` (165),
`cli.py` (311), `__init__.py` (54), `checks/__init__.py` (73), `checks/coverage.py` (59),
`checks/metadata.py` (18), `capability.py` (196), `correlate.py` (247), `disposition.py` (192).
Total 2,816 lines. Oracle: Python 3.13.2 (the interpreter that runs the 3,100-test suite; it
ships Unicode 15.1). Go on this machine: 1.24.1; `port-to-go/go.mod` says `go 1.26.0` (see
risk R1).

Every Python behaviour below was read from the source in full; every "verified" note was checked
against the local interpreter, not recalled.

## 0. Package layout (decided)

| Python | Go | Why this shape |
|---|---|---|
| `findings.py` | `internal/findings` | Imported by every check in every group; must have no dependencies of its own. |
| `ingest.py`, `resolve.py` | `internal/ingest` (`ingest.go`, `resolve.go`) | One stage ("turn a target into an inventory"), one error family, one set of caps; two files, one package. |
| `checks/__init__.py`, `checks/coverage.py`, `checks/metadata.py` | `internal/checks` (`checks.go`, `coverage.go`, `metadata.go`) | One flat package for all check modules (other groups add `grants.go`, `hooks.go`, ...) like mcp-xray's flat `internal/reposcan`; Python's checks share unexported helpers the same way. |
| `capability.py` | `internal/capability` | Its own package because `llm/judge` takes `Triad` as a parameter and `scan` imports `llm`: folding it into `scan` creates an import cycle. |
| `correlate.py`, `disposition.py` | `internal/correlate` (`correlate.go`, `disposition.go`) | Disposition mutates `Result`/`Link` in place; keeping both in the package that defines the types lets the decision-phase fields stay one embedded struct. `sarif` imports this package for `Canonical`, `SourceRegion` and the version constants. |
| `scan.py` | `internal/scan` | Pipeline driver; imports checks, capability, correlate, llm. |
| `cli.py`, `__init__.py` | `cmd/skill-xray/main.go` | cobra root command; `__version__` becomes `internal/metadata.Version = "0.1.0"` (imported by cmd and sarif, as mcp-xray). `__all__`/re-exports are dropped (ponytail). |
| (tests' `conftest.py`) | `internal/testutil` | `MakePackage(t, map[string]string) string` (no project imports, see errata); the `candidate()` builder stays beside the tests that use it (Go cannot import another package's `_test.go`). |

Helpers that reproduce Python string semantics (`PyIsSpace`, `PySplitLines`, `PyLower`,
`CaseFold`, `PySplitExt`, `PyBasename`, `UnicodeEscape`, `Quote`, `OSErrorName`) are used by
core only in this group's code, but `parse` and `instruction` will need `PyIsSpace`/`PySplitLines`
too. Decision: they live in `internal/pytext` (one file, ~120 lines, no dependencies) so no group
duplicates them. Listed under cross-group needs.

## 1. Public surface

### 1.1 `findings.py` → `internal/findings`

Consumers (grep of `src/` and `tests/`): `analyze.py`, `checks/*.py` (all), `llm/adjudicate.py`,
`llm/judge.py` (`vector_meta`), `opengrep_bridge.py` (`Finding, cap_findings, dedupe_findings,
vector_registry`), `sarif.py` (`SEVERITY_RANK`), `correlate.py`, `disposition.py`, `cli.py`,
`scan.py`; 17 test files import `Finding`.

| Python | Go | Notes |
|---|---|---|
| `Finding` (frozen dataclass) | `type Finding struct` (below) | Value type; equality via `reflect.DeepEqual`/`assert.Equal`. |
| `FINDING_CAP = 25` | `const Cap = 25` | `checks/obfuscation`, `preproc`, `supply_chain` import it. |
| `SEVERITY_RANK` | `var SeverityRank = map[string]int{"critical":0,"high":1,"medium":2,"low":3}` | `Rank(sev) int` returns 9 when unknown (the `.get(sev, 9)` idiom); disposition also uses `.get(original, 99)` and `SEVERITY_RANK[x]` (KeyError-free after validation). |
| `vector_registry()` | `var Vectors = map[string]Meta{...}` (44 entries, SXV-001..SXV-044; wave 9 added SXV-044 and moved SXV-031 to T2) | `type Meta struct{Title, Tier string; CWE []string}`. Copy titles, tiers and CWE lists verbatim from `findings.py:24-123` (the SXV-005/038/039/041/042/043 titles are multi-part string literals; join them with a single space exactly as Python concatenation does, no newline). |
| `vector_meta(v)` | `func MetaOf(v string) (Meta, bool)` | Missing vector → zero Meta, false; `to_dict` adds `title/cwe/tier` only when found. |
| `Finding.to_dict()` | `func (f Finding) ToMap() map[string]any` and `MarshalJSON` (ordered) | Key order: `vector, rule, severity, path, message, [line], [column], [offset], [length], [evidence], [title, cwe, tier]`. `evidence` present only when non-empty; `title/cwe/tier` present only when the vector is registered (`cwe` is the registry list, `[]` never happens because every entry has CWEs). |
| `sort_findings` | `func Sort(fs []Finding) []Finding` | Returns a new sorted slice; `sort.SliceStable`. |
| `dedupe_findings` | `func Dedupe(fs []Finding) []Finding` | |
| `cap_findings` | `func CapFindings(fs []Finding) []Finding` | Python name kept (00-overview §3.9). |
| `findings_to_dicts` | `func ToMaps(fs []Finding) []map[string]any` | Sorts first. |
| `_engine_occurrence`, `_sort_key` | unexported | See §2.1. |

```go
type Finding struct {
    Vector   string
    Rule     string
    Severity string
    Path     string
    Message  string
    Line     *int           // 1-based; nil == Python None
    Column   *int           // 1-based
    Offset   *int           // byte offset; 0 is a real value (analyze.py emits offset=0)
    Length   *int
    Evidence map[string]any // nil or empty == Python {}; values: string, int, bool, nil, []any, map[string]any
}
```

Decision `*int`, not sentinels: a 0 sentinel collides with real byte offset 0 (`analyze.py:440,463,
564`), and a -1 sentinel makes the Go zero value mean "line 0 present"; `*int` is the only
representation whose zero value is Python's `None`. Provide `func Int(v int) *int`.

Evidence contract (binding on every group): integers are Go `int` (never `float64`/`json.Number`),
booleans are `bool`, absent is `nil`, nested lists are `[]any`, nested objects `map[string]any`.
Python's `type(x) is int` (false for `bool`) is `isInt(v any) bool { _, ok := v.(int); return ok }`.
No check stores a float in evidence (verified by grep), so `float64` never appears.

### 1.2 `ingest.py` → `internal/ingest`

Consumers: `cli.py` (`build_ledger, build_package, discover_skill_packages`), `__init__.py`,
`checks/persistence.py` (`IDENTITY_FILES`), `disposition.py` (`_BENIGN_LEDGER`), `parse.py`
(`Package`, `Artifact` fields `rel, kind, text, raw, ledger_exceptions, identity, name`), tests
(`MAX_FILE_BYTES, MAX_FILES, MAX_DIRS, AGGREGATE_MAX_BYTES, MAX_DISCOVERY_DIRS,
MAX_DISCOVERY_ENTRIES, KNOWN_SKILL_ROOTS, posix, read_bytes, _reject_special, _decode`).

```go
type Artifact struct {
    Rel, Role, Kind string
    Text      string // valid only when Exception == "" (Python: text is None iff exception is not None)
    Exception string // "" == Python None
    Raw       []byte // nil == Python None (no successful bounded read); a read empty file is []byte{} (non-nil)
}
func (a *Artifact) Read() bool { return a.Exception == "" }

type LedgerEntry struct {
    Outcome    string  `json:"outcome"`    // "skipped" (static) | "unresolved" (parse phase, parse group)
    Phase      string  `json:"phase"`      // "static" | "parse"
    ReasonCode string  `json:"reasonCode"`
    Path       string  `json:"path"`
    Target     *string `json:"target,omitempty"` // refused symlink target only
    Detail     *string `json:"detail,omitempty"` // parse-phase only (00-overview §3.3 wins: nil == null; the CLI ledger is built from Package before parse, so it never reaches --json)
}

type Package struct {
    Root, Identity, Name string
    Artifacts        []*Artifact
    LedgerExceptions []LedgerEntry
}

type Ledger struct { // key order == Python dict insertion order
    ArtifactsSeen           int      `json:"artifactsSeen"`
    ArtifactsAnalyzed       int      `json:"artifactsAnalyzed"`
    ArtifactsSkipped        int      `json:"artifactsSkipped"`
    ArtifactsNotInspectable int      `json:"artifactsNotInspectable"`
    ArtifactsFailedRead     int      `json:"artifactsFailedRead"`
    ShippedCompiledCode     []string `json:"shippedCompiledCode"`
    AgentIdentityFiles      []string `json:"agentIdentityFiles"`
    OpaqueContent           []string `json:"opaqueContent"`
    SecretMaterial          []string `json:"secretMaterial"`
    AgentConfig             []string `json:"agentConfig"`
    InspectableDenominator  int      `json:"inspectableDenominator"`
    CoveragePercent         Percent  `json:"coveragePercent"` // float64 with Python-repr MarshalJSON ("100.0", "66.67")
    ByRole                  map[string]int `json:"byRole"`     // Go sorts map keys == Python dict(sorted(...))
    Exceptions              []LedgerEntry  `json:"exceptions"`
}

type Discovery struct { Paths []string; LedgerExceptions []LedgerEntry } // Python list subclass with .ledger_exceptions
```

All slices that reach JSON are initialised non-nil (`[]string{}`), because Python emits `[]` and
Go emits `null` for a nil slice. This rule applies to every struct in this spec.

| Python | Go |
|---|---|
| `build_package(root)` | `func BuildPackage(root string) *Package` |
| `build_ledger(pkg)` | `func BuildLedger(p *Package) Ledger` |
| `discover_skill_packages(roots=None)` | `func Discover(roots []string) Discovery` (nil → `KnownSkillRoots`) |
| `install_identity(root)` | `func InstallIdentity(root string) string` |
| `read_bytes(path, limit, expected_stat)` | `func readBytes(path string, limit int64, expected os.FileInfo) (raw []byte, reason string, n int64)` (exported for tests: `ReadBytes`) |
| `_decode(raw)` | `func Decode(raw []byte) (text string, reason string)` (exported: benchmark adapters mirror it) |
| `_reject_special(st_mode)` | `func rejectSpecial(m fs.FileMode) string` |
| `_classify`, `_classify_shebang` | `classify(name) (kind, role string)`, `classifyShebang(text) (kind, role string, ok bool)` |
| `posix(p)` | `func Posix(p string) string` (`strings.ReplaceAll(p, string(os.PathSeparator), "/")`, only the OS separator) |
| constants `SCRIPT_EXT, COMPILED_EXT, DOC_ONLY_MD, INSTRUCTION_EXT, ASSET_EXT, ACTIVE_ASSET_EXT, NESTED_ARCHIVE_EXT, SKIP_DIRS, BUNDLED_DIRS, ROOT_CONFIG, AGENT_CONFIG_FILES, SECRET_FILES, SECRET_EXT, IDENTITY_FILES, KNOWN_SKILL_ROOTS, _PKG_MARKERS, _BENIGN_LEDGER` | same names in Go case; `IdentityFiles map[string]bool` (persistence imports it), `BenignLedger map[string]bool` (disposition imports it), `KnownSkillRoots []string` (**var**, tests replace it) |
| limits `MAX_FILE_BYTES=1_048_576, MAX_FILES=5000, MAX_DIRS=5000, AGGREGATE_MAX_BYTES=256<<20, MAX_DISCOVERY_DIRS=20000, MAX_DISCOVERY_ENTRIES=100000` | package-level `var`s (tests lower them; Python monkeypatches module globals) |

### 1.3 `resolve.py` → `internal/ingest/resolve.go`

Consumers: `cli.py`, `__init__.py`, tests (`resolved_input, Resolved, IngestLimitExceededError,
UnsafeInputError, INGEST_MAX_BYTES, INGEST_MAX_ZIP_MEMBERS, URL_DEADLINE_SECONDS,
URL_TIMEOUT_SECONDS, _looks_like_zip, _looks_like_url, _looks_like_git, _check_url_host,
_check_git_remote, _git_clone, _rmtree, _enforce_tree_size, _download_capped, _fetch_url`).

```go
type Resolved struct{ Root, Name, Kind string } // Kind: "directory" | "file" | "zip" | "url" | "git"
type UnsafeInputError struct{ Msg string }         // Error() == Msg (message text is what the CLI prints)
type IngestLimitExceededError struct{ Msg string }
func Resolve(target string) (Resolved, cleanup func(), err error) // cleanup is a no-op for "directory"
```

Two error types are kept (not one sentinel) because the tests assert which one fires and the
message must be printed verbatim (`cannot ingest %s: %s`). Limits `IngestMaxBytes = 100<<20`,
`IngestMaxZipMembers = 10000`, `URLTimeout = 30s`, `URLDeadline = 120s`, `GitTimeout = 120s` are
vars. `_CHUNK` disappears (`io.Copy` with a counting writer).

### 1.4 `scan.py` → `internal/scan`

Consumers: `cli.py`, `__init__.py`, tests (`scan, scan_report, ScanReport`; monkeypatched names
`run_checks, adjudicate, build_triads, correlate, apply_dispositions, judge_candidates,
_advisory`). `sarif.py` reads `report.correlation, .dispositions, .shadow, .review_mode,
.context_errors, .llm_usage`.

```go
func Scan(parsed *parse.Package, client llm.Completer, opengrepExe string) []findings.Finding

type Options struct {
    Client            llm.Completer
    LLMShadow         bool
    OpengrepExe       string
    MaxLLMCalls       int   // 0 → 25
    LLMAdvisory       *bool // nil → default (!reviewEnabled)
    LLMReview         bool
    DispositionPolicy map[string]any // nil == None
    LLMApply          bool
}
func Report(parsed *parse.Package, o Options) (*ScanReport, error) // error == the three ValueErrors

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
func (r *ScanReport) ToMap() map[string]any // to_dict(); deep-copies
```

Test seams: `var runChecks = checks.Run`, `var adjudicate = llm.Adjudicate`, `var buildTriads =
capability.Build`, `var correlateFn = correlate.Correlate`, `var applyDispositions =
correlate.ApplyDispositions`, `var judgeCandidates = llm.Judge`, `var advisory = ...`.
Python tests monkeypatch exactly these names; package-level function vars are the smallest
equivalent.

### 1.5 `cli.py` → `cmd/skill-xray/main.go`

Consumers: tests (`cli.main(argv) -> int`, `_display`, `_print_findings`, `_print_one`,
monkeypatched `llm_from_env, build_client, scan, scan_report, build_sarif, write_sarif,
resolved_input`). Go: `func run(argv []string, stdout, stderr io.Writer) int` (tests call it;
`main()` calls `os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))`). Same seams as vars.

### 1.6 `checks/__init__.py`, `coverage.py`, `metadata.py` → `internal/checks`

| Python | Go |
|---|---|
| `run_checks(parsed, *, opengrep_executable=None, observations=None)` | `func Run(parsed *parse.Package, opengrepExe string, observations *[]map[string]any) []findings.Finding` (nil pointer == Python None: taint check is then called without the kwarg) |
| `_CHECKS` | `var registry = []struct{name string; fn func(*parse.Package) []findings.Finding}` in the Python order with names `"skill_xray.analyze", "skill_xray.checks.coverage", ".grants", ".hooks", ".instruction_exfil", ".metadata", ".obfuscation", ".persistence", ".preproc", ".supply_chain", ".taint_engine"`; taint is special-cased by index as in Python |
| `coverage.check` | `func Coverage(parsed) []Finding` |
| `coverage.is_inventory_note(dict)` | `func IsInventoryNote(vector, rule, severity string, evidence map[string]any) bool` (callers holding a `Finding` pass its fields; callers holding a finding map extract them) |
| `coverage._static_severity(reason, kind)` | `func StaticSeverity(reason, kind, rel string) string` (`""` == None; `kind == ""` when no artifact; `rel` grades an unreviewed `.svg` as a note) |
| `_LOW_PARSE`, `_LOW_STATIC` | unexported sets |
| `metadata.check` | `func Metadata(parsed) []Finding` |

### 1.7 `capability.py` → `internal/capability`

Consumers: `scan.py`, `llm/judge.py` (parameter type), tests, `review_helpers.py`.

```go
var Axes = []string{"execution", "network"}
type Triad struct {
    Manifest    *string            `json:"manifest"` // nil for the "" (ungoverned) key
    Claimed     map[string]string  `json:"claimed"`  // keys exactly Axes, values "unknown"|"present"|"denied"
    Declared    map[string]string  `json:"declared"`
    Observed    map[string]string  `json:"observed"`
    Evidence    []map[string]any   `json:"evidence"`
    Limitations []string           `json:"limitations"`
}
func Build(parsed *parse.Package, observations []map[string]any, coverage []findings.Finding) map[string]*Triad
```

`map[string]string` for the axes is safe because Go's JSON key sort (`execution` < `network`)
equals `AXES` order, so `asdict` output is byte-identical.

### 1.8 `correlate.py` + `disposition.py` → `internal/correlate`

Consumers: `scan.py`, `sarif.py` (`FINGERPRINT_VERSION, canonical, source_region,
LLM_APPLY_VECTORS, LLM_APPLY_VERSION, POLICY_VERSION`), tests.

```go
const FingerprintVersion = "skill-xray/evidence/v1"
const ContextVersion     = "skill-xray/context/v1"
const PolicyVersion      = "skill-xray/scoped-policy/v1"
const LLMApplyVersion    = "skill-xray/llm-apply/v1"
var   LLMApplyVectors    = map[string]bool{"SXV-028":true,"SXV-029":true,"SXV-030":true,"SXV-031":true}

// pytext.Canonical(v any) string     // json.dumps(sort_keys, ensure_ascii, separators=(",",":"), allow_nan=False) -- hand-written in internal/pytext, §5.19
func Digest(v any) string             // sha256 hex of pytext.Canonical
func SourceRegion(a *parse.Artifact, start, end map[string]any, byteColumns bool, lines []string) (text string, startCol, endCol int, err error)

type Candidate struct {
    CandidateID string         `json:"candidate_id"`
    Finding     map[string]any `json:"finding"`   // Finding.ToMap()
    Analyzer    string         `json:"analyzer"`
    Provenance  string         `json:"provenance"`
    Coverage    string         `json:"coverage"`
}
type FlowStep struct{ Role, Path string; Start, End map[string]any; Content string } // json: role,path,start,end,content
type Provenance struct{ Analyzer, Provenance string; EngineRule *string }            // json: analyzer,provenance,engine_rule (null when absent)
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
    *Decision                            // nil until ApplyDispositions; embedded pointer inlines its fields when set
}
type Decision struct {
    Disposition        string         `json:"disposition"`
    DecisionReason     string         `json:"decision_reason"`
    DecisionProvenance string         `json:"decision_provenance"`
    PolicyVersion      string         `json:"policy_version"`
    OriginalSeverity   string         `json:"original_severity"`
    EffectiveSeverity  string         `json:"effective_severity"`
    CapabilityContext  map[string]any `json:"capability_context"` // triad minus "evidence"; nil → null
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
type LinkDecision struct{ PolicyVersion string `json:"policy_version"`; Provenance string `json:"provenance"` }
type PackageInfo struct{ Name, ContentDigest, DigestVersion string } // json: name,content_digest,digest_version
type Correlation struct {
    RawCandidates []Candidate `json:"raw_candidates"`
    Results       []*Result   `json:"results"`
    Package       *PackageInfo `json:"package,omitempty"` // absent on the scan.py fallback value
    Links         []Link      `json:"links"`
    Errors        []string    `json:"errors,omitempty"`
    *Applied                   // nil until ApplyDispositions
}
type Applied struct {
    CapabilityContexts map[string]map[string]any `json:"capability_contexts"`
    Coverage           string                    `json:"coverage"`
    ContextLimitations []ContextLimit            `json:"context_limitations"` // {manifest, limitations}
    ExecutionSuccessful bool                     `json:"execution_successful"`
    LLMApplied         *int                      `json:"llm_applied,omitempty"` // set by ApplyLLMReview
}

func Correlate(parsed *parse.Package, candidates []Candidate) (*Correlation, error)
func ApplyDispositions(parsed *parse.Package, c *Correlation, triads map[string]*capability.Triad, policy map[string]any, contextErrors []string) (*Correlation, error) // error only for the three policy ValueErrors
func ApplyLLMReview(c *Correlation, decisions []llm.Decision) *Correlation
```

Embedded pointer structs model "keys Python adds later": encoding/json omits a nil embedded
pointer entirely and inlines its fields when non-nil. `Result.Finding` stays a generic
`map[string]any` because Python treats it as a JSON document (pops `message`, replaces
`evidence`, reads `evidence.end`) and it must round-trip through `Canonical` unchanged.

### 1.9 Cross-group identifiers core consumes (must exist with these shapes)

| Python | Group | Go shape core needs |
|---|---|---|
| `parse.ParsedPackage{identity, name, artifacts, by_rel, ledger_exceptions}` | parse | `parse.Package{Identity, Name string; Artifacts []*Artifact; ByRel map[string]*Artifact; LedgerExceptions []ingest.LedgerEntry}` |
| `parse.ParsedArtifact{rel, kind, text, raw, frontmatter, frontmatter_key_lines, unsafe_yaml_tags, grants, markdown, diagnostics}` | parse | `Text *string` (nil == None); `Raw []byte` nil==None; `Frontmatter map[string]any` (nil==None); `FrontmatterKeyLines map[string]int`; `UnsafeYamlTags []YamlTag{Tag string; Line, Column int}`; `Grants []Grant` (nil==None); `Markdown *Markdown` with `ParagraphSpans []parse.Span` (1-based inclusive, i.e. markdown-it `tok.map` as `(map[0]+1, map[1])`); `Diagnostics []Diagnostic{Code string; Detail *string}` |
| `parse.Grant{tool, pattern, raw, allowed, broad, parsed}` | parse | `Grant{Tool string; Pattern *string; Raw string; Allowed, Broad, Parsed bool}` |
| `code_lane._manifest_index(parsed)`, `_governing_manifest(index, rel)`, `_parent(rel)` | code (move to parse/IR) | `parse.ManifestIndex(p) map[string]*Artifact`, `parse.GoverningManifest(index, rel) *Artifact`. Recommendation: these read only the IR and are used by capability, correlate and llm/judge; they live in `internal/parse` (00-overview D2). |
| `grants._EXECUTION_TOOLS`, `_NETWORK_TOOLS`, `declared_capabilities(grants) -> set`, `denied_capabilities(grants) -> set`, `effective_grants(grants) -> list` | code | `grants.ExecutionTools`, `grants.NetworkTools map[string]bool`; `grants.Declared([]parse.Grant) map[string]bool`; `grants.Denied`; `grants.Effective([]parse.Grant) []parse.Grant` |
| `code_lane.build_code_lane(parsed) -> (units, notes)` | code | `codelane.Build(p) ([]codelane.Unit, []findings.Finding)` (no error value; a recovered panic makes core emit the `check-error` "executable code selection failed: %s" finding) |
| `taint_engine.check(parsed, executable=, code_units=, lane_notes=, observations=)` | code | `opengrep.Check(p, opengrep.Options{Executable: exe, Units: units, LaneNotes: notes, Observations: observations}) []Finding` |
| `analyze.analyze_package(parsed)` | code | `forensics.AnalyzePackage(p) []Finding` |
| `opengrep_runtime.VERSION ("1.29.0"), install_opengrep(), OpenGrepRuntimeError` | code | `opengrep.Version`, `opengrep.Install("", nil) (string, error)` |
| `llm.from_env() -> LLMConfig|None`, `LLMConfigError`, `build_client(cfg)`, `coverage_summary(parsed, findings) -> dict` | output-llm | `llm.FromEnv(os.Getenv) (*Config, error)`; `llm.BuildClient`; `llm.CoverageSummary(...) map[string]any` with keys `eligible, checked, truncated, skipped, errored, flagged` (ints) plus the CLI's overrides `enabled=false, checked=0, skipped=eligible, reason=...` |
| `llm.adjudicate(parsed, client) -> [Finding]`, `LLMSession(client, max_calls=25)`, `session.usage() -> dict` | output-llm | `llm.Adjudicate(p, session, 25) []Finding`; `llm.NewSession(client, maxCalls, 1<<20) (*Session, error)`; `Usage() map[string]any` |
| `llm.judge.POLICY_VERSION ("directive-shadow-v3") -> llm.ShadowPolicyVersion, REVIEW_POLICY_VERSION ("directive-review-v2") -> llm.ReviewPolicyVersion, judge_candidates(parsed, candidates, triads, session, apply_review=)` | output-llm | `llm.Decision{CandidateID string; Disposition, Status string; Proposal any; Reason, PolicyVersion, Provenance string}` (json keys `candidate_id, disposition, status, proposal, reason, policy_version, provenance`; `proposal` null when nil); `llm.Judge(p, []correlate.Candidate, map[string]*capability.Triad, *llm.Session, applyReview bool) []Decision` |
| `sarif.build_sarif(parsed, report)`, `write_sarif(doc, path, source_root=)`, `is_within_source(path, root)` | output-llm | `sarif.Build(p, *scan.ScanReport) (any, error)`; `sarif.Write(doc, path, sourceRoot string) error` (validation errors == Python `ValueError`); `sarif.IsWithinSource(path, root string) bool` |
| `checks/preproc` finding evidence `command_sha256` | parse | string |
| observations dicts appended by `opengrep_bridge`/`taint_engine` | code | `map[string]any` with keys `path` (string), `line`, `column` (int), `capability`, `state`, `analyzer`, `rule`, `vector`, `reason`, `command_sha256` (strings) |

## 2. Behaviour inventory

Test citations are `tests/<file>::<test>`.

### 2.1 `findings.py`

- `Finding.to_dict`: see §1.1 order. `tests/test_findings.py::test_legacy_positional_finding_fields_keep_their_meaning` pins positional order `(vector, rule, severity, path, message, line, offset, length, evidence, column)`; Go has no positional construction, so nothing to port beyond field names.
- `_engine_occurrence(f)`: returns `()` unless `evidence.engine == "opengrep"` and `evidence.location_mapping == "unvalidated"` and `evidence.engine_location` is a dict with dict `start` and `end`; then the 6-tuple `(start.line, start.col, start.offset, end.line, end.col, end.offset)` with each value `x if type(x) is int else -1`. Go: `[]int` (nil for `()`); tuple comparison: `()` sorts before any non-empty tuple, otherwise elementwise then by length.
- `_sort_key(f)`: `(rank(severity, default 9), path, vector, line or -1, column or -1, offset or -1, rule, message, engine_occurrence)`. String comparison is code-point order == Go bytewise (verified `sorted(["b","aé","a😀","aZ","a~","a\uffff"])` == Go `sort.Strings`).
- `sort_findings`: `sorted()` is stable → `sort.SliceStable`. Returns a new list.
- `dedupe_findings`: iterate the sorted list, keep first of each key `(vector, path, line, column, offset, rule, message, engine_occurrence)`; note severity is NOT in the key (a critical and a high with the same location collapse to the critical one because it sorts first). Test: `tests/test_findings.py::test_duplicates_do_not_consume_finding_cap`, `tests/test_report.py::test_report_preserves_raw_and_detaches_evidence` (`report.findings == dedupe_findings(raw) == scan(parsed)`).
- `cap_findings`: over `dedupe_findings(findings)`; group key `vector or rule`, and for `SXV-033` with string non-empty `evidence.understated_capability` the group is `"SXV-033:<cap>"`; count per `(path, group)`; keep the first 25; then for every `(path, group)` with count > 25 append `Finding{Vector:"", Rule:"findings-capped", Severity:"low", Path:path, Message: fmt.Sprintf("%d more %s findings in %s were suppressed (cap %d per file)", count-25, group, path, 25)}`; suppression findings are appended in `counts` dict iteration order = first-seen order of `(path, group)` (Go: keep an ordered key slice, not a map iteration). Tests: `test_findings.py::test_manifest_capability_classes_are_capped_independently`.
- `findings_to_dicts`: sort then map.
- `test_findings.py::test_every_referenced_vector_is_registered` walks the Python AST for `SXV-\d+` string constants. Go port: a test that regexp-scans every `.go` file under `internal/` and `cmd/` for `"SXV-\d{3}"` literals and asserts each is in `Vectors`.

### 2.2 `ingest.py`

Classification (`_classify(filename)`): `low = PyLower(name)`, `ext = PyLower(PySplitExt(name).ext)`; order of tests is the Python order (`skill.md` → manifest; `IDENTITY_FILES`; `ROOT_CONFIG`; `AGENT_CONFIG_FILES`; `SECRET_FILES or ext in SECRET_EXT`; `INSTRUCTION_EXT` (with `DOC_ONLY_MD` → doc); `SCRIPT_EXT`; `COMPILED_EXT or _SO_VERSIONED.search(low)` → `COMPILED_EXT.get(ext, "native_code")`; `package.json`/`pyproject.toml`/`*.txt` containing `requirements` → dep_manifest; `NESTED_ARCHIVE_EXT` → opaque; `ACTIVE_ASSET_EXT` → opaque; `ASSET_EXT` → asset; else `other`). Tests: `test_ingest.py::test_agent_identity_files_are_first_class`, `::test_agent_identity_match_is_case_insensitive`, `::test_requirements_variants_are_dependency_manifests`, `::test_native_variants_are_surfaced_as_compiled` (`lib/foo.so.1`), `::test_mdc_and_rule_files_are_classified`, `::test_agent_config_and_secret_files_are_classified`, `::test_credentials_json_classified_secret` (`.credentials.json`: `splitext` gives ext `.json`, basename match wins first), `::test_active_and_nested_content_is_surfaced_and_counted`.

`_classify_shebang(text)`: first line = text up to first `\n`, truncated to 256 code points; regex §3 (#2) with `(?i)`; group 1 lowered; `python*` → python; `bash|sh|zsh|dash|ksh|fish` → shell; `pwsh|powershell` → powershell; `node|deno|bun` → javascript; else the name (`ruby`, `perl`) → `("script_"+lang, "script")`. Only applied when `kind == "other"` and the text decoded. Test: `::test_extensionless_shebang_scripts_are_classified`.

`read_bytes(path, limit, expected_stat)`: `limit = min(max(0, limit), MAX_FILE_BYTES)`; open `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_BINARY` where defined (Unix build tag adds `syscall.O_NOFOLLOW|syscall.O_NONBLOCK`; Windows none); open error → `("unreadable:"+OSErrorName(err), 0)`; `fstat` not regular → `not_regular_file`; if `expected` given and (`Mode().Type()` differs or `!os.SameFile(expected, st)`) → `file_changed` (wave-2 correction: Go's `Lstat` info on Windows loads the file id lazily by path, so the walker must pin it with `os.SameFile(st, st)` right after `Lstat`, or `ReadBytes` compares the swapped-in file with itself and never reports `file_changed`); `st.Size() > MAX_FILE_BYTES` → `too_large`; `> limit` → `total_budget_exhausted`; read up to `limit` bytes (`io.ReadAll(io.LimitReader(f, limit))`); re-`fstat`; read error → `unreadable:<name>` with 0 bytes; post-read `final_size > MAX_FILE_BYTES` → `too_large` with `n = len(raw)` (bytes ARE charged); `> limit` → `total_budget_exhausted` with `n`; else `(raw, "", n)`. Tests: `::test_read_bytes_reports_bytes_actually_read`, `::test_read_bytes_does_not_cross_remaining_aggregate_budget` (limit 4 on a 5-byte file → `total_budget_exhausted`, n=0), `::test_walker_rejects_a_regular_file_replaced_before_open` (`file_changed`; Go test: replace the file via an injected `openFile` seam or hard link before open), `::test_file_at_the_cap_is_read`, `::test_oversized_file_is_skipped_not_read`.

`_decode(raw)`: `bytes.IndexByte(raw, 0) >= 0` → `binary_content`; strip UTF-8 BOM `EF BB BF` if present then `utf8.Valid` → text; else cp1252: if any byte in `{0x81,0x8D,0x8F,0x90,0x9D}` → `undecodable_text` (verified: exactly these five are undefined in Python's cp1252), else decode with `charmap.Windows1252` (x/text, already a module dependency); note `utf-8-sig` strips the BOM only when UTF-8 succeeds; when it fails the BOM bytes decode through cp1252 as `ï»¿`. Tests: `test_coverage_adapters.py::test_adapters_copy_exactly_what_the_scanner_decodes` (table: ascii, BOM, UTF-8 `Café`, cp1252 `Café`, NUL → binary, `\x81\x8d\x8f` → undecodable) — the adapters themselves are benchmark tooling and are not ported, but this table is the Go table test for `Decode`; `test_ingest.py::test_nul_in_script_counts_as_failed_read_not_binary`, `::test_undecodable_files_are_charged_against_the_budget`.

`build_package(root)`: `Package{Root: Abs(root), Identity: InstallIdentity(root), Name: Base(TrimRight(Root, "\\/"))}`. Iterative DFS with a stack `pending=[root]`; per directory: `seen_dirs++`; enumerate entries with `is_dir = entry.is_dir(follow_symlinks=False)` (Go `DirEntry.Type().IsDir()`; an OS error → treated as a file); `files_here`/`dirs_here` counters; **before appending each entry**: if `seen + files_here > MAX_FILES` → `truncated`, break; if `seen_dirs + len(pending) + dirs_here > MAX_DIRS` → `dirs_truncated`, break. Enumeration must be bounded (Python streams `scandir`): Go uses `f.ReadDir(512)` batches from `os.Open(dir)`, never `os.ReadDir` (`::test_flat_directory_entry_count_is_bounded` asserts only 2 of 10,000 entries were pulled with `MAX_FILES=1`; the Go test uses a real directory of a few thousand files with the limits lowered). Enumeration error → `walk_errors.append(("walk_error:"+OSErrorName(err), relpath(err.filename or dirpath)))` and `continue`. After any truncation flag the whole walk stops (`break` out of `while pending`), so an overflowing directory is dropped atomically (`::test_file_count_cap_truncates_and_records`, `::test_directory_count_cap_stops_empty_tree_and_records_gap`, `::test_directory_count_cap_stops_wide_tree_without_advancing_walk` — the Go test counts `os.Open(dir)` calls via a seam or by directory layout).
Then: `dirnames`, `filenames` from the entries; collisions: group all names (dirs+files) by `_portable_name(name) = CaseFold(NFC(name) with TrimRight(" ."))`; any group of size > 1 marks all its members. Directories in original order: collision → skip `portable_path_collision`; `SKIP_DIRS` → `excluded_dir`; `BUNDLED_DIRS` → `bundled_dir`; `_is_reparse(dp)` → `reparse_point`; else kept. `pending.extend(reversed(sorted(kept)))` (pop order = ascending). Files in `sorted(filenames)`: `seen++`; `rel = NFC(Posix(Rel(root, ap)))`; collision → Artifact with `Exception="portable_path_collision"` + ledger entry, added, continue; `lstat` error → ledger `unreadable:<name>`, continue (no artifact); `rejectSpecial(mode)`: symlink → `"symlink"` with `target = os.Readlink(ap)` (ignored on error), non-regular → `not_regular_file`; ledger entry with optional target, continue (no artifact). Else classify, `Artifact{rel, role, kind}`; `remaining = max(0, AGGREGATE_MAX_BYTES - total_read)`; if `remaining == 0` → `total_budget_exhausted` (no read); else `readBytes(ap, remaining, st)`, `total_read += n`; branch order: budget hit → `total_budget_exhausted`; read reason → that reason; `kind == "asset"` → `binary_content` (raw retained, text unset); `role == "opaque"` → `unreviewable_content`; `role == "compiled"` → `shipped_compiled`; else `Decode(raw)` → text or reason; if decoded and `kind == "other"` → shebang reclassification. Every non-empty exception also appends a ledger entry `(reason, rel)`. Append artifact. After the loop: `truncated` → ledger `walk_truncated` with path `"(more than %d files)" % MAX_FILES`; `dirs_truncated` → `"(more than %d directories)" % MAX_DIRS`; then each walk error. Tests: `::test_symlinked_file_is_not_read` (no artifact, ledger `symlink`), `::test_refused_symlink_records_its_target` (target equals the link target; Windows `\\?\` prefix tolerated), `::test_symlinked_directory_is_not_traversed`, `::test_junction_directory_does_not_escape_the_package` (Windows; `reparse_point` with path `escape`), `::test_reparse_dir_is_pruned_and_logged` (Go: build-tagged seam `isReparse`), `::test_excluded_dir_is_logged_not_silent`, `::test_posix_backslash_filename_not_collapsed`, `::test_unreadable_directory_is_logged_not_silent` (`walk_error*`), `::test_aggregate_byte_budget_bounds_memory`, `::test_budget_skipped_asset_is_not_excused_as_binary`, `::test_normal_package_is_inventoried_with_a_clean_ledger`, `::test_filenames_are_recorded_in_nfc`, `::test_nfc_collision_cannot_excuse_a_failed_asset` (two names collide after NFC → both `portable_path_collision`, both count as failed reads), `::test_shipped_bytecode_is_inventoried_not_dropped`, `::test_pyc_inside_pycache_is_seen_not_excluded`, `::test_native_code_is_surfaced_as_compiled`, `::test_binary_asset_is_ledgered_not_counted_against_coverage`, `::test_oversized_asset_is_a_failed_read_not_an_excused_icon`, `test_coverage.py::test_canonically_colliding_directories_fail_before_grant_selection`.

`_is_reparse(path)`: POSIX: `Lstat` mode has `ModeSymlink`. Windows: additionally a directory whose `FileAttributes` has `FILE_ATTRIBUTE_REPARSE_POINT` (junction). Go 1.23+ reports a junction as `ModeIrregular`, so the Windows file (`ingest_windows.go`) must check `Sys().(*syscall.Win32FileAttributeData).FileAttributes & (FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)`; a junction must be listed among `dirnames` (Python `is_dir(follow_symlinks=False)` is True for it) and then pruned as `reparse_point`, not fall through to `not_regular_file`.

`install_identity(root)`: `EvalSymlinks(Abs(root))` (fallback `Abs` when the path does not exist, matching `realpath(strict=False)`), `Posix`, lowercase a leading drive letter (`x:`), `TrimRight("/")`, restore `"c:/"` for a bare drive, `"/"` for empty. Reaches JSON as `identity` (`test_cli.py::test_cli_reports_inventory_and_ledger` asserts presence).

`discover_skill_packages(roots)`: for each root `Abs(expanduser(root))` (`~` → `os.UserHomeDir()`; Python on Windows uses `USERPROFILE`, same as Go); `Stat` error: not-exist → skip silently, other → ledger `walk_error:<name>` with path `Posix(Abs(base))`, skip; non-directory → skip. Stack `[(base, allowRootLinks=true)]`; per pop: `real = EvalSymlinks(dir)` (fallback Abs); `real in seen` → continue; `scanned_dirs >= MAX_DISCOVERY_DIRS` → ledger `walk_truncated` `"(more than %d discovery directories)"`, stop everything; `seen.add(real)`, `scanned_dirs++`; enumerate entries (bounded): `seen_entries++`, `> MAX_DISCOVERY_ENTRIES` → entry-limit flag, break; `low = PyLower(name)`; `is_link = entry.is_symlink()`, `link_dir = is_link && Stat(path).IsDir()`, `is_dir = Type().IsDir()`, `reparse = is_dir && isReparse(path)`; any error → ledger `walk_error:<name>` for `Posix(Abs(entry.path))`, continue; `link_dir`: if `allowRootLinks` push `(path, false)`; continue; not a dir: `marker |= low == "skill.md" || low in _PKG_MARKERS`; continue; dir in `SKIP_DIRS|BUNDLED_DIRS` or reparse → continue; `marker |= (dir name check, same predicate)`; push child `(path, false)`. Enumeration error → ledger, continue. Entry-limit → ledger `walk_truncated` `"(more than %d discovery entries)"`, stop everything. `marker` → `found[real] = dirpath`, continue (subtree pruned); else `pending.extend(reversed(sorted(children)))` (sorted by path string). Result: `Paths = [found[k] for k in sorted(found)]` (sorted by realpath), plus exceptions. Tests: `::test_discover_finds_packages_under_roots`, `::test_discover_skips_missing_roots`, `::test_discovery_directory_budget_is_exact_and_fail_visible`, `::test_discovery_wide_directory_enumeration_is_bounded` (yields exactly `MAX+1` entries), `::test_discovery_scandir_failure_is_recorded`, `::test_discovery_root_stat_failure_is_recorded`, `::test_discovery_entry_failure_is_recorded`, `::test_discovery_is_case_insensitive_for_skill_md`, `::test_discovery_follows_a_symlinked_package_root`, `::test_discovery_does_not_follow_nested_symlinks`, `::test_discovery_survives_a_broken_symlink_entry`, `::test_discovery_returns_plugin_root_not_leaf`, `::test_discovery_flat_skill_still_found`. Python tests fake `os.scandir`; Go tests use real directories with the limits lowered, plus a seam only where a real filesystem cannot produce the error (entry `is_symlink` failure).

`build_ledger(pkg)`: `artifact_exceptions = Counter((rel, exception))` over artifacts with an exception; `pre_skips`: for each ledger entry, if `counter[(path, reasonCode)] > 0` decrement (it is an artifact-level skip) else if reasonCode not in `_BENIGN_LEDGER` (`excluded_dir`) append (directory-level skip that lowers coverage). `analyzed` = artifacts with `Exception == ""`; `compiled/identity/opaque/secrets/configs` = sorted rels by role (`compiled`, `identity`, `opaque`, `secret`, `config|root_config`); `not_inspectable` = count of (`kind == "asset" && exc == "binary_content"`) or (`role == "compiled" && exc == "shipped_compiled"`); `failed` = artifacts with an exception that are not in `not_inspectable` + `len(pre_skips)`; `seen = analyzed + not_inspectable + failed`; `denom = analyzed + failed`; `coveragePercent = denom ? round(100.0*analyzed/denom, 2) : 100.0`; `byRole` sorted counts; `exceptions` = ledger entries stably sorted by `(path, reasonCode)`. Tests: `::test_all_binary_package_reports_full_coverage_not_zero`, `::test_excluded_dir_does_not_lower_coverage`, `::test_symlinked_away_manifest_lowers_coverage`, `::test_root_config_surfaced_in_agent_config`, and every ledger assertion above.

Line/offset computations: none (ingest has no positions).

### 2.3 `resolve.py`

`_resolve(target)`: order is fixed: `IsDir` → `("directory", Abs, name = Base(TrimRight(abs,"/\\")) or abs)`; `IsFile` (Stat follows links; Python `os.path.isfile`) → if `Lstat` is a symlink → `UnsafeInputError("single-file input is a symlink; refused: %s")` (`test_resolve.py::test_single_file_symlink_is_refused`, `::test_single_file_symlink_to_zip_is_refused`); `_looks_like_zip` → mkdtemp, extract (errors: our two types propagate after `rmtree`; any other error → `UnsafeInputError("cannot read zip %s: %s")`), kind `zip`, name `_strip_zip_ext(basename)`; `_is_unsupported_archive` → `UnsafeInputError("%s is an archive skill-xray does not extract; unpack it and scan the directory")`; else `_wrap_single_file` → kind `file`, name basename; `_looks_like_git` (trimmed, lowered: ends with `.git` or starts with `git@`, `git://`, `ssh://`) → clone; `_looks_like_url` (lowered starts with `https://`) → fetch; else `UnsafeInputError("not a directory, file, .zip, URL or git repo: %s")` (`test_cli.py::test_cli_rejects_a_non_directory` asserts "not a directory" in stderr). Tests: `::test_directory_is_used_in_place` (`r.root == str(root)` — Python returns `abspath`, and the test's `root` is already absolute; Go returns `filepath.Abs`), `::test_local_dir_named_dot_git_is_treated_as_directory`, `::test_missing_target_is_a_clear_error`, `::test_scheme_matching_is_case_insensitive`, `::test_single_file_temp_dir_is_removed_on_exit`.

`_looks_like_zip(path)`: first 4 bytes must be `PK\x03\x04`; then `zip.OpenReader` must succeed (treat `zip.ErrInsecurePath` as success: Go returns a usable reader alongside it) and at least one member must satisfy `_zip_member_extracts`: not `is_dir()` (name ends with `/`) and `path.Clean(strings.ReplaceAll(name,"\\","/")) != "."`. Tests: `::test_zip_trailer_does_not_evade_as_empty_archive`, `::test_zip_prefixed_magic_with_empty_eocd_does_not_evade`, `::test_zip_root_only_member_does_not_evade`, `::test_url_trailer_does_not_evade_as_empty_archive`, `::test_zip_degenerate_member_does_not_crash`.

`_extract_zip(zip, dest)`: `destReal = EvalSymlinks(dest)`; `len(files) > INGEST_MAX_ZIP_MEMBERS` → `IngestLimitExceededError("zip has %d members (max %d)")`; per member: `raw = NFC(ReplaceAll(name, "\\", "/"))`; leading `/` or `^[A-Za-z]:` → `UnsafeInputError("zip member uses an absolute path: %s")`; `parts = split("/") minus "" and "."`; any `..` → `"zip member escapes the extract dir: %s"`; empty parts → skip; `portable = [CaseFold(TrimRight(part, " .")) ...]`; any empty or containing `:` → `"zip member has a non-portable path: %s"`; `key = join(portable, "/")`; `parents` = every proper prefix join; `key in seen || parents ∩ files` → `"zip has colliding member paths: %s"`; `seen.add(key)`; if not dir `files.add(key)`; `out = EvalSymlinks-or-Abs(Join(dest, parts...))`; `out != destReal && !HasPrefix(out, destReal+sep)` → escapes; `out == destReal` → continue; `(ExternalAttrs>>16)&0o170000 == 0o120000` → `"zip contains a symlink: %s"`; dir → `MkdirAll`; else `MkdirAll(parent)`, copy with running total, `> INGEST_MAX_BYTES` → `IngestLimitExceededError("zip uncompressed size exceeds %d bytes")`. Note the total counts bytes actually written across members. Tests: `::test_zip_is_extracted_and_walkable`, `::test_zip_member_count_cap`, `::test_zip_uncompressed_byte_cap`, `::test_zip_slip_is_rejected`, `::test_zip_backslash_slip_is_rejected_portably`, `::test_zip_portable_path_collisions_are_rejected` (3 cases: case, NFC/NFD, trailing dot), `::test_zip_symlink_member_is_rejected`, `::test_malformed_zip_fails_closed` (`a` then `a/b`: Python hits `FileExistsError` at `makedirs`; Go's `MkdirAll` over a file returns an error → wrap as "cannot read zip").

`_wrap_single_file(path)`: mkdtemp, copy in chunks with running total, `> INGEST_MAX_BYTES` → `IngestLimitExceededError("file exceeds %d bytes")`; other errors → `UnsafeInputError("cannot read file %s: %s")`; temp dir removed on any error. `::test_single_file_size_cap_is_enforced`, `::test_single_file_is_wrapped_into_a_package`.

`_is_unsupported_archive(path, name)`: content sniff (`tarfile.is_tarfile`: gzip/bzip2/xz-wrapped or raw tar whose first header parses) OR lowered name ends with one of `_ARCHIVE_EXTS`. Go: gzip (`compress/gzip`) and bzip2 (`compress/bzip2`) → `tar.NewReader(...).Next()` succeeds; raw → same on the file; xz has no stdlib decoder → treat the xz magic `FD 37 7A 58 5A 00` as "is a tar" (`// ponytail: xz sniff refuses any xz stream, not only xz tars; upgrade path: ulikunitz/xz`). `io.EOF` from `Next()` (empty/zero-block file) is "not a tar" (Python raises `ReadError("empty file")`). Tests: `::test_non_zip_tarball_is_refused`, `::test_unknown_archive_extension_is_refused`.

`_check_url_host(url, deadline)`: parse (`net/url`); scheme lowered must be `https` else `UnsafeInputError("only https URLs are allowed")`; userinfo present (`u.User != nil` or `@` in authority) → `"URL with embedded credentials is refused"`; empty host → `"no host in URL"`; port: `u.Port()` empty → 443; not an integer in 0..65535 → `"malformed URL"` (Go's parser accepts `:99999`; Python raises `ValueError` — the Go port must range-check: `::test_url_invalid_port_is_refused`); any parse error → `"malformed URL"` (never echo the URL: `::test_malformed_url_error_does_not_echo_the_url`, `::test_malformed_url_fails_closed`); `ip = _resolve_public_ip(hostname_lowered, port, deadline)`; `target = u.RequestURI()` equivalent: `(u.EscapedPath() or "/") + ("?"+RawQuery if RawQuery)`; returns `(host, port, target, ip)`. Tests: `::test_url_ssrf_blocks_non_public` (6 URLs incl. `[::1]`, `100.64.0.1`), `::test_url_rejects_non_https_scheme`, `::test_url_with_embedded_credentials_is_refused`, `::test_url_public_host_passes_the_check`, `::test_url_ssrf_blocks_embedded_ipv4` (2), `test_url_deadline.py::test_real_isolated_dns_worker_resolves_numeric_literal_without_network` (result tuple `("93.184.216.34", 443, "/skill", "93.184.216.34")`).

`_resolve_public_ip(host, port, deadline)`: resolve ALL addresses (`net.Resolver.LookupIPAddr(ctx)` with `ctx` deadline; the Python subprocess worker exists only to bound a blocking resolver and is not ported — ponytail rung 3); timeout → `UnsafeInputError("DNS resolution timed out")` but only after the deadline check has had its chance to raise `IngestLimitExceededError` ("download exceeded the %ds deadline", `::test_stalled_dns_is_bounded_before_download` expects the limit error when the deadline passes); other failure → `"cannot resolve host: %s"`; empty → `"host did not resolve: %s"`; each address: unparseable (Go: `Zone != ""`, mirrors Python rejecting `fe80::1%lo0`) → `"host resolved to an unparseable address (%s); refused"`; `!IsGlobal(ip) || (embedded != nil && !IsGlobal(embedded))` → `"host resolves to a non-public address (%s); refused"` where `%s` is Python's `str(ip)` (compressed IPv6, `::ffff:169.254.169.254` form for mapped). Returns the FIRST address as a string. `embedded`: `Is4In6()` → `Unmap()`; in `64:ff9b::/96` → low 32 bits as IPv4. Test `::test_bounded_dns_preserves_all_address_ssrf_checks` (a public first answer with a private second still refuses), `::test_dns_worker_failure_never_reaches_connect` (never leaks resolver stderr).

`IsGlobal` must reproduce `ipaddress.is_global` of Python 3.13.2 (tables dumped from the oracle interpreter's `_constants`, wave-2 correction of the earlier hand-typed list): `is_global = not in 100.64.0.0/10 and not is_private`, where `is_private = in a private network and not in an exception`. IPv4 private networks: `0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.0.170/31, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4, 255.255.255.255/32`; exceptions `192.0.0.9/32, 192.0.0.10/32` (so `192.0.0.0/24` is the private block, not `/29`: `192.0.0.11` is NOT global); `192.88.99.0/24` IS global and multicast `224.0.0.0/4` IS global (Python quirk; keep it). IPv6 private networks: `::1/128, ::/128, ::ffff:0:0/96, 64:ff9b:1::/48, 100::/64, 2001::/23, 2001:db8::/32, 2002::/16, 3fff::/20, fc00::/7, fe80::/10`; exceptions `2001:1::1/128, 2001:1::2/128, 2001:3::/32, 2001:4:112::/48, 2001:20::/28, 2001:30::/28`; multicast `ff00::/8` IS global; `64:ff9b::/96` (NAT64) IS global at the v6 level (that is why the embedded check exists). A mapped `::ffff:a.b.c.d` answers for its embedded IPv4 (`::ffff:8.8.8.8` IS global, `::ffff:10.0.0.1` is not), so the Go caller `Unmap()`s first and the `::ffff:0:0/96` entry never decides. Do not use `netip.Addr.IsGlobalUnicast()`. Pinned by `TestIsGlobalMatchesPython313`.

`_download_capped(host, port, target, ip, dest, deadline)`: connect to `ip:port` with TLS `ServerName=host`, certificate verification on (`::test_on_time_transfer_preserves_bytes_and_tls_checks` asserts `check_hostname` and `CERT_REQUIRED`); every socket operation uses timeout `min(URL_TIMEOUT, remaining)` and the deadline is re-checked after each operation (`_download_timeout` raises `IngestLimitExceededError("download exceeded the %ds deadline")` when `remaining <= 0`). Go: `net.Dialer.DialContext` with the deadline, `tls.Client`, a `net.Conn` wrapper whose `Read`/`Write` call `SetDeadline(min(now+URLTimeout, deadline))` and re-check the deadline after the call, and `http.Transport{DialTLSContext: → that conn, DisableCompression: true, DisableKeepAlives: true}`; request `GET target` with header `User-Agent: skill-xray` and Go's default `Host` (Python lets http.client build it); `CheckRedirect` returns `http.ErrUseLastResponse`; status in `{301,302,303,307,308}` → `UnsafeInputError("URL redirected (HTTP %d); pass the final URL directly")`; other non-200 → `"URL returned HTTP %d"`; body copied in chunks with the deadline checked before and after each read and the byte cap `> INGEST_MAX_BYTES` → `IngestLimitExceededError("download exceeds %d bytes")`; an idle-timeout error must surface as a plain timeout error, not the deadline error (`::test_idle_socket_timeout_is_not_mislabeled_as_whole_download_deadline`); a read that completes after the deadline is still rejected (`::test_successful_io_returning_after_deadline_is_not_accepted`); sockets and readers are closed on every path. Tests (`test_url_deadline.py`, 27 cases) drive a fake TLS transport and a fake clock: Go needs `var now = time.Now` and a dial seam `var dialTLS func(ctx, ip, port, host) (net.Conn, error)`; the trickle cases (`body, status, header, chunk-size, chunk-body, trailer, until-eof`) become an `httptest`-free table over a `net.Pipe` server that writes the given parts with simulated delays.

`_fetch_url(url)`: `deadline = now + URL_DEADLINE`; check host (with deadline); mkdtemp; download to `<tmp>/download`; `name = PyBasename(u.Path)`, `"" | "." | ".."` → `"download"`; zip → extract into `<tmp>/extracted`, remove download, return `(extracted, tmp, strip_zip_ext(name))`; unsupported archive (by content or by `name`) → `UnsafeInputError("downloaded file is an archive skill-xray does not extract; fetch and unpack it, then scan the directory")`; else rename to `<tmp>/<name>` (skip when equal), return `(tmp, tmp, name)`. Our two errors propagate; any other error → `UnsafeInputError("failed to fetch URL: %s")`; temp dir removed on every error (`::test_deadline_failure_removes_url_temporary_directory`, `::test_dns_and_transfer_share_one_deadline`, `::test_url_download_pins_and_caps_size`, `::test_url_redirect_is_refused`).

`_check_git_remote(url)`: lowered must start with `https://` else `UnsafeInputError("git ingest supports https:// repository URLs only")`; then `_check_url_host(url)` (no deadline). `::test_git_requires_https`, `::test_git_ssrf_blocks_internal_host`.

`_git_clone(url)`: check remote; mkdtemp; env = `os.Environ()` minus `HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, http_proxy, https_proxy, all_proxy`, plus `GIT_TERMINAL_PROMPT=0, GCM_INTERACTIVE=never, GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_GLOBAL=<os.DevNull>`; argv `git -c http.followRedirects=false -c http.proxy= clone --depth 1 --single-branch --no-tags <url> <tmp>`; timeout `GIT_TIMEOUT` (`exec.CommandContext`); then `_enforce_tree_size(tmp)`. Errors: binary missing (`errors.Is(err, exec.ErrNotFound)`) → `UnsafeInputError("git is not installed")`; timeout → `IngestLimitExceededError("git clone timed out after %ds")`; non-zero exit → `UnsafeInputError("git clone failed: %s")` with stderr decoded UTF-8 (invalid bytes → U+FFFD), trimmed, first 200 code points; temp dir removed on every error. Name: `PyBasename(TrimRight(url, "/"))` with a case-insensitive `.git` suffix stripped. Tests: `::test_git_missing_binary_is_a_clear_error`, `::test_git_clone_success_from_local_repo` (real `git` over a local path with the remote check disabled via seam), `::test_git_clone_strips_uppercase_git_suffix`, `::test_git_clone_strips_proxy_env` (asserts env lacks the proxy vars and argv contains `http.proxy=`).

`_enforce_tree_size(root)`: sum `Lstat` sizes of regular entries (Python `os.walk` filenames = non-directories incl. symlinks-to-files); `> INGEST_MAX_BYTES` → `IngestLimitExceededError("cloned tree exceeds %d bytes")`; unreadable entries skipped. `::test_enforce_tree_size_caps_a_large_clone`, `::test_enforce_tree_size_allows_a_small_clone`.

`_rmtree(path)`: `os.RemoveAll`; on error, walk the tree with `Lstat`, `Chmod(mode|0700)` on every non-symlink entry (never follow a link: `::test_rmtree_does_not_follow_symlink_to_chmod_target`), retry `RemoveAll`, ignore the final error. Go's `os.Remove` already clears the Windows read-only bit, so the retry only matters for POSIX read-only directories.

Test `::test_resolved_namedtuple_is_exported` (`Resolved._fields == ("root","name","kind")`) becomes a compile-time fact.

### 2.4 `findings` consumers in `checks/__init__.py`

`run_checks`: `build_code_lane(parsed)` under recover → on panic `units = nil`, `notes = [Finding{"", "check-error", "high", "", "executable code selection failed: <name>"}]`; then each registered check under recover; a panic appends `Finding{"", "check-error", "high", "", fmt.Sprintf("check %s failed: %s", module, name)}` where `module` is the Python module string from the registry table and `name` is the recovered value's type name (crash-only, see §5.14). Taint gets `(parsed, exe, units, notes, observations)`; `nil` results are fine. Tests: `test_coverage.py::test_registered_check_failure_is_high_severity` (registry seam: `var registry` replaced), `test_capability.py::test_collector_reaches_bridge_without_new_engine_run` (observations pointer reaches the taint check).

### 2.5 `checks/coverage.py`

`check(parsed)`: `byRel` from artifacts; for each ledger entry (both phases) `phase = entry.phase or "static"`, `reason = entry.reasonCode or "unknown"`, `path = entry.path or ""`; dedupe on `(phase, reason, path)` keeping first; `phase == "parse"` → severity `low` if reason in `_LOW_PARSE` (`config_parse_error, dep_manifest_unparsed, frontmatter_parse_error, grants_unparsed_shape, markdown_parse_error, raw_html_markup, requirement_unparsed, unmodeled_content, unsupported_markup`) else `high`; static → `StaticSeverity(reason, kind, path)`: `excluded_dir` → low; `unreadable:*`/`walk_error:*` → high; `binary_content` on `kind == "asset"` → none (skip); `unreviewable_content` on an `active_asset` whose path ends in `.svg` → low (accepted: an SVG's own text and script are not read; the forensics lane sees its bytes only); else high. Finding: `Vector ""`, `Rule "analysis-incomplete"` (high) or `"coverage-note"` (low), `Path path`, `Message fmt.Sprintf("%s analysis coverage is incomplete (%s).", phase, reason)`, `Evidence {"phase": phase, "reason": reason}` (key order phase, reason). No line. Tests: `test_coverage.py::test_unsupported_executable_language_is_high`, `::test_python_parse_failure_is_not_clean`, `::test_nul_bearing_skill_manifest_is_not_clean`, `::test_raw_html_parse_gap_is_not_clean`, `::test_presentational_html_is_not_an_incomplete_analysis`, `::test_unclosed_html_code_context_is_incomplete`, `::test_parsed_html_comment_is_not_an_incomplete_analysis`, `::test_compiled_and_opaque_content_are_not_clean`, `::test_clean_supported_source_has_no_coverage_findings`, `::test_oversized_asset_emits_high_incomplete_analysis`, `::test_canonically_colliding_directories_fail_before_grant_selection`, `test_metadata.py::test_dangerous_tag_in_malformed_yaml_is_incomplete_not_sxv034` (`coverage-note` with reason `frontmatter_parse_error`), `::test_unterminated_frontmatter_is_incomplete_not_asserted_unsafe`. (The remaining `test_coverage.py` cases exercise `build_code_lane`/`scan` and belong to the code group.)

`is_inventory_note`: `vector == "" && rule == "coverage-note" && severity == "low" && evidence.phase == "static" && evidence.reason in _LOW_STATIC`.

### 2.6 `checks/metadata.py`

For each artifact, for each `YamlTag` in `unsafe_yaml_tags`: `Finding{Vector "SXV-034", Rule "unsafe-yaml-tag", Severity "critical", Path rel, Line tag.Line, Column tag.Column, Message fmt.Sprintf("frontmatter requests unsafe object construction (%s)", tag.Tag), Evidence {"tag": tag.Tag}}`; then `CapFindings`. Line/column come from the parse group's YAML tag positions; `test_metadata.py::test_unsafe_object_tag_reports_exact_parser_location` pins `(line 3, column 10)` for `payload: !!python/object/apply:os.system [echo]` on manifest line 3 and the expanded tag text (`tag:yaml.org,2002:python/...` for `!!`, verbatim for `!ruby/...`). Also `::test_known_java_gadget_tag_reports_but_custom_namespace_does_not`, `::test_python_object_prefix_lookalike_is_not_a_constructor_tag`, `::test_unsafe_tag_lookalikes_outside_yaml_tag_tokens_do_not_report` (3) — all decided by the parse group's tag extraction; metadata only maps.

### 2.7 `capability.py`

`_claims(manifest, triad)`: sources = `[(description, key_lines["description"] (may be absent → nil), prose=false)]` when `frontmatter.description` is a string; plus, when `manifest.markdown != nil`: `lines = PySplitLines(text)` (Python `str.splitlines`, §5.5); merge paragraph spans: iterate `paragraph_spans` `(start, end)`; `qualifier` = regex #6 matched against `PyStrip(lines[start-1])`; `example` = spans non-empty and regex #7 matched against `PyStrip(lines[spans[-1].start-1])`; if spans non-empty and (qualifier or example) and every line in `lines[spans[-1].end : start-1]` is blank after strip → extend the previous span's end to `end`; else append. Then for each span: `block = lines[start-1 : min(end, len(lines))]`; if `block` non-empty and `PyLower(block[0])` has prefix `"this skill "` → source `(join(block,"\n"), start, prose=true)`.
For each source `(text, line, prose)`: `evidence=[]`, `supported=true`, `position=0`; statements = split of `PyStrip(text)` at every whitespace run preceded by `.` or `!` (§3 #8 rewrite); for each statement: `start = index(text, statement, from position)`; `statement_line = line + count("\n" in text[position:start])` if prose else `line`; if prose `line = statement_line + count("\n" in statement)`; `position = start + len(statement)`; `sentence = join(PyFields(PyLower(statement)), " ")` then `TrimRight(".!")`; `clauses = split(sentence, " and ")`; if `runes(statement) > 400` or (`len(clauses) > 1` and regex #9 finds `does not|never` in sentence) → `supported=false`, break; for each clause: `TrimPrefix("this skill ")`; `negative` = regex #10 prefix match; `action` = remainder; patterns = `_DENIALS` if negative else `_CLAIMS`; `matched` = axes whose pattern full-matches `action` (iterate `AXES` order); none → `supported=false`, break; each axis → evidence `{"path": rel, "line": statement_line, "leg": "claimed", "capability": axis, "state": "denied"|"present", "text": statement}` (key order as written). After the statement loop, if supported: add states, extend `triad.evidence`. Finally per axis: exactly one state → `claimed[axis]`; more → limitation `"conflicting-<axis>-claims"`. Tests (`test_capability.py`): `::test_explicit_claims_and_uncertainty` (10), `::test_manifest_prose_claims_use_existing_markdown` (6), `::test_prose_paragraph_context_and_anchors` (17 × 3 newline styles; asserts `content.splitlines()[hit.line-1] == hit.text`), `::test_complete_claim_statements_only` (11 × prose/description), `::test_claim_excerpt_contains_late_matched_statement` (line 3 = description key line), `::test_multiline_claim_excerpt_keeps_field_anchor` (block scalar: every statement reports the key's line 3), `::test_nested_manifest_and_ungoverned_observations_do_not_leak`.

`_declarations(manifest, triad)`: `fm = frontmatter or {}`; `fields` = present keys among `allowed-tools`, `disallowed-tools` (that order); `grants = manifest.grants or []`; if any diagnostic code in `{frontmatter_parse_error, grants_unparsed_shape}`, or any field value is nil, or a string that is blank after `PyStrip`, or a list containing a string blank after strip, or any grant `!Parsed` → limitation `declaration-unparsed`, return. `allowed = DeclaredCapabilities(grants)`, `denied = DeniedCapabilities(grants)`; `uncertain = {}`; for each effective grant: tool in `ExecutionTools` → `uncertain ∪= AXES − DeclaredCapabilities([grant])`; else tool not in `NetworkTools ∪ {Read, Write, Edit, MultiEdit, Glob, Grep, LS}` → `uncertain = AXES`; non-empty → limitation `declaration-capability-unknown`; per axis: in allowed → `present`; else not uncertain and (`allowed-tools` in fm or axis in denied) → `denied`; evidence per field `{"path": rel, "leg": "declared", "field": key, "line": key_lines[key] or nil}`. Tests: `::test_grants_reuse_parser_and_explicit_states` (10), `::test_unresolved_grants_are_not_axis_denials` (8), `::test_supported_grant_precedence_stays_explicit` (5), `::test_partial_denial_does_not_deny_entire_axis`.

`build_triads(parsed, observations, coverage)`: `manifests = ManifestIndex(parsed)`; a triad per manifest keyed by rel; coverage findings with rule in `{preproc-inline-bang, preproc-fenced-bang}`, vector in `{SXV-001, SXV-002}` and a non-empty `evidence.command_sha256` become observations `{"path","line","column","capability":"execution","state":"present","analyzer":"preproc-ir","rule","vector","command_sha256"}` (line/column copied as `*int`-derived values: Python passes the raw attribute which may be None → nil); each observation: `manifest = GoverningManifest(index, path)`, key = rel or `""`; triad created on demand with `Manifest nil` for `""`; `evidence.append(deepCopy(obs))`; `capability in AXES && state == "present"` → `observed[axis] = "present"`; else limitation `obs.reason or "observation-unvalidated"`; per manifest: claims, declarations, and `text == None` → `manifest-unread`; coverage findings with empty vector that are not inventory notes: governing manifest by `finding.path` (empty path → all triads) → limitation `finding.rule`; finally `limitations = sorted(set)`, triads returned sorted by key. Tests: `::test_collects_valid_observations_without_changing_findings`, `::test_missing_manifest_and_failed_ast_stay_unknown` (key `""`, `Manifest == nil`), `::test_coverage_and_observation_evidence_are_not_mutated` (deep copy), `::test_coverage_iterator_preserves_preprocessing_and_analysis_gaps`, `::test_preprocessing_observation_uses_mechanical_evidence_not_vector_alone`, `::test_native_network_observation_and_denial_only_regression`, `::test_denial_scope_preserves_validated_observations` (6). Cases relying on `findings_from_report`/`SelectedCode` (`::test_shadowed_requests_is_not_an_observation`, `::test_observation_budget_cannot_steal_understatement_budget`, `::test_optional_validator_failure_preserves_existing_findings`) need the code group's bridge.

Line computations: `statement_line` (above); declared-leg `line` = frontmatter key line (parse group computes `lc.data[k][0] + 2`).

### 2.8 `correlate.py`

`_evidence(candidate)`: deep copy of `finding.evidence` (or `{}`); if `analyzer == "opengrep"` or `evidence.engine == "opengrep"` delete key `fingerprint`.
`_semantic_evidence(v)`: recursively drop keys in `{line, col, column, offset, end_line, end_column}` whose value `isInt`.
`_nonblank(text)`: `split("\n")` filtered by `PyStrip(line) != ""`.
`_artifact_context(a)`: nil → nil; else `{"content": text-or-null, "raw_sha256": hex-or-null, "kind": kind, "diagnostics": diagnostics}` — `diagnostics` is a list of 2-tuples `(code, detail|None)`; Canonical renders a tuple as a JSON array `["code","detail"]`/`["code",null]`, so the Go IR must give correlate `[]Diagnostic` and `Canonical` must serialise it as `[code, detail-or-null]` (detail `""` vs null must follow the parse group's representation; see cross-group needs).
`_anchor(finding, a)`: nil artifact → nil; if `raw != nil` and `isInt(offset) && offset >= 0 && isInt(length) && length > 0 && offset+length <= len(raw)` → `{"bytes": sha256hex(raw[offset:offset+length])}`; else if text present and `isInt(line)`: `lines = split(text, "\n")` (NOT splitlines), `end = evidence.end` — dict → `end.get("line", line)` (may be non-int), non-dict (incl. missing → `{}`→ line) → nil; `isInt(end) && 1 <= line <= end <= len(lines)` → `{"text": _nonblank(join(lines[line-1:end], "\n"))}`; else nil.
`source_region(a, start, end, byte_columns, lines)`: no artifact or no text → error `source unavailable`; `lines = split(text, "\n")` unless given; each position must be a dict with `isInt(line) && isInt(col) && 1 <= line <= len(lines)` else `invalid source position`; `encoded = utf8 bytes` if byte columns else runes; `1 <= col <= len(encoded)+1` else `invalid source column`; `character = RuneCount(encoded[:col-1])` (byte columns; invalid UTF-8 prefix → error, Python raises `UnicodeDecodeError ⊂ ValueError`) or `col-1`; `(first,startCol),(last,endCol)`; `positions[1] < positions[0]` → `inverted source region`; `span = lines[first-1:last]`; `span[-1] = runes(span[-1])[:endCol]` THEN `span[0] = runes(span[0])[startCol:]` (same element when first == last: apply in this order); return `join(span,"\n"), startCol+1, endCol+1`.
`_trace_location(value, parsed, role)`: `value` must be a 2-list `["CliLoc", payload]`, payload a 2-list with string second element, `payload[0]` a dict; `path = location.path` (string else artifact nil); `content = source_region(artifact, location.start, location.end)` (byte columns); `PyStrip(content) == "" || PyStrip(content) != PyStrip(payload[1])` → `trace content does not match source`; returns `{"role","path","start": copy,"end": copy,"content": payload[1]}`.
`_code_flow(evidence, parsed)`: `trace_mapping == "unvalidated"` → `([], ["trace-unvalidated"])`; no `dataflow_trace` → `([], [])`; trace must be a dict; steps = source, each `intermediate_vars` item (must be a list of ≤128 dicts with `location`, `content`) as `["CliLoc",[item.location, item.content]]`, sink; any KeyError/TypeError/ValueError → `([], ["trace-unvalidated"])`.
`_occurrence(finding)`: `(line, column, offset, length)` each `isInt ? v : -1`.
`correlate(parsed, candidates)`: deep copy; ids must be unique non-empty strings else `ValueError("candidate IDs must be unique nonempty strings")` (`test_correlate.py::test_duplicate_candidate_ids_fail_visibly`, match "candidate"); `signatures[id] = Digest(value)` where `value` = candidate minus `candidate_id` with `finding.evidence` replaced by `_evidence`; `candidate_order[id] = Canonical(value)`; stable ids: iterate ids sorted by `(signature, id)`, `stable = "candidate-<signature>-<ordinal>"` with ordinal = count of that signature so far; groups: per candidate `finding = deepcopy`; `comparable = _evidence minus {engine, engine_rule}`; `finding.evidence = comparable`; if `finding.vector != "" && len(comparable) > 0 && _anchor(finding, byRel[path]) != nil` delete `message`; group key `Canonical(finding)`; `ordered = groups sorted by (first.finding.path, _occurrence(first.finding), key)`; `context_cache[rel] = Digest(_artifact_context(a))` for every artifact; `package_context = Digest(context_cache)` (a map rel → digest); per group: sort members by `(candidate_order[id], id)`; `finding = deepcopy(group[0].finding)`, `finding.evidence = _evidence(group[0])`; `rule_id = "skill-xray/" + Quote(rule or "unknown-rule")`; `comparable` again minus engine keys; `flow, limitations = _code_flow`; `evidence.location_mapping == "unvalidated"` → append `location-unvalidated`; if flow non-empty `comparable.dataflow_trace = [{"path","role","content": _nonblank(step.content)} ...]`; `anchor = {"version": FingerprintVersion, "rule": rule_id, "path", "vector", "severity", "evidence": _semantic_evidence(comparable), "source": _anchor(finding, artifact)}`; `base = Digest(anchor)`; `ordinal = occurrences[base]++`; `fingerprint = Digest({"anchor": base, "occurrence": ordinal})`; `id = "finding-"+fingerprint`; `context = {"version": ContextVersion, "anchor": base, "package": package_context, "artifact": context_cache[path] or null, "manifest": context_cache[manifest.rel] or null}`; artifact nil or (text nil and raw nil) → `source-unavailable`; `evidence` list = distinct `_evidence(item)` keyed by Canonical, emitted in sorted key order; `provenance` list = distinct `{"analyzer": item.analyzer or "unknown", "provenance": item.provenance or "unknown", "engine_rule": item.finding.evidence.engine_rule or null}` keyed by Canonical, sorted; result fields as in §1.8; links per member with `disposition "reported"` for index 0 else `"duplicate"` and the two fixed reasons. Results sorted by `(rank(severity, 9), path, _occurrence, id)`; links sorted by `candidate_id`; `package = {"name": parsed.name, "content_digest": package_context, "digest_version": ContextVersion}`. Tests: all 47 cases of `test_correlate.py`, notably `::test_blank_lines_and_install_path_do_not_change_identity` (3 newline styles: fingerprint stable, context digest differs), `::test_repeated_identical_calls_remain_distinct_after_line_shift` (occurrence ordinal), `::test_permuted_candidates_do_not_change_correlation`, `::test_engine_fingerprints_are_not_finding_identity`, `::test_equivalent_analyzer_wording_merges_without_losing_messages`, `::test_uncertain_or_diagnostic_messages_remain_separate` (4), `::test_real_trace_is_preserved_without_stitching_findings`, `::test_malformed_or_unsupported_trace_retains_evidence_without_flow` (8), `::test_malformed_evidence_position_retains_candidate` (5), `::test_binary_evidence_identity_and_byte_occurrences`; `test_disposition.py::test_unproven_trace_content_or_utf8_boundary_is_not_a_flow` (byte column 2 inside `é`), `::test_blank_line_inside_supported_multiline_trace_keeps_fingerprint`, `::test_shell_continuation_blank_line_invalidates_policy_context`, `::test_raw_newline_semantics_invalidate_scoped_acceptance` (`raw` differs while `text` is identical).

### 2.9 `disposition.py`

`_policy_entries(policy)`: nil → empty; must be a dict with exactly keys `{version, decisions}`, `version == PolicyVersion`, `decisions` a list of ≤512 → else `ValueError("Invalid operator policy")`; each entry: dict; required keys = `{rule_id, path, fingerprint, context_digest, action, reason}` plus `effective_severity` iff `action == "demote"`; key set must equal required; every value a non-blank string; action in `{suppress, demote}`; `len(reason) <= 1024` (code points); `fingerprint`/`context_digest` full-match `[0-9a-f]{64}`; path not absolute (`HasPrefix("/")`) and no `..` segment; `effective_severity` (default `low`) in `SeverityRank` → else `ValueError("Invalid operator policy decision")`; duplicate scope tuple → `ValueError("Duplicate operator policy scope")`. Tests: `test_disposition.py::test_invalid_policy_is_rejected_not_partially_applied` (10 mutations), `::test_conflicting_duplicate_decisions_are_invalid`, `::test_scope_mismatch_never_generalizes` (4), `::test_exact_policy_preserves_posix_filename_identity` (POSIX-only: paths with `:` and `\`).
`_source_known(result, parsed)`: artifact missing or has diagnostics → false; `offset != nil` → byte-anchor validity (`raw != nil`, ints, `offset >= 0`, `length > 0`, in range); else `lines = split(text,"\n")` (empty when text nil); `isInt(line) && 1 <= line <= len(lines)`; `start = {"line": line, "col": column or 1}`; `end = evidence.end` if key present else `start`; `source_region(artifact, start, end, byteColumns = evidence.engine == "opengrep")` must not error. Tests: `::test_malformed_region_never_accepts_policy` (5), `::test_ir_unicode_column_is_not_an_opengrep_byte_column` (IR column 3 after an emoji is a character column).
`_material_ledger_entry(entry, parsed)`: `phase != "static"` → true; reason not benign and `StaticSeverity(reason, kind, path) != ""`.
`apply_dispositions(parsed, correlated, triads, policy, context_errors)`: entries; `final = deepcopy`; `contexts[key] = asdict(triad)` for sorted keys, with `evidence` sorted by `Canonical`; `final.capability_contexts = contexts`; `context_limits = [{"manifest": key, "limitations": sorted(limitations)} for sorted keys with limitations]`; `package_gap = context_errors non-empty || context_limits non-empty || any material ledger entry || any raw candidate with (vector == "" || coverage != "no-reported-gap") that is not an inventory note`; per result: `context = contexts[manifest or ""]` (nil if absent); `incomplete = package_gap || manifest == nil || context == nil || context.limitations non-empty || (!IsInventoryNote(finding) && (result.limitations non-empty || !_source_known))`; `protected = vector == "" || any provenance.provenance != "deterministic-check-output"`; defaults `("reported", "Original deterministic evidence retained", "deterministic-policy")`, `original = effective = severity`; `entry = entries[(rule_id, path, fingerprint, context_digest)]`; incomplete or protected → reason `"Incomplete context or protected operational evidence; retained"`; else entry present: suppress → `suppressed`; demote with `Rank[effective_severity] > Rank(original, 99)` → `corrected`, `effective = entry.effective_severity`; if changed → `reason = entry.reason`, `provenance = "operator-policy"`; else reason `"Policy cannot raise severity or make a no-op correction; retained"`; set the `Decision` fields; `capability_context` = context minus `evidence` (deep copy) or nil; `coverage = incomplete ? "incomplete" : "no-reported-gap"`. Links: non-duplicate → copy result's disposition/decision_reason; all → `policy_version = PolicyVersion`, `provenance = "deterministic-correlation"` if duplicate else result's decision_provenance. `final.coverage = "incomplete" if package_gap or any result incomplete else "no-reported-gap"`; `context_limitations`; `execution_successful = !(context_errors non-empty || any raw candidate with vector == "" and severity in {critical, high})`. Tests: `::test_default_retains_all_evidence_and_records_decision`, `::test_scoped_suppression_preserves_raw_result_and_audit`, `::test_demotion_is_audited_and_still_reported` (3), `::test_severity_cannot_be_promoted`, `::test_incomplete_or_unknown_context_cannot_be_suppressed` (8 gaps), `::test_operational_findings_are_never_suppressible` (5 rules), `::test_claimed_declared_and_attacker_policy_metadata_do_not_authorize`, `::test_changed_security_context_invalidates_scoped_decision`, `::test_other_artifact_change_invalidates_scoped_decision`, `::test_ledger_policy_uses_material_coverage_not_every_inventory_note` (5), `::test_scan_report_excluded_inventory_keeps_notes_without_blocking_policy`, `::test_unknown_or_parse_ledger_entries_still_block_policy` (3).
`apply_llm_review(final, decisions)`: disputed = decisions with `disposition == "llm-disputed" && status == "proposed"` by candidate id; for each link whose candidate is disputed and whose result exists and is not yet `llm_applied`: skip unless `disposition == "reported" && coverage == "no-reported-gap" && vector in LLMApplyVectors && every provenance is deterministic and not analyzer `opengrep` && Rank(severity, 99) < Rank["low"]`; then set `corrected`, `effective_severity "low"`, `decision_reason = decision.reason or "LLM review disputed the finding"`, `decision_provenance "llm-review-policy"`, `policy_version = LLMApplyVersion`, `llm_applied true`, `llm_candidate_id`; count; second pass: non-duplicate links of applied results get `corrected`, the reason, `llm-review-policy`, `LLMApplyVersion`; `final.llm_applied = applied`. Tests live in `tests/test_llm_apply.py` (output-llm group) and `::test_llm_opinion_remains_separate_and_cannot_suppress`.

### 2.10 `scan.py`

`scan`: `run_checks` (observations nil) then, if client non-nil, `_advisory(parsed, NewSession(client))` appended; `Dedupe`. `_advisory` recovers from a panic with `Finding{"", "llm-error", "low", "", "LLM adjudication pass failed (%s); deterministic findings stand"}`. Tests: `test_scan.py::test_llm_pass_never_mutates_or_reorders_deterministic_findings`, `::test_scan_isolates_a_raising_adjudicate`, `::test_scan_includes_byte_forensics_findings`.
`scan_report`: validation errors (`"Choose shadow or annotated LLM review, not both"`, `"LLM-applied demotion requires annotated LLM review"`, `"LLM review requires an explicitly supplied client"`); `llm_advisory` default `!reviewEnabled`; session when client; `raw = run_checks(..., observations=&obs)`; `gaps = {path of raw findings with vector == "" and not inventory note}`; candidates `candidate-%06d` in emission order with `analyzer = evidence.engine or "ir-check"`, `provenance "deterministic-check-output"`, `coverage = "incomplete" if "" in gaps or path in gaps else "no-reported-gap"`; `triads = build_triads(parsed, obs, raw)` under recover → `{}` + `"capability-context-error: <name>"`; review: `judge_candidates` under recover; id mismatch → error; on error append `"llm-review-error: <name>"` or `"shadow-review-error: <name>"` and synthesise one decision per candidate `{candidate_id, "reported", "error", proposal null, "Review failed; retained", policy_version REVIEW_POLICY_VERSION|POLICY_VERSION, "deterministic-policy"}`; review → `dispositions`, shadow → `shadow`; `supplemental = _advisory` when session and advisory; `usage = session.usage()` plus `advisory_enabled, judge_enabled, apply_enabled`; report candidates = candidates + `advisory-%06d` (`analyzer "llm"`, `provenance "advisory-output"`, coverage `"no-reported-gap"` if vector else `"incomplete"`); `correlation` fallback `{raw_candidates: copy, results: [], links: []}` (no `package`); `correlate` under recover → `"correlation-error: <name>"`, `correlation.errors = [that]`; else `apply_dispositions(policy)`; a policy error → `"disposition-policy-error: ValueError: <reason>"` and retry without policy; `llm_apply` → `apply_llm_review`; any other failure → `"disposition-error: <name>"`, `correlation.errors = [that]`; return `ScanReport{Dedupe(findings), candidates, triads, shadow, usage, errors, dispositions, llm_review, correlation}`. `to_dict` order: `schema_version "context-shadow-v1"`, `findings`, `raw_scope "emitted-check-results-before-reporting-deduplication"`, `raw_candidates`, `triads`, `shadow`, `llm_usage`, `context_errors`, `correlation`, and when review mode `review_mode "annotated"`, `dispositions`, `final_findings` (== findings). Tests: `test_report.py` (4), `test_disposition.py::test_successful_advisory_cannot_veto_unrelated_operator_scope` (4), `::test_report_integration_preserves_legacy_and_raw_duplicate_links`, `::test_invalid_operator_policy_retains_results_with_visible_failure` (`{"ignore": "SXV-008"}` → policy error, results retained), `::test_correlation_failure_retains_candidates_and_is_visible`, `::test_disposition_bug_is_not_mislabeled_as_correlation` (2), `test_correlation_integration.py` (7, needs opengrep).

### 2.11 `cli.py`

Since pull request 51 the CLI emits SARIF only: `scan <package> [-o|--output PATH] [--policy PATH] [--opengrep-bin PATH] [--llm] [--llm-shadow] [--llm-review] [--llm-additive] [--llm-apply]`, `system-scan [--root DIR]... [-o PATH] [--opengrep-bin PATH] [--llm] [--llm-shadow] [--llm-review] [--llm-additive] [--llm-apply]`, `install-opengrep`, `version` and `--version` (prints `skill-xray 0.1.0`); `--output` defaults to `findings.sarif.json` in the working directory, every scan analyzes, and the console shows one verdict line per package and the report path. The `--json` field lists elsewhere in this spec describe the internal finding record the SARIF results are built from.

Historical, the retired Python oracle's command line as the port reproduced it before pull request 51; nothing below is asserted by the current tests: the flags were positional `package` (optional), `--scan-known-skills`, `--analyze`, `--opengrep-bin PATH`, `--llm`, `--enrich`, `--llm-shadow`, `--llm-review`, `--llm-additive`, `--llm-apply`, `--install-opengrep`, `--json`, `--sarif PATH`, `--policy PATH`, `--version` (prints `skill-xray 0.1.0`). Usage errors print `skill-xray: error: <msg>` to stderr and exit 2 (argparse); tests assert substrings: `"scan-known-skills"` (`test_cli.py::test_cli_requires_a_target_or_the_flag`), `"no package argument"`, `"--llm requires --analyze"`, `"non-empty path"` (`--sarif ""`/`--policy ""` detected via `Flags().Changed`), plus the exact messages in `cli.py:146-203`. Order of checks is the Python order (install-opengrep standalone; scan-known exclusivity; package required; opengrep-bin/sarif/policy/enrich/review/shadow-vs-review/additive/apply; llm requires analyze; llm config: `LLMConfigError` message printed as usage error, nil config → `"--llm needs SKILLXRAY_LLM_PROVIDER and an API key in the environment"`). `--install-opengrep` → `install_opengrep()`; error → stderr `cannot install OpenGrep: %s`, exit 2; success → stdout `installed OpenGrep %s at %s`, exit 0.
Main path: `Resolve`; SARIF preflight (`Abs`+`EvalSymlinks` of report, source, policy; `os.SameFile`; policy must be outside the resolved root via `sarif.IsWithinSource`; regular file; ≤ 512 KiB (read 512*1024+1 bytes); `json.Unmarshal` into `map[string]any` (non-object incl. `null` → `"Operator policy must be an object"`; a 20,000-deep array must fail: Go's decoder limit of 10,000 nesting levels returns an error) → any failure prints `cannot prepare SARIF: %s` and exits 2 before scanning (`test_cli_sarif.py::test_cli_bad_paths_and_policy_fail_without_overwrite` (5), `::test_invalid_policy_never_starts_scan` (2), `::test_single_file_source_cannot_supply_its_own_policy`, `::test_path_resolution_runtime_error_is_reported` (2), `::test_symlink_output_is_not_accepted_from_source`, `::test_empty_reporting_paths_fail_before_ingest` (5)). `pkg = BuildPackage(root)`, `pkg.Name = r.Name`, `ledger`. Analyze: `parsed = parse.Parse(pkg)`; `enriched = enrich || reviewing || sarif != ""`; `Report` or `Scan`; SARIF write failure → stderr `cannot write SARIF: %s`, `report_failed`; JSON: `{"package", "identity", "source": argv target, "kind", "analysis": {"opengrepVersion", ["llmCoverage"]}, "findings", "ledger", ["enrichment"]}` where `findings` is popped from `enrichment` when enriched (so `enrichment` lacks `findings`: `test_report.py::test_report_cli_and_public_api`) else `ToMaps(findings)`; `llmCoverage` override when `!llm_usage.advisory_enabled`; text: `_print_findings` + LLM summary line; exit 2 if `report_failed || report.context_errors non-empty || any finding with vector == "" and severity in {critical, high}` (`test_cli_sarif.py::test_cli_success_is_not_absence_of_security_findings` (4), `test_cli.py::test_analysis_does_not_call_unsupported_code_clean`). Inventory JSON: `{"package","identity","source","kind","artifacts": [{"rel","role","kind","read","exception"}], "ledger"}`; text `_print_one`. Ingest errors → stderr `cannot ingest %s: %s` (both escaped), exit 2. `_scan_known`: discovery; per path `BuildLedger(BuildPackage(p))`; JSON list `{"package": Base(p), "path": p, "ledger"}`; text header `discovered %d skill package(s) under the known roots` and rows `  seen=%-3d analyzed=%-3d cov=%5.1f%%%s  %s` with flags `  compiled=%d`, `  identity=%d` and `~`-abbreviated path (prefix guard); discovery exceptions to stderr `skill discovery incomplete (%s): %s`; exit 2 when any. Tests: `test_cli.py::test_cli_scan_known_skills*` (4), `::test_scan_known_escapes_control_chars_in_discovered_path`.
`_display(s)`: Python `unicode_escape` (§5.17). Text formats, removed with the JSON output in pull request 51: `_print_one` (`package: %s`, `  seen=%d analyzed=%d skipped=%d coverage=%.1f%%`, `  %s %-40s %s%s`, `  SKIP  %-40s %s`), `_print_findings` (`  [%-8s] %-8s %-20s %s: %s%s`, loc `  L%d[:%d]` or `  @%d[+%d]`); `test_cli.py::test_text_finding_location_includes_column`, `::test_text_output_escapes_control_chars`, `::test_error_path_escapes_control_chars`.

## 3. Regex inventory (13 patterns; 0 need `regexp2`)

| # | Where | Pattern | RE2 verdict |
|---|---|---|---|
| 1 | `ingest._SO_VERSIONED` | `\.so(\.\d+)+$` (searched in lowered filename) | Unchanged. `$` without MULTILINE: Python also matches before a trailing `\n`, impossible in a filename. `\d`: Python matches Unicode digits, RE2 ASCII; a filename `lib.so.٣` is not worth a helper. |
| 2 | `ingest._classify_shebang` | `^#!\s*(?:\S*/env(?:\s+-S)?\s+\|\S*/)?(python(?:\d+(?:\.\d+)*)?\|bash\|sh\|zsh\|dash\|ksh\|fish\|pwsh\|powershell\|node\|deno\|bun\|ruby\|perl)(?:\s\|$)` with `re.I` | `(?i)` prefix; `$` here is end-of-first-line, fine. Replace each `\s` with `PySpace` (§5.4) and `\S` with `[^PySpace]` so a NBSP after `#!` behaves as in Python; `\d` as ASCII (accepted). |
| 3 | `resolve._extract_zip` | `^[A-Za-z]:` | Unchanged. |
| 4 | `capability._CLAIMS["execution"]` | `(?:runs?\|executes?) (?:shell commands\|commands\|scripts)\b` via `fullmatch` | `\A(?:...)\z` wrapper; the trailing `\b` is at end-of-input under fullmatch, identical. |
| 5 | `capability._CLAIMS["network"]` | `(?:uploads? (?:diagnostic logs\|logs\|data)\|sends? (?:diagnostic logs\|logs\|data) (?:over the network\|via http)\|(?:access(?:es)?\|uses?) the network\|makes? (?:http\|network) requests)\b` via `fullmatch` | Same as #4. |
| 6 | `capability` qualifier | `(?i)^(?:this (?:is\|was)\b\|that\b\|these\b\|those\b\|but\b\|however\b\|unless\b\|except\b\|only\b\|not\b\|never\b\|does not\b)` via `match` | Python `\b` is Unicode-aware (`thaté` has no boundary; RE2 sees one). Rewrite: `(?i)^(?:this (?:is\|was)\|that\|these\|those\|but\|however\|unless\|except\|only\|not\|never\|does not)(?:[^\p{L}\p{N}_]\|$)` — the boundary becomes an explicit non-word rune or end; only a bool is consumed. |
| 7 | `capability` example | `(?i)^(?:(?:for )?example\b\|the following example\b)` via `match` | Same rewrite as #6. |
| 8 | `capability._claims` | `re.split(r"(?<=[.!])\s+", text)` | LOOKBEHIND (the one in this group). Rewrite without regexp2: find all matches of `[.!]PySpace+`; each match splits the text at `match.start+1` (statement ends after the punctuation) and the next statement starts at `match.end`. Identical output incl. a trailing empty piece when the text ends with `.` + spaces (text is stripped first, so it cannot). |
| 9 | `capability._claims` | `\b(?:does not\|never)\b` via `search` on the lowered, space-collapsed sentence | Unicode `\b` again. Rewrite `(?:^\|[^\p{L}\p{N}_])(?:does not\|never)(?:$\|[^\p{L}\p{N}_])`. |
| 10 | `capability._claims` | `^(?:does not\|never)\s+` via `match` on a clause | Unchanged; after whitespace collapsing the only whitespace is ASCII space. `match.end()` is needed → `FindStringIndex`. |
| 11 | `capability._DENIALS["execution"]` | `(?:runs?\|executes?) commands` via `fullmatch` | `\A(?:...)\z`. |
| 12 | `capability._DENIALS["network"]` | `(?:access(?:es)?\|uses?) the network` via `fullmatch` | `\A(?:...)\z`. |
| 13 | `disposition._policy_entries` | `[0-9a-f]{64}` via `fullmatch` | `\A[0-9a-f]{64}\z`. |

Counts: 13 compiled patterns; 1 lookbehind (rewritten as RE2 plus a split loop); 0 lookahead; 0 backreferences; 0 conditionals; 0 `regexp2`. Case-insensitivity (`re.I`, `(?i)`) appears in #2, #6, #7: both engines use simple Unicode case folding (Kelvin sign and long s fold to k/s in both), no divergence. The `\s` divergence (#2, #8) matters for markdown prose, where NBSP (U+00A0) is common in pasted text; #8 decides statement segmentation, so it must use `PySpace`.

## 4. Third-party and stdlib replacements

None of markdown_it, tree_sitter, ruamel, jsonschema, packaging, tomllib, html, shlex, posixpath, bisect, heapq, zlib, secrets is used in this group. What is used, and its replacement (stdlib first):

| Python | Where | Go |
|---|---|---|
| `unicodedata.normalize("NFC")` | ingest (relpath, portable name), resolve (zip member) | `golang.org/x/text/unicode/norm` `norm.NFC.String` (already in go.mod). |
| `str.casefold()` | ingest, resolve | `golang.org/x/text/cases` `cases.Fold().String` (full folding: ß→ss, ﬁ→fi, İ→i̇, ς→σ; verified Python outputs in §5.2). Same module, no new dependency. |
| `codecs` cp1252 | ingest `_decode` | `golang.org/x/text/encoding/charmap` `Windows1252` + explicit rejection of `0x81 0x8D 0x8F 0x90 0x9D` (x/text maps them to U+FFFD, Python raises). |
| `ipaddress` | resolve | `net/netip` with the explicit prefix tables of §2.3 (`IsGlobal`); `Is4In6/Unmap`, `As16` for NAT64. |
| `socket.getaddrinfo` | resolve | `net.Resolver.LookupIPAddr(ctx)`; zoned results refused. |
| `http.client`, `ssl` | resolve | `net/http` + `crypto/tls` + a deadline-enforcing `net.Conn` wrapper (§2.3); `DisableCompression`, `ErrUseLastResponse`. |
| `zipfile` | resolve | `archive/zip` (`OpenReader`; tolerate `ErrInsecurePath`; `is_dir` = trailing `/`; `ExternalAttrs>>16`). |
| `tarfile.is_tarfile` | resolve | `archive/tar` + `compress/gzip` + `compress/bzip2`; xz by magic only (`// ponytail:`). |
| `subprocess` | resolve (git) | `os/exec` (`CommandContext`, `ExitError`, `ErrNotFound`). |
| `tempfile.mkdtemp(prefix="skillxray-")` | resolve | `os.MkdirTemp("", "skillxray-")`. |
| `shutil.rmtree(onexc=...)` | resolve | `os.RemoveAll` + one chmod-and-retry pass (§2.3). |
| `os.scandir`, `os.walk`, `os.lstat/fstat`, `os.open(O_NOFOLLOW|O_NONBLOCK)`, `os.readlink`, `os.path.isjunction` | ingest | `(*os.File).ReadDir(n)`, `filepath.WalkDir`, `os.Lstat`/`f.Stat`, `os.OpenFile` with build-tagged flags, `os.Readlink`, Windows attribute check (`ingest_windows.go`). |
| `os.path.realpath/abspath/relpath/basename/splitext/normpath` | ingest, resolve, cli | `filepath.EvalSymlinks` (fallback `Abs`), `filepath.Abs`, `filepath.Rel`, `filepath.Base` for filesystem names, and `pytext.PySplitExt`, `pytext.PyBasename` (URL paths), `path.Clean` for zip names (§5). |
| `hashlib.sha256` | correlate | `crypto/sha256` + `encoding/hex`. |
| `json.dumps(sort_keys, ensure_ascii, separators, allow_nan=False)` | correlate `canonical` | Hand-written `Canonical` (§5.19); `encoding/json` cannot be configured to match. |
| `json.dumps(indent=2)` / `json.loads` | cli | `encoding/json` `MarshalIndent("", "  ")` over ordered structs / `map[string]any` (parity compares parsed JSON; §7); `Unmarshal` for the policy. |
| `urllib.parse.urlparse` | resolve | `net/url` + manual port range check. |
| `urllib.parse.quote(s, safe="-._")` | correlate | `pytext.Quote` (§5.18). |
| `argparse` | cli | `github.com/spf13/cobra` (already chosen); usage errors formatted `skill-xray: error: %s`, exit 2. |
| `dataclasses.asdict`, `copy.deepcopy` | scan, capability, correlate, disposition | struct→map via `MarshalJSON` order; `deepCopy(any)` for JSON-like values (one ~20-line helper in `correlate`). |
| `collections.Counter/defaultdict/namedtuple` | ingest, correlate, resolve | maps and structs. |
| `time.monotonic` | resolve | `time.Now()` (monotonic reading) behind `var now`. |
| `pathlib.Path.resolve/samefile/is_file` | cli | `filepath.Abs`+`EvalSymlinks`, `os.SameFile`, `Stat().Mode().IsRegular()`. |

New dependencies for this group: **none**. Everything is stdlib or already in `go.mod` (`x/text`, `cobra`, `testify`). `dlclark/regexp2` is not needed by core.

## 5. Python semantics that do not translate (each named use)

1. **Unicode version.** Python 3.13.2 uses Unicode 15.1; Go 1.24 `unicode` and `x/text` tables are 15.0. NFC normalisation (3 uses) and case folding (2 uses) are unaffected: 15.1 added only CJK ideographs with no decompositions or case mappings. No action.
2. **`str.casefold()`** (`ingest._portable_name`, `resolve._extract_zip`): full folding. Verified: `Straße→strasse`, `ﬁle→file`, `İstanbul→i̇stanbul`, `ẞ→ss`, `ς→σ`. `strings.ToLower` gives none of these; use `cases.Fold()`. Collision detection between `Straße.md` and `STRASSE.md` depends on it.
3. **`str.lower()`** (`ingest._classify` filename/ext, `_classify_shebang` name, `resolve` scheme/suffix checks, `capability` sentence and `"this skill "` prefix, discovery `skill.md` match): `strings.ToLower("İ")` is `"i"`, Python gives `"i̇"` (two code points). `SKİLL.md` must NOT classify as the manifest (Python: `ski̇ll.md`). `pytext.PyLower(s)` = `strings.ToLower(strings.ReplaceAll(s, "\u0130", "i\u0307"))`. Kelvin sign `K` lowers to `k` in both, so `SKILL.md` with U+212A IS the manifest in both. Final sigma differs (`Σ`→`ς` in Python at word end, `σ` in Go) but never reaches an ASCII comparison.
4. **`str.split()` / `str.strip()` whitespace** (capability `statement.lower().split()`, `part.strip()`, `text.strip()`, `line.strip()`; correlate `_nonblank`, `content.strip()`; disposition `value.strip()`; resolve `target.strip()`, stderr `.strip()`): Python's set (verified) is `\t \n \v \f \r \x1c \x1d \x1e \x1f space \x85 \xa0 \u1680 \u2000-\u200a \u2028 \u2029 \u202f \u205f \u3000`; Go `unicode.IsSpace` lacks `\x1c-\x1f`. Provide `pytext.IsSpace(r rune) bool`, `Fields`, `Strip`, `TrimRight(s, cutset)` uses (`rstrip(" .")`, `rstrip(".!")`) are plain `strings.TrimRight`. Regex class constant `PySpace = "[\\t\\n\\v\\f\\r \\x{1c}-\\x{1f}\\x{85}\\p{Z}]"` (`\p{Z}` = Zs+Zl+Zp covers exactly the rest).
5. **`str.splitlines()`** (capability `_claims` on manifest text): splits on `\n \r \r\n \v \f \x1c \x1d \x1e \x85 \u2028 \u2029` and drops a trailing empty piece. Text is already CR-normalised by the IR, but `\f`, `\v`, `\x1c-\x1e`, `\x85`, `\u2028`, `\u2029` still split in Python and would shift every prose claim line; `pytext.SplitLines` reproduces it. (correlate/disposition use `split("\n")`, not splitlines — keep the distinction.)
6. **dict ordering** reaching output: `Finding.to_dict`, ledger, CLI JSON documents, `ScanReport.to_dict`, `asdict(triad)`, `result.update`/`link.update` key appends, per-check `evidence` insertion order. Go structs keep declared order; Go maps sort keys. The parity harness must compare parsed JSON (order-insensitive objects); when text identity is wanted, Go is deterministic on its own.
7. **`sorted` stability and keys**: `sort_findings` (stable, 9-part key with tuple-vs-empty tail), `dedupe`, `cap_findings` suppression order (first-seen), `build_ledger` (`sorted(rels)`, exceptions by `(path, reasonCode)` stable), `build_package` (`sorted(kept)`, `sorted(filenames)`), `discover` (`sorted(found)` by realpath, `reversed(sorted(children))` by path), `correlate` (four sorts, all with unique tie-breakers), `apply_dispositions` (`sorted(triads.items())`, `evidence.sort(key=canonical)`, `sorted(limitations)`), `capability` (`sorted(set(limitations))`, sorted triads). Python `str` ordering is code-point order, which equals Go's bytewise UTF-8 comparison (verified with `\uffff` vs `\U0001f600`). Use `sort.SliceStable` wherever Python relies on stability (findings) and `sort.Slice` elsewhere.
8. **Float formatting**: `coveragePercent = round(x, 2)` — Python rounds the exact binary value half-to-even (verified `round(2.675,2)=2.67`, `round(0.125,2)=0.12`); Go: `strconv.ParseFloat(strconv.FormatFloat(x,'f',2,64),64)` (same algorithm), never `math.Round(x*100)/100`. JSON repr: Python prints `100.0`, `66.67`; Go `json.Marshal(100.0)` prints `100` → `Percent.MarshalJSON` uses `FormatFloat(v,'f',-1,64)` plus `".0"` when integral. `%.1f`/`%5.1f` in text output: identical rounding in both (`0.05→0.1`, `0.25→0.2`).
9. **`%`-formatted messages that reach output** (port verbatim): `"%d more %s findings in %s were suppressed (cap %d per file)"`; `"%s analysis coverage is incomplete (%s)."`; `"frontmatter requests unsafe object construction (%s)"`; `"check %s failed: %s"`; `"executable code selection failed: %s"`; `"LLM adjudication pass failed (%s); deterministic findings stand"`; `"capability-context-error: %s"`, `"%s-review-error: %s"`, `"correlation-error: %s"`, `"disposition-policy-error: %s"`, `"disposition-error: %s"`; `"candidate-%06d"`, `"advisory-%06d"`, `"candidate-%s-%d"`; `"(more than %d files)"`, `"(more than %d directories)"`, `"(more than %d discovery %s)"`; `"walk_error:%s"`, `"unreadable:%s"`; every `UnsafeInputError`/`IngestLimitExceededError` text in §2.3 (with `%d` = 104857600, 10000, 120, 120); CLI formats in §2.11. `%s` of an int/str is `%v`; `%-8s`/`%-40s` pad by code points in both languages (all inputs are ASCII after `_display`).
10. **`shlex.split`, `posixpath.normpath`, `html.unescape`, `bisect`, `heapq`**: not used in this group. `os.path.normpath` is used once (`_zip_member_extracts`) → `path.Clean` on the backslash-normalised name (verified `""→"."`, `"a/.."→"."`, `"./"→"."`).
11. **`type(x) is int`** (findings `_engine_occurrence`; correlate `_semantic_evidence`, `_anchor`, `source_region`, `_occurrence`; disposition `_source_known`): `bool` is excluded (`type(True) is int` is False). Go `isInt` matches only `int`. Requires the evidence contract in §1.1 (positions are `int`, never `float64`).
12. **`deepcopy`** (scan, capability, correlate, disposition): the tests mutate returned documents and assert the originals are untouched (`test_report.py::test_report_preserves_raw_and_detaches_evidence`, `test_capability.py::test_coverage_and_observation_evidence_are_not_mutated`). One JSON-value deep-copy helper.
13. **`type(exc).__name__` in reason codes and messages**: `unreadable:<OSError subclass>` and `walk_error:<subclass>` reach the ledger JSON and the coverage findings. `pytext.OSErrorName(err)`: `errors.Is(err, fs.ErrPermission)`→`PermissionError`; `fs.ErrNotExist`→`FileNotFoundError`; `fs.ErrExist`→`FileExistsError`; `syscall.ENOTDIR`→`NotADirectoryError`; `EISDIR`→`IsADirectoryError`; `ETIMEDOUT`→`TimeoutError`; `EINTR`→`InterruptedError`; `EAGAIN/EWOULDBLOCK/EINPROGRESS/EALREADY`→`BlockingIOError`; `EPIPE/ESHUTDOWN`→`BrokenPipeError`; `ECONNREFUSED/ECONNRESET/ECONNABORTED`→the matching `Connection*Error`; anything else (incl. `ELOOP` from `O_NOFOLLOW`) → `OSError`. On Windows Go already maps `ERROR_ACCESS_DENIED`/`ERROR_FILE_NOT_FOUND`/`ERROR_PATH_NOT_FOUND` to `fs.ErrPermission`/`fs.ErrNotExist`. Tests pin `walk_error:PermissionError`.
14. **Crash-only exception names** (`check <module> failed: <Name>`, `capability-context-error: <Name>`, `correlation-error`, `disposition-error`, `llm-review-error`, `LLM adjudication pass failed (<Name>)`): Go recovers a panic and has no Python class name. Decision: use the recovered value's Go type name (`runtime.Error` → `RuntimeError`-like names are not attempted). These strings appear only when a check is broken; the parity harness treats any `check-error`/`*-error` as a scan-level defect to fix, not a string to match. `disposition-policy-error: ValueError: <reason>` is deterministic and must be emitted literally.
15. **`os.path.splitext`** (`_classify`): leading dots of the basename are not an extension (verified: `.env→""`, `.credentials.json→.json`, `..foo→""`, `a.→"."`, `.a.b→.b`). `filepath.Ext(".env")` is `".env"`; write `pytext.SplitExt`.
16. **`os.path.basename` of a URL path** (`_fetch_url`): `""` for `""`, `"/"`, `"/a/"` (verified); `path.Base` returns `"a"` for `/a/`. `pytext.Basename(s)` = text after the last `/`.
17. **`str.encode("unicode_escape")`** (`cli._display`): `\\`→`\\\\`; `\t \n \r` short escapes; other code points `< 0x20` and `0x7f-0xff` → `\xNN`; `0x100-0xffff` → `\uXXXX`; above → `\UXXXXXXXX`; hex lowercase; quotes untouched (verified: `ev\x1bil` → `ev\\x1bil`, `é`→`\\xe9`, `\u2028`→`\\u2028`, emoji → `\\U0001f600`). Lone surrogates cannot exist in Go strings; an invalid UTF-8 byte in a filename is escaped as `\xNN` (text output only; not a parity field).
18. **`urllib.parse.quote(s, safe="-._")`** (`correlate` rule id): percent-encode every UTF-8 byte outside `[A-Za-z0-9_.~-]` with uppercase hex (verified: `~` stays, `+`→`%2B`, `/`→`%2F`, `é`→`%C3%A9`). `url.PathEscape` keeps `!$&'()*+,;=:@` and is wrong here.
19. **`json.dumps` canonical form** (`correlate.canonical`; feeds every fingerprint, stable id and context digest): keys sorted by code point; separators `,` and `:` with no spaces; strings: `"` `\\` escaped, `\b \f \n \r \t` short escapes, other `< 0x20` and `0x7f` and every non-ASCII code point as `\uXXXX` lowercase hex (surrogate pairs above U+FFFF; verified `\u007f`, `\u00e9`, `\ud83d\ude00`), `/ < > & '` unescaped; `int` as decimal; `bool` `true/false`; `None` `null`; floats never occur (§1.1); Python tuples (diagnostics) as arrays. Go's `encoding/json` escapes `<>&` and U+2028/9 but not other non-ASCII, and prints `\u0008` for `\b`, so `Canonical` is hand-written (~60 lines) with a golden test generated from the Python oracle (R2).
20. **`round`/`%d`**: see 8; `%d` of Python ints is `%d`.
21. **`ipaddress.is_global`**: Python 3.13.2 tables in §2.3 (verified), including the multicast quirk.
22. **`os.path.realpath`** (`install_identity`, discovery dedupe): resolves symlinks and, on Windows, junctions and on-disk case; `filepath.EvalSymlinks` does the same; a non-existent path falls back to `Abs` (Python `strict=False`).
23. **`bytes.__contains__`**, **`str[:256]`/`[:200]`/`len(...) > 400`**: code-point slicing (`[]rune`), not bytes.
24. **`str.index`/`str.count` offsets** in `_claims`: code-point offsets in Python, byte offsets in Go; only differences and newline counts are used, so byte offsets are fine as long as `position`, `start` and `len(statement)` are all in bytes.
25. **`PurePosixPath.is_absolute`**: `HasPrefix(path, "/")`.
26. **`zipfile.ZipInfo.is_dir`**: trailing `/` only (Go's `FileInfo().IsDir()` also inspects mode bits; do not use it).
27. **`os.open` flags and `fstat` identity**: `os.SameFile(expected, st)` replaces the `(st_dev, st_ino)` compare on both platforms (Python populates `st_ino` on Windows too).
28. **`os.DirEntry.is_dir(follow_symlinks=False)`** → `DirEntry.Type().IsDir()`; Windows junction → see §2.2 `_is_reparse`.
29. **`socket` timeouts vs deadline**: two different error outcomes (§2.3).
30. **argparse exit semantics**: `SystemExit(2)` with `usage:` + `skill-xray: error: msg`; Go prints the same error line (usage text optional) and returns 2.

## 6. Test port plan

Fixtures: core reads no files under `tests/`; every package is built inline by `conftest.make_package` (strings written as UTF-8 with `newline=""`, bytes written raw). Go: `testutil.MakePackage(t, files map[string]string) string` writes into `t.TempDir()` exactly those bytes. The `test_postdetect_microcorpus._CASES` six packages (used by `test_correlation_integration`) are also inline Python literals; they become a Go table in the scan test (they are test inputs, not fixture files). Parity goldens generated from the Python oracle (canonical JSON vectors, microcorpus digests) go under `port-to-go/testdata/core/` and are read by table tests — never inlined.

| pytest file | expanded cases | core-owned | Go test file | Notes |
|---|---|---|---|---|
| `tests/test_ingest.py` | 62 | 62 | `internal/ingest/ingest_test.go` | `t.Skip` for symlink/junction/POSIX-perm cases as pytest does; limits lowered via package vars; scandir fakes replaced by real wide directories or the `openDir`/`isReparse` seams. |
| `tests/test_resolve.py` | 52 | 52 | `internal/ingest/resolve_test.go` | zip fixtures built with `archive/zip` in the test (mirrors `_zip`); network cases use seams `checkURLHost`, `checkGitRemote`, `dialTLS`, `runGit`, `lookupIP`. |
| `tests/test_url_deadline.py` | 27 | 27 | `internal/ingest/deadline_test.go` | fake clock (`var now`) + scripted `net.Conn` over `net.Pipe` for the 7 trickle stages, 4 setup stages, 2 on-time, 3 late-success, and the DNS cases. |
| `tests/test_findings.py` | 4 | 4 | `internal/findings/findings_test.go` | registry test scans Go sources for `SXV-\d{3}` literals. |
| `tests/test_scan.py` | 3 | 3 | `internal/scan/scan_test.go` | `runChecks`/`adjudicate` seams; fake client type implementing `llm.Completer`. |
| `tests/test_report.py` | 4 | 4 | `internal/scan/report_test.go` | |
| `tests/test_cli.py` | 16 | 16 | `cmd/skill-xray/main_test.go` | `run(argv, &stdout, &stderr)`; `KnownSkillRoots` var. |
| `tests/test_cli_analyze.py` | 7 | 7 | `cmd/skill-xray/main_test.go` | 4 cases need `llm.Config`/`FromEnv` seam and opengrep for SXV-008 (`t.Skip` when `opengrep` is absent, as the code group's tests will). |
| `tests/test_cli_sarif.py` | 28 | 28 (shared) | `cmd/skill-xray/sarif_test.go` | needs output-llm's `sarif.Build/Write/Validate`; port after that group lands. |
| `tests/test_coverage.py` | 21 | 12 | `internal/checks/coverage_test.go` | 9 cases (`test_unsupported_shell_dialects_are_not_silent` ×3, `test_unparseable_python_fence_is_not_clean`, `test_unparsed_allowed_tools_does_not_affect_fence_analysis` ×3, `test_non_execution_grant_cannot_suppress_fences`, `test_unparsed_allowed_tools_cannot_hide_executable_fence`) test `build_code_lane`/opengrep and belong to code. |
| `tests/test_metadata.py` | 80 | 14 | `internal/checks/metadata_test.go` | the 14 SXV-034 cases; the 66 SXV-033 cases test `opengrep_bridge`+`grants` (code group). |
| `tests/test_capability.py` | 133 | 118 | `internal/capability/capability_test.go` | 15 cases (`findings_from_report`/`SelectedCode`/`opengrep_check`) depend on the code group's bridge and run once it exists. |
| `tests/test_correlate.py` | 47 | 47 | `internal/correlate/correlate_test.go` | `SOURCE`, `candidate()`, `loc()`, `package()` helpers → `testutil`. |
| `tests/test_correlation_integration.py` | 7 | 7 | `internal/scan/integration_test.go` | requires opengrep binary; `t.Skip` otherwise. |
| `tests/test_disposition.py` | 72 | 72 | `internal/correlate/disposition_test.go` | POSIX-only filename cases skipped on Windows as in pytest. |
| **Total** | **563** | **473** | | 90 cases in these files are owned by other groups. |

Other files touching core symbols but owned elsewhere: `test_coverage_adapters.py` (benchmark adapters; not ported, but its decode table is reused for `Decode`), `test_msb_*.py` (benchmark scoring; not ported), `test_llm_*.py`, `test_sarif*.py`, `test_opengrep_*.py`, `test_batch3/postdetect_microcorpus.py`, `test_schema_packaging.py`.

Style: `package <name>` tests (not `_test` external packages) so seams and unexported helpers are reachable, `testify/assert` and `require`, `t.Run` subtests for every `parametrize` row with the Python ids as names, `t.TempDir()`, `t.Skip` where pytest skips. Python monkeypatching of module globals maps to package-level `var`s (limits, `KnownSkillRoots`, function seams) reset with `t.Cleanup`.

## 7. Parity hooks

CLI `--json` fields this group determines (so `tools/parity` can attribute a diff):

| Field | Owner in core | Diff means |
|---|---|---|
| `package`, `source`, `kind` | resolve/cli | target resolution or name stripping (`.zip`/`.git` suffix, basename rules). |
| `identity` | ingest `InstallIdentity` | realpath/drive-letter/trailing-slash normalisation. |
| `artifacts[*].rel/role/kind/read/exception` | ingest | classification, NFC, decode, caps, skip reasons. |
| `ledger.*` (all 14 keys) | ingest `BuildLedger` | counts/denominator/rounding; `exceptions[*]` incl. `walk_error:<Name>` strings. |
| `analysis.opengrepVersion` | code group constant | not core. |
| `analysis.llmCoverage` | output-llm | not core (core only applies the `advisory_enabled=false` override). |
| `findings[*]` membership | the emitting check's group | core owns only `check-error`, `analysis-incomplete`, `coverage-note` (coverage), `unsafe-yaml-tag` mapping (metadata), `findings-capped`, `llm-error`. |
| `findings[*]` order, duplicates, cap suppression, `title/cwe/tier` | findings | `Sort`/`Dedupe`/`CapFindings`/registry. |
| `findings[*].line/column/offset/length` presence | findings `ToMap` | nil-vs-value handling. |
| exit code | cli | the three exit-2 conditions. |
| `enrichment.schema_version/raw_scope` | scan | constants. |
| `enrichment.raw_candidates[*].candidate_id` | scan | emission order of checks (registry order + each check's intra-order: cross-group). |
| `enrichment.raw_candidates[*].analyzer/provenance/coverage` | scan | `gaps` logic. |
| `enrichment.triads` | capability | claims/declarations/observations/limitations. |
| `enrichment.shadow/dispositions/llm_usage` | output-llm (+ scan fallback decisions) | |
| `enrichment.context_errors` | scan | recovery paths. |
| `enrichment.correlation.results[*].id/fingerprint/context_digest/rule_id/manifest/candidate_ids/provenance/evidence/code_flow/limitations` | correlate | `Canonical`, anchors, `SourceRegion`; a fingerprint diff with identical findings points at `Canonical` or at IR text/raw (parse group). |
| `enrichment.correlation.links[*]` | correlate | stable ids, duplicate flags. |
| `enrichment.correlation.package.content_digest` | correlate | artifact context (`content`, `raw_sha256`, `kind`, `diagnostics`) — a diff here with identical fingerprints is a parse-group text/diagnostics diff. |
| `enrichment.correlation.results[*].disposition/decision_*/original_severity/effective_severity/capability_context/coverage`, `links[*].policy_version/provenance`, `capability_contexts`, `coverage`, `context_limitations`, `execution_successful`, `llm_applied` | disposition | policy scope matching, `_source_known`, package gap. |

SARIF (output-llm maps, core supplies): `results[*].fingerprints`/`partialFingerprints` (correlate fingerprint), `properties.disposition/coverage/governingManifest`, `suppressions` (disposition), `invocations[0].executionSuccessful` (disposition `execution_successful`), `run.properties.package.contentDigest/digestVersion`, `capabilityContexts`, `coverage`, `contextLimitations`, `contextErrors` (scan).

Harness recommendation: compare parsed JSON (object key order and `100` vs `100.0` are not diffs); compare `findings` as ordered lists (order is a core contract); compare `raw_candidates` by `candidate_id` (an ordering diff is a check-emission-order diff in the owning group).

## 8. Risks and open questions (each with the decision)

- **R1. Go toolchain**: `port-to-go/go.mod` says `go 1.26.0`; the machine has 1.24.1 and mcp-xray pins 1.25.5. With `GOTOOLCHAIN=auto` Go will try to download 1.26 on every build. Decision: set `go 1.24` in `go.mod` (nothing in core needs newer; run `go mod tidy` — if a chosen dependency demands higher, install that toolchain explicitly rather than rely on auto-download). All entries in `go.mod` are currently `// indirect`; tidy fixes that once code imports them.
- **R2. `Canonical` correctness is the whole fingerprint story.** Decision: hand-write it and gate it with a golden file `testdata/core/canonical.jsonl` produced once by a Python script (`skill_xray.correlate.canonical` over ~50 adversarial values: nested maps, control chars, DEL, non-BMP, `<>&`, bools vs ints, tuples, nulls, sorted-key order with non-ASCII keys) plus the six microcorpus `content_digest`/fingerprint values. The script lives under `port-to-go/tools/` and reads `skill-xray/` without modifying it.
- **R3. Windows junctions** (Go ≥1.23 reports `ModeIrregular`). Decision: build-tagged `isReparse` reading `Win32FileAttributeData`; a junction must land in `dirnames` and be pruned as `reparse_point`. Without this the Windows test `test_junction_directory_does_not_escape_the_package` reports `not_regular_file`.
- **R4. `OSError` subclass names in reason codes.** Decision: `pytext.OSErrorName` mapping (§5.13); the crash-only names are an accepted divergence documented in the parity harness.
- **R5. Cross-group value contracts** (evidence ints are `int`; every serialised slice non-nil; `Text`/`Raw` None-ness preserved in the IR; `Diagnostic.Detail` null-ness in `Canonical`; observation dict keys; `llm.Decision` shape; `ManifestIndex/GoverningManifest` in `internal/parse`; `grants` exports). Decision: record them in the parse/code/output-llm specs' "cross-group needs" and add a `correlate` test that digests a fixture IR built by hand to lock the `_artifact_context` shape.
- **R6. Check emission order defines `candidate_id`s.** Decision: every group ports its check's iteration order literally (artifact order = ingest order, then the check's own loops); the harness compares raw candidates by id so a diff is attributed to the emitting group.
- **R7. Python `\s`/`\b` Unicode semantics in capability regexes** (NBSP in prose changes statement segmentation). Decision: `PySpace` class and explicit non-word-rune boundaries (§3 #6-#9); covered by a table test with NBSP and `é`-adjacent words generated from the Python oracle.
- **R8. `str.splitlines` in `_claims`**: `\f`, `\x1c-\x1e`, `\x85`, `\u2028/9` shift prose lines. Decision: `pytext.SplitLines`; the parity corpus will surface any remaining case.
- **R9. Archive sniffing**: no stdlib xz. Decision: refuse on xz magic (fail closed, `// ponytail:` note). Go's `archive/zip` may reject a malformed zip Python accepts (or vice versa); both paths fail closed (single-file ingest or `UnsafeInputError`), and the parity corpus contains no archives; accepted.
- **R10. Network adapters are not parity-testable and Python's tests are transport-level fakes.** Decision: port behaviour with seams (`now`, `dialTLS`, `lookupIP`, `runGit`) and mirror each pytest case; drop the DNS subprocess worker (Go's resolver honours `ctx`). Go's `net/http` adds `Accept-Encoding: gzip` and follows redirects unless told otherwise — `DisableCompression: true` and `ErrUseLastResponse` are mandatory or the byte cap and the redirect refusal silently change meaning.
- **R11. `url.Parse` accepts out-of-range ports.** Decision: explicit range check → `malformed URL`.
- **R12. Bounded directory enumeration.** Decision: `(*os.File).ReadDir(512)` batches, never `os.ReadDir`; sorting happens afterwards exactly where Python sorts.
- **R13. `Finding` position fields.** Decision: `*int` (§1.1), because offset 0 is emitted and the zero value must mean absent.
- **R14. Typed correlation vs generic maps.** Decision: typed `Result/Link/Correlation` with embedded pointer structs for the decision phase, and `map[string]any` only for the finding document and evidence, because Python treats those two as JSON while treating results/links as records.
- **R15. cobra vs argparse text.** Decision: keep every error message string; print `skill-xray: error: <msg>` and exit 2; do not print cobra's default usage on error (`SilenceUsage`), since the tests only assert message substrings and exit codes.
- **R16. Coverage percent float representation** (`100.0` vs `100`). Decision: `Percent` type with Python-repr marshalling; harness compares numerically anyway.
- **R17. `_display` cannot represent lone surrogates.** Decision: invalid UTF-8 bytes escape as `\xNN`; text output is out of parity scope.
- **R18. `checks.Run` module names** (`skill_xray.checks.<module>`) in `check-error` messages must stay the Python strings even though the Go files are named differently; keep a name table beside the function table.

## Structured summary inputs

- Python lines: 2,816 across 12 files.
- Function definitions: 92 (`def` count: ingest 21, resolve 25, findings 9, scan 5, cli 6, checks 5, capability 4, correlate 12, disposition 5) and 10 classes. Names imported by other modules or exercised directly by tests: 65 (findings 9, ingest 14, resolve 4 + 10 tested internals, scan 3, cli 5, checks 5, capability 3, correlate 6, disposition 5, `__version__`).
- Regexes: 13; needing `regexp2`: 0 (1 lookbehind rewritten as a split loop).
- Tests to port: 473 expanded pytest cases owned by core (563 in the covering files).
- New dependencies: none (x/text, cobra, testify already in `go.mod`).
