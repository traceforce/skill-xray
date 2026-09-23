// Package ingest turns a scan target into a file inventory and a coverage ledger.
// resolve.go materialises the target as a local directory; this file walks it,
// decodes each text file, classifies every file by name and extension only, and
// records every file it does not read. Nothing is executed and nothing outside
// the package root is opened.
package ingest

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"

	"github.com/traceforce/skill-xray/internal/pytext"
)

// Artifact is one inventoried file. Text is valid only when Exception is "";
// Raw is nil when no bounded read succeeded (a read empty file is []byte{}).
type Artifact struct {
	Rel       string `json:"rel"`
	Role      string `json:"role"`
	Kind      string `json:"kind"`
	Text      string `json:"-"`
	Exception string `json:"exception"`
	Raw       []byte `json:"-"`
}

// LedgerEntry records a file or directory the scan did not analyse.
type LedgerEntry struct {
	Outcome    string  `json:"outcome"`
	Phase      string  `json:"phase"`
	ReasonCode string  `json:"reasonCode"`
	Path       string  `json:"path"`
	Target     *string `json:"target,omitempty"`
	Detail     *string `json:"detail,omitempty"`
}

// Package is the walked inventory of one skill package.
type Package struct {
	Root, Identity, Name string
	Artifacts            []*Artifact
	LedgerExceptions     []LedgerEntry
}

// Discovery is the list of package roots found under the known skill roots plus
// the traversal gaps discovery hit, in the package-ledger shape.
type Discovery struct {
	Paths            []string
	LedgerExceptions []LedgerEntry
}

// Ledger is the coverage ledger; field order is the Python dict order.
type Ledger struct {
	ArtifactsSeen           int            `json:"artifactsSeen"`
	ArtifactsAnalyzed       int            `json:"artifactsAnalyzed"`
	ArtifactsSkipped        int            `json:"artifactsSkipped"`
	ArtifactsNotInspectable int            `json:"artifactsNotInspectable"`
	ArtifactsFailedRead     int            `json:"artifactsFailedRead"`
	ShippedCompiledCode     []string       `json:"shippedCompiledCode"`
	AgentIdentityFiles      []string       `json:"agentIdentityFiles"`
	OpaqueContent           []string       `json:"opaqueContent"`
	SecretMaterial          []string       `json:"secretMaterial"`
	AgentConfig             []string       `json:"agentConfig"`
	InspectableDenominator  int            `json:"inspectableDenominator"`
	CoveragePercent         float64        `json:"coveragePercent"`
	ByRole                  map[string]int `json:"byRole"`
	Exceptions              []LedgerEntry  `json:"exceptions"`
}

var (
	scriptExt = map[string]string{".py": "python", ".pyw": "python", ".sh": "shell", ".bash": "shell",
		".zsh": "shell", ".command": "shell", ".bat": "batch", ".cmd": "batch",
		".ps1": "powershell", ".js": "javascript", ".mjs": "javascript",
		".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript",
		".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
		".rb": "ruby", ".pl": "perl"}

	// Shipped compiled or native code a text scanner cannot read; inventoried and
	// surfaced, never dropped.
	compiledExt = map[string]string{".pyc": "python_bytecode", ".pyo": "python_bytecode",
		".pyd": "python_extension", ".so": "native_code",
		".dylib": "native_code", ".dll": "native_code",
		".exe": "native_code", ".wasm": "native_code",
		".node": "native_code", ".jar": "native_code",
		".war": "native_code", ".class": "native_code",
		".o": "native_code", ".a": "native_code"}
	soVersioned = regexp.MustCompile(`\.so(\.\d+)+$`)

	docOnlyMD      = pytext.Set("readme.md", "changelog.md", "contributing.md", "license.md", "security.md", "code_of_conduct.md", "notice.md")
	instructionExt = pytext.Set(".md", ".mdc", ".markdown", ".rst")
	// Inert binary assets leave the coverage denominator; active assets and nested
	// archives are surfaced and lower coverage.
	assetExt         = pytext.Set(".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".mp4", ".webp")
	activeAssetExt   = pytext.Set(".svg", ".pdf")
	nestedArchiveExt = pytext.Set(".zip", ".gz", ".tar", ".tgz", ".whl", ".bz2", ".xz", ".rar", ".7z")

	// skipDirs are coverage-benign caches; bundledDirs are pruned too but lower coverage.
	skipDirs    = pytext.Set(".git", ".hg", ".svn", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".idea", ".tox", ".ruff_cache")
	bundledDirs = pytext.Set("node_modules", "dist", "build", "vendor", "target")

	rootConfig = map[string]string{"hooks.json": "hooks_config", ".mcp.json": "mcp_config",
		"plugin.json": "plugin_manifest", ".app.json": "app_manifest", "plugin.lock.json": "plugin_lock"}
	agentConfigFiles = pytext.Set("settings.json", "settings.local.json", "mcp.json", "claude_desktop_config.json", "config.toml")
	secretFiles      = pytext.Set(".env", ".netrc", ".npmrc", ".pypirc", "credentials", "credentials.json", ".credentials.json",
		"secrets.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
	secretExt = pytext.Set(".pem", ".key", ".pfx", ".p12", ".keystore")
	// IdentityFiles are agent identity / memory files (the persistence write target).
	IdentityFiles = pytext.Set("claude.md", "agents.md", "agent.md", "gemini.md", "soul.md", "memory.md",
		"identity.md", ".cursorrules", ".windsurfrules", ".clinerules", ".roorules", "copilot-instructions.md")

	// knownSkillRoots are the directories agents load skills from.
	knownSkillRoots = []string{
		"~/.claude/skills", "~/.claude/plugins",
		"~/.config/opencode/skills", ".opencode/skills",
		"~/.cursor/skills", ".cursor/skills",
		"~/.gemini/skills", ".gemini/skills",
		"~/.codex/skills", ".codex/skills",
		"~/.copilot/skills", ".github/skills",
		"~/.agents/skills", ".agents/skills",
		".claude/skills",
	}
	// pkgMarkers make a directory a package root even without a SKILL.md.
	pkgMarkers = pytext.Set(".claude-plugin", ".codex-plugin", "plugin.json", ".mcp.json", "hooks.json")
	// BenignLedger lists directory-level skips that do not lower coverage.
	BenignLedger = pytext.Set("excluded_dir")
)

// Read limits; tests lower them.
var (
	MaxFileBytes        int64 = 1 << 20
	maxFiles                  = 5000
	maxDirs                   = 5000
	aggregateMaxBytes   int64 = 256 << 20
	MaxDiscoveryDirs          = 20000
	maxDiscoveryEntries       = 100000
)

// Seams the tests replace: how a directory is opened and enumerated, how a file
// is opened for reading, and how a path is stat'ed during discovery.
type dirHandle interface {
	ReadDir(n int) ([]fs.DirEntry, error)
	Close() error
}

var (
	openDir  = func(path string) (dirHandle, error) { return os.Open(path) }
	openFile = os.OpenFile
	stat     = os.Stat
)

// posix translates only the OS separator: on POSIX a backslash is a filename byte.
func posix(p string) string { return strings.ReplaceAll(p, string(os.PathSeparator), "/") }

// baseName is os.path.basename: the text after the last OS separator ("/" and "\" on Windows).
func baseName(p string) string {
	return p[strings.LastIndexAny(p, "/"+string(os.PathSeparator))+1:]
}

func relpath(abspath, root string) string {
	rel, err := filepath.Rel(root, abspath)
	if err != nil {
		rel = abspath
	}
	return pytext.NFC(posix(rel))
}

func portableName(name string) string {
	return pytext.CaseFold(strings.TrimRight(pytext.NFC(name), " ."))
}

func realpath(p string) string {
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

// installIdentity is the stable identity of an install: its canonical path.
func installIdentity(root string) string {
	real, err := filepath.Abs(realpath(root))
	if err != nil {
		real = root
	}
	real = posix(real)
	if len(real) > 1 && real[1] == ':' {
		real = strings.ToLower(real[:1]) + real[1:]
	}
	real = strings.TrimRight(real, "/")
	if len(real) == 2 && real[1] == ':' {
		real += "/"
	}
	if real == "" {
		return "/"
	}
	return real
}

// readBytes reads at most limit bytes of a regular file without following a
// symlink, rejecting a special file, a file swapped since the walk-time stat and
// a file larger than MaxFileBytes. It returns the bytes, the skip reason ("" on
// success) and the number of bytes actually read, which is charged to the budget
// even when the read is then refused.
func readBytes(path string, limit int64, expected os.FileInfo) ([]byte, string, int64) {
	limit = max(0, min(limit, MaxFileBytes))
	f, err := openFile(path, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return nil, "unreadable:" + pytext.OSErrorName(err), 0
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, "unreadable:" + pytext.OSErrorName(err), 0
	}
	if !st.Mode().IsRegular() {
		return nil, "not_regular_file", 0
	}
	if expected != nil && (st.Mode().Type() != expected.Mode().Type() || !os.SameFile(expected, st)) {
		return nil, "file_changed", 0
	}
	if st.Size() > MaxFileBytes {
		return nil, "too_large", 0
	}
	if st.Size() > limit {
		return nil, "total_budget_exhausted", 0
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, "unreadable:" + pytext.OSErrorName(err), 0
	}
	final, err := f.Stat()
	if err != nil {
		return nil, "unreadable:" + pytext.OSErrorName(err), 0
	}
	n := int64(len(raw))
	if final.Size() > MaxFileBytes {
		return nil, "too_large", n
	}
	if final.Size() > limit {
		return nil, "total_budget_exhausted", n
	}
	return raw, "", n
}

var cp1252Undefined = []byte{0x81, 0x8d, 0x8f, 0x90, 0x9d}

// decode turns raw bytes into text the way the Python scanner does: a NUL byte is
// binary; then utf-8-sig, then cp1252 (whose five undefined bytes Python rejects);
// anything else is undecodable. Pure, so the decision is testable off a byte string.
func decode(raw []byte) (text, reason string) {
	if bytes.IndexByte(raw, 0) >= 0 {
		return "", "binary_content"
	}
	if utf8.Valid(raw) {
		return string(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))), ""
	}
	for _, b := range cp1252Undefined {
		if bytes.IndexByte(raw, b) >= 0 {
			return "", "undecodable_text"
		}
	}
	out, err := charmap.Windows1252.NewDecoder().Bytes(raw)
	if err != nil {
		return "", "undecodable_text"
	}
	return string(out), ""
}

func (p *Package) skip(reason, rel string) {
	p.LedgerExceptions = append(p.LedgerExceptions, discoveryEntry(reason, rel))
}

// rejectSpecial is the reason a directory entry that is not a plain file is not
// opened, or "" to read it.
func rejectSpecial(m fs.FileMode) string {
	if m&fs.ModeSymlink != 0 {
		return "symlink"
	}
	if !m.IsRegular() {
		return "not_regular_file"
	}
	return ""
}

func classify(filename string) (kind, role string) {
	low := pytext.Lower(filename)
	_, ext := pytext.SplitExt(filename)
	ext = pytext.Lower(ext)
	switch {
	case low == "skill.md":
		return "skill_manifest", "instruction_primary"
	case IdentityFiles[low]:
		return "agent_identity", "identity"
	case rootConfig[low] != "":
		return rootConfig[low], "root_config"
	case agentConfigFiles[low]:
		return "agent_config", "config"
	case secretFiles[low] || secretExt[ext]:
		return "secret_material", "secret"
	case instructionExt[ext]:
		if docOnlyMD[low] {
			return "doc", "documentation"
		}
		return "instruction", "instruction_secondary"
	case scriptExt[ext] != "":
		return "script_" + scriptExt[ext], "script"
	case compiledExt[ext] != "" || soVersioned.MatchString(low):
		if k := compiledExt[ext]; k != "" {
			return k, "compiled"
		}
		return "native_code", "compiled"
	case low == "package.json" || low == "pyproject.toml" || (strings.HasSuffix(low, ".txt") && strings.Contains(low, "requirements")):
		return "dep_manifest", "dependency_manifest"
	case nestedArchiveExt[ext]:
		return "nested_archive", "opaque"
	case activeAssetExt[ext]:
		return "active_asset", "opaque"
	case assetExt[ext]:
		return "asset", "asset"
	}
	return "other", "other"
}

var shebangRE = regexp.MustCompile(`(?i)^#!` + pytext.Space + `*(?:` + pytext.NotSpace + `*/env(?:` + pytext.Space + `+-S)?` +
	pytext.Space + `+|` + pytext.NotSpace + `*/)?(python(?:\d+(?:\.\d+)*)?|bash|sh|zsh|dash|ksh|fish|pwsh|powershell|node|deno|bun|ruby|perl)(?:` +
	pytext.Space + `|$)`)

func classifyShebang(text string) (kind, role string, ok bool) {
	first, _, _ := strings.Cut(text, "\n")
	if r := []rune(first); len(r) > 256 {
		first = string(r[:256])
	}
	m := shebangRE.FindStringSubmatch(first)
	if m == nil {
		return "", "", false
	}
	name := pytext.Lower(m[1])
	lang := name
	switch {
	case strings.HasPrefix(name, "python"):
		lang = "python"
	case pytext.Set("bash", "sh", "zsh", "dash", "ksh", "fish")[name]:
		lang = "shell"
	case name == "pwsh" || name == "powershell":
		lang = "powershell"
	case name == "node" || name == "deno" || name == "bun":
		lang = "javascript"
	}
	return "script_" + lang, "script", true
}

// BuildPackage walks the package and inventories every artifact. No parsing, no execution.
func BuildPackage(root string) *Package {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	pkg := &Package{Root: abs, Identity: installIdentity(root), Name: baseName(strings.TrimRight(abs, `\/`)),
		Artifacts: []*Artifact{}, LedgerExceptions: []LedgerEntry{}}
	var walkErrors []LedgerEntry

	seen, seenDirs := 0, 0
	pending := []string{pkg.Root}
	var totalRead int64
	truncated, dirsTruncated := false, false
	for len(pending) > 0 {
		dirpath := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		seenDirs++
		var dirnames, filenames []string
		filesHere, dirsHere := 0, 0
		err := func() error {
			h, err := openDir(dirpath)
			if err != nil {
				return err
			}
			defer h.Close()
			for {
				batch, err := h.ReadDir(512)
				for _, e := range batch {
					if isDirEntry(e) {
						dirsHere++
						dirnames = append(dirnames, e.Name())
					} else {
						filesHere++
						filenames = append(filenames, e.Name())
					}
					if seen+filesHere > maxFiles {
						truncated = true
						return nil
					}
					if seenDirs+len(pending)+dirsHere > maxDirs {
						dirsTruncated = true
						return nil
					}
				}
				if err == io.EOF {
					return nil
				}
				if err != nil {
					return err
				}
			}
		}()
		if err != nil {
			walkErrors = append(walkErrors, LedgerEntry{ReasonCode: "walk_error:" + pytext.OSErrorName(err), Path: relpath(dirpath, pkg.Root)})
			continue
		}
		if truncated || dirsTruncated {
			break
		}

		groups := map[string][]string{}
		for _, n := range slices.Concat(dirnames, filenames) {
			k := portableName(n)
			groups[k] = append(groups[k], n)
		}
		collisions := map[string]bool{}
		for _, g := range groups {
			if len(g) > 1 {
				for _, n := range g {
					collisions[n] = true
				}
			}
		}
		var kept []string
		for _, d := range dirnames {
			dp := filepath.Join(dirpath, d)
			drel := relpath(dp, pkg.Root)
			switch {
			case collisions[d]:
				pkg.skip("portable_path_collision", drel)
			case skipDirs[d]:
				pkg.skip("excluded_dir", drel)
			case bundledDirs[d]:
				pkg.skip("bundled_dir", drel)
			case isReparse(dp):
				pkg.skip("reparse_point", drel)
			default:
				kept = append(kept, d)
			}
		}
		slices.Sort(kept)
		for i := len(kept) - 1; i >= 0; i-- {
			pending = append(pending, filepath.Join(dirpath, kept[i]))
		}
		slices.Sort(filenames)
		for _, fn := range filenames {
			seen++
			ap := filepath.Join(dirpath, fn)
			rel := relpath(ap, pkg.Root)
			if collisions[fn] {
				kind, role := classify(fn)
				pkg.skip("portable_path_collision", rel)
				pkg.Artifacts = append(pkg.Artifacts, &Artifact{Rel: rel, Role: role, Kind: kind, Exception: "portable_path_collision"})
				continue
			}
			st, err := os.Lstat(ap)
			if err != nil {
				pkg.skip("unreadable:"+pytext.OSErrorName(err), rel)
				continue
			}
			// Python's lstat carries st_ino; Go loads a Windows file id lazily by path,
			// so pin it now or readBytes would compare the swapped-in file with itself.
			os.SameFile(st, st)
			if reject := rejectSpecial(st.Mode()); reject != "" {
				e := discoveryEntry(reject, rel)
				if reject == "symlink" {
					if t, err := os.Readlink(ap); err == nil {
						e.Target = &t
					}
				}
				pkg.LedgerExceptions = append(pkg.LedgerExceptions, e)
				continue
			}
			kind, role := classify(fn)
			art := &Artifact{Rel: rel, Role: role, Kind: kind}
			// One read serves decoding and byte checks and is charged to the hard cap.
			readReason := "total_budget_exhausted"
			if remaining := aggregateMaxBytes - totalRead; remaining > 0 {
				var n int64
				art.Raw, readReason, n = readBytes(ap, remaining, st)
				totalRead += n
			}
			switch {
			case readReason != "":
				art.Exception = readReason
			case kind == "asset":
				art.Exception = "binary_content"
			case role == "opaque":
				// Active content (SVG/PDF) or a nested archive: unreviewable, so it is
				// surfaced and counts against coverage, not excused like an icon.
				art.Exception = "unreviewable_content"
			case role == "compiled":
				art.Exception = "shipped_compiled"
			default:
				art.Text, art.Exception = decode(art.Raw)
				if art.Exception == "" && art.Kind == "other" {
					if k, r, ok := classifyShebang(art.Text); ok {
						art.Kind, art.Role = k, r
					}
				}
			}
			if art.Exception != "" {
				pkg.skip(art.Exception, rel)
			}
			pkg.Artifacts = append(pkg.Artifacts, art)
		}
	}

	if truncated {
		pkg.skip("walk_truncated", fmt.Sprintf("(more than %d files)", maxFiles))
	}
	if dirsTruncated {
		pkg.skip("walk_truncated", fmt.Sprintf("(more than %d directories)", maxDirs))
	}
	for _, e := range walkErrors {
		pkg.skip(e.ReasonCode, e.Path)
	}
	return pkg
}

func expandUser(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return home + p[1:]
}

func discoveryEntry(reason, path string) LedgerEntry {
	return LedgerEntry{Outcome: "skipped", Phase: "static", ReasonCode: reason, Path: path}
}

func discoveryError(err error, path string) LedgerEntry {
	abs, aerr := filepath.Abs(path)
	if aerr != nil {
		abs = path
	}
	return discoveryEntry("walk_error:"+pytext.OSErrorName(err), posix(abs))
}

// Discover returns the skill package roots found under roots (nil means the known
// agent skill roots). A root is a directory holding a SKILL.md or a plugin marker;
// once found its subtree is pruned. A symlinked ROOT is followed, nested symlinks
// are not, and hard directory and entry budgets bound the scan.
func Discover(roots []string) Discovery {
	explicit := roots != nil // a named root the operator mistyped must not pass for an empty one
	if roots == nil {
		roots = knownSkillRoots
	}
	found := map[string]string{}
	seen := map[string]bool{}
	exceptions := []LedgerEntry{}
	scannedDirs, seenEntries := 0, 0
	truncated := false
	for _, root := range roots {
		base, err := filepath.Abs(expandUser(root))
		if err != nil {
			base = expandUser(root)
		}
		rootStat, err := stat(base)
		if err != nil {
			switch {
			case explicit && errors.Is(err, fs.ErrNotExist):
				exceptions = append(exceptions, discoveryEntry("root_missing", posix(base)))
			case explicit || !errors.Is(err, fs.ErrNotExist):
				exceptions = append(exceptions, discoveryError(err, base))
			}
			continue
		}
		if !rootStat.IsDir() {
			if explicit {
				exceptions = append(exceptions, discoveryEntry("root_not_directory", posix(base)))
			}
			continue
		}
		pending := []string{base}
		for len(pending) > 0 {
			cur := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			real := realpath(cur)
			if seen[real] {
				continue
			}
			if scannedDirs >= MaxDiscoveryDirs {
				exceptions = append(exceptions, discoveryEntry("walk_truncated", fmt.Sprintf("(more than %d discovery directories)", MaxDiscoveryDirs)))
				truncated = true
				break
			}
			seen[real] = true
			scannedDirs++
			var children []string
			marker, entryLimitHit := false, false
			err := func() error {
				h, err := openDir(cur)
				if err != nil {
					return err
				}
				defer h.Close()
				for {
					batch, err := h.ReadDir(512)
					for _, e := range batch {
						seenEntries++
						if seenEntries > maxDiscoveryEntries {
							entryLimitHit = true
							return nil
						}
						low := pytext.Lower(e.Name())
						path := filepath.Join(cur, e.Name())
						isLink := e.Type()&fs.ModeSymlink != 0
						linkDir := false
						if isLink {
							st, err := stat(path)
							if err != nil && !errors.Is(err, fs.ErrNotExist) {
								exceptions = append(exceptions, discoveryError(err, path))
								continue
							}
							linkDir = err == nil && st.IsDir()
						}
						isDir := isDirEntry(e)
						isMarker := low == "skill.md" || pkgMarkers[low]
						if linkDir {
							if cur == base { // a symlinked ROOT is followed
								children = append(children, path)
							}
							continue // never follow a nested directory link
						}
						if !isDir {
							marker = marker || isMarker
							continue
						}
						if skipDirs[e.Name()] || bundledDirs[e.Name()] || isReparse(path) {
							continue
						}
						marker = marker || isMarker
						children = append(children, path)
					}
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
				}
			}()
			if err != nil {
				exceptions = append(exceptions, discoveryError(err, cur))
				continue
			}
			if entryLimitHit {
				exceptions = append(exceptions, discoveryEntry("walk_truncated", fmt.Sprintf("(more than %d discovery entries)", maxDiscoveryEntries)))
				truncated = true
				break
			}
			if marker {
				found[real] = cur
				continue // this package owns its nested skill directories
			}
			slices.Sort(children)
			for i := len(children) - 1; i >= 0; i-- {
				pending = append(pending, children[i])
			}
		}
		if truncated {
			break
		}
	}
	keys := slices.Sorted(maps.Keys(found))
	paths := make([]string, 0, len(keys))
	for _, k := range keys {
		paths = append(paths, found[k])
	}
	return Discovery{Paths: paths, LedgerExceptions: exceptions}
}

func sortedRels(arts []*Artifact, keep func(*Artifact) bool) []string {
	out := []string{}
	for _, a := range arts {
		if keep(a) {
			out = append(out, a.Rel)
		}
	}
	slices.Sort(out)
	return out
}

// BuildLedger returns the coverage ledger: files seen, files analysed, and why
// the rest were not read. Inert assets and compiled artifacts leave the text
// denominator (the compiled ones are also listed); everything else unread counts
// against coverage.
func BuildLedger(p *Package) Ledger {
	artifactExceptions := map[[2]string]int{}
	for _, a := range p.Artifacts {
		if a.Exception != "" {
			artifactExceptions[[2]string{a.Rel, a.Exception}]++
		}
	}
	preSkips := 0
	for _, e := range p.LedgerExceptions {
		key := [2]string{e.Path, e.ReasonCode}
		if artifactExceptions[key] > 0 {
			artifactExceptions[key]--
		} else if !BenignLedger[e.ReasonCode] {
			preSkips++
		}
	}
	analyzed, notInsp, failed := 0, 0, preSkips
	byRole := map[string]int{}
	for _, a := range p.Artifacts {
		byRole[a.Role]++
		switch {
		case a.Exception == "":
			analyzed++
		case (a.Kind == "asset" && a.Exception == "binary_content") || (a.Role == "compiled" && a.Exception == "shipped_compiled"):
			notInsp++
		default:
			failed++
		}
	}
	denom := analyzed + failed
	percent := 100.0
	if denom > 0 {
		percent, _ = strconv.ParseFloat(strconv.FormatFloat(100.0*float64(analyzed)/float64(denom), 'f', 2, 64), 64)
	}
	exceptions := append([]LedgerEntry{}, p.LedgerExceptions...)
	slices.SortStableFunc(exceptions, func(a, b LedgerEntry) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.ReasonCode, b.ReasonCode))
	})
	return Ledger{
		ArtifactsSeen:           analyzed + notInsp + failed,
		ArtifactsAnalyzed:       analyzed,
		ArtifactsSkipped:        notInsp + failed,
		ArtifactsNotInspectable: notInsp,
		ArtifactsFailedRead:     failed,
		ShippedCompiledCode:     sortedRels(p.Artifacts, func(a *Artifact) bool { return a.Role == "compiled" }),
		AgentIdentityFiles:      sortedRels(p.Artifacts, func(a *Artifact) bool { return a.Role == "identity" }),
		OpaqueContent:           sortedRels(p.Artifacts, func(a *Artifact) bool { return a.Role == "opaque" }),
		SecretMaterial:          sortedRels(p.Artifacts, func(a *Artifact) bool { return a.Role == "secret" }),
		AgentConfig:             sortedRels(p.Artifacts, func(a *Artifact) bool { return a.Role == "config" || a.Role == "root_config" }),
		InspectableDenominator:  denom,
		CoveragePercent:         percent,
		ByRole:                  byRole,
		Exceptions:              exceptions,
	}
}
