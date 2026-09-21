package parse

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"

	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/pyast"
	"github.com/traceforce/skill-xray/internal/pytext"
)

const (
	MaxPyChars    = 524288 // ast.parse retains a node graph that amplifies source size
	maxPyASTDepth = 512    // deterministic across platform recursion-stack sizes
	maxShellBytes = 524288 // coarse backstop for superlinear shell-parser constructs
	maxShellPipes = 3000   // long pipe chains are the known O(n^2) case
)

// pkgBudget is _PKG_BUDGET, the whole-package wall-clock cap; a test sets it negative.
var pkgBudget = 60 * time.Second

var (
	markdownKinds   = map[string]bool{"skill_manifest": true, "instruction": true, "doc": true, "agent_identity": true}
	jsonConfigKinds = map[string]bool{"hooks_config": true, "mcp_config": true, "plugin_manifest": true, "app_manifest": true, "plugin_lock": true}
	// InstructionKinds is the instruction lane: the kinds whose prose the instruction checks read.
	InstructionKinds = map[string]bool{"skill_manifest": true, "instruction": true, "agent_identity": true}
)

func detail(s string) *string { return &s }

func (a *Artifact) diag(code string, detail *string) {
	a.Diagnostics = append(a.Diagnostics, Diagnostic{Code: code, Detail: detail})
}

// Parse is parse_package: every read artifact parsed once, per-artifact isolated, under one
// wall-clock budget; diagnostics are mirrored into the ledger in artifact order.
func Parse(pkg *ingest.Package) *Package {
	out := &Package{Identity: pkg.Identity, Name: pkg.Name, Artifacts: []*Artifact{}, ByRel: map[string]*Artifact{},
		LedgerExceptions: append([]ingest.LedgerEntry{}, pkg.LedgerExceptions...)}
	deadline := time.Now().Add(pkgBudget)
	for _, art := range pkg.Artifacts {
		a := &Artifact{Rel: art.Rel, Kind: art.Kind, Raw: art.Raw}
		if art.Exception == "" {
			text := normNewlines(art.Text)
			a.Text = &text
			if time.Now().After(deadline) {
				a.diag("parse_budget_exceeded", nil)
			} else {
				parseWithin(a, text, time.Until(deadline))
			}
		}
		out.Artifacts = append(out.Artifacts, a)
		out.ByRel[a.Rel] = a
	}
	out.Refs = resolveRefs(out)
	for _, a := range out.Artifacts {
		for _, d := range a.Diagnostics {
			out.LedgerExceptions = append(out.LedgerExceptions, ingest.LedgerEntry{
				Outcome: "unresolved", Phase: "parse", ReasonCode: d.Code, Detail: d.Detail, Path: a.Rel})
		}
	}
	return out
}

// parseWithin is parseOne bounded by what is left of the package budget: a parse still running
// at the deadline is abandoned and the artifact carries parse_budget_exceeded and no IR, the
// state Python gives an artifact it never started. The abandoned goroutine finishes on its own;
// every parser is polynomial, so this is the backstop for a pathological file, not the bound.
func parseWithin(a *Artifact, text string, remaining time.Duration) {
	tmp := *a
	done := make(chan struct{})
	go func() {
		defer close(done)
		parseOne(&tmp, text)
	}()
	select {
	case <-done:
		*a = tmp
	case <-time.After(remaining):
		a.diag("parse_budget_exceeded", nil)
	}
}

// parseOne is _parse_one under its last-resort isolation: a panic becomes parse_crash.
func parseOne(a *Artifact, text string) {
	defer func() {
		if r := recover(); r != nil {
			a.diag("parse_crash", detail(fmt.Sprintf("%T", r)))
		}
	}()
	kind := a.Kind
	switch {
	case markdownKinds[kind]:
		if kind != "doc" { // a doc (README class) is body only: grants there are inert
			if err := loadFrontmatter(a, text); err != "" {
				a.diag("frontmatter_parse_error", detail(err))
			}
			if len(a.Frontmatter) > 0 {
				a.Grants = parseGrants(a.Frontmatter)
				for _, key := range [...]string{"allowed-tools", "disallowed-tools"} {
					v := a.Frontmatter[key]
					l, isList := v.([]any)
					_, isStr := v.(string)
					bad := (v != nil && !isList && !isStr) ||
						slices.ContainsFunc(l, func(x any) bool { _, ok := x.(string); return !ok }) ||
						slices.ContainsFunc(a.Grants, func(g Grant) bool { return !g.Parsed && g.Allowed == (key == "allowed-tools") })
					if bad {
						a.diag("grants_unparsed_shape", detail(key))
					}
				}
			}
		}
		parseMD(a, text, kind != "doc")
	case kind == "script_python":
		parsePython(a, text)
	case kind == "script_shell":
		parseShell(a, text)
	case kind == "script_javascript" || kind == "script_typescript":
		// no IR here; the code lane runs OpenGrep on it
	case strings.HasPrefix(kind, "script_"):
		a.diag("unsupported_language", detail(kind[len("script_"):]))
	case kind == "agent_config" || jsonConfigKinds[kind]:
		cfg, err := loadStructured(text, a.Rel)
		a.Config = cfg
		if err != "" {
			a.diag("config_parse_error", detail(err))
		} else {
			a.ManifestKind = classifyManifest(cfg)
		}
	case kind == "dep_manifest":
		base := pytext.Lower(pytext.Basename(a.Rel))
		var bad []string
		switch {
		case strings.HasSuffix(base, ".txt") && strings.Contains(base, "requirements"):
			a.Deps, bad = parseRequirements(text)
		case base == "package.json":
			cfg, err := loadStructured(text, a.Rel)
			a.Config = cfg
			if err != "" {
				a.diag("config_parse_error", detail(err))
			} else {
				a.Deps, bad = npmDeps(cfg, text)
			}
		case base == "pyproject.toml":
			cfg, md, err := decodeTOML(text)
			if err != "" {
				a.diag("config_parse_error", detail(err))
			} else {
				a.Config = cfg
				a.Deps, bad = pyprojectDeps(cfg, md)
			}
		default:
			a.diag("dep_manifest_unparsed", detail(base))
		}
		if len(bad) > 0 {
			a.diag("requirement_unparsed", detail(strings.Join(bad[:min(8, len(bad))], ";")))
		}
	case kind == "secret_material": // carried verbatim for the secret check
	default:
		a.diag("unmodeled_content", detail(kind))
	}
}

// parseMD is _parse_md on the success path only: goldmark cannot fail, so markdown_parse_error
// and the fallback scanners never run (parse.md R4). A variable so a test can make it panic.
var parseMD = func(a *Artifact, text string, stripFM bool) {
	if strings.HasSuffix(pytext.Lower(a.Rel), ".rst") {
		a.diag("unsupported_markup", detail("rst"))
	}
	body, off := text, 0
	if stripFM {
		body, off = bodyAndOffset(text)
	}
	if n := markdownTooComplex(body); n > 0 {
		a.diag("markdown_too_complex", detail(strconv.Itoa(n)))
		return
	}
	md := parseMarkdown(body, off)
	a.Markdown = md
	var inline, fenced []Preproc
	for _, t := range md.Preproc {
		if t.Kind == "inline" {
			inline = append(inline, t)
		} else {
			fenced = append(fenced, t)
		}
	}
	inlineTotal := md.PreprocCounts.Inline
	if off > 0 { // the frontmatter lines are scanned at their raw file location
		fm := strings.Join(strings.Split(text, "\n")[:off], "\n")
		fmInline, fmTotal := scanInlinePreproc(fm, 0, map[int]bool{}, false, nil)
		inline = append(fmInline, inline...)
		inlineTotal += fmTotal
	}
	kept := map[bool]int{}
	a.Preprocessing = []Preproc{}
	for _, t := range inline { // live and decoy tokens are capped separately
		if kept[t.Runs]++; kept[t.Runs] <= MaxPreprocTokens {
			a.Preprocessing = append(a.Preprocessing, t)
		}
	}
	a.Preprocessing = append(a.Preprocessing, fenced...)
	a.PreprocessingCounts = PreprocCounts{Inline: inlineTotal, Fenced: md.PreprocCounts.Fenced}
	md.Preproc = append([]Preproc{}, a.Preprocessing...)
	md.PreprocCounts = a.PreprocessingCounts
	if md.HasUninspectableHTML {
		a.diag("raw_html", nil)
	}
}

// parsePython is _parse_python: pyast.Parse into PyTree, failing closed on size, syntax and
// nesting depth.
func parsePython(a *Artifact, text string) {
	if n := utf8.RuneCountInString(text); n > MaxPyChars {
		a.diag("python_oversize", detail(strconv.Itoa(n)))
		return
	}
	m, err := pyast.Parse(text)
	if err != nil {
		switch e := err.(*pyast.SyntaxError); e.Kind {
		case "RecursionError":
			a.diag("python_too_complex", nil)
		case "MemoryError":
			a.diag("memoryerror", nil)
		default:
			line := "None"
			if e.Line != 0 {
				line = strconv.Itoa(e.Line)
			}
			a.diag("python_syntax_error", detail("line "+line))
		}
		return
	}
	if pyast.Depth(m) > maxPyASTDepth {
		a.diag("python_too_complex", nil)
		return
	}
	a.PyTree = m
}

// parseShell is parse_shell and its _parse_one diagnostics; the DoS bound lives here, at the
// parser, so every caller is protected.
func parseShell(a *Artifact, text string) {
	pipes := 0
	for i := 0; i < len(text); i++ { // a single `|`, never `||`
		if text[i] == '|' && (i == 0 || text[i-1] != '|') && (i+1 == len(text) || text[i+1] != '|') {
			pipes++
		}
	}
	if len(text) > maxShellBytes || pipes > maxShellPipes {
		a.diag("shell_too_complex", detail(strconv.Itoa(utf8.RuneCountInString(text))))
		return
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil { // one span at the first error: mvdan/sh stops there and keeps no tree (parse.md 4.8)
		var pe syntax.ParseError
		var le syntax.LangError
		line := 0
		switch {
		case errors.As(err, &pe):
			line = int(pe.Pos.Line())
		case errors.As(err, &le):
			line = int(le.Pos.Line())
		}
		a.diag("shell_error_region", detail(fmt.Sprintf("1:%d-%d", line, line)))
		return
	}
	a.ShellTree = f
}

var refSchemeRE = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*:`)

// resolveRefs is _resolve_refs: in-package markdown links resolved to artifacts; external,
// parent-escaping and self references drop, targets are unquoted and NFC-matched.
func resolveRefs(p *Package) []Ref {
	refs := []Ref{}
	for _, a := range p.Artifacts {
		if a.Markdown == nil {
			continue
		}
		base := parent(a.Rel)
		for _, l := range a.Markdown.Links {
			target, _, _ := strings.Cut(l.Href, "#")
			target, _, _ = strings.Cut(target, "?")
			target = pytext.Strip(target)
			if target == "" || refSchemeRE.MatchString(target) {
				continue
			}
			target = pytext.NFC(pytext.Unquote(target))
			resolved := path.Clean(target)
			if !strings.HasPrefix(target, "/") { // posixpath.join keeps an absolute target as is
				resolved = path.Join(base, target)
			}
			if resolved == ".." || strings.HasPrefix(resolved, "../") || resolved == "." {
				continue
			}
			if _, ok := p.ByRel[resolved]; ok {
				refs = append(refs, Ref{From: a.Rel, To: resolved, Line: l.Line})
			}
		}
	}
	return refs
}
