// Package parse holds the parsed intermediate representation every check reads (Python
// parse.ParsedPackage / ParsedArtifact). Nil on a pointer, map or slice field is Python None
// where the spec says so (00-overview D3); an empty non-nil value is a parsed empty value.
package parse

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/pyast"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// Package is one parsed skill package.
type Package struct {
	Identity, Name   string
	Artifacts        []*Artifact // ingest order; drives every check's finding order
	ByRel            map[string]*Artifact
	Refs             []Ref
	LedgerExceptions []ingest.LedgerEntry // ingest's entries plus one parse entry per diagnostic
}

// Ref is an in-package markdown link resolved to a target artifact.
type Ref struct {
	From string `json:"from"`
	To   string `json:"to"`
	Line int    `json:"line"`
}

// Artifact is the parse result of one ingested file.
type Artifact struct {
	Rel, Kind           string
	Text                *string        // nil == None; CRLF/CR normalised once
	Raw                 []byte         // nil == None
	Frontmatter         map[string]any // nil == None; keys str(k) at every depth; {} for an empty block
	FrontmatterKeys     []string       // top-level keys, document order
	FrontmatterKeyLines map[string]int // 1-based
	FrontmatterEndLine  int            // 1-based line of the closing ---/...; 0 == None
	UnsafeYamlTags      []YamlTag
	Grants              []Grant   // nil == None
	Markdown            *Markdown // nil == None
	Preprocessing       []Preproc
	PreprocessingCounts PreprocCounts
	PyTree              *pyast.Module // nil == None
	ShellTree           *syntax.File  // nil == None (and nil on a parse error, parse.md R1)
	Config              any           // map[string]any | []any | scalar; nil == None
	ManifestKind        string        // "" == None
	Deps                []Dep         // nil == None
	Diagnostics         []Diagnostic
}

// Diagnostic is a (code, detail) pair; Canonical renders it as [code, detail-or-null].
type Diagnostic struct {
	Code   string
	Detail *string
}

func (d Diagnostic) MarshalJSON() ([]byte, error) { return json.Marshal([2]any{d.Code, d.Detail}) }

// Span is a 1-based inclusive line span, rendered as [start, end].
type Span struct{ Start, End int }

func (s Span) MarshalJSON() ([]byte, error) { return json.Marshal([2]int{s.Start, s.End}) }

// Fence is a fenced or indented code block; Line is the opener line and Info "" for indented code.
type Fence struct {
	Info    string `json:"info"`
	Content string `json:"content"`
	Line    int    `json:"line"`
}

type Link struct {
	Href  string `json:"href"`
	Label string `json:"label"`
	Line  int    `json:"line"`
}

type HTMLComment struct {
	Body   string `json:"body"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// HTMLProse is the width- and newline-preserving projection of an inspectable HTML fragment.
type HTMLProse struct {
	Text string `json:"text"`
	Line int    `json:"line"`
}

// HTMLFragment is an uninspectable HTML fragment.
type HTMLFragment struct {
	Text   string `json:"text"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type HTMLTag struct {
	Name         string
	Line, Column int
	Closing      bool
	Attrs        [][2]string
}

// Markdown is the line-anchored view of a CommonMark artifact.
type Markdown struct {
	Links                         []Link
	Fences                        []Fence
	FenceSpans                    []Span // ```/~~~ fences only
	CodeSpans                     []Span // fences + indented code
	ProseSpans                    []Span // inline tokens without html_inline children
	ReferenceSpans                []Span
	ParagraphSpans                []Span // top-level paragraphs
	Preproc                       []Preproc
	PreprocCounts                 PreprocCounts
	HTMLComments                  []HTMLComment
	HTMLTags                      []HTMLTag
	HTMLProse                     []HTMLProse
	HTMLUninspectable             []HTMLFragment
	HasHTML, HasUninspectableHTML bool
	// HTMLHidesContent: an uninspectable fragment carried text, or a construct the inspector
	// could not resolve; unknown tags or attributes alone leave it false
	HTMLHidesContent bool
}

// Preproc is a load-time preprocessing token; Runs is live substitution vs decoy.
type Preproc struct {
	Kind   string `json:"kind"` // "inline" | "fenced"
	Code   string `json:"code"`
	Line   int    `json:"line"`
	Runs   bool   `json:"runs"`
	Column int    `json:"column"`
	Info   string `json:"info"`
}

type PreprocCounts struct {
	Inline int `json:"inline"`
	Fenced int `json:"fenced"`
}

// YamlTag is a parser-proven unsafe construction tag in load-bearing frontmatter.
type YamlTag struct {
	Tag    string `json:"tag"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// Grant is one allowed/disallowed-tools entry; Broad for a bare tool such as `Bash`.
type Grant struct {
	Tool    string  `json:"tool"`
	Pattern *string `json:"pattern"`
	Raw     string  `json:"raw"`
	Allowed bool    `json:"allowed"`
	Broad   bool    `json:"broad"`
	Parsed  bool    `json:"parsed"`
}

// Dep is one declared dependency; Line is nil for pyproject entries and absent for npm ones.
type Dep struct {
	Name      string `json:"name"`
	Specifier string `json:"specifier"`
	Pinned    bool   `json:"pinned"`
	Raw       string `json:"raw"`
	Line      *int   `json:"line"`
}

// parent is the directory of a package-relative path, "" for a root file.
func parent(rel string) string { return rel[:max(strings.LastIndexByte(rel, '/'), 0)] }

// ManifestIndex maps each directory ("" is the root) to its first skill_manifest artifact in
// package order.
func ManifestIndex(p *Package) map[string]*Artifact {
	index := map[string]*Artifact{}
	for _, a := range p.Artifacts {
		if dir := parent(a.Rel); a.Kind == "skill_manifest" && index[dir] == nil {
			index[dir] = a
		}
	}
	return index
}

// GoverningManifest walks from rel's directory up to the root and returns the first indexed
// manifest, or nil.
func GoverningManifest(index map[string]*Artifact, rel string) *Artifact {
	for dir := parent(rel); ; dir = parent(dir) {
		if a := index[dir]; a != nil || dir == "" {
			return a
		}
	}
}

// LiftedTargets is _lifted_targets: the doc/other artifacts reachable from an instruction-lane
// artifact over Refs; the instruction and obfuscation checks scan them as lane text.
func LiftedTargets(p *Package) map[string]bool {
	return Reach(p, InstructionKinds, pytext.Set("doc", "other"), false)
}

// Reach walks Refs depth-first from every artifact whose kind is in roots and returns the
// artifacts of a kind in targets it reaches, plus the roots themselves when includeRoots (the
// preproc loaded set); a root is never re-entered as a target.
func Reach(p *Package, roots, targets map[string]bool, includeRoots bool) map[string]bool {
	adjacency := map[string][]string{}
	for _, r := range p.Refs {
		adjacency[r.From] = append(adjacency[r.From], r.To)
	}
	seen, out := map[string]bool{}, map[string]bool{}
	var queue []string
	for _, a := range p.Artifacts {
		if roots[a.Kind] {
			seen[a.Rel] = true
			if includeRoots {
				out[a.Rel] = true
			}
			queue = append(queue, a.Rel)
		}
	}
	for len(queue) > 0 {
		source := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, target := range adjacency[source] {
			if a := p.ByRel[target]; !seen[target] && a != nil && targets[a.Kind] {
				seen[target], out[target] = true, true
				queue = append(queue, target)
			}
		}
	}
	return out
}

// presenceOnly names the diagnostics whose detail the IR dump reduces to true (parse.md R6).
var presenceOnly = map[string]bool{"config_parse_error": true, "shell_error_region": true, "parse_crash": true}

// irDoc is the per-artifact record of the IR dump (00-overview §6), in the shape the Python
// scanner's dump had. refs is the whole package's Refs; those from a.Rel are
// kept. A nil value is Python None; a typed nil slice or map renders as [] or {} through pytext.
func irDoc(a *Artifact, refs []Ref) map[string]any {
	var own []Ref
	for _, r := range refs {
		if r.From == a.Rel {
			own = append(own, r)
		}
	}
	diags := make([]any, 0, len(a.Diagnostics))
	for _, d := range a.Diagnostics {
		var detail any
		if d.Detail != nil {
			detail = *d.Detail
			if presenceOnly[d.Code] {
				detail = true
			}
		}
		diags = append(diags, []any{d.Code, detail})
	}
	doc := map[string]any{
		"rel": a.Rel, "kind": a.Kind,
		"text_sha256": nil, "raw_sha256": nil,
		"frontmatter": nil, "frontmatter_keys": nil,
		"frontmatter_key_lines": a.FrontmatterKeyLines, "frontmatter_end_line": nil,
		"unsafe_yaml_tags": a.UnsafeYamlTags, "grants": nil,
		"fences": nil, "fence_spans": nil, "code_spans": nil, "prose_spans": nil,
		"reference_spans": nil, "paragraph_spans": nil,
		"links": nil, "fallback_links": []Link{}, // the fallback path is not ported (parse.md R4)
		"html_comments": nil, "html_prose": nil, "html_uninspectable": nil,
		"has_html": nil, "has_uninspectable_html": nil,
		"preprocessing": a.Preprocessing, "preprocessing_counts": a.PreprocessingCounts,
		"config": nil, "manifest_kind": nil, "deps": nil,
		"diagnostics": diags, "refs": own,
	}
	if a.Text != nil {
		doc["text_sha256"] = fmt.Sprintf("%x", sha256.Sum256([]byte(*a.Text)))
	}
	if a.Raw != nil {
		doc["raw_sha256"] = fmt.Sprintf("%x", sha256.Sum256(a.Raw))
	}
	if a.Frontmatter != nil {
		doc["frontmatter"], doc["frontmatter_keys"] = a.Frontmatter, a.FrontmatterKeys
	}
	if a.FrontmatterEndLine != 0 {
		doc["frontmatter_end_line"] = a.FrontmatterEndLine
	}
	if a.Grants != nil {
		doc["grants"] = a.Grants
	}
	if md := a.Markdown; md != nil {
		doc["fences"], doc["fence_spans"], doc["code_spans"] = md.Fences, md.FenceSpans, md.CodeSpans
		doc["prose_spans"], doc["reference_spans"], doc["paragraph_spans"] = md.ProseSpans, md.ReferenceSpans, md.ParagraphSpans
		doc["links"], doc["html_comments"], doc["html_prose"] = md.Links, md.HTMLComments, md.HTMLProse
		doc["html_uninspectable"] = md.HTMLUninspectable
		doc["has_html"], doc["has_uninspectable_html"] = md.HasHTML, md.HasUninspectableHTML
	}
	if a.Config != nil {
		doc["config"] = typed(a.Config)
	}
	if a.ManifestKind != "" {
		doc["manifest_kind"] = a.ManifestKind
	}
	if a.Deps != nil {
		deps := make([]any, len(a.Deps))
		npm := pytext.Lower(pytext.Basename(a.Rel)) == "package.json"
		for i, d := range a.Deps {
			m := map[string]any{"name": d.Name, "specifier": d.Specifier, "pinned": d.Pinned, "raw": d.Raw}
			if !npm { // _npm_deps builds its dicts without a "line" key
				m["line"] = d.Line
			}
			deps[i] = m
		}
		doc["deps"] = deps
	}
	return doc
}

// DumpIR renders p as py_dump_ir.py does: one sorted-key JSON document per artifact, one per line.
func DumpIR(p *Package) []byte {
	var b strings.Builder
	for _, a := range p.Artifacts {
		b.WriteString(pytext.Dumps(irDoc(a, p.Refs), 0))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// typed is py_dump_ir._typed: every config value wrapped as [Python type name, value].
func typed(v any) []any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = typed(e)
		}
		return []any{"dict", m}
	case []any:
		l := make([]any, len(x))
		for i, e := range x {
			l[i] = typed(e)
		}
		return []any{"list", l}
	case nil:
		return []any{"NoneType", nil}
	case bool:
		return []any{"bool", x}
	case int:
		return []any{"int", x}
	case float64:
		return []any{"float", x}
	case string:
		return []any{"str", x}
	case Opaque: // a TOML date, time or datetime
		return []any{x.Type, x.Text}
	}
	return []any{fmt.Sprintf("%T", v), fmt.Sprint(v)}
}
