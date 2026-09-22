package parse

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"github.com/traceforce/skill-xray/internal/pep508"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// reqDep is _req_dep: a PEP 508 line to a Dep, nil when packaging would reject it.
func reqDep(raw string, line *int) *Dep {
	r, err := pep508.Parse(raw)
	if err != nil {
		return nil
	}
	return &Dep{Name: r.Name, Specifier: r.SpecifierString(), Pinned: r.Pinned(), Raw: raw, Line: line}
}

// reqTrailerRE is `\s(?:#|--)`: a trailing comment or pip option starts at the first match.
var reqTrailerRE = regexp.MustCompile(pytext.Space + `(?:#|--)`)

// parseRequirements is _parse_requirements over a requirements.txt: deps plus the lines that
// are not PEP 508 dependencies (-r, -e, VCS, local paths, options).
func parseRequirements(text string) ([]Dep, []string) {
	deps, unhandled := []Dep{}, []string{}
	var buf strings.Builder // accumulated continuation lines, never rescanned (O(n) like pip)
	startLine := 0
	lines := append(strings.Split(text, "\n"), "")
	for i, raw := range lines {
		line := i + 1
		stripped := pytext.RStrip(raw)
		if strings.HasSuffix(stripped, `\`) && !strings.HasPrefix(pytext.LStrip(stripped), "#") {
			if buf.Len() == 0 {
				startLine = line
			}
			buf.WriteString(stripped[:len(stripped)-1])
			continue
		}
		s := buf.String() + raw
		if loc := reqTrailerRE.FindStringIndex(s); loc != nil {
			s = s[:loc[0]]
		}
		s = pytext.Strip(s)
		buf.Reset()
		depLine := line
		if startLine != 0 {
			depLine = startLine
		}
		startLine = 0
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if d := reqDep(s, &depLine); d != nil {
			deps = append(deps, *d)
		} else {
			unhandled = append(unhandled, pytext.Head(s, 80))
		}
	}
	return deps, unhandled
}

// pyprojectDeps is _pyproject_deps: PEP 621 dependencies, build-system requires, optional
// dependency groups and PEP 735 dependency groups (in document order, from md), plus the
// malformed shapes as messages.
func pyprojectDeps(m map[string]any, md toml.MetaData) ([]Dep, []string) {
	deps, bad := []Dep{}, []string{}
	project, _ := m["project"].(map[string]any)
	if raw := m["project"]; raw != nil && !isMap(raw) {
		bad = append(bad, "project not a table")
	}
	groups := []any{project["dependencies"], nil}
	if bs, ok := m["build-system"].(map[string]any); ok {
		groups[1] = bs["requires"]
	}
	if dyn, ok := project["dynamic"].([]any); ok {
		for _, f := range [...]string{"dependencies", "optional-dependencies"} {
			if slices.Contains(dyn, any(f)) {
				bad = append(bad, f+" is dynamic")
			}
		}
		if slices.ContainsFunc(dyn, func(x any) bool { _, ok := x.(string); return !ok }) {
			bad = append(bad, "dynamic has a non-string entry")
		}
	} else if project["dynamic"] != nil {
		bad = append(bad, "dynamic not a list")
	}
	if tool, ok := m["tool"].(map[string]any); ok {
		if _, poetry := tool["poetry"]; poetry {
			bad = append(bad, "tool.poetry dependencies not modeled")
		}
	}
	for _, nt := range []struct {
		table any
		path  []string
	}{{project["optional-dependencies"], []string{"project", "optional-dependencies"}}, {m["dependency-groups"], []string{"dependency-groups"}}} {
		if t, ok := nt.table.(map[string]any); ok {
			for _, k := range tableKeys(md, t, nt.path...) {
				groups = append(groups, t[k])
			}
		} else if nt.table != nil {
			bad = append(bad, nt.path[len(nt.path)-1]+" not a table")
		}
	}
	for _, g := range groups {
		l, ok := g.([]any)
		if !ok {
			if g != nil {
				bad = append(bad, "non-list dependency group")
			}
			continue
		}
		for _, x := range l {
			s, ok := x.(string)
			if !ok {
				bad = append(bad, pytext.Head(pyStr(x), 80))
				continue
			}
			if d := reqDep(s, nil); d != nil {
				deps = append(deps, *d)
			} else {
				bad = append(bad, pytext.Head(s, 80))
			}
		}
	}
	return deps, bad
}

// npmPinRE is the npm exact-version pattern of _npm_deps.
var npmPinRE = regexp.MustCompile(`^[=v]?\p{Nd}+\.\p{Nd}+\.\p{Nd}+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\z`)

func npmPinned(spec string) bool {
	if strings.HasPrefix(spec, "npm:") { // an alias pins through the version after its last '@'
		at := strings.LastIndex(spec, "@")
		return at >= 0 && utf8.RuneCountInString(spec[:at]) > 4 && npmPinRE.MatchString(spec[at+1:])
	}
	return npmPinRE.MatchString(spec)
}

// npmDeps is _npm_deps over a decoded package.json; text supplies the document order of each
// section's entries, which Python's dict keeps and a Go map does not.
func npmDeps(cfg any, text string) ([]Dep, []string) {
	m, ok := cfg.(map[string]any)
	if !ok {
		return []Dep{}, []string{"package.json is not a JSON object"}
	}
	deps, bad := []Dep{}, []string{}
	var sections map[string]json.RawMessage
	json.Unmarshal([]byte(text), &sections)
	for _, section := range [...]string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		block := m[section]
		if block == nil {
			continue
		}
		obj, ok := block.(map[string]any)
		if !ok {
			bad = append(bad, section+" not an object")
			continue
		}
		for _, name := range objectKeys(sections[section]) {
			spec, ok := obj[name].(string)
			if !ok {
				bad = append(bad, name+" non-string version")
				continue
			}
			deps = append(deps, Dep{Name: name, Specifier: spec, Pinned: npmPinned(spec), Raw: name + "@" + spec})
		}
	}
	return deps, bad
}

// objectKeys lists a JSON object's keys in document order, first occurrence of each.
func objectKeys(raw json.RawMessage) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.Token() // {
	seen := map[string]bool{}
	var keys []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			break
		}
		k, _ := t.(string)
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
		var skip json.RawMessage
		dec.Decode(&skip)
	}
	return keys
}
