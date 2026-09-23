package findings

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
)

// Finding is one proven finding: Vector links to the registry, Rule is a short slug,
// Severity is this instance's severity, Line/Column are 1-based, Offset/Length locate a
// byte span. nil position fields are Python None; Offset 0 is a real value.
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
	Evidence map[string]any `json:"evidence,omitempty"`
}

func Int(v int) *int { return &v }

type Meta struct {
	Title string   `json:"title"`
	CWE   []string `json:"cwe"`
	Tier  string   `json:"tier"`
}

// Cap is the per-(path, vector-or-rule) finding cap.
const Cap = 25

// critical > high > medium > low; unknown sorts last.
var SeverityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

func Rank(sev string, missing int) int {
	if r, ok := SeverityRank[sev]; ok {
		return r
	}
	return missing
}

// ToMap is Python Finding.to_dict: positions only when set, evidence only when non-empty,
// title/cwe/tier only when the vector is registered.
func (f Finding) ToMap() map[string]any {
	d := map[string]any{"vector": f.Vector, "rule": f.Rule, "severity": f.Severity,
		"path": f.Path, "message": f.Message}
	for k, v := range map[string]*int{"line": f.Line, "column": f.Column, "offset": f.Offset, "length": f.Length} {
		if v != nil {
			d[k] = *v
		}
	}
	if len(f.Evidence) > 0 {
		d["evidence"] = f.Evidence
	}
	if m, ok := Vectors[f.Vector]; ok {
		d["title"], d["cwe"], d["tier"] = m.Title, m.CWE, m.Tier
	}
	return d
}

// MarshalJSON emits ToMap in Python key order: struct field order, omitempty for
// positions and evidence, a nil *Meta for unregistered vectors.
func (f Finding) MarshalJSON() ([]byte, error) {
	type plain Finding
	var meta *Meta
	if m, ok := Vectors[f.Vector]; ok {
		meta = &m
	}
	return json.Marshal(struct {
		plain
		*Meta
	}{plain(f), meta})
}

// engineOccurrence is Python _engine_occurrence: nil unless the evidence is an unvalidated
// OpenGrep location with dict start/end, then the six coordinates with -1 for non-ints.
func engineOccurrence(f Finding) []int {
	if f.Evidence["engine"] != any("opengrep") || f.Evidence["location_mapping"] != any("unvalidated") {
		return nil
	}
	location, ok := f.Evidence["engine_location"].(map[string]any)
	if !ok {
		return nil
	}
	var positions []int
	for _, boundary := range []string{"start", "end"} {
		point, ok := location[boundary].(map[string]any)
		if !ok {
			return nil
		}
		for _, key := range []string{"line", "col", "offset"} {
			v, ok := point[key].(int)
			if !ok {
				v = -1
			}
			positions = append(positions, v)
		}
	}
	return positions
}

func orMinusOne(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

func compare(a, b Finding) int {
	return cmp.Or(
		cmp.Compare(Rank(a.Severity, 9), Rank(b.Severity, 9)),
		cmp.Compare(a.Path, b.Path),
		cmp.Compare(a.Vector, b.Vector),
		cmp.Compare(orMinusOne(a.Line), orMinusOne(b.Line)),
		cmp.Compare(orMinusOne(a.Column), orMinusOne(b.Column)),
		cmp.Compare(orMinusOne(a.Offset), orMinusOne(b.Offset)),
		cmp.Compare(a.Rule, b.Rule),
		cmp.Compare(a.Message, b.Message),
		slices.Compare(engineOccurrence(a), engineOccurrence(b)),
	)
}

// Sort returns a new slice: most severe first, then path/vector/location. Stable.
func Sort(fs []Finding) []Finding {
	out := slices.Clone(fs)
	slices.SortStableFunc(out, compare)
	return out
}

type dedupeKey struct {
	vector, path, rule, message string
	line, column, offset        [2]int
	occurrence                  [7]int
}

func optional(p *int) [2]int {
	if p == nil {
		return [2]int{}
	}
	return [2]int{1, *p}
}

// Dedupe drops exact duplicates (same vector, path, location, rule, message, engine
// occurrence; severity excluded) keeping the first in sorted order.
func Dedupe(fs []Finding) []Finding {
	seen := map[dedupeKey]bool{}
	out := []Finding{}
	for _, f := range Sort(fs) {
		k := dedupeKey{f.Vector, f.Path, f.Rule, f.Message,
			optional(f.Line), optional(f.Column), optional(f.Offset), [7]int{}}
		occ := engineOccurrence(f)
		k.occurrence[0] = len(occ)
		copy(k.occurrence[1:], occ)
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

// CapFindings keeps at most Cap findings per (path, vector-or-rule) and reports each
// suppression as a low "findings-capped" finding, in first-seen group order.
func CapFindings(fs []Finding) []Finding {
	type key struct{ path, group string }
	kept := []Finding{}
	counts := map[key]int{}
	var order []key
	for _, f := range Dedupe(fs) {
		group := f.Vector
		if group == "" {
			group = f.Rule
		}
		if f.Vector == "SXV-033" {
			if capability, _ := f.Evidence["understated_capability"].(string); capability != "" {
				group = group + ":" + capability
			}
		}
		k := key{f.Path, group}
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
		if counts[k] <= Cap {
			kept = append(kept, f)
		}
	}
	for _, k := range order {
		if count := counts[k]; count > Cap {
			kept = append(kept, Finding{Rule: "findings-capped", Severity: "low", Path: k.path,
				Message: fmt.Sprintf("%d more %s findings in %s were suppressed (cap %d per file)",
					count-Cap, k.group, k.path, Cap)})
		}
	}
	return kept
}
