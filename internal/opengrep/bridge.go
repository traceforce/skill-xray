package opengrep

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/codelane"
	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/grants"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pyast"
	"github.com/traceforce/skill-xray/internal/pytext"
)

const maxPostfiltersPerTarget = 32 // _MAX_POSTFILTERS_PER_TARGET

var engineSeverity = map[string]string{"ERROR": "high", "WARNING": "medium", "INFO": "low"}

// pyStr is str(v or "") for the scalar engine fields the bridge stringifies.
// ponytail: a container rendered here would take Go's spelling, not Python's repr; OpenGrep
// emits strings.
func pyStr(v any) string {
	switch {
	case !pytext.Truthy(v):
		return ""
	case v == true:
		return "True"
	}
	return fmt.Sprint(v)
}

// ruleID is _rule_id: the check id from its last "skill-xray." on.
func ruleID(raw any) string {
	value := pyStr(raw)
	if i := strings.LastIndex(value, "skill-xray."); i >= 0 {
		return value[i:]
	}
	return value
}

// remapEnginePaths is _remap_engine_paths: a deep copy in which every "path" string becomes
// the selected code's rel (or the bare target name when unknown).
func remapEnginePaths(v any, targets map[string]Selected) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = remapEnginePaths(item, targets)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			if s, ok := item.(string); ok && k == "path" {
				name := targetName(s)
				if target, ok := targets[name]; ok {
					out[k] = target.Rel
				} else {
					out[k] = name
				}
				continue
			}
			out[k] = remapEnginePaths(item, targets)
		}
		return out
	}
	return v
}

// location is _location: the 1-based result line and the bounded start/end evidence.
func location(result map[string]any, target Selected) (int, map[string]any, bool) {
	start, _ := result["start"].(map[string]any)
	end, _ := result["end"].(map[string]any)
	line, ok := start["line"].(int)
	if !ok || line < 1 || line > strings.Count(target.Text, "\n")+1 {
		return 0, nil, false
	}
	bounded := func(v any, minimum int) any {
		if i, ok := v.(int); ok && i >= minimum {
			return i
		}
		return nil
	}
	return line, map[string]any{
		"start": map[string]any{"line": line, "col": bounded(start["col"], 1), "offset": bounded(start["offset"], 0)},
		"end":   map[string]any{"line": bounded(end["line"], 1), "col": bounded(end["col"], 1), "offset": bounded(end["offset"], 0)},
	}, true
}

// fenceSources caches each fence target's generated and original lines for one report.
type fenceSources map[string][2][]string

// fenceRegion is _fence_region: prove the generated UTF-8 positions against the original
// same-line Markdown. Markdown already extracted the code; a suffix comparison recovers only
// the removed container prefix. Tabs and transformed/ambiguous spans stay unlocated.
func fenceRegion(target Selected, name string, p *parse.Package, start, end any, cache fenceSources) (map[string]any, error) {
	var artifact *parse.Artifact
	if p != nil {
		artifact = p.ByRel[target.Rel]
	}
	if artifact == nil || artifact.Text == nil {
		return nil, errors.New("fence source unavailable")
	}
	lines, ok := cache[name]
	if !ok {
		lines = [2][]string{strings.Split(target.Text, "\n"), strings.Split(*artifact.Text, "\n")}
		cache[name] = lines
	}
	generated, original := lines[0], lines[1]
	type point struct{ line, char, col int }
	var points [2]point
	for i, position := range []any{start, end} {
		pos, ok := position.(map[string]any)
		if !ok {
			return nil, errors.New("invalid fence position")
		}
		line, lineOK := pos["line"].(int)
		col, colOK := pos["col"].(int)
		if !lineOK || !colOK || line < 1 || line > min(len(generated), len(original)) {
			return nil, errors.New("invalid fence position")
		}
		encoded := generated[line-1]
		if col < 1 || col > len(encoded)+1 || !utf8.ValidString(encoded[:col-1]) {
			return nil, errors.New("invalid fence column")
		}
		points[i] = point{line, utf8.RuneCountInString(encoded[:col-1]), col}
	}
	first, last := points[0], points[1]
	if last.line < first.line || last.line == first.line && last.char < first.char {
		return nil, errors.New("inverted fence region")
	}
	n := last.line - first.line + 1
	prefixes := make([]int, n)
	generatedSpan, originalSpan := make([][]rune, n), make([][]rune, n)
	for i := range n {
		source, lifted := original[first.line-1+i], generated[first.line-1+i]
		if lifted == "" || strings.ContainsRune(source, '\t') || strings.ContainsRune(lifted, '\t') || !strings.HasSuffix(source, lifted) {
			return nil, errors.New("unprovable fence prefix")
		}
		prefixes[i] = utf8.RuneCountInString(source) - utf8.RuneCountInString(lifted)
		generatedSpan[i], originalSpan[i] = []rune(lifted), []rune(source)
	}
	generatedSpan[n-1] = generatedSpan[n-1][:last.char]
	generatedSpan[0] = generatedSpan[0][first.char:]
	originalSpan[n-1] = originalSpan[n-1][:prefixes[n-1]+last.char]
	originalSpan[0] = originalSpan[0][prefixes[0]+first.char:]
	if !slices.EqualFunc(generatedSpan, originalSpan, slices.Equal[[]rune]) {
		return nil, errors.New("fence span crosses transformed source")
	}
	byteLen := func(line string, runes int) int { return len(string([]rune(line)[:runes])) }
	return map[string]any{
		"start": map[string]any{"line": first.line, "col": first.col + byteLen(original[first.line-1], prefixes[0])},
		"end":   map[string]any{"line": last.line, "col": last.col + byteLen(original[last.line-1], prefixes[n-1])},
	}, nil
}

// fenceTrace is _fence_trace: map only locations belonging to known generated fence targets.
func fenceTrace(v any, targets map[string]Selected, p *parse.Package, cache fenceSources) (any, error) {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			mapped, err := fenceTrace(item, targets, p, cache)
			if err != nil {
				return nil, err
			}
			out[i] = mapped
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			mapped, err := fenceTrace(item, targets, p, cache)
			if err != nil {
				return nil, err
			}
			out[k] = mapped
		}
		_, hasPath := x["path"]
		_, hasStart := x["start"]
		_, hasEnd := x["end"]
		if hasPath && hasStart && hasEnd {
			name := targetName(x["path"])
			target, ok := targets[name]
			if !ok {
				return nil, errors.New("unknown trace target")
			}
			if target.Origin == "fence" {
				region, err := fenceRegion(target, name, p, x["start"], x["end"], cache)
				if err != nil {
					return nil, err
				}
				maps.Copy(out, region)
			}
		}
		return out, nil
	}
	return v, nil
}

// mapFenceEvidence is _map_fence_evidence: reporting-only remapping, after detection and the
// post-filters have seen the generated coordinates.
func mapFenceEvidence(evidence map[string]any, target Selected, name string, targets map[string]Selected, p *parse.Package, trace any, cache fenceSources) {
	evidence["engine_location"] = pytext.DeepCopy(map[string]any{"start": evidence["start"], "end": evidence["end"]})
	evidence["location_mapping"] = "unvalidated"
	if region, err := fenceRegion(target, name, p, evidence["start"], evidence["end"], cache); err == nil {
		maps.Copy(evidence, region)
		evidence["location_mapping"] = "validated"
	}
	if !pytext.Truthy(trace) {
		return
	}
	evidence["engine_dataflow_trace"] = pytext.DeepCopy(evidence["dataflow_trace"])
	evidence["trace_mapping"] = "unvalidated"
	if mapped, err := fenceTrace(trace, targets, p, cache); err == nil {
		evidence["dataflow_trace"] = remapEnginePaths(mapped, targets)
		evidence["trace_mapping"] = "validated"
	}
}

// validMetavars checks the metavars shape; malformed is true for anything but a dict of dicts
// whose abstract_content, when present, is a string.
func validMetavars(v any) (metavars map[string]any, malformed bool) {
	if v == nil {
		return nil, false
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, true
	}
	for _, match := range m {
		md, ok := match.(map[string]any)
		if !ok {
			return nil, true
		}
		if ac, present := md["abstract_content"]; present {
			if _, isStr := ac.(string); !isStr {
				return nil, true
			}
		}
	}
	return m, false
}

// emptyValue is `value is None or isinstance(value, str) and not value.strip()`.
func emptyValue(v any) bool {
	s, isStr := v.(string)
	return v == nil || isStr && pytext.Strip(s) == ""
}

// observe validates one capability observation; a panic in a validator is "validation-error".
func observe(target Selected, name, capability string, line, col int, p *parse.Package, trees map[string]*pyast.Module) (valid tri, reason string) {
	defer func() {
		if recover() != nil {
			valid, reason = triNone, "validation-error"
		}
	}()
	return validatedCapability(target, name, capability, line, col, p, trees), "observation-unvalidated"
}

// FindingsFromReport is findings_from_report: translate OpenGrep's stable JSON result shape
// into native findings. observations, when non-nil, collects the capability observations;
// redactions are replaced by "<local>" in engine error messages.
func FindingsFromReport(report map[string]any, targets map[string]Selected, p *parse.Package, redactions []string, observations *[]map[string]any) []findings.Finding {
	out := []findings.Finding{}
	pythonTrees := map[string]*pyast.Module{}
	observationTrees := map[string]*pyast.Module{}
	postfilterCounts, capabilityCounts, observationCounts := map[string]int{}, map[string]int{}, map[string]int{}
	sources := fenceSources{} // split each captured source once across findings and trace steps
	var manifests map[string]*parse.Artifact
	if p != nil {
		manifests = parse.ManifestIndex(p)
	}
	invalid := func(message, path string) findings.Finding {
		return coverage("opengrep-invalid-output", message, path)
	}
	notDict := func(v any) bool { _, ok := v.(map[string]any); return !ok }

	rawResults, present := report["results"]
	if !present {
		rawResults = []any{}
	}
	results, ok := rawResults.([]any)
	if !ok {
		return []findings.Finding{invalid("OpenGrep returned JSON with an unexpected result shape.", "")}
	}
	rawErrors, present := report["errors"]
	if !present {
		rawErrors = []any{}
	}
	errs, ok := rawErrors.([]any)
	if !ok {
		out = append(out, invalid("OpenGrep returned JSON with an unexpected error shape.", ""))
		errs = nil
	}
	if slices.ContainsFunc(results, notDict) {
		out = append(out, invalid("OpenGrep returned a malformed result entry.", ""))
	}
	if slices.ContainsFunc(errs, notDict) {
		out = append(out, invalid("OpenGrep returned a malformed error entry.", ""))
	}

	for _, raw := range results {
		result, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name := targetName(result["path"])
		target, ok := targets[name]
		if !ok {
			out = append(out, coverage("opengrep-unmapped-target", "OpenGrep returned a result for an unknown temporary target.", ""))
			continue
		}
		extra, _ := result["extra"].(map[string]any)
		metadata, _ := extra["metadata"].(map[string]any)
		vector, vectorOK := metadata["skill_xray_vector"].(string)
		rule, ruleOK := metadata["skill_xray_rule"].(string)
		if _, known := findings.Vectors[vector]; !vectorOK || !known || !ruleOK {
			checkID, present := result["check_id"]
			if !present {
				checkID = "?"
			}
			out = append(out, coverage("opengrep-unmapped-rule",
				fmt.Sprintf("OpenGrep rule `%s` has no valid Skill Xray mapping.", ruleID(checkID)), target.Rel))
			continue
		}
		severity, _ := metadata["skill_xray_severity"].(string)
		switch severity {
		case "critical", "high", "medium", "low":
		default:
			severity = cmp.Or(engineSeverity[strings.ToUpper(pyStr(extra["severity"]))], "medium")
		}
		// An installer-shaped HTTPS fetch (`curl https://cli.vendor.com/install.sh | sh`) is an
		// unpinned remote install, not a dropper: keep the finding, report it at medium. The
		// whole matched line is required so a TLS-bypass flag cannot hide inside the pattern's `...`.
		installer := false
		if rule == "opengrep-shell-fetch-pipe-exec" && (severity == "critical" || severity == "high") {
			if lines, ok := extra["lines"].(string); ok && pytext.Strip(lines) != "" && codelane.InstallerIdiom(lines) {
				severity, installer = "medium", true
			}
		}
		// A script reading the skill's own install directory is not snooping on another agent:
		// keep the finding, report it at medium.
		ownPath := false
		if rule == "opengrep-agent-config-read" && severity == "high" {
			if lines, ok := extra["lines"].(string); ok && codelane.OwnInstallPath(lines, parse.GoverningManifest(manifests, target.Rel)) {
				severity, ownPath = "medium", true
			}
		}
		line, loc, ok := location(result, target)
		if !ok {
			out = append(out, invalid("OpenGrep returned a result with an invalid source location.", target.Rel))
			continue
		}
		colValue := loc["start"].(map[string]any)["col"]
		col, _ := colValue.(int)
		metavars, malformed := validMetavars(extra["metavars"])
		if malformed {
			out = append(out, invalid("OpenGrep returned malformed metavariable evidence.", target.Rel))
		}
		var manifest *parse.Artifact
		var declared []string
		capability, isStr := metadata["skill_xray_capability"].(string)
		observed := metadata["skill_xray_capability"] != nil
		if observed {
			if !isStr || capability != "execution" && capability != "network" || p == nil {
				out = append(out, coverage("opengrep-unmapped-rule", "OpenGrep capability observation has no valid correlation mapping.", target.Rel))
				continue
			}
			if observations != nil {
				// Optional context cannot consume finding-validation budgets or populate its cache.
				count := observationCounts[name]
				observationCounts[name] = count + 1
				valid, reason := triNone, "validation-budget"
				if count < maxPostfiltersPerTarget {
					reason = "observation-unvalidated"
					if !malformed {
						valid, reason = observe(target, name, capability, line, col, p, observationTrees)
					}
				}
				if valid != triFalse && count <= maxPostfiltersPerTarget {
					hit := map[string]any{
						"path": target.Rel, "line": line, "column": colValue, "capability": capability, "state": "unknown",
						"analyzer": "opengrep", "rule": rule, "vector": vector,
						"engine_rule": ruleID(result["check_id"]), "origin": target.Origin,
					}
					if valid == triTrue {
						hit["state"] = "present"
					} else {
						hit["reason"] = reason
					}
					*observations = append(*observations, hit)
				}
			}
			manifest = parse.GoverningManifest(manifests, target.Rel)
			if manifest == nil {
				continue
			}
			incomplete := func(message string, evidence map[string]any) {
				out = append(out, findings.Finding{Rule: "analysis-incomplete", Severity: "high", Path: target.Rel, Message: message, Evidence: evidence})
			}
			unparsed := map[string]any{"phase": "correlation", "reason": "capability-declaration-unparsed", "manifest": manifest.Rel, "observed_capability": capability}
			diagnostic := func(code, detail string) bool {
				return slices.ContainsFunc(manifest.Diagnostics, func(d parse.Diagnostic) bool {
					return d.Code == code && (detail == "" || d.Detail != nil && *d.Detail == detail)
				})
			}
			if diagnostic("frontmatter_parse_error", "") {
				incomplete(fmt.Sprintf("observed %s capability could not be compared because the governing frontmatter is invalid", capability), unparsed)
				continue
			}
			allowed, hasAllowed := manifest.Frontmatter["allowed-tools"]
			denied, hasDenied := manifest.Frontmatter["disallowed-tools"]
			if !hasAllowed && !hasDenied {
				continue
			}
			malformedEmpty := hasAllowed && emptyValue(allowed) || hasDenied && emptyValue(denied)
			if malformedEmpty || diagnostic("grants_unparsed_shape", "allowed-tools") || diagnostic("grants_unparsed_shape", "disallowed-tools") ||
				slices.ContainsFunc(manifest.Grants, func(g parse.Grant) bool { return !g.Parsed }) {
				incomplete(fmt.Sprintf("observed %s capability could not be compared with the malformed governing declaration", capability), unparsed)
				continue
			}
			if !hasAllowed && !grants.Denied(manifest.Grants)[capability] {
				continue
			}
			if grants.Declared(manifest.Grants)[capability] {
				continue
			}
			// Only spend the AST validation budget once the capability is actually understated.
			if target.Suffix == ".py" {
				count := capabilityCounts[name]
				capabilityCounts[name] = count + 1
				if count >= maxPostfiltersPerTarget {
					// SXV-033 needs confirmed behavior; past the budget fail visible, do not assert.
					incomplete(fmt.Sprintf("observed %s capability could not be validated within the per-file budget", capability),
						map[string]any{"phase": "correlation", "reason": "capability-validation-budget", "observed_capability": capability})
					continue
				}
				if validatedCapability(target, name, capability, line, col, p, pythonTrees) != triTrue {
					continue
				}
			}
			declared = []string{}
			for _, g := range grants.Effective(manifest.Grants) {
				if g.Tool != "" {
					declared = append(declared, g.Tool)
				}
			}
			slices.Sort(declared)
		}
		needsPostfilter := pyTaintVectors[vector] && target.Suffix == ".py" && !malformed
		postfilterSkipped, dynamicExplicitShell := false, false
		if needsPostfilter {
			count := postfilterCounts[name]
			postfilterCounts[name] = count + 1
			postfilterSkipped = count >= maxPostfiltersPerTarget
			// After the reject-only validation budget, retain engine findings.
			if !postfilterSkipped {
				if _, seen := pythonTrees[name]; !seen {
					pythonTrees[name] = parsePython(target.Text)
				}
				status, explicit := triTrue, false
				if tree := pythonTrees[name]; tree != nil {
					status, explicit = subprocessShellStatus(tree, line, col)
				}
				if status == triFalse {
					continue
				}
				dynamicExplicitShell = status == triNone && explicit
				if status == triNone && !explicit {
					out = append(out, findings.Finding{Rule: "analysis-incomplete", Severity: "high", Path: target.Rel, Line: findings.Int(line),
						Message:  "A tainted subprocess flow uses unresolved keyword arguments; execution eligibility could not be proven.",
						Evidence: map[string]any{"engine": "opengrep", "reason": "dynamic-subprocess-kwargs", "origin": target.Origin}})
					continue
				}
				if pythonDefiniteFalsePositive(extra, name, target, vector, line, col, pythonTrees) {
					continue
				}
			}
		}
		evidence := map[string]any{"engine": "opengrep", "engine_rule": ruleID(result["check_id"]), "origin": target.Origin,
			"start": loc["start"], "end": loc["end"]}
		if installer {
			evidence["installer_idiom"] = "https-named-installer"
		}
		if ownPath {
			evidence["own_install_path"] = true
		}
		if observed {
			tools := []any{"(none)"}
			if len(declared) > 0 {
				tools = make([]any, 0, len(declared))
				for _, tool := range declared {
					tools = append(tools, tool)
				}
			}
			evidence["understated_capability"], evidence["manifest"], evidence["declared_tools"] = capability, manifest.Rel, tools
		}
		if postfilterSkipped {
			evidence["postfilter"] = "retained-after-validation-budget"
		}
		if needsPostfilter && dynamicExplicitShell {
			evidence["shell_validation"] = "dynamic-explicit-shell-retained"
		}
		for _, pair := range []struct {
			source any
			key    string
		}{{extra["fingerprint"], "fingerprint"}, {metavars, "metavars"}, {extra["dataflow_trace"], "dataflow_trace"}} {
			if pytext.Truthy(pair.source) {
				evidence[pair.key] = remapEnginePaths(pair.source, targets)
			}
		}
		if target.Origin == "fence" {
			mapFenceEvidence(evidence, target, name, targets, p, extra["dataflow_trace"], sources)
		}
		var column *int
		if evidence["location_mapping"] != any("unvalidated") {
			if c, ok := evidence["start"].(map[string]any)["col"].(int); ok {
				column = findings.Int(c)
			}
		}
		message := pytext.Head(cmp.Or(pyStr(extra["message"]), "OpenGrep detected a tainted flow."), 800)
		if observed {
			message = fmt.Sprintf("governing manifest %s does not declare observed %s capability", manifest.Rel, capability)
		} else if ownPath {
			message = "The script reads its own install directory under an agent's configuration root."
		}
		out = append(out, findings.Finding{Vector: vector, Rule: rule, Severity: severity, Path: target.Rel,
			Line: findings.Int(line), Column: column, Message: message, Evidence: evidence})
	}

	for _, raw := range errs {
		e, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		path := ""
		if target, ok := targets[targetName(e["path"])]; ok {
			path = target.Rel
		}
		detail := cmp.Or(pyStr(e["message"]), pyStr(e["type"]), "unknown error")
		for _, prefix := range redactions {
			detail = strings.ReplaceAll(detail, prefix, "<local>")
		}
		out = append(out, coverage("opengrep-analysis-error", "OpenGrep could not fully analyze selected code: "+pytext.Head(detail, 500), path))
	}
	return findings.Dedupe(out)
}
