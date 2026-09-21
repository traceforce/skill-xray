// Package preproc reports load-time preprocessing findings (SXV-001 inline bang, SXV-002 bang
// fence) from the parsed IR, Python checks/preproc.py.
package preproc

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

const evidenceLimit = 400

var (
	rootKinds     = map[string]bool{"skill_manifest": true, "agent_identity": true}
	liftableKinds = map[string]bool{"instruction": true, "doc": true}
)

func finding(vector, rule, rel string, tok parse.Preproc, message string, evidence map[string]any) findings.Finding {
	return findings.Finding{Vector: vector, Rule: rule, Severity: "critical", Path: rel,
		Line: findings.Int(tok.Line), Column: findings.Int(tok.Column), Message: message, Evidence: evidence}
}

func inlineFinding(rel string, tok parse.Preproc) findings.Finding {
	command := tok.Code
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(command)))
	return finding("SXV-001", "preproc-inline-bang", rel, tok,
		"inline preprocessing executes `"+pytext.Head(command, 160)+"` while loading the skill, before its instructions are evaluated",
		map[string]any{
			"command_text":   pytext.Head(command, evidenceLimit),
			"command_length": utf8.RuneCountInString(command),
			"command_sha256": digest,
			"truncated":      utf8.RuneCountInString(command) > evidenceLimit,
			"column":         tok.Column,
			"fence_state":    "outside",
			"selector":       "inline-bang:" + digest[:12],
		})
}

func fencedFinding(rel string, tok parse.Preproc) findings.Finding {
	normalized := strings.TrimRight(tok.Code, "\n")
	executable := 0
	for _, line := range strings.Split(normalized, "\n") {
		if pytext.Strip(line) != "" {
			executable++
		}
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(normalized)))
	shown := strings.Split(pytext.Head(normalized, evidenceLimit), "\n")
	return finding("SXV-002", "preproc-fenced-bang", rel, tok,
		fmt.Sprintf("bang-tagged fenced preprocessing executes %d command line(s) while loading the skill", executable),
		map[string]any{
			"command_text":     shown,
			"command_length":   utf8.RuneCountInString(normalized),
			"command_sha256":   digest,
			"truncated":        utf8.RuneCountInString(normalized) > evidenceLimit,
			"column":           tok.Column,
			"fence_info":       tok.Info,
			"block_line_count": executable,
			"selector":         "fenced-bang:" + digest[:12],
		})
}

// Check is preproc.check: one finding per live, non-blank preprocessing token of every loaded
// artifact, plus a findings-capped note per kind whose parser count exceeded the cap.
func Check(p *parse.Package) []findings.Finding {
	var out []findings.Finding
	// the agent loads manifests and identity files plus every instruction/doc they reach over Refs
	loaded := parse.Reach(p, rootKinds, liftableKinds, true)
	for _, a := range p.Artifacts {
		if !loaded[a.Rel] {
			continue
		}
		for _, tok := range a.Preprocessing {
			switch {
			case pytext.Strip(tok.Code) == "":
			case tok.Kind == "inline" && tok.Runs:
				out = append(out, inlineFinding(a.Rel, tok))
			case tok.Kind == "fenced":
				out = append(out, fencedFinding(a.Rel, tok))
			}
		}
		for _, c := range []struct {
			count  int
			vector string
		}{{a.PreprocessingCounts.Inline, "SXV-001"}, {a.PreprocessingCounts.Fenced, "SXV-002"}} {
			if c.count > findings.Cap {
				out = append(out, findings.Finding{Rule: "findings-capped", Severity: "low", Path: a.Rel,
					Message: fmt.Sprintf("%d more %s findings in %s were suppressed (cap %d per file)",
						c.count-findings.Cap, c.vector, a.Rel, findings.Cap)})
			}
		}
	}
	return findings.Sort(out)
}
