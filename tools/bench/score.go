package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
)

var (
	highOrCritical = map[string]bool{"high": true, "critical": true}
	mediumOrAbove  = map[string]bool{"medium": true, "high": true, "critical": true}
	attackTiers    = map[string]bool{"T1": true, "T2": true}
	// an LLM lane that gave no verdict leaves the record unanalyzed; truncation does not
	llmFailed = map[string]bool{"llm-error": true, "llm-unavailable": true, "llm-budget": true,
		"llm-unparseable": true, "llm-inconclusive": true}
)

func (f finding) attack() bool { return f.Tier != nil && attackTiers[*f.Tier] }

// real keeps the findings that name a vector. Under effective, a suppressed result drops out and
// a result an LLM review demoted scores at its effective severity.
func real(fs []finding, effective bool) []finding {
	var out []finding
	for _, f := range fs {
		if f.Vector == "" || effective && f.Disposition == "suppressed" {
			continue
		}
		if effective && f.EffectiveSeverity != "" {
			f.Severity = f.EffectiveSeverity
		}
		out = append(out, f)
	}
	return out
}

type verdict struct {
	name    string
	flagged func([]finding) bool
}

// verdicts are the package-level definitions, the first being the headline: only a T1 or T2
// vector at high or critical severity flags a package. The other views include every tier.
func verdicts(effective bool) []verdict {
	anyOf := func(keep func(finding) bool) func([]finding) bool {
		return func(fs []finding) bool { return slices.ContainsFunc(real(fs, effective), keep) }
	}
	return []verdict{
		{"blocking (T1/T2 and high/critical)", anyOf(func(f finding) bool { return f.attack() && highOrCritical[f.Severity] })},
		{"high/critical any tier", anyOf(func(f finding) bool { return highOrCritical[f.Severity] })},
		{"medium+ any tier", anyOf(func(f finding) bool { return mediumOrAbove[f.Severity] })},
		{"any finding", anyOf(func(finding) bool { return true })},
	}
}

// incomplete reports a scan that did not complete, so a benign record without a finding is not
// a verified true negative: an error, an oversize or skipped file, a high-severity note without
// a vector, or an LLM lane that gave no verdict.
func incomplete(r row) bool {
	if r.Error != nil && *r.Error != "" || r.Oversize || r.LedgerSkipped != 0 {
		return true
	}
	return slices.ContainsFunc(r.Findings, func(f finding) bool {
		return f.Vector == "" && (f.Severity == "high" || llmFailed[f.Rule])
	})
}

type metric struct {
	TP, FP, TN, FN, Unanalyzed int
	Precision, Recall, F1, FPR float64
}

func metrics(rows []row, flagged func([]finding) bool) metric {
	var m metric
	for _, r := range rows {
		hit := flagged(r.Findings)
		switch {
		case r.Label == 1 && hit:
			m.TP++
		case r.Label == 1: // an unscanned attack is a miss, not a pass
			m.FN++
		case hit: // a positive prediction counts, complete or not
			m.FP++
		case incomplete(r): // an unscanned benign record is not a verified true negative
			m.Unanalyzed++
		default:
			m.TN++
		}
	}
	m.Precision = ratio(m.TP, m.TP+m.FP)
	m.Recall = ratio(m.TP, m.TP+m.FN)
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	m.FPR = ratio(m.FP, m.FP+m.TN)
	return m
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// counter counts keys and lists them by count, ties by key, so a report does not depend on the
// order the rows were written in.
type counter struct {
	order []string
	n     map[string]int
}

func (c *counter) add(k string) {
	if c.n == nil {
		c.n = map[string]int{}
	}
	if _, seen := c.n[k]; !seen {
		c.order = append(c.order, k)
	}
	c.n[k]++
}

func (c *counter) mostCommon(limit int) []string {
	keys := slices.Clone(c.order)
	slices.SortFunc(keys, func(a, b string) int { return cmp.Or(cmp.Compare(c.n[b], c.n[a]), cmp.Compare(a, b)) })
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	return keys
}

type analysis struct {
	fpVectors, fpRules, fpSources, fnSources counter
	t3OnlyBenign                             int
	caught, total                            map[string]int // by attack category
}

// analyze ranks what drives the blocking false positives and what the misses look like.
func analyze(rows []row, blocking func([]finding) bool, effective bool) analysis {
	a := analysis{caught: map[string]int{}, total: map[string]int{}}
	for _, r := range rows {
		if r.Label != 0 {
			continue
		}
		fs := real(r.Findings, effective)
		switch {
		case blocking(r.Findings):
			a.fpSources.add(r.SourceName)
			seenVector, seenRule := map[string]bool{}, map[string]bool{}
			for _, f := range fs {
				if !f.attack() || !highOrCritical[f.Severity] {
					continue
				}
				if !seenVector[f.Vector] {
					seenVector[f.Vector] = true
					a.fpVectors.add(f.Vector)
				}
				if rule := f.Vector + " / " + f.Rule; !seenRule[rule] {
					seenRule[rule] = true
					a.fpRules.add(rule)
				}
			}
		case len(fs) > 0 && !slices.ContainsFunc(fs, finding.attack):
			a.t3OnlyBenign++
		}
	}
	for _, r := range rows {
		if r.Label != 1 {
			continue
		}
		hit := blocking(r.Findings)
		if !hit {
			a.fnSources.add(r.SourceName)
		}
		for _, c := range categories(r) {
			a.total[c]++
			if hit {
				a.caught[c]++
			}
		}
	}
	return a
}

func categories(r row) []string {
	if len(r.AttackCategories) == 0 {
		return []string{"(unmapped)"}
	}
	return r.AttackCategories
}

// hot is the set of vectors that flag a package under the headline verdict.
func hot(fs []finding, effective bool) map[string]bool {
	out := map[string]bool{}
	for _, f := range real(fs, effective) {
		if f.attack() && highOrCritical[f.Severity] {
			out[f.Vector] = true
		}
	}
	return out
}

func report(rows []row, title string, effective bool) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	table := func(header string, c counter, limit int) {
		line("")
		line("| %s |", header)
		line("|---|---|")
		for _, k := range c.mostCommon(limit) {
			line("| %s | %d |", k, c.n[k])
		}
	}
	malicious, benign, errs, oversize := 0, 0, 0, 0
	var errKinds counter
	for _, r := range rows {
		switch r.Label {
		case 1:
			malicious++
		case 0:
			benign++
		}
		if r.Error != nil {
			errs++
			kind, _, _ := strings.Cut(*r.Error, ":")
			errKinds.add(kind)
		}
		if r.Oversize {
			oversize++
		}
	}
	line("# %s", title)
	line("")
	line("records: %d  (malicious %d / benign %d)  errors: %d  oversize: %d", len(rows), malicious, benign, errs, oversize)
	line("")
	line("| verdict | TP | FP | TN | FN | precision | recall | F1 | FPR |")
	line("|---|---|---|---|---|---|---|---|---|")
	vs := verdicts(effective)
	for _, v := range vs {
		m := metrics(rows, v.flagged)
		line("| %s | %d | %d | %d | %d | %.2f%% | %.2f%% | %.2f%% | %.2f%% |", v.name, m.TP, m.FP, m.TN, m.FN,
			100*m.Precision, 100*m.Recall, 100*m.F1, 100*m.FPR)
	}
	if u := metrics(rows, vs[3].flagged).Unanalyzed; u > 0 {
		line("")
		line("benign records whose scan did not complete and that carry no finding, excluded from TN and FPR: %d", u)
	}
	a := analyze(rows, vs[0].flagged, effective)
	line("")
	line("## Where the blocking false positives come from")
	line("benign packages with ONLY T3 capability findings (correctly not counted): %d", a.t3OnlyBenign)
	table("vector | benign FPs", a.fpVectors, 0)
	table("vector / rule | benign FPs", a.fpRules, 25)
	table("benign source | FPs", a.fpSources, 0)
	line("")
	line("## Recall by attack category (blocking verdict)")
	line("")
	line("| attack category | caught / total | recall |")
	line("|---|---|---|")
	cats := slices.Sorted(maps.Keys(a.total))
	slices.SortStableFunc(cats, func(x, y string) int { return cmp.Compare(a.total[y], a.total[x]) })
	for _, c := range cats {
		line("| %s | %d / %d | %.1f%% |", c, a.caught[c], a.total[c], 100*ratio(a.caught[c], a.total[c]))
	}
	table("malicious source | misses", a.fnSources, 0)
	line("")
	line("## Vector hit counts (packages), malicious vs benign")
	line("")
	line("| vector | tier | malicious | benign |")
	line("|---|---|---|---|")
	hits, tiers := map[string][2]int{}, map[string]string{}
	for _, r := range rows {
		seen := map[string]bool{}
		for _, f := range real(r.Findings, effective) {
			tiers[f.Vector] = "None"
			if f.Tier != nil {
				tiers[f.Vector] = *f.Tier
			}
			if !seen[f.Vector] {
				seen[f.Vector] = true
				h := hits[f.Vector]
				if r.Label == 1 {
					h[1]++
				} else {
					h[0]++
				}
				hits[f.Vector] = h
			}
		}
	}
	for _, v := range slices.Sorted(maps.Keys(hits)) {
		line("| %s | %s | %d | %d |", v, tiers[v], hits[v][1], hits[v][0])
	}
	if len(errKinds.order) > 0 {
		line("")
		line("## Errors")
		line("")
		for _, k := range errKinds.mostCommon(0) {
			line("- %s: %d", k, errKinds.n[k])
		}
	}
	return b.String()
}

// compare reports before and after on the same identities. An after run that covers a subset of
// the base identities leaves every other base record unchanged, so the numbers describe the
// whole split rather than the subset.
func compare(rows, base []row, effective bool) (string, error) {
	baseBy, afterBy := map[string]row{}, map[string]row{}
	var order, unknown []string
	for _, r := range base {
		if _, seen := baseBy[r.BenchmarkID]; !seen {
			order = append(order, r.BenchmarkID)
		}
		baseBy[r.BenchmarkID] = r
	}
	for _, r := range rows {
		if _, ok := baseBy[r.BenchmarkID]; ok {
			afterBy[r.BenchmarkID] = r
		} else {
			unknown = append(unknown, r.BenchmarkID)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return "", fmt.Errorf("--compare: %d after-run identities are not in the base run, e.g. %s",
			len(unknown), strings.Join(unknown[:min(3, len(unknown))], ", "))
	}
	if len(rows) > 0 && len(afterBy) == 0 {
		return "", errors.New("--compare: the after-run shares no identity with the base run")
	}
	before, after := make([]row, 0, len(order)), make([]row, 0, len(order))
	for _, id := range order {
		before = append(before, baseBy[id])
		if a, ok := afterBy[id]; ok {
			after = append(after, a)
		} else {
			after = append(after, baseBy[id])
		}
	}
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	carried := ""
	if n := len(order) - len(afterBy); n > 0 {
		carried = fmt.Sprintf(" (%d carried over unchanged from the base run: the after-run is a subset)", n)
	}
	line("")
	line("## Before / after on %d paired identities%s", len(order), carried)
	line("")
	line("| verdict | before P / R / F1 / FPR | after P / R / F1 / FPR | TP FP TN FN before | TP FP TN FN after |")
	line("|---|---|---|---|---|")
	vs := verdicts(effective)
	for _, v := range vs {
		mb, ma := metrics(before, v.flagged), metrics(after, v.flagged)
		line("| %s | %.2f%% / %.2f%% / %.2f%% / %.2f%% | %.2f%% / %.2f%% / %.2f%% / %.2f%% | %d %d %d %d | %d %d %d %d |", v.name,
			100*mb.Precision, 100*mb.Recall, 100*mb.F1, 100*mb.FPR, 100*ma.Precision, 100*ma.Recall, 100*ma.F1, 100*ma.FPR,
			mb.TP, mb.FP, mb.TN, mb.FN, ma.TP, ma.FP, ma.TN, ma.FN)
	}
	blocking := vs[0].flagged
	fpVectors := func(rs []row) map[string]int {
		c := map[string]int{}
		for _, r := range rs {
			if r.Label == 0 && blocking(r.Findings) {
				for v := range hot(r.Findings, effective) {
					c[v]++
				}
			}
		}
		return c
	}
	fb, fa := fpVectors(before), fpVectors(after)
	line("")
	line("| blocking FP vector (benign) | before | after |")
	line("|---|---|---|")
	union := slices.Sorted(maps.Keys(fb))
	for v := range fa {
		if _, ok := fb[v]; !ok {
			union = append(union, v)
		}
	}
	slices.Sort(union)
	for _, v := range union {
		line("| %s | %d | %d |", v, fb[v], fa[v])
	}
	var newTP, lostTP, newFP, fixedFP []row
	for i := range order {
		a, bf := after[i], before[i]
		wasHit, isHit := blocking(bf.Findings), blocking(a.Findings)
		switch {
		case a.Label == 1 && isHit && !wasHit:
			newTP = append(newTP, a)
		case a.Label == 1 && !isHit && wasHit:
			lostTP = append(lostTP, a)
		case a.Label == 0 && isHit && !wasHit:
			newFP = append(newFP, a)
		case a.Label == 0 && !isHit && wasHit:
			fixedFP = append(fixedFP, a)
		}
	}
	line("")
	line("newly caught malicious: %d | malicious lost: %d | benign FPs fixed: %d | new benign FPs: %d",
		len(newTP), len(lostTP), len(fixedFP), len(newFP))
	var carrier, cats counter
	for _, a := range newTP {
		for _, v := range slices.Sorted(maps.Keys(hot(a.Findings, effective))) {
			carrier.add(v)
		}
		for _, c := range categories(a) {
			cats.add(c)
		}
	}
	line("")
	line("| vector carrying the newly caught malicious | packages |")
	line("|---|---|")
	for _, v := range carrier.mostCommon(0) {
		line("| %s | %d |", v, carrier.n[v])
	}
	line("")
	line("| attack category of the newly caught | packages |")
	line("|---|---|")
	for _, c := range cats.mostCommon(0) {
		line("| %s | %d |", c, cats.n[c])
	}
	ids := func(rs []row) string {
		out := make([]string, 0, min(25, len(rs)))
		for _, r := range rs[:min(25, len(rs))] {
			out = append(out, r.BenchmarkID)
		}
		return strings.Join(out, ", ")
	}
	if len(newFP) > 0 {
		line("")
		line("new benign FP ids: %s", ids(newFP))
	}
	if len(lostTP) > 0 {
		line("lost malicious ids: %s", ids(lostTP))
	}
	return b.String(), nil
}

// excludeVectors drops the findings of the named vectors from every row, so a comparison sees
// both runs without them.
func excludeVectors(rows []row, drop map[string]bool) {
	for i := range rows {
		rows[i].Findings = slices.DeleteFunc(rows[i].Findings, func(f finding) bool { return drop[f.Vector] })
	}
}

func cmdScore(args []string) error {
	fs := flag.NewFlagSet("score", flag.ExitOnError)
	md := fs.String("md", "", "also write the report to this file")
	title := fs.String("title", "", "report title (default: the rows file)")
	base := fs.String("compare", "", "a prior run over the same identities; appends a before and after section")
	exclude := fs.String("exclude-vectors", "", "comma-separated vectors dropped before scoring, which rebuilds the view without a detector from the same run")
	effective := fs.Bool("effective", false, "score each result at its effective severity (rows an LLM review wrote)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("score takes one rows file after the flags")
	}
	rows, err := loadRows(fs.Arg(0))
	if err != nil {
		return err
	}
	drop := map[string]bool{}
	for _, v := range strings.Split(*exclude, ",") {
		if v = strings.TrimSpace(v); v != "" {
			drop[v] = true
		}
	}
	excludeVectors(rows, drop)
	if *title == "" {
		*title = fs.Arg(0)
	}
	text := report(rows, *title, *effective)
	if *base != "" {
		baseRows, err := loadRows(*base)
		if err != nil {
			return err
		}
		excludeVectors(baseRows, drop)
		delta, err := compare(rows, baseRows, *effective)
		if err != nil {
			return err
		}
		text += delta
	}
	if *md != "" {
		if err := os.WriteFile(*md, []byte(text), 0o644); err != nil {
			return err
		}
	}
	_, err = os.Stdout.WriteString(text)
	return err
}
