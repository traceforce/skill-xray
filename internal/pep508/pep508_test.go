package pep508

import (
	"cmp"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"
)

// testdata/requirements.json is written by testdata/gen_goldens.py from CPython
// packaging 24.2 and the oracle's hooks._is_exact_pin. Each requirement row
// names the pytest that exercises the input (tests/test_parse.py
// test_requirements_deps_pinned, test_requirements_prefix_range_not_pinned,
// test_requirements_url_continuation_and_comment, test_requirements_vcs_and_local_surfaced,
// test_pyproject_*; tests/test_supply_chain.py test_pep508_*; tests/test_hooks.py
// test_pep508_direct_reference_sha_is_a_pin, test_direct_reference_sha_with_subdir_fragment_is_a_pin,
// test_pep508_file_reference_is_local_pin, test_python_wildcard_pin_is_still_floating,
// test_pinned_or_local_mcp_server_does_not_report_floating_package, test_floating_mcp_package_reports)
// or "edge" for grammar corners from instruction.md 4.4.
type goldens struct {
	Requirements []struct {
		From         string     `json:"from"`
		Input        string     `json:"input"`
		Valid        bool       `json:"valid"`
		Name         string     `json:"name"`
		URL          string     `json:"url"`
		Specifiers   [][]string `json:"specifiers"`
		SpecifierStr string     `json:"specifier_str"`
		Pinned       bool       `json:"pinned"`
	} `json:"requirements"`
	ExactPin []struct {
		Runner string `json:"runner"`
		Spec   string `json:"spec"`
		Pin    *bool  `json:"pin"`
	} `json:"exact_pin"`
}

func load(t *testing.T) goldens {
	t.Helper()
	raw, err := os.ReadFile("testdata/requirements.json")
	if err != nil {
		t.Fatal(err)
	}
	var g goldens
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestParseGoldens(t *testing.T) {
	g := load(t)
	for _, want := range g.Requirements {
		t.Run(want.From+"/"+want.Input, func(t *testing.T) {
			r, err := Parse(want.Input)
			if (err == nil) != want.Valid {
				t.Fatalf("Parse(%q) err=%v, want valid=%v", want.Input, err, want.Valid)
			}
			if !want.Valid {
				return
			}
			if r.Name != want.Name || r.URL != want.URL {
				t.Errorf("name/url = %q/%q, want %q/%q", r.Name, r.URL, want.Name, want.URL)
			}
			specs := make([][]string, 0, len(r.Specifiers))
			for _, s := range r.Specifiers {
				specs = append(specs, []string{s.Op, s.Version})
			}
			slices.SortFunc(specs, func(a, b []string) int { return cmp.Compare(a[0]+a[1], b[0]+b[1]) })
			if !reflect.DeepEqual(specs, append([][]string{}, want.Specifiers...)) {
				t.Errorf("specifiers = %v, want %v", specs, want.Specifiers)
			}
			if s := r.SpecifierString(); s != want.SpecifierStr {
				t.Errorf("SpecifierString = %q, want %q", s, want.SpecifierStr)
			}
			if p := r.Pinned(); p != want.Pinned {
				t.Errorf("Pinned = %v, want %v", p, want.Pinned)
			}
		})
	}
}

func TestIsExactPinGoldens(t *testing.T) {
	g := load(t)
	for _, want := range g.ExactPin {
		t.Run(want.Runner+"/"+want.Spec, func(t *testing.T) {
			if want.Pin == nil {
				t.Skip("oracle raised")
			}
			if got := IsExactPin(want.Runner, want.Spec); got != *want.Pin {
				t.Errorf("IsExactPin(%q, %q) = %v, want %v", want.Runner, want.Spec, got, *want.Pin)
			}
		})
	}
}
