package supplychain

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/traceforce/skill-xray/internal/testutil"
)

// tests/test_wild_precision.py::test_credential_fixture_in_a_test_file_is_medium: a redaction
// test suite asserting that placeholder tokens are hidden.
func TestCredentialFixtureInATestFileIsMedium(t *testing.T) {
	token := "ghp_" + strings.Repeat("a", 36)
	found := testutil.ByVector(check(t, map[string]string{
		"test/sanitize.test.js": "assert.ok(redactString('" + token + "').includes(REDACTED));\n",
		"scripts/deploy.js":     "const token = '" + token + "';\n",
		"tests/publish.js":      "const token = '" + token + "';\n",                     // the path alone is not enough
		"tests/comment.js":      "const token = '" + token + "'; // assert(\n",          // the call must open first
		"tests/wrap.js":         "assert.ok(true); publish('" + token + "');\n",         // and still be open
		"tests/suite.js":        "test('publishes', () => publish('" + token + "'));\n", // not a sink
		"tests/nested.js":       "assert.ok(publish('" + token + "'));\n",               // the innermost call sends it
		"tests/string.js":       "const s = \"assert(\"; publish('" + token + "');\n",   // a string, not code
		"tests/block.js":        "/* assert( */ publish('" + token + "');\n",            // nor is a comment
		"tests/suffix.js":       "reassert('" + token + "'); publish_and_mask('" + token + "');\n",
	}), "SXV-017")
	byPath := map[string]string{}
	for _, f := range found {
		byPath[f.Path] = f.Severity
		if f.Path == "test/sanitize.test.js" {
			assert.Equal(t, true, f.Evidence["test_fixture"])
			assert.Equal(t, false, f.Evidence["fenced_example"])
		}
	}
	assert.Equal(t, map[string]string{
		"test/sanitize.test.js": "medium", "scripts/deploy.js": "high", "tests/publish.js": "high",
		"tests/comment.js": "high", "tests/wrap.js": "high", "tests/suite.js": "high", "tests/nested.js": "high",
		"tests/string.js": "high", "tests/block.js": "high", "tests/suffix.js": "high",
	}, byPath)
}

// tests/test_wild_precision.py::test_the_same_token_asserted_then_sent_keeps_both_positions.
func TestTheSameTokenAssertedThenSentKeepsBothPositions(t *testing.T) {
	token := "ghp_" + strings.Repeat("b", 36)
	found := testutil.ByVector(check(t, map[string]string{
		"tests/twice.js": "assert.ok(redact('" + token + "')); publish('" + token + "');\n",
	}), "SXV-017")
	var severities []string
	for _, f := range found {
		severities = append(severities, f.Severity)
	}
	slices.Sort(severities)
	assert.Equal(t, []string{"high", "medium"}, severities)
}

// tests/test_wild_precision.py::test_fixtures_do_not_push_a_live_token_past_the_cap.
func TestFixturesDoNotPushALiveTokenPastTheCap(t *testing.T) {
	var body strings.Builder
	for i := range 26 {
		fmt.Fprintf(&body, "assert.ok(redact('ghp_%s%04d'));\n", strings.Repeat("a", 32), i)
	}
	fmt.Fprintf(&body, "const token = 'ghp_%s9999';\n", strings.Repeat("a", 32))
	secrets := testutil.ByVector(check(t, map[string]string{"tests/publish.js": body.String()}), "SXV-017")
	var highLines []int
	for _, f := range secrets {
		if f.Severity == "high" {
			highLines = append(highLines, *f.Line)
		}
	}
	assert.Contains(t, highLines, 27)
	assert.Len(t, secrets, 25)
}
