package llm

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func lineCount(s string) int { return strings.Count(s, "\n") }

// test_llm_review_core.py::test_escaped_quoted_secret_is_fully_removed (2)
func TestEscapedQuotedSecretIsFullyRemoved(t *testing.T) {
	for _, source := range []string{`password="first\"remaining-sensitive-value"`, `password='first\'remaining-sensitive-value'`} {
		assert.NotContains(t, Redact(source), "remaining-sensitive-value", source)
	}
}

// test_llm_review_core.py::test_yaml_single_quote_escaping_is_redacted_without_losing_lines (3)
func TestYAMLSingleQuoteEscapingIsRedactedWithoutLosingLines(t *testing.T) {
	for _, scalar := range []string{"'first''opaque-value'", "'first''opaque-value''last'", "'first''\n  opaque-value'"} {
		source := "password: " + scalar + "\n"
		redacted := Redact(source + text)
		assert.NotContains(t, redacted, "opaque-value", scalar)
		assert.Equal(t, lineCount(source+text), lineCount(redacted), scalar)
		assert.Contains(t, redacted, text, scalar)
	}
}

// test_llm_review_core.py::test_redaction_keeps_large_nonsecret_tokens_intact
func TestRedactionKeepsLargeNonsecretTokensIntact(t *testing.T) {
	source := strings.Repeat("x", 20000) + "\n" + strings.Repeat("x-", 10000)
	assert.Equal(t, source, Redact(source))
}

// test_llm_review_core.py::test_named_multiline_redaction_preserves_source_locations,
// test_yaml_block_redaction_preserves_source_locations
func TestMultilineRedactionPreservesSourceLocations(t *testing.T) {
	for _, source := range []string{"password=\"first\nsecond\"\n" + text, "api_key: |\n  first\n  second\n" + text} {
		redacted := Redact(source)
		assert.Equal(t, lineCount(source), lineCount(redacted), source)
		assert.NotContains(t, redacted, "first", source)
		assert.NotContains(t, redacted, "second", source)
		assert.Contains(t, redacted, text, source)
	}
}

// test_llm_review_core.py::test_repeated_credential_keywords_do_not_cause_quadratic_redaction (2),
// test_decorated_multiline_redaction_is_bounded_and_keeps_following_text
func TestRedactionIsLinear(t *testing.T) {
	for _, word := range []string{"secret", "api_key"} {
		source := strings.Repeat(word, 20000/len(word))
		start := time.Now()
		assert.Equal(t, source, Redact(source))
		assert.Less(t, time.Since(start), time.Second, word)
	}
	source := `password: !!str &credential "` + strings.Repeat("opaque-value\n", 2000) + "\"\n" + text
	start := time.Now()
	redacted := Redact(source)
	assert.Less(t, time.Since(start), time.Second)
	assert.NotContains(t, redacted, "opaque-value")
	assert.Contains(t, redacted, text)
	assert.Equal(t, lineCount(source), lineCount(redacted))
}

// test_llm_review_core.py::test_decorated_named_yaml_secret_is_fully_redacted (378 cases)
func TestDecoratedNamedYAMLSecretIsFullyRedacted(t *testing.T) {
	for _, key := range []string{"password", `"password"`, "'api_key'"} {
		for _, decoration := range []string{"&credential", "!!str", "!secret", "!", "&credential !!str", "!!str &credential", "!!str\n  "} {
			for _, scalar := range []string{`"opaque-value"`, "'opaque-value'", "opaque-value", "",
				"opaque-value\n  secret-tail", "|\n  opaque-value\n  secret-tail"} {
				for _, prefix := range []string{"", "  ", "  - "} {
					indent := strings.Repeat(" ", len(prefix))
					value := strings.ReplaceAll(decoration+" "+scalar, "\n", "\n"+indent)
					source := prefix + key + ": " + value + "\n" + indent + "instruction: " + text + indent + "secret: other-value\n"
					redacted := Redact(source)
					name := key + "|" + decoration + "|" + scalar + "|" + prefix
					for _, secret := range []string{"opaque-value", "secret-tail", "other-value"} {
						assert.NotContains(t, redacted, secret, name)
					}
					assert.Equal(t, lineCount(source), lineCount(redacted), name)
					assert.Contains(t, redacted, text, name)
				}
			}
		}
	}
}

// test_llm_review_core.py::test_plain_yaml_credential_is_fully_redacted_before_transmission (9,
// redaction half; the transmission half is in adjudicate_test.go)
func TestPlainYAMLCredentialIsFullyRedacted(t *testing.T) {
	for _, scalar := range plainYAMLScalars {
		source := "---\nname: demo\npassword: " + scalar + "\n---\n" + text
		redacted := Redact(source)
		assert.Equal(t, lineCount(source), lineCount(redacted), scalar)
		assert.Contains(t, redacted, text, scalar)
		for _, part := range []string{"correct", "horse", "battery", "staple"} {
			assert.NotContains(t, redacted, part, scalar)
		}
	}
}

var plainYAMLScalars = []string{
	"correct horse battery staple", "correct horse\n  battery staple",
	"correct horse\n\n  battery staple", "correct, horse; battery staple",
	"!!str &credential correct horse\n  battery staple",
	"Bearer correct horse battery staple",
	"\n  correct horse battery staple", "\n\n  correct horse battery staple",
	"!!str\n  correct horse battery staple",
}

// test_llm_shadow.py::test_both_llm_paths_redact_before_transmission (the redaction of each
// secret shape on its own; both lanes are exercised in judge_test.go)
func TestEverySecretShapeIsRedacted(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("SecretBodyForTest", 6) + "\n-----END PRIVATE KEY-----"
	for _, secret := range []string{token, pem, "password='opaque-value'", "password: 'prefix''opaque-value'",
		`password = """opaque-value"""`, "password = '''opaque-value'''", "api_key: |\n  opaque-value\n",
		"password: >-\n  opaque-value\n", "https://user:opaque-value@example.invalid/?token=query-value",
		"Authorization: Bearer abc.def-ghi", "Basic\tZm9v"} {
		redacted := Redact(text + secret)
		for _, value := range []string{token, "SecretBodyForTest", "opaque-value", "query-value", "abc.def-ghi", "Zm9v"} {
			assert.NotContains(t, redacted, value, secret)
		}
		assert.Equal(t, lineCount(text+secret), lineCount(redacted), secret)
		assert.Contains(t, redacted, text, secret)
	}
}
