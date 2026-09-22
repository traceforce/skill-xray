package llm

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func configErr(t *testing.T, err error) {
	var ce *ConfigError
	require.ErrorAs(t, err, &ce)
}

// test_llm.py::test_from_env_disabled_returns_none
func TestFromEnvDisabledReturnsNil(t *testing.T) {
	cfg, err := FromEnv(env(nil))
	require.NoError(t, err)
	assert.Nil(t, cfg)
}

// test_llm.py::test_from_env_bad_provider_raises, test_from_env_missing_key_raises,
// test_from_env_rejects_cleartext_base_url, test_from_env_openai_compatible_needs_base_url,
// test_from_env_no_vendor_key_fallback_to_custom_host, test_from_env_vendor_key_fallback_only_on_vendor_host,
// test_from_env_rejects_hostless_base_url, test_from_env_rejects_base_url_with_query,
// test_from_env_rejects_malformed_url, test_from_env_rejects_invalid_authority (4),
// test_base_url_with_bare_query_or_fragment_is_rejected (2)
func TestFromEnvRejectsMisconfiguration(t *testing.T) {
	compatible := func(base string) map[string]string {
		return map[string]string{"SKILLXRAY_LLM_PROVIDER": "openai-compatible", "SKILLXRAY_LLM_BASE_URL": base,
			"SKILLXRAY_LLM_API_KEY": "k", "SKILLXRAY_LLM_MODEL": "m"}
	}
	cases := map[string]map[string]string{
		"bad_provider":            {"SKILLXRAY_LLM_PROVIDER": "nope"},
		"missing_key":             {"SKILLXRAY_LLM_PROVIDER": "anthropic"},
		"cleartext_base_url":      {"SKILLXRAY_LLM_PROVIDER": "openai", "SKILLXRAY_LLM_API_KEY": "k", "SKILLXRAY_LLM_BASE_URL": "http://example.com"},
		"compatible_needs_base":   {"SKILLXRAY_LLM_PROVIDER": "openai-compatible", "SKILLXRAY_LLM_API_KEY": "k"},
		"no_vendor_key_to_custom": {"SKILLXRAY_LLM_PROVIDER": "openai-compatible", "SKILLXRAY_LLM_BASE_URL": "https://attacker.example", "OPENAI_API_KEY": "sk-vendor"},
		"vendor_key_only_on_host": {"SKILLXRAY_LLM_PROVIDER": "openai", "SKILLXRAY_LLM_BASE_URL": "https://proxy.internal", "OPENAI_API_KEY": "sk-vendor"},
		"hostless":                compatible("https://"),
		"query":                   compatible("https://proxy.example/api?token=x"),
		"malformed":               compatible("https://["),
		"empty_host_port":         compatible("https://:443"),
		"non_numeric_port":        compatible("https://host:notaport"),
		"port_out_of_range":       compatible("https://host:70000"),
		"userinfo":                compatible("https://user@host"),
		"bare_query":              {"SKILLXRAY_LLM_PROVIDER": "openai-compatible", "SKILLXRAY_LLM_API_KEY": "k", "SKILLXRAY_LLM_BASE_URL": "https://api.example.com/v1?"},
		"bare_fragment":           {"SKILLXRAY_LLM_PROVIDER": "openai-compatible", "SKILLXRAY_LLM_API_KEY": "k", "SKILLXRAY_LLM_BASE_URL": "https://api.example.com/v1#"},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := FromEnv(env(m))
			configErr(t, err)
			assert.Nil(t, cfg)
		})
	}
}

// test_llm.py::test_from_env_key_fallback_and_defaults, test_from_env_openai_https_default,
// test_from_env_explicit_key_allowed_for_custom_host
func TestFromEnvDefaultsAndFallback(t *testing.T) {
	cfg, err := FromEnv(env(map[string]string{"SKILLXRAY_LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "sk-test"}))
	require.NoError(t, err)
	assert.Equal(t, "anthropic", cfg.Provider)
	assert.Equal(t, "sk-test", cfg.APIKey)
	assert.Equal(t, "https://api.anthropic.com", cfg.BaseURL)
	assert.NotEmpty(t, cfg.Model) // a per-provider default is filled in

	cfg, err = FromEnv(env(map[string]string{"SKILLXRAY_LLM_PROVIDER": "openai", "OPENAI_API_KEY": "sk"}))
	require.NoError(t, err)
	assert.Equal(t, "openai", cfg.Provider)
	assert.True(t, len(cfg.BaseURL) > 8 && cfg.BaseURL[:8] == "https://")

	cfg, err = FromEnv(env(map[string]string{"SKILLXRAY_LLM_PROVIDER": "openai-compatible",
		"SKILLXRAY_LLM_BASE_URL": "https://proxy.internal", "SKILLXRAY_LLM_MODEL": "local-model",
		"SKILLXRAY_LLM_API_KEY": "sk-explicit"}))
	require.NoError(t, err)
	assert.Equal(t, "sk-explicit", cfg.APIKey)
}

// test_llm.py::test_llmconfig_repr_hides_api_key
func TestConfigStringHidesAPIKey(t *testing.T) {
	cfg, err := newConfig("openai", "m", "supersecretkey", "https://api.openai.com/v1")
	require.NoError(t, err)
	assert.NotContains(t, fmt.Sprintf("%v %+v %s", cfg, cfg, cfg), "supersecretkey")
}

// test_llm.py::test_llmconfig_rejects_unknown_provider, test_llmconfig_rejects_non_https_base_url,
// test_llmconfig_rejects_query_and_normalizes_trailing_slash, test_llmconfig_rejects_hostless_base_url
func TestNewConfigInvariants(t *testing.T) {
	for _, args := range [][2]string{{"claude-typo", "https://api.anthropic.com"}, {"openai", "http://evil.example"},
		{"openai", "https://x/api?token=y"}, {"openai", "https://"}} {
		_, err := newConfig(args[0], "m", "k", args[1])
		configErr(t, err)
	}
	cfg, err := newConfig("openai", "m", "k", "https://api.openai.com/v1/")
	require.NoError(t, err)
	assert.Equal(t, "https://api.openai.com/v1", cfg.BaseURL)
}
