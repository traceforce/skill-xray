// Package llm is the opt-in LLM layer: operator configuration, the hand-shaped HTTP client, the
// shared call budget, credential redaction, the bounded review of text-pattern candidates and the
// advisory prompt-injection pass. It is off unless the operator configures a provider.
package llm

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/traceforce/skill-xray/internal/pytext"
)

var (
	providers    = []string{"anthropic", "openai", "openai-compatible"}
	defaultModel = map[string]string{"anthropic": "claude-haiku-4-5", "openai": "gpt-4.1-mini"}
	defaultBase  = map[string]string{"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com/v1"}
	keyFallback  = map[string]string{"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
		"openai-compatible": "OPENAI_API_KEY"}
)

// ConfigError is LLMConfigError: the layer was asked for but is misconfigured.
type ConfigError struct{ Msg string }

func (e *ConfigError) Error() string { return e.Msg }

// Config is LLMConfig.
type Config struct {
	Provider, Model, APIKey, BaseURL string
	MaxTokens                        int
	Timeout                          time.Duration
}

// String omits APIKey (Python repr=False) so a logged config never carries the key.
func (c Config) String() string {
	return fmt.Sprintf("Config{Provider:%q Model:%q BaseURL:%q MaxTokens:%d Timeout:%s}",
		c.Provider, c.Model, c.BaseURL, c.MaxTokens, c.Timeout)
}

// newConfig is LLMConfig(...): provider normalised and checked, base URL validated, defaults filled.
func newConfig(provider, model, apiKey, baseURL string) (Config, error) {
	provider = strings.ToLower(pytext.Strip(provider))
	if !slices.Contains(providers, provider) {
		return Config{}, &ConfigError{fmt.Sprintf("LLMConfig.provider must be one of %s (got %s)",
			strings.Join(providers, ", "), pytext.Repr(provider))}
	}
	base, err := validateBaseURL(baseURL, "LLMConfig.base_url")
	if err != nil {
		return Config{}, err
	}
	return Config{Provider: provider, Model: model, APIKey: apiKey, BaseURL: base, MaxTokens: 1024,
		Timeout: 30 * time.Second}, nil
}

// validateBaseURL is _validate_base_url: https, a host, no userinfo, no query/fragment (tested on
// the raw string so a bare trailing ? or # is caught too); returns the URL without trailing /.
func validateBaseURL(base, label string) (string, error) {
	u, err := pytext.URLSplit(base)
	var port *int
	if err == nil {
		port, err = u.Port()
	}
	if err != nil {
		return "", &ConfigError{label + " is not a valid URL"}
	}
	if u.Scheme != "https" || u.Hostname() == "" || (port != nil && *port == 0) ||
		strings.Contains(u.Netloc, "@") || strings.ContainsAny(base, "?#") {
		return "", &ConfigError{label + " must be an https URL with a host, no userinfo, and no query/fragment"}
	}
	return strings.TrimRight(base, "/"), nil
}

// FromEnv is from_env: nil, nil when SKILLXRAY_LLM_PROVIDER is blank (layer off); a ConfigError
// when the layer is enabled but misconfigured. The CLI passes os.Getenv, tests a map closure.
func FromEnv(getenv func(string) string) (*Config, error) {
	provider := strings.ToLower(pytext.Strip(getenv("SKILLXRAY_LLM_PROVIDER")))
	if provider == "" {
		return nil, nil
	}
	if !slices.Contains(providers, provider) {
		return nil, &ConfigError{"SKILLXRAY_LLM_PROVIDER must be one of " + strings.Join(providers, ", ")}
	}
	base := pytext.Strip(cmp.Or(getenv("SKILLXRAY_LLM_BASE_URL"), defaultBase[provider]))
	if base == "" {
		return nil, &ConfigError{"openai-compatible needs SKILLXRAY_LLM_BASE_URL (the endpoint origin)"}
	}
	base, err := validateBaseURL(base, "SKILLXRAY_LLM_BASE_URL")
	if err != nil {
		return nil, err
	}
	key := pytext.Strip(getenv("SKILLXRAY_LLM_API_KEY"))
	if key == "" {
		// The vendor-variable fallback applies only on the vendor's own host: a vendor key never
		// travels to a custom (possibly attacker-chosen) base URL.
		if base == defaultBase[provider] {
			key = pytext.Strip(getenv(keyFallback[provider]))
		}
		if key == "" {
			return nil, &ConfigError{fmt.Sprintf("no API key: set SKILLXRAY_LLM_API_KEY (the %s fallback applies "+
				"only to the vendor's own host, not a custom SKILLXRAY_LLM_BASE_URL)", keyFallback[provider])}
		}
	}
	model := pytext.Strip(cmp.Or(getenv("SKILLXRAY_LLM_MODEL"), defaultModel[provider]))
	if model == "" {
		return nil, &ConfigError{"set SKILLXRAY_LLM_MODEL (no default for this provider)"}
	}
	cfg, err := newConfig(provider, model, key, base)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
