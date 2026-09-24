package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/testutil"
)

// rt is the transport seam the Python tests reach by monkeypatching c._opener.open.
type rt func(*http.Request) (*http.Response, error)

func (f rt) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newClient(t *testing.T, provider, model, key, base string, fn rt) *httpClient {
	cfg, err := newConfig(provider, model, key, base)
	require.NoError(t, err)
	c := BuildClient(cfg).(*httpClient)
	c.http.Transport = fn
	return c
}

func respond(status int, body string, headers ...string) *http.Response {
	h := http.Header{}
	for i := 0; i+1 < len(headers); i += 2 {
		h.Set(headers[i], headers[i+1])
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}

func requestBody(t *testing.T, r *http.Request) map[string]any {
	raw, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

func noSleep(t *testing.T) *[]time.Duration {
	var slept []time.Duration
	testutil.Swap(t, &sleep, func(d time.Duration) { slept = append(slept, d) })
	return &slept
}

const (
	openaiOK    = `{"choices":[{"message":{"content":"ok"}}]}`
	anthropicOK = `{"content":[{"type":"text","text":"ok"}]}`
)

func kindOf(t *testing.T, err error) Kind {
	var e *Error
	require.ErrorAs(t, err, &e)
	return e.Kind
}

// test_llm.py::test_extract_anthropic_joins_text_parts, test_extract_openai_reads_choice,
// test_extract_malformed_raises_response_error, test_extract_non_text_content_raises_response_error;
// test_llm_review_core.py::test_provider_truncation_cannot_look_complete (2)
func TestExtract(t *testing.T) {
	text, err := extract(map[string]any{"content": []any{map[string]any{"type": "text", "text": "hello"},
		map[string]any{"type": "text", "text": " world"}}}, "anthropic")
	require.NoError(t, err)
	assert.Equal(t, "hello world", text)
	text, err = extract(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "hi"}}}}, "openai")
	require.NoError(t, err)
	assert.Equal(t, "hi", text)
	for name, c := range map[string]struct {
		payload any
		shape   string
	}{
		"malformed":            {map[string]any{"unexpected": 1}, "openai"},
		"non_text_content":     {map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": []any{"not", "text"}}}}}, "openai"},
		"openai_truncated":     {map[string]any{"choices": []any{map[string]any{"finish_reason": "length", "message": map[string]any{"content": "{}"}}}}, "openai"},
		"anthropic_truncated":  {map[string]any{"stop_reason": "max_tokens", "content": []any{map[string]any{"text": "{}"}}}, "anthropic"},
		"anthropic_list":       {[]any{}, "anthropic"},
		"openai_wrong_choices": {map[string]any{"choices": []any{"wrong-shape"}}, "openai"},
	} {
		_, err := extract(c.payload, c.shape)
		assert.Equal(t, Response, kindOf(t, err), name)
	}
}

// test_llm.py::test_build_client_returns_http_client, test_no_redirect_handler_refuses_to_follow
func TestBuildClientRefusesRedirects(t *testing.T) {
	cfg, err := newConfig("anthropic", "m", "k", "https://api.anthropic.com")
	require.NoError(t, err)
	c, ok := BuildClient(cfg).(*httpClient)
	require.True(t, ok)
	assert.Equal(t, http.ErrUseLastResponse, c.http.CheckRedirect(nil, nil))
}

// test_llm.py::test_complete_anthropic_shapes_request
func TestCompleteAnthropicShapesRequest(t *testing.T) {
	var url string
	var got map[string]any
	c := newClient(t, "anthropic", "claude", "sekret", "https://api.anthropic.com", func(r *http.Request) (*http.Response, error) {
		url, got = r.URL.String(), requestBody(t, r)
		assert.Equal(t, "sekret", r.Header.Get("x-api-key"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
		return respond(200, anthropicOK), nil
	})
	reply, err := c.Complete("sys-prompt", "user-text")
	require.NoError(t, err)
	assert.Equal(t, "ok", reply)
	assert.Equal(t, "https://api.anthropic.com/v1/messages", url)
	assert.Equal(t, "sys-prompt", got["system"])
	assert.Equal(t, float64(0), got["temperature"]) // greedy; Anthropic has no seed field
	assert.NotContains(t, got, "seed")
}

// test_llm.py::test_complete_openai_shapes_request
func TestCompleteOpenAIShapesRequest(t *testing.T) {
	var url, auth string
	var got map[string]any
	c := newClient(t, "openai", "gpt", "sk-key", "https://api.openai.com/v1", func(r *http.Request) (*http.Response, error) {
		url, auth, got = r.URL.String(), r.Header.Get("Authorization"), requestBody(t, r)
		return respond(200, openaiOK), nil
	})
	reply, err := c.Complete("sys", "usr")
	require.NoError(t, err)
	assert.Equal(t, "ok", reply)
	assert.Equal(t, "https://api.openai.com/v1/chat/completions", url)
	assert.Equal(t, "Bearer sk-key", auth)
	assert.Equal(t, "system", got["messages"].([]any)[0].(map[string]any)["role"])
}

// test_llm.py::test_complete_maps_httperror_to_llmerror_without_leaking_secret, test_500_is_not_retried
func TestHTTP500IsLLMErrorWithoutRetryOrLeak(t *testing.T) {
	noSleep(t)
	calls := 0
	c := newClient(t, "openai", "m", "supersecretkey", "https://api.openai.com/v1", func(*http.Request) (*http.Response, error) {
		calls++
		return respond(500, "boom"), nil
	})
	_, err := c.Complete("s", "u")
	assert.Equal(t, Transport, kindOf(t, err))
	assert.NotContains(t, err.Error(), "supersecretkey")
	assert.Equal(t, 1, calls) // 500 fails immediately, no retry
}

// test_llm.py::test_complete_refuses_redirect_to_protect_key
func TestRedirectIsRefusedToProtectKey(t *testing.T) {
	var hosts []string
	c := newClient(t, "openai", "m", "supersecretkey", "https://api.openai.com/v1", func(r *http.Request) (*http.Response, error) {
		hosts = append(hosts, r.URL.Host)
		return respond(302, "", "Location", "https://evil.example"), nil
	})
	_, err := c.Complete("s", "u")
	assert.Equal(t, Transport, kindOf(t, err))
	assert.NotContains(t, err.Error(), "supersecretkey")
	assert.Equal(t, []string{"api.openai.com"}, hosts) // the key header was never resent elsewhere
}

// test_llm.py::test_complete_bounds_response_body_size;
// test_llm_review_core.py::test_byte_budget_and_response_overflow_are_explicit (client half)
func TestResponseBodyIsBounded(t *testing.T) {
	huge := `{"x":"` + strings.Repeat("A", 3*maxResponseBytes) + `"}`
	r := strings.NewReader(huge)
	c := newClient(t, "openai", "m", "k", "https://api.openai.com/v1", func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{},
			Body: io.NopCloser(r)}, nil
	})
	_, err := c.Complete("s", "u")
	assert.Equal(t, Response, kindOf(t, err))
	assert.LessOrEqual(t, len(huge)-r.Len(), maxResponseBytes)
	// a body of exactly 1 MiB is over budget too
	c = newClient(t, "openai", "test", "unused", "https://example.invalid", func(*http.Request) (*http.Response, error) {
		return respond(200, "{}"+strings.Repeat(" ", maxResponseBytes-2)), nil
	})
	_, err = c.Complete("s", "u")
	assert.Equal(t, Response, kindOf(t, err))
	assert.Equal(t, "LLM response exceeded byte budget", err.Error())
}

func bodyFor(t *testing.T, provider, model, base string) map[string]any {
	var got map[string]any
	reply := openaiOK
	if provider == "anthropic" {
		reply = anthropicOK
	}
	c := newClient(t, provider, model, "k", base, func(r *http.Request) (*http.Response, error) {
		got = requestBody(t, r)
		return respond(200, reply), nil
	})
	_, err := c.Complete("s", "u")
	require.NoError(t, err)
	return got
}

// test_llm.py::test_openai_reasoning_model_uses_completion_tokens (3), test_reasoning_regex_matches_dotted_gpt5 (2),
// test_openai_reasoning_model_omits_temperature_and_seed (5), test_openai_classic_model_keeps_max_tokens,
// test_openai_classic_model_pins_temperature_and_seed, test_compatible_endpoint_keeps_max_tokens_for_reasoning_name,
// test_compatible_endpoint_pins_temperature_without_seed
func TestOpenAIRequestShapeByModel(t *testing.T) {
	for _, model := range []string{"o1-mini", "o3", "gpt-5-mini", "gpt-5.1", "gpt-5.1-codex", "gpt-5.4-mini", "gpt-5.6-luna"} {
		b := bodyFor(t, "openai", model, "https://api.openai.com/v1")
		assert.Contains(t, b, "max_completion_tokens", model)
		assert.NotContains(t, b, "max_tokens", model)
		assert.NotContains(t, b, "temperature", model)
		assert.NotContains(t, b, "seed", model)
		assert.GreaterOrEqual(t, b["max_completion_tokens"], float64(4096), model)
		assert.Equal(t, "low", b["reasoning_effort"], model)
	}
	for _, model := range []string{"gpt-4o-mini", "gpt-4.1-mini"} {
		b := bodyFor(t, "openai", model, "https://api.openai.com/v1")
		assert.Contains(t, b, "max_tokens", model)
		assert.NotContains(t, b, "max_completion_tokens", model)
		assert.Equal(t, float64(0), b["temperature"], model)
		assert.Equal(t, float64(0), b["seed"], model)
	}
	for _, model := range []string{"o1", "llama-3.3-70b"} { // a compatible endpoint: max_tokens, no seed
		b := bodyFor(t, "openai-compatible", model, "https://vllm.example/v1")
		assert.Contains(t, b, "max_tokens", model)
		assert.NotContains(t, b, "max_completion_tokens", model)
		assert.Equal(t, float64(0), b["temperature"], model)
		assert.NotContains(t, b, "seed", model)
	}
}

// test_llm.py::test_anthropic_thinking_family_omits_sampling_and_keeps_effort_low (4),
// test_anthropic_older_family_keeps_greedy_temperature (3)
func TestAnthropicRequestShapeByModel(t *testing.T) {
	for _, model := range []string{"claude-opus-5", "claude-opus-4-8", "claude-sonnet-5", "claude-fable-5-1"} {
		b := bodyFor(t, "anthropic", model, "https://api.anthropic.com")
		assert.NotContains(t, b, "temperature", model)
		assert.Equal(t, map[string]any{"effort": "low"}, b["output_config"], model)
		assert.GreaterOrEqual(t, b["max_tokens"], float64(4096), model)
	}
	for _, model := range []string{"claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus-4-6"} {
		b := bodyFor(t, "anthropic", model, "https://api.anthropic.com")
		assert.Equal(t, float64(0), b["temperature"], model)
		assert.NotContains(t, b, "output_config", model)
	}
}

// test_llm.py::test_non_latin1_key_becomes_llmerror: any failure raised by the transport surfaces
// as the contracted LLMError, never raw.
func TestTransportFailureIsLLMError(t *testing.T) {
	c := newClient(t, "openai", "m", "key", "https://api.openai.com/v1", func(*http.Request) (*http.Response, error) {
		return nil, errors.New("ordinal not in range(256)")
	})
	_, err := c.Complete("s", "u")
	assert.Equal(t, Transport, kindOf(t, err))
}

// test_llm.py::test_429_is_retried_then_succeeds, test_anthropic_529_overloaded_is_retried_then_succeeds
func TestTransientStatusIsRetried(t *testing.T) {
	slept := noSleep(t)
	calls := 0
	c := newClient(t, "openai", "m", "k", "https://api.openai.com/v1", func(*http.Request) (*http.Response, error) {
		if calls++; calls == 1 {
			return respond(429, "slow down", "Retry-After", "0"), nil
		}
		return respond(200, openaiOK), nil
	})
	reply, err := c.Complete("s", "u")
	require.NoError(t, err)
	assert.Equal(t, "ok", reply)
	assert.Equal(t, 2, calls)
	assert.Equal(t, []time.Duration{0}, *slept) // Retry-After: 0 honoured

	calls = 0
	c = newClient(t, "anthropic", "m", "k", "https://api.anthropic.com", func(*http.Request) (*http.Response, error) {
		if calls++; calls == 1 {
			return respond(529, "overloaded"), nil
		}
		return respond(200, anthropicOK), nil
	})
	reply, err = c.Complete("s", "u")
	require.NoError(t, err)
	assert.Equal(t, "ok", reply)
	assert.Equal(t, 2, calls)
	assert.Equal(t, 500*time.Millisecond, (*slept)[1]) // exponential backoff from 0.5 s
}

// test_llm.py::test_persistent_429_exhausts_retries_and_fails_closed
func TestPersistentRateLimitFailsClosed(t *testing.T) {
	noSleep(t)
	calls := 0
	c := newClient(t, "openai", "m", "supersecretkey", "https://api.openai.com/v1", func(*http.Request) (*http.Response, error) {
		calls++
		return respond(429, "slow down"), nil
	})
	_, err := c.Complete("s", "u")
	assert.Equal(t, Transport, kindOf(t, err))
	assert.Equal(t, maxRetries+1, calls)
	assert.NotContains(t, err.Error(), "supersecretkey")
	assert.Equal(t, "LLM endpoint returned HTTP 429 (after 3 retries)", err.Error())
}

// test_llm.py::test_deeply_nested_json_body_is_response_error_not_crash
func TestDeeplyNestedBodyIsResponseError(t *testing.T) {
	c := newClient(t, "openai", "m", "k", "https://api.openai.com/v1", func(*http.Request) (*http.Response, error) {
		return respond(200, strings.Repeat("[", 100000)+strings.Repeat("]", 100000)), nil
	})
	_, err := c.Complete("s", "u")
	assert.Equal(t, Response, kindOf(t, err))
}

type blockingBody struct{ done <-chan struct{} }

func (b blockingBody) Read([]byte) (int, error) { <-b.done; return 0, context.DeadlineExceeded }
func (blockingBody) Close() error               { return nil }

// test_llm.py::test_read_bounded_enforces_deadline_after_blocking_read: the whole-request
// deadline covers the body read, not only the connection. (test_read_bounded_prefers_read1_for_
// absolute_deadline is CPython socket plumbing and is not ported.)
func TestDeadlineCoversBodyRead(t *testing.T) {
	c := newClient(t, "openai", "m", "k", "https://api.openai.com/v1", func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: blockingBody{r.Context().Done()}}, nil
	})
	c.cfg.Timeout = 30 * time.Millisecond
	start := time.Now()
	_, err := c.Complete("s", "u")
	assert.Equal(t, Transport, kindOf(t, err))
	assert.Less(t, time.Since(start), 5*time.Second)
}

// The retry delay: Retry-After in 0..10 wins, else min(0.5 * 2**attempt, 8).
func TestRetryDelay(t *testing.T) {
	assert.Equal(t, 5*time.Second, retryDelay("5", 0))
	assert.Equal(t, 500*time.Millisecond, retryDelay("61", 0))
	assert.Equal(t, 500*time.Millisecond, retryDelay("30", 0), "a wait over ten seconds is not honoured")
	assert.Equal(t, 500*time.Millisecond, retryDelay("soon", 0))
	assert.Equal(t, 4*time.Second, retryDelay("", 3))
	assert.Equal(t, 8*time.Second, retryDelay("", 5))
}

// errName is type(exc).__name__ for the three Python classes; anything else is Exception.
func TestErrName(t *testing.T) {
	assert.Equal(t, "LLMError", errName(&Error{Transport, "x"}))
	assert.Equal(t, "LLMResponseError", errName(&Error{Response, "x"}))
	assert.Equal(t, "LLMBudgetError", errName(&Error{Budget, "x"}))
	assert.Equal(t, "Exception", errName(errors.New("x")))
}
