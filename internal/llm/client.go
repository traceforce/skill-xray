package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Completer is LLMClient: the one interface the adjudicator and the judge depend on.
type Completer interface {
	Complete(system, user string) (string, error)
}

// Kind tells the three Python exception classes apart: LLMError (a transport or endpoint
// failure: stop, every file would fail the same way), LLMResponseError (the endpoint answered but
// the reply was unusable: note this file, continue) and LLMBudgetError (the shared budget is spent).
type Kind int

const (
	Transport Kind = iota
	Response
	Budget
)

// Error is LLMError and its two subclasses; Msg never carries the key or a response body.
type Error struct {
	Kind Kind
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// errName is type(exc).__name__ as it reaches finding messages: the Python class name for an
// *Error, "Exception" for anything else (the session normalises everything else in production).
func errName(err error) string {
	var e *Error
	if !errors.As(err, &e) {
		return "Exception"
	}
	return [...]string{"LLMError", "LLMResponseError", "LLMBudgetError"}[e.Kind]
}

const (
	maxResponseBytes   = 1 << 20 // a verdict JSON is tiny; a body of exactly 1 MiB is over budget
	maxRetries         = 3
	maxBackoff         = 8 * time.Second
	reasoningMinOutput = 4096 // hidden reasoning shares the output cap
	reasoningEffort    = "low"
)

// retryStatus is the transient set: rate limit, the gateway family and Anthropic's 529 overload.
// A 500 is not retried.
var retryStatus = map[int]bool{429: true, 502: true, 503: true, 504: true, 529: true}

var sleep = time.Sleep // tests replace it

var (
	// o-series and gpt-5.x reject max_tokens/temperature/seed; [-.] admits dotted minors (gpt-5.1).
	openaiReasoningRE = regexp.MustCompile(`^(?:o[1-9]|gpt-5)(?:[-.]|$)`)
	// Thinking-by-default Claude families reject the sampling fields.
	anthropicThinkingRE = regexp.MustCompile(`^claude-(?:opus-(?:4-[7-9]|5)|sonnet-5|fable|mythos)`)
)

// httpClient is HTTPLLMClient: the request is shaped by hand over net/http (no vendor SDK) and
// redirects are refused so the key header is never resent to another host.
type httpClient struct {
	cfg  Config
	http *http.Client
}

// BuildClient is build_client: the real HTTP client for a config. Tests inject a fake Completer.
func BuildClient(cfg Config) Completer {
	return &httpClient{cfg, &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

func (c *httpClient) Identity() (provider, model string) { return c.cfg.Provider, c.cfg.Model }

func (c *httpClient) Complete(system, user string) (string, error) {
	return c.complete(system, user, nil)
}

// CompleteStructured asks for OpenAI's strict JSON-schema response; other providers are not
// assumed to support that contract and get the plain request.
func (c *httpClient) CompleteStructured(system, user string, schema any) (string, error) {
	if c.cfg.Provider != "openai" {
		schema = nil
	}
	return c.complete(system, user, schema)
}

func (c *httpClient) complete(system, user string, schema any) (string, error) {
	model := strings.ToLower(c.cfg.Model)
	if c.cfg.Provider == "anthropic" {
		body := map[string]any{"model": c.cfg.Model, "max_tokens": c.cfg.MaxTokens, "system": system,
			"messages": []map[string]any{{"role": "user", "content": user}}}
		if anthropicThinkingRE.MatchString(model) {
			body["max_tokens"] = max(c.cfg.MaxTokens, reasoningMinOutput)
			body["output_config"] = map[string]any{"effort": reasoningEffort}
		} else {
			body["temperature"] = 0 // greedy decoding removes one source of variance
		}
		payload, err := c.post(c.cfg.BaseURL+"/v1/messages", map[string]string{"x-api-key": c.cfg.APIKey,
			"anthropic-version": "2023-06-01", "content-type": "application/json"}, body)
		if err != nil {
			return "", err
		}
		return extract(payload, "anthropic")
	}
	tokenField := "max_tokens" // compatible endpoints only understand this; the switch is real-OpenAI only
	if c.cfg.Provider == "openai" && openaiReasoningRE.MatchString(model) {
		tokenField = "max_completion_tokens"
	}
	body := map[string]any{"model": c.cfg.Model, tokenField: c.cfg.MaxTokens,
		"messages": []map[string]any{{"role": "system", "content": system}, {"role": "user", "content": user}}}
	if tokenField == "max_tokens" {
		body["temperature"] = 0
		if c.cfg.Provider == "openai" { // seed is OpenAI's own field; a compatible endpoint may reject it
			body["seed"] = 0
		}
	} else {
		body[tokenField] = max(c.cfg.MaxTokens, reasoningMinOutput)
		body["reasoning_effort"] = reasoningEffort
	}
	if schema != nil {
		body["response_format"] = map[string]any{"type": "json_schema", "json_schema": map[string]any{
			"name": "finding_review", "strict": true, "schema": schema}}
	}
	payload, err := c.post(c.cfg.BaseURL+"/chat/completions", map[string]string{
		"authorization": "Bearer " + c.cfg.APIKey, "content-type": "application/json"}, body)
	if err != nil {
		return "", err
	}
	return extract(payload, "openai")
}

// post is _post: up to maxRetries retries on the transient statuses, every transport failure an
// LLMError without the response body, a 2xx body decoded as JSON or an LLMResponseError.
func (c *httpClient) post(url string, headers map[string]string, body map[string]any) (any, error) {
	data, _ := json.Marshal(body)
	lastCode := 0
	for attempt := 0; attempt <= maxRetries; attempt++ {
		status, raw, retryAfter, err := c.readBounded(url, headers, data)
		if err != nil {
			return nil, err
		}
		if status/100 != 2 {
			if !retryStatus[status] {
				return nil, &Error{Transport, fmt.Sprintf("LLM endpoint returned HTTP %d%s", status, httpHint[status])}
			}
			lastCode = status
			if attempt < maxRetries {
				sleep(retryDelay(retryAfter, attempt))
				continue
			}
			break
		}
		var payload any
		if err := json.Unmarshal(raw, &payload); err != nil {
			return nil, &Error{Response, fmt.Sprintf("LLM response was not JSON: %T", err)}
		}
		return payload, nil
	}
	return nil, &Error{Transport, fmt.Sprintf("LLM endpoint returned HTTP %d (after %d retries)", lastCode, maxRetries)}
}

// readBounded is _read_bounded: one POST under a whole-request deadline (connect, headers and
// body), the body capped at maxResponseBytes. A non-2xx status returns without reading the body.
func (c *httpClient) readBounded(url string, headers map[string]string, data []byte) (int, []byte, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return 0, nil, "", unreachable(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, "", unreachable(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, nil, resp.Header.Get("Retry-After"), nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, "", unreachable(err)
	}
	if len(raw) >= maxResponseBytes {
		return 0, nil, "", &Error{Response, "LLM response exceeded byte budget"}
	}
	return resp.StatusCode, raw, "", nil
}

// httpHint tells the operator what the common refusals mean; the body is never read.
var httpHint = map[int]string{401: " (API key rejected)", 403: " (access denied for this key)",
	404: " (model or endpoint not found; check SKILLXRAY_LLM_MODEL and SKILLXRAY_LLM_BASE_URL)"}

func unreachable(err error) error {
	why := "connection failed"
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		why = "timed out"
	}
	return &Error{Transport, "LLM endpoint unreachable: " + why}
}

// retryDelay is _retry_delay: a sane Retry-After (0..60 s) wins, else capped exponential backoff.
func retryDelay(retryAfter string, attempt int) time.Duration {
	if secs, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && 0 <= secs && secs <= 60 {
		return time.Duration(secs) * time.Second
	}
	return min(time.Second/2<<attempt, maxBackoff)
}

// extract is _extract: the reply text for the provider shape; every shape problem is a Response
// error (the endpoint is alive, so the caller notes this file and continues).
func extract(payload any, shape string) (string, error) {
	bad := &Error{Response, "bad LLM response shape"}
	obj, ok := payload.(map[string]any)
	if !ok {
		return "", bad
	}
	var text any
	if shape == "anthropic" {
		if obj["stop_reason"] == "max_tokens" {
			return "", &Error{Response, "LLM response was truncated"}
		}
		parts, ok := obj["content"].([]any)
		if !ok {
			return "", bad
		}
		var b strings.Builder
		for _, p := range parts {
			if m, ok := p.(map[string]any); ok {
				if t, present := m["text"]; present {
					s, ok := t.(string)
					if !ok {
						return "", bad
					}
					b.WriteString(s)
				}
			}
		}
		text = b.String()
	} else {
		choices, _ := obj["choices"].([]any)
		if len(choices) == 0 {
			return "", bad
		}
		choice, ok := choices[0].(map[string]any)
		if !ok {
			return "", bad
		}
		if fr := choice["finish_reason"]; fr == "length" || fr == "content_filter" {
			return "", &Error{Response, "LLM response was truncated or filtered"}
		}
		message, ok := choice["message"].(map[string]any)
		if !ok {
			return "", bad
		}
		if text, ok = message["content"]; !ok {
			return "", bad
		}
	}
	s, ok := text.(string)
	if !ok {
		return "", &Error{Response, "LLM response content was not text"}
	}
	return s, nil
}
