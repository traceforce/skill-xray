package llm

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/pytext"
)

// identifiedClient is a Completer with a cfg-like identity (SimpleNamespace(cfg=...)).
type identifiedClient struct {
	fakeClient
	provider, model string
}

func (c *identifiedClient) Identity() (string, string) { return c.provider, c.model }

// LLMSession(client, max_calls, max_bytes) rejects negative budgets.
func TestNewSessionRejectsNegativeBudgets(t *testing.T) {
	_, err := NewSession(&fakeClient{}, -1, 0)
	assert.EqualError(t, err, "LLM budgets must be non-negative integers")
	_, err = NewSession(&fakeClient{}, 0, -1)
	assert.Error(t, err)
}

// test_llm_review_core.py::test_byte_budget_and_response_overflow_are_explicit (session half)
func TestByteBudgetIsCheckedBeforeTheCall(t *testing.T) {
	c := &fakeClient{reply: "{}"}
	s, err := NewSession(c, 25, 1)
	require.NoError(t, err)
	_, err = s.Complete("system", "text")
	assert.Equal(t, Budget, kindOf(t, err))
	assert.Equal(t, 0, c.calls)
}

type structured struct{ calls int }

func (s *structured) Complete(string, string) (string, error) { return "plain", nil }
func (s *structured) CompleteStructured(_, _ string, _ any) (string, error) {
	s.calls++
	return "{}", nil
}

// test_judge_response_contract.py::test_shared_budget_counts_structured_schema_bytes
func TestSharedBudgetCountsStructuredSchemaBytes(t *testing.T) {
	schema := map[string]any{"type": "object", "description": strings.Repeat("x", 30)}
	encoded := len(pytext.Dumps(schema, 0))
	client := &structured{}
	s, err := NewSession(client, 1, 2+encoded)
	require.NoError(t, err)
	reply, err := s.complete("s", "u", schema)
	require.NoError(t, err)
	assert.Equal(t, "{}", reply)
	assert.Equal(t, 1, client.calls) // complete_structured is preferred when the client has it
	assert.Equal(t, 2+encoded, s.InputBytes)
	_, err = s.complete("s", "u", schema)
	assert.Equal(t, Budget, kindOf(t, err))
	tooSmall, _ := NewSession(&structured{}, 25, 2+encoded-1)
	_, err = tooSmall.complete("s", "u", schema)
	assert.Equal(t, Budget, kindOf(t, err))
	assert.Equal(t, 0, tooSmall.Calls)
}

type malformedThenValid struct {
	calls   int
	payload any
	shape   string
}

func (m *malformedThenValid) Complete(string, string) (string, error) {
	if m.calls++; m.calls == 1 {
		return extract(m.payload, m.shape)
	}
	return "{}", nil
}

// test_llm_review_core.py::test_wrong_provider_shapes_remain_response_errors (2)
func TestWrongProviderShapesRemainResponseErrors(t *testing.T) {
	for name, c := range map[string]*malformedThenValid{
		"anthropic_list": {payload: []any{}, shape: "anthropic"},
		"openai_choices": {payload: map[string]any{"choices": []any{"wrong-shape"}}, shape: "openai"},
	} {
		s, _ := NewSession(c, 25, 1<<20)
		_, err := s.Complete("system", "user")
		assert.Equal(t, Response, kindOf(t, err), name)
		reply, err := s.Complete("system", "user")
		require.NoError(t, err, name)
		assert.Equal(t, "{}", reply, name)
		assert.False(t, s.Unavailable, name)
		assert.Equal(t, 1, s.Failures, name)
	}
}

// test_llm_shadow.py::test_transport_failure_shared_between_lanes (session half): an LLMError or
// an OS-level error disables the session and its text (a credential) never propagates.
func TestTransportFailureDisablesSessionWithoutEchoingTheError(t *testing.T) {
	for name, err := range map[string]error{
		"llm_error": &Error{Transport, "secret " + token},
		"os_error":  &net.OpError{Op: "dial", Err: errors.New(token)},
	} {
		c := &fakeClient{err: err}
		s, _ := NewSession(c, 25, 1<<20)
		_, got := s.Complete("s", "u")
		assert.Equal(t, Transport, kindOf(t, got), name)
		assert.Equal(t, "session transport failure", got.Error(), name)
		assert.True(t, s.Unavailable, name)
		_, got = s.Complete("s", "u")
		assert.Equal(t, "session unavailable", got.Error(), name)
		assert.Equal(t, 1, c.calls, name)
	}
}

// test_llm_shadow.py::test_per_file_client_error_does_not_disable_later_calls (session half): an
// error that is neither an LLMError nor OS-level passes through unchanged and keeps the session up.
func TestOtherClientErrorsPassThrough(t *testing.T) {
	boom := errors.New("bad file response")
	s, _ := NewSession(&fakeClient{err: boom}, 25, 1<<20)
	_, err := s.Complete("s", "u")
	assert.Same(t, boom, err)
	assert.False(t, s.Unavailable)
	assert.Equal(t, 1, s.Failures)
	// a reply over the text budget is a Response error and keeps the session up
	s, _ = NewSession(&fakeClient{reply: strings.Repeat("x", 16385)}, 25, 1<<20)
	_, err = s.Complete("s", "u")
	assert.Equal(t, Response, kindOf(t, err))
	assert.False(t, s.Unavailable)
}

// test_llm_review_core.py::test_session_provenance_is_bounded_json_without_coercion (the string
// cases: empty, blank, oversized, control; the non-string Python values collapse to the identity
// interface), test_session_provenance_does_not_serialize_objects_or_propagate_properties
func TestUsageIdentityIsBounded(t *testing.T) {
	for _, bad := range []string{"", " ", strings.Repeat("x", 201), "bad\nidentity"} {
		u, _ := NewSession(&identifiedClient{provider: bad, model: bad}, 25, 1<<20)
		usage := u.Usage()
		assert.Equal(t, "unknown", usage["provider"], bad)
		assert.Equal(t, "unknown", usage["model"], bad)
	}
	valid, _ := NewSession(&identifiedClient{provider: "fixture", model: "local/models/model-1"}, 25, 1<<20)
	assert.Equal(t, "fixture", valid.Usage()["provider"])
	assert.Equal(t, "local/models/model-1", valid.Usage()["model"])
	missing, _ := NewSession(&fakeClient{}, 25, 1<<20)
	usage := missing.Usage()
	assert.Equal(t, "custom", usage["provider"])
	assert.Equal(t, "unknown", usage["model"])
	assert.Equal(t, map[string]any{"calls": 0, "input_bytes": 0, "provider": "custom", "model": "unknown",
		"failures": 0, "unavailable": false, "max_calls": 25, "max_input_bytes": 1 << 20,
		"unit": "logical-completions; transport retries remain separately bounded"}, usage)
}
