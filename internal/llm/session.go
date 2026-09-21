package llm

import (
	"errors"
	"net"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/pytext"
)

// Session is LLMSession: one logical-call and input-byte budget shared by the review and the
// advisory pass. A transport failure marks it unavailable for both.
type Session struct {
	Client                                          Completer
	MaxCalls, MaxBytes, Calls, InputBytes, Failures int
	Unavailable                                     bool
}

// NewSession is LLMSession(client, max_calls, max_bytes); the budgets must be non-negative.
func NewSession(c Completer, maxCalls, maxBytes int) (*Session, error) {
	if maxCalls < 0 || maxBytes < 0 {
		return nil, errors.New("LLM budgets must be non-negative integers")
	}
	return &Session{Client: c, MaxCalls: maxCalls, MaxBytes: maxBytes}, nil
}

// structuredCompleter and identified are the optional client surface (Python getattr duck typing).
type structuredCompleter interface {
	CompleteStructured(system, user string, schema any) (string, error)
}
type identified interface {
	Identity() (provider, model string)
}

// Complete satisfies Completer, so Adjudicate runs through the shared budget.
func (s *Session) Complete(system, user string) (string, error) { return s.complete(system, user, nil) }

// complete is LLMSession.complete: budget first, then the call, then the reply bound. A Response
// error passes through; a transport (or OS-level) failure disables the session and is replaced by
// a fixed message so a credential in the original text never propagates.
func (s *Session) complete(system, user string, schema any) (string, error) {
	if s.Unavailable {
		return "", &Error{Transport, "session unavailable"}
	}
	size := len(system) + len(user)
	if schema != nil {
		// ponytail: Python dumps with ensure_ascii=False; identical for the ASCII response schema.
		size += len(pytext.Dumps(schema, 0))
	}
	if s.Calls >= s.MaxCalls || s.InputBytes+size > s.MaxBytes {
		return "", &Error{Budget, "shared LLM budget exhausted"}
	}
	s.Calls++
	s.InputBytes += size
	var reply string
	var err error
	if sc, ok := s.Client.(structuredCompleter); ok && schema != nil {
		reply, err = sc.CompleteStructured(system, user, schema)
	} else {
		reply, err = s.Client.Complete(system, user)
	}
	if err == nil && len(reply) > 16384 {
		err = &Error{Response, "response exceeds text budget"}
	}
	if err == nil {
		return reply, nil
	}
	s.Failures++
	var e *Error
	var netErr net.Error // ponytail: OSError is net.Error here; a custom client's file errors classify as "error"
	switch {
	case errors.As(err, &e) && e.Kind == Response:
		return "", err
	case errors.As(err, &e) || errors.As(err, &netErr):
		s.Unavailable = true
		return "", &Error{Transport, "session transport failure"}
	}
	return "", err
}

// Usage is LLMSession.usage(): the enrichment.llm_usage record. The client identity is kept only
// when it is a bounded, stripped, printable string; otherwise "unknown".
func (s *Session) Usage() map[string]any {
	provider, model := "custom", "unknown"
	if id, ok := s.Client.(identified); ok {
		provider, model = id.Identity()
	}
	bounded := func(v string) string {
		if n := utf8.RuneCountInString(v); 0 < n && n <= 200 && v == pytext.Strip(v) && pytext.IsPrintable(v) {
			return v
		}
		return "unknown"
	}
	return map[string]any{"calls": s.Calls, "input_bytes": s.InputBytes, "provider": bounded(provider),
		"model": bounded(model), "failures": s.Failures, "unavailable": s.Unavailable, "max_calls": s.MaxCalls,
		"max_input_bytes": s.MaxBytes, "unit": "logical-completions; transport retries remain separately bounded"}
}
