// Package opengrep drives the pinned OpenGrep binary over the executable code selected from
// the IR and translates its JSON report into findings.
package opengrep

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/pytext"
)

// Selected is opengrep_bridge.SelectedCode: one code unit handed to the engine.
type Selected struct{ Rel, Text, Origin, Suffix string }

// coverage is _coverage: a vector-less gap finding.
func coverage(rule, message, path string) findings.Finding {
	return findings.Finding{Rule: rule, Severity: "high", Path: path, Message: message}
}

// targetName is _target_name: the last path segment of a reported path, either separator.
func targetName(raw any) string {
	s, _ := raw.(string)
	s = strings.ReplaceAll(s, `\`, "/")
	return s[strings.LastIndexByte(s, '/')+1:]
}

// decodeReport is json.loads: numbers decode through json.Number and are normalised once so
// evidence carries plain int and float64.
func decodeReport(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, strconv.ErrSyntax // trailing data: json.loads raises "Extra data"
	}
	return pytext.Intify(v), nil
}
