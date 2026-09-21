package parse

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/traceforce/skill-xray/internal/pytext"
)

// loadStructured is _load_structured: TOML by extension, else strict JSON; the second value is
// the diagnostic detail ("" on success).
func loadStructured(text, rel string) (any, string) {
	if strings.HasSuffix(pytext.Lower(rel), ".toml") {
		cfg, _, err := decodeTOML(text)
		if err != "" {
			return nil, err
		}
		return cfg, ""
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, "json_parse_error:" + pytext.Head(err.Error(), 80)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, "json_parse_error:Extra data"
	}
	v, err := jsonValue(v)
	if err != nil {
		return nil, "json_parse_error:" + pytext.Head(err.Error(), 80)
	}
	return v, ""
}

// decodeTOML is tomllib.loads: the document as Python-shaped values plus the metadata whose
// Keys() carry the document order tomllib's dicts keep and a Go map does not. The error is the
// config_parse_error detail ("" on success).
func decodeTOML(text string) (map[string]any, toml.MetaData, string) {
	if tomlTooDeep(text) {
		return nil, toml.MetaData{}, fmt.Sprintf("toml_parse_error:key path deeper than %d", tomlMaxDepth)
	}
	v := map[string]any{}
	md, err := toml.Decode(text, &v)
	if err != nil {
		return nil, md, "toml_parse_error:" + pytext.Head(err.Error(), 80)
	}
	return tomlValue(v).(map[string]any), md, ""
}

// tomlMaxDepth bounds a key path. BurntSushi/toml records every key with its full path, so a
// dotted key or inline-table chain of depth n costs n²/2 strings: 12 GB at 30k segments, where
// tomllib is merely slow. Past the bound the document is refused as config_parse_error; tomllib
// would still decode it, a documented divergence (00-overview §7) no real manifest reaches.
const tomlMaxDepth = 1000

// tomlTooDeep reports a key with more than tomlMaxDepth dotted segments or inline tables nested
// deeper than that, counting outside strings and comments.
func tomlTooDeep(text string) bool {
	depth, dots, quote := 0, 0, byte(0)
	inKey := true
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' {
				i++
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '\n':
			dots, inKey = 0, true
		case c == '=':
			inKey = false
		case c == '.' && inKey:
			dots++
			if dots > tomlMaxDepth {
				return true
			}
		case c == '{':
			depth++
			if depth > tomlMaxDepth {
				return true
			}
			dots, inKey = 0, true
		case c == '}':
			depth--
		case c == ',' && depth > 0:
			dots, inKey = 0, true
		}
	}
	return false
}

// tomlValue maps BurntSushi's value types onto tomllib's: int64 to int, arrays of tables to
// lists, datetimes to their Python class and str() (tomllib truncates fractions to microseconds).
func tomlValue(v any) any {
	switch x := v.(type) {
	case int64:
		return int(x)
	case map[string]any:
		for k, e := range x {
			x[k] = tomlValue(e)
		}
	case []any:
		for i, e := range x {
			x[i] = tomlValue(e)
		}
	case []map[string]any:
		l := make([]any, len(x))
		for i, e := range x {
			l[i] = tomlValue(e)
		}
		return l
	case time.Time:
		frac := ""
		if us := x.Nanosecond() / 1000; us != 0 {
			frac = fmt.Sprintf(".%06d", us)
		}
		switch x.Location().String() { // BurntSushi marks local kinds with sentinel zones
		case "date-local":
			return Opaque{"date", x.Format("2006-01-02")}
		case "time-local":
			return Opaque{"time", x.Format("15:04:05") + frac}
		case "datetime-local":
			return Opaque{"datetime", x.Format("2006-01-02 15:04:05") + frac}
		}
		return Opaque{"datetime", x.Format("2006-01-02 15:04:05") + frac + x.Format("-07:00")}
	}
	return v
}

// tableKeys lists the keys directly under path in document order, then any the metadata did
// not record (a zero MetaData) sorted.
func tableKeys(md toml.MetaData, table map[string]any, path ...string) []string {
	seen := map[string]bool{}
	var keys []string
	for _, k := range md.Keys() {
		if len(k) == len(path)+1 && slices.Equal(k[:len(path)], path) && !seen[k[len(path)]] {
			seen[k[len(path)]] = true
			keys = append(keys, k[len(path)])
		}
	}
	for _, k := range slices.Sorted(maps.Keys(table)) {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	return keys
}

// jsonValue normalises a UseNumber tree to the D7 shape: int when the literal fits int64,
// float64 otherwise, with CPython's 4300-digit integer limit kept as the ValueError it raises.
func jsonValue(v any) (any, error) {
	switch x := v.(type) {
	case json.Number:
		s := string(x)
		if !strings.ContainsAny(s, ".eE") {
			if i, err := strconv.ParseInt(s, 10, 64); err == nil {
				return int(i), nil
			}
			if len(strings.TrimLeft(s, "-")) > 4300 {
				return nil, errors.New("Exceeds the limit (4300 digits) for integer string conversion")
			}
		}
		f, _ := strconv.ParseFloat(s, 64)
		return f, nil
	case map[string]any:
		for k, e := range x {
			n, err := jsonValue(e)
			if err != nil {
				return nil, err
			}
			x[k] = n
		}
	case []any:
		for i, e := range x {
			n, err := jsonValue(e)
			if err != nil {
				return nil, err
			}
			x[i] = n
		}
	}
	return v, nil
}

// classifyManifest is classify_manifest: a manifest kind by content, most specific first; ""
// for a non-mapping config (Python None).
func classifyManifest(cfg any) string {
	m, ok := cfg.(map[string]any)
	if !ok {
		return ""
	}
	has := func(k string) bool { _, ok := m[k]; return ok }
	switch hooks := m["hooks"]; {
	case has("mcpServers") || has("mcp_servers"):
		return "mcp_servers"
	case isMap(hooks) || isList(hooks):
		return "hooks"
	case has("lockVersion") || has("integrity"):
		return "lockfile"
	case has("skills") || has("interface") || (has("name") && has("version")):
		return "plugin"
	}
	for _, v := range m {
		s, ok := v.(map[string]any)
		if !ok {
			continue
		}
		_, args := s["args"]
		_, command := s["command"]
		_, url := s["url"]
		if (args && command) || ((s["type"] == "http" || s["type"] == "sse") && url) {
			return "mcp_servers"
		}
	}
	return "generic"
}

func isMap(v any) bool  { _, ok := v.(map[string]any); return ok }
func isList(v any) bool { _, ok := v.([]any); return ok }
