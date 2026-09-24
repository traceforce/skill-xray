package pytext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Canonical is json.dumps(v, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
// allow_nan=False); it panics on NaN or an infinity as Python raises ValueError.
func Canonical(v any) string {
	var b strings.Builder
	encode(&b, v, 0, encOpts{item: ",", key: ":"})
	return b.String()
}

// Dumps is json.dumps(v, ensure_ascii=True, indent=indent), where indent 0 is
// Python's indent=None (default separators). Go maps carry no insertion order, so
// keys are always emitted sorted (sort_keys=True).
func Dumps(v any, indent int) string {
	o := encOpts{item: ", ", key: ": ", allowNaN: true}
	if indent > 0 {
		o.indent, o.item = strings.Repeat(" ", indent), ","
	}
	var b strings.Builder
	encode(&b, v, 0, o)
	return b.String()
}

// Intify normalises a UseNumber-decoded tree in place: a json.Number becomes
// int when integral and within int64, else float64.
func Intify(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return int(i)
		}
		f, _ := x.Float64()
		return f
	case []any:
		for i := range x {
			x[i] = Intify(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = Intify(x[k])
		}
	}
	return v
}

// JSONView is json.loads(json.dumps(v)) with integral numbers as int: the generic, deep-copied
// view of a JSON-encodable value (the to_dict shape); it panics where Marshal fails.
func JSONView(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		panic("pytext: " + err.Error())
	}
	// encoding/json rewrites a byte that is not UTF-8 (a file name Python carries as a
	// surrogate) as U+FFFD, written as the escape \ufffd by Go 1.26 and as the character by
	// Go 1.27; when the output holds either form, marshal a copy with such bytes escaped into
	// private-use runes and restore them after decoding. A genuine U+FFFD takes the same path,
	// which is lossless for it.
	escaped := bytes.Contains(raw, []byte(`\ufffd`)) || bytes.Contains(raw, []byte("\uFFFD"))
	if escaped {
		if raw, err = json.Marshal(escapeInvalid(reflect.ValueOf(v)).Interface()); err != nil {
			panic("pytext: " + err.Error())
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	dec.Decode(&out) // Marshal output always decodes
	if escaped {
		out = unescapeInvalid(out)
	}
	return Intify(out)
}

// escapeMarker opens an escape: the marker doubled is a literal marker, the marker followed by
// escapeBase+b is the byte b. Both runes are private use and valid UTF-8, so encoding/json
// carries them unchanged.
const escapeMarker, escapeBase = '\uF8FF', rune(0xE000)

func escapeString(s string) string {
	if utf8.ValidString(s) && !strings.ContainsRune(s, escapeMarker) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			b.WriteRune(escapeMarker)
			b.WriteRune(escapeBase + rune(s[i]))
		case r == escapeMarker:
			b.WriteRune(escapeMarker)
			b.WriteRune(escapeMarker)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

func unescapeString(s string) string {
	if !strings.ContainsRune(s, escapeMarker) {
		return s
	}
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		if rs[i] != escapeMarker || i+1 == len(rs) {
			b.WriteRune(rs[i])
			continue
		}
		i++
		if rs[i] == escapeMarker {
			b.WriteRune(escapeMarker)
		} else {
			b.WriteByte(byte(rs[i] - escapeBase))
		}
	}
	return b.String()
}

// escapeInvalid is a copy of v with every string, map key included, passed through
// escapeString; unexported struct fields are copied as they are (encoding/json skips them).
func escapeInvalid(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.String:
		return reflect.ValueOf(escapeString(v.String())).Convert(v.Type())
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		p := reflect.New(v.Type().Elem())
		p.Elem().Set(escapeInvalid(v.Elem()))
		return p
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(escapeInvalid(v.Elem()))
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := 0; i < v.NumField(); i++ {
			if f := out.Field(i); f.CanSet() {
				f.Set(escapeInvalid(v.Field(i)))
			}
		}
		return out
	case reflect.Slice:
		if v.IsNil() || v.Type().Elem().Kind() == reflect.Uint8 {
			return v
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(escapeInvalid(v.Index(i)))
		}
		return out
	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(escapeInvalid(v.Index(i)))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		for it := v.MapRange(); it.Next(); {
			out.SetMapIndex(escapeInvalid(it.Key()), escapeInvalid(it.Value()))
		}
		return out
	}
	return v
}

func unescapeInvalid(v any) any {
	switch x := v.(type) {
	case string:
		return unescapeString(x)
	case []any:
		for i := range x {
			x[i] = unescapeInvalid(x[i])
		}
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[unescapeString(k)] = unescapeInvalid(val)
		}
		return out
	}
	return v
}

type encOpts struct {
	allowNaN          bool
	item, key, indent string
}

func encode(b *strings.Builder, v any, level int, o encOpts) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		encodeString(b, x)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		fmt.Fprintf(b, "%d", x)
	case float64:
		b.WriteString(jsonFloat(x, o.allowNaN))
	case float32:
		b.WriteString(jsonFloat(float64(x), o.allowNaN))
	case json.Number:
		if i, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			b.WriteString(strconv.FormatInt(i, 10))
		} else {
			f, _ := strconv.ParseFloat(string(x), 64)
			b.WriteString(jsonFloat(f, o.allowNaN))
		}
	case []any:
		encodeList(b, x, level, o)
	case map[string]any:
		encodeDict(b, x, level, o)
	default:
		encodeReflect(b, v, level, o)
	}
}

func encodeReflect(b *strings.Builder, v any, level int, o encOpts) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			b.WriteString("null")
		} else {
			encode(b, rv.Elem().Interface(), level, o)
		}
	case reflect.Slice, reflect.Array:
		l := make([]any, rv.Len())
		for i := range l {
			l[i] = rv.Index(i).Interface()
		}
		encodeList(b, l, level, o)
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			panic(fmt.Sprintf("pytext: keys must be str, not %s", rv.Type().Key()))
		}
		m := make(map[string]any, rv.Len())
		for it := rv.MapRange(); it.Next(); {
			m[it.Key().String()] = it.Value().Interface()
		}
		encodeDict(b, m, level, o)
	default: // structs and MarshalJSON types: round-trip through encoding/json
		encode(b, JSONView(v), level, o)
	}
}

func encodeList(b *strings.Builder, l []any, level int, o encOpts) {
	container(b, "[]", len(l), level, o, func(i, level int) { encode(b, l[i], level, o) })
}

func encodeDict(b *strings.Builder, m map[string]any, level int, o encOpts) {
	keys := slices.Sorted(maps.Keys(m))
	container(b, "{}", len(keys), level, o, func(i, level int) {
		encodeString(b, keys[i])
		b.WriteString(o.key)
		encode(b, m[keys[i]], level, o)
	})
}

// container writes n items between brackets with json's item separator and indentation.
func container(b *strings.Builder, brackets string, n, level int, o encOpts, item func(i, level int)) {
	if n == 0 {
		b.WriteString(brackets)
		return
	}
	b.WriteByte(brackets[0])
	sep := o.item
	if o.indent != "" {
		level++
		nl := "\n" + strings.Repeat(o.indent, level)
		b.WriteString(nl)
		sep += nl
	}
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(sep)
		}
		item(i, level)
	}
	if o.indent != "" {
		b.WriteString("\n" + strings.Repeat(o.indent, level-1))
	}
	b.WriteByte(brackets[1])
}

// encodeString is json's ensure_ascii string form: short escapes for \" \\ \n \r \t \b \f,
// \u00XX for other C0 and DEL, \uXXXX (surrogate pairs above the BMP) for everything
// non-ASCII; an undecodable byte is written as the \udcXX surrogateescape would carry.
func encodeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, n := decodeRune(s, i)
		i += n
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case ' ' <= r && r <= '~':
			b.WriteByte(byte(r))
		case r < 0x10000:
			writeHex(b, `\u`, r, 4)
		default:
			r -= 0x10000
			writeHex(b, `\u`, 0xd800|(r>>10), 4)
			writeHex(b, `\u`, 0xdc00|(r&0x3ff), 4)
		}
	}
	b.WriteByte('"')
}

// FloatRepr is float.__repr__: shortest round-trip digits, exponent form when the decimal
// point would sit before position -3 or after 16, and nan, inf or -inf.
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64)
	sign := ""
	if e[0] == '-' {
		sign, e = "-", e[1:]
	}
	k := strings.IndexByte(e, 'e')
	digits := strings.Replace(e[:k], ".", "", 1)
	exp, _ := strconv.Atoi(e[k+1:])
	decpt := exp + 1
	switch {
	case decpt <= -4 || decpt > 16:
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		return fmt.Sprintf("%s%se%+03d", sign, m, exp)
	case decpt <= 0:
		return sign + "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		return sign + digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		return sign + digits[:decpt] + "." + digits[decpt:]
	}
}

// jsonFloat is json.encoder.floatstr: FloatRepr with nan and inf spelled NaN, Infinity and
// -Infinity, or the ValueError panic when allow_nan is off.
func jsonFloat(f float64, allowNaN bool) string {
	if !math.IsNaN(f) && !math.IsInf(f, 0) {
		return FloatRepr(f)
	}
	if !allowNaN {
		panic("ValueError: Out of range float values are not JSON compliant: " + FloatRepr(f))
	}
	switch {
	case math.IsNaN(f):
		return "NaN"
	case f > 0:
		return "Infinity"
	}
	return "-Infinity"
}

// Truthy is Python bool() over the JSON values evidence carries.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
