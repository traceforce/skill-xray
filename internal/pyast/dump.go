package pyast

import (
	"bytes"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/traceforce/skill-xray/internal/pytext"
)

// dump is ast.dump(node, annotate_fields=True, include_attributes=includeAttributes) on
// CPython 3.13: fields that are None or [] are omitted (except Constant/MatchSingleton.value).
func dump(n Node, includeAttributes bool) string {
	var b strings.Builder
	dumpNode(&b, n, includeAttributes)
	return b.String()
}

func dumpNode(b *strings.Builder, n Node, attrs bool) {
	v := reflect.ValueOf(n).Elem()
	p := planOf(v.Type())
	b.WriteString(p.class)
	b.WriteByte('(')
	first := true
	sep := func() {
		if !first {
			b.WriteString(", ")
		}
		first = false
	}
	for k, i := range p.fields {
		f := v.Field(i)
		alwaysShown := p.names[k] == "value" && (p.class == "Constant" || p.class == "MatchSingleton")
		if !alwaysShown && isEmpty(f) {
			continue
		}
		sep()
		b.WriteString(p.names[k])
		b.WriteByte('=')
		dumpValue(b, f, attrs)
	}
	if attrs && p.hasPos {
		pos := v.FieldByName("Pos").Interface().(Pos)
		for _, a := range [...]struct {
			name string
			val  int
		}{{"lineno", pos.Lineno}, {"col_offset", pos.ColOffset}, {"end_lineno", pos.EndLineno}, {"end_col_offset", pos.EndColOffset}} {
			sep()
			b.WriteString(a.name)
			b.WriteByte('=')
			b.WriteString(strconv.Itoa(a.val))
		}
	}
	b.WriteByte(')')
}

func isEmpty(f reflect.Value) bool {
	switch f.Kind() {
	case reflect.Interface, reflect.Pointer:
		return f.IsNil()
	case reflect.Slice, reflect.String:
		return f.Len() == 0
	}
	return false
}

func dumpValue(b *strings.Builder, f reflect.Value, attrs bool) {
	switch f.Kind() {
	case reflect.Interface, reflect.Pointer:
		if f.IsNil() {
			b.WriteString("None")
			return
		}
		if n, ok := f.Interface().(Node); ok {
			dumpNode(b, n, attrs)
			return
		}
		b.WriteString(repr(f.Interface()))
	case reflect.Slice:
		b.WriteByte('[')
		for j := 0; j < f.Len(); j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			dumpValue(b, f.Index(j), attrs)
		}
		b.WriteByte(']')
	case reflect.String:
		b.WriteString(pytext.Repr(f.String()))
	case reflect.Int:
		b.WriteString(strconv.FormatInt(f.Int(), 10))
	default:
		b.WriteString(repr(f.Interface()))
	}
}

// repr is repr() of a constant value as Constant.Value holds it.
func repr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(x, 10)
	case *big.Int:
		return x.String()
	case float64:
		return pytext.FloatRepr(x)
	case complex128:
		return complexRepr(x)
	case string:
		return pytext.Repr(x)
	case []byte:
		return bytesRepr(x)
	case EllipsisValue:
		return "Ellipsis"
	}
	return "?"
}

// complexRepr is complex.__repr__: the parts print without float's ".0".
func complexRepr(c complex128) string {
	part := func(f float64) string { return strings.TrimSuffix(pytext.FloatRepr(f), ".0") }
	re, im := real(c), imag(c)
	if re == 0 && !math.Signbit(re) {
		return part(im) + "j"
	}
	sign := "+"
	if im < 0 || (im == 0 && math.Signbit(im)) {
		sign = "-"
		im = -im
	}
	return "(" + part(re) + sign + part(im) + "j)"
}

func bytesRepr(b []byte) string {
	q := byte('\'')
	if bytes.IndexByte(b, '\'') >= 0 && bytes.IndexByte(b, '"') < 0 {
		q = '"'
	}
	var sb strings.Builder
	sb.WriteByte('b')
	sb.WriteByte(q)
	const hex = "0123456789abcdef"
	for _, c := range b {
		switch {
		case c == q || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c == '\t':
			sb.WriteString(`\t`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c < ' ' || c >= 0x7f:
			sb.WriteString(`\x`)
			sb.WriteByte(hex[c>>4])
			sb.WriteByte(hex[c&0xf])
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte(q)
	return sb.String()
}
