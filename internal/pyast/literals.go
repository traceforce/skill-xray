package pyast

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/text/unicode/runenames"
)

// parseNumber converts a NUMBER token's text the way the compiler does (int with base
// prefixes and underscores, float, imaginary).
func parseNumber(s string) any {
	s = strings.ReplaceAll(s, "_", "")
	last := s[len(s)-1]
	if last == 'j' || last == 'J' {
		f, _ := strconv.ParseFloat(s[:len(s)-1], 64)
		return complex(0, f)
	}
	// Base 0 reads the 0x/0o/0b prefixes; a bare leading 0 (octal to Go) only ever arrives as
	// 0, 00, ... because the tokenizer refuses leading zeros in decimals.
	if v, err := strconv.ParseInt(s, 0, 64); err == nil {
		return v
	}
	if b, ok := new(big.Int).SetString(s, 0); ok {
		return b
	}
	f, _ := strconv.ParseFloat(s, 64) // out of range parses to ±Inf like CPython's literal
	return f
}

// stringToken is a STRING token split into its parts.
type stringToken struct {
	body            string
	raw, bytes, uni bool
}

func splitStringToken(s string) stringToken {
	var st stringToken
	i := 0
	for ; i < len(s) && s[i] != '\'' && s[i] != '"'; i++ {
		switch s[i] {
		case 'r', 'R':
			st.raw = true
		case 'b', 'B':
			st.bytes = true
		case 'u', 'U':
			st.uni = true
		}
	}
	q := s[i:]
	quoteLen := 1
	if len(q) >= 6 && q[1] == q[0] && q[2] == q[0] {
		quoteLen = 3
	}
	st.body = q[quoteLen : len(q)-quoteLen]
	return st
}

// decodeStringLiteral is _PyPegen_parse_string: the Constant value for one STRING token; the
// error carries the message CPython wraps as "(unicode error) ..." / "(value error) ...".
func decodeStringLiteral(s string) (value any, kind string, err error) {
	st := splitStringToken(s)
	if st.uni {
		kind = "u"
	}
	if st.bytes {
		if strings.IndexFunc(st.body, func(r rune) bool { return r >= 0x80 }) >= 0 {
			return nil, "", errors.New("bytes can only contain ASCII literal characters")
		}
		if st.raw {
			return []byte(st.body), kind, nil
		}
		b, e := decodeBytesEscapes(st.body)
		if e != nil {
			return nil, "", fmt.Errorf("(value error) %v", e)
		}
		return b, kind, nil
	}
	if st.raw {
		return st.body, kind, nil
	}
	v, e := decodeUnicodeEscapes(st.body)
	if e != nil {
		return nil, "", fmt.Errorf("(unicode error) %v", e)
	}
	return v, kind, nil
}

// simpleEscapes are the one-byte escapes shared by str and bytes literals.
var simpleEscapes = map[byte]byte{'\\': '\\', '\'': '\'', '"': '"', 'a': 7, 'b': 8, 'f': 12, 'n': '\n', 'r': '\r', 't': '\t', 'v': 11}

// decodeUnicodeEscapes is the unicode_escape codec as the compiler applies it to str
// literals: unknown escapes are kept verbatim.
func decodeUnicodeEscapes(s string) (string, error) {
	if strings.IndexByte(s, '\\') < 0 {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\\' {
			b.WriteByte(c)
			i++
			continue
		}
		start := i
		i++
		if i >= len(s) {
			b.WriteByte('\\')
			break
		}
		c = s[i]
		i++
		switch c {
		case '\n':
		case '0', '1', '2', '3', '4', '5', '6', '7':
			v := int(c - '0')
			for k := 0; k < 2 && i < len(s) && s[i] >= '0' && s[i] <= '7'; k++ {
				v = v*8 + int(s[i]-'0')
				i++
			}
			writeCodePoint(&b, rune(v)) // #nosec G115 -- v is at most three octal digits
		case 'x', 'u', 'U':
			n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
			end := i
			for end < len(s) && end < i+n && isXDigit(int(s[end])) {
				end++
			}
			if end < i+n {
				return "", fmt.Errorf("'unicodeescape' codec can't decode bytes in position %d-%d: truncated \\%cXX%s escape", start, end-1, c, map[byte]string{'x': "", 'u': "XX", 'U': "XXXXXX"}[c])
			}
			v, _ := strconv.ParseUint(s[i:end], 16, 32)
			if v > 0x10FFFF {
				return "", fmt.Errorf("'unicodeescape' codec can't decode bytes in position %d-%d: illegal Unicode character", start, i+n-1)
			}
			i += n
			writeCodePoint(&b, rune(v))
		case 'N':
			if i >= len(s) || s[i] != '{' {
				return "", fmt.Errorf("'unicodeescape' codec can't decode bytes in position %d-%d: malformed \\N character escape", start, i-1)
			}
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return "", fmt.Errorf("'unicodeescape' codec can't decode bytes in position %d-%d: malformed \\N character escape", start, len(s)-1)
			}
			name := s[i+1 : i+end]
			r, ok := lookupName(name)
			if !ok {
				return "", fmt.Errorf("'unicodeescape' codec can't decode bytes in position %d-%d: unknown Unicode character name", start, i+end)
			}
			i += end + 1
			writeCodePoint(&b, r)
		default:
			if e, ok := simpleEscapes[c]; ok {
				b.WriteByte(e)
			} else {
				b.WriteByte('\\')
				b.WriteByte(c)
			}
		}
	}
	return b.String(), nil
}

// writeCodePoint encodes r, keeping lone surrogates as their three-byte form so that
// pytext.Repr renders them like Python does.
func writeCodePoint(b *strings.Builder, r rune) {
	if r >= 0xD800 && r <= 0xDFFF {
		b.WriteByte(byte(0xE0 | r>>12))       // #nosec G115 -- r is a surrogate in D800..DFFF, so r>>12 is 0xD
		b.WriteByte(byte(0x80 | (r>>6)&0x3F)) // #nosec G115 -- masked to six bits
		b.WriteByte(byte(0x80 | r&0x3F))      // #nosec G115 -- masked to six bits
		return
	}
	b.WriteRune(r)
}

// decodeBytesEscapes is PyBytes_DecodeEscape (no \N, \u, \U).
func decodeBytesEscapes(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			i++
			continue
		}
		i++
		if i >= len(s) {
			return nil, errors.New("Trailing \\ in string")
		}
		c = s[i]
		i++
		switch c {
		case '\n':
		case '0', '1', '2', '3', '4', '5', '6', '7':
			v := int(c - '0')
			for k := 0; k < 2 && i < len(s) && s[i] >= '0' && s[i] <= '7'; k++ {
				v = v*8 + int(s[i]-'0')
				i++
			}
			out = append(out, byte(v)) // #nosec G115 -- an octal escape above 0o377 stores mod 256, as CPython does
		case 'x':
			if i+2 > len(s) || !isXDigit(int(s[i])) || !isXDigit(int(s[i+1])) {
				return nil, fmt.Errorf("invalid \\x escape at position %d", i-2)
			}
			v, _ := strconv.ParseUint(s[i:i+2], 16, 8)
			out = append(out, byte(v))
			i += 2
		default:
			if e, ok := simpleEscapes[c]; ok {
				out = append(out, e)
			} else {
				out = append(out, '\\', c)
			}
		}
	}
	return out, nil
}

// nameTable is the \N{...} reverse table (formal names only).
// ponytail: x/text has no reverse lookup, so the table is built lazily from every code point
// on first use; name aliases are not covered (none occur in the corpus).
var nameTable = sync.OnceValue(func() map[string]rune {
	m := make(map[string]rune, 1<<17)
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if n := runenames.Name(r); n != "" && !strings.HasPrefix(n, "<") {
			m[n] = r
		}
	}
	return m
})

// lookupName resolves a \N{...} name case-insensitively.
func lookupName(name string) (rune, bool) {
	r, ok := nameTable()[strings.ToUpper(name)]
	return r, ok
}
