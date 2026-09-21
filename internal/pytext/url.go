package pytext

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const alwaysSafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~"

// Quote is urllib.parse.quote(s, safe): UTF-8 bytes outside [A-Za-z0-9_.~-] and safe
// become uppercase %XX.
func Quote(s, safe string) string { return QuoteBytes([]byte(s), safe) }

// NFC is unicodedata.normalize("NFC", s) for a name that may carry undecodable bytes: Python
// keeps each as a lone surrogate that never composes with anything, so every valid UTF-8 run
// is normalised on its own and the bytes between runs are copied through unchanged.
func NFC(s string) string {
	if utf8.ValidString(s) {
		return norm.NFC.String(s)
	}
	var b strings.Builder
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString(norm.NFC.String(s[start:i]))
			b.WriteByte(s[i])
			i++
			start = i
			continue
		}
		i += size
	}
	b.WriteString(norm.NFC.String(s[start:]))
	return b.String()
}

// QuoteBytes is urllib.parse.quote_from_bytes(b, safe); non-ASCII safe characters are ignored.
func QuoteBytes(b []byte, safe string) string {
	var out strings.Builder
	for _, c := range b {
		if c < 0x80 && (strings.IndexByte(alwaysSafe, c) >= 0 || strings.IndexByte(safe, c) >= 0) {
			out.WriteByte(c)
		} else {
			fmt.Fprintf(&out, "%%%02X", c)
		}
	}
	return out.String()
}

// Unquote is urllib.parse.unquote(s): each ASCII run has its valid %XX escapes decoded
// and is then read as UTF-8 with Python's replacement rule (one U+FFFD per maximal
// invalid subsequence); other escapes and non-ASCII text pass through.
func Unquote(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var out strings.Builder
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && s[j] < 0x80 {
			j++
		}
		if j > i {
			out.WriteString(decodeReplace(unquoteBytes(s[i:j])))
		} else {
			for j < len(s) && s[j] >= 0x80 {
				j++
			}
			out.WriteString(s[i:j])
		}
		i = j
	}
	return out.String()
}

func unquoteBytes(s string) []byte {
	bits := strings.Split(s, "%")
	res := []byte(bits[0])
	for _, item := range bits[1:] {
		if len(item) >= 2 {
			if v, err := strconv.ParseUint(item[:2], 16, 8); err == nil {
				res = append(res, byte(v))
				res = append(res, item[2:]...)
				continue
			}
		}
		res = append(res, '%')
		res = append(res, item...)
	}
	return res
}

// decodeReplace is bytes.decode("utf-8", "replace").
func decodeReplace(b []byte) string {
	var out strings.Builder
	for i := 0; i < len(b); {
		r, n := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || n == 3 {
			out.WriteRune(r)
			i += n
			continue
		}
		out.WriteRune(utf8.RuneError)
		i += invalidLen(b[i:])
	}
	return out.String()
}

// invalidLen is the length of the maximal invalid subsequence at the start of b, as
// CPython's decoder counts it: the lead byte plus every continuation byte that was
// still admissible for it.
func invalidLen(b []byte) int {
	c := b[0]
	var need int
	switch {
	case 0xE0 <= c && c <= 0xEF:
		need = 2
	case 0xF0 <= c && c <= 0xF4:
		need = 3
	default:
		return 1
	}
	lo, hi := byte(0x80), byte(0xBF)
	switch c {
	case 0xE0:
		lo = 0xA0
	case 0xED:
		hi = 0x9F
	case 0xF0:
		lo = 0x90
	case 0xF4:
		hi = 0x8F
	}
	n := 1
	for ; n <= need && n < len(b); n++ {
		if b[n] < lo || b[n] > hi {
			break
		}
		lo, hi = 0x80, 0xBF
	}
	return n
}

// URL is urllib.parse.SplitResult.
type URL struct{ Scheme, Netloc, Path, Query, Fragment string }

const (
	c0AndSpace  = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f "
	schemeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-."
)

var (
	unsafeURLBytes = strings.NewReplacer("\t", "", "\r", "", "\n", "")
	ipvFuture      = regexp.MustCompile(`^v[a-fA-F0-9]+\..+$`)
	usesNetloc     = map[string]bool{"ftp": true, "http": true, "gopher": true, "nntp": true,
		"telnet": true, "imap": true, "wais": true, "file": true, "mms": true, "https": true,
		"shttp": true, "snews": true, "prospero": true, "rtsp": true, "rtsps": true,
		"rtspu": true, "rsync": true, "svn": true, "svn+ssh": true, "sftp": true, "nfs": true,
		"git": true, "git+ssh": true, "ws": true, "wss": true, "itms-services": true}
)

// URLSplit is urllib.parse.urlsplit(url); the error carries Python's ValueError text.
func URLSplit(url string) (URL, error) {
	url = unsafeURLBytes.Replace(strings.TrimLeft(url, c0AndSpace))
	var u URL
	if i := strings.IndexByte(url, ':'); i > 0 && isASCIIAlpha(url[0]) && strings.Trim(url[:i], schemeChars) == "" {
		u.Scheme, url = strings.ToLower(url[:i]), url[i+1:]
	}
	if strings.HasPrefix(url, "//") {
		u.Netloc, url = splitNetloc(url, 2)
		open, close := strings.Contains(u.Netloc, "["), strings.Contains(u.Netloc, "]")
		if open != close {
			return URL{}, errors.New("Invalid IPv6 URL")
		}
		if open {
			if err := checkBracketedNetloc(u.Netloc); err != nil {
				return URL{}, err
			}
		}
	}
	if k := strings.IndexByte(url, '#'); k >= 0 {
		url, u.Fragment = url[:k], url[k+1:]
	}
	if k := strings.IndexByte(url, '?'); k >= 0 {
		url, u.Query = url[:k], url[k+1:]
	}
	if err := checkNetloc(u.Netloc); err != nil {
		return URL{}, err
	}
	u.Path = url
	return u, nil
}

func isASCIIAlpha(c byte) bool { return 'a' <= c|0x20 && c|0x20 <= 'z' }

func splitNetloc(url string, start int) (string, string) {
	delim := len(url)
	for _, c := range []byte("/?#") {
		if w := strings.IndexByte(url[start:], c); w >= 0 && start+w < delim {
			delim = start + w
		}
	}
	return url[start:delim], url[delim:]
}

func checkBracketedNetloc(netloc string) error {
	hostPort := netloc[strings.LastIndexByte(netloc, '@')+1:]
	before, bracketed, open := strings.Cut(hostPort, "[")
	host := hostPort
	if open {
		var port string
		host, port, _ = strings.Cut(bracketed, "]")
		if before != "" || (port != "" && !strings.HasPrefix(port, ":")) {
			return errors.New("Invalid IPv6 URL")
		}
	} else {
		host, _, _ = strings.Cut(hostPort, ":")
	}
	if strings.HasPrefix(host, "v") {
		if !ipvFuture.MatchString(host) {
			return errors.New("IPvFuture address is invalid")
		}
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%s does not appear to be an IPv4 or IPv6 address", Repr(host))
	}
	if addr.Is4() {
		return errors.New("An IPv4 address cannot be in brackets")
	}
	return nil
}

var netlocDelims = strings.NewReplacer("@", "", ":", "", "#", "", "?", "")

func checkNetloc(netloc string) error {
	if netloc == "" || IsASCII(netloc) {
		return nil
	}
	n := netlocDelims.Replace(netloc)
	n2 := norm.NFKC.String(n)
	if n != n2 && strings.ContainsAny(n2, "/?#@:") {
		return fmt.Errorf("netloc '%s' contains invalid characters under NFKC normalization", netloc)
	}
	return nil
}

// IsASCII is str.isascii().
func IsASCII(s string) bool { return strings.IndexFunc(s, func(r rune) bool { return r >= 0x80 }) < 0 }

func (u URL) hostinfo() (host, port string) {
	hostinfo := u.Netloc[strings.LastIndexByte(u.Netloc, '@')+1:]
	if _, bracketed, open := strings.Cut(hostinfo, "["); open {
		host, port, _ = strings.Cut(bracketed, "]")
		_, port, _ = strings.Cut(port, ":")
		return host, port
	}
	host, port, _ = strings.Cut(hostinfo, ":")
	return host, port
}

// Hostname is SplitResult.hostname ("" for None): lowercased, an IPv6 zone kept as written.
func (u URL) Hostname() string {
	host, _ := u.hostinfo()
	if host == "" {
		return ""
	}
	host, zone, scoped := strings.Cut(host, "%")
	if scoped {
		return Lower(host) + "%" + zone
	}
	return Lower(host)
}

// Port is SplitResult.port: nil when absent, an error for a non-numeric or out-of-range port.
func (u URL) Port() (*int, error) {
	_, port := u.hostinfo()
	if port == "" {
		return nil, nil
	}
	if strings.Trim(port, "0123456789") != "" {
		return nil, fmt.Errorf("Port could not be cast to integer value as %s", Repr(port))
	}
	n, err := strconv.Atoi(port)
	if err != nil || n > 65535 {
		return nil, errors.New("Port out of range 0-65535")
	}
	return &n, nil
}

// URLUnsplit is urllib.parse.urlunsplit((scheme, netloc, path, query, fragment)).
func URLUnsplit(scheme, netloc, path, query, fragment string) string {
	switch {
	case netloc != "":
		if path != "" && path[0] != '/' {
			path = "/" + path
		}
		path = "//" + netloc + path
	case strings.HasPrefix(path, "//"):
		path = "//" + path
	case scheme != "" && usesNetloc[scheme] && (path == "" || path[0] == '/'):
		path = "//" + path
	}
	if scheme != "" {
		path = scheme + ":" + path
	}
	if query != "" {
		path += "?" + query
	}
	if fragment != "" {
		path += "#" + fragment
	}
	return path
}
