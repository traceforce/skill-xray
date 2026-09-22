// Package pytext reproduces the Python str, json, shlex and urllib semantics
// that the scanner's findings and reports depend on.
package pytext

import (
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// IsSpace is str.isspace for one code point.
func IsSpace(r rune) bool { return unicode.IsSpace(r) || (0x1c <= r && r <= 0x1f) }

const (
	// SpaceBody is the Python \s set as an RE2 class body, for use inside a larger [...].
	SpaceBody = `\t\n\v\f\r\x{1c}-\x{1f} \x{85}\p{Z}`
	// Space and NotSpace are the Python \s and \S classes.
	Space    = "[" + SpaceBody + "]"
	NotSpace = "[^" + SpaceBody + "]"
)

// PyRE compiles a Python pattern under RE2 with \s widened to Python's whitespace set.
func PyRE(pattern string) *regexp.Regexp {
	return regexp.MustCompile(strings.ReplaceAll(pattern, `\s`, Space))
}

// IsWord is Python \w on str patterns: isalnum() or "_".
func IsWord(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r) }

// WordBoundary is Python \b at byte offset i of s: exactly one of the code points before and at
// i is a word character (neither exists past the string edges).
func WordBoundary(s string, i int) bool {
	r, _ := runeAt(s, i)
	return IsWord(runeBefore(s, i)) != IsWord(r)
}

// BlankKeepNewlines turns every code point except "\n" into a space, so byte offsets, columns
// and line numbers of the original survive.
func BlankKeepNewlines(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		return ' '
	}, s)
}

// Fields is str.split() with no argument.
func Fields(s string) []string { return strings.FieldsFunc(s, IsSpace) }

// Set is set(xs) as a membership map.
func Set[T comparable](xs ...T) map[T]bool {
	m := make(map[T]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Strip, LStrip and RStrip are str.strip(), lstrip() and rstrip() with no argument.
func Strip(s string) string  { return strings.TrimFunc(s, IsSpace) }
func LStrip(s string) string { return strings.TrimLeftFunc(s, IsSpace) }
func RStrip(s string) string { return strings.TrimRightFunc(s, IsSpace) }

// Head is s[:n] on code points.
func Head(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// SplitLines is str.splitlines(): it breaks at \n \r \r\n \v \f \x1c \x1d \x1e \x85
// \u2028 \u2029 and drops a trailing empty piece.
func SplitLines(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, s[start:i])
			if r == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				n = 2
			}
			start = i + n
		}
		i += n
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// JoinLines is "\n".join(lines[lo:hi]) with Python slice clamping.
func JoinLines(lines []string, lo, hi int) string {
	lo, hi = min(max(lo, 0), len(lines)), min(max(hi, 0), len(lines))
	return strings.Join(lines[lo:max(lo, hi)], "\n")
}

// Lower is str.lower(): full case mapping (İ -> i̇) with the final-sigma rule.
func Lower(s string) string { return cases.Lower(language.Und).String(s) }

// CaseFold is str.casefold(). x/text folds the Cherokee capitals to the small letters;
// CaseFolding.txt (and so Python) folds the small letters to the capitals, which are stable.
func CaseFold(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case 0xAB70 <= r && r <= 0xABBF:
			return r - 0xAB70 + 0x13A0
		case 0x13F8 <= r && r <= 0x13FD:
			return r - 8
		}
		return r
	}, cases.Fold().String(s))
}

// SplitExt is posixpath.splitext: leading dots of the last component are not an extension.
func SplitExt(p string) (root, ext string) {
	sep := strings.LastIndexByte(p, '/')
	dot := strings.LastIndexByte(p, '.')
	if dot > sep {
		for i := sep + 1; i < dot; i++ {
			if p[i] != '.' {
				return p[:dot], p[dot:]
			}
		}
	}
	return p, ""
}

// Basename is posixpath.basename: the text after the last slash.
func Basename(p string) string { return p[strings.LastIndexByte(p, '/')+1:] }

// CommandBasename is the lowercased basename of a command token, backslashes read as slashes and
// the first matching suffix stripped (the oracle's _basename / _basename_any / _portable_basename).
func CommandBasename(token string, suffixes ...string) string {
	name := Lower(Basename(strings.ReplaceAll(token, `\`, "/")))
	for _, x := range suffixes {
		if strings.HasSuffix(name, x) {
			return strings.TrimSuffix(name, x)
		}
	}
	return name
}

// IsPrintable is str.isprintable().
func IsPrintable(s string) bool {
	return utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0
}

// decodeRune reads one code point; an undecodable byte becomes the lone surrogate
// Python's surrogateescape handler would carry for it.
func decodeRune(s string, i int) (rune, int) {
	r, n := utf8.DecodeRuneInString(s[i:])
	if r == utf8.RuneError && n == 1 {
		return 0xDC00 + rune(s[i]), 1
	}
	return r, n
}

func writeHex(b *strings.Builder, prefix string, r rune, width int) {
	fmt.Fprintf(b, "%s%0*x", prefix, width, r)
}

// Repr is repr(str).
func Repr(s string) string {
	q := '\''
	if strings.IndexByte(s, '\'') >= 0 && strings.IndexByte(s, '"') < 0 {
		q = '"'
	}
	var b strings.Builder
	b.WriteRune(q)
	for i := 0; i < len(s); {
		r, n := decodeRune(s, i)
		i += n
		switch {
		case r == q || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < ' ' || r == 0x7f:
			writeHex(&b, `\x`, r, 2)
		case r < 0x7f || unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xff:
			writeHex(&b, `\x`, r, 2)
		case r <= 0xffff:
			writeHex(&b, `\u`, r, 4)
		default:
			writeHex(&b, `\U`, r, 8)
		}
	}
	b.WriteRune(q)
	return b.String()
}

// UnicodeEscape is str.encode("unicode_escape").decode("ascii").
func UnicodeEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := decodeRune(s, i)
		i += n
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < ' ' || (0x7f <= r && r <= 0xff):
			writeHex(&b, `\x`, r, 2)
		case r < 0x7f:
			b.WriteByte(byte(r))
		case r <= 0xffff:
			writeHex(&b, `\u`, r, 4)
		default:
			writeHex(&b, `\U`, r, 8)
		}
	}
	return b.String()
}

// FindAllIf is re.finditer for a pattern whose lookaround or backreference RE2 lacks: accept
// sees each candidate's submatch indices (absolute bytes) and may reject it, in which case
// scanning resumes one code point later, as Python's engine would, so a dropped match cannot
// hide an overlapping accepted one. An accepted match resumes after itself; an empty one, even
// at the end of s, advances one code point.
func FindAllIf(re *regexp.Regexp, s string, accept func(m []int) bool) [][]int {
	var out [][]int
	for pos := 0; pos <= len(s); {
		m := re.FindStringSubmatchIndex(s[pos:])
		if m == nil {
			break
		}
		for i := range m {
			if m[i] >= 0 {
				m[i] += pos
			}
		}
		if accept(m) {
			out = append(out, m)
			if m[1] > m[0] {
				pos = m[1]
				continue
			}
		}
		_, n := runeAt(s, m[0])
		pos = m[0] + n
	}
	return out
}

// FindAllBounded is FindAllIf for a pattern whose zero-width assertions sit at its ends (\b,
// lookarounds): re is the pattern without them; left and right see the code point before and
// after each candidate match (-1 at the string edges) and must both accept it (nil accepts
// everything).
func FindAllBounded(re *regexp.Regexp, s string, left, right func(rune) bool) [][]int {
	return FindAllIf(re, s, func(m []int) bool {
		r, _ := runeAt(s, m[1])
		return accepts(left, runeBefore(s, m[0])) && accepts(right, r)
	})
}

func accepts(f func(rune) bool, r rune) bool { return f == nil || f(r) }

func runeBefore(s string, i int) rune {
	if i == 0 {
		return -1
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return r
}

// runeAt is the code point at i and its width, or (-1, 1) at the end of s.
func runeAt(s string, i int) (rune, int) {
	if i >= len(s) {
		return -1, 1
	}
	return utf8.DecodeRuneInString(s[i:])
}

// OSErrorName is type(exc).__name__ for the OSError Python would raise for err.
func OSErrorName(err error) string {
	for _, m := range osErrorNames {
		for _, target := range m.targets {
			if errors.Is(err, target) {
				return m.name
			}
		}
	}
	return "OSError"
}

var osErrorNames = []struct {
	name    string
	targets []error
}{
	{"PermissionError", []error{fs.ErrPermission}},
	{"FileNotFoundError", []error{fs.ErrNotExist, exec.ErrNotFound}}, // subprocess: a missing binary
	{"FileExistsError", []error{fs.ErrExist}},
	{"NotADirectoryError", notADirectory()},
	{"IsADirectoryError", []error{syscall.EISDIR}},
	{"TimeoutError", []error{syscall.ETIMEDOUT}},
	{"InterruptedError", []error{syscall.EINTR}},
	{"BlockingIOError", []error{syscall.EAGAIN, syscall.EWOULDBLOCK, syscall.EINPROGRESS, syscall.EALREADY}},
	{"BrokenPipeError", []error{syscall.EPIPE, syscall.ESHUTDOWN}},
	{"ConnectionRefusedError", []error{syscall.ECONNREFUSED}},
	{"ConnectionResetError", []error{syscall.ECONNRESET}},
	{"ConnectionAbortedError", []error{syscall.ECONNABORTED}},
}

// Python raises NotADirectoryError for ERROR_DIRECTORY (267) on Windows; Go's invented
// ENOTDIR there is ERROR_PATH_NOT_FOUND (3), which both sides report as FileNotFoundError.
func notADirectory() []error {
	errs := []error{syscall.ENOTDIR}
	if runtime.GOOS == "windows" {
		errs = append(errs, syscall.Errno(267))
	}
	return errs
}

// DeepCopy is copy.deepcopy for the JSON-like values the scanner builds (map[string]any,
// []any, []map[string]any, []string); everything else is returned as is.
// ponytail: a new evidence slice type would alias until a case is added here.
func DeepCopy(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case map[string]any:
		if x == nil {
			return v
		}
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = DeepCopy(e)
		}
		return m
	case []any:
		if x == nil {
			return v
		}
		l := make([]any, len(x))
		for i, e := range x {
			l[i] = DeepCopy(e)
		}
		return l
	case []map[string]any:
		if x == nil {
			return v
		}
		l := make([]map[string]any, len(x))
		for i, e := range x {
			l[i] = DeepCopy(e).(map[string]any)
		}
		return l
	case []string:
		return slices.Clone(x)
	}
	return v
}
