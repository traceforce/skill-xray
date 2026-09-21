package pytext

import (
	"errors"
	"strings"
)

// ShlexSplit is shlex.split(s): POSIX quoting and escapes, whitespace_split, no comments.
func ShlexSplit(s string) ([]string, error) { return ShlexTokens(s, true, "", " \t\r\n") }

// ShlexTokens is list(shlex.shlex(s, posix=posix, punctuation_chars=punctuation)) after
// the scanner's configuration: whitespace_split=True, commenters="" and the given
// whitespace set. Under whitespace_split wordchars never decide anything, so it has none.
// The errors are Python's "No closing quotation" and "No escaped character".
func ShlexTokens(s string, posix bool, punctuation, whitespace string) ([]string, error) {
	l := &shlexer{in: []rune(s), posix: posix, punct: punctuation, ws: whitespace, state: ' '}
	out := []string{}
	for {
		tok, eof, err := l.readToken()
		if err != nil {
			return nil, err
		}
		if eof {
			return out, nil
		}
		out = append(out, tok)
	}
}

const shlexQuotes = `'"`

type shlexer struct {
	in        []rune
	pos       int
	pushback  []rune
	posix     bool
	punct, ws string
	state     rune // ' ', 'a', 'c', a quote, '\\', or -1 past the end of input
	token     []rune
}

func (l *shlexer) next() rune {
	if l.punct != "" && len(l.pushback) > 0 {
		c := l.pushback[len(l.pushback)-1]
		l.pushback = l.pushback[:len(l.pushback)-1]
		return c
	}
	if l.pos >= len(l.in) {
		return -1
	}
	c := l.in[l.pos]
	l.pos++
	return c
}

func in(set string, c rune) bool { return c >= 0 && strings.ContainsRune(set, c) }

// readToken is shlex.read_token; eof reports what __next__ treats as the end marker
// (None in POSIX mode, "" otherwise).
func (l *shlexer) readToken() (tok string, eof bool, err error) {
	quoted := false
	escapedState := ' '
	emit := func() bool { return len(l.token) > 0 || (l.posix && quoted) }
scan:
	for {
		c := l.next()
		switch {
		case l.state == -1:
			l.token = nil
			break scan
		case l.state == ' ':
			switch {
			case c < 0:
				l.state = -1
				break scan
			case in(l.ws, c):
				if emit() {
					break scan
				}
			case l.posix && c == '\\':
				escapedState, l.state = 'a', c
			case in(l.punct, c):
				l.token, l.state = []rune{c}, 'c'
			case in(shlexQuotes, c):
				if !l.posix {
					l.token = []rune{c}
				}
				l.state = c
			default:
				l.token, l.state = []rune{c}, 'a'
			}
		case in(shlexQuotes, l.state):
			quoted = true
			switch {
			case c < 0:
				return "", false, errors.New("No closing quotation")
			case c == l.state:
				if !l.posix {
					l.token = append(l.token, c)
					l.state = ' '
					break scan
				}
				l.state = 'a'
			case l.posix && c == '\\' && l.state == '"':
				escapedState, l.state = l.state, c
			default:
				l.token = append(l.token, c)
			}
		case l.state == '\\':
			if c < 0 {
				return "", false, errors.New("No escaped character")
			}
			if in(shlexQuotes, escapedState) && c != l.state && c != escapedState {
				l.token = append(l.token, l.state)
			}
			l.token = append(l.token, c)
			l.state = escapedState
		default: // 'a' or 'c'
			switch {
			case c < 0:
				l.state = -1
				break scan
			case in(l.ws, c):
				l.state = ' '
				if emit() {
					break scan
				}
			case l.state == 'c':
				if in(l.punct, c) {
					l.token = append(l.token, c)
					continue
				}
				if !in(l.ws, c) {
					l.pushback = append(l.pushback, c)
				}
				l.state = ' '
				break scan
			case l.posix && in(shlexQuotes, c):
				l.state = c
			case l.posix && c == '\\':
				escapedState, l.state = 'a', c
			case !in(l.punct, c):
				l.token = append(l.token, c)
			default:
				l.pushback = append(l.pushback, c)
				l.state = ' '
				if emit() {
					break scan
				}
			}
		}
	}
	tok, l.token = string(l.token), nil
	return tok, tok == "" && (!l.posix || !quoted), nil
}
