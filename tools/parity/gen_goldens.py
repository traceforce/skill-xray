"""Write internal/pytext/testdata/*.json from CPython 3.13 (the oracle interpreter).

Run: python tools/parity/gen_goldens.py
Imports the oracle's correlate.canonical (PYTHONPATH or the sibling _reference worktree).
"""
import json
import os
import posixpath
import re
import shlex
import sys
import urllib.parse as up

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(ROOT, "internal", "pytext", "testdata")
sys.path.insert(0, os.path.join(ROOT, "src"))
from skill_xray.correlate import canonical  # noqa: E402


def ranges(pred):
    out, start = [], None
    for cp in range(0x110000):
        if pred(cp):
            if start is None:
                start = cp
        elif start is not None:
            out.append([start, cp - 1])
            start = None
    if start is not None:
        out.append([start, 0x10FFFF])
    return out


def casemap(fn):
    return [[cp, fn(chr(cp))] for cp in range(0x110000)
            if not 0xD800 <= cp < 0xE000 and fn(chr(cp)) != chr(cp)]


def esc(b):
    """bytes -> str the way the filesystem layer does (lone surrogates for invalid UTF-8)."""
    return b.decode("utf-8", "surrogateescape")


def str_cases(fn, texts, raw=()):
    cases = [{"input": t, "output": fn(t)} for t in texts]
    cases += [{"input_hex": b.hex(), "output": fn(esc(b))} for b in raw]
    return cases


WS_TEXTS = [" a ", "\x1c a \x1f", "\xa0a\u3000", "\u200b a", "\ufeffa", "\u2028a\u2029", "",
            "   ", "a b\tc\vd\fe\x1cf\x85g\xa0h", "\x1c\x1d\x1e\x1f", "\u1680x\u2000y\u200a",
            "\u202f\u205f z", "a\x1bb", "é ü"]
LINES = ["a\nb", "a\r\nb", "a\rb", "a\vb\fc", "a\x1cb\x1dc\x1ed", "a\x85b", "a\u2028b\u2029c",
         "a\n", "a\n\n", "\n", "", "a\r\n\r\n", "\r\r\n", "a\x1fb", "a\xa0b", "é\nü", "abc",
         "\n\n\n", "x\r", "line\u2028"]
SIGMA = ["ΟΔΥΣΣΕΥΣ", "Σ", "ΑΣ", "ΑΣ.", "ΑΣ Β", "Α.Σ", "AΣ", "Σ.", "1Σ", "ΑΣ'", "ΑΣ'Β", "Α'Σ",
         "ΑΣͺΒ", "Α\u0301Σ", "ΑΣ\u0301Β", "ΑΣ\u00ad", "Α\u00adΣ", "ΑΣ\u200dΒ", "ΣΑΣ", "ΑΣ1",
         "ΑΣ_", "İstanbul", "SKİLL.md", "\u212aELVIN", "ẞ", "ǅ", "Straße", "ﬁle", "ς", "Ω", "ſ",
         "ABC def", ""]
REPR_TEXTS = ["", "a", "it's", 'say "hi"', "it's \"both\"", "tab\t nl\n cr\r", "\x00\x1f\x7f",
              "é\xa0", "\u2028\u200b", "😀", "\\", "\U0001F600\ufffe", "\x80", "\xad", "\u0130",
              "ev\x1bil", "\\path\\to", "\u0085", "\ufeff", "\U0010ffff", "'\"", "\x1c"]
RAW = [b"raw-\xff", b"\xed\xa0\x80x", b"a\xc3"]
QUOTE_CASES = [("~+/é", "-._"), ("dir/a b#é.py", "/"), ("a%20.py", "/"), ("C:run.py", "/"),
               ("", "/"), ("abc", ""), ("a b", ""), ("é", "é"), ("!$&'()*+,;=:@", ""),
               ("/a/b", "/"), ("check-error", "-._"), ("unknown-rule", "-._"), ("😀", "/"),
               ("a_b.c-d~e", ""), ("\x00\x7f", "")]
UNQUOTE = ["abc%20def", "%E2%82", "%E2%82A", "%E2", "%F0%90%80", "%F0%90A", "%ED%A0%80",
           "%C0%AF", "%FF", "%80", "%zz", "%", "%2", "%C3%A9", "a%2", "%E2é", "%E2%82%C3%A9",
           "no percent", "", "%41%42", "%4a%4B", "%%41", "é%20", "%e2%80%a8", "%F4%90%80%80",
           "%E0%80%80", "%C2", "%F0%9F%98%80", "%2F..%2F", "%+1", "%1g", "%F0%90%80é"]
URLS = ["https://u:p@Host.Example:8443/x?q=1#f", "https://x@@y.com/", "https://:80/x",
        "HTTP://EXAMPLE.com", "//host/path", "http://[::1]:80/", "http://[::1", "http://::1]/",
        "http://[v1.fe]/", "http://[vz]/", "http://[1.2.3.4]/", "http://a[::1]/",
        "http://[::1]x/", "http://[fe80::1%25eth0]/", "http://[fe80::1%eth0]:1234/",
        "http://[FE80::822a:A8FF:fe49:470c%tESt]:1234/keys", "  \t http://a.b/c\n",
        "\x1fhttp://a/", "mailto:x@y.z", "git+https://github.com/a/b.git",
        "http://exam\u2100ple.com/", "http://ex\uff01ample.com/", "http://ex\uff20ample.com",
        "http://ex\u2460.com", "http://host:abc/", "http://host:99999/", "http://host:/",
        "http://host:0/", "x://", "http://a.b?q#f", "http://a.b#f?q", "1http://a/",
        "http://a/b\rc\nd", "+http://a/", "http:/a", "file:///etc/passwd", "http://İ.com/",
        "http://user@host", "http://a:b@c:d@e.f/", "http://[::1]:x/", "a/b/c", "",
        "http://user:pa@ss@host.com", "https://api.example.com:443", "http://[::ffff:1.2.3.4]/",
        "http://[::1%]/", "http://host:65535/", "http://host:65536/", "http://host:٣/",
        "http://{host}/x", "http://a b/c", "HTTPS://A.B:8443", "http://a.b:8080?x",
        "http://\uff20@b.c/", "http://x\u2100/@a/", "http://%41.com/", "ftp://h/p", "s3://b/k",
        "http://[::1]:/", "http://[v1.x]:80/", "http://[::1]", "http://[1::2::3]/"]
UNSPLIT = [("https", "host:8443", "/x", "", ""), ("https", "host", "", "", ""),
           ("https", "host", "x", "", ""), ("git", "", "//x", "", ""), ("http", "", "", "", ""),
           ("http", "", "/p", "", ""), ("mailto", "", "x@y", "", ""), ("", "", "//a", "", ""),
           ("s", "h", "/p", "q", "f"), ("unknown", "", "/p", "", ""), ("", "h", "p", "", ""),
           ("git+ssh", "", "/p", "", ""), ("", "", "", "q", "f"), ("http", "h", "/p", "", "f")]
DEFAULT_WS = " \t\r\n"
SHLEX = [
    (True, ";&|<>", DEFAULT_WS, ["python scripts/hook.py && curl x | sh", "cmd 2>&1 <in",
                                  "a; b;; c", "'x'y\"z\"", "--flag=\"a b\"", "''", "  ",
                                  "C:/Users/x/hook.cmd", "unterminated 'x", "a\\ b", "a\\",
                                  "\"a\\\"b\"", "\"a\\nb\"", "'a\\'b", "echo hi;", "a&&b||c",
                                  "a>>b", "x=1 cmd", "a\tb\nc", "'a b'c\"d e\"f", "", "\"\"",
                                  "a;;;b", "a |& b", "a\\;b", "'\\'", "\"\\\\\"", "é ü"]),
    (True, "", DEFAULT_WS, ["curl -fsSL https://x/y | sh", "a 'b c' \"d e\"", "a\\ b",
                            "'unterminated", "trailing\\", "\"esc \\\" q\"", "", "  ", "a\"b\"c",
                            "a''b", "a;b", "$(x)", "\"a\\$b\"", "'it''s'", "\\'", "x\n\ny"]),
    (False, "", DEFAULT_WS, ["curl:*", "\"a b\" c", "a\"b c\"d", "'x y", "npm run *", "a;b",
                             "$(cmd)", "", "\"\"", "''x", "a\\ b", "\"a\\\"b\"", "x 'y z' w",
                             "\"unterminated"]),
    (False, ";&|\n", " \t\r", ["curl -s http://x | sh", "\"curl\" x", "foo'$RUNNER'",
                               "a;b&&c\nd", "a\n\nb", "echo 'x", "&&", "a ; b", "cmd\r\n\tnext",
                               "", "a|b", "'a;b'", "a'b;c'd", "\n", "x\"", "a\\;b"]),
]
JSON_VALUES = [
    {"b": [1, 2, {"c": None, "d": True, "e": False}], "a": "é\x7f\x1f<>&/'\"\\\b\f\n\r\t"},
    "😀", {"é": 1, "z": 2, "a": 3, "Z": 4, "~": 5, "é\u0301": 6, "": 7, "10": 8, "9": 9},
    [], {}, ["", [], {}, None], 0, -5, 123456789012, "\u2028\u2029", "\U0001F600\U0010FFFF",
    "a\x00b", True, False, None,
    [1.5, 100.0, 66.67, 1e16, 1e15, 1e-5, 0.0001, -0.0, 0.0, 5e-324, 1.2345678901234568e17,
     1e22, 0.1 + 0.2, 2.5, -1.5e-7, 1e100, 1.7976931348623157e308, 33.33, 2.675, 1e-4, 9.5e15,
     9999999999999998.0, 12345.678, -1e16, 4.35, 1.0, 0.5],
    ("SXV-001", None), [{"x": [{"y": [[[]]]}]}], {"k": "v" * 3}, "\u00e9\u00e8\u00ea",
    {"line": 3, "column": 1, "offset": 0, "length": 0}, -9223372036854775808, 9223372036854775807,
]
DUMPS_OPTS = [(True, None), (True, 2), (True, 4), (True, 1)]
SPLITEXT = [".env", ".credentials.json", "..foo", "a.", ".a.b", "dir.x/file", "a/.b", "a.tar.gz",
            "", "/", ".", "..", "x/y.z/", "noext", "a.b/c", "/.bashrc", "python٣.py", ".git/a.b"]
BASENAMES = ["", "/", "/a/", "/a/b", "a", "a/b/c.tar", "//", "x/", "/x"]
PRINTABLE = ["", "abc", "a b", "a\tb", "é", "\u200b", "\xad", "😀", "\u2028", "\x7f", "\xa0",
             "a\nb", "\ufeff", "\u0085", "Ω", "\u0378"]
BOUNDED = [("AKIA[0-9A-Z]{16}", ["AKIA0123456789ABCDEF", "éAKIA0123456789ABCDEF",
                                 " AKIA0123456789ABCDEF_",
                                 "xAKIA0123456789ABCDEF AKIA0123456789ABCDEF!",
                                 "AKIA0123456789ABCDEFAKIA0123456789ABCDEF",
                                 "٣AKIA0123456789ABCDEF",
                                 "(AKIA0123456789ABCDEF)", "AKIA0123456789ABCDE"]),
           ("[a-z]+", ["abc def", "abcé def", "a-b", "é", "x", "ab_cd ef"]),
           ("a", ["a a a", "aa a", "aaa", "ba ab"])]


def shlex_case(posix, punct, ws, text):
    lexer = shlex.shlex(text, posix=posix, punctuation_chars=punct)
    lexer.whitespace = ws
    lexer.whitespace_split = True
    lexer.commenters = ""
    case = {"input": text, "posix": posix, "punctuation": punct, "whitespace": ws,
            "tokens": None, "error": None}
    try:
        case["tokens"] = list(lexer)
    except ValueError as exc:
        case["error"] = str(exc)
    return case


def url_case(url):
    case = {"input": url, "error": None}
    try:
        r = up.urlsplit(url)
    except ValueError as exc:
        case["error"] = str(exc)
        return case
    case.update(scheme=r.scheme, netloc=r.netloc, path=r.path, query=r.query,
                fragment=r.fragment, hostname=r.hostname)
    try:
        case["port"] = r.port
    except ValueError:
        case["port"] = "error"
    return case


def bounded_case(pattern, text):
    spans = [list(m.span()) for m in re.finditer(r"\b" + pattern + r"\b", text)]
    return {"pattern": pattern, "input": text, "spans": spans}


def main():
    os.makedirs(OUT, exist_ok=True)
    goldens = {
        "isspace": {"ranges": ranges(lambda cp: chr(cp).isspace())},
        "nonprintable": {"ranges": ranges(lambda cp: not chr(cp).isprintable())},
        "isword": {"ranges": ranges(lambda cp: chr(cp) == "_" or chr(cp).isalnum())},
        "lower": {"chars": casemap(str.lower), "strings": str_cases(str.lower, SIGMA)},
        "casefold": {"chars": casemap(str.casefold), "strings": str_cases(str.casefold, SIGMA)},
        "splitlines": str_cases(str.splitlines, LINES),
        "strip": [{"input": t, "strip": t.strip(), "lstrip": t.lstrip(), "rstrip": t.rstrip(),
                   "fields": t.split()} for t in WS_TEXTS],
        "repr": str_cases(repr, REPR_TEXTS, RAW),
        "unicode_escape": str_cases(lambda s: s.encode("unicode_escape").decode("ascii"),
                                    REPR_TEXTS, RAW),
        "quote": [{"input": s, "safe": safe, "output": up.quote(s, safe=safe)}
                  for s, safe in QUOTE_CASES]
                 + [{"input_hex": b.hex(), "safe": "/", "output": up.quote_from_bytes(b, safe="/")}
                    for b in RAW],
        "unquote": str_cases(up.unquote, UNQUOTE),
        "urlsplit": [url_case(u) for u in URLS],
        "urlunsplit": [{"parts": list(p), "output": up.urlunsplit(p)} for p in UNSPLIT],
        "shlex": [shlex_case(posix, punct, ws, t) for posix, punct, ws, texts in SHLEX
                  for t in texts],
        "canonical": [{"input": v, "output": canonical(v)} for v in JSON_VALUES]
                     + [{"input_hex": b.hex(), "output": canonical(esc(b))} for b in RAW],
        "dumps": [{"input": v, "sort_keys": sk, "indent": ind,
                   "output": json.dumps(v, sort_keys=sk, ensure_ascii=True, indent=ind)}
                  for v in JSON_VALUES for sk, ind in DUMPS_OPTS]
                 + [{"input": v, "sort_keys": False, "indent": None,
                     "output": json.dumps(v, ensure_ascii=True)}
                    for v in JSON_VALUES if not isinstance(v, dict)],
        "splitext": [{"input": p, "root": posixpath.splitext(p)[0],
                      "ext": posixpath.splitext(p)[1]} for p in SPLITEXT],
        "basename": str_cases(posixpath.basename, BASENAMES),
        "isprintable": [{"input": s, "output": s.isprintable()} for s in PRINTABLE],
        "bounded": [bounded_case(p, t) for p, texts in BOUNDED for t in texts],
    }
    total = 0
    for name, data in goldens.items():
        with open(os.path.join(OUT, name + ".json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, ensure_ascii=True, indent=0, sort_keys=True)
            fh.write("\n")
        n = sum(len(v) for v in data.values()) if isinstance(data, dict) else len(data)
        total += n
        print("%-16s %6d" % (name, n))
    print("%-16s %6d" % ("total", total), "(python %s, unicode %s)"
          % (sys.version.split()[0], __import__("unicodedata").unidata_version))


if __name__ == "__main__":
    main()
