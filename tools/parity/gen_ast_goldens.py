"""Write the internal/pyast goldens from CPython 3.13.2 (the oracle interpreter).

Run: python tools/parity/gen_ast_goldens.py [--corpus corpus/pyast] [--xid-only]

For every corpus/pyast/{pytest,msb}/<sha>.py (read as UTF-8 bytes, no newline translation):

  corpus/pyast/expected/<sha>.txt   line 1 "ok" and then
                                    ast.dump(ast.parse(src), include_attributes=True),
                                    or line 1 "error" and then one JSON object
                                    {"class", "msg", "lineno", "offset", "end_lineno", "end_offset"}
                                    (RecursionError/MemoryError: {"class", "msg"} only).
  corpus/pyast/tokens/<sha>.txt     tokenize.generate_tokens over the newline-translated source
                                    (\r\n and \r -> \n, as _PyTokenizer_FromUTF8 does
                                    before lexing),
                                    one token per line
                                    "TYPE\tstart_line\tstart_col\tend_line\tend_col\t<json string>"
                                    and, when tokenize raises, a last line
                                    "ERROR\t<class>\t<json msg>\t<lineno>\t<offset>".

internal/pyast/testdata/xid.json holds the code point ranges of XID_Start (str.isidentifier on the
single character, so '_' is included) and XID_Continue ("a" + ch).isidentifier() from this
interpreter's Unicode tables.
"""
import ast
import io
import json
import os
import sys
import time
import tokenize
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def expected(src):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(src)
    except SyntaxError as e:
        return "error\n" + json.dumps({"class": type(e).__name__, "msg": e.msg, "lineno": e.lineno,
                                       "offset": e.offset, "end_lineno": e.end_lineno,
                                       "end_offset": e.end_offset}, ensure_ascii=False)
    except (RecursionError, MemoryError) as e:
        return "error\n" + json.dumps({"class": type(e).__name__, "msg": str(e)},
                                      ensure_ascii=False)
    try:
        return "ok\n" + ast.dump(tree, include_attributes=True)
    except RecursionError:  # the parse fit CPython's C limit; dumping needs more Python frames
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(20000)
        try:
            return "ok\n" + ast.dump(tree, include_attributes=True)
        finally:
            sys.setrecursionlimit(old)


def tokens(src):
    translated = src.replace("\r\n", "\n").replace("\r", "\n")
    out = []
    try:
        for t in tokenize.generate_tokens(io.StringIO(translated).readline):
            out.append("%s\t%d\t%d\t%d\t%d\t%s" % (
                tokenize.tok_name[t.type], t.start[0], t.start[1], t.end[0], t.end[1],
                json.dumps(t.string, ensure_ascii=False)))
    except tokenize.TokenError as e:
        out.append("ERROR\tTokenError\t%s\t%d\t%d" % (
            json.dumps(e.args[0], ensure_ascii=False), e.args[1][0], e.args[1][1]))
    except SyntaxError as e:  # IndentationError, TabError
        out.append("ERROR\t%s\t%s\t%s\t%s" % (
            type(e).__name__, json.dumps(e.msg, ensure_ascii=False), e.lineno, e.offset))
    return "\n".join(out) + "\n"


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


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def main(argv):
    corpus = os.path.join(ROOT, "corpus", "pyast")
    if "--corpus" in argv:
        corpus = argv[argv.index("--corpus") + 1]
    xid = {"start": ranges(lambda cp: chr(cp).isidentifier()),
           "continue": ranges(lambda cp: ("a" + chr(cp)).isidentifier())}
    write(os.path.join(ROOT, "internal", "pyast", "testdata", "xid.json"), json.dumps(xid) + "\n")
    print("xid.json: %d start ranges, %d continue ranges" % (
        len(xid["start"]), len(xid["continue"])))
    if "--xid-only" in argv:
        return 0
    t0 = time.time()
    counts = {"ok": 0}
    n = 0
    for sub in ("pytest", "msb"):
        d = os.path.join(corpus, sub)
        if not os.path.isdir(d):
            print("missing", d)
            continue
        for name in sorted(os.listdir(d)):
            if not name.endswith(".py"):
                continue
            sha = name[:-3]
            with open(os.path.join(d, name), "rb") as f:
                src = f.read().decode("utf-8")
            exp = expected(src)
            key = "ok" if exp.startswith("ok\n") else json.loads(exp.split("\n", 1)[1])["class"]
            counts[key] = counts.get(key, 0) + 1
            write(os.path.join(corpus, "expected", sha + ".txt"), exp)
            write(os.path.join(corpus, "tokens", sha + ".txt"), tokens(src))
            n += 1
    print("%d inputs in %.1f s: %s" % (n, time.time() - t0, counts))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
