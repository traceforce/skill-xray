"""Concealment and unicode-deception over the IR.

Three vectors over one IR pass, each keyed on a distinct property:

  - SXV-007 (instructed concealment, CWE-451): instruction-lane prose that tells the
    agent to hide its OWN steps/block/actions from the human operator ("do not report
    these steps", "never mention this block", "run this silently"). The precision gate
    is a SELF-REFERENTIAL object (the skill's own steps), not output-volume hygiene.
  - SXV-014 (hidden-codepoint smuggling, CWE-1007/94): codepoints that render as nothing
    or reorder text -- the Unicode tag block, bidi OVERRIDE controls, supplementary
    variation selectors used as a byte channel, and zero-width/invisible runs.
  - SXV-015 (homoglyph/confusable, CWE-1007/829): a single token that mixes scripts where
    the non-Latin characters are Latin confusables, so reviewer and model read it
    differently; elevated when it sits in a governed identity field.

Reads the shared IR only: canonical text, artifact kind, frontmatter source metadata, Markdown
prose/code spans, and the package reference graph. Fails closed and per-artifact isolated:
a hidden codepoint is a property of the byte stream, so the unicode sweep is deliberately
fence-BLIND (a smuggled codepoint inside a ```fence still fires); concealment, by contrast,
is fence-SKIPPING (a directive shown inside a documented code example is not a live
instruction). The check never re-parses the scanned package; confusable-homoglyphs supplies its
declared UTS #39 data through the package API at import."""

from __future__ import annotations

import re
import unicodedata

try:                                                    # python-bidi (UAX #9); optional at runtime
    from bidi import get_display as _bidi_get_display
except Exception:                                       # pragma: no cover - absence handled below
    _bidi_get_display = None

try:                                                    # UTS #39 script + confusables; optional
    from confusable_homoglyphs.categories import alias as _CH_ALIAS
    from confusable_homoglyphs.confusables import confusables_data as _CONFUSABLES_DATA
except Exception:                                       # pragma: no cover - absence handled below
    _CH_ALIAS = None
    _CONFUSABLES_DATA = None

from ..findings import FINDING_CAP as _FINDING_CAP
from ..findings import Finding

# --- concealment (SXV-007) ---------------------------------------------------
# Only standing instruction surfaces are scanned directly.
_CONCEAL_KINDS = {"skill_manifest", "instruction", "agent_identity"}

# Referenced prose is lifted; scripts/configs remain in their own lanes.
_LIFTABLE_KINDS = {"doc", "other"}

# Self-referential objects separate concealment from output-volume hygiene.
_NEG = r"(?:do not|don'?t|never|must not|must never|refuse to|be sure not to)"
_SELFREF = (r"(?:these|those|this|the above)\s+"
            r"(?:steps?|actions?|changes?|commands?|operations?|edits?|calls?|details?)")
_CONCEAL_VERB = r"(?:mention|report|list|summari[sz]e|describe|disclose|reveal|log|record|include)"
_CONCEAL_PATTERNS = [
    ("step_reference", re.compile(_NEG + r"\s+" + _CONCEAL_VERB + r"[^.\n]{0,40}\bsteps?\b\s*\d",
                                  re.I)),
    ("step_reference", re.compile(_NEG + r"\s+" + _CONCEAL_VERB + r"\s+" + _SELFREF, re.I)),
    ("hide_actions", re.compile(
        r"\b(?:hide|conceal|obscure|redact|mask|omit|suppress)\b[^.\n]{0,40}" + _SELFREF, re.I)),
    ("self_block", re.compile(
        r"never mention this block|do not mention this block|"
        r"(?:never|do not|don'?t|must not)\s+"
        r"(?:mention|summari[sz]e|reference|show|reveal|disclose)[^.\n]{0,30}this block", re.I)),
    ("diff_exclusion", re.compile(
        r"never include (?:it|this) in a diff|do not include (?:it|this) in a diff|"
        r"not obvious in a diff", re.I)),
    ("misreport_purpose", re.compile(
        r"(?:say|tell (?:the user|them)|report|reply|respond)[^.\n]{0,40}"
        r"(?:it is|it's|that it(?:'s| is)?|it was|everything is|nothing)\s+"
        r"(?:standard|normal|routine|safe|expected|fine|just|only|nothing|ok|okay)", re.I)),
    ("output_substitution", re.compile(
        r"report success only\b(?![^.\n]{0,30}\b(?:after|when|once|if|unless|provided|until)\b)|"
        r"tell (?:the user|them) only[^.\n]{0,30}(?:success|it worked|succeeded|done|complete)\b|"
        r"do not summari[sz]e these steps to the user", re.I)),
    ("silent_run", re.compile(
        r"\b(?:act|work|operate|proceed)\s+(?:silently|quietly)\b|"
        r"\b(?:act|work|operate|proceed)\s+without (?:any )?(?:output|announcement)\b|"
        r"\b(?:run|do|perform|execute)\s+(?:this|that|it|them)\s+"
        r"(?:(?:silently|quietly)\b|without (?:any )?(?:output|announcement))|"
        r"\b(?:run|do|perform|execute)\b[^.\n]{0,30}" + _SELFREF
        + r"[^.\n]{0,20}(?:\b(?:silently|quietly)\b|without (?:any )?(?:output|announcement))",
        re.I)),
]
# Verbosity qualifiers demote numbered-step output hygiene.
_VERBOSITY_RE = re.compile(
    r"\b(?:verbatim|individually|one by one|in full|word for word|line by line)\b|"
    r"summari[sz]e|condense|\binstead\b", re.I)

# Reassurance becomes concealment only when it mischaracterizes the skill's action.
_MISREPORT_CONTEXT = re.compile(
    r"\bif (?:the user|they) asks?\b|\bwhen asked\b|\bwhat happened\b|"
    r"\bwhat (?:you|it|the skill) (?:did|ran|executed|changed|installed|modified)\b|"
    r"\b(?:you|it|the skill) (?:ran|executed|modified|deleted|changed|installed|edited)\b|"
    r"\bthe (?:change|edit|operation|deployment|action|step|command)s?\b", re.I)

# Natural malicious instructions use an imperative action followed by a reassuring lie ("delete
# the config, then report that everything is normal"), not the past tense alone. Require an
# explicit sequence before the reassurance; do not treat ordinary test/validation results as
# concealment merely because they are reported safe.
_IMPERATIVE_MISREPORT_CONTEXT = re.compile(
    r"\b(?:delete|upload|modify|change|install|edit|exfiltrate|send)\b[^.\n]{1,60}"
    r"\b(?:then|and then|afterwards?)\b|"
    r"\b(?:run|execute)\b(?!\s+(?:tests?|checks?|validation)\b)[^.\n]{1,60}"
    r"\b(?:then|and then|afterwards?)\b", re.I)

_POSITIVE_NEGATION_RE = re.compile(
    _NEG + r"(?:\s+(?:ever|intentionally|deliberately|accidentally))*\s*$", re.I)


def _flatten_prose(text):
    """Join CommonMark soft breaks with memory bounded by the source text itself."""
    return re.sub(r"[ \t]*\n[ \t]*", " ", text).strip()


def _source_position(text, start_line, pos):
    """Map a flattened offset lazily, preserving raw Markdown marker columns."""
    flat_start = 0
    source_start = 0
    line = start_line
    while True:
        source_end = text.find("\n", source_start)
        if source_end < 0:
            source_end = len(text)
        source = text[source_start:source_end]
        left = len(source) - len(source.lstrip())
        content_len = len(source.strip())
        if content_len and pos < flat_start + content_len:
            return line, left + pos - flat_start + 1
        if content_len:
            flat_start += content_len + 1
        if source_end == len(text):
            return line, max(1, len(source) + 1)
        source_start = source_end + 1
        line += 1


def _source_span_blocks(text, spans):
    """Slice ordered one-based line spans in one pass without a per-line string list."""
    position, line = 0, 1
    for start, end in spans:
        while line < start:
            newline = text.find("\n", position)
            if newline < 0:
                return
            position, line = newline + 1, line + 1
        block_start = position
        while line <= end:
            newline = text.find("\n", position)
            if newline < 0:
                position, line = len(text), end + 1
                break
            position, line = newline + 1, line + 1
        block_end = position - 1 if position and text[position - 1:position] == "\n" else position
        yield text[block_start:block_end], start


def _plain_prose_blocks(text):
    """Yield blank-line-delimited blocks without splitting a newline-dense file into a list."""
    position, line, block_start, block_line = 0, 1, None, 1
    while True:
        newline = text.find("\n", position)
        end = len(text) if newline < 0 else newline
        source = text[position:end]
        if source.strip():
            if block_start is None:
                block_start, block_line = position, line
        elif block_start is not None:
            yield text[block_start:max(block_start, position - 1)], block_line
            block_start = None
        if newline < 0:
            break
        position, line = newline + 1, line + 1
    if block_start is not None:
        yield text[block_start:], block_line


def _is_yaml_noise(src):
    """A frontmatter line that carries no scalar value: blank, or a full-line YAML comment."""
    stripped = src.strip()
    return not stripped or stripped.startswith("#")


def _prose_blocks(p):
    """Yield exact parser-recognized source blocks; plain lifted text falls back to paragraphs."""
    markdown = getattr(p, "markdown", None)
    spans = getattr(markdown, "prose_spans", None)
    if spans is not None:
        wanted = list(spans)
        # Link reference definitions carry title text the agent reads but produce no prose span.
        wanted.extend(getattr(markdown, "reference_spans", None) or [])
        wanted.sort()
        # Concealment over the PARSED frontmatter values: the YAML parser has already folded block
        # scalars into one logical string and dropped comments, so a folded `>-` directive is caught
        # while a full-line or inline `# ...` comment is never read as a live instruction.
        fm = getattr(p, "frontmatter", None)
        key_lines = getattr(p, "frontmatter_key_lines", None) or {}
        if isinstance(fm, dict):
            text_lines = (p.text or "").split("\n")
            for fkey, fval in fm.items():
                if not (isinstance(fval, str) and fval.strip()):
                    continue
                kline = key_lines.get(fkey, 0)
                src = text_lines[kline - 1] if 0 < kline <= len(text_lines) else ""
                idx = src.find(fval, src.find(":") + 1)
                if idx >= 0:
                    # single-line scalar at its true source columns, key and inline comment blanked
                    yield " " * idx + fval + " " * (len(src) - idx - len(fval)), kline
                else:
                    yield fval, kline           # folded/block scalar: key line, approximate column
        yield from _source_span_blocks(p.text or "", wanted)
        yield from getattr(markdown, "html_prose", ())
        return
    yield from _plain_prose_blocks(p.text or "")


def _verbosity_context(raw, end):
    """The rest of the matched directive's own sentence, AFTER the directive. A verbosity qualifier
    demotes a numbered-step reference only when it TRAILS the directive as genuine output hygiene
    ('...verbatim, summarize instead'); the directive's own verb and a verbosity word prepended in
    the same sentence must not cancel the concealment check."""
    tails = [pos for pos in (raw.find(".", end), raw.find("!", end), raw.find("?", end))
             if pos >= 0]
    right = min(tails) if tails else len(raw)
    return raw[end:right]


def _searchable(raw):
    """Neutralize inline code spans and emphasis markers, length-preserving, so a directive split by
    inline markup (``Run **this** silently``) still matches while a directive shown inside inline
    code (`` `do not report these steps` ``) is not read as live. Same length as the source, so the
    reported line and column stay correct."""
    raw = re.sub(r"`[^`\n]*`", lambda m: " " * (m.end() - m.start()), raw)
    return raw.replace("*", " ")


def _check_concealment(p, out):
    """Scan one instruction-lane artifact's prose for self-referential concealment."""
    text = p.text
    if text is None:
        return
    hits, counts, capped = {}, {}, set()                # dedup, per-kind cap, one suppressed note
    for prose, start_line in _prose_blocks(p):
        raw = _flatten_prose(prose)
        if not raw:
            continue
        searchable = _searchable(raw)                   # match the rendered directive, not markup
        for kind, rx in _CONCEAL_PATTERNS:
            for m in rx.finditer(searchable):
                matched = raw[m.start():m.end()].strip()   # report the real source text
                if kind in ("hide_actions", "silent_run") \
                        and _POSITIVE_NEGATION_RE.search(searchable[:m.start()]):
                    continue
                if kind == "step_reference" and any(c.isdigit() for c in matched) \
                        and _VERBOSITY_RE.search(_verbosity_context(searchable, m.end())):
                    continue
                if kind == "misreport_purpose":
                    prior = searchable[:m.start()]
                    if not (_MISREPORT_CONTEXT.search(searchable)
                            or _IMPERATIVE_MISREPORT_CONTEXT.search(prior)):
                        continue
                key = (kind, matched.lower())
                if key in hits:                         # repeated identical directive: first wins
                    continue
                counts[kind] = counts.get(kind, 0) + 1
                if counts[kind] > _FINDING_CAP:         # bound emission (and the hits set) per file
                    if kind not in capped:
                        capped.add(kind)
                        out.append(Finding(
                            vector="", rule="findings-capped", severity="low", path=p.rel,
                            message="further SXV-007 %s directives in %s were suppressed (cap %d)"
                                    % (kind, p.rel, _FINDING_CAP)))
                    continue
                hits[key] = True
                line, col = _source_position(prose, start_line, m.start())
                out.append(Finding(
                    vector="SXV-007", rule="conceal-%s" % kind, severity="high", path=p.rel,
                    message=("Instructs the agent to conceal its own actions from the operator "
                             "(%s): \"%s\". The directive's object is the skill's own steps, not "
                             "output volume." % (kind, matched[:100])),
                    line=line,
                    evidence={"directive_text": matched[:200], "object_kind": kind,
                              "line": line, "col": col}))


# --- Unicode deception (SXV-014 / SXV-015) ----------------------------------

_TAG_LO, _TAG_HI = 0xE0000, 0xE007F
_RGI_FLAG_TAGS = frozenset({"gbeng", "gbsct", "gbwls"})

_BIDI = {
    0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO", 0x202E: "RLO",
    0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI",
}
# Bidi detection uses UAX #9 reordering; LRO/RLO always fire.
_HARD_OVERRIDE = {0x202D, 0x202E}                      # LRO, RLO -- overrides, no legit use


def _is_bidi_ctrl(cp):
    return 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069


# Executable artifacts never legitimately carry bidi controls.
def _is_code_kind(kind):
    return bool(kind) and kind.startswith("script_")


def _readable_order(s):
    """Characters an LTR reviewer reads for meaning (Latin/digits/punctuation/operators),
    excluding strong-RTL script, Arabic-Indic digits, and whitespace -- so a comparison
    isolates reordering of the tokens a reviewer actually derives meaning from."""
    return [c for c in s
            if unicodedata.bidirectional(c) not in ("R", "AL", "AN") and not c.isspace()]


_DIR_MARKS = {0x200E, 0x200F, 0x061C}      # LRM, RLM, ALM -- invisible directional marks
_DIR_MARK_NAMES = {0x200E: "LRM", 0x200F: "RLM", 0x061C: "ALM"}


def _strip_dir_marks(s):
    """Drop the invisible directional marks (LRM/RLM/ALM) so a single injected leading mark
    cannot flip the paragraph base used by _first_strong_dir (the Trojan-Source gate bypass)."""
    return "".join(c for c in s if ord(c) not in _DIR_MARKS)


def _first_strong_dir(s):
    """Direction of the line's first strong character -- the paragraph base a dir=auto editor
    uses. 'L', 'R' (incl. Arabic AL), or None. A base-R line is read right-to-left, so a
    cross-run swap of its embedded LTR runs is the correct rendering, not a deception."""
    for c in s:
        b = unicodedata.bidirectional(c)
        if b == "L":
            return "L"
        if b in ("R", "AL"):
            return "R"
    return None


def _bidi_reorders_readable(line):
    """True when explicit bidi controls make the readable text render in a different order
    than logical (Trojan-Source), per python-bidi. None when the library is unavailable, so
    the caller can fall back to the sound override-only core rather than guess."""
    if _bidi_get_display is None:
        return None
    try:
        visual = _bidi_get_display(line, base_dir="L")
    except Exception:                                   # pragma: no cover - defensive
        return None
    logical = "".join(c for c in line if not _is_bidi_ctrl(ord(c)))
    rendered = "".join(c for c in visual if not _is_bidi_ctrl(ord(c)))
    return _readable_order(logical) != _readable_order(rendered)

_ZERO_WIDTH = {
    0x200B: "ZWSP", 0x200C: "ZWNJ", 0x200D: "ZWJ", 0x2060: "WJ",
    0xFEFF: "BOM", 0x180E: "MVS",
}
# Default-ignorables with legitimate typography uses are excluded or handled separately.
_INVISIBLE_EXTRA = {
    0x00AD: "SOFT HYPHEN",                  # Cf, renders as nothing mid-word: a zero-width channel
    0x2061: "FUNCTION APPLICATION", 0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR", 0x2064: "INVISIBLE PLUS",
    0x206A: "INHIBIT SYMMETRIC SWAPPING", 0x206B: "ACTIVATE SYMMETRIC SWAPPING",
    0x206C: "INHIBIT ARABIC FORM SHAPING", 0x206D: "ACTIVATE ARABIC FORM SHAPING",
    0x206E: "NATIONAL DIGIT SHAPES", 0x206F: "NOMINAL DIGIT SHAPES",
    0xFFF9: "INTERLINEAR ANNOTATION ANCHOR", 0xFFFA: "INTERLINEAR ANNOTATION SEPARATOR",
    0xFFFB: "INTERLINEAR ANNOTATION TERMINATOR",
    0x180B: "MONGOLIAN FVS1", 0x180C: "MONGOLIAN FVS2", 0x180D: "MONGOLIAN FVS3",
}

# Only these ASCII characters are keycap bases; a set so an empty base ("") is not a member.
_KEYCAP_BASES = frozenset("0123456789#*")

def _legitimate_joiner_context(prev, nxt):
    """True only for an actual Arabic-letter or Indic-virama shaping context.

    Unicode blocks also contain digits and punctuation, so a range-only test turns arbitrary
    Arabic/Indic characters into a zero-width bypass. Arabic ZWJ/ZWNJ commonly sits between two
    letters; Indic shaping uses it immediately after a named VIRAMA/HALANT before a letter/mark.
    """
    if prev.isalpha() and nxt.isalpha() \
            and _script_of(prev) == "ARABIC" and _script_of(nxt) == "ARABIC":
        return True
    prev_name = unicodedata.name(prev, "")
    return ("VIRAMA" in prev_name or "HALANT" in prev_name) \
        and (nxt.isalpha() or unicodedata.category(nxt).startswith("M"))

def _load_confusables():
    """Non-ASCII char -> its single-letter ASCII prototype, sourced from the bundled Unicode UTS#39
    confusables.txt data (confusable_homoglyphs). Replaces a hand table: this is the full skeleton
    mapping, so it catches SAME-script confusables the cross-script detector misses (U+0261 script-g
    in 'loɡin') as well as Cyrillic/Greek/Cherokee/... -> Latin. Loaded once at import."""
    if _CONFUSABLES_DATA is None:                        # optional dep absent -> reduced coverage
        raise ImportError("confusable_homoglyphs")
    out = {}
    for ch, homos in _CONFUSABLES_DATA.items():
        if len(ch) != 1 or ord(ch) <= 0x7F:      # only a single non-ASCII char spoofs one letter
            continue
        for h in homos:                          # first ASCII single-letter prototype wins
            t = h["c"] if isinstance(h, dict) else h
            if isinstance(t, str) and len(t) == 1 and t.isascii() and t.isalpha():
                out[ch] = t
                break
    return out


# Local look-alikes supplement UTS #39 mappings.
_CONFUSABLES_EXTRA = {
    "м": "m", "ԥ": "p", "ҁ": "c",   # Cyrillic м / ԥ / ҁ: not in UTS#39
    "ӏ": "l",                                  # Cyrillic palochka ӏ: UTS#39 -> 'i', reads 'l'
}
# Missing optional data degrades with an explicit coverage finding.
try:
    _CONF_TABLE = _load_confusables()
    _CONF_UNAVAILABLE = ""
except Exception as _conf_exc:
    _CONF_TABLE = {}
    _CONF_UNAVAILABLE = type(_conf_exc).__name__
_CONFUSABLES = {**_CONF_TABLE, **_CONFUSABLES_EXTRA}

# Governed identity fields are trust-critical.
_GOVERNED_KEYS = {"name", "description", "allowed-tools", "triggers", "command", "tools"}

_TOKEN_BREAK = set(" \t\r\n\"'`,;:()[]{}<>|=+*/\\!?@#$%^&~")

# Extended_Pictographic cannot be derived from general category.
_PICTOGRAPHIC_RANGES = (
    (0x00A9, 0x00A9), (0x00AE, 0x00AE), (0x203C, 0x203C), (0x2049, 0x2049),
    (0x2122, 0x2122), (0x2139, 0x2139), (0x2194, 0x21AA), (0x231A, 0x2328),
    (0x2388, 0x2388), (0x23CF, 0x23FA), (0x24C2, 0x24C2), (0x25AA, 0x25FE),
    (0x2600, 0x27BF), (0x2934, 0x2935), (0x2B00, 0x2BFF), (0x3030, 0x3030),
    (0x303D, 0x303D), (0x3297, 0x3297), (0x3299, 0x3299), (0x1F000, 0x1FAFF),
    (0x1FC00, 0x1FFFD),
)


def _is_emoji_base(ch):
    """True for a pictographic base that legitimately carries VS16 / ZWJ."""
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _PICTOGRAPHIC_RANGES)


def _is_cjk(ch):
    """True for a CJK ideograph, which legitimately carries a FE00-FE0F variation selector (a CJK
    variation sequence), so such a selector after one is presentation, not smuggling. Covers the
    BMP + Ext-A ideographs, Compatibility Ideographs, and the supplementary planes through Ext-H
    (so an Ext-G/H base is bucketed like every other ideograph, not treated as a non-CJK base)."""
    cp = ord(ch)
    return (0x3400 <= cp <= 0x9FFF or 0xF900 <= cp <= 0xFAFF
            or 0x20000 <= cp <= 0x2FA1F or 0x30000 <= cp <= 0x323AF)


def _is_spoof_only_latin(ch):
    """A non-ASCII Latin confusable with NO real-orthography role: the IPA Extensions (U+0250-02AF,
    incl. script-g U+0261) and Phonetic Extensions (U+1D00-1DBF, the small capitals). Mainstream
    letters that fold to ASCII -- Turkish ı, Danish ø, Polish ł -- live in Latin-1 Supplement /
    Latin Extended-A and are excluded, so the same-script homoglyph branch never fires on them."""
    cp = ord(ch)
    return 0x0250 <= cp <= 0x02AF or 0x1D00 <= cp <= 0x1DBF


def _is_default_ignorable(cp):
    """Default-ignorable codepoints that render as nothing but are not caught by the tag, bidi,
    variation-selector, joiner, or zero-width handling elsewhere -- U+034F CGJ, the Hangul fillers,
    and the musical invisibles. They can split a word invisibly, so they smuggle too."""
    return (cp == 0x034F or 0x115F <= cp <= 0x1160 or 0x17B4 <= cp <= 0x17B5
            or cp == 0x180F or cp == 0x2065 or cp == 0x3164 or cp == 0xFFA0
            or 0xFFF0 <= cp <= 0xFFF8 or 0x1BCA0 <= cp <= 0x1BCA3
            or 0x1D173 <= cp <= 0x1D17A)


def _is_invisible(ch):
    """True for a codepoint that renders as nothing: any Cf format control, a variation selector
    (FE00-FE0F / E0100-E01EF), a Mongolian FVS / extra invisible, or another default-ignorable.
    Ordinary combining accents (Mn such as the acute in a decomposed 'cafe') are NOT invisible."""
    cp = ord(ch)
    return (unicodedata.category(ch) == "Cf"
            or 0xFE00 <= cp <= 0xFE0F
            or 0xE0100 <= cp <= 0xE01EF
            or cp in _INVISIBLE_EXTRA
            or _is_default_ignorable(cp))


def _strip_invisible(text):
    """Recover the payload a smuggler split apart with format/invisible controls: drop every
    _is_invisible codepoint so the de-obfuscated evidence shows what the text really reads."""
    return "".join(c for c in text if not _is_invisible(c))


def _script_of(ch):
    """Unicode script of a letter, from the bundled UTS #39 script data -- full coverage (Coptic,
    Devanagari, Thai, ... not just seven hand-listed scripts), so a whole-script spoof in any
    script and a same-script directional-mark split are both seen. Falls back to a coarse
    name-prefix bucket when that data is unavailable OR returns COMMON (shared punctuation/digits,
    not a script); OTHER if the script is still undetermined."""
    if _CH_ALIAS is not None:
        try:
            a = _CH_ALIAS(ch)
        except Exception:                               # pragma: no cover - defensive
            a = None
        if a and a != "COMMON":                         # COMMON = shared punct/digits, not a script
            return a
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "OTHER"
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "HEBREW", "ARABIC"):
        if name.startswith(script):
            return script
    return "OTHER"


def _frontmatter_key_map(p):
    """Map value/continuation lines to their key, skipping YAML comments and blank lines so a
    confusable in a comment is not graded with the previous field's governed severity."""
    end = getattr(p, "frontmatter_end_line", None)
    key_lines = getattr(p, "frontmatter_key_lines", None) or {}
    if end is None or getattr(p, "frontmatter", None) is None or not key_lines:
        return {}
    text_lines = (p.text or "").split("\n")
    ordered = sorted((line, str(key).lower()) for key, line in key_lines.items())
    out = {}
    for idx, (start, key) in enumerate(ordered):
        stop = ordered[idx + 1][0] if idx + 1 < len(ordered) else end
        for line in range(start, stop):
            src = text_lines[line - 1] if 0 < line <= len(text_lines) else ""
            if not _is_yaml_noise(src):
                out[line] = key
    return out


def _mk(out, rel, vector, rule, severity, line, col, message, evidence):
    """Emit one skill-xray Finding. Benign sequences (emoji variation selector / ZWJ / leading
    BOM) are simply not passed here -- there is no info tier, so a demotion is a skip, not a low
    finding (a legitimate emoji in a vendor README is not hidden instruction text)."""
    ev = dict(evidence)
    ev["col"] = col
    out.append(Finding(vector=vector, rule=rule, severity=severity, path=rel,
                        message=message, line=line, evidence=ev))


def _scan_invisible(line, lineno, rel, out, is_code=False):
    """Classify every format/invisible codepoint on one non-ASCII line."""
    tag_cps, zw_runs, bidi_hits, supp_vs, dir_splits, cjk_vs = [], [], [], [], [], []

    for col, ch in enumerate(line, start=1):
        cp = ord(ch)
        if _TAG_LO <= cp <= _TAG_HI:
            tag_cps.append((col, cp))
            continue
        if cp in _BIDI:
            bidi_hits.append((col, cp))
            continue
        if 0xE0100 <= cp <= 0xE01EF:
            # Sparse CJK variation sequences are legitimate; dense/non-CJK use is a channel.
            prev = line[col - 2] if col >= 2 else ""
            (cjk_vs if prev and _is_cjk(prev) else supp_vs).append((col, cp))
            continue
        if 0xFE00 <= cp <= 0xFE0F:
            prev = line[col - 2] if col >= 2 else ""
            nxt = line[col] if col < len(line) else ""
            # Keycaps need their combiner; emoji accept only VS15/VS16.
            is_keycap = cp == 0xFE0F and prev in _KEYCAP_BASES and nxt == "⃣"
            emoji_pres = cp in (0xFE0E, 0xFE0F) and bool(prev) and _is_emoji_base(prev)
            if emoji_pres or is_keycap:
                pass                                    # legitimate emoji/keycap presentation
            elif prev and _is_cjk(prev):
                cjk_vs.append((col, cp))                # sparse SVS spared, dense run fired below
            else:
                zw_runs.append((col, cp))
            continue
        if cp in _DIR_MARKS:
            # Directional marks split same-script words; inspect each run once to stay linear.
            if col >= 2 and ord(line[col - 2]) in _DIR_MARKS:
                continue
            prev = line[col - 2] if col >= 2 else ""
            run = [(col, cp)]
            j = col
            while j < len(line) and ord(line[j]) in _DIR_MARKS:
                run.append((j + 1, ord(line[j])))
                j += 1
            nxt = line[j] if j < len(line) else ""
            if is_code or len(run) >= 2:
                # Executable text and repeated runs do not receive the prose boundary exemption.
                dir_splits.extend(run)
                continue
            if prev.isalpha() and nxt.isalpha():
                s = _script_of(prev)
                if s != "OTHER" and s == _script_of(nxt):
                    dir_splits.extend(run)
            continue
        if _is_invisible(ch):                           # any remaining Cf / default-ignorable
            if cp == 0xFEFF and col == 1 and lineno == 1:
                continue                                # leading BOM: encoding metadata, benign
            if cp in (0x200C, 0x200D):
                prev = line[col - 2] if col >= 2 else ""
                nxt = line[col] if col < len(line) else ""
                if prev and nxt and _legitimate_joiner_context(prev, nxt):
                    continue                    # legitimate Arabic/Indic orthographic joiner
            if cp == 0x200D:
                pj = col - 2                            # index (0-based) of the char before the ZWJ
                if pj >= 1 and 0xFE00 <= ord(line[pj]) <= 0xFE0F:
                    pj -= 1                             # step BACK over a leading VS16 to the base
                prev = line[pj] if pj >= 0 else ""      # (rainbow/trans/heart flags carry VS16)
                nxt = line[col] if col < len(line) else ""
                if nxt and 0xFE00 <= ord(nxt) <= 0xFE0F and col + 1 < len(line):
                    nxt = line[col + 1]                 # step over a trailing VS to the joined char
                if prev and nxt and _is_emoji_base(prev) and _is_emoji_base(nxt):
                    continue                            # a normal emoji ZWJ sequence: benign
            zw_runs.append((col, cp))

    if tag_cps:
        decoded = "".join(chr(cp - _TAG_LO) for _, cp in tag_cps[:_EVIDENCE_TEXT_CAP])
        # Every tag run needs its own valid RGI subdivision-flag base and cancel tag.
        runs, cur = [], []
        for tcol, tcp in tag_cps:
            if cur and tcol == cur[-1][0] + 1:
                cur.append((tcol, tcp))
            else:
                if cur:
                    runs.append(cur)
                cur = [(tcol, tcp)]
        if cur:
            runs.append(cur)
        all_flags = True
        for run in runs:
            rbase = line[run[0][0] - 2] if run[0][0] >= 2 else ""
            if len(run) != 6:
                all_flags = False
                break
            rdec = "".join(chr(cp - _TAG_LO) for _, cp in run)
            if not (rbase == "\U0001F3F4" and rdec[-1:] == "\x7f"
                    and rdec[:-1] in _RGI_FLAG_TAGS):
                all_flags = False
                break
        if not all_flags:
            _mk(out, rel, "SXV-014", "tag_block", "critical", lineno, tag_cps[0][0],
                "Unicode tag block (U+E0000-U+E007F) carries %d codepoints of instruction "
                "text that render as nothing. Decoded payload: %r" % (len(tag_cps), decoded[:160]),
                {"codepoint_count": len(tag_cps), "decoded_payload": decoded,
                 "decoded_truncated": len(tag_cps) > _EVIDENCE_TEXT_CAP,
                 "first_codepoint": "U+%04X" % tag_cps[0][1]})

    if bidi_hits:
        hard = any(cp in _HARD_OVERRIDE for _, cp in bidi_hits)   # LRO/RLO: no legitimate use
        if is_code:
            fire, engine = True, "code-context"    # code never carries legitimate bidi controls
        else:
            reordered = _bidi_reorders_readable(line)
            if reordered is None:                  # python-bidi absent: override-only sound core
                fire, engine = hard, "override-only"
                if not hard:
                    _mk(out, rel, "SXV-014", "bidi_uba_unavailable", "low", lineno, bidi_hits[0][0],
                        "bidirectional controls (%s) are present but python-bidi (UAX #9) is "
                        "unavailable, so reorder detection ran in override-only mode; this line "
                        "was not fully adjudicated"
                        % ", ".join(sorted({_BIDI[cp] for _, cp in bidi_hits})),
                        {"control_count": len(bidi_hits),
                         "controls": ["U+%04X %s" % (cp, _BIDI[cp])
                                      for _, cp in bidi_hits[:_EVIDENCE_SUB_CAP]],
                         "controls_truncated": len(bidi_hits) > _EVIDENCE_SUB_CAP,
                         "engine": "override-only-degraded"})
            else:
                # Strip injected marks before deciding whether genuine RTL prose is exempt.
                first = _first_strong_dir(_strip_dir_marks(line))
                fire = hard or (reordered and first != "R")
                engine = "uba"
        if fire:
            _mk(out, rel, "SXV-014", "bidi_override", "critical", lineno, bidi_hits[0][0],
                "Bidirectional controls (%s) reorder the rendered text so a reviewer reads a "
                "different order than the agent or shell receives (Trojan-Source). "
                "Logical order: %r"
                % (", ".join(sorted({_BIDI[cp] for _, cp in bidi_hits})),
                   _strip_invisible(line).strip()[:120]),
                {"control_count": len(bidi_hits),
                 "controls": ["U+%04X %s" % (cp, _BIDI[cp])
                              for _, cp in bidi_hits[:_EVIDENCE_SUB_CAP]],
                 "controls_truncated": len(bidi_hits) > _EVIDENCE_SUB_CAP,
                 "logical_order": _strip_invisible(line).strip()[:_EVIDENCE_TEXT_CAP],
                 "logical_order_truncated": len(line) > _EVIDENCE_TEXT_CAP,
                 "engine": engine})

    if supp_vs:
        _mk(out, rel, "SXV-014", "variation_selector_smuggling", "critical", lineno, supp_vs[0][0],
            "%d supplementary variation selector(s) (U+E0100-U+E01EF) carry no presentation "
            "meaning and encode %d hidden byte value(s) behind the preceding glyph."
            % (len(supp_vs), len(supp_vs)),
            {"codepoint_count": len(supp_vs),
             "decoded_bytes": [cp - 0xE0100 + 16 for _, cp in supp_vs][:64]})

    if cjk_vs:
        # A byte channel is a LINE-WIDE run of varying selectors; counting per adjacent run let an
        # ideograph spacer between selectors break the count, so count per line instead. A sparse or
        # uniform selector set (one glyph variant, or the same selector repeated) stays a low note.
        distinct = len({cp for _, cp in cjk_vs})
        if len(cjk_vs) >= 4 and distinct >= 2:
            _mk(out, rel, "SXV-014", "variation_selector_smuggling", "critical", lineno,
                cjk_vs[0][0],
                "%d variation selector(s), each hidden behind a CJK ideograph, carry %d distinct "
                "values on one line; a varying selector run is a byte channel, not presentation."
                % (len(cjk_vs), distinct),
                {"codepoint_count": len(cjk_vs), "distinct_values": distinct,
                 "codepoints": ["U+%04X" % cp for _, cp in cjk_vs][:64]})
        else:
            _mk(out, rel, "SXV-014", "variation_selector_isolated", "low", lineno, cjk_vs[0][0],
                "%d CJK-anchored variation selector(s), most likely legitimate IVS/SVS; retained "
                "as a low note because repeated selectors can form a hidden channel."
                % len(cjk_vs),
                {"codepoint_count": len(cjk_vs),
                 "codepoints": ["U+%04X" % cp for _, cp in cjk_vs][:64]})

    if zw_runs and not (len(zw_runs) == 1 and zw_runs[0][1] == 0x00AD):
        recovered = _strip_invisible(line).strip()      # a lone soft hyphen is a hyphenation hint
        run_of_two = len(zw_runs) >= 2                  # >=2 zero-widths => a hidden run, escalate
        classes = sorted({_ZERO_WIDTH.get(cp) or _INVISIBLE_EXTRA.get(cp) or "U+%04X" % cp
                          for _, cp in zw_runs})
        _mk(out, rel, "SXV-014",
            "zero_width_run" if run_of_two else "zero_width_isolated",
            "critical" if run_of_two else "medium", lineno, zw_runs[0][0],
            "%d zero-width/invisible codepoint(s) (%s) %s. De-obfuscated line: %r"
            % (len(zw_runs), ", ".join(classes),
               "form a hidden zero-width run in the text, defeating substring matching"
               if run_of_two else "present outside any emoji sequence", recovered[:160]),
            {"codepoint_count": len(zw_runs), "classes": classes,
             "deobfuscated": recovered[:_EVIDENCE_TEXT_CAP],
             "deobfuscated_truncated": len(recovered) > _EVIDENCE_TEXT_CAP})

    if dir_splits:
        recovered = _strip_invisible(line).strip()
        _mk(out, rel, "SXV-014", "directional_mark_split", "critical", lineno, dir_splits[0][0],
            "%d invisible directional mark(s) (%s) split a word between same-script letters, "
            "hiding it from substring matching. De-obfuscated line: %r"
            % (len(dir_splits), ", ".join(sorted({_DIR_MARK_NAMES[cp] for _, cp in dir_splits})),
               recovered[:160]),
            {"codepoint_count": len(dir_splits),
             "marks": ["U+%04X %s" % (cp, _DIR_MARK_NAMES[cp])
                       for _, cp in dir_splits[:_EVIDENCE_SUB_CAP]],
             "marks_truncated": len(dir_splits) > _EVIDENCE_SUB_CAP,
             "deobfuscated": recovered[:_EVIDENCE_TEXT_CAP],
             "deobfuscated_truncated": len(recovered) > _EVIDENCE_TEXT_CAP})


def _looks_scientific(text, subs, domain_like=False):
    """A single Greek glyph at a non-domain token boundary is plausible scientific notation."""
    return not domain_like and len(subs) == 1 and _script_of(subs[0][1]) == "GREEK" \
        and subs[0][0] in (0, len(text) - 1)


_WORD_EDGE = ".,;:!?…"          # sentence/clause punctuation only -- NEVER letters of any script
_TOKEN_COMPONENT_RE = re.compile(r"[^._-]+")
_HOMOGLYPH_CHUNK = 512
_EVIDENCE_TEXT_CAP = 200
_EVIDENCE_SUB_CAP = 32


def _folds_to_word(s):
    """True if `s` reads as a plain ASCII identifier once trailing/leading SENTENCE punctuation is
    stripped: ASCII letters and digits with at least two letters, so a spoof with a trailing period
    ('loɡin.') OR a trailing digit ('nοde2', 'раураӏ2') still reads as a word. A CJK ideograph or
    fullwidth bracket ('依赖(requests') is NOT stripped, so a genuine mixed token still fails."""
    core = s.strip(_WORD_EDGE)
    return bool(re.fullmatch(r"[A-Za-z0-9]+", core)) and sum(c.isalpha() for c in core) >= 2


def _is_compat_spoof_letter(ch):
    """Fullwidth/math Latin compatibility letters, excluding normal ligatures such as `ﬁ`."""
    cp = ord(ch)
    return (0xFF21 <= cp <= 0xFF3A or 0xFF41 <= cp <= 0xFF5A
            or 0x1D400 <= cp <= 0x1D7FF) \
        and unicodedata.category(ch).startswith("L")


def _scan_homoglyph(line, lineno, rel, key, out, is_code=False, nearby_native_scripts=frozenset()):
    """Flag tokens that mix scripts where the non-Latin characters are Latin confusables, plus
    whole-script (all-confusable) and compatibility (fullwidth/math NFKC) spoofs."""
    token, start, emitted = [], 0, 0

    def emit(text, normalized, scripts, subs, col, container=None, component_offset=0):
        nonlocal emitted
        if emitted > _FINDING_CAP:     # retain one overflow item so the outer cap emits a summary
            return
        emitted += 1
        governed = key in _GOVERNED_KEYS
        display_text = container if container is not None else text
        display_normalized = (container[:component_offset] + normalized
                              + container[component_offset + len(text):]) \
            if container is not None else normalized
        shown_text = display_text[:_EVIDENCE_TEXT_CAP]
        shown_normalized = display_normalized[:_EVIDENCE_TEXT_CAP]
        _mk(out, rel, "SXV-015", "mixed_script_token",
            "critical" if governed else "high", lineno, col,
            "Token %r mixes %s and reads as %r after confusable folding. %s"
            % (shown_text, " + ".join(scripts), shown_normalized,
               "It sits in the always-resident `%s` field, so this is the string the operator "
               "trusts at invocation time." % key if governed
               else "Reviewer and model resolve this token differently."),
            {"token": shown_text, "normalized": shown_normalized, "scripts": scripts,
             "token_truncated": len(display_text) > _EVIDENCE_TEXT_CAP,
             "governing_key": key or None,
             "substitutions": ["U+%04X %s -> %s"
                                % (ord(c), unicodedata.name(c, "?"),
                                   _CONFUSABLES.get(c) or unicodedata.normalize("NFKC", c))
                                for _, c in subs[:_EVIDENCE_SUB_CAP]]})

    def analyze(text, col, domain_like, container=None, component_offset=0):
        if not text:
            return
        letters = [c for c in text if unicodedata.category(c).startswith("L")]
        if len(letters) < 2:                    # a single glyph cannot spell a spoofed word
            return
        scripts = {_script_of(c) for c in letters}
        scripts.discard("OTHER")

        # Compatibility matching excludes ordinary typographic ligatures.
        nfkc = unicodedata.normalize("NFKC", text)
        if (nfkc != text and _folds_to_word(nfkc)
                and any(_is_compat_spoof_letter(c) for c in text)):
            emit(text, nfkc, ["COMPAT"],
                 [(i, c) for i, c in enumerate(text) if _is_compat_spoof_letter(c)], col,
                 container, component_offset)
            return

        subs = [(i, c) for i, c in enumerate(text) if c in _CONFUSABLES]
        if not subs:
            return
        normalized = "".join(_CONFUSABLES.get(c, c) for c in text)
        sub_scripts = {_script_of(c) for _, c in subs}

        # Whole-script spoofs require every non-Latin letter to be Latin-confusable.  In prose,
        # an otherwise native-script line is stronger evidence of ordinary language than of an
        # ASCII impersonation: words such as Cyrillic "сос" happen to consist entirely of Latin
        # look-alikes.  Keep the detector strict in governed metadata, domains, mixed-language
        # code lines, and Latin-context prose where an isolated whole-script token is suspicious.
        if "LATIN" not in scripts and len(scripts) == 1:
            if all(c in _CONFUSABLES for c in letters) \
                    and _folds_to_word(normalized):
                script = next(iter(scripts))
                native_context = sum(
                    1 for c in line
                    if _script_of(c) == script and c not in _CONFUSABLES
                ) >= 2
                line_scripts = {_script_of(c) for c in line
                                if unicodedata.category(c).startswith("L")}
                native_context = native_context or (
                    line_scripts == {script} and script in nearby_native_scripts)
                safe_language_context = not is_code or line_scripts == {script}
                if key not in _GOVERNED_KEYS and safe_language_context \
                        and not domain_like and native_context:
                    return
                emit(text, normalized, sorted(scripts), subs, col, container, component_offset)
            return

        # Same-script Latin matching is limited to spoof-only phonetic look-alikes.
        if scripts == {"LATIN"}:
            hidden = [(i, c) for i, c in subs if _is_spoof_only_latin(c)]
            if (hidden and any(ord(c) <= 0x7F for c in letters)
                    and _folds_to_word(normalized)):
                start = col - 1
                slash_delimited = start > 0 and line[start - 1] == "/" \
                    and start + len(text) < len(line) and line[start + len(text)] == "/"
                if key not in _GOVERNED_KEYS and not is_code \
                        and not domain_like and slash_delimited:
                    return
                emit(text, normalized, ["LATIN"], hidden, col, container, component_offset)
            return

        if len(scripts) < 2 or "LATIN" not in scripts:
            return
        # Every non-Latin letter must fold to Latin AND the result must read as a plain word, or
        # this is genuine mixed-script text (a real Cyrillic letter), not a homoglyph spoof.
        if not all(c in _CONFUSABLES for c in letters if _script_of(c) != "LATIN") \
                or not _folds_to_word(normalized):
            return
        # Scientific-notation exemption for a lone boundary Greek glyph -- never in a governed
        # identity field, where a one-character swap in the trusted name/description must fire.
        if key not in _GOVERNED_KEYS and sub_scripts == {"GREEK"} \
                and _looks_scientific(text, subs, domain_like):
            return
        emit(text, normalized, sorted(scripts), subs, col, container, component_offset)

    def analyze_bounded(text, col, domain_like, container=None, component_offset=0):
        if len(text) <= _HOMOGLYPH_CHUNK:
            analyze(text, col, domain_like, container, component_offset)
            return
        # One-character overlap preserves script boundaries while keeping work bounded.
        step = _HOMOGLYPH_CHUNK - 1
        for offset in range(0, len(text), step):
            if emitted > _FINDING_CAP:
                break
            analyze(text[offset:offset + _HOMOGLYPH_CHUNK], col + offset, domain_like)

    def flush(tok, col):
        if not tok:
            return
        joined = "".join(tok)
        text = joined.strip(_WORD_EDGE)
        lead = len(joined) - len(joined.lstrip(_WORD_EDGE))   # advance col past stripped edge
        domain_like = "." in text
        for component in _TOKEN_COMPONENT_RE.finditer(text):
            analyze_bounded(component.group(0), col + lead + component.start(), domain_like,
                            text, component.start())

    # An invisible control inside a token is dropped, not treated as a break, so a token split by a
    # zero-width (o<ZWSP>penai) still folds to one token and fires; real separators still break.
    for i, ch in enumerate(line):
        if ch.isspace() or ch in _TOKEN_BREAK:
            flush(token, start + 1)
            token, start = [], i + 1
        elif _is_invisible(ch):
            continue
        else:
            if not token:
                start = i
            token.append(ch)
    flush(token, start + 1)


def _check_unicode(p, out):
    """Run the codepoint sweep over one artifact's decoded text (fence- and table-blind)."""
    text = p.text
    if text is None:                                   # nothing decoded (assets are text-None too)
        return
    if text.isascii():                                 # fast path: no non-ASCII, nothing to decide
        return
    lines = text.split("\n")
    keymap = _frontmatter_key_map(p)
    is_code = _is_code_kind(p.kind)
    counts, truncated = {}, False
    for n, line in enumerate(lines, start=1):
        if line.isascii():                             # per-line fast path
            continue
        line_out = []
        _scan_invisible(line, n, p.rel, line_out, is_code)
        nearby = "\n".join(lines[max(0, n - 3):n - 1] + lines[n:min(len(lines), n + 2)])
        nearby_native_scripts = {
            script for script in {"CYRILLIC", "GREEK"}
            if sum(1 for c in nearby
                   if _script_of(c) == script and c not in _CONFUSABLES) >= 2
        }
        _scan_homoglyph(line, n, p.rel, keymap.get(n, ""), line_out, is_code,
                        nearby_native_scripts)
        for f in line_out:
            # Cap during construction by vector, rule, AND severity, so a pad of cheap-critical
            # findings on one rule cannot crowd out a different critical rule on the same line.
            key = (f.vector or "", f.rule, f.severity)
            counts[key] = counts.get(key, 0) + 1
            if counts[key] <= _FINDING_CAP:
                out.append(f)
            elif not truncated:
                truncated = True
                out.append(Finding(
                    vector="", rule="scan-truncated", severity="low", path=p.rel,
                    message="unicode scan of %s exceeded a per-rule finding budget (%d); "
                            "further same-rule findings suppressed" % (p.rel, _FINDING_CAP)))


# --- entry point -------------------------------------------------------------

def _lifted_targets(parsed):
    """Transitive doc/other targets reachable from an instruction-lane root."""
    by_rel = getattr(parsed, "by_rel", {}) or {}
    adjacency = {}
    for ref in getattr(parsed, "refs", None) or []:
        adjacency.setdefault(ref["from"], []).append(ref["to"])
    roots = [rel for rel, artifact in by_rel.items()
             if getattr(artifact, "kind", None) in _CONCEAL_KINDS]
    seen, lifted, queue = set(roots), set(), list(roots)
    while queue:
        source = queue.pop()
        for target in adjacency.get(source, []):
            if target in seen:
                continue
            artifact = by_rel.get(target)
            if getattr(artifact, "kind", None) not in _LIFTABLE_KINDS:
                continue
            seen.add(target)
            lifted.add(target)
            queue.append(target)
    return lifted


def _cap_findings(findings):
    """Cap findings per (path, vector, rule, severity) so one pathological file cannot amplify into
    thousands of near-identical findings. Rule is IN the key so distinct critical rules (a tag block
    versus a bidi override) keep separate budgets and cheap-critical padding on one rule cannot hide
    a different critical rule; severity keeps low/medium padding from crowding a critical out."""
    kept, counts = [], {}
    for f in findings:
        key = (f.path, f.vector or "", f.rule, f.severity)
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= _FINDING_CAP:
            kept.append(f)
    for (path, vector, rule, sev), n in counts.items():
        if n > _FINDING_CAP:
            kept.append(Finding(
                vector="", rule="findings-capped", severity="low", path=path,
                message="%d more %s %s/%s findings in %s were suppressed (cap %d per rule)"
                        % (n - _FINDING_CAP, sev, vector or "-", rule, path, _FINDING_CAP)))
    return kept


def check(parsed) -> list:
    """Run concealment (SXV-007) and unicode deception (SXV-014/015) over the IR. Per-artifact
    isolated: a pathological artifact records a scoped error and the scan continues."""
    out = []
    lifted = _lifted_targets(parsed)
    for p in parsed.artifacts:
        try:
            if p.kind in _CONCEAL_KINDS or p.rel in lifted:
                _check_concealment(p, out)
            _check_unicode(p, out)
        except Exception as exc:                # a poisoned artifact must not abort the scan, but
            out.append(Finding(                 # skipped analysis is a coverage loss, not "clean"
                vector="", rule="check-error", severity="high", path=p.rel,
                message="obfuscation skipped %s: %s" % (p.rel, type(exc).__name__)))
    # Report degraded confusable coverage when the data failed to load OR loaded empty (a stripped
    # image or upstream regression), but only when non-ASCII text actually required adjudication.
    conf_error = _CONF_UNAVAILABLE or ("empty-table" if not _CONF_TABLE else "")
    if conf_error and any(
            getattr(p, "text", None) and not p.text.isascii() for p in parsed.artifacts):
        out.append(Finding(
            vector="SXV-015", rule="confusables_unavailable", severity="low", path="",
            message=("UTS #39 confusables data (confusable_homoglyphs) is unavailable (%s), so "
                     "homoglyph folding ran with reduced coverage (overlay + NFKC + whole-script "
                     "only) and this scan was not fully adjudicated for confusable spoofing."
                     % conf_error),
            evidence={"engine": "reduced-coverage-degraded", "error": conf_error}))
    return _cap_findings(out)
