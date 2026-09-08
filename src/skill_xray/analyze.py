"""Byte-level forensics over the IR: magic-byte mismatch, polyglot, and
unreferenced (overlay / appended) bytes.

These checks read only the raw bytes ingest captured (parse carries them into the IR);
they never re-open a file, so the fail-closed filesystem guarantees live once, in ingest.

A skill package's files are small and declared by name, so a file whose BYTES
contradict its declared type is hiding something from a name-and-text scan:

  - magic-byte mismatch (SXV-035): an ELF/PE/Mach-O executable or a zip archive shipped
    as ``notes.md``, or a shell script renamed to ``logo.png`` -- the extension and the
    ledger say inert, the bytes say otherwise.
  - polyglot (SXV-036): one file valid as two formats at once. The dangerous common shape
    is a container prepended to another file -- an image with a zip appended (the "GIFAR"),
    which loads as an image yet unzips as code.
  - unreferenced bytes (SXV-037): data past a container's logical end (after a zip's
    end-of-central-directory record or a PNG's IEND chunk), or a validated native/archive
    payload embedded in an image carrier. The format ignores it; an agent that carves or
    executes the file does not.

Fail closed: an unrecognised byte string is never a finding, but a recognised format that
contradicts the declared one, or bytes a container does not reference, is. A malformed
container is reported as unverifiable, never silently passed. Every embedded-payload magic
is confirmed by a header check, a CRC, or a bounded decompression -- never a bare magic --
so an incidental magic in pixel data cannot fire.
"""

from __future__ import annotations

import os
import zlib

from .findings import Finding, dedupe_findings

__all__ = ["analyze_package", "analyze_artifact", "sniff_magic"]

# byte-forensics rule slugs -> the vector each proves in the registry.
_VECTOR = {"magic-mismatch": "SXV-035", "polyglot": "SXV-036",
           "unreferenced-bytes": "SXV-037", "analyzer-error": ""}


def _F(rule, severity, path, message, offset=None, length=None, detail=None):
    """Build a canonical Finding from a byte-forensics rule slug, mapping the slug to
    its vector and folding an optional detail token into the evidence."""
    return Finding(vector=_VECTOR.get(rule, ""), rule=rule, severity=severity, path=path,
                   message=message, offset=offset, length=length,
                   evidence={"detail": detail} if detail is not None else {})


# ---------------------------------------------------------------------------
# magic signatures
# ---------------------------------------------------------------------------

# Offset-0 signatures, longest first so a longer match wins over a short prefix
# (e.g. the 8-byte PNG signature over a 2-byte one). Formats sniffed only to name a
# masquerade or a polyglot half; this is not a full file-type database.
_SIGS: tuple[tuple[bytes, str], ...] = tuple(sorted((
    (b"\x7fELF", "elf"),
    (b"\xca\xfe\xba\xbe", "macho_fat"),         # Mach-O fat binary and Java .class share this
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),                     # empty-archive end-of-central-directory
    (b"PK\x07\x08", "zip"),                     # spanned archive
    (b"\x1f\x8b", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "sevenzip"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"MZ", "pe"),
), key=lambda s: -len(s[0])))

_EXECUTABLE = {"elf", "pe", "macho", "macho_fat"}
_ARCHIVE = {"zip", "gzip", "sevenzip"}
# Formats that must never be the true bytes of a file declared as human/agent-readable
# text or code, nor of an inert image asset.
_DANGEROUS = _EXECUTABLE | _ARCHIVE
_IMAGE_FORMATS = {"png", "jpeg", "gif"}

# What an asset extension should be, so a contradicting known image can be named.
_EXT_EXPECT = {".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif"}

# Kinds ingest labels as decoded text or source (parse consumes their .text). A known
# binary/executable magic at offset 0 of one of these is a masquerade.
_TEXT_KINDS = {"skill_manifest", "instruction", "doc", "agent_identity", "agent_config",
               "hooks_config", "mcp_config", "plugin_manifest", "app_manifest",
               "plugin_lock", "dep_manifest", "secret_material"}
_COMPILED_KINDS = {"python_bytecode", "python_extension", "native_code"}

_SNIFF_WINDOW = 64          # bytes of a region handed to sniff_magic to name a payload
_ZIP_COMMENT_MAX = 65535    # a zip end-of-central-directory comment field is 16-bit


# ---------------------------------------------------------------------------
# structurally-validated executable magics (not a bare 2-byte ASCII prefix)
# ---------------------------------------------------------------------------

_ELF_MAGIC = b"\x7fELF"
_MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                 b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def _is_pe(raw: bytes, i: int = 0) -> bool:
    """A real PE/DOS executable at offset i: 'MZ' then a PE\\x00\\x00 header at the e_lfanew offset
    stored at 0x3C. Without this, the two ASCII letters 'MZ' -- which begin ordinary prose and turn
    up constantly in pixel data -- would sniff/scan as 'pe'."""
    if len(raw) < i + 0x40 or raw[i:i + 2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(raw[i + 0x3C:i + 0x40], "little")
    off = i + e_lfanew
    return 0 <= e_lfanew and off + 4 <= len(raw) and raw[off:off + 4] == b"PE\x00\x00"


def _is_elf(raw: bytes, i: int = 0) -> bool:
    """A plausible ELF header at offset i: magic + class(1|2) + data(1|2) + ident-version 1, AND
    e_version == EV_CURRENT(1). The extra e_version word (always 1 in every real ELF) means a
    7-byte magic+ident run crafted into pixel data does not chance-validate as an executable."""
    if not (raw[i:i + 4] == _ELF_MAGIC and len(raw) >= i + 24
            and raw[i + 4] in (1, 2) and raw[i + 5] in (1, 2) and raw[i + 6] == 1):
        return False
    endian = "little" if raw[i + 5] == 1 else "big"
    return int.from_bytes(raw[i + 20:i + 24], endian) == 1     # e_version == EV_CURRENT


# Mach-O cputype low 24 bits (the 0x01000000 bit marks the 64-bit ABI): VAX/MC680x0/x86/
# MC98000/HPPA/ARM/SPARC/i860/Alpha/PowerPC. filetype is MH_OBJECT(1)..MH_KEXT_BUNDLE(11).
_MACHO_CPU = frozenset({1, 6, 7, 10, 11, 12, 14, 15, 16, 18})
_MACHO_FILETYPE = frozenset(range(1, 12))


def _is_macho(raw: bytes, i: int = 0) -> bool:
    """A plausible Mach-O header at offset i. The 4-byte magics collide with ordinary data --
    0xCAFEBABE is also the Java class-file magic and turns up in zlib/pixel streams -- so a bare
    magic is not enough: validate the header fields (fat: a bounded nfat_arch whose arch table
    fits and a known first cputype; thin: a known cputype and a filetype in the MH_* range)."""
    magic = raw[i:i + 4]
    if len(magic) < 4:
        return False
    if magic == b"\xca\xfe\xba\xbe":                     # fat/universal, fields big-endian
        if len(raw) < i + 12:
            return False
        nfat = int.from_bytes(raw[i + 4:i + 8], "big")
        if not 1 <= nfat <= 32 or i + 8 + nfat * 20 > len(raw):
            return False                                 # Java .class reads nfat = major (>=49)
        cpu = int.from_bytes(raw[i + 8:i + 12], "big") & 0x00ffffff
        return cpu in _MACHO_CPU
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):        # thin, big-endian
        endian = "big"
    elif magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):      # thin, little-endian
        endian = "little"
    else:
        return False
    if len(raw) < i + 16:
        return False
    cpu = int.from_bytes(raw[i + 4:i + 8], endian) & 0x00ffffff
    filetype = int.from_bytes(raw[i + 12:i + 16], endian)
    return cpu in _MACHO_CPU and filetype in _MACHO_FILETYPE


_CAPPED = "capped"                              # sentinel: a capped scan gave up amid decoy tiling


def _first_validated(raw: bytes, magic: bytes, validator, kind: str, cap=None):
    """(offset, kind) of the first `magic` occurrence at offset > 0 passing `validator`; None if
    fully scanned with no match; or _CAPPED if `cap` is set and reached with occurrences still
    unexamined. A cap is used ONLY for the expensive CRC validator (7z): a benign file has ~0 of
    those long magics, so exhausting the cap means crafted decoy-tiling -- itself anomalous and
    worth reporting, never a reason to silently pass. The cheap validators (O(1) header checks /
    output-capped decompression) are bounded per candidate and run uncapped, so a real payload is
    never missed behind decoys."""
    k = raw.find(magic, 1)
    tries = 0
    while k > 0:
        if validator(raw, k):
            return (k, kind)
        k = raw.find(magic, k + 1)
        tries += 1
        if cap is not None and tries >= cap:
            return _CAPPED if k > 0 else None   # more occurrences remain: anomalous decoy tiling
    return None


def _earliest(*candidates):
    """The (offset, kind) with the smallest offset among the tuple candidates (ignores None and the
    _CAPPED sentinel), or None."""
    found = [c for c in candidates if c is not None and c is not _CAPPED]
    return min(found, key=lambda c: c[0]) if found else None


def _embedded_executable(raw: bytes):
    """(offset, kind) of a native executable carved into a file at offset > 0, or None. Used on
    IMAGE carriers, where an embedded ELF/Mach-O/PE is an appended-payload polyglot (GIFAR-style
    with native code). All three are header-validated -- a bare magic that lands by chance in
    pixel/compressed data (0xCAFEBABE, or the two ASCII bytes 'MZ') is not enough to report."""
    macho = _earliest(*(_first_validated(raw, sig, _is_macho, "macho") for sig in _MACHO_MAGICS))
    return _earliest(_first_validated(raw, _ELF_MAGIC, _is_elf, "elf"),
                     macho,
                     _first_validated(raw, b"MZ", _is_pe, "pe"))


_GZIP_MAGIC = b"\x1f\x8b"
_DECOMPRESS_OUTPUT = 64                          # bounded output cap (no decompression bomb)


def _is_gzip(raw: bytes, i: int) -> bool:
    """A real gzip member at offset i. The 2-byte magic and even the fixed header fields chance-
    collide in pixel data (1f 8b 08 00 00 00 00 00 00 00 is an ordinary colour run), so after a
    cheap header pre-filter the bytes must actually decompress as gzip -- fed the whole remaining
    tail as a zero-copy memoryview with the OUTPUT capped, so a bomb yields <=64 bytes."""
    if not (len(raw) >= i + 10 and raw[i:i + 2] == _GZIP_MAGIC and raw[i + 2] == 8
            and (raw[i + 3] & 0xE0) == 0):
        return False
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(memoryview(raw)[i:], _DECOMPRESS_OUTPUT)
        return bool(out) or getattr(d, "eof", False)
    except (zlib.error, OSError, ValueError):
        return False


_7Z_MAGIC = b"7z\xbc\xaf\x27\x1c"
# A 7z Next-Header that a validator CRCs must not span an attacker-controlled length: without a cap,
# a file tiling thousands of magic records -- each forcing a crc32 over the whole tail -- is O(N^2)
# (a DoS). A real embedded archive's header is far smaller than this bound.
_MAX_ARCHIVE_HEADER = 262144
# Candidate cap for the expensive 7z CRC validator only (rationale in _first_validated): bounds a
# crafted decoy-tiling file; the cheap validators (gzip) run uncapped.
_MAX_EMBED_CANDIDATES = 64


def _is_7z(raw: bytes, i: int) -> bool:
    """A real 7z archive at offset i: the 6-byte magic, the Start-Header CRC32 over the 20-byte
    Start Header, AND the Next-Header CRC32 over the actual next-header bytes it points to. The
    first CRC alone (20 crafted bytes) is self-satisfiable in pixel data; the second CRC, over the
    header the Start Header references, is what a chance/crafted pixel run cannot also satisfy."""
    if len(raw) < i + 32 or raw[i:i + 6] != _7Z_MAGIC:
        return False
    if zlib.crc32(raw[i + 12:i + 32]) != int.from_bytes(raw[i + 8:i + 12], "little"):
        return False
    nh_off = int.from_bytes(raw[i + 12:i + 20], "little")    # NextHeaderOffset (from byte 32)
    nh_size = int.from_bytes(raw[i + 20:i + 28], "little")   # NextHeaderSize
    nh_crc = int.from_bytes(raw[i + 28:i + 32], "little")    # NextHeaderCRC
    base = i + 32
    if not 0 < nh_size <= _MAX_ARCHIVE_HEADER or base + nh_off + nh_size > len(raw):
        return False                                         # cap the CRC region (see the constant)
    return zlib.crc32(raw[base + nh_off:base + nh_off + nh_size]) == nh_crc


# Every embedded-payload magic is confirmed by a validator: a bare or even a "long" magic occurs in
# ordinary pixel data, so the validator -- a decompression or a CRC -- distinguishes a real payload
# from colour bytes. (magic, validator, kind, cap): only the expensive CRC validator (7z) carries a
# candidate cap; gzip is per-candidate bounded (output-capped decompression) and uncapped.
_EMBED_ARCHIVE_CHECKS = (
    (_GZIP_MAGIC, _is_gzip, "gzip", None),
    (_7Z_MAGIC, _is_7z, "sevenzip", _MAX_EMBED_CANDIDATES),
)


def _embedded_dangerous(raw: bytes):
    """(offset, kind) of a native executable OR compressed archive carved into an image at offset
    > 0; None if none; or _CAPPED if the capped (7z) scan gave up amid decoy tiling without finding
    a real payload. Every magic is validated, so a chance match cannot fire."""
    capped = False
    found = [_embedded_executable(raw)]                   # ELF / Mach-O / PE, header-validated
    for magic, validator, kind, cap in _EMBED_ARCHIVE_CHECKS:
        r = _first_validated(raw, magic, validator, kind, cap)
        if r is _CAPPED:
            capped = True
        elif r is not None:
            found.append(r)
    best = _earliest(*found)
    return best if best else (_CAPPED if capped else None)


def sniff_magic(raw: bytes):
    """The format named by the bytes at offset 0, or None. Recognises a handful of executable,
    archive and image signatures. Pure, no I/O."""
    if not raw:
        return None
    for sig, name in _SIGS:
        if raw.startswith(sig):
            if name == "pe" and not _is_pe(raw):
                continue                        # "MZ" is 2 ASCII letters -- validate the PE header
            return name
    return None


def _looks_textual(raw: bytes) -> bool:
    """True if the leading bytes read as ordinary UTF-8 text (a script or markup
    renamed to a binary asset extension), False for real binary data."""
    sample = raw[:512]
    if not sample or b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / len(sample) > 0.85


def _declared(kind: str, ext: str, text) -> str:
    """The byte nature the package CLAIMS for an artifact, from its kind/extension."""
    if kind in _TEXT_KINDS or kind.startswith("script_"):
        return "text"
    if kind == "other" and text is not None:
        return "text"                      # decoded text with no specific role
    if kind == "asset":
        return "image"                     # inert asset (image/font/media) by extension
    if kind == "active_asset":
        return "pdf" if ext == ".pdf" else "svg"
    if kind == "nested_archive":
        return "archive"
    if kind in _COMPILED_KINDS:
        return "compiled"
    return "other"


# ---------------------------------------------------------------------------
# container structure (polyglot + unreferenced bytes)
# ---------------------------------------------------------------------------

def _u16le(raw, i):
    return int.from_bytes(raw[i:i + 2], "little")


def _u32le(raw, i):
    return int.from_bytes(raw[i:i + 4], "little")


def _find_eocd(raw: bytes):
    """Locate a VALIDATED, NON-EMPTY zip end-of-central-directory record, or None. A bare PK\x05\x06
    byte sequence is not enough: those four bytes occur by chance in pixel data and compressed
    streams, so the record must actually resolve to a central directory present in the file -- its
    cd_size lands on a PK\x01\x02 central-directory header. An EMPTY archive (total==0 / cd_size==0)
    is not accepted: it carries no files, so it cannot be a prepended-container polyglot, and its
    all-zero fields are exactly what incidental PK\x05\x06 pixel bytes supply."""
    sig = b"PK\x05\x06"
    span = _ZIP_COMMENT_MAX + 22
    window = raw[-span:] if len(raw) > span else raw
    idx = window.rfind(sig)
    if idx < 0:
        return None
    e = len(raw) - len(window) + idx
    if e + 22 > len(raw):
        return None
    total = _u16le(raw, e + 10)                 # total central-directory entries
    cd_size = _u32le(raw, e + 12)
    cd_offset = _u32le(raw, e + 16)
    comment_len = _u16le(raw, e + 20)
    cd_pos = e - cd_size
    if total == 0 or cd_size == 0:              # an empty archive references no files: not a
        return None                            # polyglot/overlay carrier (and the FP shape)
    if cd_pos < 0 or raw[cd_pos:cd_pos + 4] != b"PK\x01\x02":
        return None                             # size points to non-directory bytes: chance PK
    return {"eocd": e, "cd_size": cd_size, "cd_offset": cd_offset,
            "comment_len": comment_len, "total": total}


def _zip_findings(rel: str, raw: bytes) -> list:
    """Prepend polyglot and trailing-overlay findings for a file that ends in a zip
    end-of-central-directory record. Fails closed: an inconsistent record is reported as
    unverifiable, never silently passed."""
    info = _find_eocd(raw)
    if info is None:
        return []
    e, cd_size, cd_offset, comment_len = (
        info["eocd"], info["cd_size"], info["cd_offset"], info["comment_len"])
    filesize = len(raw)
    logical_end = e + 22 + comment_len
    cd_pos = e - cd_size                       # central directory sits just before the EOCD
    archive_start = cd_pos - cd_offset         # its recorded offset is from the archive start
    out = []
    if not (0 <= cd_pos <= e and 0 <= archive_start <= cd_pos):
        # a bare 22-byte EOCD appended to another file, or a truncated/garbled archive:
        # the trailer says "zip" but the structure does not line up.
        out.append(_F(
            "unreferenced-bytes", "medium", rel,
            "a zip end-of-central-directory record is present but its structure does not "
            "line up; bytes may be concealed around it", offset=e, length=filesize - e))
        return out
    if archive_start > 0:
        pre = sniff_magic(raw)
        out.append(_F(
            "polyglot", "high", rel,
            "%d byte(s) precede a valid zip archive: the file is both %s and a zip "
            "(prepended-container polyglot)" % (archive_start, pre or "other data"),
            offset=0, length=archive_start, detail=pre))
    if logical_end < filesize:
        trail = filesize - logical_end
        ts = sniff_magic(raw[logical_end:logical_end + _SNIFF_WINDOW])
        out.append(_F(
            "unreferenced-bytes", "high" if ts in _DANGEROUS else "medium", rel,
            "%d byte(s) follow the zip end-of-central-directory record "
            "(appended overlay%s)" % (trail, ": %s" % ts if ts else ""),
            offset=logical_end, length=trail, detail=ts))
    return out


def _png_findings(rel: str, raw: bytes) -> list:
    """Trailing bytes after a PNG's IEND chunk. Walks the chunk list from the signature;
    a malformed chunk length stops the walk and is reported rather than trusted."""
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return []
    n = len(raw)
    pos = 8
    while pos + 8 <= n:
        length = int.from_bytes(raw[pos:pos + 4], "big")
        ctype = raw[pos + 4:pos + 8]
        nxt = pos + 8 + length + 4              # data + 4-byte CRC
        if ctype == b"IEND":
            if nxt < n:
                trail = n - nxt
                ts = sniff_magic(raw[nxt:nxt + _SNIFF_WINDOW])
                return [_F(
                    "unreferenced-bytes", "high" if ts in _DANGEROUS else "medium", rel,
                    "%d byte(s) follow the PNG IEND chunk (appended overlay%s)"
                    % (trail, ": %s" % ts if ts else ""),
                    offset=nxt, length=trail, detail=ts)]
            return []
        if nxt <= pos or nxt > n:               # oversized/garbled length: cannot verify
            return [_F(
                "unreferenced-bytes", "low", rel,
                "the PNG chunk structure is malformed; trailing bytes could not be verified",
                offset=pos, length=n - pos)]
        pos = nxt
    return []


# ---------------------------------------------------------------------------
# per-artifact and per-package entry points
# ---------------------------------------------------------------------------

def _magic_mismatch(rel, declared, ext, detected, raw) -> list:
    """Findings for bytes that contradict the declared type. Emits only on a positive,
    recognised contradiction, so a genuine text/asset file is never flagged."""
    out = []
    if declared == "text":
        # genuinely-textual content is never a binary masquerade, even when a 2-byte ASCII
        # magic collides ("MZ Motorrad..." sniffs pe): guard on content.
        if _looks_textual(raw):
            return out
        if detected in _DANGEROUS:
            out.append(_F(
                "magic-mismatch", "high", rel,
                "declared as readable text/code but the bytes are %s "
                "(executable or archive masquerading as text)" % detected, detail=detected))
        elif detected in _IMAGE_FORMATS:
            out.append(_F(
                "magic-mismatch", "low", rel,
                "declared as text/code but the bytes are %s-format image data" % detected,
                detail=detected))
    elif declared == "image":
        expect = _EXT_EXPECT.get(ext)
        if detected in _DANGEROUS:
            out.append(_F(
                "magic-mismatch", "high", rel,
                "an inert %s asset by name, but the bytes are %s "
                "(executable or archive hidden as an asset)" % (ext or "binary", detected),
                detail=detected))
        elif detected is None and _looks_textual(raw):
            out.append(_F(
                "magic-mismatch", "medium", rel,
                "an inert %s asset by name, but the bytes are text or a script"
                % (ext or "binary"), detail="text"))
        elif detected in _IMAGE_FORMATS and expect is not None and detected != expect:
            out.append(_F(
                "magic-mismatch", "low", rel,
                "labeled %s but the bytes are %s-format image data" % (ext, detected),
                detail=detected))
    elif declared == "svg":
        if detected in _DANGEROUS:
            out.append(_F(
                "magic-mismatch", "high", rel,
                "an .svg by name, but the bytes are %s "
                "(executable or archive hidden as an image)" % detected, detail=detected))
    elif declared == "archive":
        if detected in _EXECUTABLE:
            out.append(_F(
                "magic-mismatch", "high", rel,
                "an archive by name, but the bytes are %s (an executable)" % detected,
                detail=detected))
    # Catch-all: a native executable under ANY declared type not expected to be one -- e.g. an
    # ELF shipped as `model.dat` (unknown extension -> declared "other"). A `compiled` artifact
    # (.so/.exe/native_code) legitimately IS an executable, so it is excluded.
    if not out and detected in _EXECUTABLE and declared != "compiled":
        out.append(_F(
            "magic-mismatch", "high", rel,
            "named/declared as %s (%s) but the bytes are a %s executable"
            % (declared, ext or "no extension", detected), detail=detected))
    return out


def analyze_artifact(rel: str, kind: str, text, raw: bytes) -> list:
    """Byte-level findings for one artifact. Returns [] when there is nothing to inspect
    (no bytes) or the bytes match the declared type. Never raises."""
    if not raw:
        return []
    try:
        ext = os.path.splitext(rel)[1].lower()
        declared = _declared(kind, ext, text)
        detected = sniff_magic(raw)
        out = _magic_mismatch(rel, declared, ext, detected, raw)

        # Trailing bytes after a PNG's logical end (IEND chunk).
        if detected == "png":
            out += _png_findings(rel, raw)

        # Zip polyglot / appended-archive: _find_eocd STRUCTURALLY validates the EOCD (it must
        # resolve to a real central directory), so a chance "PK\x05\x06" inside pixel data or a
        # compressed stream yields nothing, and a real prepended/appended zip on any carrier is
        # still caught.
        carrier = (detected in {"zip", "png", "gif", "jpeg"}
                   or declared in {"image", "svg", "pdf", "archive", "compiled"})
        if carrier and b"PK\x05\x06" in raw:
            out += _zip_findings(rel, raw)

        # Backstop: a native executable OR compressed archive carved into an IMAGE carrier (the
        # GIFAR shape). Every magic here is validated (header/CRC/decompression), so a chance match
        # in pixel data cannot fire.
        if detected in _IMAGE_FORMATS or declared == "image":
            emb = _embedded_dangerous(raw)
            if emb is _CAPPED:
                # A capped (7z) scan gave up amid many decoy headers without validating one. A
                # benign image has ~0 of these long magics, so this tiling is itself anomalous (a
                # decoy pad to push a real payload past the DoS cap) -- report it, never pass.
                out.append(_F(
                    "unreferenced-bytes", "medium", rel,
                    "an unusually large number of embedded archive-header signatures "
                    "(possible decoy tiling to evade payload detection)", detail="capped"))
            elif emb:
                off, kind_ = emb
                # Drop only a TEXT/unrecognised handler finding anchored INSIDE the validated
                # payload (offset > off) -- a mis-anchor on the payload's own interior marker. A
                # finding naming a distinct recognised format at another offset is a genuinely
                # separate payload, so it is kept.
                out = [f for f in out if not (
                    f.rule in ("unreferenced-bytes", "polyglot")
                    and f.offset is not None and f.offset > off
                    and f.evidence.get("detail") in (None, "text"))]
                already = any(
                    f.rule in ("unreferenced-bytes", "polyglot") and f.offset is not None
                    and f.offset <= off < f.offset + (f.length or 0) for f in out)
                if not already:
                    out.append(_F(
                        "unreferenced-bytes", "high", rel,
                        "a %s payload is embedded at offset %d in this image "
                        "(appended native or archive data)" % (kind_, off),
                        offset=off, length=len(raw) - off, detail=kind_))
        return out
    except Exception as exc:                    # fail closed: an analyzer bug is a finding
        return [_F("analyzer-error", "low", rel,
                   "byte analysis could not complete: %s" % type(exc).__name__)]


def analyze_package(parsed) -> list:
    """Run the byte-level checks over every artifact in a ParsedPackage and return the
    findings, most severe first and deterministically ordered. Reads only the bytes the
    IR carries; touches no filesystem."""
    findings = []
    for p in parsed.artifacts:
        findings.extend(analyze_artifact(p.rel, p.kind, p.text, getattr(p, "raw", None)))
    return dedupe_findings(findings)
