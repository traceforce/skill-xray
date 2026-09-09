"""Offline byte forensics for SXV-035 through SXV-037."""

from __future__ import annotations

import os
import re
import zlib

from .findings import Finding, dedupe_findings

__all__ = ["analyze_package", "analyze_artifact", "sniff_magic"]

_VECTOR = {"magic-mismatch": "SXV-035", "polyglot": "SXV-036",
           "unreferenced-bytes": "SXV-037", "analyzer-error": ""}


def _F(rule, severity, path, message, offset=None, length=None, detail=None):
    return Finding(vector=_VECTOR.get(rule, ""), rule=rule, severity=severity, path=path,
                   message=message, offset=offset, length=length,
                   evidence={"detail": detail} if detail is not None else {})

_SIGS: tuple[tuple[bytes, str], ...] = tuple(sorted((
    (b"\x7fELF", "elf"), (b"\xca\xfe\xba\xbe", "macho_fat"),
    (b"\xfe\xed\xfa\xce", "macho"), (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"), (b"\xcf\xfa\xed\xfe", "macho"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),                     # empty-archive end-of-central-directory
    (b"PK\x07\x08", "zip"),                     # spanned archive
    (b"\x1f\x8b", "gzip"), (b"7z\xbc\xaf\x27\x1c", "sevenzip"),
    (b"\x89PNG\r\n\x1a\n", "png"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
    (b"\xff\xd8\xff", "jpeg"), (b"MZ", "pe"),
), key=lambda s: -len(s[0])))

_EXECUTABLE = {"elf", "pe", "macho", "macho_fat"}
_ARCHIVE = {"zip", "gzip", "sevenzip"}
_DANGEROUS = _EXECUTABLE | _ARCHIVE
_IMAGE_FORMATS = {"png", "jpeg", "gif"}
_EXT_EXPECT = {".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif"}
_ARCHIVE_EXT_EXPECT = {".zip": "zip", ".whl": "zip", ".gz": "gzip", ".gzip": "gzip",
                       ".tgz": "gzip", ".7z": "sevenzip"}
_COMPILED_EXT_EXPECT = {".jar": {"zip"}, ".war": {"zip"}, ".class": set(),
    ".pyc": set(), ".pyo": set(), ".wasm": set(), ".a": set(),
    ".so": _EXECUTABLE, ".node": _EXECUTABLE, ".o": _EXECUTABLE,
    ".dylib": {"macho", "macho_fat"}, ".dll": {"pe"}, ".exe": {"pe"}, ".pyd": {"pe"}}

_TEXT_KINDS = {"skill_manifest", "instruction", "doc", "agent_identity", "agent_config",
               "hooks_config", "mcp_config", "plugin_manifest", "app_manifest",
               "plugin_lock", "dep_manifest", "secret_material"}
_COMPILED_KINDS = {"python_bytecode", "python_extension", "native_code"}
_ELF_MAGIC = b"\x7fELF"
_MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                 b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def _is_pe(raw: bytes, i: int = 0) -> bool:
    if len(raw) < i + 0x40 or raw[i:i + 2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(raw[i + 0x3C:i + 0x40], "little")
    off = i + e_lfanew
    if e_lfanew < 0x40 or off + 24 > len(raw) or raw[off:off + 4] != b"PE\x00\x00":
        return False
    optional_size = int.from_bytes(raw[off + 20:off + 22], "little")
    return off + 24 + optional_size <= len(raw)


def _is_elf(raw: bytes, i: int = 0) -> bool:
    if not (raw[i:i + 4] == _ELF_MAGIC and len(raw) >= i + 7
            and raw[i + 4] in (1, 2) and raw[i + 5] in (1, 2) and raw[i + 6] == 1):
        return False
    endian = "little" if raw[i + 5] == 1 else "big"
    header_size = 52 if raw[i + 4] == 1 else 64
    ehsize_offset = i + (40 if raw[i + 4] == 1 else 52)
    return (len(raw) >= i + header_size
            and int.from_bytes(raw[i + 20:i + 24], endian) == 1
            and int.from_bytes(raw[ehsize_offset:ehsize_offset + 2], endian) == header_size)


_MACHO_CPU = frozenset({1, 6, 7, 10, 11, 12, 14, 15, 16, 18})
_MACHO_FILETYPE = frozenset(range(1, 12))


def _is_macho(raw: bytes, i: int = 0) -> bool:
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
    header_size = 32 if magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") else 28
    if len(raw) < i + header_size:
        return False
    cpu = int.from_bytes(raw[i + 4:i + 8], endian) & 0x00ffffff
    filetype = int.from_bytes(raw[i + 12:i + 16], endian)
    return cpu in _MACHO_CPU and filetype in _MACHO_FILETYPE


_CAPPED = "capped"                              # sentinel: a capped scan gave up amid decoy tiling


def _first_validated(raw: bytes, magic: bytes, validator, kind: str, cap=None):
    """Return the first validated embedded signature, or _CAPPED when an expensive
    validator exhausts its candidate budget."""
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
    found = [c for c in candidates if c is not None and c is not _CAPPED]
    return min(found, key=lambda c: c[0]) if found else None


def _embedded_executable(raw: bytes):
    candidates = [_first_validated(raw, _ELF_MAGIC, _is_elf, "elf", _MAX_EMBED_CANDIDATES),
                  _first_validated(raw, b"MZ", _is_pe, "pe", _MAX_EMBED_CANDIDATES)]
    candidates += [_first_validated(raw, sig, _is_macho, "macho", _MAX_EMBED_CANDIDATES)
                   for sig in _MACHO_MAGICS]
    return _earliest(*candidates) or (_CAPPED if _CAPPED in candidates else None)


_GZIP_MAGIC = b"\x1f\x8b"
_MAX_GZIP_OUTPUT = 1048576


def _is_gzip(raw: bytes, i: int) -> bool:
    if not (len(raw) >= i + 10 and raw[i:i + 2] == _GZIP_MAGIC and raw[i + 2] == 8
            and (raw[i + 3] & 0xE0) == 0):
        return False
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        pending = memoryview(raw)[i:]
        produced = 0
        while pending and not d.eof:
            out = d.decompress(pending, _MAX_GZIP_OUTPUT - produced + 1)
            produced += len(out)
            if produced > _MAX_GZIP_OUTPUT:
                return False
            pending = d.unconsumed_tail
            if not pending:
                break
        return d.eof
    except (zlib.error, OSError, ValueError):
        return False


_7Z_MAGIC = b"7z\xbc\xaf\x27\x1c"
_MAX_ARCHIVE_HEADER = 262144
_MAX_EMBED_CANDIDATES = 64
_MAX_EOCD_CANDIDATES = 128


def _is_7z(raw: bytes, i: int) -> bool:
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


_EMBED_ARCHIVE_CHECKS = (
    (_GZIP_MAGIC, _is_gzip, "gzip", _MAX_EMBED_CANDIDATES),
    (_7Z_MAGIC, _is_7z, "sevenzip", _MAX_EMBED_CANDIDATES),
)


def _embedded_dangerous(raw: bytes):
    executable = _embedded_executable(raw)
    capped = executable is _CAPPED
    found = [executable]                                  # ELF / Mach-O / PE, header-validated
    zip_info = _find_eocd(raw)
    if isinstance(zip_info, dict):
        start = zip_info["eocd"] - zip_info["cd_size"] - zip_info["cd_offset"]
        if start > 0:
            found.append((start, "zip"))
    capped |= zip_info is _CAPPED
    for magic, validator, kind, cap in _EMBED_ARCHIVE_CHECKS:
        r = _first_validated(raw, magic, validator, kind, cap)
        if r is _CAPPED:
            capped = True
        elif r is not None:
            found.append(r)
    best = _earliest(*found)
    return best if best else (_CAPPED if capped else None)


def sniff_magic(raw: bytes):
    if not raw:
        return None
    for sig, name in _SIGS:
        if raw.startswith(sig):
            if name == "pe" and not _is_pe(raw):
                continue
            if name == "elf" and not _is_elf(raw):
                continue
            if name in {"macho", "macho_fat"} and not _is_macho(raw):
                continue
            if name == "gzip" and not _is_gzip(raw, 0):
                continue
            if name == "sevenzip" and not _is_7z(raw, 0):
                continue
            if name == "zip":
                info = _find_eocd(raw)
                if not isinstance(info, dict):
                    continue
            return name
    return None


def _looks_textual(raw: bytes) -> bool:
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


def _u16le(raw, i):
    return int.from_bytes(raw[i:i + 2], "little")


def _u32le(raw, i):
    return int.from_bytes(raw[i:i + 4], "little")


def _eocd_candidate(raw: bytes, e: int):
    if e + 22 > len(raw):
        return None
    disk = _u16le(raw, e + 4)
    cd_disk = _u16le(raw, e + 6)
    disk_entries = _u16le(raw, e + 8)
    total = _u16le(raw, e + 10)
    cd_size = _u32le(raw, e + 12)
    cd_offset = _u32le(raw, e + 16)
    comment_len = _u16le(raw, e + 20)
    if e + 22 + comment_len > len(raw):
        return None
    if disk or cd_disk or disk_entries != total:
        return None
    if total == 0:
        if cd_size or cd_offset:
            return None
        prefix = raw[:e]
        if e:
            image_kind = ("png" if prefix.startswith(b"\x89PNG\r\n\x1a\n") else
                          "gif" if prefix.startswith((b"GIF87a", b"GIF89a")) else
                          "jpeg" if prefix.startswith(b"\xff\xd8") else None)
            if not _valid_image_carrier(prefix, image_kind):
                return None
        return {"eocd": e, "cd_size": 0, "cd_offset": 0,
                "comment_len": comment_len, "total": 0}
    if total == 0xffff or cd_size == 0xffffffff or cd_offset == 0xffffffff:
        return None
    cd_pos = e - cd_size
    archive_start = cd_pos - cd_offset
    if cd_pos < 0 or archive_start < 0:
        return None
    pos = cd_pos
    for _ in range(total):
        if pos + 46 > e or raw[pos:pos + 4] != b"PK\x01\x02":
            return None
        name_len = _u16le(raw, pos + 28)
        extra_len = _u16le(raw, pos + 30)
        entry_comment_len = _u16le(raw, pos + 32)
        compressed_size = _u32le(raw, pos + 20)
        if not name_len or _u16le(raw, pos + 34) != 0:
            return None
        local_offset = _u32le(raw, pos + 42)
        local_pos = archive_start + local_offset
        if local_pos < archive_start or local_pos + 30 > cd_pos:
            return None
        if raw[local_pos:local_pos + 4] != b"PK\x03\x04":
            return None
        local_name_len = _u16le(raw, local_pos + 26)
        local_extra_len = _u16le(raw, local_pos + 28)
        data_pos = local_pos + 30 + local_name_len + local_extra_len
        central_name = raw[pos + 46:pos + 46 + name_len]
        local_name = raw[local_pos + 30:local_pos + 30 + local_name_len]
        if central_name != local_name or data_pos + compressed_size > cd_pos:
            return None
        pos += 46 + name_len + extra_len + entry_comment_len
        if pos > e:
            return None
    if pos != e:
        return None
    return {"eocd": e, "cd_size": cd_size, "cd_offset": cd_offset,
            "comment_len": comment_len, "total": total}


def _find_eocd(raw: bytes):
    sig = b"PK\x05\x06"
    before = len(raw)
    for _ in range(_MAX_EOCD_CANDIDATES):
        e = raw.rfind(sig, 0, before)
        if e < 0:
            return None
        info = _eocd_candidate(raw, e)
        if info is not None:
            return info
        before = e
    return _CAPPED if raw.rfind(sig, 0, before) >= 0 else None


def _valid_gif(raw: bytes) -> bool:
    if len(raw) < 14 or raw[:6] not in (b"GIF87a", b"GIF89a"):
        return False
    pos = 13
    if raw[10] & 0x80:
        pos += 3 * (1 << ((raw[10] & 7) + 1))
    while pos < len(raw):
        marker = raw[pos]
        pos += 1
        if marker == 0x3B:
            return pos == len(raw)
        if marker == 0x2C:
            if pos + 9 > len(raw):
                return False
            packed = raw[pos + 8]
            pos += 9 + (3 * (1 << ((packed & 7) + 1)) if packed & 0x80 else 0)
            if pos >= len(raw):
                return False
            pos += 1
        elif marker == 0x21:
            if pos >= len(raw):
                return False
            pos += 1
        else:
            return False
        while pos < len(raw):
            size = raw[pos]
            pos += 1
            if size == 0:
                break
            pos += size
            if pos > len(raw):
                return False
        else:
            return False
    return False


def _valid_jpeg(raw: bytes) -> bool:
    if not raw.startswith(b"\xff\xd8"):
        return False
    pos, saw_frame, saw_scan = 2, False, False
    while pos + 1 < len(raw):
        if raw[pos] != 0xff:
            if not saw_scan:
                return False
            pos += 1
            continue
        while pos < len(raw) and raw[pos] == 0xff:
            pos += 1
        if pos >= len(raw):
            return False
        marker = raw[pos]
        pos += 1
        if marker == 0x00 and saw_scan:
            continue
        if marker == 0xD9:
            return saw_frame and saw_scan and pos == len(raw)
        if marker in range(0xD0, 0xD8) or marker == 0x01:
            continue
        if pos + 2 > len(raw):
            return False
        size = int.from_bytes(raw[pos:pos + 2], "big")
        if size < 2 or pos + size > len(raw):
            return False
        saw_frame |= marker in range(0xC0, 0xD0) and marker not in {0xC4, 0xC8, 0xCC}
        saw_scan |= marker == 0xDA
        pos += size
    return False


def _valid_image_carrier(raw: bytes, kind: str | None) -> bool:
    if kind == "png":
        return _png_logical_end(raw) == len(raw)
    if kind == "gif":
        return _valid_gif(raw)
    if kind == "jpeg":
        return _valid_jpeg(raw)
    return False


def _zip_findings(rel: str, raw: bytes) -> list:
    info = _find_eocd(raw)
    if info is _CAPPED:
        return [_F(
            "unreferenced-bytes", "medium", rel,
            "an unusually large number of ZIP end-record signatures prevented complete "
            "validation", detail="capped")]
    if info is None:
        if raw.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            return [_F(
                "unreferenced-bytes", "low", rel,
                "the ZIP structure is malformed or unsupported; trailing bytes could not "
                "be verified", offset=0, length=len(raw))]
        return []
    e, cd_size, cd_offset, comment_len = (
        info["eocd"], info["cd_size"], info["cd_offset"], info["comment_len"])
    filesize = len(raw)
    logical_end = e + 22 + comment_len
    cd_pos = e - cd_size                       # central directory sits just before the EOCD
    archive_start = cd_pos - cd_offset         # its recorded offset is from the archive start
    out = []
    if not (0 <= cd_pos <= e and 0 <= archive_start <= cd_pos):
        out.append(_F(
            "unreferenced-bytes", "medium", rel,
            "a zip end-of-central-directory record is present but its structure does not "
            "line up; bytes may be concealed around it", offset=e, length=filesize - e))
        return out
    if archive_start > 0:
        prefix = raw[:archive_start]
        pre = sniff_magic(prefix)
        if _valid_image_carrier(prefix, pre):
            out.append(_F(
                "polyglot", "high", rel,
                "%d byte(s) precede a valid zip archive: the file is both %s and a zip "
                "(prepended-container polyglot)" % (archive_start, pre),
                offset=0, length=archive_start, detail=pre))
        else:
            out.append(_F(
                "polyglot", "medium", rel,
                "%d byte(s) precede a valid zip archive but the prefix format is unrecognized"
                % archive_start, offset=0, length=archive_start))
    if logical_end < filesize:
        tail = raw[logical_end:]
        payload = sniff_magic(tail)
        payload_offset = 0
        if payload not in _DANGEROUS:
            embedded = _embedded_dangerous(tail)
            if isinstance(embedded, tuple):
                payload_offset, payload = embedded
        if payload in _DANGEROUS and payload_offset:
            out.append(_F(
                "unreferenced-bytes", "medium", rel,
                "%d unreferenced byte(s) precede an appended payload"
                % payload_offset, offset=logical_end, length=payload_offset))
        start = logical_end + payload_offset
        out.append(_F(
            "unreferenced-bytes", "high" if payload in _DANGEROUS else "medium", rel,
            "%d byte(s) follow the zip end record (appended overlay%s)"
            % (filesize - start, ": %s" % payload if payload in _DANGEROUS else ""),
            offset=start, length=filesize - start,
            detail=payload if payload in _DANGEROUS else None))
    return out


def _png_logical_end(raw: bytes):
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    n = len(raw)
    pos = 8
    first = True
    saw_idat = False
    while pos + 8 <= n:
        length = int.from_bytes(raw[pos:pos + 4], "big")
        ctype = raw[pos + 4:pos + 8]
        nxt = pos + 8 + length + 4              # data + 4-byte CRC
        if nxt <= pos or nxt > n:
            return None
        data_end = pos + 8 + length
        expected_crc = int.from_bytes(raw[data_end:nxt], "big")
        if zlib.crc32(raw[pos + 4:data_end]) != expected_crc:
            return None
        if first and (ctype != b"IHDR" or length != 13):
            return None
        first = False
        if ctype == b"IDAT":
            saw_idat = True
        if ctype == b"IEND":
            return nxt if length == 0 and saw_idat else None
        pos = nxt
    return None


def _png_findings(rel: str, raw: bytes) -> list:
    logical_end = _png_logical_end(raw)
    if logical_end is None:
        return [_F(
            "unreferenced-bytes", "low", rel,
            "the PNG chunk structure is malformed; trailing bytes could not be verified",
            offset=8, length=max(0, len(raw) - 8))]
    if logical_end < len(raw):
        trail = len(raw) - logical_end
        ts = sniff_magic(raw[logical_end:])
        return [_F(
            "unreferenced-bytes", "high" if ts in _DANGEROUS else "medium", rel,
            "%d byte(s) follow the PNG IEND chunk (appended overlay%s)"
            % (trail, ": %s" % ts if ts else ""),
            offset=logical_end, length=trail, detail=ts)]
    return []


def _magic_mismatch(rel, declared, ext, detected, raw) -> list:
    if declared == "text" and _looks_textual(raw):
        return []
    severity, detail = None, detected
    if declared == "compiled":
        if detected in _DANGEROUS and detected not in _COMPILED_EXT_EXPECT.get(ext, ()):
            severity = "high"
    elif detected in _EXECUTABLE:
        severity = "high"
    elif detected in _ARCHIVE:
        if declared in {"text", "image", "svg", "pdf"}:
            severity = "high"
        elif declared == "archive" and detected != _ARCHIVE_EXT_EXPECT.get(ext):
            severity = "medium"
    elif detected in _IMAGE_FORMATS:
        if (declared in {"text", "svg", "pdf"}
                or declared == "image" and detected != _EXT_EXPECT.get(ext)):
            severity = "low"
        elif declared == "archive":
            severity = "medium"
    elif detected is None and declared in {"image", "archive"} and _looks_textual(raw):
        severity, detail = "medium", "text"
    if severity is None:
        return []
    return [_F("magic-mismatch", severity, rel,
               "declared %s (%s), but bytes are %s" % (declared, ext or "no extension", detail),
               offset=0, length=len(raw), detail=detail)]


def analyze_artifact(rel: str, kind: str, text, raw: bytes) -> list:
    if not raw:
        return []
    try:
        ext = os.path.splitext(re.sub(r"\.so(?:\.\d+)+$", ".so", rel.lower()))[1]
        declared = _declared(kind, ext, text)
        detected = sniff_magic(raw)
        out = _magic_mismatch(rel, declared, ext, detected, raw)

        if detected == "png":
            out += _png_findings(rel, raw)

        if b"PK\x05\x06" in raw or raw.startswith((b"PK\x03\x04", b"PK\x07\x08")):
            out += _zip_findings(rel, raw)

        if detected in _IMAGE_FORMATS or declared == "image":
            emb = _embedded_dangerous(raw)
            if emb is _CAPPED:
                out.append(_F(
                    "unreferenced-bytes", "medium", rel,
                    "an unusually large number of embedded archive-header signatures "
                    "(possible decoy tiling to evade payload detection)", detail="capped"))
            elif emb:
                off, kind_ = emb
                out = [f for f in out if not (
                    f.rule in ("unreferenced-bytes", "polyglot")
                    and f.offset is not None and f.offset > off
                    and f.evidence.get("detail") in (None, "text"))]
                already = any(
                    f.rule in ("unreferenced-bytes", "polyglot") and f.offset is not None
                    and f.offset <= off < f.offset + (f.length or 0)
                    and f.evidence.get("detail") == kind_ for f in out)
                if not already:
                    out.append(_F(
                        "unreferenced-bytes", "high", rel,
                        "a %s payload is embedded at offset %d in this image "
                        "(appended native or archive data)" % (kind_, off),
                        offset=off, length=len(raw) - off, detail=kind_))
        return out
    except Exception as exc:                    # fail closed: an analyzer bug is a finding
        return [_F("analyzer-error", "high", rel,
                   "byte analysis could not complete: %s" % type(exc).__name__)]


def analyze_package(parsed) -> list:
    findings = []
    for p in parsed.artifacts:
        findings.extend(analyze_artifact(p.rel, p.kind, p.text, getattr(p, "raw", None)))
    return dedupe_findings(findings)
