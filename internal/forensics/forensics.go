// Package forensics is analyze.py: offline byte forensics for SXV-035 (magic mismatch),
// SXV-036 (polyglot) and SXV-037 (unreferenced bytes) over each artifact's raw bytes.
package forensics

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/traceforce/skill-xray/internal/findings"
	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/pytext"
)

var vector = map[string]string{"magic-mismatch": "SXV-035", "polyglot": "SXV-036", "unreferenced-bytes": "SXV-037"}

// f is _F; a "" detail is Python None (no evidence).
func f(rule, severity, path, message string, offset, length *int, detail string) findings.Finding {
	out := findings.Finding{Vector: vector[rule], Rule: rule, Severity: severity, Path: path,
		Message: message, Offset: offset, Length: length}
	if detail != "" {
		out.Evidence = map[string]any{"detail": detail}
	}
	return out
}

// sigs is _SIGS: signatures by descending length, the listed order kept among equals.
var sigs = []struct {
	magic []byte
	name  string
}{
	{[]byte("\x89PNG\r\n\x1a\n"), "png"},
	{[]byte("7z\xbc\xaf\x27\x1c"), "sevenzip"}, {[]byte("GIF87a"), "gif"}, {[]byte("GIF89a"), "gif"},
	{[]byte("\x7fELF"), "elf"}, {[]byte("\xca\xfe\xba\xbe"), "macho_fat"},
	{[]byte("\xfe\xed\xfa\xce"), "macho"}, {[]byte("\xce\xfa\xed\xfe"), "macho"},
	{[]byte("\xfe\xed\xfa\xcf"), "macho"}, {[]byte("\xcf\xfa\xed\xfe"), "macho"},
	{[]byte("PK\x03\x04"), "zip"}, {[]byte("PK\x05\x06"), "zip"}, {[]byte("PK\x07\x08"), "zip"},
	{[]byte("\xff\xd8\xff"), "jpeg"},
	{[]byte("\x1f\x8b"), "gzip"}, {[]byte("MZ"), "pe"},
}

var (
	executable        = map[string]bool{"elf": true, "pe": true, "macho": true, "macho_fat": true}
	archive           = map[string]bool{"zip": true, "gzip": true, "sevenzip": true}
	imageFormats      = map[string]bool{"png": true, "jpeg": true, "gif": true}
	extExpect         = map[string]string{".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif"}
	archiveExtExpect  = map[string]string{".zip": "zip", ".whl": "zip", ".gz": "gzip", ".gzip": "gzip", ".tgz": "gzip", ".7z": "sevenzip"}
	compiledExtExpect = map[string]map[string]bool{".jar": pytext.Set("zip"), ".war": pytext.Set("zip"),
		".so": executable, ".node": executable, ".o": executable,
		".dylib": pytext.Set("macho", "macho_fat"), ".dll": pytext.Set("pe"), ".exe": pytext.Set("pe"), ".pyd": pytext.Set("pe")}
	textKinds = map[string]bool{"skill_manifest": true, "instruction": true, "doc": true, "agent_identity": true,
		"agent_config": true, "hooks_config": true, "mcp_config": true, "plugin_manifest": true, "app_manifest": true,
		"plugin_lock": true, "dep_manifest": true, "secret_material": true}
	compiledKinds = map[string]bool{"python_bytecode": true, "python_extension": true, "native_code": true}
	elfMagic      = []byte("\x7fELF")
	exeProbes     = []probe{{elfMagic, isELF, "elf"}, {[]byte("MZ"), isPE, "pe"},
		{[]byte("\xfe\xed\xfa\xce"), isMacho, "macho"}, {[]byte("\xfe\xed\xfa\xcf"), isMacho, "macho"},
		{[]byte("\xce\xfa\xed\xfe"), isMacho, "macho"}, {[]byte("\xcf\xfa\xed\xfe"), isMacho, "macho"}, {[]byte("\xca\xfe\xba\xbe"), isMacho, "macho"}}
	machoCPU   = map[uint32]bool{1: true, 6: true, 7: true, 10: true, 11: true, 12: true, 14: true, 15: true, 16: true, 18: true}
	gzipMagic  = []byte("\x1f\x8b")
	sevenMagic = []byte("7z\xbc\xaf\x27\x1c")
	eocdSig    = []byte("PK\x05\x06")
	soVersion  = regexp.MustCompile(`\.so(?:\.\p{Nd}+)+$`)
)

func dangerous(kind string) bool { return executable[kind] || archive[kind] }

const (
	maxGzipOutput     = 1048576
	maxArchiveHeader  = 262144
	maxEmbedCandidate = 64
	maxEOCDCandidates = 128
	isCapped          = -1 // Python's _CAPPED sentinel as an offset
)

// slice is Python raw[a:b]: clamped, never out of range.
func slice(raw []byte, a, b int) []byte {
	a, b = max(0, min(a, len(raw))), max(0, min(b, len(raw)))
	return raw[a:max(a, b)]
}

func isPE(raw []byte, i int) bool {
	if len(raw) < i+0x40 || !bytes.Equal(raw[i:i+2], []byte("MZ")) {
		return false
	}
	eLfanew := int(binary.LittleEndian.Uint32(raw[i+0x3c:]))
	off := i + eLfanew
	if eLfanew < 0x40 || off+24 > len(raw) || !bytes.Equal(raw[off:off+4], []byte("PE\x00\x00")) {
		return false
	}
	return off+24+int(binary.LittleEndian.Uint16(raw[off+20:])) <= len(raw)
}

func isELF(raw []byte, i int) bool {
	if !(bytes.Equal(slice(raw, i, i+4), elfMagic) && len(raw) >= i+7 &&
		(raw[i+4] == 1 || raw[i+4] == 2) && (raw[i+5] == 1 || raw[i+5] == 2) && raw[i+6] == 1) {
		return false
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if raw[i+5] == 2 {
		order = binary.BigEndian
	}
	headerSize, ehsizeOffset := 64, i+52
	if raw[i+4] == 1 {
		headerSize, ehsizeOffset = 52, i+40
	}
	return len(raw) >= i+headerSize && order.Uint32(raw[i+20:]) == 1 &&
		int(order.Uint16(raw[ehsizeOffset:])) == headerSize
}

func isMacho(raw []byte, i int) bool {
	magic := slice(raw, i, i+4)
	if len(magic) < 4 {
		return false
	}
	if bytes.Equal(magic, []byte("\xca\xfe\xba\xbe")) {
		if len(raw) < i+12 {
			return false
		}
		nfat := int(binary.BigEndian.Uint32(raw[i+4:]))
		if nfat < 1 || nfat > 32 || i+8+nfat*20 > len(raw) {
			return false
		}
		return machoCPU[binary.BigEndian.Uint32(raw[i+8:])&0x00ffffff]
	}
	order := binary.ByteOrder(binary.LittleEndian)
	switch string(magic) {
	case "\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf":
		order = binary.BigEndian
	case "\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe":
	default:
		return false
	}
	headerSize := 28
	if s := string(magic); s == "\xfe\xed\xfa\xcf" || s == "\xcf\xfa\xed\xfe" {
		headerSize = 32
	}
	if len(raw) < i+headerSize {
		return false
	}
	filetype := order.Uint32(raw[i+12:])
	return machoCPU[order.Uint32(raw[i+4:])&0x00ffffff] && 1 <= filetype && filetype <= 11
}

// find is bytes.find(sub, start): -1 when absent or start is past the end.
func find(raw, sub []byte, start int) int {
	if start > len(raw) {
		return -1
	}
	if k := bytes.Index(raw[start:], sub); k >= 0 {
		return k + start
	}
	return -1
}

// firstValidated is _first_validated: the first validated embedded signature after offset 0,
// or isCapped when the candidate budget runs out with occurrences remaining; 0 is None.
func firstValidated(raw, magic []byte, valid func([]byte, int) bool) int {
	k := find(raw, magic, 1)
	for tries := 0; k > 0; {
		if valid(raw, k) {
			return k
		}
		k = find(raw, magic, k+1)
		if tries++; tries >= maxEmbedCandidate && k > 0 {
			return isCapped
		}
	}
	return 0
}

type candidate struct {
	offset int
	kind   string
}

// earliest is _earliest: the first candidate with the smallest offset, kind "" when none.
func earliest(cs []candidate) candidate {
	var best candidate
	for _, c := range cs {
		if c.kind != "" && (best.kind == "" || c.offset < best.offset) {
			best = c
		}
	}
	return best
}

type probe struct {
	magic []byte
	valid func([]byte, int) bool
	kind  string
}

// collect runs firstValidated for each probe, separating hits from the capped flag.
func collect(raw []byte, probes []probe) (found []candidate, capped bool) {
	for _, p := range probes {
		switch off := firstValidated(raw, p.magic, p.valid); {
		case off == isCapped:
			capped = true
		case off > 0:
			found = append(found, candidate{off, p.kind})
		}
	}
	return found, capped
}

func isGzip(raw []byte, i int) bool {
	if !(len(raw) >= i+10 && bytes.Equal(raw[i:i+2], gzipMagic) && raw[i+2] == 8 && raw[i+3]&0xE0 == 0) {
		return false
	}
	r, err := gzip.NewReader(bytes.NewReader(raw[i:]))
	if err != nil {
		return false
	}
	r.Multistream(false)
	n, err := io.Copy(io.Discard, io.LimitReader(r, maxGzipOutput+1))
	return err == nil && n <= maxGzipOutput
}

func is7z(raw []byte, i int) bool {
	if len(raw) < i+32 || !bytes.Equal(raw[i:i+6], sevenMagic) ||
		crc32.ChecksumIEEE(raw[i+12:i+32]) != binary.LittleEndian.Uint32(raw[i+8:]) {
		return false
	}
	nhOff, nhSize, nhCRC := binary.LittleEndian.Uint64(raw[i+12:]), binary.LittleEndian.Uint64(raw[i+20:]), binary.LittleEndian.Uint32(raw[i+28:])
	base := uint64(i + 32)
	if nhSize == 0 || nhSize > maxArchiveHeader || base+nhOff+nhSize > uint64(len(raw)) || base+nhOff+nhSize < base {
		return false
	}
	return crc32.ChecksumIEEE(raw[base+nhOff:base+nhOff+nhSize]) == nhCRC
}

// embeddedDangerous is _embedded_dangerous: the earliest validated executable or archive after
// offset 0; capped is Python's _CAPPED when nothing was found but a scan gave up.
func embeddedDangerous(raw []byte) (candidate, bool) {
	found, capped := collect(raw, exeProbes)
	info, zipCapped := findEOCD(raw)
	if info != nil {
		if start := info.eocd - info.cdSize - info.cdOffset; start > 0 {
			found = append(found, candidate{start, "zip"})
		}
	}
	more, archiveCapped := collect(raw, []probe{{gzipMagic, isGzip, "gzip"}, {sevenMagic, is7z, "sevenzip"}})
	best := earliest(append(found, more...))
	return best, best.kind == "" && (capped || zipCapped || archiveCapped)
}

// sniffMagic is sniff_magic: the first validated signature the bytes start with, "" for none; a
// variable so a test can make the analyzer fail (test_analyzer_failure_is_recorded_not_raised).
var sniffMagic = func(raw []byte) string {
	for _, s := range sigs {
		if !bytes.HasPrefix(raw, s.magic) {
			continue
		}
		ok := true
		switch s.name {
		case "pe":
			ok = isPE(raw, 0)
		case "elf":
			ok = isELF(raw, 0)
		case "macho", "macho_fat":
			ok = isMacho(raw, 0)
		case "gzip":
			ok = isGzip(raw, 0)
		case "sevenzip":
			ok = is7z(raw, 0)
		case "zip":
			info, _ := findEOCD(raw)
			ok = info != nil
		}
		if ok {
			return s.name
		}
	}
	return ""
}

func looksTextual(raw []byte) bool {
	sample := slice(raw, 0, 512)
	if len(sample) == 0 || bytes.IndexByte(sample, 0) >= 0 || !utf8.Valid(sample) {
		return false
	}
	printable := 0
	for _, b := range sample {
		if b == 9 || b == 10 || b == 13 || (32 <= b && b <= 126) {
			printable++
		}
	}
	return float64(printable)/float64(len(sample)) > 0.85
}

func declared(kind, ext string, hasText bool) string {
	switch {
	case textKinds[kind] || strings.HasPrefix(kind, "script_") || (kind == "other" && hasText):
		return "text"
	case kind == "asset":
		return "image"
	case kind == "active_asset" && ext == ".pdf":
		return "pdf"
	case kind == "active_asset":
		return "svg"
	case kind == "nested_archive":
		return "archive"
	case compiledKinds[kind]:
		return "compiled"
	}
	return "other"
}

type eocd struct{ eocd, cdSize, cdOffset, commentLen int }

func eocdCandidate(raw []byte, e int) *eocd {
	if e+22 > len(raw) {
		return nil
	}
	u16 := func(i int) int { return int(binary.LittleEndian.Uint16(raw[i:])) }
	u32 := func(i int) int { return int(binary.LittleEndian.Uint32(raw[i:])) }
	disk, cdDisk, diskEntries, total := u16(e+4), u16(e+6), u16(e+8), u16(e+10)
	cdSize, cdOffset, commentLen := u32(e+12), u32(e+16), u16(e+20)
	if e+22+commentLen > len(raw) || disk != 0 || cdDisk != 0 || diskEntries != total {
		return nil
	}
	if total == 0 {
		if cdSize != 0 || cdOffset != 0 {
			return nil
		}
		if e > 0 {
			prefix, kind := raw[:e], ""
			for _, s := range sigs {
				if imageFormats[s.name] && bytes.HasPrefix(prefix, s.magic) {
					kind = s.name
					break
				}
			}
			if !validImageCarrier(prefix, kind) {
				return nil
			}
		}
		return &eocd{e, 0, 0, commentLen}
	}
	if total == 0xffff || cdSize == 0xffffffff || cdOffset == 0xffffffff {
		return nil
	}
	cdPos := e - cdSize
	archiveStart := cdPos - cdOffset
	if cdPos < 0 || archiveStart < 0 {
		return nil
	}
	pos := cdPos
	for range total {
		if pos+46 > e || !bytes.Equal(raw[pos:pos+4], []byte("PK\x01\x02")) {
			return nil
		}
		nameLen, extraLen, entryCommentLen, compressedSize := u16(pos+28), u16(pos+30), u16(pos+32), u32(pos+20)
		if nameLen == 0 || u16(pos+34) != 0 {
			return nil
		}
		localPos := archiveStart + u32(pos+42)
		if localPos < archiveStart || localPos+30 > cdPos || !bytes.Equal(raw[localPos:localPos+4], []byte("PK\x03\x04")) {
			return nil
		}
		localNameLen, localExtraLen := u16(localPos+26), u16(localPos+28)
		dataPos := localPos + 30 + localNameLen + localExtraLen
		if !bytes.Equal(slice(raw, pos+46, pos+46+nameLen), slice(raw, localPos+30, localPos+30+localNameLen)) ||
			dataPos+compressedSize > cdPos {
			return nil
		}
		pos += 46 + nameLen + extraLen + entryCommentLen
		if pos > e {
			return nil
		}
	}
	if pos != e {
		return nil
	}
	return &eocd{e, cdSize, cdOffset, commentLen}
}

// findEOCD is _find_eocd: the first valid end-of-central-directory record scanning backwards,
// or capped when 128 candidates failed and more remain.
func findEOCD(raw []byte) (*eocd, bool) {
	before := len(raw)
	for range maxEOCDCandidates {
		e := bytes.LastIndex(raw[:before], eocdSig)
		if e < 0 {
			return nil, false
		}
		if info := eocdCandidate(raw, e); info != nil {
			return info, false
		}
		before = e
	}
	return nil, bytes.LastIndex(raw[:before], eocdSig) >= 0
}

func validGIF(raw []byte) bool {
	if len(raw) < 14 || !(bytes.HasPrefix(raw, []byte("GIF87a")) || bytes.HasPrefix(raw, []byte("GIF89a"))) {
		return false
	}
	pos := 13
	if raw[10]&0x80 != 0 {
		pos += 3 * (1 << ((raw[10] & 7) + 1))
	}
	for pos < len(raw) {
		marker := raw[pos]
		pos++
		switch marker {
		case 0x3B:
			return pos == len(raw)
		case 0x2C:
			if pos+9 > len(raw) {
				return false
			}
			packed := raw[pos+8]
			pos += 9
			if packed&0x80 != 0 {
				pos += 3 * (1 << ((packed & 7) + 1))
			}
			if pos >= len(raw) {
				return false
			}
			pos++
		case 0x21:
			if pos >= len(raw) {
				return false
			}
			pos++
		default:
			return false
		}
		terminated := false
		for pos < len(raw) {
			size := int(raw[pos])
			pos++
			if size == 0 {
				terminated = true
				break
			}
			pos += size
			if pos > len(raw) {
				return false
			}
		}
		if !terminated {
			return false
		}
	}
	return false
}

func validJPEG(raw []byte) bool {
	if !bytes.HasPrefix(raw, []byte("\xff\xd8")) {
		return false
	}
	pos, sawFrame, sawScan := 2, false, false
	for pos+1 < len(raw) {
		if raw[pos] != 0xff {
			if !sawScan {
				return false
			}
			pos++
			continue
		}
		for pos < len(raw) && raw[pos] == 0xff {
			pos++
		}
		if pos >= len(raw) {
			return false
		}
		marker := raw[pos]
		pos++
		switch {
		case marker == 0x00 && sawScan:
			continue
		case marker == 0xD9:
			return sawFrame && sawScan && pos == len(raw)
		case 0xD0 <= marker && marker < 0xD8, marker == 0x01:
			continue
		}
		if pos+2 > len(raw) {
			return false
		}
		size := int(binary.BigEndian.Uint16(raw[pos:]))
		if size < 2 || pos+size > len(raw) {
			return false
		}
		sawFrame = sawFrame || (0xC0 <= marker && marker < 0xD0 && marker != 0xC4 && marker != 0xC8 && marker != 0xCC)
		sawScan = sawScan || marker == 0xDA
		pos += size
	}
	return false
}

func validImageCarrier(raw []byte, kind string) bool {
	switch kind {
	case "png":
		return pngLogicalEnd(raw) == len(raw)
	case "gif":
		return validGIF(raw)
	case "jpeg":
		return validJPEG(raw)
	}
	return false
}

func zipFindings(rel string, raw []byte) []findings.Finding {
	info, capped := findEOCD(raw)
	if capped {
		return []findings.Finding{f("unreferenced-bytes", "medium", rel,
			"an unusually large number of ZIP end-record signatures prevented complete validation", nil, nil, "capped")}
	}
	if info == nil {
		if p := string(slice(raw, 0, 4)); p == "PK\x03\x04" || p == "PK\x05\x06" || p == "PK\x07\x08" {
			return []findings.Finding{f("unreferenced-bytes", "low", rel,
				"the ZIP structure is malformed or unsupported; trailing bytes could not be verified",
				findings.Int(0), findings.Int(len(raw)), "")}
		}
		return nil
	}
	e, filesize := info.eocd, len(raw)
	logicalEnd := e + 22 + info.commentLen
	cdPos := e - info.cdSize
	archiveStart := cdPos - info.cdOffset
	var out []findings.Finding
	if !(0 <= cdPos && cdPos <= e && 0 <= archiveStart && archiveStart <= cdPos) {
		return append(out, f("unreferenced-bytes", "medium", rel,
			"a zip end-of-central-directory record is present but its structure does not line up; bytes may be concealed around it",
			findings.Int(e), findings.Int(filesize-e), ""))
	}
	if archiveStart > 0 {
		prefix := raw[:archiveStart]
		pre := sniffMagic(prefix)
		if validImageCarrier(prefix, pre) {
			out = append(out, f("polyglot", "high", rel,
				fmt.Sprintf("%d byte(s) precede a valid zip archive: the file is both %s and a zip (prepended-container polyglot)", archiveStart, pre),
				findings.Int(0), findings.Int(archiveStart), pre))
		} else {
			out = append(out, f("polyglot", "medium", rel,
				fmt.Sprintf("%d byte(s) precede a valid zip archive but the prefix format is unrecognized", archiveStart),
				findings.Int(0), findings.Int(archiveStart), ""))
		}
	}
	if logicalEnd < filesize {
		tail := raw[logicalEnd:]
		payload, payloadOffset := sniffMagic(tail), 0
		if !dangerous(payload) {
			if emb, _ := embeddedDangerous(tail); emb.kind != "" {
				payloadOffset, payload = emb.offset, emb.kind
			}
		}
		if dangerous(payload) && payloadOffset != 0 {
			out = append(out, f("unreferenced-bytes", "medium", rel,
				fmt.Sprintf("%d unreferenced byte(s) precede an appended payload", payloadOffset),
				findings.Int(logicalEnd), findings.Int(payloadOffset), ""))
		}
		start := logicalEnd + payloadOffset
		severity, suffix, detail := "medium", "", ""
		if dangerous(payload) {
			severity, suffix, detail = "high", ": "+payload, payload
		}
		out = append(out, f("unreferenced-bytes", severity, rel,
			fmt.Sprintf("%d byte(s) follow the zip end record (appended overlay%s)", filesize-start, suffix),
			findings.Int(start), findings.Int(filesize-start), detail))
	}
	return out
}

// pngLogicalEnd is _png_logical_end: the byte after a CRC-valid chunk walk ending in a
// zero-length IEND after an IDAT, or -1 (Python None).
func pngLogicalEnd(raw []byte) int {
	if !bytes.HasPrefix(raw, []byte("\x89PNG\r\n\x1a\n")) {
		return -1
	}
	n, pos, first, sawIDAT := len(raw), 8, true, false
	for pos+8 <= n {
		length := int(binary.BigEndian.Uint32(raw[pos:]))
		ctype := raw[pos+4 : pos+8]
		nxt := pos + 8 + length + 4
		if nxt <= pos || nxt > n {
			return -1
		}
		dataEnd := pos + 8 + length
		if crc32.ChecksumIEEE(raw[pos+4:dataEnd]) != binary.BigEndian.Uint32(raw[dataEnd:]) {
			return -1
		}
		if first && (string(ctype) != "IHDR" || length != 13) {
			return -1
		}
		first = false
		if string(ctype) == "IDAT" {
			sawIDAT = true
		}
		if string(ctype) == "IEND" {
			if length == 0 && sawIDAT {
				return nxt
			}
			return -1
		}
		pos = nxt
	}
	return -1
}

func pngFindings(rel string, raw []byte) []findings.Finding {
	logicalEnd := pngLogicalEnd(raw)
	if logicalEnd < 0 {
		return []findings.Finding{f("unreferenced-bytes", "low", rel,
			"the PNG chunk structure is malformed; trailing bytes could not be verified",
			findings.Int(8), findings.Int(max(0, len(raw)-8)), "")}
	}
	if logicalEnd < len(raw) {
		trail := len(raw) - logicalEnd
		ts := sniffMagic(raw[logicalEnd:])
		severity, suffix := "medium", ""
		if dangerous(ts) {
			severity = "high"
		}
		if ts != "" {
			suffix = ": " + ts
		}
		return []findings.Finding{f("unreferenced-bytes", severity, rel,
			fmt.Sprintf("%d byte(s) follow the PNG IEND chunk (appended overlay%s)", trail, suffix),
			findings.Int(logicalEnd), findings.Int(trail), ts)}
	}
	return nil
}

func magicMismatch(rel, declared, ext, detected string, raw []byte) []findings.Finding {
	if declared == "text" && looksTextual(raw) {
		return nil
	}
	severity, detail := "", detected
	switch {
	case declared == "compiled":
		if dangerous(detected) && !compiledExtExpect[ext][detected] {
			severity = "high"
		}
	case executable[detected]:
		severity = "high"
	case archive[detected]:
		if declared == "text" || declared == "image" || declared == "svg" || declared == "pdf" {
			severity = "high"
		} else if declared == "archive" && detected != archiveExtExpect[ext] {
			severity = "medium"
		}
	case imageFormats[detected]:
		if declared == "text" || declared == "svg" || declared == "pdf" || (declared == "image" && detected != extExpect[ext]) {
			severity = "low"
		} else if declared == "archive" {
			severity = "medium"
		}
	case detected == "" && (declared == "image" || declared == "archive") && looksTextual(raw):
		severity, detail = "medium", "text"
	}
	if severity == "" {
		return nil
	}
	shown := ext
	if shown == "" {
		shown = "no extension"
	}
	return []findings.Finding{f("magic-mismatch", severity, rel,
		fmt.Sprintf("declared %s (%s), but bytes are %s", declared, shown, detail),
		findings.Int(0), findings.Int(len(raw)), detail)}
}

// analyzeArtifact is analyze_artifact; hasText is Python `text is not None`. A panic is the
// fail-closed analyzer-error finding, as the Python `except Exception` is.
func analyzeArtifact(rel, kind string, hasText bool, raw []byte) (out []findings.Finding) {
	if len(raw) == 0 {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			out = []findings.Finding{f("analyzer-error", "high", rel, "byte analysis could not complete: RuntimeError", nil, nil, "")}
		}
	}()
	_, ext := pytext.SplitExt(soVersion.ReplaceAllString(pytext.Lower(rel), ".so"))
	decl := declared(kind, ext, hasText)
	detected := sniffMagic(raw)
	out = magicMismatch(rel, decl, ext, detected, raw)
	if detected == "png" {
		out = append(out, pngFindings(rel, raw)...)
	}
	if bytes.Contains(raw, eocdSig) || bytes.HasPrefix(raw, []byte("PK\x03\x04")) || bytes.HasPrefix(raw, []byte("PK\x07\x08")) {
		out = append(out, zipFindings(rel, raw)...)
	}
	if imageFormats[detected] || decl == "image" {
		emb, capped := embeddedDangerous(raw)
		switch {
		case capped:
			out = append(out, f("unreferenced-bytes", "medium", rel,
				"an unusually large number of embedded archive-header signatures (possible decoy tiling to evade payload detection)", nil, nil, "capped"))
		case emb.kind != "":
			off := emb.offset
			kept, already := out[:0], false
			for _, x := range out {
				detail, _ := x.Evidence["detail"].(string)
				span := x.Rule == "unreferenced-bytes" || x.Rule == "polyglot"
				if span && x.Offset != nil && *x.Offset > off && (detail == "" || detail == "text") {
					continue
				}
				length := 0
				if x.Length != nil {
					length = *x.Length
				}
				if span && x.Offset != nil && *x.Offset <= off && off < *x.Offset+length && detail == emb.kind {
					already = true
				}
				kept = append(kept, x)
			}
			out = kept
			if !already {
				out = append(out, f("unreferenced-bytes", "high", rel,
					fmt.Sprintf("a %s payload is embedded at offset %d in this image (appended native or archive data)", emb.kind, off),
					findings.Int(off), findings.Int(len(raw)-off), emb.kind))
			}
		}
	}
	return out
}

// AnalyzePackage is analyze_package: every artifact's forensics, deduplicated.
func AnalyzePackage(p *parse.Package) []findings.Finding {
	var out []findings.Finding
	for _, a := range p.Artifacts {
		out = append(out, analyzeArtifact(a.Rel, a.Kind, a.Text != nil, a.Raw)...)
	}
	return findings.Dedupe(out)
}
