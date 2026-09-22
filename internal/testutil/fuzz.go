package testutil

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/traceforce/skill-xray/internal/findings"
)

// FuzzSep splits one fuzz input into per-file slices; a layout longer than the parts cycles.
var FuzzSep = []byte("\n@@@\n")

// FuzzLayout is the six-file package the config-lane fuzz targets share.
var FuzzLayout = []string{"SKILL.md", "hooks.json", ".mcp.json", "package.json", "requirements.txt", "pyproject.toml"}

// FuzzSlow is the per-input wall-time ceiling; a slower input is recorded as a hang.
const FuzzSlow = 10 * time.Second

// Hang fails an input that ran longer than FuzzSlow since start: `defer Hang(t, time.Now(), len(data))`.
func Hang(t testing.TB, start time.Time, n int) {
	if d := time.Since(start); d > FuzzSlow {
		t.Fatalf("hang: %s for %d bytes", d, n)
	}
}

// FuzzDir is one reusable package root per fuzz worker process: files are rewritten in place
// each iteration, so no mkdir or rmdir sits on the hot path. SKILLXRAY_FUZZ_TMP places it and
// "" is os.TempDir.
func FuzzDir(f *testing.F, subdirs ...string) string {
	dir, err := os.MkdirTemp(os.Getenv("SKILLXRAY_FUZZ_TMP"), "sx-fuzz-*")
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { os.RemoveAll(dir) })
	root := filepath.Join(dir, "pkg")
	for _, s := range append([]string{""}, subdirs...) {
		if err := os.MkdirAll(filepath.Join(root, s), 0o755); err != nil {
			f.Fatal(err)
		}
	}
	return root
}

// FuzzFiles writes layout[i] under root with part i of data (split on FuzzSep, cycling).
func FuzzFiles(t testing.TB, root string, layout []string, data []byte) {
	parts := bytes.Split(data, FuzzSep)
	for i, rel := range layout {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(rel)), parts[i%len(parts)], 0o644); err != nil {
			t.Skip(err) // the volume or Defender, not the scanner
		}
	}
}

// FuzzJoin builds a seed for FuzzFiles: one part per file.
func FuzzJoin(parts ...string) []byte {
	return []byte(strings.Join(parts, string(FuzzSep)))
}

// NoRecoveredPanic fails on the finding a lane emits in place of a panic it swallowed
// (checks.isolated, forensics.analyzeArtifact, obfuscation.scanArtifact, instruction.runEngine).
func NoRecoveredPanic(t testing.TB, fs []findings.Finding) {
	for _, f := range fs {
		if f.Rule == "check-error" || f.Rule == "analyzer-error" {
			t.Fatalf("recovered panic: %s %s: %s", f.Path, f.Rule, f.Message)
		}
	}
}
