package opengrep

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/testutil"
)

func hexSHA256(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// The embedded rule file matches its pinned SHA-256 byte for byte.
func TestEmbeddedRulesAreByteIdentical(t *testing.T) {
	assert.Equal(t, "f39f777ad115f0881ff2ffd7501836c9e36e6ec96b57c386c2760bd42a1bbd92", hexSHA256(Rules))
}

// tests/test_opengrep_runtime.py::test_platform_assets_are_pinned
func TestPlatformAssetsArePinned(t *testing.T) {
	a, err := platformAsset("Windows", "AMD64")
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(a.Name, ".exe"))
	a, err = platformAsset("Linux", "arm64")
	require.NoError(t, err)
	assert.Equal(t, "opengrep_manylinux_aarch64", a.Name)
	a, err = platformAsset("Darwin", "x86_64")
	require.NoError(t, err)
	assert.Equal(t, int64(48_310_144), a.Size)
	_, err = platformAsset("Plan9", "mips")
	require.ErrorAs(t, err, new(runtimeError))
	a, err = platformAsset("windows", "amd64") // Go spellings resolve too
	require.NoError(t, err)
	assert.Equal(t, release+"/opengrep_windows_x86.exe", a.url())
}

// tests/test_opengrep_runtime.py::test_verify_rejects_wrong_size_or_digest
func TestVerifyRejectsWrongSizeOrDigest(t *testing.T) {
	candidate := filepath.Join(t.TempDir(), "opengrep")
	require.NoError(t, os.WriteFile(candidate, []byte("wrong"), 0o644))
	_, err := verifyExecutable(candidate, &asset{"test", 5, strings.Repeat("0", 64)})
	require.ErrorAs(t, err, new(runtimeError))
	assert.Contains(t, err.Error(), "does not match pinned v1.29.0 asset")
	_, err = verifyExecutable(candidate, &asset{"test", 4, hexSHA256([]byte("wrong"))})
	require.ErrorAs(t, err, new(runtimeError))
	_, err = verifyExecutable(filepath.Join(t.TempDir(), "absent"), &asset{"test", 5, ""})
	require.ErrorAs(t, err, new(runtimeError))
	assert.Contains(t, err.Error(), "is unavailable")
	got, err := verifyExecutable(candidate, &asset{"test", 5, hexSHA256([]byte("wrong"))})
	require.NoError(t, err)
	assert.Equal(t, candidate, got)
}

// tests/test_opengrep_runtime.py::test_verified_binary_digest_is_cached_by_file_identity
func TestVerifiedBinaryDigestIsCachedByFileIdentity(t *testing.T) {
	candidate := filepath.Join(t.TempDir(), "opengrep")
	require.NoError(t, os.WriteFile(candidate, []byte("valid"), 0o644))
	a := &asset{"test", 5, hexSHA256([]byte("valid"))}
	clear(digests)
	calls := 0
	original := digestFile
	testutil.Swap(t, &digestFile, func(f *os.File) (string, error) { calls++; return original(f) })
	for range 2 {
		_, err := verifyExecutable(candidate, a)
		require.NoError(t, err)
	}
	assert.Equal(t, 1, calls)
}

// Concurrent verifications of one binary hash it once: the first holds the lock while it hashes
// and the others read its result.
func TestConcurrentVerificationsHashOnce(t *testing.T) {
	candidate := filepath.Join(t.TempDir(), "opengrep")
	require.NoError(t, os.WriteFile(candidate, []byte("valid"), 0o644))
	a := &asset{"test", 5, hexSHA256([]byte("valid"))}
	clear(digests)
	var calls atomic.Int32
	original := digestFile
	testutil.Swap(t, &digestFile, func(f *os.File) (string, error) { calls.Add(1); return original(f) })
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := verifyExecutable(candidate, a)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), calls.Load())
}

// A bare name is verified in the working directory and the run gets that absolute path, never
// a PATH lookup of the name.
func TestVerifiedPathIsAbsolute(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "opengrep"), []byte("valid"), 0o644))
	t.Chdir(dir)
	wd, err := os.Getwd()
	require.NoError(t, err)
	clear(digests)
	got, err := verifyExecutable("opengrep", &asset{"test", 5, hexSHA256([]byte("valid"))})
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(got))
	assert.Equal(t, filepath.Join(wd, "opengrep"), got)
}

// The cached digest is trusted only while the path names the same file: a replacement with the
// same size and modification time is hashed again and refused.
func TestCachedDigestRequiresTheSameFile(t *testing.T) {
	dir := t.TempDir()
	candidate := filepath.Join(dir, "opengrep")
	require.NoError(t, os.WriteFile(candidate, []byte("valid"), 0o644))
	a := &asset{"test", 5, hexSHA256([]byte("valid"))}
	clear(digests)
	calls := 0
	original := digestFile
	testutil.Swap(t, &digestFile, func(f *os.File) (string, error) { calls++; return original(f) })
	_, err := verifyExecutable(candidate, a)
	require.NoError(t, err)
	st, err := os.Stat(candidate)
	require.NoError(t, err)
	other := filepath.Join(dir, "other")
	require.NoError(t, os.WriteFile(other, []byte("wrong"), 0o644))
	require.NoError(t, os.Rename(other, candidate))
	require.NoError(t, os.Chtimes(candidate, st.ModTime(), st.ModTime()))
	_, err = verifyExecutable(candidate, a)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
	assert.Equal(t, 2, calls)
}

// The cached digest is dropped when the same file is rewritten in place with its size and its
// modification time kept: the write moves the change time, which is part of the key.
func TestCachedDigestDropsARewrittenFile(t *testing.T) {
	candidate := filepath.Join(t.TempDir(), "opengrep")
	require.NoError(t, os.WriteFile(candidate, []byte("valid"), 0o644))
	a := &asset{"test", 5, hexSHA256([]byte("valid"))}
	clear(digests)
	calls := 0
	original := digestFile
	testutil.Swap(t, &digestFile, func(f *os.File) (string, error) { calls++; return original(f) })
	_, err := verifyExecutable(candidate, a)
	require.NoError(t, err)
	st, err := os.Stat(candidate)
	require.NoError(t, err)
	// File times come from a clock that advances once per scheduler tick; this pause spans several
	// ticks on every platform, so the rewrite is stamped later than the file it replaces.
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, os.WriteFile(candidate, []byte("wrong"), 0o644))
	require.NoError(t, os.Chtimes(candidate, st.ModTime(), st.ModTime()))
	_, err = verifyExecutable(candidate, a)
	assert.ErrorContains(t, err, "does not match")
	assert.Equal(t, 2, calls)
}

// A world-writable file, or a world-writable directory without the sticky bit anywhere above the
// engine, on the path as named or as resolved, is refused.
func TestUntrustedLocationIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are synthesised on Windows")
	}
	shared := filepath.Join(t.TempDir(), "shared")
	dir := filepath.Join(shared, "locked")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	candidate := filepath.Join(dir, "opengrep")
	require.NoError(t, os.WriteFile(candidate, []byte("valid"), 0o644))
	a := &asset{"test", 5, hexSHA256([]byte("valid"))}
	clear(digests)
	_, err := verifyExecutable(candidate, a)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(shared, 0o777)) // the grandparent, not the engine's own directory
	_, err = verifyExecutable(candidate, a)
	assert.ErrorContains(t, err, "changed by another user")
	require.NoError(t, os.Chmod(shared, 0o777|os.ModeSticky))
	_, err = verifyExecutable(candidate, a)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(candidate, 0o666))
	_, err = verifyExecutable(candidate, a)
	assert.ErrorContains(t, err, "changed by another user")
	require.NoError(t, os.Chmod(candidate, 0o644))
	open := filepath.Join(t.TempDir(), "open")
	require.NoError(t, os.Mkdir(open, 0o755))
	require.NoError(t, os.Chmod(open, 0o777))
	link := filepath.Join(open, "opengrep")
	require.NoError(t, os.Symlink(candidate, link)) // the link's own directory is on the path as named
	_, err = verifyExecutable(link, a)
	assert.ErrorContains(t, err, "changed by another user")
	private := filepath.Join(t.TempDir(), "private")
	require.NoError(t, os.Mkdir(private, 0o755))
	link = filepath.Join(private, "opengrep")
	require.NoError(t, os.Symlink(candidate, link)) // a link has open permission bits; its owner is what counts
	_, err = verifyExecutable(link, a)
	require.NoError(t, err)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// serve is tests/test_opengrep_runtime.py::_Response: an in-memory download with Content-Length.
func serve(payload []byte, requested *[]string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		*requested = append(*requested, r.URL.String())
		return &http.Response{StatusCode: 200, ContentLength: int64(len(payload)),
			Body: io.NopCloser(strings.NewReader(string(payload))), Request: r}, nil
	})}
}

// tests/test_opengrep_runtime.py::test_install_is_atomic_and_verified
func TestInstallIsAtomicAndVerified(t *testing.T) {
	payload := []byte("verified-opengrep")
	a := asset{"opengrep-test", int64(len(payload)), hexSHA256(payload)}
	testutil.Swap(t, &hostAsset, func() (asset, error) { return a, nil })
	dir := t.TempDir()
	var requested []string
	installed, err := Install(dir, serve(payload, &requested))
	require.NoError(t, err)
	got, err := os.ReadFile(installed)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
	assert.Equal(t, []string{a.url()}, requested)
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".opengrep-*"))
	assert.Empty(t, leftovers)
	// A verified destination is returned without a second download.
	installed2, err := Install(dir, serve(payload, &requested))
	require.NoError(t, err)
	assert.Equal(t, installed, installed2)
	assert.Len(t, requested, 1)
}

// tests/test_opengrep_runtime.py::test_install_rejects_unverified_payload
func TestInstallRejectsUnverifiedPayload(t *testing.T) {
	testutil.Swap(t, &hostAsset, func() (asset, error) { return asset{"opengrep-test", 4, hexSHA256([]byte("good"))}, nil })
	dir := t.TempDir()
	var requested []string
	_, err := Install(dir, serve([]byte("evil"), &requested))
	require.ErrorAs(t, err, new(runtimeError))
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".opengrep-*"))
	assert.Empty(t, leftovers)
	assert.NoFileExists(t, CachedExecutable(dir))
}

// tests/test_opengrep_runtime.py::test_resolve_prefers_explicit_and_requires_verification
func TestResolvePrefersExplicitAndRequiresVerification(t *testing.T) {
	candidate := filepath.Join(t.TempDir(), "opengrep")
	require.NoError(t, os.WriteFile(candidate, []byte("x"), 0o644))
	_, err := Resolve(candidate)
	require.ErrorAs(t, err, new(runtimeError))
	assert.Contains(t, err.Error(), candidate) // the explicit path was verified, not the cache
	t.Setenv(envBinary, candidate)
	_, err = Resolve("")
	require.ErrorAs(t, err, new(runtimeError))
	assert.Contains(t, err.Error(), candidate)
}

func TestCachedExecutableUsesDefaultCacheDir(t *testing.T) {
	assert.Equal(t, defaultCacheDir(), filepath.Dir(CachedExecutable("")))
	assert.True(t, strings.HasSuffix(defaultCacheDir(), filepath.Join("skill-xray", "opengrep", Version)))
	assert.Equal(t, filepath.Dir(CachedExecutable("cache")), "cache")
}
