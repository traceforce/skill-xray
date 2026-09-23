package opengrep

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

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
	testutil.Swap(t, &digestFile, func(path string) (string, error) { calls++; return original(path) })
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
	testutil.Swap(t, &digestFile, func(path string) (string, error) { calls.Add(1); return original(path) })
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
