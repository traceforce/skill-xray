package ingest

// Port of tests/test_resolve.py (44 functions, 52 cases). Directory, file and zip
// run fully offline; the URL and git safety checks go through the seams.

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/testutil"
)

type member struct{ name, data string }

func writeZip(t *testing.T, p string, members []member) {
	f, err := os.Create(p)
	require.NoError(t, err)
	zw := zip.NewWriter(f)
	for _, m := range members {
		w, err := zw.Create(m.name)
		require.NoError(t, err)
		_, err = w.Write([]byte(m.data))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())
}

func isUnsafe(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, errors.As(err, &unsafeInputError{}), "want unsafeInputError, got %T: %v", err, err)
}

func isLimit(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, errors.As(err, &ingestLimitExceededError{}), "want ingestLimitExceededError, got %T: %v", err, err)
}

// resolveOK resolves and registers the cleanup.
func resolveOK(t *testing.T, target string) Resolved {
	t.Helper()
	r, cleanup, err := Resolve(target)
	require.NoError(t, err)
	t.Cleanup(cleanup)
	return r
}

func addrs(ips ...string) func(context.Context, string) ([]netip.Addr, error) {
	return func(context.Context, string) ([]netip.Addr, error) {
		out := []netip.Addr{}
		for _, ip := range ips {
			out = append(out, netip.MustParseAddr(ip))
		}
		return out, nil
	}
}

var exampleIP = netip.MustParseAddr("93.184.216.34")

func fakeHost(target string) func(string, time.Time) (urlTarget, error) {
	return func(string, time.Time) (urlTarget, error) {
		return urlTarget{"example.com", 443, target, exampleIP}, nil
	}
}

// serve replaces dialTLS with a conn that answers any request with response.
func serve(t *testing.T, response string) {
	testutil.Swap(t, &dialTLS, func(context.Context, netip.Addr, int, string) (net.Conn, error) {
		return &fakeConn{chunks: []chunk{{data: []byte(response)}}}, nil
	})
}

// test_directory_is_used_in_place
func TestDirectoryIsUsedInPlace(t *testing.T) {
	root := testutil.MakePackage(t, map[string]string{"SKILL.md": manifest})
	r := resolveOK(t, root)
	assert.Equal(t, "directory", r.Kind)
	assert.Equal(t, root, r.Root)
}

// test_single_file_is_wrapped_into_a_package
func TestSingleFileIsWrappedIntoAPackage(t *testing.T) {
	f := filepath.Join(t.TempDir(), "SKILL.md")
	writeFile(t, f, manifest)
	r := resolveOK(t, f)
	assert.Equal(t, "file", r.Kind)
	assert.Contains(t, rels(BuildPackage(r.Root)), "SKILL.md")
}

// test_single_file_symlink_is_refused
func openRO(t *testing.T, p string) *os.File {
	t.Helper()
	f, err := os.Open(p)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

// The single-file path reads only through the handle it checked: once opened, the target can be
// removed or replaced and every later read still sees the checked bytes. A directory or a link in
// the file's place is refused at the open.
func TestSingleFileReadsUseTheCheckedHandle(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "skill.md")
	require.NoError(t, os.WriteFile(p, []byte("# a\n"), 0o644))
	f, err := openTarget(p)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, os.Remove(p))
	_ = os.WriteFile(p, []byte("# swapped\n"), 0o644) // may fail while a delete is pending on Windows
	assert.False(t, looksLikeZip(f))
	assert.False(t, isUnsupportedArchive(f, p))
	tmp, err := wrapSingleFile(f, p)
	require.NoError(t, err)
	defer rmtree(tmp)
	copied, err := os.ReadFile(filepath.Join(tmp, "skill.md"))
	require.NoError(t, err)
	assert.Equal(t, "# a\n", string(copied))

	d := filepath.Join(dir, "dir.md")
	require.NoError(t, os.Mkdir(d, 0o755))
	_, err = openTarget(d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
	target := filepath.Join(dir, "target.md")
	require.NoError(t, os.WriteFile(target, []byte("# b\n"), 0o644))
	link := filepath.Join(dir, "link.md")
	testutil.SymlinkOrSkip(t, target, link)
	_, err = openTarget(link)
	require.Error(t, err)
}

func TestSingleFileSymlinkIsRefused(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "secret"), "SENSITIVE")
	testutil.SymlinkOrSkip(t, filepath.Join(tmp, "secret"), filepath.Join(tmp, "SKILL.md"))
	_, _, err := Resolve(filepath.Join(tmp, "SKILL.md"))
	isUnsafe(t, err)
}

// test_single_file_symlink_to_zip_is_refused
func TestSingleFileSymlinkToZipIsRefused(t *testing.T) {
	tmp := t.TempDir()
	writeZip(t, filepath.Join(tmp, "real.zip"), []member{{"SKILL.md", manifest}})
	testutil.SymlinkOrSkip(t, filepath.Join(tmp, "real.zip"), filepath.Join(tmp, "link.zip"))
	_, _, err := Resolve(filepath.Join(tmp, "link.zip"))
	isUnsafe(t, err)
}

// test_single_file_size_cap_is_enforced
func TestSingleFileSizeCapIsEnforced(t *testing.T) {
	testutil.Swap(t, &ingestMaxBytes, 100)
	f := filepath.Join(t.TempDir(), "big.txt")
	writeFile(t, f, strings.Repeat("x", 5000))
	_, _, err := Resolve(f)
	isLimit(t, err)
}

// test_single_file_temp_dir_is_removed_on_exit
func TestSingleFileTempDirIsRemovedOnExit(t *testing.T) {
	f := filepath.Join(t.TempDir(), "SKILL.md")
	writeFile(t, f, manifest)
	r, cleanup, err := Resolve(f)
	require.NoError(t, err)
	assert.DirExists(t, r.Root)
	cleanup()
	assert.NoDirExists(t, r.Root)
}

// test_missing_target_is_a_clear_error
func TestMissingTargetIsAClearError(t *testing.T) {
	_, _, err := Resolve("/no/such/target/xyz")
	isUnsafe(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

// test_local_dir_named_dot_git_is_treated_as_directory
func TestLocalDirNamedDotGitIsTreatedAsDirectory(t *testing.T) {
	pkg := testutil.MakePackage(t, map[string]string{"SKILL.md": manifest})
	root := filepath.Join(filepath.Dir(pkg), "foo.git")
	require.NoError(t, os.Rename(pkg, root))
	assert.Equal(t, "directory", resolveOK(t, root).Kind)
}

// test_zip_is_extracted_and_walkable
func TestZipIsExtractedAndWalkable(t *testing.T) {
	z := filepath.Join(t.TempDir(), "skill.zip")
	writeZip(t, z, []member{{"SKILL.md", manifest}, {"scripts/run.py", "print(1)\n"}})
	r := resolveOK(t, z)
	assert.Equal(t, "zip", r.Kind)
	assert.Equal(t, "skill", r.Name)
	got := rels(BuildPackage(r.Root))
	assert.Contains(t, got, "SKILL.md")
	assert.Contains(t, got, "scripts/run.py")
}

const eocd = "PK\x05\x06" + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

// test_zip_trailer_does_not_evade_as_empty_archive
func TestZipTrailerDoesNotEvadeAsEmptyArchive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "evil.md")
	writeFile(t, p, "---\nname: evil\n---\nbody\n"+eocd)
	r := resolveOK(t, p)
	assert.Equal(t, "file", r.Kind)
	assert.Contains(t, rels(BuildPackage(r.Root)), "evil.md")
}

// test_zip_prefixed_magic_with_empty_eocd_does_not_evade
func TestZipPrefixedMagicWithEmptyEocdDoesNotEvade(t *testing.T) {
	p := filepath.Join(t.TempDir(), "evil.md")
	writeFile(t, p, "PK\x03\x04---\nname: evil\n---\nbody\n"+eocd)
	assert.False(t, looksLikeZip(openRO(t, p)))
	r := resolveOK(t, p)
	assert.Equal(t, "file", r.Kind)
	assert.NotEmpty(t, BuildPackage(r.Root).Artifacts)
}

// test_zip_root_only_member_does_not_evade
func TestZipRootOnlyMemberDoesNotEvade(t *testing.T) {
	z := filepath.Join(t.TempDir(), "dot.zip")
	writeZip(t, z, []member{{".", "payload"}})
	assert.False(t, looksLikeZip(openRO(t, z)))
	assert.Equal(t, "file", resolveOK(t, z).Kind)
}

// test_url_trailer_does_not_evade_as_empty_archive
func TestURLTrailerDoesNotEvadeAsEmptyArchive(t *testing.T) {
	blob := "---\nname: evil\n---\nbody\n" + eocd
	testutil.Swap(t, &checkURLHost, fakeHost("/skill.zip"))
	serve(t, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"+blob)
	r := resolveOK(t, "https://example.com/skill.zip")
	assert.Equal(t, "url", r.Kind)
	assert.Contains(t, rels(BuildPackage(r.Root)), "skill.zip")
}

// test_zip_member_count_cap
func TestZipMemberCountCap(t *testing.T) {
	testutil.Swap(t, &ingestMaxZipMembers, 2)
	z := filepath.Join(t.TempDir(), "many.zip")
	writeZip(t, z, []member{{"a", "1"}, {"b", "2"}, {"c", "3"}})
	_, _, err := Resolve(z)
	isLimit(t, err)
}

// test_zip_uncompressed_byte_cap
func TestZipUncompressedByteCap(t *testing.T) {
	testutil.Swap(t, &ingestMaxBytes, 1000)
	z := filepath.Join(t.TempDir(), "big.zip")
	writeZip(t, z, []member{{"SKILL.md", strings.Repeat("x", 5000)}})
	_, _, err := Resolve(z)
	isLimit(t, err)
}

// test_zip_slip_is_rejected
func TestZipSlipIsRejected(t *testing.T) {
	z := filepath.Join(t.TempDir(), "slip.zip")
	writeZip(t, z, []member{{"../escape.txt", "pwned"}})
	_, _, err := Resolve(z)
	isUnsafe(t, err)
}

// test_zip_backslash_slip_is_rejected_portably
func TestZipBackslashSlipIsRejectedPortably(t *testing.T) {
	z := filepath.Join(t.TempDir(), "backslash-slip.zip")
	writeZip(t, z, []member{{"..\\escape.txt", "pwned"}})
	_, _, err := Resolve(z)
	isUnsafe(t, err)
}

// test_zip_portable_path_collisions_are_rejected
func TestZipPortablePathCollisionsAreRejected(t *testing.T) {
	for _, names := range [][2]string{
		{"Skill.md", "SKILL.md"},
		{"café.md", "café.md"},
		{"name", "name."},
	} {
		t.Run(names[0], func(t *testing.T) {
			z := filepath.Join(t.TempDir(), "collision.zip")
			writeZip(t, z, []member{{names[0], "one"}, {names[1], "two"}})
			_, _, err := Resolve(z)
			isUnsafe(t, err)
		})
	}
}

// test_zip_symlink_member_is_rejected
func TestZipSymlinkMemberIsRejected(t *testing.T) {
	z := filepath.Join(t.TempDir(), "link.zip")
	f, err := os.Create(z)
	require.NoError(t, err)
	zw := zip.NewWriter(f)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "link", ExternalAttrs: (0o120777 & 0xFFFF) << 16})
	require.NoError(t, err)
	_, err = w.Write([]byte("/etc/passwd"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())
	_, _, err = Resolve(z)
	isUnsafe(t, err)
}

// test_zip_degenerate_member_does_not_crash
func TestZipDegenerateMemberDoesNotCrash(t *testing.T) {
	z := filepath.Join(t.TempDir(), "deg.zip")
	writeZip(t, z, []member{{"SKILL.md", manifest}, {".", ""}})
	assert.Equal(t, "zip", resolveOK(t, z).Kind)
}

// test_url_ssrf_blocks_non_public
func TestURLSsrfBlocksNonPublic(t *testing.T) {
	for _, u := range []string{
		"https://127.0.0.1/x", "https://localhost/x", "https://10.0.0.5/x",
		"https://169.254.169.254/latest/meta-data", "https://[::1]/x",
		"https://100.64.0.1/x", // CGNAT: not is_private, but not public either
	} {
		t.Run(u, func(t *testing.T) {
			_, err := checkURLHost(u, time.Time{})
			isUnsafe(t, err)
		})
	}
}

// test_url_rejects_non_https_scheme
func TestURLRejectsNonHttpsScheme(t *testing.T) {
	for _, bad := range []string{"ftp://example.com/x", "http://example.com/x"} {
		_, err := checkURLHost(bad, time.Time{})
		isUnsafe(t, err)
	}
}

// test_url_invalid_port_is_refused
func TestURLInvalidPortIsRefused(t *testing.T) {
	_, err := checkURLHost("https://example.com:99999/x", time.Time{})
	isUnsafe(t, err)
}

// test_url_with_embedded_credentials_is_refused
func TestURLWithEmbeddedCredentialsIsRefused(t *testing.T) {
	_, err := checkURLHost("https://user:pass@example.com/x", time.Time{})
	isUnsafe(t, err)
}

// test_malformed_url_error_does_not_echo_the_url
func TestMalformedURLErrorDoesNotEchoTheURL(t *testing.T) {
	_, err := checkURLHost("https://[::1/secret-token", time.Time{})
	isUnsafe(t, err)
	assert.NotContains(t, err.Error(), "secret-token")
}

// test_url_public_host_passes_the_check
func TestURLPublicHostPassesTheCheck(t *testing.T) {
	testutil.Swap(t, &lookupIP, addrs("93.184.216.34"))
	got, err := checkURLHost("https://example.com/skill.zip", time.Time{})
	require.NoError(t, err)
	assert.Equal(t, urlTarget{"example.com", 443, "/skill.zip", exampleIP}, got)
}

// test_url_download_pins_and_caps_size
func TestURLDownloadPinsAndCapsSize(t *testing.T) {
	testutil.Swap(t, &ingestMaxBytes, 1000)
	testutil.Swap(t, &checkURLHost, fakeHost("/x"))
	serve(t, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"+strings.Repeat("x", 5000))
	_, _, err := Resolve("https://example.com/big.bin")
	isLimit(t, err)
}

// test_git_requires_https
func TestGitRequiresHttps(t *testing.T) {
	testutil.Swap(t, &checkURLHost, func(string, time.Time) (urlTarget, error) { return urlTarget{}, nil })
	require.NoError(t, checkGitRemote("https://github.com/u/r.git"))
	for _, bad := range []string{"git@github.com:u/r.git", "git://host/r.git", "ssh://h/r.git", "http://h/r.git", "/local/path/repo.git", "repo.git"} {
		isUnsafe(t, checkGitRemote(bad))
	}
}

// test_git_ssrf_blocks_internal_host
func TestGitSsrfBlocksInternalHost(t *testing.T) {
	testutil.Swap(t, &lookupIP, addrs("10.0.0.5"))
	isUnsafe(t, checkGitRemote("https://internal.example.com/r.git"))
}

// test_git_missing_binary_is_a_clear_error
func TestGitMissingBinaryIsAClearError(t *testing.T) {
	testutil.Swap(t, &checkGitRemote, func(string) error { return nil })
	testutil.Swap(t, &runGit, func(context.Context, []string, []string) ([]byte, error) {
		return nil, &exec.Error{Name: "git", Err: exec.ErrNotFound}
	})
	_, _, err := gitClone("https://github.com/u/r.git")
	isUnsafe(t, err)
	assert.Equal(t, "git is not installed", err.Error())
}

func localRepo(t *testing.T, name string) string {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	src := filepath.Join(t.TempDir(), name)
	writeFile(t, filepath.Join(src, "SKILL.md"), manifest)
	env := append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e")
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}, {"commit", "-qm", "init"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = src
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
	return src
}

// test_git_clone_success_from_local_repo
func TestGitCloneSuccessFromLocalRepo(t *testing.T) {
	src := localRepo(t, "src")
	testutil.Swap(t, &checkGitRemote, func(string) error { return nil })
	root, _, err := gitClone(src)
	require.NoError(t, err)
	t.Cleanup(func() { rmtree(root) })
	assert.FileExists(t, filepath.Join(root, "SKILL.md"))
}

// test_git_clone_strips_uppercase_git_suffix
func TestGitCloneStripsUppercaseGitSuffix(t *testing.T) {
	src := localRepo(t, "myrepo.GIT")
	testutil.Swap(t, &checkGitRemote, func(string) error { return nil })
	root, name, err := gitClone(src)
	require.NoError(t, err)
	t.Cleanup(func() { rmtree(root) })
	assert.Equal(t, "myrepo", name)
}

// test_rmtree_does_not_follow_symlink_to_chmod_target
func TestRmtreeDoesNotFollowSymlinkToChmodTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics")
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "outside.txt")
	writeFile(t, target, "x")
	require.NoError(t, os.Chmod(target, 0o644))
	sub := filepath.Join(tmp, "tree", "sub")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	testutil.SymlinkOrSkip(t, target, filepath.Join(sub, "link"))
	require.NoError(t, os.Chmod(sub, 0o500))
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
	rmtree(filepath.Join(tmp, "tree"))
	st, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), st.Mode().Perm())
}

// test_malformed_zip_fails_closed
func TestMalformedZipFailsClosed(t *testing.T) {
	z := filepath.Join(t.TempDir(), "bad.zip")
	writeZip(t, z, []member{{"a", "i am a file"}, {"a/b", "child under a file"}})
	_, _, err := Resolve(z)
	isUnsafe(t, err)
}

// test_malformed_url_fails_closed
func TestMalformedURLFailsClosed(t *testing.T) {
	_, err := checkURLHost("https://[::1/x", time.Time{})
	isUnsafe(t, err)
}

// test_scheme_matching_is_case_insensitive
func TestSchemeMatchingIsCaseInsensitive(t *testing.T) {
	assert.True(t, looksLikeURL("HTTPS://example.com/x"))
	assert.False(t, looksLikeURL("HTTP://example.com/x"))
	assert.True(t, looksLikeGit("https://host/REPO.GIT"))
}

// test_url_ssrf_blocks_embedded_ipv4
func TestURLSsrfBlocksEmbeddedIPv4(t *testing.T) {
	for _, addr := range []string{
		"::ffff:169.254.169.254", // IPv4-mapped cloud metadata
		"64:ff9b::a9fe:a9fe",     // NAT64-embedded 169.254.169.254 (is_global at v6 level)
	} {
		t.Run(addr, func(t *testing.T) {
			testutil.Swap(t, &lookupIP, addrs(addr))
			_, err := checkURLHost("https://sneaky.example.com/x", time.Time{})
			isUnsafe(t, err)
		})
	}
}

// test_non_zip_tarball_is_refused
func TestNonZipTarballIsRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "skill.tar.gz")
	f, err := os.Create(p)
	require.NoError(t, err)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "SKILL.md", Mode: 0o644, Size: int64(len(manifest))}))
	_, err = tw.Write([]byte(manifest))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, f.Close())
	_, _, err = Resolve(p)
	isUnsafe(t, err)
}

// test_unknown_archive_extension_is_refused
func TestUnknownArchiveExtensionIsRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "skill.7z")
	writeFile(t, p, "7z\xbc\xaf\x27\x1c not a real archive")
	_, _, err := Resolve(p)
	isUnsafe(t, err)
}

// test_url_redirect_is_refused
func TestURLRedirectIsRefused(t *testing.T) {
	testutil.Swap(t, &checkURLHost, fakeHost("/x"))
	serve(t, "HTTP/1.1 302 Found\r\nLocation: https://elsewhere/\r\nContent-Length: 0\r\n\r\n")
	_, _, err := Resolve("https://example.com/x")
	isUnsafe(t, err)
	assert.Contains(t, err.Error(), "redirected")
}

// test_enforce_tree_size_caps_a_large_clone
func TestEnforceTreeSizeCapsALargeClone(t *testing.T) {
	testutil.Swap(t, &ingestMaxBytes, 10)
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "big"), strings.Repeat("x", 100))
	isLimit(t, enforceTreeSize(tmp))
}

// test_enforce_tree_size_allows_a_small_clone
func TestEnforceTreeSizeAllowsASmallClone(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "small"), "xxxxx")
	assert.NoError(t, enforceTreeSize(tmp))
}

// test_resolved_namedtuple_is_exported: the three fields, in this order.
func TestResolvedFields(t *testing.T) {
	assert.Equal(t, Resolved{Root: "r", Name: "n", Kind: "k"}, Resolved{"r", "n", "k"})
}

// test_git_clone_strips_proxy_env
func TestGitCloneStripsProxyEnv(t *testing.T) {
	testutil.Swap(t, &checkGitRemote, func(string) error { return nil })
	t.Setenv("HTTPS_PROXY", "http://169.254.169.254:3128")
	t.Setenv("HTTP_PROXY", "http://169.254.169.254:3128")
	var seenArgv, seenEnv []string
	testutil.Swap(t, &runGit, func(_ context.Context, argv, env []string) ([]byte, error) {
		seenArgv, seenEnv = argv, env
		return []byte("fatal: nope"), &exec.ExitError{}
	})
	_, _, err := gitClone("https://github.com/u/r.git")
	isUnsafe(t, err)
	assert.Equal(t, "git clone failed: fatal: nope", err.Error())
	for _, kv := range seenEnv {
		k, _, _ := strings.Cut(kv, "=")
		assert.NotContains(t, []string{"HTTPS_PROXY", "HTTP_PROXY"}, strings.ToUpper(k))
	}
	assert.Contains(t, seenArgv, "http.proxy=")
	assert.Contains(t, seenEnv, "GIT_TERMINAL_PROMPT=0")
}

// isGlobal reproduces ipaddress.is_global as printed by the oracle's Python 3.13.2
// (run on 2026-09-18; the mapped-address rows are why callers Unmap first).
func TestIsGlobalMatchesPython313(t *testing.T) {
	for addr, want := range map[string]bool{
		"0.1.2.3": false, "10.0.0.5": false, "100.64.0.1": false, "100.127.255.255": false, "100.128.0.0": true,
		"127.0.0.1": false, "169.254.169.254": false, "172.16.0.1": false, "172.32.0.1": true,
		"192.0.0.7": false, "192.0.0.8": false, "192.0.0.9": true, "192.0.0.10": true,
		"192.0.0.170": false, "192.0.0.171": false, "192.0.0.172": false, "192.0.2.1": false,
		"192.88.99.1": true, "192.168.1.1": false, "198.18.0.1": false, "198.19.255.255": false,
		"198.20.0.1": true, "198.51.100.1": false, "203.0.113.1": false, "224.0.0.1": true,
		"239.255.255.255": true, "240.0.0.1": false, "255.255.255.255": false, "93.184.216.34": true,
		"::": false, "::1": false, "64:ff9b::a9fe:a9fe": true, "64:ff9b:1::1": false,
		"100::1": false, "100::1:0:0:0:0": true, "2001::1": false, "2001:1::1": true, "2001:1::2": true,
		"2001:1::3": false, "2001:2::1": false, "2001:3::1": true, "2001:4:112::1": true,
		"2001:4:113::1": false, "2001:20::1": true, "2001:2f::1": true, "2001:30::1": true,
		"2001:3f::1": true, "2001:40::1": false, "2001:db8::1": false, "2001:200::1": true,
		"2002::1": false, "fc00::1": false, "fdff::1": false, "fe80::1": false, "febf::1": false,
		"fec0::1": true, "ff02::1": true, "2606:2800:220:1:248:1893:25c8:1946": true,
	} {
		assert.Equal(t, want, isGlobal(netip.MustParseAddr(addr)), addr)
	}
	// Python 3.13 answers for the embedded IPv4 of a mapped address.
	assert.True(t, isGlobal(netip.MustParseAddr("::ffff:8.8.8.8").Unmap()))
	assert.False(t, isGlobal(netip.MustParseAddr("::ffff:169.254.169.254").Unmap()))
}
