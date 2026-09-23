package opengrep

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/traceforce/skill-xray/internal/pytext"
)

// Version is the pinned OpenGrep release; it reaches analysis.opengrepVersion.
const Version = "1.29.0"

const (
	release     = "https://github.com/opengrep/opengrep/releases/download/v" + Version
	maxDownload = 64 << 20
	envBinary   = "SKILL_XRAY_OPENGREP_BIN"
)

// runtimeError is OpenGrepRuntimeError: the binary is missing, unpinned or uninstallable.
type runtimeError struct{ Msg string }

func (e runtimeError) Error() string { return e.Msg }

// asset is one pinned release binary.
type asset struct {
	Name   string
	Size   int64
	SHA256 string
}

func (a asset) url() string { return release + "/" + a.Name }

var assets = map[[2]string]asset{
	{"windows", "x86_64"}: {"opengrep_windows_x86.exe", 53_536_256,
		"ee485b31912704dc6410bc43f04b5c6ad896697db56e360a98204abf95fa1025"},
	{"linux", "x86_64"}: {"opengrep_manylinux_x86", 46_442_664,
		"3365ef49d04893e01338d85d9bbd49b2bd5261ad4c9c0df0a6a0f8d44232ae13"},
	{"linux", "aarch64"}: {"opengrep_manylinux_aarch64", 47_916_824,
		"db3cda6e6e53251a3874e62b7c8493c281508480b3f3b4db554be41583b21174"},
	{"darwin", "x86_64"}: {"opengrep_osx_x86", 48_310_144,
		"7173bd701491b58e1d1f62c24470ca0be124ecd63885c4d6293cbf71fd706508"},
	{"darwin", "aarch64"}: {"opengrep_osx_arm64", 47_281_712,
		"dacc12a24e95b22c8b1ab55be1777b6eb877a922c5571a95b9a8de30f3963438"},
}

// platformAsset is platform_asset: goos/goarch may be Go (amd64, arm64) or Python
// (Windows, AMD64, x86_64, aarch64) spellings.
func platformAsset(goos, goarch string) (asset, error) {
	system, machine := strings.ToLower(goos), strings.ToLower(goarch)
	switch machine {
	case "amd64", "x64", "x86_64":
		machine = "x86_64"
	case "arm64", "aarch64":
		machine = "aarch64"
	}
	a, ok := assets[[2]string{system, machine}]
	if !ok {
		return asset{}, runtimeError{fmt.Sprintf("OpenGrep v%s is not pinned for %s/%s", Version, system, machine)}
	}
	return a, nil
}

// hostAsset is the asset for this machine; tests swap it (test_install_* monkeypatch platform_asset).
var hostAsset = func() (asset, error) { return platformAsset(runtime.GOOS, runtime.GOARCH) }

// defaultCacheDir is default_cache_dir.
func defaultCacheDir() string {
	home, _ := os.UserHomeDir()
	var root string
	switch {
	case runtime.GOOS == "windows" && os.Getenv("LOCALAPPDATA") != "":
		root = os.Getenv("LOCALAPPDATA")
	case runtime.GOOS == "darwin":
		root = filepath.Join(home, "Library", "Caches")
	case os.Getenv("XDG_CACHE_HOME") != "":
		root = os.Getenv("XDG_CACHE_HOME")
	default:
		root = filepath.Join(home, ".cache")
	}
	return filepath.Join(root, "skill-xray", "opengrep", Version)
}

// CachedExecutable is cached_executable: the pinned binary's path under dir (default cache).
func CachedExecutable(dir string) string {
	if dir == "" {
		dir = defaultCacheDir()
	}
	name := "opengrep"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(dir, name)
}

// digestFile is _digest over the open handle; a test counts its calls.
var digestFile = func(f *os.File) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, 1<<62)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// digests caches a verified binary's digest by file identity (_digest_cached, lru_cache(8)).
// ponytail: identity is (abs path, size, mtime, ctime) plus the os.SameFile check on the entry,
// which stands for ino and dev (code.md R10); the cache is cleared rather than LRU-evicted when
// it fills. Scans may run concurrently in one process, so the lookup and the hash run under one
// lock: the first scan hashes the engine and the others wait for its result instead of hashing
// the same file again.
var (
	digests   = map[digestKey]digestEntry{}
	digestsMu sync.Mutex
)

type digestKey struct {
	path  string
	size  int64
	mtime time.Time
	ctime int64
}

// digestEntry keeps the identity of the file that was hashed. A replacement with the same size
// and modification time is hashed again, and so is the same file rewritten in place with both
// kept, since a write moves its change time, which is part of the key.
type digestEntry struct {
	digest string
	info   os.FileInfo
}

// trustedLocation refuses an engine that a user other than this one or an administrator could
// swap between the verification and the run. Every component on the path as named and on the
// path it resolves to, from the engine itself up to the root, must pass the platform's
// trustedComponent: on Unix it is owned by this user or root and is not world-writable unless it
// is a sticky directory; on Windows its owner is this user, Administrators, SYSTEM or
// TrustedInstaller and its DACL grants no replacing right to Everyone, Authenticated Users or
// Users. A group one of them granted write to keeps it on both.
func trustedLocation(info os.FileInfo, abs string) error {
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return err
	}
	if err := trustedComponent(real, info); err != nil { // the engine itself, as opened
		return err
	}
	chains := []string{filepath.Dir(real)}
	if abs != real {
		chains = append(chains, abs) // the link and every directory on the path as named
	}
	for _, start := range chains {
		for p := start; ; p = filepath.Dir(p) {
			st, err := os.Lstat(p) // #nosec G703 -- a component of the engine's path, judged by its owner and permissions
			if err != nil {
				return err
			}
			if err := trustedComponent(p, st); err != nil {
				return err
			}
			if filepath.Dir(p) == p {
				break
			}
		}
	}
	return nil
}

// verifyExecutable is verify_executable: path must be a regular file with the asset's size
// and SHA-256 (nil asset: this machine's), both read through one open handle, in a location
// that only this user, root or an administrator, or a group one of them granted, can change,
// on every platform. It returns the absolute path it verified, and the engine runs from that
// path; the window between the verification and the run is open to those writers alone, so
// the pin defends against a corrupt or stale download rather than against them.
func verifyExecutable(path string, asset *asset) (string, error) {
	if asset == nil {
		a, err := hostAsset()
		if err != nil {
			return "", err
		}
		asset = &a
	}
	f, err := os.Open(path) // #nosec G304 G703 -- hashing the engine the operator or the cache names is the verification itself
	if err != nil {
		return "", runtimeError{"OpenGrep executable is unavailable: " + path}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", runtimeError{"OpenGrep executable is unavailable: " + path}
	}
	mismatch := runtimeError{fmt.Sprintf("OpenGrep executable does not match pinned v%s asset: %s", Version, path)}
	if !info.Mode().IsRegular() || info.Size() != asset.Size {
		return "", mismatch
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", runtimeError{"OpenGrep executable is unavailable: " + path}
	}
	if err := trustedLocation(info, abs); err != nil {
		return "", runtimeError{fmt.Sprintf("OpenGrep executable location can be changed by another user (%s): %s", err, path)}
	}
	ctime, err := changeTime(f, info)
	if err != nil {
		return "", runtimeError{"OpenGrep executable is unavailable: " + path}
	}
	key := digestKey{abs, info.Size(), info.ModTime(), ctime}
	digestsMu.Lock()
	defer digestsMu.Unlock()
	entry, ok := digests[key]
	if !ok || !os.SameFile(entry.info, info) {
		digest, err := digestFile(f)
		if err != nil {
			return "", runtimeError{"OpenGrep executable is unavailable: " + path}
		}
		if len(digests) >= 8 {
			clear(digests)
		}
		entry = digestEntry{digest, info}
		digests[key] = entry
	}
	if entry.digest != asset.SHA256 {
		return "", mismatch
	}
	return abs, nil
}

// Resolve is resolve_opengrep: the explicit path, else $SKILL_XRAY_OPENGREP_BIN, else the
// cached binary, else "opengrep" on PATH; every candidate is verified. ("", nil) means none.
func Resolve(explicit string) (string, error) {
	if configured := cmp.Or(explicit, os.Getenv(envBinary)); configured != "" {
		return verifyExecutable(configured, nil)
	}
	cached := CachedExecutable("")
	if _, err := os.Stat(cached); err == nil {
		return verifyExecutable(cached, nil)
	}
	if discovered, err := exec.LookPath("opengrep"); err == nil {
		return verifyExecutable(discovered, nil)
	}
	return "", nil
}

// Install is install_opengrep: download this platform's asset into cacheDir (default cache)
// through client (nil: 60 s timeout), verify it in a temp file, then move it into place.
func Install(cacheDir string, client *http.Client) (string, error) {
	asset, err := hostAsset()
	if err != nil {
		return "", err
	}
	destination := CachedExecutable(cacheDir)
	if verified, err := verifyExecutable(destination, &asset); err == nil {
		return verified, nil
	}
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	temporary, err := download(asset, destination, client)
	if temporary != "" {
		defer os.Remove(temporary)
	}
	if err != nil {
		return "", err
	}
	if _, err := verifyExecutable(temporary, &asset); err != nil {
		return "", err
	}
	if err := os.Chmod(temporary, 0o700); err != nil { // #nosec G302 -- the verified engine must stay executable; 0o700 is owner-only
		return "", installFailed(err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return "", installFailed(err)
	}
	return verifyExecutable(destination, &asset)
}

func installFailed(err error) error {
	return runtimeError{"OpenGrep installation failed: " + pytext.OSErrorName(err)}
}

// download streams the asset into a ".opengrep-*" file beside destination, capped at 64 MiB.
// The temp file's name is returned even on failure so the caller removes it.
func download(asset asset, destination string, client *http.Client) (string, error) {
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return "", installFailed(err)
	}
	req, err := http.NewRequest(http.MethodGet, asset.url(), nil)
	if err != nil {
		return "", installFailed(err)
	}
	req.Header.Set("User-Agent", "skill-xray/"+Version)
	resp, err := client.Do(req)
	if err != nil {
		return "", installFailed(err)
	}
	defer resp.Body.Close()
	if resp.ContentLength > maxDownload {
		return "", runtimeError{"OpenGrep download exceeds the safety limit"}
	}
	f, err := os.CreateTemp(filepath.Dir(destination), ".opengrep-*")
	if err != nil {
		return "", installFailed(err)
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxDownload+1))
	f.Close()
	switch {
	case err != nil:
		return f.Name(), installFailed(err)
	case n > maxDownload:
		return f.Name(), runtimeError{"OpenGrep download exceeds the safety limit"}
	}
	return f.Name(), nil
}
