package opengrep

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A directory whose DACL lets Everyone write is refused as the engine's location and accepted
// again once that entry is gone; the default temporary directory passes as it is. Everyone is
// named by SID so icacls reads it in every locale.
func TestUntrustedWindowsLocationIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	require.NoError(t, os.Mkdir(dir, 0o755))
	icacls := func(args ...string) {
		out, err := exec.Command("icacls", append([]string{dir}, args...)...).CombinedOutput()
		require.NoError(t, err, string(out))
	}
	icacls("/grant", "*S-1-1-0:(OI)(CI)F")
	candidate := filepath.Join(dir, "opengrep")
	require.NoError(t, os.WriteFile(candidate, []byte("valid"), 0o644))
	a := &asset{"test", 5, hexSHA256([]byte("valid"))}
	clear(digests)
	_, err := verifyExecutable(candidate, a)
	assert.ErrorContains(t, err, "changed by another user")
	icacls("/remove", "*S-1-1-0")
	_, err = verifyExecutable(candidate, a)
	require.NoError(t, err)
}

// A link on the engine's path is judged by the rights that let its target be rewritten: a
// junction that grants Users only the add-file right is refused, since that same bit rewrites a
// reparse point, while a real directory with the same grant is accepted, since adding an entry
// leaves the engine alone. Users is named by SID so icacls reads it in every locale.
func TestLinkOnWindowsPathIsJudgedByItsOwnRights(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	require.NoError(t, os.Mkdir(target, 0o755))
	link := filepath.Join(base, "link")
	run := func(name string, args ...string) {
		out, err := exec.Command(name, args...).CombinedOutput()
		require.NoError(t, err, string(out))
	}
	run("cmd", "/c", "mklink", "/J", link, target)
	run("icacls", link, "/L", "/grant", "*S-1-5-32-545:(WD)") // the link itself: the right that re-points it
	run("icacls", target, "/grant", "*S-1-5-32-545:(WD)")     // the directory: adding an entry leaves the engine alone
	linkInfo, err := os.Lstat(link)
	require.NoError(t, err)
	assert.ErrorContains(t, trustedComponent(link, linkInfo), "is writable by S-1-5-32-545")
	dirInfo, err := os.Stat(target)
	require.NoError(t, err)
	assert.NoError(t, trustedComponent(target, dirInfo))
}

// The engine file is refused when Users hold only the attribute right, since that right alone
// lets FSCTL_SET_REPARSE_POINT turn the file into a link where symbolic links need no privilege;
// a directory with the same grant is accepted, since the call refuses a directory that is not
// empty and a directory on the path never is.
func TestAttributeRightOnTheEngineFileIsRefused(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "opengrep.exe")
	require.NoError(t, os.WriteFile(file, []byte("MZ"), 0o644))
	dir := filepath.Join(base, "dir")
	require.NoError(t, os.Mkdir(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "child"), []byte("c"), 0o644))
	for _, p := range []string{file, dir} {
		out, err := exec.Command("icacls", p, "/grant", "*S-1-5-32-545:(WA)").CombinedOutput()
		require.NoError(t, err, string(out))
	}
	fileInfo, err := os.Lstat(file)
	require.NoError(t, err)
	assert.ErrorContains(t, trustedComponent(file, fileInfo), "is writable by S-1-5-32-545")
	dirInfo, err := os.Lstat(dir)
	require.NoError(t, err)
	assert.NoError(t, trustedComponent(dir, dirInfo))
}

// A UNC engine path reaches the system under the UNC device, not as an invalid extended path.
func TestExtendedPathKeepsUNCShares(t *testing.T) {
	assert.Equal(t, `\\?\UNC\server\share\opengrep.exe`, extendedPath(`\\server\share\opengrep.exe`))
	assert.Equal(t, `\\?\C:\Tools\opengrep.exe`, extendedPath(`C:\Tools\opengrep.exe`))
	assert.Equal(t, `\\?\UNC\server\share`, extendedPath(`\\?\UNC\server\share`))
}
