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
