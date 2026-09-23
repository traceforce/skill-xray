//go:build unix

package opengrep

import (
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownedBy is a real file's info with its owner replaced, since a test cannot chown.
type ownedBy struct {
	os.FileInfo
	uid uint32
}

func (o ownedBy) Sys() any { return &syscall.Stat_t{Uid: o.uid} }

// A component owned by neither this user nor root is refused whatever its permission bits; one
// owned by root or by this user is judged by its bits alone.
func TestComponentOwnedByAnotherUserIsRefused(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Lstat(dir)
	require.NoError(t, err)
	err = trustedComponent(dir, ownedBy{info, uint32(os.Getuid() + 1)})
	assert.ErrorContains(t, err, dir)
	assert.ErrorContains(t, err, "owned by another user")
	assert.NoError(t, trustedComponent(dir, ownedBy{info, 0}))
	assert.NoError(t, trustedComponent(dir, ownedBy{info, uint32(os.Getuid())}))
}
