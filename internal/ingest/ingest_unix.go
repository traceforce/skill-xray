//go:build !windows

package ingest

import (
	"io/fs"
	"os"
	"syscall"
)

// A symlink or FIFO put in place after the walk is neither followed nor blocked on.
const openFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

func isDirEntry(e fs.DirEntry) bool { return e.Type().IsDir() }

// openNoFollow opens path for reading without following a symlink or blocking on a FIFO.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|openFlags, 0) // #nosec G304 -- the single-file scan target, checked on the handle
}

// isReparse is true for a directory symlink; tests replace it.
var isReparse = func(path string) bool {
	st, err := os.Lstat(path)
	return err == nil && st.Mode()&fs.ModeSymlink != 0
}
