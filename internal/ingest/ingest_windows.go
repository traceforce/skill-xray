package ingest

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Windows has no O_NOFOLLOW/O_NONBLOCK; the walk-time lstat and the post-open
// fstat regular-file check stand in for them.
const openFlags = 0

// openNoFollow opens path for reading without following a reparse point: a symlink or a junction
// opens as the link itself, which Stat then reports as not a regular file. The verbatim prefix
// lets a long path open too.
func openNoFollow(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	switch {
	case strings.HasPrefix(abs, `\\?\`) || strings.HasPrefix(abs, `\\.\`):
	case strings.HasPrefix(abs, `\\`):
		abs = `\\?\UNC\` + abs[2:]
	default:
		abs = `\\?\` + abs
	}
	name, err := syscall.UTF16PtrFromString(abs)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

func attrs(info os.FileInfo) uint32 {
	if d, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.FileAttributes
	}
	return 0
}

// isDirEntry is DirEntry.is_dir(follow_symlinks=False): true for a directory and
// for an NTFS junction (Go reports a junction as ModeIrregular; Python lists it as
// a directory so the walker can prune it as a reparse point).
func isDirEntry(e fs.DirEntry) bool {
	if e.Type().IsDir() {
		return true
	}
	if e.Type()&fs.ModeIrregular == 0 {
		return false
	}
	info, err := e.Info()
	return err == nil && attrs(info)&syscall.FILE_ATTRIBUTE_DIRECTORY != 0
}

// isReparse is true for a directory symlink or junction; tests replace it.
var isReparse = func(path string) bool {
	st, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return st.Mode()&fs.ModeSymlink != 0 || attrs(st)&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
