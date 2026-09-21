package ingest

import (
	"io/fs"
	"os"
	"syscall"
)

// Windows has no O_NOFOLLOW/O_NONBLOCK; the walk-time lstat and the post-open
// fstat regular-file check stand in for them.
const openFlags = 0

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
