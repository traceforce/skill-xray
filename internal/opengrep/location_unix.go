//go:build unix

package opengrep

import (
	"fmt"
	"os"
	"syscall"
)

// trustedComponent refuses a component of the engine's path that a user other than this one or
// root could replace: one owned by anybody else, or one every user may write to unless it is a
// directory with the sticky bit, whose entries only their owners can rename or remove. A symlink
// carries open permission bits and is judged by its owner alone. Write access granted to a group
// is an administrative grant and stays allowed.
func trustedComponent(path string, info os.FileInfo) error {
	if !ownedByUserOrRoot(info) {
		return fmt.Errorf("%s is owned by another user", path)
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 || mode.Perm()&0o002 == 0 || (mode.IsDir() && mode&os.ModeSticky != 0) {
		return nil
	}
	return fmt.Errorf("%s is world-writable", path)
}

// ownedByUserOrRoot reports whether info describes a file owned by this process's user or by root.
func ownedByUserOrRoot(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && (st.Uid == 0 || int64(st.Uid) == int64(os.Getuid()))
}
