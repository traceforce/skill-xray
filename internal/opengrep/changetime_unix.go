//go:build unix && !darwin

package opengrep

import (
	"errors"
	"os"
	"syscall"
)

// changeTime is the file's change time in nanoseconds from the handle's stat; every write to its
// data or its metadata moves it.
func changeTime(_ *os.File, info os.FileInfo) (int64, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("no change time")
	}
	return st.Ctim.Nano(), nil
}
