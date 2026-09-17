//go:build unix

package delta

import (
	"io/fs"
	"syscall"
)

// os.FileInfo.Sys() returns *syscall.Stat_t (NOT golang.org/x/sys/unix.Stat_t
// — a distinct type; asserting the wrong one silently fails and drops back to
// the fallback, which quietly disabled inode/nlink detection).
func inodeOf(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

func nlinkOf(fi fs.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int64(st.Nlink)
	}
	return 1
}
