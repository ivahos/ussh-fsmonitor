//go:build unix

package delta

import (
	"io/fs"

	"golang.org/x/sys/unix"
)

func inodeOf(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*unix.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

func nlinkOf(fi fs.FileInfo) int64 {
	if st, ok := fi.Sys().(*unix.Stat_t); ok {
		return int64(st.Nlink)
	}
	return 1
}
