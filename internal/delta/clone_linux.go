package delta

import (
	"os"

	"golang.org/x/sys/unix"
)

// reflink: FICLONE — copy-on-write on btrfs, XFS (reflink=1) and others;
// EOPNOTSUPP/EXDEV elsewhere, and the caller falls back to a byte copy.
func reflink(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := unix.IoctlFileClone(int(out.Fd()), int(in.Fd())); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}
