package delta

import "golang.org/x/sys/unix"

// reflink: APFS clonefile(2) — an instant copy-on-write clone. Fails on
// other filesystems, and the caller falls back to a byte copy.
func reflink(src, dst string) error {
	return unix.Clonefile(src, dst, 0)
}
