package delta

import (
	"strings"

	"golang.org/x/sys/unix"
)

// copyXattrs copies every extended attribute from src to dst, POSIX ACLs
// included (they live in system.posix_acl_access / _default xattrs). The
// owner can set user.* and its own posix_acl_* freely; security.* /
// trusted.* may refuse without privilege and are skipped with a log line.
func copyXattrs(src, dst string, logf func(string, ...any)) int {
	// Size the name buffer, then read it.
	sz, err := unix.Listxattr(src, nil)
	if err != nil || sz == 0 {
		return 0
	}
	buf := make([]byte, sz)
	sz, err = unix.Listxattr(src, buf)
	if err != nil {
		logf("metadata: listxattr %s: %v", src, err)
		return 0
	}
	copied := 0
	for _, name := range splitNull(buf[:sz]) {
		if name == "" {
			continue
		}
		vsz, err := unix.Getxattr(src, name, nil)
		if err != nil {
			continue
		}
		val := make([]byte, vsz)
		if vsz > 0 {
			if _, err := unix.Getxattr(src, name, val); err != nil {
				continue
			}
		}
		if err := unix.Setxattr(dst, name, val, 0); err != nil {
			logf("metadata: setxattr %s %s: %v", dst, name, err)
			continue
		}
		copied++
	}
	return copied
}

func splitNull(b []byte) []string {
	return strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
}
