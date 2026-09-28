//go:build netbsd

package watch

import "golang.org/x/sys/unix"

// NetBSD exposes the mount's type through statvfs rather than statfs; the
// field carries the same names (see pseudofs_bsd.go).
func fsTypeName(dir string) (string, error) {
	var st unix.Statvfs_t
	if err := unix.Statvfs(dir, &st); err != nil {
		return "", err
	}
	b := make([]byte, 0, len(st.Fstypename))
	for _, c := range st.Fstypename {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b), nil
}
