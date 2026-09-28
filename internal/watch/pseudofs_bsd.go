//go:build darwin || freebsd || dragonfly

package watch

import "golang.org/x/sys/unix"

// The BSDs and macOS carry the mount's type name in statfs itself, so a
// single syscall answers it exactly — no mount table to parse, no magic
// numbers, and it follows the filesystem rather than the path.
func fsTypeName(dir string) (string, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
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
