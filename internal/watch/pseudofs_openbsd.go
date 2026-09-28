//go:build openbsd

package watch

import "golang.org/x/sys/unix"

// OpenBSD spells the field F_fstypename; otherwise identical to the other
// BSDs (see pseudofs_bsd.go).
func fsTypeName(dir string) (string, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return "", err
	}
	b := make([]byte, 0, len(st.F_fstypename))
	for _, c := range st.F_fstypename {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b), nil
}
