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
	return cstr(st.F_fstypename[:]), nil
}

func cstr(f []byte) string {
	for i, c := range f {
		if c == 0 {
			return string(f[:i])
		}
	}
	return string(f)
}

func mountTable() []mount {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil || n <= 0 {
		return nil
	}
	buf := make([]unix.Statfs_t, n)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil
	}
	out := make([]mount, 0, n)
	for _, st := range buf[:n] {
		out = append(out, mount{point: cstr(st.F_mntonname[:]), fsType: cstr(st.F_fstypename[:])})
	}
	return out
}
