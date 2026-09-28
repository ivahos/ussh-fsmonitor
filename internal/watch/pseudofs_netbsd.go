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
	return cstr(st.Fstypename[:]), nil
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
	n, err := unix.Getvfsstat(nil, unix.ST_NOWAIT)
	if err != nil || n <= 0 {
		return nil
	}
	buf := make([]unix.Statvfs_t, n)
	n, err = unix.Getvfsstat(buf, unix.ST_NOWAIT)
	if err != nil {
		return nil
	}
	out := make([]mount, 0, n)
	for _, st := range buf[:n] {
		out = append(out, mount{point: cstr(st.Mntonname[:]), fsType: cstr(st.Fstypename[:])})
	}
	return out
}
