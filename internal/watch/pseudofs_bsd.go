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
	return cstr(st.Fstypename[:]), nil
}

// cstr turns a NUL-terminated fixed-size C string field into a Go string.
func cstr(f []byte) string {
	for i, c := range f {
		if c == 0 {
			return string(f[:i])
		}
	}
	return string(f)
}

// mountTable reads the whole mount table in one call — the BSD/macOS way,
// and the only way to see a jail's or container's nested devfs.
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
		out = append(out, mount{point: cstr(st.Mntonname[:]), fsType: cstr(st.Fstypename[:])})
	}
	return out
}
