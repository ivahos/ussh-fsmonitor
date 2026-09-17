package delta

import (
	"errors"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// copyMetadata replicates the source file's ownership and permissions onto
// dst, and its extended attributes on filesystems that carry them. It runs
// only on the rename path (clone → patch → rename), where a NEW file object
// replaces the original and would otherwise lose all of this; the in-place
// path keeps the original object and needs none of it.
//
// APFS clonefile already copies mode, owner and xattrs, so on macOS this is
// a redundant-but-harmless re-set of the same values and copyXattrs is a
// no-op (see meta_darwin.go). The Linux FICLONE and the byte-copy fallback
// clone data only, so this is where owner/mode/xattrs are actually restored.
//
// Best-effort by design: a cross-owner chown needs privilege the session
// user rarely has (its own files are already the right owner), and some
// xattr namespaces (security.*, system.*) may refuse without privilege. A
// failure is logged, never fatal — the data is already correct.
func copyMetadata(src, dst string, logf func(string, ...any)) {
	fi, err := os.Stat(src)
	if err != nil {
		logf("metadata: stat %s: %v", src, err)
		return
	}
	if err := os.Chmod(dst, fi.Mode().Perm()); err != nil {
		logf("metadata: chmod %s: %v", dst, err)
	}
	if st, ok := fi.Sys().(*unix.Stat_t); ok {
		if err := os.Chown(dst, int(st.Uid), int(st.Gid)); err != nil {
			// Same-owner chown is a no-op success; a cross-owner one needs
			// privilege. Either way the clone is already owned by whoever
			// the helper runs as, which is the user who owns the file in
			// the common case.
			if !errors.Is(err, fs.ErrPermission) {
				logf("metadata: chown %s: %v", dst, err)
			}
		}
	}
	n := copyXattrs(src, dst, logf)
	// One concise line: the app never sees the clone's metadata work over
	// the data stream, so this is a genuine internal op worth logging — but
	// a summary, never one line per attribute.
	if n > 0 {
		logf("metadata: copied owner, perms and %d xattr(s) to %s", n, dst)
	} else {
		logf("metadata: copied owner and perms to %s", dst)
	}
}
