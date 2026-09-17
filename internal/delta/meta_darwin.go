package delta

// On APFS the clone is made with clonefile(2), which already copies the
// file's extended attributes and ACLs, so there is nothing to do here. The
// rare byte-copy fallback on a non-APFS macOS volume (exFAT, SMB) targets
// filesystems that carry no xattrs worth preserving.
func copyXattrs(src, dst string, logf func(string, ...any)) {}
