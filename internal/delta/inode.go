package delta

// InodeOf exposes the file's inode number for callers that need to prove an
// operation preserved it (selftest). 0 when the platform doesn't report one.
import "io/fs"

func InodeOf(fi fs.FileInfo) uint64 { return inodeOf(fi) }
