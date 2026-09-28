package watch

import (
	"os"
	"path/filepath"
	"sort"
)

// Pseudo filesystems — devfs, procfs, sysfs and friends — hold no user
// data, and their contents are synthesised per read: /dev on a FreeBSD box
// lists hundreds of device nodes that appear and vanish as hardware is
// probed, /proc is one entry per live process. Watching them is pure cost
// (one descriptor per node on kqueue, one watch per directory on inotify)
// and the events are noise no file browser wants.
//
// It matters most for a root of "/", which is exactly what a router or NAS
// bookmark tends to be: seen 2026-09-28 on an OPNsense box, where enabling
// the feed pointed the whole machinery at the entire root filesystem and
// /dev alone contributed 512 entries.
//
// The check is by filesystem TYPE, never by path. A blocklist of names like
// "/dev" would be wrong in both directions — it would skip a real directory
// that happens to be called dev, and miss the same filesystem mounted
// somewhere else. Type names come from statfs on the BSDs and macOS and
// from /proc/self/mounts on Linux, where statfs would report devtmpfs and
// tmpfs with the same magic number and /tmp must NOT be skipped.
var pseudoTypes = map[string]bool{
	// BSD / macOS
	"devfs": true, "fdescfs": true, "procfs": true, "linprocfs": true,
	"linsysfs": true, "kernfs": true, "ptyfs": true,
	// Linux
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
	"cgroup": true, "cgroup2": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "selinuxfs": true, "pstore": true, "bpf": true,
	"mqueue": true, "hugetlbfs": true, "binfmt_misc": true, "configfs": true,
	"nsfs": true, "autofs": true, "rpc_pipefs": true, "fusectl": true,
	"efivarfs": true, "tracefs2": true,
}

// isPseudoFS reports whether dir sits on a filesystem that carries no user
// data, along with the type name for the log line. A path it cannot classify
// is never skipped — a feed that watches too much still works, one that
// silently skips a real directory does not.
func isPseudoFS(dir string) (string, bool) {
	name, err := fsTypeName(dir)
	if err != nil || name == "" {
		return "", false
	}
	return name, pseudoTypes[name]
}

// PseudoMountsUnder lists the immediate children of root that sit on a
// filesystem holding no user data, as root-relative names.
//
// The helper is the only party that can answer this: the File Provider side
// reaches the host over SFTP, which has no statfs and no mount table, so
// from there /dev is just a directory with 512 entries in it. Reporting the
// names in the handshake lets the extension leave them out of its listings
// as well — without them the whole tree still gets enumerated into the sync
// engine even though nothing watches it.
//
// One level deep: these are mount points, and a pseudo filesystem nested
// deeper is both rare and cheap to leave in.
func PseudoMountsUnder(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, pseudo := isPseudoFS(filepath.Join(root, e.Name())); pseudo {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}
