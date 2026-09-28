package watch

import (
	"path/filepath"
	"sort"
	"strings"
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

// PseudoMountsUnder lists every pseudo filesystem mounted at or below root,
// as root-relative paths.
//
// It reads the mount table rather than walking the tree: one syscall instead
// of a recursive descent, and — the reason it matters — it finds mounts at
// any depth. A jail or a container brings its own devfs with it, nested
// wherever it lives: OPNsense mounts one at /var/unbound/dev and another at
// /var/captiveportal/zone0/dev, and Docker puts /proc and /sys inside each
// container root under /var/lib/docker. Looking only at the root's immediate
// children would miss every one of them, which is the wrong answer for
// exactly the routers and NAS boxes this is for.
func PseudoMountsUnder(root string) []string {
	root = filepath.Clean(root)
	prefix := strings.TrimSuffix(root, "/") + "/"
	var out []string
	for _, m := range mountTable() {
		if !pseudoTypes[m.fsType] {
			continue
		}
		point := filepath.Clean(m.point)
		switch {
		case point == root:
			continue // the root itself; nothing to exclude from its own listing
		case strings.HasPrefix(point, prefix):
			out = append(out, strings.TrimPrefix(point, prefix))
		}
	}
	sort.Strings(out)
	return out
}

// mount is one entry of the host's mount table.
type mount struct {
	point  string
	fsType string
}
