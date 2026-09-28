//go:build linux

package watch

import (
	"os"
	"strings"
	"sync"
)

// Linux cannot answer this from statfs: /dev is devtmpfs and /tmp is tmpfs,
// and both report TMPFS_MAGIC — skipping by magic number would take /tmp
// with it. /proc/self/mounts names the type outright, so that is what we
// read: longest matching mount point wins, the way the kernel resolves it.
//
// Read once and cached. Mounts do change, but a feed is short-lived (it dies
// with the SSH channel) and a stale entry only means watching a filesystem we
// would have skipped — never skipping one we should watch.
var (
	mountsOnce sync.Once
	mountTypes map[string]string // mount point -> fs type
)

func loadMounts() {
	mountTypes = map[string]string{}
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		// Fields are escaped octal for spaces and tabs; mount points with
		// those are vanishingly rare and a miss only costs us a skip.
		mountTypes[f[1]] = f[2]
	}
}

func fsTypeName(dir string) (string, error) {
	mountsOnce.Do(loadMounts)
	best, bestLen := "", -1
	for point, typ := range mountTypes {
		if point != "/" && !strings.HasPrefix(dir, strings.TrimSuffix(point, "/")+"/") && dir != point {
			continue
		}
		if len(point) > bestLen {
			best, bestLen = typ, len(point)
		}
	}
	return best, nil
}
