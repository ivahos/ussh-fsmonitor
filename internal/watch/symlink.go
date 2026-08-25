package watch

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// maxFollowedTargets caps how many distinct symlink targets the watcher will
// follow out of the tree. It bounds the extra FSEvents stream paths (macOS)
// and inotify subtrees (Linux) a link farm can create; inotify's own kernel
// watch limit still backstops the per-directory cost. Past this, following
// stops and the feed marks itself partial so uSSH knows resyncs still matter.
const maxFollowedTargets = 256

// follow records one symlink whose target we watch: the link's path relative
// to the root (the virtual path uSSH's File Provider understands) and the
// resolved absolute target directory whose events we rewrite back onto it.
type follow struct {
	linkRel   string
	targetAbs string
}

// linkFollower turns events under followed symlink targets back into the
// link-relative paths the consumer understands, and enforces the follow
// guardrails: directories only, never into the root's own subtree (already
// watched) or an ancestor of it (a cycle), deduped by resolved target, and
// budgeted. It carries no knowledge of any backend — inotify and FSEvents
// both drive it the same way.
//
// The emitted link-relative paths (e.g. "optlink/foo") are ordinary
// root-relative paths from uSSH's view: the extension already maps them and
// stat-dereferences the link, so nothing downstream needs to change.
type linkFollower struct {
	root    string
	mu      sync.Mutex
	follows []follow
	targets map[string]bool // resolved targetAbs already watched (dedup)
	partial bool
}

func newLinkFollower(root string) *linkFollower {
	return &linkFollower{root: root, targets: map[string]bool{}}
}

// consider examines a symlink at its own absolute path. When it points to a
// directory outside the watched tree, the link→target mapping is recorded and
// the resolved target is returned with watch=true so the backend watches that
// subtree. watch=false means the mapping is either unusable (broken, in-tree,
// cyclic, over budget) or already covered by an equal/enclosing followed
// target — in the latter case the mapping is still recorded so this link, too,
// receives the target's events; the subtree just needn't be watched again.
func (lf *linkFollower) consider(abs string) (target string, watch bool) {
	linkRel := Relative(lf.root, abs)
	if linkRel == "" || linkRel == "." {
		return "", false
	}
	t, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false
	}
	if st, err := os.Stat(t); err != nil || !st.IsDir() {
		return "", false // broken link or not a directory
	}
	// Inside the root (already watched), equal to it, or an ancestor of it
	// (a cycle that would re-watch the whole tree): leave it be.
	if t == lf.root || contains(lf.root, t) || contains(t, lf.root) {
		return "", false
	}

	lf.mu.Lock()
	defer lf.mu.Unlock()
	for _, f := range lf.follows {
		if f.linkRel == linkRel && f.targetAbs == t {
			return "", false // this exact link already registered
		}
	}
	// Same target as, or nested under, an already-followed target: record the
	// mapping (so this link gets the events too) but don't re-watch.
	for _, f := range lf.follows {
		if t == f.targetAbs || contains(f.targetAbs, t) {
			lf.follows = append(lf.follows, follow{linkRel, t})
			return "", false
		}
	}
	if len(lf.targets) >= maxFollowedTargets {
		lf.partial = true
		return "", false
	}
	lf.follows = append(lf.follows, follow{linkRel, t})
	lf.targets[t] = true
	return t, true
}

// rel returns the protocol path(s) for an absolute event path: the
// root-relative form when the path is under the root, otherwise the
// link-relative form for every followed link whose target contains it (more
// than one when several links point at the same target).
func (lf *linkFollower) rel(abs string) []string {
	if r := Relative(lf.root, abs); r != "" {
		return []string{r}
	}
	lf.mu.Lock()
	defer lf.mu.Unlock()
	var out []string
	for _, f := range lf.follows {
		if abs == f.targetAbs {
			out = append(out, f.linkRel)
		} else if strings.HasPrefix(abs, f.targetAbs+"/") {
			out = append(out, f.linkRel+"/"+abs[len(f.targetAbs)+1:])
		}
	}
	return out
}

// Partial reports whether following hit its budget and some targets went
// unwatched — folded into the handshake caps.
func (lf *linkFollower) Partial() bool {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	return lf.partial
}

// contains reports whether child is strictly below parent. Both are clean
// absolute paths.
func contains(parent, child string) bool {
	return strings.HasPrefix(child, strings.TrimSuffix(parent, "/")+"/")
}
