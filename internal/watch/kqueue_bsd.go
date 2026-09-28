//go:build freebsd || netbsd || openbsd || dragonfly

package watch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// kqueue is the BSD backend. It differs from inotify in one way that shapes
// everything here: an EVFILT_VNODE registration is made against an open FILE
// DESCRIPTOR, and a directory's events say only "something in here changed" —
// never what. So a watched directory carries a snapshot of its entry names,
// and NOTE_WRITE means "re-list and diff"; arrivals become Modified,
// disappearances Deleted.
//
// The second consequence is that a directory watch does NOT report writes to
// the files inside it (inotify's IN_MODIFY has no kqueue equivalent). Each
// regular file directly inside a watched directory therefore gets its own
// descriptor. That is the real cost of this backend, and it is why the watch
// budget below matters: uSSH runs the helper scoped to the handful of
// directories the user actually has open, where the cost is trivial; an
// unscoped whole-tree feed on a large home directory will hit the budget and
// report itself partial, exactly as inotify does when it runs out of watches.
//
// A file uSSH cannot open (no read permission) simply goes unwatched — its
// creation, rename and deletion still surface through its directory's diff,
// only in-place writes are missed. That is strictly better than failing.
const vnodeMask = unix.NOTE_WRITE | unix.NOTE_EXTEND | unix.NOTE_DELETE |
	unix.NOTE_RENAME | unix.NOTE_ATTRIB | unix.NOTE_REVOKE

type kqueueWatcher struct {
	root  string
	kq    int
	fds   map[int]string             // descriptor -> absolute path
	paths map[string]int             // absolute path -> descriptor
	isDir map[string]bool            // watched path is a directory
	names map[string]map[string]bool // directory -> entry names as last seen
	// budget/partial mirror the inotify backend: a tree that outgrows the
	// descriptor budget stops adding and marks itself partial rather than
	// failing, and the handshake carries "partial" so uSSH knows resyncs
	// remain meaningful.
	budget  int
	partial bool
	wakeFd  int
	lf      *linkFollower
	logf    func(string, ...any)
	// scoped, when non-nil, lists the ONLY directories watched — each
	// non-recursively, no symlink following. Set by NewScoped (--watch).
	scoped map[string]bool
}

// New returns the kqueue backend for root (absolute, cleaned).
func New(root string, logf func(string, ...any)) (Watcher, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, fmt.Errorf("kqueue: %w", err)
	}
	unix.CloseOnExec(kq)
	return &kqueueWatcher{
		root: root, kq: kq, fds: map[int]string{}, paths: map[string]int{},
		isDir: map[string]bool{}, names: map[string]map[string]bool{},
		budget: watchBudget(), wakeFd: -1,
		lf: newLinkFollower(root), logf: logf,
	}, nil
}

// NewScoped returns the kqueue backend watching only dirs (absolute,
// cleaned, under root), each non-recursively: the directory itself and the
// regular files directly inside it, nothing below, no symlink following. A
// directory that does not exist is skipped (and reported deleted so the
// consumer can drop it).
func NewScoped(root string, dirs []string, logf func(string, ...any)) (Watcher, error) {
	w, err := New(root, logf)
	if err != nil {
		return nil, err
	}
	kw := w.(*kqueueWatcher)
	kw.scoped = map[string]bool{}
	for _, d := range dirs {
		kw.scoped[d] = true
	}
	return kw, nil
}

// watchBudget is how many descriptors the watcher will spend. The soft file
// limit is raised to the hard one first — a feed that can watch more is
// strictly better, and this only ever affects the helper's own process.
func watchBudget() int {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		return 1024
	}
	if lim.Cur < lim.Max {
		lim.Cur = lim.Max
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
			_ = unix.Getrlimit(unix.RLIMIT_NOFILE, &lim)
		}
	}
	// Headroom for stdio, the kqueue, the wake pipe and Go's own runtime.
	n := int(lim.Cur) - 64
	if n > 16384 {
		n = 16384
	}
	if n < 64 {
		n = 64
	}
	return n
}

func (w *kqueueWatcher) Caps() []string {
	caps := []string{"kqueue"}
	if w.partial || w.lf.Partial() {
		caps = append(caps, "partial")
	}
	return caps
}

// emit sends a change for every protocol path an absolute path resolves to —
// one when it is under the root, one per followed symlink otherwise (see
// linkFollower.rel).
func (w *kqueueWatcher) emit(out chan<- Change, kind Kind, abs string) {
	for _, r := range w.lf.rel(abs) {
		out <- Change{Kind: kind, Path: r}
	}
}

// watch opens path and registers it for vnode events. Reports whether the
// registration now exists (already-watched counts as success).
func (w *kqueueWatcher) watch(path string, dir bool) bool {
	if _, ok := w.paths[path]; ok {
		return true
	}
	if len(w.fds) >= w.budget {
		if !w.partial {
			w.partial = true
			w.logf("descriptor budget %d reached at %s; feed is partial", w.budget, path)
		}
		return false
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK
	if dir {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		// Unreadable or gone: not fatal. A file we cannot open still has its
		// arrival and departure reported by its directory's diff.
		if dir && !errors.Is(err, unix.ENOENT) {
			w.logf("watch %s: %v", path, err)
		}
		return false
	}
	var ev unix.Kevent_t
	unix.SetKevent(&ev, fd, unix.EVFILT_VNODE, unix.EV_ADD|unix.EV_CLEAR)
	ev.Fflags = vnodeMask
	if _, err := unix.Kevent(w.kq, []unix.Kevent_t{ev}, nil, nil); err != nil {
		unix.Close(fd)
		w.logf("kevent add %s: %v", path, err)
		return false
	}
	w.fds[fd] = path
	w.paths[path] = fd
	w.isDir[path] = dir
	return true
}

// unwatch drops path and, when it is a directory, everything below it. The
// kernel removes a registration when its descriptor closes, so closing is
// the whole job.
func (w *kqueueWatcher) unwatch(path string) {
	prefix := path + "/"
	for p, fd := range w.paths {
		if p != path && !strings.HasPrefix(p, prefix) {
			continue
		}
		unix.Close(fd)
		delete(w.paths, p)
		delete(w.fds, fd)
		delete(w.isDir, p)
		delete(w.names, p)
	}
}

// snapshot records a directory's entry names and watches the regular files
// inside it, so their in-place writes are seen. report surfaces what is
// already there (used when a directory ARRIVES, never at start — the
// consumer enumerates on start anyway).
func (w *kqueueWatcher) snapshot(dir string, out chan<- Change, report bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		w.names[dir] = map[string]bool{}
		return
	}
	now := make(map[string]bool, len(entries))
	for _, e := range entries {
		now[e.Name()] = true
		abs := filepath.Join(dir, e.Name())
		if report {
			w.emit(out, Modified, abs)
		}
		if e.Type()&os.ModeSymlink == 0 && !e.IsDir() {
			w.watch(abs, false)
		}
	}
	w.names[dir] = now
}

// addTree watches dir and every directory below it, plus the regular files
// in each. followLinks follows symlinks-to-directories out of the tree (their
// targets are watched too and their events rewritten onto the link path); it
// is off when walking a followed target, keeping following to a single hop.
func (w *kqueueWatcher) addTree(dir string, out chan<- Change, report, followLinks bool) {
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skip, keep going
		}
		if d.Type()&os.ModeSymlink != 0 {
			// WalkDir never descends a symlink (it Lstats); surface it like
			// any other entry, then follow it if it points to a directory out
			// of the tree.
			if report {
				w.emit(out, Modified, p)
			}
			if followLinks {
				if target, watch := w.lf.consider(p); watch {
					w.addTree(target, out, false, false)
				}
			}
			return nil
		}
		if !d.IsDir() {
			if report {
				w.emit(out, Modified, p)
			}
			w.watch(p, false)
			return nil
		}
		if !w.watch(p, true) {
			if w.partial {
				return filepath.SkipDir
			}
			return nil
		}
		if report && p != dir {
			w.emit(out, Modified, p)
		}
		// Names only: the files are watched by the walk itself as it descends.
		if entries, err := os.ReadDir(p); err == nil {
			now := make(map[string]bool, len(entries))
			for _, e := range entries {
				now[e.Name()] = true
			}
			w.names[p] = now
		}
		return nil
	})
}

// addOne watches a single directory and the regular files directly inside
// it, non-recursively.
func (w *kqueueWatcher) addOne(dir string, out chan<- Change) {
	if !w.watch(dir, true) {
		if _, err := os.Stat(dir); err != nil && dir != w.root {
			w.emit(out, Deleted, dir)
		}
		return
	}
	w.snapshot(dir, out, false)
}

// rescan diffs a directory against its last snapshot. This is what turns
// kqueue's contentless "this directory changed" into per-path events.
func (w *kqueueWatcher) rescan(dir string, out chan<- Change) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // vanished or unreadable; NOTE_DELETE handles the former
	}
	now := make(map[string]bool, len(entries))
	for _, e := range entries {
		now[e.Name()] = true
	}
	prev := w.names[dir]
	for name := range now {
		if prev[name] {
			continue
		}
		abs := filepath.Join(dir, name)
		w.emit(out, Modified, abs)
		fi, err := os.Lstat(abs)
		if err != nil {
			continue
		}
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			// A symlink to a directory out of the tree: start following it
			// now and surface what it already holds.
			if w.scoped == nil {
				if target, watch := w.lf.consider(abs); watch {
					w.addTree(target, out, true, false)
				}
			}
		case fi.IsDir():
			// A new directory may already hold files created before it could
			// be watched (mkdir -p, untar, git checkout): report them.
			// Scoped: the directory itself is the news; its contents are
			// watched only once the consumer asks for them.
			if w.scoped == nil {
				w.addTree(abs, out, true, true)
			}
		default:
			w.watch(abs, false)
		}
	}
	for name := range prev {
		if now[name] {
			continue
		}
		abs := filepath.Join(dir, name)
		w.unwatch(abs)
		w.emit(out, Deleted, abs)
	}
	w.names[dir] = now
}

func (w *kqueueWatcher) Run(ctx context.Context, out chan<- Change) error {
	defer func() {
		for fd := range w.fds {
			unix.Close(fd)
		}
		unix.Close(w.kq)
	}()

	if w.scoped != nil {
		for dir := range w.scoped {
			w.addOne(dir, out)
		}
	} else {
		w.addTree(w.root, out, false, true)
	}

	// Wake the blocking Kevent when ctx ends: closing the write end makes the
	// read end readable at EOF.
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pipeR.Close()
	go func() { <-ctx.Done(); pipeW.Close() }()
	w.wakeFd = int(pipeR.Fd())
	var wake unix.Kevent_t
	unix.SetKevent(&wake, w.wakeFd, unix.EVFILT_READ, unix.EV_ADD)
	if _, err := unix.Kevent(w.kq, []unix.Kevent_t{wake}, nil, nil); err != nil {
		return fmt.Errorf("kevent add wake: %w", err)
	}

	events := make([]unix.Kevent_t, 64)
	for {
		n, err := unix.Kevent(w.kq, nil, events, nil)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("kevent: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		for i := 0; i < n; i++ {
			w.dispatch(events[i], out)
		}
	}
}

func (w *kqueueWatcher) dispatch(ev unix.Kevent_t, out chan<- Change) {
	fd := int(ev.Ident)
	if fd == w.wakeFd {
		return // ctx cancellation; the loop re-checks ctx
	}
	path, ok := w.fds[fd]
	if !ok {
		return
	}
	f := uint32(ev.Fflags)
	if f&(unix.NOTE_DELETE|unix.NOTE_RENAME|unix.NOTE_REVOKE) != 0 {
		if path == w.root {
			out <- Change{Kind: Overflow} // root vanished: consumer must rescan/fail
			return
		}
		w.unwatch(path)
		w.emit(out, Deleted, path)
		return
	}
	if w.isDir[path] {
		if f&(unix.NOTE_WRITE|unix.NOTE_EXTEND) != 0 {
			w.rescan(path, out)
		}
		if f&unix.NOTE_ATTRIB != 0 {
			w.emit(out, Modified, path)
		}
		return
	}
	// A regular file: every one of these flags means the same thing to the
	// consumer. A write that also unlinked the file is caught by the
	// directory's diff, which follows in the same batch.
	w.emit(out, Modified, path)
}
