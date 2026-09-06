//go:build linux

package watch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// inotify watches one directory per watch descriptor, so a tree costs one
// watch per directory and new directories must be added as they appear.
// The kernel limit (fs.inotify.max_user_watches) is read up front; a tree
// that outgrows it stops adding at the limit and reports itself partial
// rather than failing — a partial feed still beats none, and the handshake
// carries "partial" so uSSH knows resyncs remain meaningful.
const dirMask = unix.IN_CREATE | unix.IN_MODIFY | unix.IN_CLOSE_WRITE |
	unix.IN_ATTRIB | unix.IN_DELETE | unix.IN_DELETE_SELF |
	unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_MOVE_SELF |
	unix.IN_EXCL_UNLINK | unix.IN_ONLYDIR

type inotifyWatcher struct {
	root    string
	fd      int
	wd      map[int]string // wd -> absolute dir
	paths   map[string]int // absolute dir -> wd
	limit   int
	partial bool
	lf      *linkFollower
	logf    func(string, ...any)
	// scoped, when non-nil, lists the ONLY directories watched — each
	// non-recursively, no symlink following. Set by NewScoped (--watch).
	scoped map[string]bool
}

// NewScoped returns the inotify backend watching only dirs (absolute,
// cleaned, under root), each non-recursively: one watch per directory,
// nothing below it, no symlink following. A directory that does not exist
// is skipped (and reported deleted so the consumer can drop it).
func NewScoped(root string, dirs []string, logf func(string, ...any)) (Watcher, error) {
	w, err := New(root, logf)
	if err != nil {
		return nil, err
	}
	iw := w.(*inotifyWatcher)
	iw.scoped = map[string]bool{}
	for _, d := range dirs {
		iw.scoped[d] = true
	}
	return iw, nil
}

// New returns the inotify backend for root (absolute, cleaned).
func New(root string, logf func(string, ...any)) (Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init: %w", err)
	}
	w := &inotifyWatcher{root: root, fd: fd, wd: map[int]string{},
		paths: map[string]int{}, limit: readWatchLimit(),
		lf: newLinkFollower(root), logf: logf}
	return w, nil
}

func readWatchLimit() int {
	b, err := os.ReadFile("/proc/sys/fs/inotify/max_user_watches")
	if err != nil {
		return 8192
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 {
		return 8192
	}
	return n
}

func (w *inotifyWatcher) Caps() []string {
	caps := []string{"inotify"}
	if w.partial || w.lf.Partial() {
		caps = append(caps, "partial")
	}
	return caps
}

// emit sends a change for every protocol path an absolute path resolves to —
// one when it is under the root, one per followed symlink otherwise (see
// linkFollower.rel).
func (w *inotifyWatcher) emit(out chan<- Change, kind Kind, abs string) {
	for _, r := range w.lf.rel(abs) {
		out <- Change{Kind: kind, Path: r}
	}
}

// addTree watches dir and every directory below it. Files that already
// exist are not reported — the consumer enumerates on start anyway.
// followLinks follows symlinks-to-directories out of the tree (their targets
// are watched too and their events rewritten onto the link path); it is off
// when walking a followed target, keeping following to a single hop.
func (w *inotifyWatcher) addTree(dir string, out chan<- Change, report, followLinks bool) {
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skip, keep going
		}
		if d.Type()&os.ModeSymlink != 0 {
			// A symlink is never descended by WalkDir (it Lstats); surface it
			// like any other entry, then follow it if it points to a directory
			// out of the tree.
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
			return nil
		}
		if _, ok := w.paths[p]; ok {
			return nil
		}
		// Leave headroom for other inotify users of this uid.
		if len(w.wd) >= w.limit-64 {
			if !w.partial {
				w.partial = true
				w.logf("watch limit %d reached under %s; feed is partial", w.limit, p)
			}
			return filepath.SkipDir
		}
		wd, err := unix.InotifyAddWatch(w.fd, p, dirMask)
		if err != nil {
			if errors.Is(err, unix.ENOSPC) {
				w.partial = true
				return filepath.SkipDir
			}
			return nil
		}
		w.wd[wd] = p
		w.paths[p] = wd
		if report && p != dir {
			w.emit(out, Modified, p)
		}
		return nil
	})
}

func (w *inotifyWatcher) remove(dir string) {
	prefix := dir + "/"
	for p, wd := range w.paths {
		if p == dir || strings.HasPrefix(p, prefix) {
			delete(w.paths, p)
			delete(w.wd, wd)
			// The kernel drops the watch itself on IN_DELETE_SELF/IN_IGNORED;
			// removing an already-gone wd is harmless.
			_, _ = unix.InotifyRmWatch(w.fd, uint32(wd))
		}
	}
}

// addOne watches a single directory, non-recursively.
func (w *inotifyWatcher) addOne(dir string, out chan<- Change) {
	if _, ok := w.paths[dir]; ok {
		return
	}
	wd, err := unix.InotifyAddWatch(w.fd, dir, dirMask)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			if dir != w.root {
				w.emit(out, Deleted, dir)
			}
			return
		}
		if errors.Is(err, unix.ENOSPC) {
			w.partial = true
		}
		w.logf("watch %s: %v", dir, err)
		return
	}
	w.wd[wd] = dir
	w.paths[dir] = wd
}

func (w *inotifyWatcher) Run(ctx context.Context, out chan<- Change) error {
	defer unix.Close(w.fd)
	if w.scoped != nil {
		for dir := range w.scoped {
			w.addOne(dir, out)
		}
	} else {
		w.addTree(w.root, out, false, true)
	}

	// Wake the blocking poll when ctx ends.
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pipeR.Close()
	go func() { <-ctx.Done(); pipeW.Close() }()

	buf := make([]byte, 64*1024)
	fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN},
		{Fd: int32(pipeR.Fd()), Events: unix.POLLIN | unix.POLLHUP}}
	for {
		_, err := unix.Poll(fds, -1)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return fmt.Errorf("poll: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("read: %w", err)
		}
		w.dispatch(buf[:n], out)
	}
}

func (w *inotifyWatcher) dispatch(b []byte, out chan<- Change) {
	for len(b) >= unix.SizeofInotifyEvent {
		ev := (*unix.InotifyEvent)(unsafe.Pointer(&b[0]))
		nameLen := int(ev.Len)
		name := ""
		if nameLen > 0 {
			name = strings.TrimRight(string(b[unix.SizeofInotifyEvent:unix.SizeofInotifyEvent+nameLen]), "\x00")
		}
		b = b[unix.SizeofInotifyEvent+nameLen:]
		mask := ev.Mask

		if mask&unix.IN_Q_OVERFLOW != 0 {
			out <- Change{Kind: Overflow}
			continue
		}
		dir, ok := w.wd[int(ev.Wd)]
		if !ok {
			continue
		}
		if mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0 {
			if dir == w.root {
				out <- Change{Kind: Overflow} // root vanished: consumer must rescan/fail
				continue
			}
			w.remove(dir)
			w.emit(out, Deleted, dir)
			continue
		}
		if mask&unix.IN_IGNORED != 0 || name == "" {
			continue
		}
		abs := filepath.Join(dir, name)
		switch {
		case mask&(unix.IN_DELETE|unix.IN_MOVED_FROM) != 0:
			if mask&unix.IN_ISDIR != 0 {
				w.remove(abs)
			}
			w.emit(out, Deleted, abs)
		case mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 && mask&unix.IN_ISDIR != 0:
			// A new directory may already contain files created before the
			// watch existed (mkdir -p, untar, git checkout): report them.
			// Scoped: the directory itself is the news; its contents are
			// watched only once the consumer asks for them.
			w.emit(out, Modified, abs)
			if w.scoped == nil {
				w.addTree(abs, out, true, true)
			}
		default:
			w.emit(out, Modified, abs)
			// A symlink appears as a non-directory create; if it points to a
			// directory out of the tree, start following it now and surface
			// what it already holds.
			if w.scoped == nil && mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 {
				if fi, err := os.Lstat(abs); err == nil && fi.Mode()&os.ModeSymlink != 0 {
					if target, watch := w.lf.consider(abs); watch {
						w.addTree(target, out, true, false)
					}
				}
			}
		}
	}
}
