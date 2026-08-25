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
	logf    func(string, ...any)
}

// New returns the inotify backend for root (absolute, cleaned).
func New(root string, logf func(string, ...any)) (Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init: %w", err)
	}
	w := &inotifyWatcher{root: root, fd: fd, wd: map[int]string{},
		paths: map[string]int{}, limit: readWatchLimit(), logf: logf}
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
	if w.partial {
		caps = append(caps, "partial")
	}
	return caps
}

// addTree watches dir and every directory below it. Files that already
// exist are not reported — the consumer enumerates on start anyway.
func (w *inotifyWatcher) addTree(dir string, out chan<- Change, report bool) {
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skip, keep going
		}
		if !d.IsDir() {
			if report {
				out <- Change{Kind: Modified, Path: Relative(w.root, p)}
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
			out <- Change{Kind: Modified, Path: Relative(w.root, p)}
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

func (w *inotifyWatcher) Run(ctx context.Context, out chan<- Change) error {
	defer unix.Close(w.fd)
	w.addTree(w.root, out, false)

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
			out <- Change{Kind: Deleted, Path: Relative(w.root, dir)}
			continue
		}
		if mask&unix.IN_IGNORED != 0 || name == "" {
			continue
		}
		abs := filepath.Join(dir, name)
		rel := Relative(w.root, abs)
		switch {
		case mask&(unix.IN_DELETE|unix.IN_MOVED_FROM) != 0:
			if mask&unix.IN_ISDIR != 0 {
				w.remove(abs)
			}
			out <- Change{Kind: Deleted, Path: rel}
		case mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 && mask&unix.IN_ISDIR != 0:
			// A new directory may already contain files created before the
			// watch existed (mkdir -p, untar, git checkout): report them.
			out <- Change{Kind: Modified, Path: rel}
			w.addTree(abs, out, true)
		default:
			out <- Change{Kind: Modified, Path: rel}
		}
	}
}
