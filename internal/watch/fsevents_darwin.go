//go:build darwin

package watch

/*
#cgo LDFLAGS: -framework CoreServices
#include <stdlib.h>
#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>

extern void usshFSEventsCallback(uintptr_t handle, size_t n, char **paths, unsigned int *flags);

static void bridge(ConstFSEventStreamRef stream, void *info, size_t n,
                   void *eventPaths, const FSEventStreamEventFlags flags[],
                   const FSEventStreamEventId ids[]) {
	usshFSEventsCallback((uintptr_t)info, n, (char **)eventPaths, (unsigned int *)flags);
}

// ussh_stream_start watches every path in roots[0..n): the tree root plus each
// followed symlink target (FSEvents does not descend symlinks, so their
// targets are watched as their own roots).
static FSEventStreamRef ussh_stream_start(uintptr_t handle, char **roots, int n, double latency) {
	CFStringRef *strs = malloc(sizeof(CFStringRef) * n);
	for (int i = 0; i < n; i++)
		strs[i] = CFStringCreateWithCString(NULL, roots[i], kCFStringEncodingUTF8);
	CFArrayRef paths = CFArrayCreate(NULL, (const void **)strs, n, &kCFTypeArrayCallBacks);
	FSEventStreamContext ctx = {0, (void *)handle, NULL, NULL, NULL};
	FSEventStreamRef stream = FSEventStreamCreate(NULL, bridge, &ctx, paths,
		kFSEventStreamEventIdSinceNow, latency,
		kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer |
		kFSEventStreamCreateFlagWatchRoot);
	CFRelease(paths);
	for (int i = 0; i < n; i++) CFRelease(strs[i]);
	free(strs);
	if (stream == NULL) return NULL;
	dispatch_queue_t q = dispatch_queue_create("au.ussh.fsmonitor", DISPATCH_QUEUE_SERIAL);
	FSEventStreamSetDispatchQueue(stream, q);
	if (!FSEventStreamStart(stream)) {
		FSEventStreamInvalidate(stream);
		FSEventStreamRelease(stream);
		return NULL;
	}
	return stream;
}

static void ussh_stream_stop(FSEventStreamRef stream) {
	FSEventStreamStop(stream);
	FSEventStreamInvalidate(stream);
	FSEventStreamRelease(stream);
}
*/
import "C"

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime/cgo"
	"unsafe"
)

// FSEvents is recursive per root and coalesced by the kernel; the stream's
// own latency does the first round of batching and the Coalescer the
// second. Renames arrive as ItemRenamed on both the old and the new path
// with no pairing, so each path is classified by whether it exists now.
//
// FSEvents never descends symlinks, so out-of-tree targets of symlinks found
// under the root are added to the stream as their own watch roots (discovered
// by a walk at start); their events are rewritten onto the link path by the
// shared linkFollower. Symlinks created after the feed starts are picked up on
// the next feed cycle rather than mid-stream (uSSH restarts feeds often).
type fseventsWatcher struct {
	root string
	lf   *linkFollower
	logf func(string, ...any)
	out  chan<- Change
	// scoped, when non-nil, lists the ONLY directories of interest. FSEvents
	// streams are recursive by nature, so each is a stream root and events
	// are kept only for the directory itself and its direct children.
	scoped map[string]bool
}

func New(root string, logf func(string, ...any)) (Watcher, error) {
	return &fseventsWatcher{root: root, lf: newLinkFollower(root), logf: logf}, nil
}

// NewScoped returns the FSEvents backend for dirs (absolute, cleaned, under
// root), each watched non-recursively; no symlink following.
func NewScoped(root string, dirs []string, logf func(string, ...any)) (Watcher, error) {
	w := &fseventsWatcher{root: root, lf: newLinkFollower(root), logf: logf, scoped: map[string]bool{}}
	for _, d := range dirs {
		w.scoped[d] = true
	}
	return w, nil
}

func (w *fseventsWatcher) Caps() []string {
	caps := []string{"fsevents"}
	if w.lf.Partial() {
		caps = append(caps, "partial")
	}
	return caps
}

// discoverTargets walks the tree once to find symlinks-to-directories that
// point out of it, registering each with the follower and collecting the
// resolved targets to watch. A single hop: targets themselves are not walked
// for further symlinks.
func (w *fseventsWatcher) discoverTargets() []string {
	var targets []string
	_ = filepath.WalkDir(w.root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if target, watch := w.lf.consider(p); watch {
				targets = append(targets, target)
			}
		}
		return nil
	})
	return targets
}

func (w *fseventsWatcher) Run(ctx context.Context, out chan<- Change) error {
	w.out = out
	h := cgo.NewHandle(w)
	defer h.Delete()

	var roots []string
	if w.scoped != nil {
		for d := range w.scoped {
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				roots = append(roots, d)
			} else if d != w.root {
				out <- Change{Kind: Deleted, Path: Relative(w.root, d)}
			}
		}
		if len(roots) == 0 {
			roots = []string{w.root}
		}
	} else {
		roots = append([]string{w.root}, w.discoverTargets()...)
	}
	cstrs := make([]*C.char, len(roots))
	for i, r := range roots {
		cstrs[i] = C.CString(r)
	}
	defer func() {
		for _, c := range cstrs {
			C.free(unsafe.Pointer(c))
		}
	}()

	stream := C.ussh_stream_start(C.uintptr_t(h),
		(**C.char)(unsafe.Pointer(&cstrs[0])), C.int(len(cstrs)), C.double(0.1))
	if stream == nil {
		return errors.New("FSEventStreamCreate/Start failed")
	}
	<-ctx.Done()
	C.ussh_stream_stop(stream)
	return nil
}

const (
	flagMustScanSubDirs = C.kFSEventStreamEventFlagMustScanSubDirs
	flagRootChanged     = C.kFSEventStreamEventFlagRootChanged
	flagKernelDropped   = C.kFSEventStreamEventFlagKernelDropped
	flagUserDropped     = C.kFSEventStreamEventFlagUserDropped
	flagIsDir           = C.kFSEventStreamEventFlagItemIsDir
)

//export usshFSEventsCallback
func usshFSEventsCallback(handle C.uintptr_t, n C.size_t, paths **C.char, flags *C.uint) {
	w := cgo.Handle(handle).Value().(*fseventsWatcher)
	cpaths := unsafe.Slice(paths, int(n))
	cflags := unsafe.Slice(flags, int(n))
	for i := range cpaths {
		f := uint32(cflags[i])
		if f&(flagMustScanSubDirs|flagKernelDropped|flagUserDropped|flagRootChanged) != 0 {
			w.out <- Change{Kind: Overflow}
			continue
		}
		abs := filepath.Clean(C.GoString(cpaths[i]))
		var rels []string
		if w.scoped != nil {
			// Only the watched directories and their direct children.
			if !w.scoped[abs] && !w.scoped[filepath.Dir(abs)] {
				continue
			}
			if rel := Relative(w.root, abs); rel != "" {
				rels = []string{rel}
			}
		} else {
			rels = w.lf.rel(abs) // root-relative, or link-relative under a followed target
		}
		if len(rels) == 0 {
			continue
		}
		kind := Modified
		if _, err := os.Lstat(abs); err != nil {
			kind = Deleted
		}
		for _, rel := range rels {
			w.out <- Change{Kind: kind, Path: rel}
		}
	}
}
