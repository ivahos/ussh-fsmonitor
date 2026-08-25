//go:build darwin

package watch

/*
#cgo LDFLAGS: -framework CoreServices
#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>

extern void usshFSEventsCallback(uintptr_t handle, size_t n, char **paths, unsigned int *flags);

static void bridge(ConstFSEventStreamRef stream, void *info, size_t n,
                   void *eventPaths, const FSEventStreamEventFlags flags[],
                   const FSEventStreamEventId ids[]) {
	usshFSEventsCallback((uintptr_t)info, n, (char **)eventPaths, (unsigned int *)flags);
}

static FSEventStreamRef ussh_stream_start(uintptr_t handle, const char *root, double latency) {
	CFStringRef s = CFStringCreateWithCString(NULL, root, kCFStringEncodingUTF8);
	CFArrayRef paths = CFArrayCreate(NULL, (const void **)&s, 1, &kCFTypeArrayCallBacks);
	FSEventStreamContext ctx = {0, (void *)handle, NULL, NULL, NULL};
	FSEventStreamRef stream = FSEventStreamCreate(NULL, bridge, &ctx, paths,
		kFSEventStreamEventIdSinceNow, latency,
		kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer |
		kFSEventStreamCreateFlagWatchRoot);
	CFRelease(paths);
	CFRelease(s);
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
type fseventsWatcher struct {
	root string
	logf func(string, ...any)
	out  chan<- Change
}

func New(root string, logf func(string, ...any)) (Watcher, error) {
	return &fseventsWatcher{root: root, logf: logf}, nil
}

func (w *fseventsWatcher) Caps() []string { return []string{"fsevents"} }

func (w *fseventsWatcher) Run(ctx context.Context, out chan<- Change) error {
	w.out = out
	h := cgo.NewHandle(w)
	defer h.Delete()
	croot := C.CString(w.root)
	defer C.free(unsafe.Pointer(croot))
	stream := C.ussh_stream_start(C.uintptr_t(h), croot, C.double(0.1))
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
		rel := Relative(w.root, abs)
		if rel == "" {
			continue
		}
		if _, err := os.Lstat(abs); err != nil {
			w.out <- Change{Kind: Deleted, Path: rel}
		} else {
			w.out <- Change{Kind: Modified, Path: rel}
		}
	}
}
