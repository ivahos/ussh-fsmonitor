// Package watch is the platform-neutral face of the file-system watcher:
// a Watcher streams raw changes for a root, and Coalescer folds bursts
// into one event per path per window before they reach stdout.
package watch

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind of a raw change. Renames and creates both surface as Modified for
// whichever path exists afterwards and Deleted for the one that doesn't;
// the watcher stats when the platform doesn't say.
type Kind int

const (
	Modified Kind = iota
	Deleted
	// Overflow means the platform dropped events; the consumer must do a
	// full rescan. The coalescer collapses everything pending into it.
	Overflow
)

// Change is one raw event with a root-relative, slash-separated path.
type Change struct {
	Kind Kind
	Path string
}

// Watcher delivers changes under one root until ctx ends.
type Watcher interface {
	// Caps names the backend for the handshake ("fsevents", "inotify").
	Caps() []string
	// Run blocks, sending changes, until ctx is cancelled or the backend
	// fails irrecoverably (returned error).
	Run(ctx context.Context, out chan<- Change) error
}

// Coalescer buffers changes for a window and emits each path once, the
// last kind winning, deletes ordered before modifies so a consumer that
// applies them in order ends in the right state. An Overflow flushes
// immediately as a lone event.
type Coalescer struct {
	Window time.Duration
	Emit   func([]Change)

	mu      sync.Mutex
	pending map[string]Kind
	timer   *time.Timer
}

func (c *Coalescer) Add(ch Change) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch.Kind == Overflow {
		c.pending = nil
		if c.timer != nil {
			c.timer.Stop()
			c.timer = nil
		}
		c.mu.Unlock()
		c.Emit([]Change{ch})
		c.mu.Lock()
		return
	}
	if c.pending == nil {
		c.pending = make(map[string]Kind)
	}
	c.pending[ch.Path] = ch.Kind
	if c.timer == nil {
		c.timer = time.AfterFunc(c.Window, c.flush)
	}
}

func (c *Coalescer) flush() {
	c.mu.Lock()
	batch := c.pending
	c.pending = nil
	c.timer = nil
	c.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	out := make([]Change, 0, len(batch))
	for p, k := range batch {
		out = append(out, Change{Kind: k, Path: p})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == Deleted
		}
		return out[i].Path < out[j].Path
	})
	c.Emit(out)
}

// Flush emits anything pending now (used at shutdown and by tests).
func (c *Coalescer) Flush() { c.flush() }

// Relative turns an absolute path under root into the protocol form, or
// "" (skip) when it isn't under root. Both must be clean absolute paths.
func Relative(root, abs string) string {
	if abs == root {
		return "."
	}
	prefix := strings.TrimSuffix(root, "/") + "/"
	if !strings.HasPrefix(abs, prefix) {
		return ""
	}
	return strings.TrimPrefix(abs, prefix)
}
