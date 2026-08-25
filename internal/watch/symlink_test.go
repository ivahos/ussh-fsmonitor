package watch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// collect runs the platform watcher over root, applies mutate once the watch
// has settled, and returns the paths seen (path -> kind) plus the caps.
func collect(t *testing.T, root string, mutate func()) (map[string]Kind, []string) {
	t.Helper()
	w, err := New(root, func(string, ...any) {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	raw := make(chan Change, 1024)
	seen := map[string]Kind{}
	done := make(chan struct{})
	go func() {
		for c := range raw {
			seen[c.Path] = c.Kind
		}
		close(done)
	}()
	errc := make(chan error, 1)
	go func() { errc <- w.Run(ctx, raw) }()

	time.Sleep(400 * time.Millisecond) // let the watch settle
	mutate()
	time.Sleep(1500 * time.Millisecond) // FSEvents latency + inotify delivery
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("watcher: %v", err)
	}
	close(raw)
	<-done
	return seen, w.Caps()
}

// A symlink under the root pointing to a directory OUTSIDE the root should be
// followed: changes in the target surface under the link's path.
func TestFollowsOutOfTreeSymlink(t *testing.T) {
	root := realTempDir(t)
	target := realTempDir(t) // a sibling temp dir, not under root
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	seen, caps := collect(t, root, func() {
		if err := os.WriteFile(filepath.Join(target, "file.txt"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	})

	if k, ok := seen["link/file.txt"]; !ok || k != Modified {
		t.Fatalf("want link/file.txt Modified, got %v (ok=%v); all=%v caps=%v",
			seen["link/file.txt"], ok, seen, caps)
	}
	if _, over := seen[""]; over {
		t.Fatalf("empty path emitted (rewrite missed a target event): %v", seen)
	}
}

// A subdirectory inside a followed target must map through the link too.
func TestFollowsNestedTargetPath(t *testing.T) {
	root := realTempDir(t)
	target := realTempDir(t)
	if err := os.MkdirAll(filepath.Join(target, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, "opt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	seen, _ := collect(t, root, func() {
		if err := os.WriteFile(filepath.Join(target, "sub", "deep.txt"), []byte("y"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	})

	if k, ok := seen["opt/sub/deep.txt"]; !ok || k != Modified {
		t.Fatalf("want opt/sub/deep.txt Modified, got %v (ok=%v); all=%v", seen["opt/sub/deep.txt"], ok, seen)
	}
}

// A broken symlink (dangling target) must not be followed and must not crash.
func TestBrokenSymlinkIsInert(t *testing.T) {
	root := realTempDir(t)
	if err := os.Symlink(filepath.Join(root, "does-not-exist"), filepath.Join(root, "dead")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// Just prove startup + a normal in-tree change still works.
	seen, _ := collect(t, root, func() {
		if err := os.WriteFile(filepath.Join(root, "real.txt"), []byte("z"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	})
	if _, ok := seen["real.txt"]; !ok {
		t.Fatalf("want real.txt; all=%v", seen)
	}
}

// realTempDir returns a fully symlink-resolved temp dir (macOS /var →
// /private/var) that is cleaned up with the test.
func realTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ussh-sym-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	resolved, err := filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatalf("evalsymlinks: %v", err)
	}
	return resolved
}
