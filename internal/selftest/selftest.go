// Package selftest drives the real watcher against a temporary tree and
// checks that the expected paths surface. It runs on the target host
// itself (`ussh-fsmonitor --selftest`), so uSSH can prove a freshly
// pushed helper works on that kernel before trusting its feed.
package selftest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ivahos/ussh-fsmonitor/internal/watch"
)

func Run(logf func(string, ...any)) error {
	dir, err := os.MkdirTemp("", "ussh-fsmonitor-selftest-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	dir, _ = filepath.EvalSymlinks(dir) // /var → /private/var on macOS

	w, err := watch.New(dir, logf)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw := make(chan watch.Change, 1024)
	seen := map[string]watch.Kind{}
	done := make(chan struct{})
	go func() {
		for c := range raw {
			seen[c.Path] = c.Kind
		}
		close(done)
	}()
	errc := make(chan error, 1)
	go func() { errc <- w.Run(ctx, raw) }()

	time.Sleep(300 * time.Millisecond) // let the watch settle

	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one"), 0o644))
	must(os.MkdirAll(filepath.Join(dir, "sub", "deep"), 0o755))
	time.Sleep(150 * time.Millisecond) // give inotify the subdir watch
	must(os.WriteFile(filepath.Join(dir, "sub", "deep", "b.txt"), []byte("two"), 0o644))
	must(os.Rename(filepath.Join(dir, "a.txt"), filepath.Join(dir, "c.txt")))
	must(os.Remove(filepath.Join(dir, "sub", "deep", "b.txt")))

	time.Sleep(1500 * time.Millisecond) // FSEvents latency + coalescing headroom
	cancel()
	if err := <-errc; err != nil {
		return fmt.Errorf("watcher: %w", err)
	}
	close(raw)
	<-done

	expect := map[string]watch.Kind{
		"c.txt":          watch.Modified,
		"a.txt":          watch.Deleted,
		"sub":            watch.Modified,
		"sub/deep/b.txt": watch.Deleted,
	}
	var failures []string
	for p, k := range expect {
		got, ok := seen[p]
		if !ok {
			failures = append(failures, fmt.Sprintf("missing %s", p))
		} else if got != k {
			failures = append(failures, fmt.Sprintf("%s: kind %d, want %d", p, got, k))
		}
	}
	if _, over := seen[""]; over {
		failures = append(failures, "unexpected overflow")
	}
	if len(failures) > 0 {
		return fmt.Errorf("selftest failed (%s): %v", w.Caps(), failures)
	}
	logf("selftest ok (%v): %d paths observed", w.Caps(), len(seen))
	return nil
}
