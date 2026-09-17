// Package selftest drives the real watcher against a temporary tree and
// checks that the expected paths surface. It runs on the target host
// itself (`ussh-fsmonitor --selftest`), so uSSH can prove a freshly
// pushed helper works on that kernel before trusting its feed.
package selftest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ivahos/ussh-fsmonitor/internal/delta"
	"github.com/ivahos/ussh-fsmonitor/internal/watch"
)

func Run(logf func(string, ...any)) error {
	if err := runRecursive(logf); err != nil {
		return err
	}
	if err := runScoped(logf); err != nil {
		return err
	}
	return runDelta(logf)
}

// runDelta: the block-delta round trip on this host's filesystem — hash,
// clone (reporting whether reflink works here), patch two blocks the way
// uSSH does over SFTP, commit, verify the bytes and that the stale-base
// guard refuses.
func runDelta(logf func(string, ...any)) error {
	dir, err := os.MkdirTemp("", "ussh-fsmonitor-selftest-delta-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	const block = 256 * 1024
	orig := make([]byte, 4*block+999)
	rand.New(rand.NewSource(7)).Read(orig)
	path := filepath.Join(dir, "image.bin")
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		return err
	}
	var out bytes.Buffer
	if err := delta.Hash(path, block, &out); err != nil {
		return fmt.Errorf("delta hash: %w", err)
	}
	var hdr delta.HashHeader
	first, _, _ := strings.Cut(out.String(), "\n")
	if err := json.Unmarshal([]byte(first), &hdr); err != nil {
		return fmt.Errorf("delta hash header: %w", err)
	}
	if hdr.Blocks != 5 || strings.Count(out.String(), "\n") != 7 {
		return fmt.Errorf("delta hash: %d blocks, %d lines", hdr.Blocks, strings.Count(out.String(), "\n"))
	}
	cl, err := delta.Clone(path, &hdr.Stat)
	if err != nil {
		return fmt.Errorf("delta clone: %w", err)
	}
	next := append([]byte{}, orig...)
	copy(next[block:], bytes.Repeat([]byte{0x5A}, block))
	next = next[:3*block+17] // shrink, too
	f, err := os.OpenFile(cl.Path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	f.WriteAt(next[block:2*block], block)
	f.Close()
	sum := sha256.Sum256(next)
	if _, err := delta.Commit(delta.CommitRequest{File: path, From: cl.Path, Size: int64(len(next)),
		SHA256: hex.EncodeToString(sum[:]), Base: &hdr.Stat}); err != nil {
		return fmt.Errorf("delta commit: %w", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, next) {
		return fmt.Errorf("delta selftest: committed bytes differ")
	}
	stale := hdr.Stat
	if _, err := delta.Clone(path, &stale); delta.AsError(err).Code != "changed" {
		return fmt.Errorf("delta selftest: stale base not refused (%v)", err)
	}
	logf("delta selftest ok: clone via %s", cl.Method)
	return nil
}

// runScoped: --watch semantics. Only the root and "sub" are watched; a
// change under sub/deep must NOT surface, a new directory in sub must.
func runScoped(logf func(string, ...any)) error {
	dir, err := os.MkdirTemp("", "ussh-fsmonitor-selftest-scoped-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	dir, _ = filepath.EvalSymlinks(dir)
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "sub", "deep"), 0o755))

	w, err := watch.NewScoped(dir, []string{dir, filepath.Join(dir, "sub")}, logf)
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
	time.Sleep(300 * time.Millisecond)

	must(os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("two"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "sub", "deep", "hidden.txt"), []byte("three"), 0o644))
	must(os.Mkdir(filepath.Join(dir, "sub", "new"), 0o755))

	time.Sleep(1500 * time.Millisecond)
	cancel()
	if err := <-errc; err != nil {
		return fmt.Errorf("scoped watcher: %w", err)
	}
	close(raw)
	<-done

	for _, p := range []string{"a.txt", "sub/b.txt", "sub/new"} {
		if k, ok := seen[p]; !ok || k != watch.Modified {
			return fmt.Errorf("scoped selftest: expected mod %s, saw %v", p, seen)
		}
	}
	if _, ok := seen["sub/deep/hidden.txt"]; ok {
		return fmt.Errorf("scoped selftest: sub/deep/hidden.txt must not surface (saw %v)", seen)
	}
	logf("scoped selftest ok: %d event(s)", len(seen))
	return nil
}

func runRecursive(logf func(string, ...any)) error {
	dir, err := os.MkdirTemp("", "ussh-fsmonitor-selftest-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	dir, _ = filepath.EvalSymlinks(dir) // /var → /private/var on macOS

	// An out-of-tree directory reached through a symlink inside the root: the
	// watcher must follow it and rewrite its events onto the link path. The
	// link has to exist before the watch starts (that is when targets are
	// discovered).
	target, err := os.MkdirTemp("", "ussh-fsmonitor-selftest-target-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(target)
	target, _ = filepath.EvalSymlinks(target)
	if err := os.Symlink(target, filepath.Join(dir, "linked")); err != nil {
		return err
	}

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
	must(os.WriteFile(filepath.Join(target, "t.txt"), []byte("via link"), 0o644))

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
		"linked/t.txt":   watch.Modified, // event in the out-of-tree target, via the symlink
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
