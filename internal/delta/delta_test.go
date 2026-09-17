package delta

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func parseHash(t *testing.T, out []byte) (HashHeader, []string, HashTrailer) {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(out))
	var hdr HashHeader
	var tr HashTrailer
	var lines []string
	if !sc.Scan() {
		t.Fatal("no header")
	}
	if err := json.Unmarshal(sc.Bytes(), &hdr); err != nil {
		t.Fatalf("header: %v", err)
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "{") {
			if err := json.Unmarshal([]byte(line), &tr); err != nil {
				t.Fatalf("trailer: %v", err)
			}
			break
		}
		lines = append(lines, line)
	}
	return hdr, lines, tr
}

func TestHashCloneCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.bin")
	const block = 64 * 1024
	orig := make([]byte, 5*block+123) // a partial last block
	rand.New(rand.NewSource(1)).Read(orig)
	if err := os.WriteFile(path, orig, 0o640); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	os.Chtimes(path, stamp, stamp)

	var out bytes.Buffer
	if err := Hash(path, block, &out); err != nil {
		t.Fatalf("hash: %v", err)
	}
	hdr, lines, tr := parseHash(t, out.Bytes())
	if hdr.Blocks != 6 || len(lines) != 6 || hdr.Size != int64(len(orig)) {
		t.Fatalf("header %+v, %d lines", hdr, len(lines))
	}
	whole := sha256.Sum256(orig)
	if tr.SHA256 != hex.EncodeToString(whole[:]) || !tr.Stat.equal(hdr.Stat) {
		t.Fatalf("trailer %+v", tr)
	}
	b2 := sha256.Sum256(orig[2*block : 3*block])
	if lines[2] != hex.EncodeToString(b2[:]) {
		t.Fatal("block 2 digest wrong")
	}
	last := sha256.Sum256(orig[5*block:])
	if lines[5] != hex.EncodeToString(last[:]) {
		t.Fatal("partial last block digest wrong")
	}

	// New content: block 2 rewritten, file grown by half a block.
	next := append([]byte{}, orig...)
	copy(next[2*block:], bytes.Repeat([]byte{0xAB}, block))
	next = append(next, bytes.Repeat([]byte{0xCD}, block/2)...)

	base := hdr.Stat
	cl, err := Clone(path, &base, nil)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if filepath.Dir(cl.Path) != dir || !strings.HasPrefix(filepath.Base(cl.Path), ".image.bin.ussh-delta-") {
		t.Fatalf("clone path %s", cl.Path)
	}
	t.Logf("clone method: %s", cl.Method)
	if got, _ := os.ReadFile(cl.Path); !bytes.Equal(got, orig) {
		t.Fatal("clone content differs")
	}
	// What the app does over SFTP: write the changed block and the tail.
	f, err := os.OpenFile(cl.Path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt(next[2*block:3*block], 2*block)
	f.WriteAt(next[len(orig):], int64(len(orig)))
	f.Close()

	newSum := sha256.Sum256(next)
	newStamp := time.Date(2026, 9, 17, 10, 30, 0, 500, time.UTC)
	res, err := Commit(CommitRequest{File: path, From: cl.Path, Size: int64(len(next)),
		SHA256: hex.EncodeToString(newSum[:]), Mtime: &newStamp, Base: &base})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, next) {
		t.Fatal("committed content differs")
	}
	fi, _ := os.Stat(path)
	if !fi.ModTime().Equal(newStamp) || fi.Mode().Perm() != 0o640 || res.Size != int64(len(next)) {
		t.Fatalf("stat after commit: %v %v %+v", fi.ModTime(), fi.Mode(), res)
	}
	if _, err := os.Stat(cl.Path); !os.IsNotExist(err) {
		t.Fatal("clone left behind")
	}
}

func TestGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	os.WriteFile(path, []byte("hello world"), 0o644)
	var out bytes.Buffer
	if err := Hash(path, 4, &out); err != nil {
		t.Fatal(err)
	}
	hdr, lines, _ := parseHash(t, out.Bytes())
	if len(lines) != 3 {
		t.Fatalf("%d blocks", len(lines))
	}
	stale := hdr.Stat
	stale.Size++
	if _, err := Clone(path, &stale, nil); AsError(err).Code != "changed" {
		t.Fatalf("stale clone: %v", err)
	}
	cl, err := Clone(path, &hdr.Stat, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong digest: refused, clone removed, original intact.
	if _, err := Commit(CommitRequest{File: path, From: cl.Path, Size: 11, SHA256: strings.Repeat("0", 64)}); AsError(err).Code != "mismatch" {
		t.Fatalf("digest mismatch: %v", err)
	}
	if _, err := os.Stat(cl.Path); !os.IsNotExist(err) {
		t.Fatal("clone not removed after mismatch")
	}
	if got, _ := os.ReadFile(path); string(got) != "hello world" {
		t.Fatal("original touched")
	}
	// Too small: blocks missing.
	cl, _ = Clone(path, nil, nil)
	if _, err := Commit(CommitRequest{File: path, From: cl.Path, Size: 20}); AsError(err).Code != "mismatch" {
		t.Fatalf("short clone: %v", err)
	}
	// Original changed after hashing: refused.
	cl, _ = Clone(path, nil, nil)
	os.Chtimes(path, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	if _, err := Commit(CommitRequest{File: path, From: cl.Path, Size: 11, Base: &hdr.Stat}); AsError(err).Code != "changed" {
		t.Fatalf("changed original: %v", err)
	}
	// Shrink: a larger clone is truncated to --size.
	cl, _ = Clone(path, nil, nil)
	if _, err := Commit(CommitRequest{File: path, From: cl.Path, Size: 5}); err != nil {
		t.Fatalf("shrink: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "hello" {
		t.Fatalf("after shrink: %q", got)
	}
}

func TestCopyFallback(t *testing.T) {
	saved := reflinkFn
	reflinkFn = func(src, dst string) error { return errors.New("no reflink here") }
	defer func() { reflinkFn = saved }()
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	content := bytes.Repeat([]byte("copy me "), 100_000)
	os.WriteFile(path, content, 0o600)
	cl, err := Clone(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Method != "copy" || cl.Size != int64(len(content)) {
		t.Fatalf("%+v", cl)
	}
	got, _ := os.ReadFile(cl.Path)
	if !bytes.Equal(got, content) {
		t.Fatal("copy differs")
	}
	fi, _ := os.Stat(cl.Path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", fi.Mode())
	}
	os.Remove(cl.Path)
}
