package delta

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// writePatch builds the patch file (changed blocks' new bytes, index order)
// and returns it plus the index list, the way uSSH will over SFTP.
func writePatch(t *testing.T, dir string, next []byte, block int64, indices []int64) string {
	t.Helper()
	var buf bytes.Buffer
	for _, i := range indices {
		off := i * block
		end := off + block
		if end > int64(len(next)) {
			end = int64(len(next))
		}
		buf.Write(next[off:end])
	}
	p := filepath.Join(dir, "patch.bin")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInPlaceCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.bin")
	const block = 64 * 1024
	orig := make([]byte, 6*block+321)
	rand.New(rand.NewSource(3)).Read(orig)
	if err := os.WriteFile(path, orig, 0o640); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	ino := inode(t, path)
	base := statOf(fi)

	// Change block 1 and block 4, and grow by half a block.
	next := append([]byte{}, orig...)
	copy(next[1*block:], bytes.Repeat([]byte{0x11}, block))
	copy(next[4*block:], bytes.Repeat([]byte{0x44}, block))
	next = append(next, bytes.Repeat([]byte{0x99}, block/2)...)
	// The grown tail lands in what is now block 6's remainder + a new
	// partial block 7; recompute which blocks differ.
	indices := changedBlocks(orig, next, block)
	patch := writePatch(t, dir, next, block, indices)

	sum := sha256.Sum256(next)
	res, err := InPlaceCommit(InPlaceRequest{
		File: path, Patch: patch, Block: block, Indices: indices,
		FinalSize: int64(len(next)), SHA256: hex.EncodeToString(sum[:]), Base: &base,
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, next) {
		t.Fatal("content differs after in-place commit")
	}
	if res.Size != int64(len(next)) {
		t.Fatalf("size %d", res.Size)
	}
	if inode(t, path) != ino {
		t.Fatal("inode changed — in-place did not preserve it")
	}
	fi, _ = os.Stat(path)
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("perm %v", fi.Mode())
	}
	// No journal or patch left behind.
	if leftovers := glob(t, dir, "."+"image.bin"+journalSuffix+"*"); len(leftovers) != 0 {
		t.Fatalf("journal left: %v", leftovers)
	}
	if _, err := os.Stat(patch); !os.IsNotExist(err) {
		t.Fatal("patch not removed")
	}
}

func TestInPlaceRollbackOnDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.bin")
	const block = 4096
	orig := make([]byte, 3*block)
	rand.New(rand.NewSource(9)).Read(orig)
	os.WriteFile(path, orig, 0o644)
	ino := inode(t, path)

	next := append([]byte{}, orig...)
	copy(next[block:], bytes.Repeat([]byte{0x22}, block))
	indices := []int64{1}
	patch := writePatch(t, dir, next, block, indices)

	// Wrong digest → must roll back to orig, file untouched, inode kept.
	_, err := InPlaceCommit(InPlaceRequest{
		File: path, Patch: patch, Block: block, Indices: indices,
		FinalSize: int64(len(next)), SHA256: "00" + hex.EncodeToString(make([]byte, 31)),
	})
	if AsError(err).Code != "mismatch" {
		t.Fatalf("expected mismatch, got %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, orig) {
		t.Fatal("file not rolled back to original")
	}
	if inode(t, path) != ino {
		t.Fatal("inode changed during rollback")
	}
	if leftovers := glob(t, dir, ".f.bin"+journalSuffix+"*"); len(leftovers) != 0 {
		t.Fatalf("journal left after rollback: %v", leftovers)
	}
}

func TestRecoverRollsBackLeftoverJournal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vol.bin")
	const block = 8192
	orig := make([]byte, 4*block)
	rand.New(rand.NewSource(4)).Read(orig)
	os.WriteFile(path, orig, 0o600)

	// Simulate an interrupted apply: write a journal for block 2's old
	// bytes, then corrupt block 2 on disk (as a torn write would).
	f, _ := os.OpenFile(path, os.O_RDWR, 0)
	jp := abs2journal(mustAbs(t, path))
	if err := writeJournal(jp, mustAbs(t, path), int64(len(orig)), int64(len(orig)), f, block, []int64{2}); err != nil {
		t.Fatal(err)
	}
	f.WriteAt(bytes.Repeat([]byte{0xEE}, block), 2*block) // torn block
	f.Close()

	results, err := Recover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Rolled {
		t.Fatalf("recover results: %+v", results)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, orig) {
		t.Fatal("recover did not restore the original content")
	}
	if leftovers := glob(t, dir, ".vol.bin"+journalSuffix+"*"); len(leftovers) != 0 {
		t.Fatalf("journal left after recover: %v", leftovers)
	}
}

// changedBlocks returns the ascending indices where old and new differ,
// counting whole blocks over the NEW file (the client's own diff).
func changedBlocks(old, next []byte, block int64) []int64 {
	var idx []int64
	blocks := (int64(len(next)) + block - 1) / block
	for i := int64(0); i < blocks; i++ {
		off := i * block
		nEnd := min64(off+block, int64(len(next)))
		oEnd := min64(off+block, int64(len(old)))
		var ob []byte
		if off < int64(len(old)) {
			ob = old[off:oEnd]
		}
		if !bytes.Equal(ob, next[off:nEnd]) {
			idx = append(idx, i)
		}
	}
	return idx
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return inodeOf(fi)
}

func glob(t *testing.T, dir, pat string) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, pat))
	return m
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestStatNlink(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	os.WriteFile(a, []byte("data"), 0o644)
	s1, err := StatFile(a)
	if err != nil || s1.Nlink != 1 {
		t.Fatalf("single link: %+v %v", s1, err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("hard links unsupported here: %v", err)
	}
	s2, _ := StatFile(a)
	if s2.Nlink != 2 {
		t.Fatalf("after hard link nlink=%d, want 2", s2.Nlink)
	}
}
