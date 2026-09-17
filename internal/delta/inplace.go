package delta

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// In-place commit: apply only the changed blocks to the ORIGINAL file at
// their offsets, so the inode (and with it hardlinks, and everything the
// rename path has to copy by hand) is preserved. Chosen by uSSH when the
// file is hardlinked (st_nlink > 1) or a bookmark opts in.
//
// In-place is not atomic — the file is briefly a mix of old and new — so a
// rollback JOURNAL makes it recoverable: the old bytes of every region the
// apply will destroy are written and fsynced BEFORE the first overwrite.
// If the apply is interrupted (power loss, SIGKILL/OOM, ENOSPC), the file
// is left torn until recovery, which rolls it back to fully-old from the
// journal. That is a weaker guarantee than the rename path's "never torn,
// no recovery needed" — which is why rename stays the default.
//
// A client DISCONNECT is the case we DO defend against directly: the new
// bytes are already on the host (the patch), so the apply is local, and we
// ignore SIGHUP/SIGPIPE across it so the dropped connection cannot cut it
// short. SIGINT/SIGTERM stay live, so a deliberate stop still works.

const journalMagic = "USSHDJ1\n"

// journalSuffix marks a rollback journal; recovery globs for it. The name
// is .<file>.ussh-delta-journal-<hex> next to the file, so it shares the
// directory (and filesystem) and is hidden.
const journalSuffix = ".ussh-delta-journal-"

// InPlaceRequest drives InPlaceCommit.
type InPlaceRequest struct {
	File      string  // the original, patched in place
	Patch     string  // concatenated NEW bytes of the changed blocks, in index order
	Block     int64   // block size the indices count in
	Indices   []int64 // changed block indices, ascending, unique
	FinalSize int64   // the file's size after the edit
	SHA256    string  // expected whole-file digest, hex; "" skips the check
	Mtime     *time.Time
	Base      *Stat // the file's stat at hash time; nil skips the guard
}

// InPlaceCommit applies the patch to File in place, journalling for
// rollback, and returns the file's stat afterwards.
func InPlaceCommit(req InPlaceRequest) (*CommitResult, error) {
	abs, err := filepath.Abs(req.File)
	if err != nil {
		return nil, err
	}
	if req.Block <= 0 {
		return nil, errorf("usage", "block size must be positive")
	}
	// A leftover journal here means a previous apply to this file was
	// interrupted: roll it back before touching the file again.
	if err := rollbackJournalsFor(abs, nil); err != nil {
		return nil, err
	}
	for i := 1; i < len(req.Indices); i++ {
		if req.Indices[i] <= req.Indices[i-1] {
			return nil, errorf("usage", "indices must be ascending and unique")
		}
	}

	f, err := os.OpenFile(abs, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errorf("usage", "%s is not a regular file", abs)
	}
	origSize := fi.Size()
	if req.Base != nil && !req.Base.equal(statOf(fi)) {
		return nil, errorf("changed", "%s changed since it was hashed", abs)
	}

	// Expected patch length: the sum of the new lengths of the changed
	// blocks (the last block of the file may be partial).
	var patchLen int64
	for _, i := range req.Indices {
		off := i * req.Block
		if off > req.FinalSize {
			return nil, errorf("usage", "block %d starts past the final size", i)
		}
		patchLen += min64(req.Block, req.FinalSize-off)
	}
	patch, err := os.Open(req.Patch)
	if err != nil {
		return nil, err
	}
	defer patch.Close()
	if pst, err := patch.Stat(); err != nil {
		return nil, err
	} else if pst.Size() != patchLen {
		return nil, errorf("mismatch", "patch is %d bytes, expected %d for %d block(s)", pst.Size(), patchLen, len(req.Indices))
	}

	// Journal every region the apply will destroy: each changed block's old
	// bytes, and — if the file is shrinking — the tail beyond the new size,
	// so a rollback can restore it. Fsynced before the first overwrite.
	journalPath := abs2journal(abs)
	if err := writeJournal(journalPath, abs, origSize, req.FinalSize, f, req.Block, req.Indices); err != nil {
		return nil, err
	}

	applyErr := withDisconnectGuard(func() error {
		buf := make([]byte, req.Block)
		for _, i := range req.Indices {
			off := i * req.Block
			n := min64(req.Block, req.FinalSize-off)
			if _, err := io.ReadFull(patch, buf[:n]); err != nil {
				return errorf("io", "read patch for block %d: %v", i, err)
			}
			if _, err := f.WriteAt(buf[:n], off); err != nil {
				return errorf("io", "write block %d: %v", i, err)
			}
		}
		if err := f.Truncate(req.FinalSize); err != nil {
			return errorf("io", "truncate: %v", err)
		}
		return fsync(f)
	})
	if applyErr != nil {
		// The apply itself failed (e.g. ENOSPC): roll back to old and drop
		// the journal, leaving the file exactly as it was.
		_ = rollbackJournal(journalPath)
		return nil, applyErr
	}

	// Verify OUTSIDE the disconnect guard (a multi-GB hash must stay
	// interruptible). A mismatch rolls back to the old content.
	if req.SHA256 != "" {
		got, err := fileDigest(f)
		if err != nil {
			_ = rollbackJournal(journalPath)
			return nil, err
		}
		if got != req.SHA256 {
			_ = rollbackJournal(journalPath)
			return nil, errorf("mismatch", "result digest %s, %s expected — rolled back %s", got, req.SHA256, abs)
		}
	}
	if req.Mtime != nil {
		if err := os.Chtimes(abs, *req.Mtime, *req.Mtime); err != nil {
			return nil, err
		}
	}
	// Success: the new content is durable, so the journal (and the patch)
	// can go.
	_ = os.Remove(journalPath)
	_ = os.Remove(req.Patch)
	syncDir(filepath.Dir(abs))

	fi, err = os.Stat(abs)
	if err != nil {
		return nil, err
	}
	res := &CommitResult{T: "done", File: abs, Stat: statOf(fi), Nlink: nlinkOf(fi)}
	if req.SHA256 != "" {
		res.SHA256 = req.SHA256
	}
	return res, nil
}

// withDisconnectGuard runs fn with SIGHUP and SIGPIPE ignored, so a client
// disconnect cannot cut a local apply short. SIGINT/SIGTERM stay live for a
// deliberate stop, and nothing here can defend against SIGKILL or power
// loss — that is what the journal + recovery are for.
func withDisconnectGuard(fn func() error) error {
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	defer signal.Reset(syscall.SIGHUP, syscall.SIGPIPE)
	return fn()
}

func abs2journal(abs string) string {
	dir, name := filepath.Split(abs)
	return filepath.Join(dir, "."+name+journalSuffix+randHex())
}

// writeJournal records the old bytes of every region the apply will
// destroy, fsynced, so rollbackJournal can restore the file.
func writeJournal(path, target string, origSize, finalSize int64, f *os.File, block int64, indices []int64) error {
	j, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer j.Close()
	w := func(b []byte) error { _, err := j.Write(b); return err }
	if err := w([]byte(journalMagic)); err != nil {
		return err
	}
	var hdr [8]byte
	tb := []byte(target)
	binary.BigEndian.PutUint64(hdr[:], uint64(len(tb)))
	if err := w(hdr[:]); err != nil {
		return err
	}
	if err := w(tb); err != nil {
		return err
	}
	binary.BigEndian.PutUint64(hdr[:], uint64(origSize))
	if err := w(hdr[:]); err != nil {
		return err
	}
	binary.BigEndian.PutUint64(hdr[:], uint64(finalSize))
	if err := w(hdr[:]); err != nil {
		return err
	}

	// The regions to save: each changed block's overlap with the OLD file,
	// plus the shrunk tail [finalSize, origSize) if the file is shrinking.
	type region struct{ off, length int64 }
	var regions []region
	for _, i := range indices {
		off := i * block
		if off >= origSize {
			continue // a block being appended has no old bytes to save
		}
		regions = append(regions, region{off, min64(block, origSize-off)})
	}
	if finalSize < origSize {
		regions = append(regions, region{finalSize, origSize - finalSize})
	}

	binary.BigEndian.PutUint64(hdr[:], uint64(len(regions)))
	if err := w(hdr[:]); err != nil {
		return err
	}
	buf := make([]byte, block)
	for _, r := range regions {
		if int64(cap(buf)) < r.length {
			buf = make([]byte, r.length)
		}
		if _, err := f.ReadAt(buf[:r.length], r.off); err != nil {
			return errorf("io", "journal read [%d,%d): %v", r.off, r.off+r.length, err)
		}
		binary.BigEndian.PutUint64(hdr[:], uint64(r.off))
		if err := w(hdr[:]); err != nil {
			return err
		}
		binary.BigEndian.PutUint64(hdr[:], uint64(r.length))
		if err := w(hdr[:]); err != nil {
			return err
		}
		if err := w(buf[:r.length]); err != nil {
			return err
		}
	}
	return fsync(j)
}

// rollbackJournal restores the target file to its pre-apply content from
// the journal, then removes the journal. Idempotent: a second run finds no
// journal and does nothing.
func rollbackJournal(path string) error {
	j, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer j.Close()

	magic := make([]byte, len(journalMagic))
	if _, err := io.ReadFull(j, magic); err != nil || string(magic) != journalMagic {
		return errorf("io", "journal %s: bad magic", path)
	}
	readU64 := func() (int64, error) {
		var b [8]byte
		if _, err := io.ReadFull(j, b[:]); err != nil {
			return 0, err
		}
		return int64(binary.BigEndian.Uint64(b[:])), nil
	}
	nameLen, err := readU64()
	if err != nil {
		return err
	}
	nameBuf := make([]byte, nameLen)
	if _, err := io.ReadFull(j, nameBuf); err != nil {
		return err
	}
	target := string(nameBuf)
	origSize, err := readU64()
	if err != nil {
		return err
	}
	if _, err := readU64(); err != nil { // finalSize, unused on rollback
		return err
	}
	count, err := readU64()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(target, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	err = withDisconnectGuard(func() error {
		for k := int64(0); k < count; k++ {
			off, err := readU64()
			if err != nil {
				return err
			}
			length, err := readU64()
			if err != nil {
				return err
			}
			data := make([]byte, length)
			if _, err := io.ReadFull(j, data); err != nil {
				return err
			}
			if _, err := f.WriteAt(data, off); err != nil {
				return err
			}
		}
		// Undo any growth: the file must end at its pre-apply size.
		if err := f.Truncate(origSize); err != nil {
			return err
		}
		return fsync(f)
	})
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// rollbackJournalsFor rolls back every journal that belongs to `abs`
// (there should be at most one). logf may be nil.
func rollbackJournalsFor(abs string, logf func(string, ...any)) error {
	dir, name := filepath.Split(abs)
	matches, _ := filepath.Glob(filepath.Join(dir, "."+name+journalSuffix+"*"))
	for _, m := range matches {
		if logf != nil {
			logf("recover: rolling back interrupted apply of %s (%s)", abs, filepath.Base(m))
		}
		if err := rollbackJournal(m); err != nil {
			return err
		}
	}
	return nil
}

// RecoverResult is one recovered file, reported by Recover.
type RecoverResult struct {
	T      string `json:"t"` // "recover"
	Target string `json:"target"`
	Rolled bool   `json:"rolled_back"`
}

// Recover sweeps a directory (recursively) for rollback journals left by an
// interrupted in-place apply and rolls each one back, returning what it
// touched. uSSH calls it on reconnect so a torn file becomes fully-old
// again without waiting for the next edit to that file.
func Recover(root string) ([]RecoverResult, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var out []RecoverResult
	err = filepath.WalkDir(abs, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !isJournalName(name) {
			return nil
		}
		target, jerr := journalTarget(path)
		if rerr := rollbackJournal(path); rerr != nil {
			out = append(out, RecoverResult{T: "recover", Target: target, Rolled: false})
			return nil
		}
		_ = jerr
		out = append(out, RecoverResult{T: "recover", Target: target, Rolled: true})
		return nil
	})
	return out, err
}

func isJournalName(name string) bool {
	// .<something>.ussh-delta-journal-<hex>
	i := indexOf(name, journalSuffix)
	return len(name) > 0 && name[0] == '.' && i > 0
}

func journalTarget(path string) (string, error) {
	j, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer j.Close()
	magic := make([]byte, len(journalMagic))
	if _, err := io.ReadFull(j, magic); err != nil || string(magic) != journalMagic {
		return "", errorf("io", "bad journal")
	}
	var b [8]byte
	if _, err := io.ReadFull(j, b[:]); err != nil {
		return "", err
	}
	nameBuf := make([]byte, binary.BigEndian.Uint64(b[:]))
	if _, err := io.ReadFull(j, nameBuf); err != nil {
		return "", err
	}
	return string(nameBuf), nil
}

func fileDigest(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fsync(f *os.File) error { return f.Sync() }

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
