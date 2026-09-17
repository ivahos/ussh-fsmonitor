// Package delta is the host half of uSSH's block-delta uploads: the three
// one-shot commands the app runs over an exec channel around a large file
// it is about to replace.
//
//	hash    per-block SHA-256 of the current file (+ the whole-file digest)
//	clone   a private copy of the file next to it, reflinked when the
//	        filesystem can, so the app can write only the changed blocks
//	        into the copy over plain SFTP
//	commit  verify the copy (size, digest), stamp its mtime, and rename it
//	        over the original — the file is never patched in place, so a
//	        dropped connection leaves the original untouched
//
// Every command guards against the file changing underneath: the stat
// taken at hash time (size + mtime) travels back in as --base-* and a
// mismatch refuses the operation. Output is one JSON object per line on
// stdout, like the feed; hash's block digests are bare hex lines between
// its header and its trailer so a 100 GB file's 100 000 digests stay
// small and trivially parsed.
package delta

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// DefaultBlock is the block size when the caller gives none: 1 MiB suits
// in-place writers (disk images, databases) and keeps a 4.5 GB image's
// digest list under 300 KB of text.
const DefaultBlock = 1 << 20

// Stat is the identity the guards compare: size plus mtime split into
// seconds and nanoseconds, so it survives JSON parsers that round large
// integers to doubles.
type Stat struct {
	Size    int64 `json:"size"`
	MtimeS  int64 `json:"mtime_s"`
	MtimeNS int64 `json:"mtime_ns"`
}

func statOf(fi os.FileInfo) Stat {
	m := fi.ModTime()
	return Stat{Size: fi.Size(), MtimeS: m.Unix(), MtimeNS: int64(m.Nanosecond())}
}

func (s Stat) equal(o Stat) bool {
	return s.Size == o.Size && s.MtimeS == o.MtimeS && s.MtimeNS == o.MtimeNS
}

// Error is what the commands report on stdout before a non-zero exit.
type Error struct {
	T    string `json:"t"`    // always "error"
	Code string `json:"code"` // usage | changed | mismatch | io
	Msg  string `json:"msg"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errorf(code, format string, a ...any) error {
	return &Error{T: "error", Code: code, Msg: fmt.Sprintf(format, a...)}
}

// AsError wraps any failure as an Error for the caller to print.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{T: "error", Code: "io", Msg: err.Error()}
}

// HashHeader opens hash's output.
type HashHeader struct {
	V    int    `json:"v"`
	T    string `json:"t"` // "hash"
	File string `json:"file"`
	Stat
	Block  int64  `json:"block"`
	Blocks int64  `json:"blocks"`
	Alg    string `json:"alg"` // "sha256"
}

// HashTrailer closes it, with the digest of the whole file and the stat
// re-taken after the read (equal to the header's, or hash failed).
type HashTrailer struct {
	T      string `json:"t"` // "done"
	SHA256 string `json:"sha256"`
	Stat
}

// Hash writes the header, one lowercase hex SHA-256 per block, and the
// trailer. The file must not change while it is read: size or mtime
// moving between the opening and closing stat fails the command, because
// digests of a moving target would let the client patch the wrong bytes.
func Hash(path string, block int64, out io.Writer) error {
	if block <= 0 {
		block = DefaultBlock
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	f, err := os.Open(abs)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errorf("usage", "%s is not a regular file", abs)
	}
	before := statOf(fi)
	blocks := (before.Size + block - 1) / block
	enc := json.NewEncoder(out)
	if err := enc.Encode(HashHeader{V: 1, T: "hash", File: abs, Stat: before, Block: block, Blocks: blocks, Alg: "sha256"}); err != nil {
		return err
	}
	whole := sha256.New()
	buf := make([]byte, block)
	var read int64
	for i := int64(0); i < blocks; i++ {
		n, err := io.ReadFull(f, buf)
		if err == io.ErrUnexpectedEOF && i == blocks-1 && n > 0 {
			err = nil
		}
		if err != nil {
			return errorf("io", "read block %d: %v", i, err)
		}
		read += int64(n)
		sum := sha256.Sum256(buf[:n])
		whole.Write(buf[:n])
		if _, err := fmt.Fprintf(out, "%s\n", hex.EncodeToString(sum[:])); err != nil {
			return err
		}
	}
	fi, err = f.Stat()
	if err != nil {
		return err
	}
	after := statOf(fi)
	if !after.equal(before) || read != before.Size {
		return errorf("changed", "%s changed while it was being hashed (size %d→%d)", abs, before.Size, after.Size)
	}
	return enc.Encode(HashTrailer{T: "done", SHA256: hex.EncodeToString(whole.Sum(nil)), Stat: after})
}

// CloneResult is clone's one output line.
type CloneResult struct {
	T      string `json:"t"` // "clone"
	Path   string `json:"path"`
	Method string `json:"method"` // reflink | copy
	Stat
}

// Clone makes a private copy of the file in the same directory (so the
// final rename is atomic and stays on one filesystem), named
// .<name>.ussh-delta-<random>, with the original's permission bits. A
// reflink (APFS clonefile, Linux FICLONE on btrfs/XFS) costs nothing;
// anything else falls back to a byte copy. With a base stat, the file
// must still match it.
func Clone(path string, base *Stat) (*CloneResult, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errorf("usage", "%s is not a regular file", abs)
	}
	current := statOf(fi)
	if base != nil && !base.equal(current) {
		return nil, errorf("changed", "%s changed since it was hashed", abs)
	}
	dst, err := tempName(abs)
	if err != nil {
		return nil, err
	}
	method := "reflink"
	if err := reflinkFn(abs, dst); err != nil {
		method = "copy"
		if err := byteCopy(abs, dst, fi.Mode().Perm()); err != nil {
			os.Remove(dst)
			return nil, errorf("io", "copy %s: %v", abs, err)
		}
	}
	if err := os.Chmod(dst, fi.Mode().Perm()); err != nil {
		os.Remove(dst)
		return nil, err
	}
	cfi, err := os.Stat(dst)
	if err != nil {
		os.Remove(dst)
		return nil, err
	}
	return &CloneResult{T: "clone", Path: dst, Method: method, Stat: statOf(cfi)}, nil
}

// reflinkFn is the platform clone (clone_*.go); tests swap it out to
// exercise the byte-copy fallback, which macOS's APFS never takes.
var reflinkFn = reflink

func tempName(abs string) (string, error) {
	var r [6]byte
	if _, err := rand.Read(r[:]); err != nil {
		return "", err
	}
	dir, name := filepath.Split(abs)
	return filepath.Join(dir, "."+name+".ussh-delta-"+hex.EncodeToString(r[:])), nil
}

func byteCopy(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// CommitRequest is what commit checks before the rename.
type CommitRequest struct {
	File string // the original
	From string // the clone, patched by the client
	// Size the clone must end up with: larger is truncated (the client
	// may have shrunk the file), smaller is an error (blocks are missing).
	Size int64
	// Expected whole-file digest of the clone, hex; "" skips the check.
	SHA256 string
	// mtime to stamp, nil keeps the clone's current one.
	Mtime *time.Time
	// The original's stat at hash time; nil skips the guard.
	Base *Stat
}

// CommitResult is commit's one output line.
type CommitResult struct {
	T      string `json:"t"` // "done"
	File   string `json:"file"`
	SHA256 string `json:"sha256,omitempty"`
	Stat
}

// Commit verifies the patched clone and renames it over the original.
// On any failure the clone is removed and the original is untouched.
func Commit(req CommitRequest) (*CommitResult, error) {
	abs, err := filepath.Abs(req.File)
	if err != nil {
		return nil, err
	}
	from, err := filepath.Abs(req.From)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*CommitResult, error) {
		os.Remove(from)
		return nil, err
	}
	if filepath.Dir(from) != filepath.Dir(abs) {
		return nil, errorf("usage", "%s is not next to %s", from, abs)
	}
	if req.Base != nil {
		fi, err := os.Stat(abs)
		if err != nil {
			return fail(err)
		}
		if !req.Base.equal(statOf(fi)) {
			return fail(errorf("changed", "%s changed since it was hashed — not replacing it", abs))
		}
	}
	f, err := os.OpenFile(from, os.O_RDWR, 0)
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !fi.Mode().IsRegular() {
		return fail(errorf("usage", "%s is not a regular file", from))
	}
	switch {
	case fi.Size() < req.Size:
		return fail(errorf("mismatch", "clone is %d bytes, %d expected — blocks missing", fi.Size(), req.Size))
	case fi.Size() > req.Size:
		if err := f.Truncate(req.Size); err != nil {
			return fail(err)
		}
	}
	digest := ""
	if req.SHA256 != "" {
		h := sha256.New()
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return fail(err)
		}
		if _, err := io.Copy(h, f); err != nil {
			return fail(err)
		}
		digest = hex.EncodeToString(h.Sum(nil))
		if digest != req.SHA256 {
			return fail(errorf("mismatch", "clone digest %s, %s expected — not replacing %s", digest, req.SHA256, abs))
		}
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if req.Mtime != nil {
		if err := os.Chtimes(from, *req.Mtime, *req.Mtime); err != nil {
			return fail(err)
		}
	}
	if err := os.Rename(from, abs); err != nil {
		return fail(err)
	}
	syncDir(filepath.Dir(abs))
	fi, err = os.Stat(abs)
	if err != nil {
		return nil, err
	}
	return &CommitResult{T: "done", File: abs, SHA256: digest, Stat: statOf(fi)}, nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
