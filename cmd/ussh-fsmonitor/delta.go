package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ivahos/ussh-fsmonitor/internal/delta"
)

// The delta subcommands (hash / clone / commit / recover) share the binary
// with the feed so a host needs one helper, one signature, one version.
// Each is a one-shot: run, print JSON lines, exit — no stdin protocol.
// uSSH writes the changed blocks (to a clone, or a patch file) itself over
// SFTP, so the helper never receives file content from the app.

func runDelta(cmd string, args []string) {
	logf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "ussh-fsmonitor: "+format+"\n", a...)
	}
	if cmd == "recover" {
		runRecover(args, logf)
		return
	}
	if cmd == "stat" {
		runStat(args)
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	file := fs.String("file", "", "the file (required)")
	var (
		block   = fs.Int64("block", delta.DefaultBlock, "block size in bytes (hash, commit --in-place)")
		from    = fs.String("from", "", "the patched clone to rename over --file (commit, rename mode)")
		inPlace = fs.Bool("in-place", false, "apply --patch to --file in place, preserving the inode (commit)")
		patch   = fs.String("patch", "", "file of the changed blocks' new bytes, index order (commit --in-place)")
		indices = fs.String("indices", "", "file of changed block indices, ascending (commit --in-place)")
		size    = fs.Int64("size", -1, "final size of the file (commit, required)")
		sha     = fs.String("sha256", "", "expected whole-file digest, hex (commit)")
		mtimeS  = fs.Int64("mtime-s", -1, "mtime to stamp, seconds (commit)")
		mtimeN  = fs.Int64("mtime-ns", 0, "mtime to stamp, nanoseconds part (commit)")
		baseSz  = fs.Int64("base-size", -1, "the file's size at hash time (clone, commit)")
		baseS   = fs.Int64("base-mtime-s", -1, "the file's mtime seconds at hash time (clone, commit)")
		baseN   = fs.Int64("base-mtime-ns", -1, "the file's mtime nanoseconds at hash time (clone, commit)")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: ussh-fsmonitor %s --file F [flags]\n", cmd)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if *file == "" {
		fs.Usage()
		os.Exit(2)
	}
	var base *delta.Stat
	if *baseSz >= 0 || *baseS >= 0 || *baseN >= 0 {
		if *baseSz < 0 || *baseS < 0 || *baseN < 0 {
			fail(delta.AsError(fmt.Errorf("usage: --base-size, --base-mtime-s and --base-mtime-ns go together")), 2)
		}
		base = &delta.Stat{Size: *baseSz, MtimeS: *baseS, MtimeNS: *baseN}
	}
	var mtime *time.Time
	if *mtimeS >= 0 {
		t := time.Unix(*mtimeS, *mtimeN)
		mtime = &t
	}
	enc := json.NewEncoder(os.Stdout)
	switch cmd {
	case "hash":
		if err := delta.Hash(*file, *block, os.Stdout); err != nil {
			fail(delta.AsError(err), 1)
		}
	case "clone":
		res, err := delta.Clone(*file, base, logf)
		if err != nil {
			fail(delta.AsError(err), 1)
		}
		_ = enc.Encode(res)
	case "commit":
		if *size < 0 {
			fs.Usage()
			os.Exit(2)
		}
		if *inPlace {
			if *patch == "" || *indices == "" {
				fail(delta.AsError(fmt.Errorf("usage: commit --in-place needs --patch and --indices")), 2)
			}
			idx, err := readIndices(*indices)
			if err != nil {
				fail(delta.AsError(err), 2)
			}
			res, err := delta.InPlaceCommit(delta.InPlaceRequest{
				File: *file, Patch: *patch, Block: *block, Indices: idx,
				FinalSize: *size, SHA256: *sha, Mtime: mtime, Base: base,
			})
			if err != nil {
				fail(delta.AsError(err), 1)
			}
			_ = enc.Encode(res)
			return
		}
		if *from == "" {
			fs.Usage()
			os.Exit(2)
		}
		res, err := delta.Commit(delta.CommitRequest{
			File: *file, From: *from, Size: *size, SHA256: *sha, Mtime: mtime, Base: base,
		})
		if err != nil {
			fail(delta.AsError(err), 1)
		}
		_ = enc.Encode(res)
	}
}

// recover sweeps a directory for rollback journals left by an interrupted
// in-place apply and rolls each back to the pre-edit content. uSSH runs it
// on reconnect so a torn file becomes fully-old without waiting for the
// next edit to that file.
func runRecover(args []string, logf func(string, ...any)) {
	fs := flag.NewFlagSet("recover", flag.ExitOnError)
	root := fs.String("root", "", "directory to sweep, recursively (required)")
	_ = fs.Parse(args)
	if *root == "" {
		fmt.Fprintln(os.Stderr, "usage: ussh-fsmonitor recover --root DIR")
		os.Exit(2)
	}
	results, err := delta.Recover(*root)
	if err != nil {
		fail(delta.AsError(err), 1)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, r := range results {
		_ = enc.Encode(r)
	}
}

// stat prints one file's size, mtime and hard-link count as JSON — the
// cheap probe uSSH uses to auto-detect hard-linked files.
func runStat(args []string) {
	fs := flag.NewFlagSet("stat", flag.ExitOnError)
	file := fs.String("file", "", "the file (required)")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "usage: ussh-fsmonitor stat --file F")
		os.Exit(2)
	}
	res, err := delta.StatFile(*file)
	if err != nil {
		fail(delta.AsError(err), 1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(res)
}

// readIndices parses ascending block indices from a file (whitespace- or
// comma-separated), the map that says which blocks --patch carries.
func readIndices(path string) ([]int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var idx []int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	sc.Split(bufio.ScanWords)
	for sc.Scan() {
		for _, tok := range strings.Split(sc.Text(), ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			n, err := strconv.ParseInt(tok, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("bad index %q", tok)
			}
			idx = append(idx, n)
		}
	}
	return idx, sc.Err()
}

// fail prints the error as the command's last stdout line (the app reads
// stdout) and on stderr, then exits. Usage errors exit 2; guard failures
// ("changed", "mismatch") and I/O errors exit 1.
func fail(e *delta.Error, code int) {
	_ = json.NewEncoder(os.Stdout).Encode(e)
	fmt.Fprintf(os.Stderr, "ussh-fsmonitor: %s\n", e.Error())
	os.Exit(code)
}
