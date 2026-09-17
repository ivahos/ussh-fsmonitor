package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ivahos/ussh-fsmonitor/internal/delta"
)

// The delta subcommands (hash / clone / commit) share the binary with the
// feed so a host needs one helper, one signature, one version. Each is a
// one-shot: run, print JSON lines, exit — no stdin protocol, no daemon.
// uSSH writes the changed blocks into the clone itself over SFTP between
// clone and commit, so the helper never sees file content from the app.

func runDelta(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	file := fs.String("file", "", "the file (required)")
	var (
		block  = fs.Int64("block", delta.DefaultBlock, "block size in bytes (hash)")
		from   = fs.String("from", "", "the patched clone to rename over --file (commit)")
		size   = fs.Int64("size", -1, "final size of the clone (commit, required)")
		sha    = fs.String("sha256", "", "expected whole-file digest of the clone, hex (commit)")
		mtimeS = fs.Int64("mtime-s", -1, "mtime to stamp, seconds (commit)")
		mtimeN = fs.Int64("mtime-ns", 0, "mtime to stamp, nanoseconds part (commit)")
		baseSz = fs.Int64("base-size", -1, "the file's size at hash time (clone, commit)")
		baseS  = fs.Int64("base-mtime-s", -1, "the file's mtime seconds at hash time (clone, commit)")
		baseN  = fs.Int64("base-mtime-ns", -1, "the file's mtime nanoseconds at hash time (clone, commit)")
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
	enc := json.NewEncoder(os.Stdout)
	switch cmd {
	case "hash":
		if err := delta.Hash(*file, *block, os.Stdout); err != nil {
			fail(delta.AsError(err), 1)
		}
	case "clone":
		res, err := delta.Clone(*file, base)
		if err != nil {
			fail(delta.AsError(err), 1)
		}
		_ = enc.Encode(res)
	case "commit":
		if *from == "" || *size < 0 {
			fs.Usage()
			os.Exit(2)
		}
		req := delta.CommitRequest{File: *file, From: *from, Size: *size, SHA256: *sha, Base: base}
		if *mtimeS >= 0 {
			t := time.Unix(*mtimeS, *mtimeN)
			req.Mtime = &t
		}
		res, err := delta.Commit(req)
		if err != nil {
			fail(delta.AsError(err), 1)
		}
		_ = enc.Encode(res)
	}
}

// fail prints the error as the command's last stdout line (the app reads
// stdout) and on stderr (for a human), then exits. Usage errors exit 2,
// guard failures ("changed", "mismatch") and I/O errors exit 1.
func fail(e *delta.Error, code int) {
	_ = json.NewEncoder(os.Stdout).Encode(e)
	fmt.Fprintf(os.Stderr, "ussh-fsmonitor: %s\n", e.Error())
	os.Exit(code)
}
