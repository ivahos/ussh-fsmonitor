# ussh-fsmonitor

The change-feed helper for [uSSH](https://ussh.au)'s Finder & Files
integration. uSSH pushes this small binary to a host you have enabled it
for, runs it over an SSH exec channel **as your own user**, and reads a
stream of file-system changes from its stdout so Finder and the Files app
refresh themselves instead of waiting for a manual resync.

It is published as source so the hosts you run it on can be audited:
what it does is everything it can do.

## What it does — and doesn't

- Watches one directory tree (`--root`) with FSEvents on macOS or inotify
  on Linux and writes one JSON object per line to stdout.
- Or, with one or more `--watch <dir>` (root-relative, `.` = the root),
  watches ONLY those directories, each non-recursively — what uSSH uses
  once it knows which folders are open in Finder or Files, so a busy home
  directory no longer streams every change under it. The handshake carries
  `scoped` when the build understands `--watch`; uSSH restarts the helper
  with a new set as folders open and close.
- Writes nothing else: no files, no sockets, no network, no configuration.
- Runs as whoever started it. It never escalates and needs no privileges
  beyond reading the tree — the same access SFTP already has.
- Exits the moment stdin closes (uSSH disconnects or disables the feed).
  It is never a daemon and never survives the session that started it.
- Reports itself honestly: `overflow` when the kernel dropped events, and
  `partial` in the handshake when a tree exceeds the inotify watch limit.

## Protocol (stdout, newline-delimited JSON)

```
{"v":1,"caps":["inotify"],"root":"/home/ivar","version":"1.0.0"}   handshake, first line
{"t":"mod","p":"src/main.go"}       path changed or appeared (file or directory)
{"t":"del","p":"build"}             path disappeared
{"t":"overflow"}                    events were lost: do a full rescan
{"t":"ping"}                        every 30 s when idle
```

Paths are relative to the root. Bursts are coalesced (`--coalesce`,
default 200 ms) into one line per path. Renames surface as `del` of the
old path and `mod` of the new; creates and modifies are both `mod` — the
consumer re-lists the parent either way. stderr carries diagnostics only.

## Building

```
make            # ./bin/ussh-fsmonitor for this machine
make selftest   # runs the watcher against a temporary tree
make release    # dist/<version>/: darwin-universal, linux-amd64, linux-arm64 + statements
```

The macOS build uses cgo for FSEvents and is a universal binary; the Linux
builds are static (`CGO_ENABLED=0`). Every binary reports its identity:

```
$ ussh-fsmonitor --version
ussh-fsmonitor 1.0.0
protocol 1
target linux-amd64
commit 3f9c2a1
```

## Releases and verification

Each release binary ships with a `.statement` sidecar:

```
ussh-fsmonitor 1.0.0
protocol 1
target linux-amd64
commit 3f9c2a1
sha256 29d808b8…
built 2026-09-02
__SIGNATURE__
<base64 Ed25519 signature>
```

The signature is Ed25519 over the SHA-256 of everything before the
`__SIGNATURE__` line — the same scheme dnseditd installers use, made with
the same key on a hardware token. The public key is not in this repo: it
is published, DNSSEC-signed, as
`_signing._dnseditd.dnsedit.au TXT "pubkey=<hex>"` (with
`outgoing_pubkey=` alongside during a key rotation). uSSH resolves and
validates that record with its own DNSSEC resolver every time it verifies
a statement, checks the digest, and only then pushes the binary to a host
— where `--version` must match the statement's first four lines.

Verify a release yourself with stock tools:

```
dig +short TXT _signing._dnseditd.dnsedit.au           # the key (use a validating resolver)
go run ./cmd/verify --pub <hex> --statement ussh-fsmonitor-linux-amd64.statement \
                    --binary ussh-fsmonitor-linux-amd64
```

## License

Source-available — see [LICENSE](LICENSE). You may inspect, build, and
verify; use is licensed through uSSH.
