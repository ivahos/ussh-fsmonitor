// ussh-fsmonitor streams file-system changes under one directory as
// newline-delimited JSON on stdout, for uSSH's Finder & Files integration.
// It is started by uSSH over an SSH exec channel as the session user, never
// escalates, writes nothing but stdout/stderr, and exits when stdin closes.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ivahos/ussh-fsmonitor/internal/protocol"
	"github.com/ivahos/ussh-fsmonitor/internal/selftest"
	"github.com/ivahos/ussh-fsmonitor/internal/version"
	"github.com/ivahos/ussh-fsmonitor/internal/watch"
)

func main() {
	root := flag.String("root", "", "directory to watch (required unless --version/--selftest)")
	window := flag.Duration("coalesce", 200*time.Millisecond, "batching window for change events")
	showVersion := flag.Bool("version", false, "print the build statement and exit")
	runSelftest := flag.Bool("selftest", false, "exercise the watcher on a temporary tree and exit")
	flag.Parse()

	logf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "ussh-fsmonitor: "+format+"\n", a...)
	}

	switch {
	case *showVersion:
		fmt.Print(version.Statement())
		return
	case *runSelftest:
		if err := selftest.Run(logf); err != nil {
			logf("%v", err)
			os.Exit(1)
		}
		return
	case *root == "":
		flag.Usage()
		os.Exit(2)
	}

	abs, err := filepath.Abs(*root)
	if err == nil {
		abs, err = filepath.EvalSymlinks(abs)
	}
	if err != nil {
		logf("root: %v", err)
		os.Exit(1)
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		logf("root %s is not a directory", abs)
		os.Exit(1)
	}

	w, err := watch.New(abs, logf)
	if err != nil {
		logf("%v", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Lifetime = the exec channel: when uSSH closes stdin (drop, reconnect,
	// disabling the feed) we leave, taking nothing with us.
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		cancel()
	}()

	bw := bufio.NewWriter(os.Stdout)
	pw := protocol.NewWriter(bw)
	emit := func(v any) {
		if err := pw.Write(v); err != nil {
			cancel()
			return
		}
		if err := bw.Flush(); err != nil {
			cancel()
		}
	}
	emit(protocol.Handshake{V: protocol.Version, Caps: w.Caps(), Root: abs, Version: version.Version})

	co := &watch.Coalescer{Window: *window, Emit: func(batch []watch.Change) {
		for _, c := range batch {
			switch c.Kind {
			case watch.Overflow:
				emit(protocol.Event{T: protocol.Overflow})
			case watch.Deleted:
				emit(protocol.Event{T: protocol.Deleted, P: c.Path})
			default:
				emit(protocol.Event{T: protocol.Modified, P: c.Path})
			}
		}
	}}

	raw := make(chan watch.Change, 4096)
	errc := make(chan error, 1)
	go func() { errc <- w.Run(ctx, raw) }()

	ping := time.NewTicker(protocol.PingInterval)
	defer ping.Stop()
	for {
		select {
		case c := <-raw:
			co.Add(c)
		case <-ping.C:
			emit(protocol.Event{T: protocol.Ping})
		case err := <-errc:
			co.Flush()
			if err != nil && ctx.Err() == nil {
				logf("watcher failed: %v", err)
				os.Exit(1)
			}
			return
		case <-ctx.Done():
			co.Flush()
			<-errc
			return
		}
	}
}
