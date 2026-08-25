// Package version carries the build identity stamped in at link time
// (see the Makefile) and renders the statement the helper reports for
// `--version`. uSSH compares this text against the signed release
// statement after pushing a binary to a host, so the two must agree on
// field names and order.
package version

import "fmt"

// Protocol is the stdout protocol generation this build speaks. Bump only
// on incompatible changes; uSSH refuses helpers outside its supported range.
const Protocol = 1

var (
	// Version is the release version (semver), "dev" for local builds.
	Version = "dev"
	// Target is the distribution target, e.g. "linux-amd64" or
	// "darwin-universal" (both slices of a universal binary carry the same).
	Target = "unknown"
	// GitCommit is the short commit the binary was built from, "-dirty"
	// when the tree had uncommitted changes.
	GitCommit = "unknown"
)

// Statement is the human- and machine-readable identity block.
func Statement() string {
	return fmt.Sprintf("ussh-fsmonitor %s\nprotocol %d\ntarget %s\ncommit %s\n",
		Version, Protocol, Target, GitCommit)
}
