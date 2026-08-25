// verify checks a ussh-fsmonitor release statement and, optionally, the
// binary it describes. It is the public half of the signing scheme shared
// with dnseditd: the statement's payload (everything up to the newline
// before the __SIGNATURE__ marker) is hashed with SHA-256 and that digest
// is signed with Ed25519; the signature follows the marker, base64 on one
// line. The public key is the hex string published, DNSSEC-signed, at
// _signing._dnseditd.dnsedit.au (TXT "pubkey=…"); pass it with --pub.
//
//	verify --pub <hex> --statement ussh-fsmonitor-linux-amd64.statement [--binary ussh-fsmonitor-linux-amd64]
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

const marker = "\n__SIGNATURE__\n"

func main() {
	pubHex := flag.String("pub", "", "hex-encoded Ed25519 public key (from DNS)")
	statement := flag.String("statement", "", "signed .statement file")
	binary := flag.String("binary", "", "optional: binary whose sha256 must match the statement")
	flag.Parse()
	if *pubHex == "" || *statement == "" {
		flag.Usage()
		os.Exit(2)
	}
	pub, err := hex.DecodeString(*pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fail("--pub must be %d hex bytes", ed25519.PublicKeySize)
	}
	content, err := os.ReadFile(*statement)
	if err != nil {
		fail("%v", err)
	}
	idx := bytes.Index(content, []byte(marker))
	if idx < 0 {
		fail("no __SIGNATURE__ marker in %s — unsigned", *statement)
	}
	payload := content[:idx+1]
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(content[idx+len(marker):])))
	if err != nil || len(sig) != ed25519.SignatureSize {
		fail("malformed signature")
	}
	h := sha256.Sum256(payload)
	if !ed25519.Verify(ed25519.PublicKey(pub), h[:], sig) {
		fail("SIGNATURE INVALID for %s", *statement)
	}
	fmt.Printf("signature ok: %s\n", *statement)

	if *binary != "" {
		want := field(string(payload), "sha256")
		b, err := os.ReadFile(*binary)
		if err != nil {
			fail("%v", err)
		}
		sum := sha256.Sum256(b)
		got := hex.EncodeToString(sum[:])
		if got != want {
			fail("BINARY MISMATCH: statement says %s, %s is %s", want, *binary, got)
		}
		fmt.Printf("binary ok: %s (%s)\n", *binary, field(string(payload), "target"))
	}
}

func field(payload, name string) string {
	for _, line := range strings.Split(payload, "\n") {
		if strings.HasPrefix(line, name+" ") {
			return strings.TrimSpace(strings.TrimPrefix(line, name+" "))
		}
	}
	return ""
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "verify: "+format+"\n", a...)
	os.Exit(1)
}
