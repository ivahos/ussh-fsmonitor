# ussh-fsmonitor — build, statement, sign, release.
#
#   make              build for this machine into ./bin (dev)
#   make selftest     build + run the watcher self-test here
#   make release      all targets into dist/<VERSION>/ with statements
#   make sign         sign every statement on the YubiKey (dnseditd cmd/sign --gpg)
#   make verify       verify every statement + binary with ./cmd/verify
#   make install      publish the signed dist to the web share + update latest
#   make dns          print the DNS records a release needs
#
# Ship order: release -> sign -> verify -> install (-> publish the dns TXT).
#
# Release binaries are stamped with VERSION, TARGET and the git commit
# ("-dirty" if the tree isn't clean). uSSH compares `--version` output on a
# host against the signed statement it verified before pushing.

MODULE   := github.com/ivahos/ussh-fsmonitor
VERSION  ?= 0.3.0
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DIRTY    := $(shell git diff --quiet -- cmd internal go.mod go.sum 2>/dev/null || echo -dirty)
DIST     := dist/$(VERSION)
# Signing uses the same Ed25519 key and format as dnseditd installers:
# SHA-256 of the statement, Ed25519-signed on the YubiKey (GPG smart card),
# signature appended after a __SIGNATURE__ marker. The signer lives in the
# private dnseditd tree; the public verifier is ./cmd/verify.
SIGN_TOOL   ?= $(HOME)/Desktop/Xcode/DnsEditor/dnseditd/cmd/sign
RELEASE_KEY := $(shell cat RELEASE_KEY.hex)

ldflags = -s -w \
  -X $(MODULE)/internal/version.Version=$(VERSION) \
  -X $(MODULE)/internal/version.Target=$(1) \
  -X $(MODULE)/internal/version.GitCommit=$(COMMIT)$(DIRTY)

.PHONY: all dev selftest release darwin linux statements sign verify install clean

# Live web share (SMB). `latest` is a plain file holding the version string,
# not a symlink — uSSH reads it as text (the signed _release TXT is the real
# source of truth); serving a symlink would break that fetch.
WEBHOST ?= /Volumes/Web/ussh.au
WEBROOT := $(WEBHOST)/fsmonitor
# Source-of-truth mirror in the macterm repo's website tree (kept under git and
# deployed with the rest of the site); install copies the release here too so
# the two never drift.
MIRROR  ?= $(HOME)/Desktop/Xcode/macterm/website/fsmonitor

all: dev

dev:
	@mkdir -p bin
	go build -trimpath -ldflags "$(call ldflags,dev-$(shell go env GOOS)-$(shell go env GOARCH))" -o bin/ussh-fsmonitor ./cmd/ussh-fsmonitor

selftest: dev
	./bin/ussh-fsmonitor --selftest

release: darwin linux statements
	@echo; echo "release $(VERSION) ($(COMMIT)$(DIRTY)) in $(DIST):"; ls -l $(DIST)
	@$(MAKE) --no-print-directory dns

# uSSH cannot write DNS itself (no dnseditd behind it), so every release
# prints the records to publish by hand. The pointer is what uSSH resolves
# — DNSSEC-validated — to learn the current version before it downloads
# from https://ussh.au/fsmonitor/<version>/; the key record already exists
# and only changes on rotation.
dns:
	@echo
	@echo "DNS records to publish (zone ussh.au, DNSSEC-signed):"
	@echo
	@echo "_release._ussh-fsmonitor.ussh.au. 300 IN TXT \"version=$(VERSION) protocol=$$(go run ./cmd/ussh-fsmonitor --version 2>/dev/null | awk '/^protocol/{print $$2}') built=$$(date -u +%Y-%m-%d)\""
	@echo
	@echo "Unchanged unless the key rotates (zone dnsedit.au):"
	@echo "_signing._dnseditd.dnsedit.au. TXT \"pubkey=$(RELEASE_KEY)\""
	@echo

darwin:
	@mkdir -p $(DIST) build
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(call ldflags,darwin-universal)" -o build/darwin-arm64 ./cmd/ussh-fsmonitor
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$(call ldflags,darwin-universal)" -o build/darwin-amd64 ./cmd/ussh-fsmonitor
	lipo -create build/darwin-arm64 build/darwin-amd64 -output $(DIST)/ussh-fsmonitor-darwin-universal
	codesign --force --sign - $(DIST)/ussh-fsmonitor-darwin-universal

linux:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(call ldflags,linux-amd64)" -o $(DIST)/ussh-fsmonitor-linux-amd64 ./cmd/ussh-fsmonitor
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(call ldflags,linux-arm64)" -o $(DIST)/ussh-fsmonitor-linux-arm64 ./cmd/ussh-fsmonitor

# One statement per binary: what it is, for which target, and its digest.
# This text is what gets signed; the binary's own --version prints the
# first four lines so a host copy can be matched back to it.
statements:
	@for f in $(DIST)/ussh-fsmonitor-*; do \
	  case $$f in *.statement|*.sig) continue;; esac; \
	  t=$${f##*/ussh-fsmonitor-}; \
	  printf 'ussh-fsmonitor %s\nprotocol %s\ntarget %s\ncommit %s\nsha256 %s\nbuilt %s\n' \
	    "$(VERSION)" "$$(go run ./cmd/ussh-fsmonitor --version 2>/dev/null | awk '/^protocol/{print $$2}')" \
	    "$$t" "$(COMMIT)$(DIRTY)" "$$(shasum -a 256 $$f | cut -c1-64)" "$$(date -u +%Y-%m-%d)" \
	    > $$f.statement; \
	done; ls $(DIST)/*.statement

# Same ritual as dnseditd's make-installer.sh: pinentry needs GPG_TTY,
# scdaemon is woken with SCD SERIALNO before the first signature, and the
# card is locked again afterwards so the next signing needs the PIN.
sign:
	@test -d "$(SIGN_TOOL)" || { echo "SIGN_TOOL=$(SIGN_TOOL) not found"; exit 1; }
	@export GPG_TTY=$$(tty); \
	gpg-connect-agent "SCD SERIALNO" /bye 2>/dev/null | grep -q '^OK' || { echo "no YubiKey/GPG smart card detected"; exit 1; }; \
	for st in $(DIST)/*.statement; do \
	  grep -q '^__SIGNATURE__$$' $$st && { echo "already signed: $$st"; continue; }; \
	  (cd $(SIGN_TOOL) && go run . --sign --gpg --file $(CURDIR)/$$st) || { echo "signing failed: $$st"; exit 1; }; \
	  echo "signed $$st"; \
	done; \
	gpg-connect-agent "RELOADAGENT" /bye >/dev/null 2>&1; gpgconf --kill scdaemon 2>/dev/null; true

verify:
	@for st in $(DIST)/*.statement; do \
	  go run ./cmd/verify --pub $(RELEASE_KEY) --statement $$st --binary $${st%.statement}; \
	done

# Publish the built + SIGNED dist to the web share: a fresh version directory
# with the six files, then point `latest` at it. Deploys what is in dist/ and
# NEVER rebuilds — a rebuild would overwrite the signed statements with
# unsigned ones. Refuses to publish if a statement is unsigned or the share
# isn't mounted. xattr -c + cp -X keep macOS extended attributes off the SMB
# copy; the darwin binary's embedded codesign is untouched (it isn't an xattr).
install:
	@test -d "$(WEBHOST)" || { echo "web share not mounted: $(WEBHOST)"; exit 1; }
	@test -d "$(DIST)" || { echo "nothing built: $(DIST) — run 'make release' first"; exit 1; }
	@for st in $(DIST)/*.statement; do \
	  grep -q '^__SIGNATURE__$$' "$$st" || { echo "unsigned: $$st — run 'make sign' first"; exit 1; }; \
	done
	@test ! -d "$(WEBROOT)/$(VERSION)" || echo "note: $(WEBROOT)/$(VERSION) exists — overwriting its files"
	mkdir -p "$(WEBROOT)/$(VERSION)"
	xattr -cr $(DIST) 2>/dev/null || true
	cp -X $(DIST)/ussh-fsmonitor-* "$(WEBROOT)/$(VERSION)/"
	printf '%s\n' "$(VERSION)" > "$(WEBROOT)/latest"
	@echo; echo "published $(VERSION) -> $(WEBROOT)/$(VERSION); latest -> $$(cat "$(WEBROOT)/latest")"
	@ls -l "$(WEBROOT)/$(VERSION)"
	@# Keep the repo mirror in sync (skipped, not failed, if the repo is absent).
	@if [ -d "$(dir $(MIRROR))" ]; then \
	  mkdir -p "$(MIRROR)/$(VERSION)"; \
	  cp -X $(DIST)/ussh-fsmonitor-* "$(MIRROR)/$(VERSION)/"; \
	  printf '%s\n' "$(VERSION)" > "$(MIRROR)/latest"; \
	  echo "mirrored -> $(MIRROR)/$(VERSION) (commit it in the macterm repo)"; \
	else \
	  echo "note: repo mirror $(MIRROR) not found — live share updated only"; \
	fi

clean:
	rm -rf bin build dist
