# ussh-fsmonitor — build, statement, sign, release.
#
#   make              build for this machine into ./bin (dev)
#   make selftest     build + run the watcher self-test here
#   make release      all targets into dist/<VERSION>/ with statements
#   make sign         SSHSIG-sign every statement with SIGN_KEY (YubiKey touch)
#   make verify       check every signature with stock ssh-keygen
#
# Release binaries are stamped with VERSION, TARGET and the git commit
# ("-dirty" if the tree isn't clean). uSSH compares `--version` output on a
# host against the signed statement it verified before pushing.

MODULE   := github.com/ivahos/ussh-fsmonitor
VERSION  ?= 0.1.0
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DIRTY    := $(shell git diff --quiet -- cmd internal go.mod go.sum 2>/dev/null || echo -dirty)
DIST     := dist/$(VERSION)
SIGN_KEY ?= $(HOME)/.ssh/id_ed25519_sk
NAMESPACE := ussh-fsmonitor

ldflags = -s -w \
  -X $(MODULE)/internal/version.Version=$(VERSION) \
  -X $(MODULE)/internal/version.Target=$(1) \
  -X $(MODULE)/internal/version.GitCommit=$(COMMIT)$(DIRTY)

.PHONY: all dev selftest release darwin linux statements sign verify clean

all: dev

dev:
	@mkdir -p bin
	go build -trimpath -ldflags "$(call ldflags,dev-$(shell go env GOOS)-$(shell go env GOARCH))" -o bin/ussh-fsmonitor ./cmd/ussh-fsmonitor

selftest: dev
	./bin/ussh-fsmonitor --selftest

release: darwin linux statements
	@echo; echo "release $(VERSION) ($(COMMIT)$(DIRTY)) in $(DIST):"; ls -l $(DIST)

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

sign:
	@test -f "$(SIGN_KEY)" || { echo "SIGN_KEY=$(SIGN_KEY) not found"; exit 1; }
	@for s in $(DIST)/*.statement; do \
	  ssh-keygen -Y sign -f $(SIGN_KEY) -n $(NAMESPACE) $$s && echo "signed $$s"; \
	done

# allowed_signers: "ussh-release namespaces="ussh-fsmonitor" ssh-ed25519 AAAA..."
verify:
	@for s in $(DIST)/*.statement; do \
	  ssh-keygen -Y verify -f allowed_signers -I ussh-release -n $(NAMESPACE) -s $$s.sig < $$s && echo "ok $$s"; \
	done

clean:
	rm -rf bin build dist
