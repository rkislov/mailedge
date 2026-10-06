.PHONY: build test clean run fmt vet wallpapers release-binaries

BINARY := mgw
CMD := ./cmd/mgw
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-s -w -X github.com/rkislov/mailedge/internal/version.Version=$(VERSION)"
DIST := dist

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) $(CMD)

test:
	CGO_ENABLED=0 go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

# Full Retina wallpaper pack → wallpapers/mgw-wallpaper-pack.zip
wallpapers:
	chmod +x wallpapers/export.sh
	./wallpapers/export.sh

# Cross-compiled release binaries for GitHub Releases
release-binaries:
	@mkdir -p $(DIST)
	@for os in linux darwin freebsd; do \
	  for arch in amd64 arm64; do \
	    out=$(DIST)/mgw-$(VERSION)-$$os-$$arch; \
	    echo "→ $$out"; \
	    GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(LDFLAGS) -o $$out $(CMD); \
	    (cd $(DIST) && shasum -a 256 $$(basename $$out) > $$(basename $$out).sha256); \
	  done; \
	done

clean:
	rm -f $(BINARY)
	rm -rf $(DIST)

run: build
	./$(BINARY) server start --config configs/config.example.yaml
