.PHONY: build test clean run fmt vet wallpapers

BINARY := mgw
CMD := ./cmd/mgw
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-s -w -X github.com/rkislov/mailedge/internal/version.Version=$(VERSION)"

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

clean:
	rm -f $(BINARY)

run: build
	./$(BINARY) server start --config configs/config.example.yaml
