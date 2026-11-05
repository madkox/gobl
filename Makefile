# Defaults to the git tag (e.g. v0.1.0, or v0.1.0-3-gabc1234 between tags).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
export GOTOOLCHAIN := local
export CGO_ENABLED := 0

.PHONY: build test integration vet clean

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/gobl ./cmd/gobl

test:
	go test ./...

vet:
	go vet ./...

integration: build
	test/integration.sh bin/gobl

clean:
	rm -rf bin
