# Defaults to the git tag (e.g. v0.1.0, or v0.1.0-3-gabc1234 between tags).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
export GOTOOLCHAIN := local
export CGO_ENABLED := 0

LDFLAGS := -s -w -X main.version=$(VERSION)

# Release targets: <name>:<GOARCH>[:<GOARM>]
DIST_TARGETS := linux_amd64:amd64 linux_arm64:arm64 linux_armv7:arm:7

.PHONY: build test integration vet dist clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gobl ./cmd/gobl

test:
	go test ./...

vet:
	go vet ./...

integration: build
	test/integration.sh bin/gobl

# dist/gobl_<os>_<arch>.tar.gz (binary + docs + packaging files) and
# dist/SHA256SUMS. Asset names carry no version, so
# .../releases/latest/download/gobl_linux_amd64.tar.gz always works.
dist:
	rm -rf dist && mkdir -p dist
	set -e; for t in $(DIST_TARGETS); do \
		name=$${t%%:*}; rest=$${t#*:}; arch=$${rest%%:*}; arm=; \
		case $$rest in *:*) arm=$${rest#*:};; esac; \
		dir=dist/gobl_$$name; mkdir -p $$dir; \
		GOOS=linux GOARCH=$$arch GOARM=$$arm \
			go build -trimpath -ldflags "$(LDFLAGS)" -o $$dir/gobl ./cmd/gobl; \
		cp -r LICENSE README.md packaging $$dir/; \
		tar -C dist --owner=0 --group=0 --mode='u+rwX,go+rX,go-w' -czf dist/gobl_$$name.tar.gz gobl_$$name; \
		rm -rf $$dir; \
	done
	cd dist && sha256sum *.tar.gz > SHA256SUMS

clean:
	rm -rf bin dist
