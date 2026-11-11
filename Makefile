BINARY_NAME := xray-panel-server
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)

.PHONY: all build build-linux-amd64 build-linux-arm64 test clean

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/server

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/server

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/server

release: build-linux-amd64 build-linux-arm64

test:
	go test -v ./...

clean:
	rm -rf bin/
