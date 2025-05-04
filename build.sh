#!/usr/bin/env bash

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

go fmt ./...
go get -u ./...
go mod tidy

mkdir -p $SCRIPT_DIR/bin/

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" \
    -o $SCRIPT_DIR/bin/tundler-api $SCRIPT_DIR/cmd/tundler-api