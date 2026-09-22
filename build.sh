#!/bin/bash

BINFILE=drydock
if [ -n "$MSYSTEM" ]; then
    BINFILE=drydock.exe
fi
VERSION=$(git describe --tags)
echo "Building $VERSION..."
go build -o $BINFILE -ldflags "-X github.com/drydock-updater/drydock/internal/meta.Version=$VERSION"
