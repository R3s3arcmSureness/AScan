#!/bin/bash
set -e
echo "========================================"
echo "  AScan - Cross-Platform Build"
echo "========================================"
echo ""

mkdir -p bin

echo "[1/5] Building Windows amd64..."
GOOS=windows GOARCH=amd64 go build -o bin/ascan-windows-amd64.exe .

echo "[2/5] Building Windows arm64..."
GOOS=windows GOARCH=arm64 go build -o bin/ascan-windows-arm64.exe .

echo "[3/5] Building Linux amd64..."
GOOS=linux GOARCH=amd64 go build -o bin/ascan-linux-amd64 .

echo "[4/5] Building macOS amd64..."
GOOS=darwin GOARCH=amd64 go build -o bin/ascan-darwin-amd64 .

echo "[5/5] Building macOS arm64..."
GOOS=darwin GOARCH=arm64 go build -o bin/ascan-darwin-arm64 .

echo ""
echo "All builds complete! Output in bin/ directory."
ls -la bin/
