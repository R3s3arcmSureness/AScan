@echo off
echo ========================================
echo  AScan - Cross-Platform Build
echo ========================================
echo.

set GO_BIN="C:\Program Files\Go\bin\go.exe"

echo [1/5] Building Windows amd64...
%GO_BIN% build -o bin\ascan-windows-amd64.exe .
echo [2/5] Building Windows arm64...
set GOOS=windows
set GOARCH=arm64
%GO_BIN% build -o bin\ascan-windows-arm64.exe .
echo [3/5] Building Linux amd64...
set GOOS=linux
set GOARCH=amd64
%GO_BIN% build -o bin\ascan-linux-amd64 .
echo [4/5] Building macOS amd64...
set GOOS=darwin
set GOARCH=amd64
%GO_BIN% build -o bin\ascan-darwin-amd64 .
echo [5/5] Building macOS arm64...
set GOOS=darwin
set GOARCH=arm64
%GO_BIN% build -o bin\ascan-darwin-arm64 .

echo.
echo All builds complete! Output in bin\ directory.
dir /b bin\
