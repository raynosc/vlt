#!/bin/bash
# build-all.sh — Compile all vlt binaries for macOS (Apple Silicon + Intel).
# Usage: ./scripts/build-all.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTDIR="${PROJECT_DIR}/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== vlt build script ===${NC}"
echo ""

# Create output directory
mkdir -p "$OUTDIR"

# Platforms to build for
PLATFORMS=("darwin/arm64" "darwin/amd64")

# Binaries to build
BINARIES=(
    "vlt"
    "vlt-gui"
    "vlt-tui"
    "vlt-quick"
    "vlt-sync"
)

# CGO flag for biometric support on darwin
CGO_FLAGS="-tags darwin"

echo -e "${YELLOW}Cleaning previous builds...${NC}"
rm -rf "$OUTDIR"/*

echo ""
echo -e "${YELLOW}Building ${#BINARIES[@]} binaries × ${#PLATFORMS[@]} platforms${NC}"
echo ""

build_binary() {
    local binary="$1"
    local platform="$2"
    local os="${platform%/*}"
    local arch="${platform#*/}"
    local output_name="${binary}-${os}-${arch}"
    if [[ "$os" == "darwin" ]]; then
        output_name="${binary}-macos-${arch}"
    fi

    local output_path="${OUTDIR}/${output_name}"
    local goos="$os"
    local goarch="$arch"

    echo -n "  Building ${YELLOW}${output_name}${NC}... "

    if CGO_ENABLED=1 GOOS="$goos" GOARCH="$goarch" go build \
        -ldflags="-s -w" \
        -o "$output_path" \
        "./cmd/${binary}" 2>&1; then
        local size=$(du -h "$output_path" | cut -f1)
        echo -e "${GREEN}✓${NC} ($size)"
    else
        echo -e "${RED}✗ FAILED${NC}"
        return 1
    fi
}

for binary in "${BINARIES[@]}"; do
    echo -e "${GREEN}▶ ${binary}${NC}"
    for platform in "${PLATFORMS[@]}"; do
        build_binary "$binary" "$platform"
    done
    echo ""
done

echo -e "${YELLOW}=== Build summary ===${NC}"
echo ""
ls -lh "$OUTDIR"/
echo ""
echo -e "${GREEN}All binaries built successfully → ${OUTDIR}/${NC}"