.PHONY: all build build-signed test test-all build-all build-darwin build-linux build-windows clean fmt lint

# Go parameters
GOCMD      = go
GOBUILD    = $(GOCMD) build
GOTEST     = $(GOCMD) test
GOFMT      = $(GOCMD) fmt
GOVET      = $(GOCMD) vet

# Output directory
BIN_DIR    = bin
BUILD_DIR  = .

# CGO flag for biometric on darwin
CGO_ENABLED = 1

# Binaries
BINARIES   = vlt vlt-gui vlt-tui vlt-quick vlt-sync
LINUX_BINS = vlt vlt-tui vlt-quick vlt-sync

# Platforms
PLATFORMS  = darwin/arm64 darwin/amd64
LINUX_ARCH = amd64 arm64

# Build flags
LDFLAGS    = -s -w

# ── Default ──────────────────────────────────────────────────────────────────

all: test build

# ── Build (Host Platform) ───────────────────────────────────────────────────

build:
	@echo "Building all binaries for current platform..."
	@CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/vlt      ./cmd/vlt
	@CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/vlt-gui   ./cmd/vlt-gui
	@CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/vlt-tui  ./cmd/vlt-tui
	@CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/vlt-quick ./cmd/vlt-quick
	@CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/vlt-sync  ./cmd/vlt-sync
	@echo "Done → $(BIN_DIR)/"

# ── macOS Application Bundle (.app) ──────────────────────────────────────────

app:
	@bash scripts/macos/package-app.sh

install-mac:
	@bash scripts/macos/install-app.sh

uninstall-mac:
	@bash scripts/macos/uninstall-app.sh

# ── Signed build with native biometric Keychain ──────────────────────────────
#
# Builds vlt-gui with the `keychain_biometric` tag, which stores the master key
# in the data-protection Keychain behind a native Touch ID access-control object
# (reading the item itself requires Touch ID). This REQUIRES code signing with a
# keychain-access-groups entitlement — set CODESIGN_IDENTITY to your Developer ID
# and edit build/entitlements.plist with your Team ID first. Unsigned/ad-hoc
# builds fail at runtime with errSecMissingEntitlement (-34018); use plain
# `make build` (software biometric gate) for unsigned development instead.

CODESIGN_IDENTITY ?= -
ENTITLEMENTS      = build/entitlements.plist

build-signed:
	@echo "Building vlt-gui with native biometric Keychain (-tags keychain_biometric)..."
	@CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) -tags keychain_biometric -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/vlt-gui ./cmd/vlt-gui
	@echo "Code signing with identity '$(CODESIGN_IDENTITY)'..."
	@codesign --force --options runtime --entitlements $(ENTITLEMENTS) --sign "$(CODESIGN_IDENTITY)" $(BIN_DIR)/vlt-gui
	@echo "Done → $(BIN_DIR)/vlt-gui (signed)"
	@echo "NOTE: ad-hoc identity '-' will NOT satisfy the data-protection Keychain;"
	@echo "      use a real Developer ID and set CODESIGN_IDENTITY=\"Developer ID Application: ...\"."

# ── Cross-compile all platforms (macOS, Linux, Windows) ──────────────────────

build-all: clean build build-darwin build-linux build-windows
	@echo ""
	@echo "================================================================"
	@echo "All binaries successfully compiled for all platforms:"
	@echo "================================================================"
	@ls -lh $(BIN_DIR)/

# ── Cross-compile for macOS (Darwin) ─────────────────────────────────────────

build-darwin:
	@mkdir -p $(BIN_DIR)
	@echo "Building macOS binaries (arm64, amd64)..."
	@for binary in $(BINARIES); do \
		for platform in $(PLATFORMS); do \
			os=$${platform%/*}; arch=$${platform#*/}; \
			name=$$binary-macos-$$arch; \
			echo -n "  Building $$name... "; \
			CGO_ENABLED=$(CGO_ENABLED) GOOS=$$os GOARCH=$$arch \
				$(GOBUILD) -ldflags="$(LDFLAGS)" \
				-o $(BIN_DIR)/$$name ./cmd/$$binary && echo "✓" || echo "✗"; \
		done; \
	done

# ── Cross-compile for Linux ─────────────────────────────────────────────────

build-linux:
	@mkdir -p $(BIN_DIR)
	@echo "Building Linux binaries (amd64, arm64)..."
	@for binary in $(LINUX_BINS); do \
		for arch in $(LINUX_ARCH); do \
			os=linux; \
			name=$$binary-linux-$$arch; \
			echo -n "  Building $$name... "; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
				$(GOBUILD) -ldflags="$(LDFLAGS)" \
				-o $(BIN_DIR)/$$name ./cmd/$$binary && echo "✓" || echo "✗"; \
		done; \
	done

# ── Cross-compile for Windows ───────────────────────────────────────────────

build-windows:
	@mkdir -p $(BIN_DIR)
	@echo "Building Windows binaries (vlt.exe, vlt-gui.exe, vlt-sync.exe, vlt-tui.exe, vlt-quick.exe)..."
	@echo -n "  Building vlt.exe (CLI)... "
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/vlt.exe ./cmd/vlt && echo "✓" || echo "✗"
	@echo -n "  Building vlt-gui.exe (Desktop GUI)... "
	@CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS) -H=windowsgui" -o $(BIN_DIR)/vlt-gui.exe ./cmd/vlt-gui && echo "✓" || echo "✗"
	@echo -n "  Building vlt-sync.exe (Sync Server)... "
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/vlt-sync.exe ./cmd/vlt-sync && echo "✓" || echo "✗"
	@echo -n "  Building vlt-tui.exe (Terminal UI)... "
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/vlt-tui.exe ./cmd/vlt-tui && echo "✓" || echo "✗"
	@echo -n "  Building vlt-quick.exe (Quick Popup)... "
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/vlt-quick.exe ./cmd/vlt-quick && echo "✓" || echo "✗"
	@echo "Done → $(BIN_DIR)/*.exe"

# ── Tests ───────────────────────────────────────────────────────────────────

test:
	@echo "Running unit tests..."
	@$(GOTEST) -count=1 ./internal/...

test-all:
	@echo "Running all tests (race detector)..."
	@$(GOTEST) -count=1 -race ./internal/...

test-cover:
	@echo "Running tests with coverage across internal packages..."
	@$(GOTEST) -count=1 -coverprofile=coverage.out ./internal/...
	@$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@$(GOCMD) tool cover -func=coverage.out | tail -n 1
	@echo "Coverage report generated → coverage.html"

# ── Lint, Format & CI Pipeline Checks ──────────────────────────────────────────

fmt:
	@echo "Formatting code..."
	@$(GOFMT) ./...

vet:
	@echo "Running go vet..."
	@$(GOVET) ./...

lint: fmt vet
	@echo "Running golangci-lint..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	elif [ -f "$$(go env GOPATH)/bin/golangci-lint" ]; then \
		$$(go env GOPATH)/bin/golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi
	@echo "All lint checks passed."

vuln:
	@echo "Running govulncheck..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	elif [ -f "$$(go env GOPATH)/bin/govulncheck" ]; then \
		$$(go env GOPATH)/bin/govulncheck ./...; \
	else \
		echo "govulncheck not installed. Run: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

sec:
	@echo "Running gosec security scanner..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec -quiet -exclude=G101,G103,G104,G115,G117,G204,G304,G402,G505,G703,G705 ./...; \
	elif [ -f "$$(go env GOPATH)/bin/gosec" ]; then \
		$$(go env GOPATH)/bin/gosec -quiet -exclude=G101,G103,G104,G115,G117,G204,G304,G402,G505,G703,G705 ./...; \
	else \
		echo "gosec not installed. Run: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
	fi
	@echo "All gosec security checks passed."

fuzz:
	@echo "Running fuzz tests (mutation data testing)..."
	@$(GOTEST) -fuzz=FuzzParseCSV -fuzztime=2s ./internal/parse
	@$(GOTEST) -fuzz=FuzzDetectFormat -fuzztime=2s ./internal/parse
	@$(GOTEST) -fuzz=FuzzUnpackEnvelope -fuzztime=2s ./internal/crypto
	@$(GOTEST) -fuzz=FuzzValidatePINFormat -fuzztime=2s ./internal/crypto
	@$(GOTEST) -fuzz=FuzzMnemonicDecode -fuzztime=2s ./internal/crypto
	@$(GOTEST) -fuzz=FuzzParseHIBPResponse -fuzztime=2s ./internal/watchtower
	@echo "All fuzz tests passed."

check: lint sec test
	@echo "All local pipeline checks (lint + format + vet + gosec + unit tests) passed."

ci: lint sec vuln test-all
	@echo "Full CI suite (lint + gosec + vulncheck + tests with race detector) passed."

# ── Clean ───────────────────────────────────────────────────────────────────

clean:
	@echo "Cleaning..."
	@rm -rf $(BIN_DIR)/
	@rm -f coverage.out coverage.html
	@echo "Done."

# ── Run ─────────────────────────────────────────────────────────────────────

run-gui:
	CGO_ENABLED=$(CGO_ENABLED) $(GOCMD) run ./cmd/vlt-gui

run-tui:
	CGO_ENABLED=$(CGO_ENABLED) $(GOCMD) run ./cmd/vlt-tui

run-quick:
	CGO_ENABLED=$(CGO_ENABLED) $(GOCMD) run ./cmd/vlt-gui --quick

run-cli:
	CGO_ENABLED=$(CGO_ENABLED) $(GOCMD) run ./cmd/vlt

# ── Help ────────────────────────────────────────────────────────────────────

help:
	@echo "vlt — Makefile Target Reference"
	@echo ""
	@echo "  🔨 Compilation & Packaging:"
	@echo "    make build          Build all 5 binaries for current platform (bin/)"
	@echo "    make build-signed   Build signed macOS GUI with native Touch ID (-tags keychain_biometric)"
	@echo "    make build-all      Cross-compile for all platforms (macOS, Linux amd64/arm64, Windows)"
	@echo "    make build-darwin   Cross-compile macOS binaries (arm64 + amd64)"
	@echo "    make build-linux    Cross-compile Linux binaries (amd64 + arm64)"
	@echo "    make build-windows  Cross-compile Windows binaries (.exe) including GUI"
	@echo ""
	@echo "  🧪 Testing & Code Quality:"
	@echo "    make test           Run unit tests for all internal packages"
	@echo "    make test-all       Run all tests with Go Concurrency Race Detector (-race)"
	@echo "    make test-cover     Run tests and generate HTML coverage report (coverage.html)"
	@echo "    make fmt            Format all Go code using gofmt"
	@echo "    make vet            Run go vet static analysis"
	@echo "    make lint           Format, vet, and run golangci-lint"
	@echo ""
	@echo "  🛡️  Security & Vulnerability Auditing:"
	@echo "    make sec            Run gosec AST security scanner for cryptographic/logic flaws"
	@echo "    make vuln           Run govulncheck against the Go vulnerability database (CVEs)"
	@echo "    make fuzz           Run continuous mutation fuzz testing on parsers and crypto layers"
	@echo ""
	@echo "  🚀 Quality Gates & Pipelines:"
	@echo "    make check          Local pre-commit gate (fmt + vet + lint + sec + test)"
	@echo "    make ci             Full CI pipeline (lint + sec + vuln + test-all with race detector)"
	@echo ""
	@echo "  🏃 Run Applications Locally:"
	@echo "    make run-gui        Run desktop GUI application"
	@echo "    make run-tui        Run interactive terminal UI"
	@echo "    make run-quick      Run quick search-and-copy floating popup"
	@echo "    make run-cli        Run core CLI"
	@echo ""
	@echo "  🧹 Maintenance:"
	@echo "    make clean          Remove bin/ binaries and coverage artifacts"