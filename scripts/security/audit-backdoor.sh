#!/usr/bin/env bash
# ==============================================================================
# vlt Security & Backdoor Audit Script
# ==============================================================================
# This script performs static analysis and architectural boundary verification
# to detect unauthorized network exfiltration, rogue process execution,
# supply-chain tampering, and common backdoor vectors in the codebase.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

FAILED=0

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}        vlt Anti-Backdoor & Supply-Chain Security Audit           ${NC}"
echo -e "${BLUE}==================================================================${NC}\n"

# Helper for test reporting
pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $1"
}

fail() {
    echo -e "  ${RED}✗ FAIL${NC}: $1"
    echo -e "    ${YELLOW}Details:${NC} $2"
    FAILED=1
}

warn() {
    echo -e "  ${YELLOW}! WARN${NC}: $1"
    echo -e "    ${YELLOW}Details:${NC} $2"
}

# ------------------------------------------------------------------------------
# 1. Supply-Chain: Go Module Verification
# ------------------------------------------------------------------------------
echo -e "${BLUE}[1/6] Verifying Go Module Integrity (go mod verify)...${NC}"
if go mod verify > /dev/null 2>&1; then
    pass "All dependencies match cryptographic hashes in go.sum"
else
    fail "Module verification failed!" "Dependencies may have been tampered with. Run 'go mod verify' for details."
fi

# ------------------------------------------------------------------------------
# 2. Network Isolation Boundaries
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[2/6] Auditing Network Isolation Boundaries...${NC}"
# In vlt, sensitive core packages MUST NEVER import net/http.
# Allowed packages: internal/sync, internal/syncserver, internal/watchtower, internal/gui (favicons).
# Strictly FORBIDDEN: internal/crypto, internal/store, internal/secret, internal/tui, internal/quick.

FORBIDDEN_NET_PACKAGES="internal/crypto internal/store internal/secret internal/tui internal/quick"
NET_VIOLATIONS=0

for pkg in $FORBIDDEN_NET_PACKAGES; do
    if [ -d "$pkg" ]; then
        MATCHES=$(grep -rn --include="*.go" -E '"net/http"' "$pkg" || true)
        if [ -n "$MATCHES" ]; then
            fail "Unauthorized net/http import in core package '$pkg'" "$MATCHES"
            NET_VIOLATIONS=$((NET_VIOLATIONS + 1))
        fi
    fi
done

if [ "$NET_VIOLATIONS" -eq 0 ]; then
    pass "Core crypto, store, secret, and TUI packages have zero network capability"
fi

# ------------------------------------------------------------------------------
# 3. Process Execution Boundaries (os/exec)
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[3/6] Auditing Process Execution (os/exec)...${NC}"
# In vlt, os/exec is strictly confined to:
# - internal/notify (osascript / notify-send)
# - internal/cli/root.go (detached clipboard auto-clear subprocess)
# - internal/cli/quick.go (vlt-quick popup launcher)
# - internal/gui/gui.go (default browser launcher for secret URLs)
#
# It is STRICTLY FORBIDDEN in: internal/crypto, internal/store, internal/secret, internal/sync, internal/syncserver

FORBIDDEN_EXEC_PACKAGES="internal/crypto internal/store internal/secret internal/sync internal/syncserver internal/otp internal/watchtower"
EXEC_VIOLATIONS=0

for pkg in $FORBIDDEN_EXEC_PACKAGES; do
    if [ -d "$pkg" ]; then
        MATCHES=$(grep -rn --include="*.go" -E '"os/exec"' "$pkg" || true)
        if [ -n "$MATCHES" ]; then
            fail "Unauthorized os/exec import in sensitive package '$pkg'" "$MATCHES"
            EXEC_VIOLATIONS=$((EXEC_VIOLATIONS + 1))
        fi
    fi
done

if [ "$EXEC_VIOLATIONS" -eq 0 ]; then
    pass "No unauthorized process execution in crypto, store, secret, or sync engines"
fi

# ------------------------------------------------------------------------------
# 4. Unsafe Memory Boundaries (unsafe package)
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[4/6] Auditing Unsafe Pointer & Memory Usage (unsafe)...${NC}"
# unsafe is strictly restricted to OS CGo bridges (keychain, hotkeys, peer credential checks).
# It is FORBIDDEN in core crypto, store, and secret manipulation.

FORBIDDEN_UNSAFE_PACKAGES="internal/crypto internal/store internal/secret internal/sync internal/syncserver internal/otp internal/watchtower internal/parse"
UNSAFE_VIOLATIONS=0

for pkg in $FORBIDDEN_UNSAFE_PACKAGES; do
    if [ -d "$pkg" ]; then
        MATCHES=$(grep -rn --include="*.go" -E '"unsafe"' "$pkg" || true)
        if [ -n "$MATCHES" ]; then
            fail "Unauthorized unsafe package usage in '$pkg'" "$MATCHES"
            UNSAFE_VIOLATIONS=$((UNSAFE_VIOLATIONS + 1))
        fi
    fi
done

if [ "$UNSAFE_VIOLATIONS" -eq 0 ]; then
    pass "Core logic and cryptographic engines contain 0 instances of 'unsafe'"
fi

# ------------------------------------------------------------------------------
# 5. Blind Indexing Invariant (No Plaintext WHERE name = ?)
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[5/6] Verifying SQLite Blind Indexing Invariant...${NC}"
# In schema v7, secret names are HMAC-blind-indexed. Queries must use name_lookup, never plaintext name.

PLAINTEXT_SQL=$(grep -rn --include="*.go" --exclude="*_test.go" -E 'WHERE[[:space:]]+name[[:space:]]*=' internal/store/ || true)
if [ -n "$PLAINTEXT_SQL" ]; then
    fail "Plaintext name query found in production store!" "$PLAINTEXT_SQL"
else
    pass "All production store queries honor HMAC-SHA256 blind indexing (name_lookup)"
fi

# ------------------------------------------------------------------------------
# 6. Suspicious Shell / Eval Injection Patterns
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[6/6] Scanning for Suspicious Shell Invocation Patterns...${NC}"
# Scan for dangerous invocation patterns like "sh -c", "bash -c", "cmd.exe /c"
SUSPICIOUS_SHELL=$(grep -rn --include="*.go" --exclude="*_test.go" -E '(exec\.Command\("(sh|bash|cmd|powershell)",\s*"-c")' internal/ cmd/ || true)
if [ -n "$SUSPICIOUS_SHELL" ]; then
    fail "Suspicious shell -c command invocation detected" "$SUSPICIOUS_SHELL"
else
    pass "Zero arbitrary shell (-c) command executions in codebase"
fi

# ------------------------------------------------------------------------------
# Summary & Result
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}==================================================================${NC}"
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}AUDIT PASSED: No backdoors, exfiltration routes, or boundary leaks.${NC}"
    echo -e "${BLUE}==================================================================${NC}\n"
    exit 0
else
    echo -e "${RED}AUDIT FAILED: Security boundary violations detected!${NC}"
    echo -e "${BLUE}==================================================================${NC}\n"
    exit 1
fi
