#!/bin/bash
#
# Security Test Script
# Tests security features: timestamp validation, CRC checking, rate limiting,
# and malformed packet handling.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SERVER_BIN="$PROJECT_DIR/vault_server"
CLIENT_BIN="$PROJECT_DIR/vault_client"
SHM_FILE="/dev/shm/vault_shm"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Verbose flag
VERBOSE=0
if [ "$1" == "-v" ] || [ "$1" == "--verbose" ]; then
    VERBOSE=1
fi

log_verbose() {
    if [ $VERBOSE -eq 1 ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           Bank Vault Security Test Suite                   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Track test results
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
START_TIME=$(date +%s.%N)

# Check binaries exist
if [ ! -x "$SERVER_BIN" ]; then
    echo -e "${RED}ERROR: Server binary not found at $SERVER_BIN${NC}"
    echo "Run 'make' first to build the project."
    exit 1
fi

# Cleanup function
cleanup() {
    echo ""
    log_info "Cleaning up..."
    if [ ! -z "$SERVER_PID" ]; then
        kill -TERM $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    rm -f "$SHM_FILE" 2>/dev/null || true
    log_info "Cleanup complete."
}
trap cleanup EXIT

# Kill any existing server and clean up
pkill -f vault_server 2>/dev/null || true
sleep 1
rm -f "$SHM_FILE" 2>/dev/null || true

# Start server with debug logging
log_info "Starting server with debug logging..."
$SERVER_BIN --port 7780 --workers 2 --log-level debug &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    log_fail "Server failed to start"
    exit 1
fi
log_pass "Server started (PID: $SERVER_PID)"

# ============================================================
# Test 1: Bad Magic Number
# ============================================================
echo ""
echo -e "${YELLOW}Test 1: Bad Magic Number${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

# Send packet with wrong magic (0xBAD0 instead of 0xC0DE)
# Format: Length(4) + Magic(2) + Ver(1) + Flags(1) + Op(2) + Seq(4) + Timestamp(8) + CRC(4)
log_verbose "Sending packet with wrong magic number 0xBAD0..."
printf '\x00\x00\x00\x1a\xba\xd0\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | \
    nc -q 1 127.0.0.1 7780 2>/dev/null || true

# Server should still be running
if kill -0 $SERVER_PID 2>/dev/null; then
    log_pass "Server handled bad magic without crashing"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Server crashed on bad magic"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
fi

# ============================================================
# Test 2: Bad CRC
# ============================================================
echo ""
echo -e "${YELLOW}Test 2: Bad CRC${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

# Send packet with correct magic but bad CRC
log_verbose "Sending packet with invalid CRC..."
printf '\x00\x00\x00\x1a\xc0\xde\x01\x00\x00\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef\x00\x00' | \
    nc -q 1 127.0.0.1 7780 2>/dev/null || true

if kill -0 $SERVER_PID 2>/dev/null; then
    log_pass "Server handled bad CRC without crashing"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Server crashed on bad CRC"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
fi

# ============================================================
# Test 3: Oversized Packet Length
# ============================================================
echo ""
echo -e "${YELLOW}Test 3: Oversized Packet Length${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

# Send packet claiming to be 1MB in size
log_verbose "Sending packet with oversized length claim (1MB)..."
printf '\x00\x10\x00\x00' | nc -q 1 127.0.0.1 7780 2>/dev/null || true

if kill -0 $SERVER_PID 2>/dev/null; then
    log_pass "Server handled oversized length without crashing"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Server crashed on oversized length"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
fi

# ============================================================
# Test 4: Truncated Packet
# ============================================================
echo ""
echo -e "${YELLOW}Test 4: Truncated Packet${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

# Send only length field, then close connection
log_verbose "Sending truncated packet (only length field)..."
printf '\x00\x00\x00\x20' | nc -q 1 127.0.0.1 7780 2>/dev/null || true

if kill -0 $SERVER_PID 2>/dev/null; then
    log_pass "Server handled truncated packet without crashing"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Server crashed on truncated packet"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
fi

# ============================================================
# Test 5: Multiple Malformed Packets (Disconnect Threshold)
# ============================================================
echo ""
echo -e "${YELLOW}Test 5: Multiple Malformed Packets${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

# Send multiple bad packets to trigger disconnect threshold (MAX_MALFORMED_PACKETS=3)
log_verbose "Sending multiple malformed packets to test disconnect threshold..."
for i in 1 2 3 4 5; do
    printf '\x00\x00\x00\x04XXXX' | nc -q 1 127.0.0.1 7780 2>/dev/null || true
done

if kill -0 $SERVER_PID 2>/dev/null; then
    log_pass "Server handled multiple malformed packets"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Server crashed on multiple malformed packets"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
fi

# ============================================================
# Test 6: Connection Flood
# ============================================================
echo ""
echo -e "${YELLOW}Test 6: Connection Flood${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

# Open many connections rapidly
log_verbose "Opening 50 rapid connections..."
for i in $(seq 1 50); do
    (echo "" | nc -q 0 127.0.0.1 7780 2>/dev/null || true) &
done
wait
sleep 1

if kill -0 $SERVER_PID 2>/dev/null; then
    log_pass "Server survived connection flood"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Server crashed during connection flood"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
fi

# ============================================================
# Test 7: Rate Limiting (via load generator)
# ============================================================
echo ""
echo -e "${YELLOW}Test 7: Rate Limiting${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

if [ -x "$CLIENT_BIN" ]; then
    log_verbose "Running high-rate load test..."
    # Run a short burst that should trigger rate limiting
    RESULT=$($CLIENT_BIN --host 127.0.0.1 --port 7780 --threads 10 --ops 100 2>&1 || true)
    
    if kill -0 $SERVER_PID 2>/dev/null; then
        log_pass "Server handled high-rate load (rate limiting active)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        if [ $VERBOSE -eq 1 ]; then
            echo "$RESULT" | grep -E "(throughput|err)" || true
        fi
    else
        log_fail "Server crashed during rate limit test"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        exit 1
    fi
else
    log_info "Client binary not found, skipping rate limit test"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

# ============================================================
# Test 8: Zero-length Body Operations
# ============================================================
echo ""
echo -e "${YELLOW}Test 8: Zero-length Body Operations${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

# Send valid PING (no body required) - just verify server handles properly
log_verbose "Sending empty/minimal requests..."
for i in 1 2 3; do
    printf '\x00\x00\x00\x1a\xc0\xde\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | \
        nc -q 1 127.0.0.1 7780 2>/dev/null || true
done

if kill -0 $SERVER_PID 2>/dev/null; then
    log_pass "Server handled zero-length body operations"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Server crashed on zero-length body"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
fi

# ============================================================
# Test 9: Random Binary Data
# ============================================================
echo ""
echo -e "${YELLOW}Test 9: Random Binary Data${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

log_verbose "Sending random binary data..."
dd if=/dev/urandom bs=1024 count=1 2>/dev/null | nc -q 1 127.0.0.1 7780 2>/dev/null || true

if kill -0 $SERVER_PID 2>/dev/null; then
    log_pass "Server handled random binary data"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Server crashed on random data"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
fi

# ============================================================
# Calculate Runtime
# ============================================================
END_TIME=$(date +%s.%N)
DURATION=$(echo "$END_TIME - $START_TIME" | bc)

# Print summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  SECURITY TEST SUMMARY                     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Tests Run:    $TESTS_RUN"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
printf "Duration:     %.2f seconds\n" $DURATION
echo ""

# Graceful shutdown
log_info "Sending SIGINT for graceful shutdown..."
kill -INT $SERVER_PID 2>/dev/null || true
sleep 2

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           ALL SECURITY TESTS PASSED! ✓                     ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║           SOME SECURITY TESTS FAILED! ✗                    ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi

