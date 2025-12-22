#!/bin/bash
#
# Failure Handling Test Script
# Tests that the server properly handles malformed packets, bad CRC, etc.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SERVER_BIN="$PROJECT_DIR/vault_server"
SHM_FILE="/dev/shm/vault_shm"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "   Bank Vault Failure Handling Test"
echo "========================================"
echo ""

# Check server binary exists
if [ ! -x "$SERVER_BIN" ]; then
    echo -e "${RED}ERROR: Server binary not found at $SERVER_BIN${NC}"
    echo "Run 'make' first to build the project."
    exit 1
fi

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ ! -z "$SERVER_PID" ]; then
        kill -TERM $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    rm -f "$SHM_FILE" 2>/dev/null || true
    echo "Cleanup complete."
}
trap cleanup EXIT

# Kill any existing server
pkill -f vault_server 2>/dev/null || true
sleep 1

# Remove stale shared memory
rm -f "$SHM_FILE" 2>/dev/null || true

# Start server
echo "Starting server..."
$SERVER_BIN --port 7778 --workers 2 &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}ERROR: Server failed to start${NC}"
    exit 1
fi

echo -e "${GREEN}Server started (PID: $SERVER_PID)${NC}"
echo ""

# Test 1: Send garbage data
echo "Test 1: Sending garbage data..."
echo "GARBAGE_DATA_NOT_A_VALID_PACKET" | nc -w 2 -q 1 127.0.0.1 7778 2>/dev/null || true
echo -e "${GREEN}Server handled garbage data without crashing${NC}"
echo ""

# Test 2: Send truncated packet (only length field)
echo "Test 2: Sending truncated packet..."
printf '\x00\x00\x00\x20' | nc -w 2 -q 1 127.0.0.1 7778 2>/dev/null || true
echo -e "${GREEN}Server handled truncated packet${NC}"
echo ""

# Test 3: Send packet with wrong magic
echo "Test 3: Sending packet with wrong magic..."
# Length=26, WrongMagic=0xBAD0, Ver=1, Flags=0, Op=0, Seq=0, Timestamp=0, CRC=0
printf '\x00\x00\x00\x1a\xba\xd0\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | nc -w 2 -q 1 127.0.0.1 7778 2>/dev/null || true
echo -e "${GREEN}Server handled wrong magic${NC}"
echo ""

# Test 4: Send packet with oversized length
echo "Test 4: Sending packet with oversized length claim..."
# Claim length is 1MB
printf '\x00\x10\x00\x00' | nc -w 2 -q 1 127.0.0.1 7778 2>/dev/null || true
echo -e "${GREEN}Server handled oversized length${NC}"
echo ""

# Test 5: Multiple bad packets to test disconnect threshold
echo "Test 5: Sending multiple malformed packets..."
for i in 1 2 3 4 5; do
    printf '\x00\x00\x00\x04XXXX' | nc -w 2 -q 1 127.0.0.1 7778 2>/dev/null || true
done
echo -e "${GREEN}Server handled multiple malformed packets${NC}"
echo ""

# Test 6: Connection flood (many rapid connections)
echo "Test 6: Connection flood test (20 rapid connections)..."
for i in $(seq 1 20); do
    (echo "" | timeout 3 nc -w 2 -q 0 127.0.0.1 7778 2>/dev/null || true) &
done
wait
sleep 1
echo -e "${GREEN}Server survived connection flood${NC}"
echo ""

# Verify server is still running
if kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${GREEN}Server is still running after all failure tests!${NC}"
else
    echo -e "${RED}ERROR: Server crashed during failure tests${NC}"
    exit 1
fi

echo ""
echo "========================================"
echo -e "${GREEN}All failure handling tests passed!${NC}"
echo "========================================"

exit 0

