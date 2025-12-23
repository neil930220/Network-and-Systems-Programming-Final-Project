#!/bin/bash
#
# Concurrency Test Script
# Tests 100 concurrent threads performing random banking operations.
# Verifies that balances never go negative and operations are atomic.
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
NC='\033[0m' # No Color

echo "========================================"
echo "   Bank Vault Concurrency Test"
echo "========================================"
echo ""

# Check binaries exist
if [ ! -x "$SERVER_BIN" ]; then
    echo -e "${RED}ERROR: Server binary not found at $SERVER_BIN${NC}"
    echo "Run 'make' first to build the project."
    exit 1
fi

if [ ! -x "$CLIENT_BIN" ]; then
    echo -e "${RED}ERROR: Client binary not found at $CLIENT_BIN${NC}"
    echo "Run 'make' first to build the project."
    exit 1
fi

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ ! -z "$SERVER_PID" ]; then
        kill -TERM $SERVER_PID 2>/dev/null || true
        # Wait up to 5 seconds for graceful shutdown
        for i in 1 2 3 4 5; do
            if ! kill -0 $SERVER_PID 2>/dev/null; then
                break
            fi
            sleep 1
        done
        # Force kill if still running
        kill -9 $SERVER_PID 2>/dev/null || true
    fi
    # Remove shared memory if it exists
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
echo "Starting server with 4 workers..."
$SERVER_BIN --port 7777 --workers 4 &
SERVER_PID=$!
sleep 2

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}ERROR: Server failed to start${NC}"
    exit 1
fi

echo -e "${GREEN}Server started (PID: $SERVER_PID)${NC}"
echo ""

# Run test 1: Balanced mix of operations
echo "Test 1: Mixed operations (100 threads, 500 ops each)"
echo "Mix: balance=40%, deposit=30%, withdraw=20%, transfer=10%"
echo ""

$CLIENT_BIN --host 127.0.0.1 --port 7777 --threads 100 --ops 500 \
    --mix "balance=40,deposit=30,withdraw=20,transfer=10"

# Run test 2: Heavy transfer load
echo ""
echo "Test 2: Heavy transfer load (50 threads, 200 ops each)"
echo "Mix: balance=10%, deposit=10%, withdraw=10%, transfer=70%"
echo ""

$CLIENT_BIN --host 127.0.0.1 --port 7777 --threads 50 --ops 200 \
    --mix "balance=10,deposit=10,withdraw=10,transfer=70"

# Run test 3: Stress test with many threads
echo ""
echo "Test 3: High concurrency (200 threads, 100 ops each)"
echo "Mix: balance=25%, deposit=25%, withdraw=25%, transfer=25%"
echo ""

$CLIENT_BIN --host 127.0.0.1 --port 7777 --threads 200 --ops 100 \
    --mix "balance=25,deposit=25,withdraw=25,transfer=25"

echo ""
echo "========================================"
echo -e "${GREEN}All concurrency tests completed!${NC}"
echo "========================================"

# Graceful shutdown
echo ""
echo "Sending SIGINT to server for graceful shutdown..."
kill -INT $SERVER_PID 2>/dev/null || true
sleep 2

# Check if shared memory was cleaned up
if [ -f "$SHM_FILE" ]; then
    echo -e "${YELLOW}WARNING: Shared memory file still exists${NC}"
else
    echo -e "${GREEN}Shared memory cleaned up successfully${NC}"
fi

echo ""
echo "Test completed successfully!"
exit 0

