#!/bin/bash
#
# Graceful Shutdown Test Script
# Tests that the server properly handles SIGINT and cleans up IPC resources.
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
echo "   Bank Vault Shutdown Test"
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

# Kill any existing server and clean up
pkill -f vault_server 2>/dev/null || true
sleep 1
rm -f "$SHM_FILE" 2>/dev/null || true

echo "Test 1: Basic startup and SIGINT shutdown"
echo "=========================================="

# Start server
echo "Starting server..."
$SERVER_BIN --port 7779 --workers 2 &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}ERROR: Server failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}Server started (PID: $SERVER_PID)${NC}"

# Check shared memory exists
if [ -f "$SHM_FILE" ]; then
    echo -e "${GREEN}Shared memory created at $SHM_FILE${NC}"
else
    echo -e "${RED}ERROR: Shared memory not found${NC}"
    kill -TERM $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Send SIGINT
echo "Sending SIGINT..."
kill -INT $SERVER_PID
sleep 3

# Check server exited
if kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}ERROR: Server did not exit after SIGINT${NC}"
    kill -KILL $SERVER_PID 2>/dev/null || true
    exit 1
fi
echo -e "${GREEN}Server exited cleanly${NC}"

# Check shared memory cleanup
if [ -f "$SHM_FILE" ]; then
    echo -e "${RED}ERROR: Shared memory not cleaned up!${NC}"
    rm -f "$SHM_FILE"
    exit 1
fi
echo -e "${GREEN}Shared memory cleaned up${NC}"

echo ""
echo "Test 2: Shutdown during active load"
echo "===================================="

# Start server again
echo "Starting server..."
$SERVER_BIN --port 7779 --workers 4 &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}ERROR: Server failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}Server started (PID: $SERVER_PID)${NC}"

# Start client load in background
echo "Starting client load (20 threads, 1000 ops each)..."
$CLIENT_BIN --host 127.0.0.1 --port 7779 --threads 20 --ops 1000 &
CLIENT_PID=$!
sleep 2

# Send SIGINT while client is running
echo "Sending SIGINT during load..."
kill -INT $SERVER_PID

# Wait for both to finish (with timeout)
for i in 1 2 3 4 5 6 7 8 9 10; do
    CLIENT_RUNNING=0
    SERVER_RUNNING=0
    kill -0 $CLIENT_PID 2>/dev/null && CLIENT_RUNNING=1
    kill -0 $SERVER_PID 2>/dev/null && SERVER_RUNNING=1
    if [ $CLIENT_RUNNING -eq 0 ] && [ $SERVER_RUNNING -eq 0 ]; then
        break
    fi
    sleep 1
done
# Force kill if still running
kill -9 $CLIENT_PID 2>/dev/null || true
kill -9 $SERVER_PID 2>/dev/null || true

# Check cleanup
sleep 1
if [ -f "$SHM_FILE" ]; then
    echo -e "${YELLOW}WARNING: Shared memory not cleaned up after load test${NC}"
    rm -f "$SHM_FILE"
else
    echo -e "${GREEN}Shared memory cleaned up after load test${NC}"
fi

echo ""
echo "Test 3: SIGTERM handling"
echo "========================"

# Start server
echo "Starting server..."
$SERVER_BIN --port 7779 --workers 2 &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}ERROR: Server failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}Server started (PID: $SERVER_PID)${NC}"

# Send SIGTERM
echo "Sending SIGTERM..."
kill -TERM $SERVER_PID
sleep 3

# Check server exited
if kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}ERROR: Server did not exit after SIGTERM${NC}"
    kill -KILL $SERVER_PID 2>/dev/null || true
    rm -f "$SHM_FILE" 2>/dev/null || true
    exit 1
fi
echo -e "${GREEN}Server exited cleanly on SIGTERM${NC}"

# Check cleanup
if [ -f "$SHM_FILE" ]; then
    echo -e "${YELLOW}WARNING: Shared memory not cleaned up${NC}"
    rm -f "$SHM_FILE"
else
    echo -e "${GREEN}Shared memory cleaned up${NC}"
fi

echo ""
echo "========================================"
echo -e "${GREEN}All shutdown tests passed!${NC}"
echo "========================================"

exit 0

