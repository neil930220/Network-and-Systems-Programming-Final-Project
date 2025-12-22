#!/bin/bash
#
# Master Test Runner
# Runs all tests and reports overall results.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           Bank Vault - Complete Test Suite                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Build project first
echo -e "${YELLOW}Building project...${NC}"
cd "$PROJECT_DIR"
make clean
make all
make test_protocol
echo -e "${GREEN}Build complete!${NC}"
echo ""

# Track results
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local name="$1"
    local cmd="$2"
    
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Running: $name${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    if $cmd; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo ""
        echo -e "${GREEN}✓ $name PASSED${NC}"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo ""
        echo -e "${RED}✗ $name FAILED${NC}"
    fi
}

# Clean up any leftover processes
pkill -f vault_server 2>/dev/null || true
rm -f /dev/shm/vault_shm 2>/dev/null || true
sleep 1

# Run unit tests
run_test "Protocol Unit Tests" "$PROJECT_DIR/test_protocol"

# Run integration tests
run_test "Failure Handling Tests" "$SCRIPT_DIR/test_failures.sh"
run_test "Shutdown Tests" "$SCRIPT_DIR/test_shutdown.sh"
run_test "Concurrency Tests" "$SCRIPT_DIR/test_concurrency.sh"

# Print summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                     TEST SUMMARY                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Tests Run:    $TESTS_RUN"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              ALL TESTS PASSED! ✓                           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║              SOME TESTS FAILED! ✗                          ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi

