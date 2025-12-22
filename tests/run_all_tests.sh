#!/bin/bash
#
# Master Test Runner with Runtime Metrics
# Runs all tests and reports overall results with timing and memory stats.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$SCRIPT_DIR/logs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Parse arguments
VERBOSE=0
SAVE_LOGS=0
while [ $# -gt 0 ]; do
    case "$1" in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --save-logs)
            SAVE_LOGS=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -v, --verbose    Show detailed test output"
            echo "  --save-logs      Save server logs to tests/logs/"
            echo "  -h, --help       Show this help"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Create logs directory if saving logs
if [ $SAVE_LOGS -eq 1 ]; then
    mkdir -p "$LOG_DIR"
fi

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           Bank Vault - Complete Test Suite                 ║${NC}"
echo -e "${BLUE}║                  with Runtime Metrics                      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Get memory usage (Linux specific)
get_memory_kb() {
    if [ -f /proc/meminfo ]; then
        grep MemAvailable /proc/meminfo | awk '{print $2}'
    else
        echo "0"
    fi
}

# Format memory in human-readable form
format_memory() {
    local kb=$1
    if [ $kb -gt 1048576 ]; then
        echo "$(echo "scale=1; $kb/1048576" | bc)G"
    elif [ $kb -gt 1024 ]; then
        echo "$(echo "scale=1; $kb/1024" | bc)M"
    else
        echo "${kb}K"
    fi
}

# Build project first
echo -e "${YELLOW}Building project...${NC}"
cd "$PROJECT_DIR"
make clean > /dev/null 2>&1
make all > /dev/null 2>&1
make test_protocol > /dev/null 2>&1
echo -e "${GREEN}Build complete!${NC}"
echo ""

# Track results
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_START_TIME=$(date +%s.%N)

# Display system info
echo -e "${CYAN}System Information:${NC}"
echo "  Hostname: $(hostname)"
echo "  Kernel: $(uname -r)"
echo "  CPUs: $(nproc)"
echo "  Memory: $(free -h | grep Mem | awk '{print $2}')"
echo ""

run_test() {
    local name="$1"
    local cmd="$2"
    local verbose_flag=""
    
    if [ $VERBOSE -eq 1 ]; then
        verbose_flag="-v"
    fi
    
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Running: $name${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    # Get memory before test
    MEM_BEFORE=$(get_memory_kb)
    
    # Get start time
    TEST_START=$(date +%s.%N)
    START_TIME_STR=$(date "+%Y-%m-%d %H:%M:%S")
    
    echo "  Start time: $START_TIME_STR"
    
    # Run test
    local output_file=""
    if [ $SAVE_LOGS -eq 1 ]; then
        output_file="$LOG_DIR/$(echo "$name" | tr ' ' '_')_$(date +%Y%m%d_%H%M%S).log"
    fi
    
    local result=0
    if [ $VERBOSE -eq 1 ]; then
        if [ -n "$output_file" ]; then
            $cmd $verbose_flag 2>&1 | tee "$output_file" || result=$?
        else
            $cmd $verbose_flag || result=$?
        fi
    else
        if [ -n "$output_file" ]; then
            $cmd $verbose_flag > "$output_file" 2>&1 || result=$?
        else
            $cmd $verbose_flag > /dev/null 2>&1 || result=$?
        fi
    fi
    
    # Get end time
    TEST_END=$(date +%s.%N)
    DURATION=$(echo "$TEST_END - $TEST_START" | bc)
    
    # Get memory after test
    MEM_AFTER=$(get_memory_kb)
    MEM_DIFF=$((MEM_BEFORE - MEM_AFTER))
    
    # Display results
    printf "  Duration: %.2f seconds\n" $DURATION
    if [ $MEM_BEFORE -gt 0 ]; then
        echo "  Memory used: $(format_memory $MEM_DIFF)"
    fi
    
    if [ $result -eq 0 ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo ""
        echo -e "  ${GREEN}✓ $name PASSED${NC}"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo ""
        echo -e "  ${RED}✗ $name FAILED${NC}"
        if [ -n "$output_file" ]; then
            echo "  Log saved to: $output_file"
        fi
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
run_test "Security Tests" "$SCRIPT_DIR/test_security.sh"

# Calculate total time
TOTAL_END_TIME=$(date +%s.%N)
TOTAL_DURATION=$(echo "$TOTAL_END_TIME - $TOTAL_START_TIME" | bc)

# Print summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                     TEST SUMMARY                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Tests Run:    $TESTS_RUN"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
printf "Total Time:   %.2f seconds\n" $TOTAL_DURATION
echo ""

if [ $SAVE_LOGS -eq 1 ]; then
    echo "Logs saved to: $LOG_DIR"
    echo ""
fi

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
