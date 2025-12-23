CC = gcc
CFLAGS = -Wall -Wextra -pthread -Iinclude -O2
CFLAGS_DEBUG = -Wall -Wextra -pthread -Iinclude -g -O0 -DDEBUG
LDFLAGS = -lrt -lpthread

# Source files
PROTO_SRC = libproto/protocol.c
SHM_SRC = libshm/vault_shm.c
UTIL_SRC = libutil/logger.c
SERVER_SRC = server/vault_server.c
CLIENT_SRC = client/vault_client.c
CLI_SRC = client/vault_cli.c
TEST_PROTO_SRC = tests/test_protocol.c

# Object files
PROTO_OBJ = libproto/protocol.o
SHM_OBJ = libshm/vault_shm.o
UTIL_OBJ = libutil/logger.o

# Debug object files
PROTO_OBJ_DEBUG = libproto/protocol.debug.o
SHM_OBJ_DEBUG = libshm/vault_shm.debug.o
UTIL_OBJ_DEBUG = libutil/logger.debug.o

# Targets
SERVER_BIN = vault_server
CLIENT_BIN = vault_client
CLI_BIN = vault_cli
TEST_PROTO_BIN = test_protocol

# Debug targets
SERVER_BIN_DEBUG = vault_server_debug
CLIENT_BIN_DEBUG = vault_client_debug
CLI_BIN_DEBUG = vault_cli_debug

.PHONY: all server client cli test test_protocol integration clean help
.PHONY: debug debug-server debug-client debug-cli
.PHONY: verbose-test test-security

all: server client cli

# Build object files (release)
libproto/protocol.o: $(PROTO_SRC) include/protocol.h include/common.h
	$(CC) $(CFLAGS) -c $(PROTO_SRC) -o $@

libshm/vault_shm.o: $(SHM_SRC) include/vault_shm.h
	$(CC) $(CFLAGS) -c $(SHM_SRC) -o $@

libutil/logger.o: $(UTIL_SRC) include/logger.h
	$(CC) $(CFLAGS) -c $(UTIL_SRC) -o $@

# Build object files (debug)
libproto/protocol.debug.o: $(PROTO_SRC) include/protocol.h include/common.h
	$(CC) $(CFLAGS_DEBUG) -c $(PROTO_SRC) -o $@

libshm/vault_shm.debug.o: $(SHM_SRC) include/vault_shm.h
	$(CC) $(CFLAGS_DEBUG) -c $(SHM_SRC) -o $@

libutil/logger.debug.o: $(UTIL_SRC) include/logger.h
	$(CC) $(CFLAGS_DEBUG) -c $(UTIL_SRC) -o $@

# Build server (release)
server: $(SERVER_BIN)

$(SERVER_BIN): $(SERVER_SRC) $(PROTO_OBJ) $(SHM_OBJ) $(UTIL_OBJ)
	$(CC) $(CFLAGS) $(SERVER_SRC) $(PROTO_OBJ) $(SHM_OBJ) $(UTIL_OBJ) -o $@ $(LDFLAGS)

# Build client load generator (release)
client: $(CLIENT_BIN)

$(CLIENT_BIN): $(CLIENT_SRC) $(PROTO_OBJ)
	$(CC) $(CFLAGS) $(CLIENT_SRC) $(PROTO_OBJ) -o $@ $(LDFLAGS)

# Build interactive CLI (release) - requires ncurses
cli: $(CLI_BIN)

$(CLI_BIN): $(CLI_SRC) $(PROTO_OBJ)
	$(CC) $(CFLAGS) $(CLI_SRC) $(PROTO_OBJ) -o $@ $(LDFLAGS) -lncurses

# Build protocol unit tests
test_protocol: $(PROTO_OBJ)
	$(CC) $(CFLAGS) $(TEST_PROTO_SRC) $(PROTO_OBJ) -o $(TEST_PROTO_BIN) $(LDFLAGS)

# ======================================================
# Debug builds
# ======================================================

debug: debug-server debug-client debug-cli

debug-server: $(SERVER_BIN_DEBUG)

$(SERVER_BIN_DEBUG): $(SERVER_SRC) $(PROTO_OBJ_DEBUG) $(SHM_OBJ_DEBUG) $(UTIL_OBJ_DEBUG)
	$(CC) $(CFLAGS_DEBUG) $(SERVER_SRC) $(PROTO_OBJ_DEBUG) $(SHM_OBJ_DEBUG) $(UTIL_OBJ_DEBUG) -o $@ $(LDFLAGS)

debug-client: $(CLIENT_BIN_DEBUG)

$(CLIENT_BIN_DEBUG): $(CLIENT_SRC) $(PROTO_OBJ_DEBUG)
	$(CC) $(CFLAGS_DEBUG) $(CLIENT_SRC) $(PROTO_OBJ_DEBUG) -o $@ $(LDFLAGS)

debug-cli: $(CLI_BIN_DEBUG)

$(CLI_BIN_DEBUG): $(CLI_SRC) $(PROTO_OBJ_DEBUG)
	$(CC) $(CFLAGS_DEBUG) $(CLI_SRC) $(PROTO_OBJ_DEBUG) -o $@ $(LDFLAGS) -lncurses

# ======================================================
# Test targets
# ======================================================

# Run all tests
test: all test_protocol
	@echo ""
	@echo "=== Running Unit Tests ==="
	./$(TEST_PROTO_BIN)
	@echo ""
	@echo "=== Running Integration Tests ==="
	./tests/run_all_tests.sh

# Run tests with verbose output
verbose-test: all test_protocol
	@echo ""
	@echo "=== Running Unit Tests ==="
	./$(TEST_PROTO_BIN)
	@echo ""
	@echo "=== Running Integration Tests (Verbose) ==="
	./tests/run_all_tests.sh -v

# Run integration tests only
integration: all
	@echo "=== Running Integration Tests ==="
	./tests/test_failures.sh
	./tests/test_shutdown.sh
	./tests/test_concurrency.sh
	./tests/test_security.sh

# Run security tests only
test-security: all
	@echo "=== Running Security Tests ==="
	./tests/test_security.sh -v

# ======================================================
# Clean and Help
# ======================================================

# Clean build artifacts
clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN) $(CLI_BIN) $(TEST_PROTO_BIN)
	rm -f $(SERVER_BIN_DEBUG) $(CLIENT_BIN_DEBUG) $(CLI_BIN_DEBUG)
	rm -f $(PROTO_OBJ) $(SHM_OBJ) $(UTIL_OBJ)
	rm -f $(PROTO_OBJ_DEBUG) $(SHM_OBJ_DEBUG) $(UTIL_OBJ_DEBUG)
	rm -f /dev/shm/vault_shm 2>/dev/null || true
	rm -rf tests/logs 2>/dev/null || true

# Show help
help:
	@echo "Bank Vault - Makefile Targets"
	@echo ""
	@echo "Build Targets (Release):"
	@echo "  all           - Build server, client, and CLI (default)"
	@echo "  server        - Build vault_server only"
	@echo "  client        - Build vault_client (load generator)"
	@echo "  cli           - Build vault_cli (interactive client)"
	@echo "  test_protocol - Build protocol unit tests"
	@echo ""
	@echo "Build Targets (Debug):"
	@echo "  debug         - Build all with debug symbols (-g -DDEBUG)"
	@echo "  debug-server  - Build vault_server_debug"
	@echo "  debug-client  - Build vault_client_debug"
	@echo "  debug-cli     - Build vault_cli_debug"
	@echo ""
	@echo "Test Targets:"
	@echo "  test          - Run all tests (unit + integration)"
	@echo "  verbose-test  - Run all tests with verbose output"
	@echo "  integration   - Run integration tests only"
	@echo "  test-security - Run security tests with verbose output"
	@echo ""
	@echo "Other:"
	@echo "  clean         - Remove build artifacts"
	@echo "  help          - Show this help"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make                  # Build everything"
	@echo "  make test             # Run all tests"
	@echo "  make verbose-test     # Run tests with detailed output"
	@echo "  make debug            # Build with debug symbols"
	@echo ""
	@echo "  ./vault_server --port 7777 --workers 4"
	@echo "  ./vault_server --port 7777 --log-level debug"
	@echo "  ./vault_client --host 127.0.0.1 --port 7777 --threads 100 --ops 500"
	@echo "  ./vault_cli --host 127.0.0.1 --port 7777"
