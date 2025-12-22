CC = gcc
CFLAGS = -Wall -Wextra -pthread -Iinclude -O2
LDFLAGS = -lrt -lpthread

# Source files
PROTO_SRC = libproto/protocol.c
SHM_SRC = libshm/vault_shm.c
SERVER_SRC = server/vault_server.c
CLIENT_SRC = client/vault_client.c
TEST_PROTO_SRC = tests/test_protocol.c

# Object files
PROTO_OBJ = libproto/protocol.o
SHM_OBJ = libshm/vault_shm.o

# Targets
SERVER_BIN = vault_server
CLIENT_BIN = vault_client
TEST_PROTO_BIN = test_protocol

.PHONY: all server client test test_protocol integration clean help

all: server client

# Build object files
libproto/protocol.o: $(PROTO_SRC) include/protocol.h include/common.h
	$(CC) $(CFLAGS) -c $(PROTO_SRC) -o $@

libshm/vault_shm.o: $(SHM_SRC) include/vault_shm.h
	$(CC) $(CFLAGS) -c $(SHM_SRC) -o $@

# Build server
server: $(SERVER_BIN)

$(SERVER_BIN): $(SERVER_SRC) $(PROTO_OBJ) $(SHM_OBJ)
	$(CC) $(CFLAGS) $(SERVER_SRC) $(PROTO_OBJ) $(SHM_OBJ) -o $@ $(LDFLAGS)

# Build client
client: $(CLIENT_BIN)

$(CLIENT_BIN): $(CLIENT_SRC) $(PROTO_OBJ)
	$(CC) $(CFLAGS) $(CLIENT_SRC) $(PROTO_OBJ) -o $@ $(LDFLAGS)

# Build protocol unit tests
test_protocol: $(PROTO_OBJ)
	$(CC) $(CFLAGS) $(TEST_PROTO_SRC) $(PROTO_OBJ) -o $(TEST_PROTO_BIN) $(LDFLAGS)

# Run all tests
test: all test_protocol
	@echo ""
	@echo "=== Running Unit Tests ==="
	./$(TEST_PROTO_BIN)
	@echo ""
	@echo "=== Running Integration Tests ==="
	./tests/run_all_tests.sh

# Run integration tests only
integration: all
	@echo "=== Running Integration Tests ==="
	./tests/test_failures.sh
	./tests/test_shutdown.sh
	./tests/test_concurrency.sh

# Clean build artifacts
clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN) $(TEST_PROTO_BIN)
	rm -f $(PROTO_OBJ) $(SHM_OBJ)
	rm -f /dev/shm/vault_shm 2>/dev/null || true

# Show help
help:
	@echo "Bank Vault - Makefile Targets"
	@echo ""
	@echo "  all           - Build server and client (default)"
	@echo "  server        - Build vault_server only"
	@echo "  client        - Build vault_client only"
	@echo "  test_protocol - Build protocol unit tests"
	@echo "  test          - Run all tests (unit + integration)"
	@echo "  integration   - Run integration tests only"
	@echo "  clean         - Remove build artifacts"
	@echo "  help          - Show this help"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make                  # Build everything"
	@echo "  make test             # Run all tests"
	@echo "  ./vault_server --port 7777 --workers 4"
	@echo "  ./vault_client --host 127.0.0.1 --port 7777 --threads 100 --ops 500"
