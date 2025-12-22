## Bank Vault

A small “bank vault” system implemented in C: a multi-process, epoll-based TCP server plus two clients:

- **`vault_cli`**: an interactive ncurses TUI for login/balance/deposit/withdraw/transfer + history.
- **`vault_client`**: a threaded load generator for concurrency/perf testing.

State (accounts + counters) is shared across worker processes via **POSIX shared memory**.

### Key features

- **Multi-process server**: master + N worker processes (`--workers`), each using `epoll`.
- **Shared state**: balances are stored in cents, with per-account **process-shared mutexes**.
- **Binary protocol**: length-prefixed frames with **magic/version**, **timestamp**, and **CRC32**.
- **Basic protections**: per-connection rate limiting, idle timeouts, malformed packet thresholds, timestamp window checks.
- **Structured logging**: levels (debug/info/warn/error/audit), stdout and optional log file.
- **Test suite**: unit tests for protocol + integration/security/concurrency/shutdown scripts.

> Note on security: this is coursework-style security hardening (integrity checks, replay window, rate limiting). It is **not** a production-secure banking system.

## Build

### Requirements

- **GCC/Clang**, `make`
- **pthread**, **librt** (POSIX shm)
- **ncurses** (for `vault_cli`)

Examples:
- Arch: `sudo pacman -S base-devel ncurses`
- Debian/Ubuntu: `sudo apt-get install build-essential libncurses-dev`

### Compile

```bash
make
```

Useful targets:

```bash
make help
make clean
make debug
```

This produces:

- `vault_server`
- `vault_client`
- `vault_cli`
- `test_protocol`

## Run

### Start the server

```bash
./vault_server --port 7777 --workers 4 --log-level info
```

Optional logging to a file:

```bash
./vault_server --port 7777 --workers 4 --log-level debug --log-file server.log
```

To stop the server gracefully: press **Ctrl+C** (master sets a shared shutdown flag and terminates workers).

### Interactive TUI client (`vault_cli`)

`vault_cli` is a full-screen ncurses UI (minimum terminal size **80x24**).

```bash
./vault_cli --host 127.0.0.1 --port 7777
```

In the UI:
- Navigate with **UP/DOWN** or number keys
- **Login** first, then run operations
- **History** shows recent operations and latencies

### Load generator (`vault_client`)

Runs a multi-threaded request mix against the server and prints throughput + latency percentiles.

```bash
./vault_client --host 127.0.0.1 --port 7777 --threads 100 --ops 500
```

Customize the operation mix (percentages sum to 100):

```bash
./vault_client --mix balance=40,deposit=30,withdraw=20,transfer=10
```

## Tests

Run everything (unit + integration):

```bash
make test
```

Verbose integration tests:

```bash
make verbose-test
```

Run the full test runner directly (optionally save logs):

```bash
./tests/run_all_tests.sh -v --save-logs
```

Individual integration scripts:

- `./tests/test_failures.sh`
- `./tests/test_shutdown.sh`
- `./tests/test_concurrency.sh`
- `./tests/test_security.sh`

## Architecture

### Server model

- **Master process**:
  - Parses flags (`--port`, `--workers`, `--log-level`, `--log-file`)
  - Initializes shared memory (`/dev/shm/vault_shm` on Linux)
  - Forks worker processes
  - On SIGINT/SIGTERM, triggers a graceful shutdown
- **Workers**:
  - Use `epoll` to accept and handle connections
  - Maintain per-connection session state (login flag, session id/key, rate limiter, malformed count, buffers)
  - Apply rate limiting + timestamp validation before dispatching operations

### Shared memory

The shared state is defined in `include/vault_shm.h`:

- `MAX_ACCOUNTS = 10000`
- Each account has a **process-shared mutex** + `balance_cents`
- Accounts start with **$1000.00** (`100000` cents) on first initialization
- Shared counters: `total_requests`, `total_errors`, `active_connections`, `shutdown_flag`, `next_session_id`

On Linux the segment is backed by `SHM_NAME="/vault_shm"` and typically appears as:
- `/dev/shm/vault_shm`

### Logging

Logging is implemented in `include/logger.h` / `libutil/logger.c` with levels:

- `debug`, `info`, `warn`, `error` (filtered by chosen level)
- `audit` (always logged)

Server log lines include timestamp + optional `[worker:X][conn:Y]` context.

## Protocol

### Frame format

Wire format (all multibyte fields in network byte order):

```
[Len:4][Magic:2][Ver:1][Flags:1][Op:2][Seq:4][Timestamp:8][CRC32:4][Body...]
```

- `Magic`: `0xC0DE`
- `Ver`: `1`
- `CRC32`: computed over the entire packet (with the CRC field zeroed during verification)
- `Timestamp`: milliseconds since epoch; server validates it is within a ~30s window

### Operations (opcodes)

- `OP_LOGIN` (0x0001)
- `OP_DEPOSIT` (0x0002)
- `OP_WITHDRAW` (0x0003)
- `OP_BALANCE` (0x0004)
- `OP_TRANSFER` (0x0005)
- `OP_PING` (0x00F0)

### Status codes

Responses embed a 16-bit status code in the body (see `include/common.h`), for example:

- `STATUS_OK` (0x0000)
- Protocol/parse errors (0x1xxx): bad magic/version/CRC, parse errors, etc.
- Auth/session errors (0x2xxx): not authenticated, session invalid, etc.
- Business logic errors (0x3xxx): insufficient funds, invalid amount, etc.
- Rate/availability errors (0x4xxx): rate limited, server busy, etc.
- Server/internal errors (0x5xxx)

## Security notes (educational)

- **Integrity**: CRC32 detects accidental corruption/tampering but is not a cryptographic MAC.
- **Replay window**: server rejects frames with timestamps outside `TIMESTAMP_WINDOW_MS` (30s).
- **Rate limiting**: per-connection token bucket; requests may return `STATUS_ERR_RATE_LIMIT`.
- **Optional body “encryption”**: protocol supports XOR body encryption (`FLAG_ENCRYPTED`) with a session-derived key.
  - The current shipped clients send bodies with `flags=0` (no encryption), but the hooks exist in the protocol/server.

## Troubleshooting

- **`vault_cli` fails to link**: install ncurses dev headers (`libncurses-dev` / `ncurses`).
- **Stale shared memory**: run `make clean` (it removes `/dev/shm/vault_shm`) or manually:

```bash
rm -f /dev/shm/vault_shm
```

- **Seeing rate-limit errors in load tests**: reduce `--threads/--ops` or adjust `RATE_LIMIT_*` constants in `include/common.h`.

## Repo layout

- **`server/`**: `vault_server.c`
- **`client/`**: `vault_client.c` (load generator), `vault_cli.c` (ncurses TUI)
- **`include/`**: protocol + shared memory + logging headers
- **`libproto/`**: protocol encoding/decoding + CRC/XOR helpers
- **`libshm/`**: shared memory initialization/helpers
- **`libutil/`**: structured logging implementation
- **`tests/`**: unit tests + integration/security test scripts
- **`Bank_Vault_Project_Plan.pdf`**, **`Bank_Vault_Security_Design.pdf`**: design docs

## License

See `LICENSE`.