#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

/* protocol constants */
#define MAGIC 0xC0DE
#define PROTO_VERSION 1
#define MAX_PACKET 65536
#define HEADER_SIZE 26  /* 4+2+1+1+2+4+8+4 = Len+Magic+Ver+Flags+Op+Seq+Timestamp+CRC */

/* flag bits */
#define FLAG_ENCRYPTED   0x01  /* bit0: XOR encrypted body */
#define FLAG_ERROR       0x02  /* bit1: error response */
#define FLAG_RESERVED    0x04  /* bit2: reserved */

/* opcodes */
#define OP_LOGIN    0x0001
#define OP_DEPOSIT  0x0002
#define OP_WITHDRAW 0x0003
#define OP_BALANCE  0x0004
#define OP_TRANSFER 0x0005
#define OP_PING     0x00F0

/* status codes - Success */
#define STATUS_OK                   0x0000

/* status codes - Protocol/Parse errors (0x1xxx) */
#define STATUS_ERR_BAD_MAGIC        0x1001
#define STATUS_ERR_BAD_VERSION      0x1002
#define STATUS_ERR_BAD_LENGTH       0x1003
#define STATUS_ERR_TOO_LARGE        0x1004
#define STATUS_ERR_BAD_OPCODE       0x1005
#define STATUS_ERR_PARSE            0x1006
#define STATUS_ERR_BAD_CRC          0x1007
#define STATUS_ERR_BAD_MAC          0x1008
#define STATUS_ERR_REPLAY           0x100A
#define STATUS_ERR_BAD_TIMESTAMP    0x100C

/* status codes - Auth/Session errors (0x2xxx) */
#define STATUS_ERR_NOT_AUTH         0x2001
#define STATUS_ERR_AUTH_FAILED      0x2002
#define STATUS_ERR_AUTH_LOCKED      0x2003
#define STATUS_ERR_SESSION_INVALID  0x2004
#define STATUS_ERR_PERMISSION       0x2006

/* status codes - Business logic errors (0x3xxx) */
#define STATUS_ERR_NO_ACCOUNT       0x3001
#define STATUS_ERR_INSUFFICIENT     0x3002
#define STATUS_ERR_AMOUNT_INVALID   0x3003
#define STATUS_ERR_TXN_CONFLICT     0x3006

/* status codes - Rate/Availability errors (0x4xxx) */
#define STATUS_ERR_RATE_LIMIT       0x4001
#define STATUS_ERR_TOO_MANY_CONN    0x4002
#define STATUS_ERR_SERVER_BUSY      0x4003
#define STATUS_ERR_TIMEOUT          0x4004

/* status codes - Internal server errors (0x5xxx) */
#define STATUS_ERR_INTERNAL         0x5001
#define STATUS_ERR_IPC_FAIL         0x5002
#define STATUS_ERR_SHUTTING_DOWN    0x5004

/* Legacy aliases for backward compatibility */
#define STATUS_ERR_AUTH             STATUS_ERR_NOT_AUTH
#define STATUS_ERR_INSUFFIC         STATUS_ERR_INSUFFICIENT

/* connection limits */
#define MAX_CONNECTIONS_PER_WORKER  1024
#define IDLE_TIMEOUT_SEC            60
#define MAX_MALFORMED_PACKETS       3
#define RATE_LIMIT_PER_SEC          50

/* timestamp validation (replay protection) */
#define TIMESTAMP_WINDOW_MS         30000  /* 30 seconds */

/* rate limiting configuration */
#define RATE_LIMIT_BUCKET_SIZE      1000   /* max burst size (increased for high-throughput testing) */
#define RATE_LIMIT_REFILL_MS        1000   /* refill interval */

/* debug configuration */
#ifdef DEBUG
#define DEBUG_PROTOCOL              1      /* enable protocol debugging */
#define DEBUG_TIMING                1      /* enable timing measurements */
#else
#define DEBUG_PROTOCOL              0
#define DEBUG_TIMING                0
#endif

/* Helper macro for status code categories */
#define STATUS_IS_OK(s)             ((s) == STATUS_OK)
#define STATUS_IS_PROTOCOL_ERR(s)   (((s) & 0xF000) == 0x1000)
#define STATUS_IS_AUTH_ERR(s)       (((s) & 0xF000) == 0x2000)
#define STATUS_IS_BUSINESS_ERR(s)   (((s) & 0xF000) == 0x3000)
#define STATUS_IS_RATE_ERR(s)       (((s) & 0xF000) == 0x4000)
#define STATUS_IS_SERVER_ERR(s)     (((s) & 0xF000) == 0x5000)

/* Get status code name string */
const char *status_code_name(uint16_t status);

#endif
