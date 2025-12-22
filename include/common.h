#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

/* protocol constants */
#define MAGIC 0xC0DE
#define PROTO_VERSION 1

/* opcodes */
#define OP_LOGIN    0x0001
#define OP_DEPOSIT  0x0002
#define OP_WITHDRAW 0x0003
#define OP_BALANCE  0x0004
#define OP_PING     0x00F0

/* status codes */
#define STATUS_OK             0
#define STATUS_ERR_AUTH       1
#define STATUS_ERR_BAD_CRC    2
#define STATUS_ERR_INSUFFIC   5

#endif