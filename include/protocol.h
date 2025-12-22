#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stdlib.h>

/*
 * Custom binary frame with enhanced security fields.
 * All multi-byte fields are sent in network byte order.
 *
 * Wire format:
 * [Len:4][Magic:2][Ver:1][Flags:1][Op:2][Seq:4][Timestamp:8][CRC32:4][Body]
 */
typedef struct {
    uint8_t  flags;        /* FLAG_ENCRYPTED, FLAG_ERROR, etc. */
    uint16_t opcode;
    uint32_t seq;
    uint64_t timestamp_ms; /* milliseconds since epoch for replay protection */
    uint8_t *body;
    uint32_t body_len;
} frame_t;

/* Encode frame -> wire buffer */
int proto_encode(frame_t *f, uint8_t **out, size_t *out_len);

/* Decode wire buffer -> frame */
int proto_decode(uint8_t *buf, size_t len, frame_t *out);

/* CRC32 integrity check */
uint32_t proto_crc32(const uint8_t *buf, size_t len);

/* XOR encryption/decryption (symmetric) */
void proto_xor_crypt(uint8_t *data, size_t len, uint32_t key);

/* Derive session key from user and session_id */
uint32_t proto_derive_key(const char *user, uint32_t session_id);

/* Get current timestamp in milliseconds */
uint64_t proto_timestamp_ms(void);

/* Validate timestamp is within acceptable window (30 seconds) */
int proto_validate_timestamp(uint64_t pkt_ts, uint64_t now_ts);

#endif
