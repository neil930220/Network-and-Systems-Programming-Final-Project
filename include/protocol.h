#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stdlib.h>

/*
 * Custom binary frame.
 * All multi-byte fields are sent in network byte order.
 */
typedef struct {
    uint16_t opcode;
    uint32_t seq;
    uint8_t *body;
    uint32_t body_len;
} frame_t;

/* Encode frame -> wire buffer */
int proto_encode(frame_t *f, uint8_t **out, size_t *out_len);

/* Decode wire buffer -> frame */
int proto_decode(uint8_t *buf, size_t len, frame_t *out);

/* CRC32 integrity check */
uint32_t proto_crc32(const uint8_t *buf, size_t len);

#endif
