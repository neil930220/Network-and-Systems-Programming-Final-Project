#include "protocol.h"
#include "common.h"
#include <string.h>
#include <arpa/inet.h>

/*
 * Simple CRC32 implementation.
 * Not optimized; clarity is preferred for coursework.
 */
uint32_t proto_crc32(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int j = 0; j < 8; j++) {
            uint32_t mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return ~crc;
}

/*
 * Frame format on wire:
 * [len][magic][ver][opcode][seq][crc][body]
 */
int proto_encode(frame_t *f, uint8_t **out, size_t *out_len) {
    uint32_t total = 4 + 2 + 1 + 2 + 4 + 4 + f->body_len;
    uint8_t *buf = calloc(1, total);
    uint32_t off = 0;

    uint32_t nlen = htonl(total);
    memcpy(buf + off, &nlen, 4); off += 4;

    uint16_t magic = htons(MAGIC);
    memcpy(buf + off, &magic, 2); off += 2;

    buf[off++] = PROTO_VERSION;

    uint16_t nop = htons(f->opcode);
    memcpy(buf + off, &nop, 2); off += 2;

    uint32_t nseq = htonl(f->seq);
    memcpy(buf + off, &nseq, 4); off += 4;

    /* CRC placeholder */
    off += 4;

    if (f->body_len)
        memcpy(buf + off, f->body, f->body_len);

    uint32_t crc = proto_crc32(buf, total);
    uint32_t ncrc = htonl(crc);
    memcpy(buf + 13, &ncrc, 4);

    *out = buf;
    *out_len = total;
    return 0;
}

int proto_decode(uint8_t *buf, size_t len, frame_t *out) {
    uint32_t pkt_len;
    memcpy(&pkt_len, buf, 4);
    pkt_len = ntohl(pkt_len);
    if (pkt_len != len) return -1;

    uint32_t recv_crc;
    memcpy(&recv_crc, buf + 13, 4);
    recv_crc = ntohl(recv_crc);

    memset(buf + 13, 0, 4);
    if (proto_crc32(buf, len) != recv_crc)
        return -2;

    out->opcode = ntohs(*(uint16_t *)(buf + 7));
    out->seq    = ntohl(*(uint32_t *)(buf + 9));
    out->body_len = len - 17;

    if (out->body_len) {
        out->body = malloc(out->body_len);
        memcpy(out->body, buf + 17, out->body_len);
    }
    return 0;
}
