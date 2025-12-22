#include "protocol.h"
#include "common.h"
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

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
 * XOR encryption/decryption using a 32-bit key.
 * Key bytes are cycled over the data.
 */
void proto_xor_crypt(uint8_t *data, size_t len, uint32_t key) {
    uint8_t key_bytes[4];
    key_bytes[0] = (key >> 24) & 0xFF;
    key_bytes[1] = (key >> 16) & 0xFF;
    key_bytes[2] = (key >> 8) & 0xFF;
    key_bytes[3] = key & 0xFF;

    for (size_t i = 0; i < len; i++) {
        data[i] ^= key_bytes[i % 4];
    }
}

/*
 * Derive session key from username and session_id.
 */
uint32_t proto_derive_key(const char *user, uint32_t session_id) {
    size_t user_len = strlen(user);
    size_t total_len = user_len + sizeof(session_id);
    uint8_t *buf = malloc(total_len);
    
    memcpy(buf, user, user_len);
    memcpy(buf + user_len, &session_id, sizeof(session_id));
    
    uint32_t key = proto_crc32(buf, total_len);
    free(buf);
    return key;
}

/*
 * Get current timestamp in milliseconds since epoch.
 */
uint64_t proto_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * Validate that packet timestamp is within 30 seconds of current time.
 */
int proto_validate_timestamp(uint64_t pkt_ts, uint64_t now_ts) {
    int64_t diff = (int64_t)now_ts - (int64_t)pkt_ts;
    if (diff < 0) diff = -diff;
    return diff <= 30000;  /* 30 seconds in ms */
}

/*
 * Frame format on wire (updated):
 * [len:4][magic:2][ver:1][flags:1][opcode:2][seq:4][timestamp:8][crc:4][body]
 *
 * Header size = 4 + 2 + 1 + 1 + 2 + 4 + 8 + 4 = 26 bytes
 */
int proto_encode(frame_t *f, uint8_t **out, size_t *out_len) {
    uint32_t total = HEADER_SIZE + f->body_len;
    uint8_t *buf = calloc(1, total);
    if (!buf) return -1;
    
    uint32_t off = 0;

    /* Length */
    uint32_t nlen = htonl(total);
    memcpy(buf + off, &nlen, 4); off += 4;

    /* Magic */
    uint16_t magic = htons(MAGIC);
    memcpy(buf + off, &magic, 2); off += 2;

    /* Version */
    buf[off++] = PROTO_VERSION;

    /* Flags */
    buf[off++] = f->flags;

    /* Opcode */
    uint16_t nop = htons(f->opcode);
    memcpy(buf + off, &nop, 2); off += 2;

    /* Sequence */
    uint32_t nseq = htonl(f->seq);
    memcpy(buf + off, &nseq, 4); off += 4;

    /* Timestamp */
    uint64_t ts = f->timestamp_ms;
    if (ts == 0) ts = proto_timestamp_ms();
    uint64_t nts = htobe64(ts);
    memcpy(buf + off, &nts, 8); off += 8;

    /* CRC placeholder */
    off += 4;

    /* Body */
    if (f->body_len && f->body) {
        memcpy(buf + off, f->body, f->body_len);
    }

    /* Calculate and insert CRC */
    uint32_t crc = proto_crc32(buf, total);
    uint32_t ncrc = htonl(crc);
    memcpy(buf + 22, &ncrc, 4);  /* CRC is at offset 22 */

    *out = buf;
    *out_len = total;
    return 0;
}

int proto_decode(uint8_t *buf, size_t len, frame_t *out) {
    /* Minimum header size check */
    if (len < HEADER_SIZE) return -1;

    /* Packet length */
    uint32_t pkt_len;
    memcpy(&pkt_len, buf, 4);
    pkt_len = ntohl(pkt_len);
    if (pkt_len != len) return -1;
    if (pkt_len > MAX_PACKET) return -1;

    /* Magic validation */
    uint16_t magic;
    memcpy(&magic, buf + 4, 2);
    magic = ntohs(magic);
    if (magic != MAGIC) return -2;

    /* Version validation */
    uint8_t version = buf[6];
    if (version != PROTO_VERSION) return -3;

    /* CRC validation */
    uint32_t recv_crc;
    memcpy(&recv_crc, buf + 22, 4);
    recv_crc = ntohl(recv_crc);

    /* Zero CRC field for calculation */
    uint8_t saved_crc[4];
    memcpy(saved_crc, buf + 22, 4);
    memset(buf + 22, 0, 4);
    uint32_t calc_crc = proto_crc32(buf, len);
    memcpy(buf + 22, saved_crc, 4);  /* Restore */

    if (calc_crc != recv_crc) return -4;

    /* Parse fields */
    out->flags = buf[7];
    out->opcode = ntohs(*(uint16_t *)(buf + 8));
    out->seq = ntohl(*(uint32_t *)(buf + 10));
    out->timestamp_ms = be64toh(*(uint64_t *)(buf + 14));
    out->body_len = len - HEADER_SIZE;

    if (out->body_len > 0) {
        out->body = malloc(out->body_len);
        if (!out->body) return -5;
        memcpy(out->body, buf + HEADER_SIZE, out->body_len);
    } else {
        out->body = NULL;
    }

    return 0;
}
