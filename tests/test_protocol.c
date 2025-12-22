/*
 * Unit tests for protocol encoding/decoding, CRC32, and XOR encryption.
 * Compile: gcc -Wall -Iinclude tests/test_protocol.c libproto/protocol.c -o test_protocol
 * Run: ./test_protocol
 */

#define _DEFAULT_SOURCE  /* For usleep */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "protocol.h"
#include "common.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("Running %s... ", #name); \
    fflush(stdout); \
    test_##name(); \
    printf("PASSED\n"); \
    tests_passed++; \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAILED: %s != %s (got %ld, expected %ld)\n", #a, #b, (long)(a), (long)(b)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("FAILED: memory mismatch at %s vs %s\n", #a, #b); \
        tests_failed++; \
        return; \
    } \
} while(0)

/* Test CRC32 known values */
TEST(crc32_basic) {
    /* Empty string */
    uint32_t crc = proto_crc32((uint8_t *)"", 0);
    ASSERT_EQ(crc, 0x00000000);
    
    /* "123456789" - standard CRC32 test vector */
    crc = proto_crc32((uint8_t *)"123456789", 9);
    ASSERT_EQ(crc, 0xCBF43926);
}

TEST(crc32_single_byte) {
    uint8_t data = 0x00;
    uint32_t crc = proto_crc32(&data, 1);
    /* CRC32 of single zero byte */
    ASSERT_EQ(crc, 0xD202EF8D);
}

TEST(crc32_hello) {
    uint32_t crc = proto_crc32((uint8_t *)"Hello, World!", 13);
    /* Known CRC32 of "Hello, World!" */
    ASSERT_EQ(crc, 0xEC4AC3D0);
}

/* Test XOR encryption/decryption */
TEST(xor_roundtrip) {
    uint8_t original[] = "This is a secret message!";
    size_t len = sizeof(original);
    uint8_t data[sizeof(original)];
    memcpy(data, original, len);
    
    uint32_t key = 0xDEADBEEF;
    
    /* Encrypt */
    proto_xor_crypt(data, len, key);
    
    /* Should be different from original */
    int different = 0;
    for (size_t i = 0; i < len; i++) {
        if (data[i] != original[i]) {
            different = 1;
            break;
        }
    }
    ASSERT_EQ(different, 1);
    
    /* Decrypt */
    proto_xor_crypt(data, len, key);
    
    /* Should match original */
    ASSERT_MEM_EQ(data, original, len);
}

TEST(xor_empty) {
    uint8_t data[] = "";
    uint32_t key = 0x12345678;
    proto_xor_crypt(data, 0, key);
    /* Should not crash */
}

TEST(xor_single_byte) {
    uint8_t original = 0x42;
    uint8_t data = original;
    uint32_t key = 0xAABBCCDD;
    
    proto_xor_crypt(&data, 1, key);
    ASSERT_EQ(data, original ^ 0xAA);  /* First key byte */
    
    proto_xor_crypt(&data, 1, key);
    ASSERT_EQ(data, original);
}

/* Test session key derivation */
TEST(derive_key) {
    uint32_t key1 = proto_derive_key("user1", 12345);
    uint32_t key2 = proto_derive_key("user1", 12345);
    uint32_t key3 = proto_derive_key("user1", 12346);
    uint32_t key4 = proto_derive_key("user2", 12345);
    
    /* Same inputs should give same key */
    ASSERT_EQ(key1, key2);
    
    /* Different session_id should give different key */
    if (key1 == key3) {
        printf("FAILED: key1 == key3 (unexpected collision)\n");
        tests_failed++;
        return;
    }
    
    /* Different user should give different key */
    if (key1 == key4) {
        printf("FAILED: key1 == key4 (unexpected collision)\n");
        tests_failed++;
        return;
    }
}

/* Test timestamp */
TEST(timestamp) {
    uint64_t ts1 = proto_timestamp_ms();
    usleep(10000);  /* 10ms */
    uint64_t ts2 = proto_timestamp_ms();
    
    /* ts2 should be greater */
    if (ts2 <= ts1) {
        printf("FAILED: timestamp not monotonic\n");
        tests_failed++;
        return;
    }
    
    /* Difference should be reasonable (between 10ms and 1s) */
    uint64_t diff = ts2 - ts1;
    if (diff < 5 || diff > 1000) {
        printf("FAILED: timestamp diff unreasonable: %lu\n", (unsigned long)diff);
        tests_failed++;
        return;
    }
}

TEST(validate_timestamp) {
    uint64_t now = proto_timestamp_ms();
    
    /* Same timestamp should be valid */
    ASSERT_EQ(proto_validate_timestamp(now, now), 1);
    
    /* 1 second ago should be valid */
    ASSERT_EQ(proto_validate_timestamp(now - 1000, now), 1);
    
    /* 29 seconds ago should be valid */
    ASSERT_EQ(proto_validate_timestamp(now - 29000, now), 1);
    
    /* 31 seconds ago should be invalid */
    ASSERT_EQ(proto_validate_timestamp(now - 31000, now), 0);
    
    /* 1 second in future should be valid */
    ASSERT_EQ(proto_validate_timestamp(now + 1000, now), 1);
    
    /* 31 seconds in future should be invalid */
    ASSERT_EQ(proto_validate_timestamp(now + 31000, now), 0);
}

/* Test protocol encode/decode */
TEST(encode_decode_empty_body) {
    frame_t req = {
        .flags = 0,
        .opcode = OP_PING,
        .seq = 42,
        .timestamp_ms = 0,
        .body = NULL,
        .body_len = 0
    };
    
    uint8_t *buf;
    size_t len;
    int rc = proto_encode(&req, &buf, &len);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(len, HEADER_SIZE);
    
    /* Decode */
    frame_t resp = {0};
    rc = proto_decode(buf, len, &resp);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(resp.opcode, OP_PING);
    ASSERT_EQ(resp.seq, 42);
    ASSERT_EQ(resp.body_len, 0);
    
    free(buf);
}

TEST(encode_decode_with_body) {
    uint8_t body[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    frame_t req = {
        .flags = FLAG_ENCRYPTED,
        .opcode = OP_BALANCE,
        .seq = 12345,
        .timestamp_ms = 0,
        .body = body,
        .body_len = sizeof(body)
    };
    
    uint8_t *buf;
    size_t len;
    int rc = proto_encode(&req, &buf, &len);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(len, HEADER_SIZE + sizeof(body));
    
    /* Decode */
    frame_t resp = {0};
    rc = proto_decode(buf, len, &resp);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(resp.flags, FLAG_ENCRYPTED);
    ASSERT_EQ(resp.opcode, OP_BALANCE);
    ASSERT_EQ(resp.seq, 12345);
    ASSERT_EQ(resp.body_len, sizeof(body));
    ASSERT_MEM_EQ(resp.body, body, sizeof(body));
    
    free(buf);
    free(resp.body);
}

TEST(decode_bad_magic) {
    uint8_t buf[HEADER_SIZE] = {0};
    uint32_t len = htonl(HEADER_SIZE);
    memcpy(buf, &len, 4);
    /* Wrong magic */
    buf[4] = 0xBA;
    buf[5] = 0xD0;
    
    frame_t resp = {0};
    int rc = proto_decode(buf, HEADER_SIZE, &resp);
    ASSERT_EQ(rc, -2);  /* Magic error */
}

TEST(decode_bad_version) {
    uint8_t buf[HEADER_SIZE] = {0};
    uint32_t len = htonl(HEADER_SIZE);
    uint16_t magic = htons(MAGIC);
    memcpy(buf, &len, 4);
    memcpy(buf + 4, &magic, 2);
    buf[6] = 99;  /* Wrong version */
    
    frame_t resp = {0};
    int rc = proto_decode(buf, HEADER_SIZE, &resp);
    ASSERT_EQ(rc, -3);  /* Version error */
}

TEST(decode_bad_crc) {
    frame_t req = {
        .flags = 0,
        .opcode = OP_PING,
        .seq = 1,
        .timestamp_ms = 0,
        .body = NULL,
        .body_len = 0
    };
    
    uint8_t *buf;
    size_t len;
    proto_encode(&req, &buf, &len);
    
    /* Corrupt CRC */
    buf[22] ^= 0xFF;
    
    frame_t resp = {0};
    int rc = proto_decode(buf, len, &resp);
    ASSERT_EQ(rc, -4);  /* CRC error */
    
    free(buf);
}

TEST(decode_too_short) {
    uint8_t buf[10] = {0};
    frame_t resp = {0};
    int rc = proto_decode(buf, 10, &resp);
    ASSERT_EQ(rc, -1);  /* Too short */
}

TEST(decode_length_mismatch) {
    uint8_t buf[HEADER_SIZE] = {0};
    uint32_t len = htonl(100);  /* Claim longer than buffer */
    memcpy(buf, &len, 4);
    
    frame_t resp = {0};
    int rc = proto_decode(buf, HEADER_SIZE, &resp);
    ASSERT_EQ(rc, -1);  /* Length mismatch */
}

/* Test all opcodes defined */
TEST(opcodes_defined) {
    ASSERT_EQ(OP_LOGIN, 0x0001);
    ASSERT_EQ(OP_DEPOSIT, 0x0002);
    ASSERT_EQ(OP_WITHDRAW, 0x0003);
    ASSERT_EQ(OP_BALANCE, 0x0004);
    ASSERT_EQ(OP_TRANSFER, 0x0005);
    ASSERT_EQ(OP_PING, 0x00F0);
}

/* Test status codes defined */
TEST(status_codes_defined) {
    ASSERT_EQ(STATUS_OK, 0x0000);
    ASSERT_EQ(STATUS_ERR_BAD_CRC, 0x1007);
    ASSERT_EQ(STATUS_ERR_NOT_AUTH, 0x2001);
    ASSERT_EQ(STATUS_ERR_INSUFFICIENT, 0x3002);
    ASSERT_EQ(STATUS_ERR_RATE_LIMIT, 0x4001);
}

/* Main test runner */
int main(void) {
    printf("=== Protocol Unit Tests ===\n\n");
    
    /* CRC32 tests */
    RUN_TEST(crc32_basic);
    RUN_TEST(crc32_single_byte);
    RUN_TEST(crc32_hello);
    
    /* XOR encryption tests */
    RUN_TEST(xor_roundtrip);
    RUN_TEST(xor_empty);
    RUN_TEST(xor_single_byte);
    
    /* Key derivation tests */
    RUN_TEST(derive_key);
    
    /* Timestamp tests */
    RUN_TEST(timestamp);
    RUN_TEST(validate_timestamp);
    
    /* Encode/decode tests */
    RUN_TEST(encode_decode_empty_body);
    RUN_TEST(encode_decode_with_body);
    RUN_TEST(decode_bad_magic);
    RUN_TEST(decode_bad_version);
    RUN_TEST(decode_bad_crc);
    RUN_TEST(decode_too_short);
    RUN_TEST(decode_length_mismatch);
    
    /* Constants tests */
    RUN_TEST(opcodes_defined);
    RUN_TEST(status_codes_defined);
    
    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}

