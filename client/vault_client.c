#include <pthread.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>
#include <stdlib.h>

#include "protocol.h"
#include "common.h"

#define THREADS 100
#define OPS_PER_THREAD 500

static double lat[THREADS * OPS_PER_THREAD];
static atomic_int lat_idx = 0;

static double diff_ms(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000.0 +
           (b.tv_nsec - a.tv_nsec) / 1e6;
}

void *worker(void *arg) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(7777);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    connect(fd, (void *)&addr, sizeof(addr));

    /* LOGIN */
    frame_t login = {.opcode = OP_LOGIN, .seq = 1};
    uint8_t *out; size_t out_len;
    proto_encode(&login, &out, &out_len);
    write(fd, out, out_len);
    read(fd, out, out_len);
    free(out);

    for (int i = 0; i < OPS_PER_THREAD; i++) {
        uint32_t acct = htonl(1);
        frame_t req = {.opcode = OP_BALANCE, .seq = i,
                       .body = (uint8_t *)&acct, .body_len = 4};

        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);

        proto_encode(&req, &out, &out_len);
        write(fd, out, out_len);
        read(fd, out, out_len);

        clock_gettime(CLOCK_MONOTONIC, &t2);

        int idx = atomic_fetch_add(&lat_idx, 1);
        lat[idx] = diff_ms(t1, t2);

        free(out);

        if (i % 100 == 0) {
            frame_t ping = {.opcode = OP_PING, .seq = i};
            proto_encode(&ping, &out, &out_len);
            write(fd, out, out_len);
            free(out);
        }
    }
    close(fd);
    return NULL;
}

int cmp(const void *a, const void *b) {
    double x = *(double *)a, y = *(double *)b;
    return (x > y) - (x < y);
}

int main() {
    pthread_t th[THREADS];
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < THREADS; i++)
        pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < THREADS; i++)
        pthread_join(th[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &end);

    int total = lat_idx;
    qsort(lat, total, sizeof(double), cmp);

    double sec = diff_ms(start, end) / 1000.0;

    printf("total_ops=%d\n", total);
    printf("throughput=%.2f req/s\n", total / sec);
    printf("latency_ms: p50=%.2f p95=%.2f p99=%.2f max=%.2f\n",
           lat[total*50/100],
           lat[total*95/100],
           lat[total*99/100],
           lat[total-1]);
}
