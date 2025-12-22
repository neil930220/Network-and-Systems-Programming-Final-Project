#include <pthread.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <errno.h>
#include <getopt.h>

#include "protocol.h"
#include "common.h"

/* Default configuration */
#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 7777
#define DEFAULT_THREADS 100
#define DEFAULT_OPS 500
#define MAX_LATENCY_SAMPLES (1024 * 1024)

/* Operation mix percentages (must sum to 100) */
typedef struct {
    int balance;
    int deposit;
    int withdraw;
    int transfer;
} op_mix_t;

/* Global configuration */
static char g_host[256] = DEFAULT_HOST;
static int g_port = DEFAULT_PORT;
static int g_threads = DEFAULT_THREADS;
static int g_ops = DEFAULT_OPS;
static op_mix_t g_mix = {40, 30, 20, 10};  /* balance, deposit, withdraw, transfer */

/* Global statistics */
static double *g_latencies;
static atomic_int g_lat_idx = 0;
static atomic_int g_ok_count = 0;
static atomic_int g_err_count = 0;
static atomic_int g_timeout_count = 0;
static atomic_int g_reconnect_count = 0;

/* Barrier for synchronized start */
static pthread_barrier_t g_barrier;

/* Calculate time difference in milliseconds */
static double diff_ms(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000.0 +
           (b.tv_nsec - a.tv_nsec) / 1e6;
}

/* Connect to server with timeout */
static int connect_to_server(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_port);
    inet_pton(AF_INET, g_host, &addr.sin_addr);
    
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    return fd;
}

/* Send request and receive response */
static int send_recv(int fd, frame_t *req, frame_t *resp) {
    uint8_t *out;
    size_t out_len;
    
    if (proto_encode(req, &out, &out_len) != 0) {
        return -1;
    }
    
    /* Send request */
    ssize_t sent = write(fd, out, out_len);
    free(out);
    
    if (sent != (ssize_t)out_len) {
        return -1;
    }
    
    /* Read response header (at least 4 bytes for length) */
    uint8_t buf[65536];
    ssize_t n = read(fd, buf, 4);
    if (n != 4) {
        return -1;
    }
    
    uint32_t pkt_len = ntohl(*(uint32_t *)buf);
    if (pkt_len > sizeof(buf) || pkt_len < HEADER_SIZE) {
        return -1;
    }
    
    /* Read rest of packet */
    size_t remaining = pkt_len - 4;
    size_t total_read = 4;
    while (remaining > 0) {
        n = read(fd, buf + total_read, remaining);
        if (n <= 0) {
            return -1;
        }
        total_read += n;
        remaining -= n;
    }
    
    /* Decode response */
    return proto_decode(buf, pkt_len, resp);
}

/* Perform login */
static int do_login(int fd, uint32_t *session_id) {
    /* Build login body: user_len(1) + user + pass_len(1) + pass */
    const char *user = "testuser";
    const char *pass = "testpass";
    uint8_t body[256];
    size_t off = 0;
    
    body[off++] = strlen(user);
    memcpy(body + off, user, strlen(user));
    off += strlen(user);
    body[off++] = strlen(pass);
    memcpy(body + off, pass, strlen(pass));
    off += strlen(pass);
    
    frame_t req = {
        .flags = 0,
        .opcode = OP_LOGIN,
        .seq = 0,
        .body = body,
        .body_len = off
    };
    
    frame_t resp = {0};
    if (send_recv(fd, &req, &resp) != 0) {
        return -1;
    }
    
    /* Check response */
    if (resp.body_len >= 6) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        if (status == STATUS_OK) {
            *session_id = ntohl(*(uint32_t *)(resp.body + 2));
            if (resp.body) free(resp.body);
            return 0;
        }
    }
    
    if (resp.body) free(resp.body);
    return -1;
}

/* Perform balance query */
static int do_balance(int fd, uint32_t acct_id, uint32_t seq) {
    uint32_t nacct = htonl(acct_id);
    
    frame_t req = {
        .flags = 0,
        .opcode = OP_BALANCE,
        .seq = seq,
        .body = (uint8_t *)&nacct,
        .body_len = 4
    };
    
    frame_t resp = {0};
    if (send_recv(fd, &req, &resp) != 0) {
        return -1;
    }
    
    int result = -1;
    if (resp.body_len >= 2) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        result = (status == STATUS_OK) ? 0 : status;
    }
    
    if (resp.body) free(resp.body);
    return result;
}

/* Perform deposit */
static int do_deposit(int fd, uint32_t acct_id, int64_t amount, uint32_t seq) {
    uint8_t body[12];
    uint32_t nacct = htonl(acct_id);
    int64_t namount = htobe64(amount);
    memcpy(body, &nacct, 4);
    memcpy(body + 4, &namount, 8);
    
    frame_t req = {
        .flags = 0,
        .opcode = OP_DEPOSIT,
        .seq = seq,
        .body = body,
        .body_len = 12
    };
    
    frame_t resp = {0};
    if (send_recv(fd, &req, &resp) != 0) {
        return -1;
    }
    
    int result = -1;
    if (resp.body_len >= 2) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        result = (status == STATUS_OK) ? 0 : status;
    }
    
    if (resp.body) free(resp.body);
    return result;
}

/* Perform withdraw */
static int do_withdraw(int fd, uint32_t acct_id, int64_t amount, uint32_t seq) {
    uint8_t body[12];
    uint32_t nacct = htonl(acct_id);
    int64_t namount = htobe64(amount);
    memcpy(body, &nacct, 4);
    memcpy(body + 4, &namount, 8);
    
    frame_t req = {
        .flags = 0,
        .opcode = OP_WITHDRAW,
        .seq = seq,
        .body = body,
        .body_len = 12
    };
    
    frame_t resp = {0};
    if (send_recv(fd, &req, &resp) != 0) {
        return -1;
    }
    
    int result = -1;
    if (resp.body_len >= 2) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        result = (status == STATUS_OK) ? 0 : status;
    }
    
    if (resp.body) free(resp.body);
    return result;
}

/* Perform transfer */
static int do_transfer(int fd, uint32_t from_id, uint32_t to_id, int64_t amount, uint32_t seq) {
    uint8_t body[16];
    uint32_t nfrom = htonl(from_id);
    uint32_t nto = htonl(to_id);
    int64_t namount = htobe64(amount);
    memcpy(body, &nfrom, 4);
    memcpy(body + 4, &nto, 4);
    memcpy(body + 8, &namount, 8);
    
    frame_t req = {
        .flags = 0,
        .opcode = OP_TRANSFER,
        .seq = seq,
        .body = body,
        .body_len = 16
    };
    
    frame_t resp = {0};
    if (send_recv(fd, &req, &resp) != 0) {
        return -1;
    }
    
    int result = -1;
    if (resp.body_len >= 2) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        result = (status == STATUS_OK) ? 0 : status;
    }
    
    if (resp.body) free(resp.body);
    return result;
}

/* Perform ping/heartbeat */
static int do_ping(int fd, uint32_t seq) {
    frame_t req = {
        .flags = 0,
        .opcode = OP_PING,
        .seq = seq,
        .body = NULL,
        .body_len = 0
    };
    
    frame_t resp = {0};
    if (send_recv(fd, &req, &resp) != 0) {
        return -1;
    }
    
    int result = -1;
    if (resp.body_len >= 2) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        result = (status == STATUS_OK) ? 0 : status;
    }
    
    if (resp.body) free(resp.body);
    return result;
}

/* Select operation based on mix */
static int select_operation(void) {
    int r = rand() % 100;
    if (r < g_mix.balance) return OP_BALANCE;
    r -= g_mix.balance;
    if (r < g_mix.deposit) return OP_DEPOSIT;
    r -= g_mix.deposit;
    if (r < g_mix.withdraw) return OP_WITHDRAW;
    return OP_TRANSFER;
}

/* Worker thread function */
static void *worker(void *arg) {
    int thread_id = (int)(long)arg;
    unsigned int seed = time(NULL) ^ thread_id;
    
    /* Wait for all threads to be ready */
    pthread_barrier_wait(&g_barrier);
    
    int fd = -1;
    uint32_t session_id = 0;
    int retry_count = 0;
    const int max_retries = 3;
    
reconnect:
    if (fd >= 0) {
        close(fd);
        atomic_fetch_add(&g_reconnect_count, 1);
    }
    
    fd = connect_to_server();
    if (fd < 0) {
        if (++retry_count < max_retries) {
            usleep(100000 * retry_count);  /* Exponential backoff */
            goto reconnect;
        }
        return NULL;
    }
    
    /* Perform login */
    if (do_login(fd, &session_id) != 0) {
        if (++retry_count < max_retries) {
            usleep(100000 * retry_count);
            goto reconnect;
        }
        close(fd);
        return NULL;
    }
    
    /* Execute operations */
    for (int i = 0; i < g_ops; i++) {
        struct timespec t1, t2;
        int op = select_operation();
        int result = -1;
        uint32_t seq = i;
        
        /* Random account selection */
        uint32_t acct1 = rand_r(&seed) % 100;  /* Use first 100 accounts */
        uint32_t acct2 = (acct1 + 1 + (rand_r(&seed) % 99)) % 100;
        int64_t amount = (rand_r(&seed) % 100 + 1) * 100;  /* $1-$100 in cents */
        
        clock_gettime(CLOCK_MONOTONIC, &t1);
        
        switch (op) {
            case OP_BALANCE:
                result = do_balance(fd, acct1, seq);
                break;
            case OP_DEPOSIT:
                result = do_deposit(fd, acct1, amount, seq);
                break;
            case OP_WITHDRAW:
                result = do_withdraw(fd, acct1, amount, seq);
                break;
            case OP_TRANSFER:
                result = do_transfer(fd, acct1, acct2, amount, seq);
                break;
        }
        
        clock_gettime(CLOCK_MONOTONIC, &t2);
        
        /* Record latency */
        int idx = atomic_fetch_add(&g_lat_idx, 1);
        if (idx < MAX_LATENCY_SAMPLES) {
            g_latencies[idx] = diff_ms(t1, t2);
        }
        
        /* Track success/failure */
        if (result == 0) {
            atomic_fetch_add(&g_ok_count, 1);
        } else if (result < 0) {
            atomic_fetch_add(&g_timeout_count, 1);
            /* Try to reconnect */
            retry_count = 0;
            goto reconnect;
        } else {
            /* Business logic error (e.g., insufficient funds) - still counts as processed */
            atomic_fetch_add(&g_err_count, 1);
        }
        
        /* Send heartbeat every 100 operations */
        if (i > 0 && i % 100 == 0) {
            do_ping(fd, seq);
        }
    }
    
    close(fd);
    return NULL;
}

/* Comparison function for qsort */
static int cmp_double(const void *a, const void *b) {
    double x = *(double *)a;
    double y = *(double *)b;
    return (x > y) - (x < y);
}

/* Parse operation mix string: "balance=40,deposit=30,withdraw=20,transfer=10" */
static int parse_mix(const char *str) {
    char *dup = strdup(str);
    char *token = strtok(dup, ",");
    
    g_mix.balance = g_mix.deposit = g_mix.withdraw = g_mix.transfer = 0;
    
    while (token) {
        char op[32];
        int val;
        if (sscanf(token, "%31[^=]=%d", op, &val) == 2) {
            if (strcmp(op, "balance") == 0) g_mix.balance = val;
            else if (strcmp(op, "deposit") == 0) g_mix.deposit = val;
            else if (strcmp(op, "withdraw") == 0) g_mix.withdraw = val;
            else if (strcmp(op, "transfer") == 0) g_mix.transfer = val;
        }
        token = strtok(NULL, ",");
    }
    
    free(dup);
    
    int total = g_mix.balance + g_mix.deposit + g_mix.withdraw + g_mix.transfer;
    if (total != 100) {
        fprintf(stderr, "Warning: mix percentages sum to %d, not 100. Adjusting balance.\n", total);
        g_mix.balance += (100 - total);
    }
    
    return 0;
}

/* Print usage */
static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --host HOST      Server host (default: %s)\n", DEFAULT_HOST);
    fprintf(stderr, "  --port PORT      Server port (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  --threads N      Number of client threads (default: %d)\n", DEFAULT_THREADS);
    fprintf(stderr, "  --ops N          Operations per thread (default: %d)\n", DEFAULT_OPS);
    fprintf(stderr, "  --mix STR        Operation mix (default: balance=40,deposit=30,withdraw=20,transfer=10)\n");
    fprintf(stderr, "  --help           Show this help\n");
}

int main(int argc, char *argv[]) {
    /* Parse command line arguments */
    static struct option long_options[] = {
        {"host", required_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"threads", required_argument, 0, 't'},
        {"ops", required_argument, 0, 'o'},
        {"mix", required_argument, 0, 'm'},
        {"help", no_argument, 0, '?'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "h:p:t:o:m:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                strncpy(g_host, optarg, sizeof(g_host) - 1);
                break;
            case 'p':
                g_port = atoi(optarg);
                break;
            case 't':
                g_threads = atoi(optarg);
                break;
            case 'o':
                g_ops = atoi(optarg);
                break;
            case 'm':
                parse_mix(optarg);
                break;
            case '?':
            default:
                usage(argv[0]);
                return 1;
        }
    }
    
    printf("Bank Vault Client - Load Generator\n");
    printf("===================================\n");
    printf("Target: %s:%d\n", g_host, g_port);
    printf("Threads: %d\n", g_threads);
    printf("Ops/thread: %d\n", g_ops);
    printf("Mix: balance=%d%%, deposit=%d%%, withdraw=%d%%, transfer=%d%%\n",
           g_mix.balance, g_mix.deposit, g_mix.withdraw, g_mix.transfer);
    printf("\n");
    
    /* Allocate latency array */
    g_latencies = calloc(MAX_LATENCY_SAMPLES, sizeof(double));
    if (!g_latencies) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    
    /* Initialize barrier */
    pthread_barrier_init(&g_barrier, NULL, g_threads);
    
    /* Create threads */
    pthread_t *threads = calloc(g_threads, sizeof(pthread_t));
    struct timespec start, end;
    
    printf("Starting load test...\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < g_threads; i++) {
        pthread_create(&threads[i], NULL, worker, (void *)(long)i);
    }
    
    /* Wait for all threads to complete */
    for (int i = 0; i < g_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    /* Calculate statistics */
    int total_samples = g_lat_idx;
    if (total_samples > MAX_LATENCY_SAMPLES) {
        total_samples = MAX_LATENCY_SAMPLES;
    }
    
    double duration_sec = diff_ms(start, end) / 1000.0;
    int total_ok = g_ok_count;
    int total_err = g_err_count;
    int total_timeout = g_timeout_count;
    int total_reconnect = g_reconnect_count;
    int total_ops = total_ok + total_err;
    
    /* Sort latencies for percentile calculation */
    if (total_samples > 0) {
        qsort(g_latencies, total_samples, sizeof(double), cmp_double);
    }
    
    /* Print results */
    printf("\n");
    printf("RESULT:\n");
    printf("=======\n");
    printf("total_ops=%d ok=%d err=%d duration=%.2fs\n",
           total_ops, total_ok, total_err, duration_sec);
    printf("throughput=%.1f req/s\n", total_ops / duration_sec);
    
    if (total_samples > 0) {
        printf("latency_ms: p50=%.2f p95=%.2f p99=%.2f max=%.2f\n",
               g_latencies[(int)(total_samples * 0.50)],
               g_latencies[(int)(total_samples * 0.95)],
               g_latencies[(int)(total_samples * 0.99)],
               g_latencies[total_samples - 1]);
    }
    
    printf("reconnects=%d timeouts=%d\n", total_reconnect, total_timeout);
    
    /* Cleanup */
    free(threads);
    free(g_latencies);
    pthread_barrier_destroy(&g_barrier);
    
    return 0;
}
