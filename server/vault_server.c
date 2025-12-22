/*
 * vault_server.c - Bank Vault Server with Logging and Rate Limiting
 * 
 * Multi-process server with epoll-based I/O, structured logging,
 * per-connection rate limiting, and timestamp validation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "protocol.h"
#include "vault_shm.h"
#include "common.h"
#include "logger.h"

/* Configuration */
#define DEFAULT_PORT 7777
#define DEFAULT_WORKERS 4
#define MAX_EVENTS 64
#define READ_BUF_SIZE 65536
#define STATS_INTERVAL_SEC 60

/* Shared memory pointer */
static vault_shm_t *g_shm = NULL;
static volatile sig_atomic_t g_running = 1;
static int g_worker_id = -1;  /* -1 for master */
static time_t g_start_time = 0;
static int g_server_log_level = LEVEL_INFO;
static char g_log_file[256] = "";

/* Rate limiter state */
typedef struct {
    uint64_t tokens;           /* Current token count */
    uint64_t last_refill_ms;   /* Last refill timestamp */
} rate_limiter_t;

/* Per-connection session state */
typedef struct {
    int fd;
    int logged_in;
    uint32_t session_id;
    uint32_t session_key;
    char username[64];
    char client_ip[INET_ADDRSTRLEN];
    time_t connect_time;
    time_t last_seen;
    int malformed_count;
    uint64_t request_count;
    
    /* Rate limiting */
    rate_limiter_t rate_limiter;
    
    /* Read buffer for partial messages */
    uint8_t read_buf[READ_BUF_SIZE];
    size_t read_pos;
    
    /* Write buffer for pending responses */
    uint8_t *write_buf;
    size_t write_len;
    size_t write_pos;
} session_t;

/* Session array for epoll-based handling */
static session_t *sessions[MAX_CONNECTIONS_PER_WORKER];

/* Forward declarations */
static const char *opcode_name(uint16_t opcode);

/* SIGINT handler: trigger graceful shutdown */
static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
    if (g_shm) g_shm->shutdown_flag = 1;
}

/* Set socket to non-blocking mode */
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Initialize rate limiter */
static void rate_limiter_init(rate_limiter_t *rl) {
    rl->tokens = RATE_LIMIT_BUCKET_SIZE;
    rl->last_refill_ms = proto_timestamp_ms();
}

/* Check and consume rate limit token */
static int rate_limiter_allow(rate_limiter_t *rl) {
    uint64_t now = proto_timestamp_ms();
    uint64_t elapsed = now - rl->last_refill_ms;
    
    /* Refill tokens based on elapsed time */
    if (elapsed >= RATE_LIMIT_REFILL_MS) {
        uint64_t refill = (elapsed / RATE_LIMIT_REFILL_MS) * RATE_LIMIT_PER_SEC;
        rl->tokens += refill;
        if (rl->tokens > RATE_LIMIT_BUCKET_SIZE) {
            rl->tokens = RATE_LIMIT_BUCKET_SIZE;
        }
        rl->last_refill_ms = now;
    }
    
    /* Try to consume a token */
    if (rl->tokens > 0) {
        rl->tokens--;
        return 1;  /* Allowed */
    }
    
    return 0;  /* Rate limited */
}

/* Create and initialize a new session */
static session_t *session_create(int fd, struct sockaddr_in *addr) {
    session_t *s = calloc(1, sizeof(session_t));
    if (!s) return NULL;
    
    s->fd = fd;
    s->connect_time = time(NULL);
    s->last_seen = s->connect_time;
    
    /* Store client IP */
    if (addr) {
        inet_ntop(AF_INET, &addr->sin_addr, s->client_ip, sizeof(s->client_ip));
    } else {
        strcpy(s->client_ip, "unknown");
    }
    
    /* Initialize rate limiter */
    rate_limiter_init(&s->rate_limiter);
    
    return s;
}

/* Destroy session and free resources */
static void session_destroy(session_t *s) {
    if (!s) return;
    
    /* Log disconnection */
    time_t duration = time(NULL) - s->connect_time;
    log_ctx_t ctx = LOG_CTX(g_worker_id, s->fd);
    LOG_INFO_CTX(ctx, "DISCONNECT ip=%s user=%s duration=%lds requests=%lu",
                 s->client_ip, 
                 s->logged_in ? s->username : "(none)",
                 (long)duration,
                 (unsigned long)s->request_count);
    
    if (s->write_buf) free(s->write_buf);
    close(s->fd);
    free(s);
}

/* Get opcode name for logging */
static const char *opcode_name(uint16_t opcode) {
    switch (opcode) {
        case OP_LOGIN:    return "LOGIN";
        case OP_DEPOSIT:  return "DEPOSIT";
        case OP_WITHDRAW: return "WITHDRAW";
        case OP_BALANCE:  return "BALANCE";
        case OP_TRANSFER: return "TRANSFER";
        case OP_PING:     return "PING";
        default:          return "UNKNOWN";
    }
}

/* Build error response frame */
static void build_error_response(frame_t *resp, uint16_t opcode, uint32_t seq, uint16_t status) {
    resp->flags = FLAG_ERROR;
    resp->opcode = opcode;
    resp->seq = seq;
    resp->timestamp_ms = proto_timestamp_ms();
    resp->body_len = 2;
    resp->body = malloc(2);
    uint16_t ns = htons(status);
    memcpy(resp->body, &ns, 2);
}

/* Handle LOGIN operation */
static void handle_login(session_t *sess, frame_t *req, frame_t *resp) {
    log_ctx_t ctx = LOG_CTX(g_worker_id, sess->fd);
    
    /* Parse username and password from body */
    if (req->body_len < 2) {
        LOG_WARN_CTX(ctx, "LOGIN parse error: body too short");
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_PARSE);
        return;
    }
    
    uint8_t user_len = req->body[0];
    if (req->body_len < (uint32_t)(1 + user_len + 1)) {
        LOG_WARN_CTX(ctx, "LOGIN parse error: invalid user_len=%u", user_len);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_PARSE);
        return;
    }
    
    /* Extract username */
    if (user_len > 0 && user_len < sizeof(sess->username)) {
        memcpy(sess->username, req->body + 1, user_len);
        sess->username[user_len] = '\0';
    } else {
        strncpy(sess->username, "user", sizeof(sess->username) - 1);
    }
    
    /* Generate session ID and derive key */
    sess->session_id = vault_shm_next_session(g_shm);
    sess->session_key = proto_derive_key(sess->username, sess->session_id);
    sess->logged_in = 1;
    
    /* Log successful login */
    LOG_AUDIT_CTX(ctx, "LOGIN user=%s session=0x%08X ip=%s",
                  sess->username, sess->session_id, sess->client_ip);
    
    /* Build success response: status(2) + session_id(4) */
    resp->flags = 0;
    resp->opcode = req->opcode;
    resp->seq = req->seq;
    resp->timestamp_ms = proto_timestamp_ms();
    resp->body_len = 6;
    resp->body = malloc(6);
    
    uint16_t ok = htons(STATUS_OK);
    uint32_t nsid = htonl(sess->session_id);
    memcpy(resp->body, &ok, 2);
    memcpy(resp->body + 2, &nsid, 4);
}

/* Handle PING operation */
static void handle_ping(session_t *sess, frame_t *req, frame_t *resp) {
    (void)sess;
    
    resp->flags = 0;
    resp->opcode = req->opcode;
    resp->seq = req->seq;
    resp->timestamp_ms = proto_timestamp_ms();
    resp->body_len = 10;
    resp->body = malloc(10);
    
    uint16_t ok = htons(STATUS_OK);
    uint64_t now = htobe64(proto_timestamp_ms());
    memcpy(resp->body, &ok, 2);
    memcpy(resp->body + 2, &now, 8);
}

/* Handle BALANCE operation */
static void handle_balance(session_t *sess, frame_t *req, frame_t *resp) {
    log_ctx_t ctx = LOG_CTX(g_worker_id, sess->fd);
    
    if (req->body_len < 4) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_PARSE);
        return;
    }
    
    uint32_t acct_id;
    memcpy(&acct_id, req->body, 4);
    acct_id = ntohl(acct_id);
    
    if (acct_id >= MAX_ACCOUNTS) {
        LOG_WARN_CTX(ctx, "BALANCE invalid account=%u", acct_id);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NO_ACCOUNT);
        return;
    }
    
    /* Lock account and read balance */
    pthread_mutex_lock(&g_shm->acct[acct_id].lock);
    int64_t balance = g_shm->acct[acct_id].balance_cents;
    pthread_mutex_unlock(&g_shm->acct[acct_id].lock);
    
    LOG_DEBUG_CTX(ctx, "BALANCE acct=%u bal=%ld", acct_id, (long)balance);
    
    /* Build response: status(2) + balance(8) */
    resp->flags = 0;
    resp->opcode = req->opcode;
    resp->seq = req->seq;
    resp->timestamp_ms = proto_timestamp_ms();
    resp->body_len = 10;
    resp->body = malloc(10);
    
    uint16_t ok = htons(STATUS_OK);
    int64_t nbal = htobe64(balance);
    memcpy(resp->body, &ok, 2);
    memcpy(resp->body + 2, &nbal, 8);
}

/* Handle DEPOSIT operation */
static void handle_deposit(session_t *sess, frame_t *req, frame_t *resp) {
    log_ctx_t ctx = LOG_CTX(g_worker_id, sess->fd);
    
    if (req->body_len < 12) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_PARSE);
        return;
    }
    
    uint32_t acct_id;
    int64_t amount;
    memcpy(&acct_id, req->body, 4);
    memcpy(&amount, req->body + 4, 8);
    acct_id = ntohl(acct_id);
    amount = be64toh(amount);
    
    if (acct_id >= MAX_ACCOUNTS) {
        LOG_WARN_CTX(ctx, "DEPOSIT invalid account=%u", acct_id);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NO_ACCOUNT);
        return;
    }
    
    if (amount <= 0) {
        LOG_WARN_CTX(ctx, "DEPOSIT invalid amount=%ld", (long)amount);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_AMOUNT_INVALID);
        return;
    }
    
    /* Lock account, add amount, unlock */
    pthread_mutex_lock(&g_shm->acct[acct_id].lock);
    g_shm->acct[acct_id].balance_cents += amount;
    int64_t new_balance = g_shm->acct[acct_id].balance_cents;
    pthread_mutex_unlock(&g_shm->acct[acct_id].lock);
    
    /* Log transaction */
    LOG_AUDIT_CTX(ctx, "DEPOSIT user=%s acct=%u amt=%ld bal=%ld",
                  sess->username, acct_id, (long)amount, (long)new_balance);
    
    /* Build response: status(2) + new_balance(8) */
    resp->flags = 0;
    resp->opcode = req->opcode;
    resp->seq = req->seq;
    resp->timestamp_ms = proto_timestamp_ms();
    resp->body_len = 10;
    resp->body = malloc(10);
    
    uint16_t ok = htons(STATUS_OK);
    int64_t nbal = htobe64(new_balance);
    memcpy(resp->body, &ok, 2);
    memcpy(resp->body + 2, &nbal, 8);
}

/* Handle WITHDRAW operation */
static void handle_withdraw(session_t *sess, frame_t *req, frame_t *resp) {
    log_ctx_t ctx = LOG_CTX(g_worker_id, sess->fd);
    
    if (req->body_len < 12) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_PARSE);
        return;
    }
    
    uint32_t acct_id;
    int64_t amount;
    memcpy(&acct_id, req->body, 4);
    memcpy(&amount, req->body + 4, 8);
    acct_id = ntohl(acct_id);
    amount = be64toh(amount);
    
    if (acct_id >= MAX_ACCOUNTS) {
        LOG_WARN_CTX(ctx, "WITHDRAW invalid account=%u", acct_id);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NO_ACCOUNT);
        return;
    }
    
    if (amount <= 0) {
        LOG_WARN_CTX(ctx, "WITHDRAW invalid amount=%ld", (long)amount);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_AMOUNT_INVALID);
        return;
    }
    
    /* Lock account, check balance, subtract if sufficient */
    pthread_mutex_lock(&g_shm->acct[acct_id].lock);
    int64_t balance = g_shm->acct[acct_id].balance_cents;
    
    if (balance < amount) {
        pthread_mutex_unlock(&g_shm->acct[acct_id].lock);
        LOG_WARN_CTX(ctx, "WITHDRAW insufficient acct=%u bal=%ld amt=%ld",
                     acct_id, (long)balance, (long)amount);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_INSUFFICIENT);
        return;
    }
    
    g_shm->acct[acct_id].balance_cents -= amount;
    int64_t new_balance = g_shm->acct[acct_id].balance_cents;
    pthread_mutex_unlock(&g_shm->acct[acct_id].lock);
    
    /* Log transaction */
    LOG_AUDIT_CTX(ctx, "WITHDRAW user=%s acct=%u amt=%ld bal=%ld",
                  sess->username, acct_id, (long)amount, (long)new_balance);
    
    /* Build response: status(2) + new_balance(8) */
    resp->flags = 0;
    resp->opcode = req->opcode;
    resp->seq = req->seq;
    resp->timestamp_ms = proto_timestamp_ms();
    resp->body_len = 10;
    resp->body = malloc(10);
    
    uint16_t ok = htons(STATUS_OK);
    int64_t nbal = htobe64(new_balance);
    memcpy(resp->body, &ok, 2);
    memcpy(resp->body + 2, &nbal, 8);
}

/* Handle TRANSFER operation */
static void handle_transfer(session_t *sess, frame_t *req, frame_t *resp) {
    log_ctx_t ctx = LOG_CTX(g_worker_id, sess->fd);
    
    if (req->body_len < 16) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_PARSE);
        return;
    }
    
    uint32_t from_id, to_id;
    int64_t amount;
    memcpy(&from_id, req->body, 4);
    memcpy(&to_id, req->body + 4, 4);
    memcpy(&amount, req->body + 8, 8);
    from_id = ntohl(from_id);
    to_id = ntohl(to_id);
    amount = be64toh(amount);
    
    if (from_id >= MAX_ACCOUNTS || to_id >= MAX_ACCOUNTS) {
        LOG_WARN_CTX(ctx, "TRANSFER invalid accounts from=%u to=%u", from_id, to_id);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NO_ACCOUNT);
        return;
    }
    
    if (amount <= 0) {
        LOG_WARN_CTX(ctx, "TRANSFER invalid amount=%ld", (long)amount);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_AMOUNT_INVALID);
        return;
    }
    
    if (from_id == to_id) {
        LOG_WARN_CTX(ctx, "TRANSFER same account from=%u to=%u", from_id, to_id);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_AMOUNT_INVALID);
        return;
    }
    
    /* Lock both accounts in order to prevent deadlock */
    uint32_t first = (from_id < to_id) ? from_id : to_id;
    uint32_t second = (from_id < to_id) ? to_id : from_id;
    
    pthread_mutex_lock(&g_shm->acct[first].lock);
    pthread_mutex_lock(&g_shm->acct[second].lock);
    
    /* Check source balance */
    if (g_shm->acct[from_id].balance_cents < amount) {
        pthread_mutex_unlock(&g_shm->acct[second].lock);
        pthread_mutex_unlock(&g_shm->acct[first].lock);
        LOG_WARN_CTX(ctx, "TRANSFER insufficient from=%u amt=%ld",
                     from_id, (long)amount);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_INSUFFICIENT);
        return;
    }
    
    /* Perform transfer */
    g_shm->acct[from_id].balance_cents -= amount;
    g_shm->acct[to_id].balance_cents += amount;
    
    int64_t from_balance = g_shm->acct[from_id].balance_cents;
    int64_t to_balance = g_shm->acct[to_id].balance_cents;
    
    pthread_mutex_unlock(&g_shm->acct[second].lock);
    pthread_mutex_unlock(&g_shm->acct[first].lock);
    
    /* Log transaction */
    LOG_AUDIT_CTX(ctx, "TRANSFER user=%s from=%u to=%u amt=%ld from_bal=%ld to_bal=%ld",
                  sess->username, from_id, to_id, (long)amount,
                  (long)from_balance, (long)to_balance);
    
    /* Build response: status(2) + from_balance(8) + to_balance(8) */
    resp->flags = 0;
    resp->opcode = req->opcode;
    resp->seq = req->seq;
    resp->timestamp_ms = proto_timestamp_ms();
    resp->body_len = 18;
    resp->body = malloc(18);
    
    uint16_t ok = htons(STATUS_OK);
    int64_t nfrom = htobe64(from_balance);
    int64_t nto = htobe64(to_balance);
    memcpy(resp->body, &ok, 2);
    memcpy(resp->body + 2, &nfrom, 8);
    memcpy(resp->body + 10, &nto, 8);
}

/* Process a complete request frame and generate response */
static int process_request(session_t *sess, frame_t *req, frame_t *resp) {
    log_ctx_t ctx = LOG_CTX(g_worker_id, sess->fd);
    
    memset(resp, 0, sizeof(frame_t));
    sess->request_count++;
    
    /* Update stats - count every request regardless of outcome */
    pthread_mutex_lock(&g_shm->global_lock);
    g_shm->total_requests++;
    pthread_mutex_unlock(&g_shm->global_lock);
    
    /* Check rate limit */
    if (!rate_limiter_allow(&sess->rate_limiter)) {
        LOG_WARN_CTX(ctx, "RATE_LIMIT user=%s ip=%s", 
                     sess->logged_in ? sess->username : "(none)", sess->client_ip);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_RATE_LIMIT);
        pthread_mutex_lock(&g_shm->global_lock);
        g_shm->total_errors++;
        pthread_mutex_unlock(&g_shm->global_lock);
        return 0;
    }
    
    /* Validate timestamp (replay protection) */
    uint64_t now = proto_timestamp_ms();
    if (!proto_validate_timestamp(req->timestamp_ms, now)) {
        LOG_WARN_CTX(ctx, "BAD_TIMESTAMP pkt=%lu now=%lu",
                     (unsigned long)req->timestamp_ms, (unsigned long)now);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_BAD_TIMESTAMP);
        pthread_mutex_lock(&g_shm->global_lock);
        g_shm->total_errors++;
        pthread_mutex_unlock(&g_shm->global_lock);
        return 0;
    }
    
    /* Check if login required for this operation */
    if (!sess->logged_in && req->opcode != OP_LOGIN && req->opcode != OP_PING) {
        LOG_WARN_CTX(ctx, "NOT_AUTH op=%s", opcode_name(req->opcode));
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NOT_AUTH);
        pthread_mutex_lock(&g_shm->global_lock);
        g_shm->total_errors++;
        pthread_mutex_unlock(&g_shm->global_lock);
        return 0;
    }
    
    /* Log request at debug level */
    LOG_DEBUG_CTX(ctx, "REQUEST op=%s seq=%u", opcode_name(req->opcode), req->seq);
    
    /* Dispatch to operation handler */
    switch (req->opcode) {
        case OP_LOGIN:
            handle_login(sess, req, resp);
            break;
        case OP_PING:
            handle_ping(sess, req, resp);
            break;
        case OP_BALANCE:
            handle_balance(sess, req, resp);
            break;
        case OP_DEPOSIT:
            handle_deposit(sess, req, resp);
            break;
        case OP_WITHDRAW:
            handle_withdraw(sess, req, resp);
            break;
        case OP_TRANSFER:
            handle_transfer(sess, req, resp);
            break;
        default:
            LOG_WARN_CTX(ctx, "BAD_OPCODE op=0x%04X", req->opcode);
            build_error_response(resp, req->opcode, req->seq, STATUS_ERR_BAD_OPCODE);
            pthread_mutex_lock(&g_shm->global_lock);
            g_shm->total_errors++;
            pthread_mutex_unlock(&g_shm->global_lock);
            break;
    }
    
    return 0;
}

/* Try to extract and process complete frames from read buffer */
static int process_read_buffer(session_t *sess, int epfd) {
    log_ctx_t ctx = LOG_CTX(g_worker_id, sess->fd);
    
    while (sess->read_pos >= 4) {
        /* Read packet length */
        uint32_t pkt_len;
        memcpy(&pkt_len, sess->read_buf, 4);
        pkt_len = ntohl(pkt_len);
        
        /* Validate length */
        if (pkt_len < HEADER_SIZE || pkt_len > MAX_PACKET) {
            sess->malformed_count++;
            LOG_WARN_CTX(ctx, "MALFORMED pkt_len=%u count=%d", pkt_len, sess->malformed_count);
            if (sess->malformed_count >= MAX_MALFORMED_PACKETS) {
                LOG_ERROR_CTX(ctx, "TOO_MANY_MALFORMED disconnecting");
                return -1;  /* Disconnect */
            }
            /* Skip 4 bytes and try again */
            memmove(sess->read_buf, sess->read_buf + 4, sess->read_pos - 4);
            sess->read_pos -= 4;
            continue;
        }
        
        /* Wait for complete packet */
        if (sess->read_pos < pkt_len) {
            break;
        }
        
        /* Decode frame */
        frame_t req = {0};
        int rc = proto_decode(sess->read_buf, pkt_len, &req);
        
        /* Remove processed bytes from buffer */
        memmove(sess->read_buf, sess->read_buf + pkt_len, sess->read_pos - pkt_len);
        sess->read_pos -= pkt_len;
        
        if (rc != 0) {
            sess->malformed_count++;
            uint16_t err_code;
            const char *err_name;
            
            switch (rc) {
                case -2: err_code = STATUS_ERR_BAD_MAGIC; err_name = "BAD_MAGIC"; break;
                case -3: err_code = STATUS_ERR_BAD_VERSION; err_name = "BAD_VERSION"; break;
                case -4: err_code = STATUS_ERR_BAD_CRC; err_name = "BAD_CRC"; break;
                default: err_code = STATUS_ERR_PARSE; err_name = "PARSE"; break;
            }
            
            LOG_WARN_CTX(ctx, "%s rc=%d count=%d", err_name, rc, sess->malformed_count);
            
            if (sess->malformed_count >= MAX_MALFORMED_PACKETS) {
                LOG_ERROR_CTX(ctx, "TOO_MANY_MALFORMED disconnecting");
                return -1;
            }
            
            /* Send error response */
            frame_t resp = {0};
            build_error_response(&resp, 0, 0, err_code);
            
            uint8_t *out;
            size_t out_len;
            proto_encode(&resp, &out, &out_len);
            write(sess->fd, out, out_len);  /* Best effort */
            free(out);
            free(resp.body);
            continue;
        }
        
        /* Decrypt body if encrypted flag is set */
        if ((req.flags & FLAG_ENCRYPTED) && sess->logged_in && req.body_len > 0) {
            proto_xor_crypt(req.body, req.body_len, sess->session_key);
        }
        
        /* Process request */
        frame_t resp = {0};
        process_request(sess, &req, &resp);
        
        /* Encode and send response */
        uint8_t *out;
        size_t out_len;
        proto_encode(&resp, &out, &out_len);
        
        /* Queue for writing (simplified: blocking write for now) */
        ssize_t written = write(sess->fd, out, out_len);
        if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            free(out);
            free(resp.body);
            if (req.body) free(req.body);
            return -1;
        }
        
        free(out);
        free(resp.body);
        if (req.body) free(req.body);
        
        /* Update last seen time */
        sess->last_seen = time(NULL);
    }
    
    (void)epfd;
    return 0;
}

/* Worker process main loop using epoll */
static void worker_loop(int listen_fd, int worker_id) {
    g_worker_id = worker_id;
    
    /* Initialize logging for worker */
    int log_dest = LOG_DEST_STDOUT;
    if (g_log_file[0]) {
        log_dest |= LOG_DEST_FILE;
    }
    log_init(g_server_log_level, log_dest, g_log_file[0] ? g_log_file : NULL, LOG_COLOR_AUTO);
    
    LOG_INFO("Worker %d started (PID %d)", worker_id, getpid());
    
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        LOG_ERROR("epoll_create1 failed: %s", strerror(errno));
        return;
    }
    
    /* Add listening socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);
    
    struct epoll_event events[MAX_EVENTS];
    time_t last_stats_time = time(NULL);
    
    while (g_running && !g_shm->shutdown_flag) {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, 1000);  /* 1 second timeout */
        
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            
            if (fd == listen_fd) {
                /* Accept new connection */
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
                
                if (client_fd < 0) continue;
                
                if (client_fd >= MAX_CONNECTIONS_PER_WORKER) {
                    LOG_WARN("Connection rejected: fd=%d >= max=%d", 
                             client_fd, MAX_CONNECTIONS_PER_WORKER);
                    close(client_fd);
                    continue;
                }
                
                set_nonblocking(client_fd);
                
                /* Create session */
                session_t *sess = session_create(client_fd, &client_addr);
                if (!sess) {
                    close(client_fd);
                    continue;
                }
                sessions[client_fd] = sess;
                
                /* Add to epoll */
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = client_fd;
                epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev);
                
                vault_shm_conn_add(g_shm);
                
                log_ctx_t ctx = LOG_CTX(worker_id, client_fd);
                LOG_INFO_CTX(ctx, "CONNECT ip=%s", sess->client_ip);
                
            } else {
                /* Handle client data */
                session_t *sess = sessions[fd];
                if (!sess) continue;
                
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    /* Connection error or hangup */
                    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                    session_destroy(sess);
                    sessions[fd] = NULL;
                    vault_shm_conn_remove(g_shm);
                    continue;
                }
                
                if (events[i].events & EPOLLIN) {
                    /* Read available data */
                    while (1) {
                        size_t space = sizeof(sess->read_buf) - sess->read_pos;
                        if (space == 0) break;
                        
                        ssize_t n = read(fd, sess->read_buf + sess->read_pos, space);
                        if (n < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                            /* Error - close connection */
                            epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                            session_destroy(sess);
                            sessions[fd] = NULL;
                            vault_shm_conn_remove(g_shm);
                            goto next_event;
                        }
                        if (n == 0) {
                            /* EOF - close connection */
                            epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                            session_destroy(sess);
                            sessions[fd] = NULL;
                            vault_shm_conn_remove(g_shm);
                            goto next_event;
                        }
                        
                        sess->read_pos += n;
                    }
                    
                    /* Process complete frames */
                    if (process_read_buffer(sess, epfd) < 0) {
                        epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                        session_destroy(sess);
                        sessions[fd] = NULL;
                        vault_shm_conn_remove(g_shm);
                    }
                }
            }
            next_event:;
        }
        
        /* Check for idle connections and log stats periodically */
        time_t now = time(NULL);
        
        for (int fd = 0; fd < MAX_CONNECTIONS_PER_WORKER; fd++) {
            if (sessions[fd] && (now - sessions[fd]->last_seen) > IDLE_TIMEOUT_SEC) {
                log_ctx_t ctx = LOG_CTX(worker_id, fd);
                LOG_INFO_CTX(ctx, "IDLE_TIMEOUT ip=%s", sessions[fd]->client_ip);
                epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                session_destroy(sessions[fd]);
                sessions[fd] = NULL;
                vault_shm_conn_remove(g_shm);
            }
        }
        
        /* Periodic stats logging */
        if (now - last_stats_time >= STATS_INTERVAL_SEC) {
            log_stats(g_shm->total_requests, g_shm->total_errors,
                      g_shm->active_connections, now - g_start_time);
            last_stats_time = now;
        }
    }
    
    /* Cleanup: close all client connections */
    for (int fd = 0; fd < MAX_CONNECTIONS_PER_WORKER; fd++) {
        if (sessions[fd]) {
            session_destroy(sessions[fd]);
            sessions[fd] = NULL;
        }
    }
    
    close(epfd);
    LOG_INFO("Worker %d shutting down", worker_id);
    log_shutdown();
}

/* Print usage */
static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --port PORT      Listen port (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  --workers N      Number of worker processes (default: %d)\n", DEFAULT_WORKERS);
    fprintf(stderr, "  --log-level LVL  Log level: debug, info, warn, error (default: info)\n");
    fprintf(stderr, "  --log-file FILE  Log file path (default: stdout only)\n");
    fprintf(stderr, "  --help           Show this help\n");
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    int num_workers = DEFAULT_WORKERS;
    
    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
            num_workers = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "debug") == 0) g_server_log_level = LEVEL_DEBUG;
            else if (strcmp(argv[i], "info") == 0) g_server_log_level = LEVEL_INFO;
            else if (strcmp(argv[i], "warn") == 0) g_server_log_level = LEVEL_WARN;
            else if (strcmp(argv[i], "error") == 0) g_server_log_level = LEVEL_ERROR;
        } else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc) {
            strncpy(g_log_file, argv[++i], sizeof(g_log_file) - 1);
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }
    
    /* Initialize logging for master */
    int log_dest = LOG_DEST_STDOUT;
    if (g_log_file[0]) {
        log_dest |= LOG_DEST_FILE;
    }
    log_init(g_server_log_level, log_dest, g_log_file[0] ? g_log_file : NULL, LOG_COLOR_AUTO);
    
    /* Set up signal handlers */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGCHLD, SIG_IGN);  /* Auto-reap children */
    
    /* Initialize shared memory */
    g_shm = vault_shm_init(1);
    if (!g_shm) {
        LOG_ERROR("Failed to initialize shared memory");
        return 1;
    }
    
    g_start_time = time(NULL);
    
    LOG_INFO("Bank Vault Server starting...");
    LOG_INFO("  Port: %d", port);
    LOG_INFO("  Workers: %d", num_workers);
    LOG_INFO("  Accounts: %d", MAX_ACCOUNTS);
    LOG_INFO("  Rate limit: %d req/s", RATE_LIMIT_PER_SEC);
    LOG_INFO("  Log level: %d", g_server_log_level);
    
    /* Create listening socket */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        LOG_ERROR("socket() failed: %s", strerror(errno));
        vault_shm_cleanup(g_shm);
        return 1;
    }
    
    /* Set socket options */
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("bind() failed: %s", strerror(errno));
        close(listen_fd);
        vault_shm_cleanup(g_shm);
        return 1;
    }
    
    if (listen(listen_fd, 128) < 0) {
        LOG_ERROR("listen() failed: %s", strerror(errno));
        close(listen_fd);
        vault_shm_cleanup(g_shm);
        return 1;
    }
    
    LOG_INFO("Listening on port %d...", port);
    
    /* Fork worker processes */
    pid_t workers[num_workers];
    for (int i = 0; i < num_workers; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            /* Child - run worker loop */
            worker_loop(listen_fd, i);
            exit(0);
        } else if (pid > 0) {
            workers[i] = pid;
        } else {
            LOG_ERROR("fork() failed: %s", strerror(errno));
        }
    }
    
    LOG_INFO("Master process running (PID %d)", getpid());
    LOG_INFO("Press Ctrl+C to shutdown gracefully");
    
    /* Master process waits for shutdown signal */
    while (g_running) {
        pause();
    }
    
    LOG_INFO("Shutdown signal received. Stopping workers...");
    
    /* Signal workers to stop */
    g_shm->shutdown_flag = 1;
    
    /* Wait for workers to finish */
    for (int i = 0; i < num_workers; i++) {
        if (workers[i] > 0) {
            kill(workers[i], SIGTERM);
            waitpid(workers[i], NULL, 0);
        }
    }
    
    /* Print final stats */
    LOG_INFO("=== Final Statistics ===");
    LOG_INFO("  Total Requests: %lu", (unsigned long)g_shm->total_requests);
    LOG_INFO("  Total Errors: %lu", (unsigned long)g_shm->total_errors);
    LOG_INFO("  Uptime: %ld seconds", (long)(time(NULL) - g_start_time));
    
    /* Cleanup */
    close(listen_fd);
    vault_shm_cleanup(g_shm);
    
    LOG_INFO("Server shutdown complete.");
    log_shutdown();
    
    return 0;
}
