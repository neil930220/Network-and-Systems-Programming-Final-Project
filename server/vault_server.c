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

/* Configuration */
#define DEFAULT_PORT 7777
#define DEFAULT_WORKERS 4
#define MAX_EVENTS 64
#define READ_BUF_SIZE 65536

/* Shared memory pointer */
static vault_shm_t *g_shm = NULL;
static volatile sig_atomic_t g_running = 1;

/* Per-connection session state */
typedef struct {
    int fd;
    int logged_in;
    uint32_t session_id;
    uint32_t session_key;
    char username[64];
    time_t last_seen;
    int malformed_count;
    
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

/* Create and initialize a new session */
static session_t *session_create(int fd) {
    session_t *s = calloc(1, sizeof(session_t));
    if (!s) return NULL;
    s->fd = fd;
    s->last_seen = time(NULL);
    return s;
}

/* Destroy session and free resources */
static void session_destroy(session_t *s) {
    if (!s) return;
    if (s->write_buf) free(s->write_buf);
    close(s->fd);
    free(s);
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
    /* Parse username and password from body */
    if (req->body_len < 2) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_PARSE);
        return;
    }
    
    uint8_t user_len = req->body[0];
    if (req->body_len < (uint32_t)(1 + user_len + 1)) {
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
    (void)sess;
    
    if (req->body_len < 4) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_PARSE);
        return;
    }
    
    uint32_t acct_id;
    memcpy(&acct_id, req->body, 4);
    acct_id = ntohl(acct_id);
    
    if (acct_id >= MAX_ACCOUNTS) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NO_ACCOUNT);
        return;
    }
    
    /* Lock account and read balance */
    pthread_mutex_lock(&g_shm->acct[acct_id].lock);
    int64_t balance = g_shm->acct[acct_id].balance_cents;
    pthread_mutex_unlock(&g_shm->acct[acct_id].lock);
    
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
    (void)sess;
    
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
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NO_ACCOUNT);
        return;
    }
    
    if (amount <= 0) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_AMOUNT_INVALID);
        return;
    }
    
    /* Lock account, add amount, unlock */
    pthread_mutex_lock(&g_shm->acct[acct_id].lock);
    g_shm->acct[acct_id].balance_cents += amount;
    int64_t new_balance = g_shm->acct[acct_id].balance_cents;
    pthread_mutex_unlock(&g_shm->acct[acct_id].lock);
    
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
    (void)sess;
    
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
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NO_ACCOUNT);
        return;
    }
    
    if (amount <= 0) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_AMOUNT_INVALID);
        return;
    }
    
    /* Lock account, check balance, subtract if sufficient */
    pthread_mutex_lock(&g_shm->acct[acct_id].lock);
    int64_t balance = g_shm->acct[acct_id].balance_cents;
    
    if (balance < amount) {
        pthread_mutex_unlock(&g_shm->acct[acct_id].lock);
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_INSUFFICIENT);
        return;
    }
    
    g_shm->acct[acct_id].balance_cents -= amount;
    int64_t new_balance = g_shm->acct[acct_id].balance_cents;
    pthread_mutex_unlock(&g_shm->acct[acct_id].lock);
    
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
    (void)sess;
    
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
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NO_ACCOUNT);
        return;
    }
    
    if (amount <= 0) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_AMOUNT_INVALID);
        return;
    }
    
    if (from_id == to_id) {
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
    memset(resp, 0, sizeof(frame_t));
    
    /* Update stats */
    pthread_mutex_lock(&g_shm->global_lock);
    g_shm->total_requests++;
    pthread_mutex_unlock(&g_shm->global_lock);
    
    /* Check if login required for this operation */
    if (!sess->logged_in && req->opcode != OP_LOGIN && req->opcode != OP_PING) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NOT_AUTH);
        pthread_mutex_lock(&g_shm->global_lock);
        g_shm->total_errors++;
        pthread_mutex_unlock(&g_shm->global_lock);
        return 0;
    }
    
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
    while (sess->read_pos >= 4) {
        /* Read packet length */
        uint32_t pkt_len;
        memcpy(&pkt_len, sess->read_buf, 4);
        pkt_len = ntohl(pkt_len);
        
        /* Validate length */
        if (pkt_len < HEADER_SIZE || pkt_len > MAX_PACKET) {
            sess->malformed_count++;
            if (sess->malformed_count >= MAX_MALFORMED_PACKETS) {
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
            if (sess->malformed_count >= MAX_MALFORMED_PACKETS) {
                return -1;
            }
            
            /* Send error response for CRC failure */
            frame_t resp = {0};
            uint16_t err_code = (rc == -4) ? STATUS_ERR_BAD_CRC : STATUS_ERR_PARSE;
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
    printf("[Worker %d] Started (PID %d)\n", worker_id, getpid());
    
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        return;
    }
    
    /* Add listening socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);
    
    struct epoll_event events[MAX_EVENTS];
    
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
                    close(client_fd);
                    continue;
                }
                
                set_nonblocking(client_fd);
                
                /* Create session */
                session_t *sess = session_create(client_fd);
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
        
        /* Check for idle connections (every loop iteration for simplicity) */
        time_t now = time(NULL);
        for (int fd = 0; fd < MAX_CONNECTIONS_PER_WORKER; fd++) {
            if (sessions[fd] && (now - sessions[fd]->last_seen) > IDLE_TIMEOUT_SEC) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                session_destroy(sessions[fd]);
                sessions[fd] = NULL;
                vault_shm_conn_remove(g_shm);
            }
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
    printf("[Worker %d] Shutting down\n", worker_id);
}

/* Print usage */
static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --port PORT      Listen port (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  --workers N      Number of worker processes (default: %d)\n", DEFAULT_WORKERS);
    fprintf(stderr, "  --accounts N     Number of accounts (default: %d)\n", MAX_ACCOUNTS);
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
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }
    
    /* Set up signal handlers */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGCHLD, SIG_IGN);  /* Auto-reap children */
    
    /* Initialize shared memory */
    g_shm = vault_shm_init(1);
    if (!g_shm) {
        fprintf(stderr, "Failed to initialize shared memory\n");
        return 1;
    }
    
    printf("Bank Vault Server starting...\n");
    printf("  Port: %d\n", port);
    printf("  Workers: %d\n", num_workers);
    printf("  Accounts: %d\n", MAX_ACCOUNTS);
    
    /* Create listening socket */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
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
        perror("bind");
        close(listen_fd);
        vault_shm_cleanup(g_shm);
        return 1;
    }
    
    if (listen(listen_fd, 128) < 0) {
        perror("listen");
        close(listen_fd);
        vault_shm_cleanup(g_shm);
        return 1;
    }
    
    printf("Listening on port %d...\n", port);
    
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
            perror("fork");
        }
    }
    
    printf("Master process running (PID %d)\n", getpid());
    printf("Press Ctrl+C to shutdown gracefully\n\n");
    
    /* Master process waits for shutdown signal */
    while (g_running) {
        pause();
    }
    
    printf("\nShutdown signal received. Stopping workers...\n");
    
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
    printf("\nFinal Statistics:\n");
    printf("  Total Requests: %lu\n", (unsigned long)g_shm->total_requests);
    printf("  Total Errors: %lu\n", (unsigned long)g_shm->total_errors);
    
    /* Cleanup */
    close(listen_fd);
    vault_shm_cleanup(g_shm);
    
    printf("Server shutdown complete.\n");
    return 0;
}
