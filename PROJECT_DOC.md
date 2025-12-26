## Bank Vault 專案詳細文件（含 code 位置標註）

## 專案概觀

此專案實作一個「小型銀行金庫系統」：

- **Server**：多行程（master + N workers），每個 worker 使用 `epoll` 處理 TCP 連線與請求。
- **Client (TUI)**：`ncurses` 互動式介面，支援登入、查餘額、存款、提款、轉帳、歷史紀錄。
- **Client (Load Generator)**：多執行緒壓測工具，支援混合操作比例與延遲統計。
- **Shared State**：帳戶餘額/全域統計透過 POSIX shared memory 在 worker 行程間共享，並以 process-shared mutex 保護。
- **Binary Protocol**：長度前置（length-prefixed）的二進位封包，含 magic/version/timestamp/CRC32，並提供 XOR body 加解密鉤子。

`README.md` 已有高階介紹；本文件補上「原始碼層級」的拆解與定位方式。

---

## Repo 結構與責任分工

- **`server/`**：server 主程式與核心流程  
  - `server/vault_server.c`
- **`client/`**：兩個 client  
  - `client/vault_cli.c`（ncurses TUI）  
  - `client/vault_client.c`（load generator）
- **`include/`**：共用 header（protocol / constants / shared memory / logger）  
  - `include/protocol.h`, `include/common.h`, `include/vault_shm.h`, `include/logger.h`
- **`libproto/`**：協定 encode/decode、CRC32、XOR、key derivation  
  - `libproto/protocol.c`
- **`libshm/`**：shared memory 初始化與 helper  
  - `libshm/vault_shm.c`
- **`libutil/`**：logger 實作  
  - `libutil/logger.c`
- **`tests/`**：單元測試 + 整合測試（shell scripts）  
  - `tests/test_protocol.c`, `tests/run_all_tests.sh`, `tests/test_*.sh`

目錄結構可參考 `README.md` 最下方 “Repo layout”。

---

## 編譯與執行

### Makefile 目標（build / debug / test）

Makefile 定義了 release/debug 目標與測試入口：

```40:117:Makefile
all: server client cli

$(SERVER_BIN): $(SERVER_SRC) $(PROTO_OBJ) $(SHM_OBJ) $(UTIL_OBJ)
	$(CC) $(CFLAGS) $(SERVER_SRC) $(PROTO_OBJ) $(SHM_OBJ) $(UTIL_OBJ) -o $@ $(LDFLAGS)

$(CLIENT_BIN): $(CLIENT_SRC) $(PROTO_OBJ)
	$(CC) $(CFLAGS) $(CLIENT_SRC) $(PROTO_OBJ) -o $@ $(LDFLAGS)

$(CLI_BIN): $(CLI_SRC) $(PROTO_OBJ)
	$(CC) $(CFLAGS) $(CLI_SRC) $(PROTO_OBJ) -o $@ $(LDFLAGS) -lncurses

test: all test_protocol
	./$(TEST_PROTO_BIN)
	./tests/run_all_tests.sh
```

### 執行方式（Linux/WSL 建議）

此專案使用 `fork()`、POSIX shared memory（`shm_open`/`mmap`）與 `epoll`，**原生 Windows 無法直接執行**；建議在 **Linux 或 WSL** 進行編譯與測試。

基本執行（與 `README.md` 一致）：

- Server：`./vault_server --port 7777 --workers 4 --log-level info`
- TUI：`./vault_cli --host 127.0.0.1 --port 7777`
- Load generator：`./vault_client --host 127.0.0.1 --port 7777 --threads 100 --ops 500`

---

## 協定（Protocol）設計與封包格式

### Frame（抽象結構）

協定在程式內使用 `frame_t` 作為抽象表示（flags/opcode/seq/timestamp/body）：

14:43:include/protocol.h

```14:43:include/protocol.h
typedef struct {
    uint8_t  flags;        /* FLAG_ENCRYPTED, FLAG_ERROR, etc. */
    uint16_t opcode;
    uint32_t seq;
    uint64_t timestamp_ms; /* milliseconds since epoch for replay protection */
    uint8_t *body;
    uint32_t body_len;
} frame_t;

int proto_encode(frame_t *f, uint8_t **out, size_t *out_len);
int proto_decode(uint8_t *buf, size_t len, frame_t *out);
```

### Wire format（實際封包）

wire format 由 `Len` 開頭，總 header size = 26 bytes：

6:16:include/common.h

```6:16:include/common.h
#define MAGIC 0xC0DE
#define PROTO_VERSION 1
#define MAX_PACKET 65536
#define HEADER_SIZE 26  /* 4+2+1+1+2+4+8+4 = Len+Magic+Ver+Flags+Op+Seq+Timestamp+CRC */
```

### proto_encode：組封包 + 計算 CRC32

`proto_encode` 負責把 `frame_t` 轉成 wire buffer，CRC 欄位在 offset 22：

115:166:libproto/protocol.c

```115:166:libproto/protocol.c
int proto_encode(frame_t *f, uint8_t **out, size_t *out_len) {
    uint32_t total = HEADER_SIZE + f->body_len;
    uint8_t *buf = calloc(1, total);
    if (!buf) return -1;

    uint32_t off = 0;
    uint32_t nlen = htonl(total);
    memcpy(buf + off, &nlen, 4); off += 4;

    uint16_t magic = htons(MAGIC);
    memcpy(buf + off, &magic, 2); off += 2;

    buf[off++] = PROTO_VERSION;
    buf[off++] = f->flags;

    uint16_t nop = htons(f->opcode);
    memcpy(buf + off, &nop, 2); off += 2;

    uint32_t nseq = htonl(f->seq);
    memcpy(buf + off, &nseq, 4); off += 4;

    uint64_t ts = f->timestamp_ms;
    if (ts == 0) ts = proto_timestamp_ms();
    uint64_t nts = htobe64(ts);
    memcpy(buf + off, &nts, 8); off += 8;

    off += 4; /* CRC placeholder */
    if (f->body_len && f->body) memcpy(buf + off, f->body, f->body_len);

    uint32_t crc = proto_crc32(buf, total);
    uint32_t ncrc = htonl(crc);
    memcpy(buf + 22, &ncrc, 4);
    *out = buf;
    *out_len = total;
    return 0;
}
```

### proto_decode：驗 magic/version/CRC + parse 出 frame

`proto_decode` 做完整檢查，CRC 驗證時會把 CRC 欄位清 0 再重算：

168:219:libproto/protocol.c

```168:219:libproto/protocol.c
int proto_decode(uint8_t *buf, size_t len, frame_t *out) {
    if (len < HEADER_SIZE) return -1;

    uint32_t pkt_len;
    memcpy(&pkt_len, buf, 4);
    pkt_len = ntohl(pkt_len);
    if (pkt_len != len) return -1;
    if (pkt_len > MAX_PACKET) return -1;

    uint16_t magic;
    memcpy(&magic, buf + 4, 2);
    magic = ntohs(magic);
    if (magic != MAGIC) return -2;

    uint8_t version = buf[6];
    if (version != PROTO_VERSION) return -3;

    uint32_t recv_crc;
    memcpy(&recv_crc, buf + 22, 4);
    recv_crc = ntohl(recv_crc);

    uint8_t saved_crc[4];
    memcpy(saved_crc, buf + 22, 4);
    memset(buf + 22, 0, 4);
    uint32_t calc_crc = proto_crc32(buf, len);
    memcpy(buf + 22, saved_crc, 4);
    if (calc_crc != recv_crc) return -4;

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
```

### XOR “加密” 與 key derivation（教育用途）

此專案提供 XOR 加解密（非加密學安全），並以 `(username + session_id)` 的 CRC32 做 key：

63:89:libproto/protocol.c

```63:89:libproto/protocol.c
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
```

### timestamp 與 replay window

timestamp 以毫秒為單位，`proto_validate_timestamp` 限制在 ±30s 內：

94:107:libproto/protocol.c

```94:107:libproto/protocol.c
uint64_t proto_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int proto_validate_timestamp(uint64_t pkt_ts, uint64_t now_ts) {
    int64_t diff = (int64_t)now_ts - (int64_t)pkt_ts;
    if (diff < 0) diff = -diff;
    return diff <= 30000;
}
```

---

## Shared Memory（跨行程共享狀態）

### 資料結構：帳戶鎖 + 餘額（cents）+ 全域 counters

shared memory 的 layout 在 `vault_shm_t`：

14:31:include/vault_shm.h

```14:31:include/vault_shm.h
typedef struct {
    pthread_mutex_t lock;     /* process-shared mutex */
    int64_t balance_cents;
} account_t;

typedef struct {
    pthread_mutex_t global_lock;   /* protects counters */
    uint64_t total_requests;       /* total requests handled */
    uint64_t total_errors;         /* total error responses */
    uint32_t active_connections;   /* current active connections */
    uint32_t shutdown_flag;        /* set by master on SIGINT */
    uint32_t next_session_id;      /* monotonically increasing session id */
    account_t acct[MAX_ACCOUNTS];
} vault_shm_t;
```

### 初始化：shm_open + mmap + PTHREAD_PROCESS_SHARED + 初始餘額

server 啟動時呼叫 `vault_shm_init(create=1)` 建立 shared memory，並初始化 robust mutex、帳戶初始餘額 `$1000.00`：

8:58:libshm/vault_shm.c

```8:58:libshm/vault_shm.c
vault_shm_t *vault_shm_init(int create) {
    int flags = O_RDWR;
    if (create) flags |= O_CREAT;

    int fd = shm_open(SHM_NAME, flags, 0666);
    if (fd < 0) { perror("shm_open"); return NULL; }

    if (create) {
        if (ftruncate(fd, sizeof(vault_shm_t)) < 0) { perror("ftruncate"); close(fd); return NULL; }
    }

    vault_shm_t *shm = mmap(NULL, sizeof(vault_shm_t),
                           PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (shm == MAP_FAILED) { perror("mmap"); return NULL; }

    if (create) {
        memset(shm, 0, sizeof(vault_shm_t));
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
        pthread_mutex_init(&shm->global_lock, &attr);

        for (int i = 0; i < MAX_ACCOUNTS; i++) {
            pthread_mutex_init(&shm->acct[i].lock, &attr);
            shm->acct[i].balance_cents = 100000;
        }
        shm->next_session_id = 1;
        pthread_mutexattr_destroy(&attr);
    }
    return shm;
}
```

---

## Server 設計（multi-process + epoll）

### Session 狀態（per-connection）

server 對每個連線維護 `session_t`，包含 login/session_key、rate limiter、malformed 計數、read buffer：

42:72:server/vault_server.c

```42:72:server/vault_server.c
typedef struct {
    uint64_t tokens;
    uint64_t last_refill_ms;
} rate_limiter_t;

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
    rate_limiter_t rate_limiter;
    uint8_t read_buf[READ_BUF_SIZE];
    size_t read_pos;
    uint8_t *write_buf;
    size_t write_len;
    size_t write_pos;
} session_t;
```

### Rate limiting（token bucket）

每個連線一個 token bucket：超過速率會回 `STATUS_ERR_RATE_LIMIT`：

94:122:server/vault_server.c

```94:122:server/vault_server.c
static void rate_limiter_init(rate_limiter_t *rl) {
    rl->tokens = RATE_LIMIT_BUCKET_SIZE;
    rl->last_refill_ms = proto_timestamp_ms();
}

static int rate_limiter_allow(rate_limiter_t *rl) {
    uint64_t now = proto_timestamp_ms();
    uint64_t elapsed = now - rl->last_refill_ms;
    if (elapsed >= RATE_LIMIT_REFILL_MS) {
        uint64_t refill = (elapsed / RATE_LIMIT_REFILL_MS) * RATE_LIMIT_PER_SEC;
        rl->tokens += refill;
        if (rl->tokens > RATE_LIMIT_BUCKET_SIZE) rl->tokens = RATE_LIMIT_BUCKET_SIZE;
        rl->last_refill_ms = now;
    }
    if (rl->tokens > 0) { rl->tokens--; return 1; }
    return 0;
}
```

速率常數位於 `include/common.h`：

68:80:include/common.h

```68:80:include/common.h
#define MAX_CONNECTIONS_PER_WORKER  1024
#define IDLE_TIMEOUT_SEC            60
#define MAX_MALFORMED_PACKETS       3
#define RATE_LIMIT_PER_SEC          50
#define TIMESTAMP_WINDOW_MS         30000
#define RATE_LIMIT_BUCKET_SIZE      1000
#define RATE_LIMIT_REFILL_MS        1000
```

### Request 處理主流程：統計、rate limit、timestamp、auth、dispatch

所有 op 都會進 `process_request`：更新 counters、做 rate limit、timestamp window、未登入限制，最後 switch dispatch：

493:570:server/vault_server.c

```493:570:server/vault_server.c
static int process_request(session_t *sess, frame_t *req, frame_t *resp) {
    memset(resp, 0, sizeof(frame_t));
    sess->request_count++;

    pthread_mutex_lock(&g_shm->global_lock);
    g_shm->total_requests++;
    pthread_mutex_unlock(&g_shm->global_lock);

    if (!rate_limiter_allow(&sess->rate_limiter)) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_RATE_LIMIT);
        pthread_mutex_lock(&g_shm->global_lock);
        g_shm->total_errors++;
        pthread_mutex_unlock(&g_shm->global_lock);
        return 0;
    }

    uint64_t now = proto_timestamp_ms();
    if (!proto_validate_timestamp(req->timestamp_ms, now)) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_BAD_TIMESTAMP);
        pthread_mutex_lock(&g_shm->global_lock);
        g_shm->total_errors++;
        pthread_mutex_unlock(&g_shm->global_lock);
        return 0;
    }

    if (!sess->logged_in && req->opcode != OP_LOGIN && req->opcode != OP_PING) {
        build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NOT_AUTH);
        pthread_mutex_lock(&g_shm->global_lock);
        g_shm->total_errors++;
        pthread_mutex_unlock(&g_shm->global_lock);
        return 0;
    }

    switch (req->opcode) {
        case OP_LOGIN:    handle_login(sess, req, resp); break;
        case OP_PING:     handle_ping(sess, req, resp); break;
        case OP_BALANCE:  handle_balance(sess, req, resp); break;
        case OP_DEPOSIT:  handle_deposit(sess, req, resp); break;
        case OP_WITHDRAW: handle_withdraw(sess, req, resp); break;
        case OP_TRANSFER: handle_transfer(sess, req, resp); break;
        default:
            build_error_response(resp, req->opcode, req->seq, STATUS_ERR_BAD_OPCODE);
            pthread_mutex_lock(&g_shm->global_lock);
            g_shm->total_errors++;
            pthread_mutex_unlock(&g_shm->global_lock);
            break;
    }
    return 0;
}
```

### 讀取 buffer → 切 frame → proto_decode →（可選）XOR 解密 → 回包

server 在 `process_read_buffer` 做「長度前置」切包與 malformed threshold，`proto_decode` 失敗會回錯誤並累積 malformed count；若封包帶 `FLAG_ENCRYPTED` 且已登入，會用 session key XOR 解密：

573:667:server/vault_server.c

```573:667:server/vault_server.c
static int process_read_buffer(session_t *sess, int epfd) {
    while (sess->read_pos >= 4) {
        uint32_t pkt_len;
        memcpy(&pkt_len, sess->read_buf, 4);
        pkt_len = ntohl(pkt_len);

        if (pkt_len < HEADER_SIZE || pkt_len > MAX_PACKET) {
            sess->malformed_count++;
            if (sess->malformed_count >= MAX_MALFORMED_PACKETS) return -1;
            memmove(sess->read_buf, sess->read_buf + 4, sess->read_pos - 4);
            sess->read_pos -= 4;
            continue;
        }

        if (sess->read_pos < pkt_len) break;

        frame_t req = {0};
        int rc = proto_decode(sess->read_buf, pkt_len, &req);
        memmove(sess->read_buf, sess->read_buf + pkt_len, sess->read_pos - pkt_len);
        sess->read_pos -= pkt_len;

        if (rc != 0) {
            sess->malformed_count++;
            frame_t resp = {0};
            build_error_response(&resp, 0, 0, STATUS_ERR_PARSE);
            uint8_t *out; size_t out_len;
            proto_encode(&resp, &out, &out_len);
            write(sess->fd, out, out_len);
            free(out);
            free(resp.body);
            continue;
        }

        if ((req.flags & FLAG_ENCRYPTED) && sess->logged_in && req.body_len > 0) {
            proto_xor_crypt(req.body, req.body_len, sess->session_key);
        }

        frame_t resp = {0};
        process_request(sess, &req, &resp);
        uint8_t *out; size_t out_len;
        proto_encode(&resp, &out, &out_len);
        write(sess->fd, out, out_len);
        free(out);
        free(resp.body);
        if (req.body) free(req.body);
        sess->last_seen = time(NULL);
    }
    (void)epfd;
    return 0;
}
```

### Worker loop（epoll accept/read）、Idle timeout、統計 log

worker 使用 `epoll_wait`，accept 後建立 session，讀取後呼叫 `process_read_buffer`；同時週期性檢查 idle 連線並印 stats：

677:825:server/vault_server.c

```677:825:server/vault_server.c
static void worker_loop(int listen_fd, int worker_id) {
    int epfd = epoll_create1(0);
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);

    while (g_running && !g_shm->shutdown_flag) {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, 1000);
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            if (fd == listen_fd) {
                int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
                set_nonblocking(client_fd);
                session_t *sess = session_create(client_fd, &client_addr);
                sessions[client_fd] = sess;
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = client_fd;
                epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev);
                vault_shm_conn_add(g_shm);
            } else if (events[i].events & EPOLLIN) {
                /* read → process_read_buffer → maybe disconnect */
            }
        }

        time_t now = time(NULL);
        for (int fd = 0; fd < MAX_CONNECTIONS_PER_WORKER; fd++) {
            if (sessions[fd] && (now - sessions[fd]->last_seen) > IDLE_TIMEOUT_SEC) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                session_destroy(sessions[fd]);
                sessions[fd] = NULL;
                vault_shm_conn_remove(g_shm);
            }
        }

        if (now - last_stats_time >= STATS_INTERVAL_SEC) {
            log_stats(g_shm->total_requests, g_shm->total_errors,
                      g_shm->active_connections, now - g_start_time);
            last_stats_time = now;
        }
    }
}
```

（上段中間略去的讀取/錯誤處理，完整邏輯見原檔同段。）

### Master：初始化 shared memory、fork workers、SIGINT/SIGTERM graceful shutdown

main 會初始化 logger、註冊 signal handler、建立 listen socket、fork workers；收到訊號後設定 `shutdown_flag` 並 kill/wait workers，最後 cleanup：

851:987:server/vault_server.c

```851:987:server/vault_server.c
int main(int argc, char *argv[]) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGCHLD, SIG_IGN);

    g_shm = vault_shm_init(1);
    if (!g_shm) return 1;

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(listen_fd, 128);

    pid_t workers[num_workers];
    for (int i = 0; i < num_workers; i++) {
        pid_t pid = fork();
        if (pid == 0) { worker_loop(listen_fd, i); exit(0); }
        else if (pid > 0) { workers[i] = pid; }
    }

    while (g_running) pause();

    g_shm->shutdown_flag = 1;
    for (int i = 0; i < num_workers; i++) {
        if (workers[i] > 0) { kill(workers[i], SIGTERM); waitpid(workers[i], NULL, 0); }
    }

    close(listen_fd);
    vault_shm_cleanup(g_shm);
    log_shutdown();
    return 0;
}
```

---

## Server 業務操作（Balance/Deposit/Withdraw/Transfer/Login）

### Login：建立 session_id + derive key（server 端）

`handle_login` 會從 body 解析 username，產生 `session_id`，derive `session_key`，回包 `status + session_id`：

189:236:server/vault_server.c

```189:236:server/vault_server.c
static void handle_login(session_t *sess, frame_t *req, frame_t *resp) {
    if (req->body_len < 2) { build_error_response(resp, req->opcode, req->seq, STATUS_ERR_PARSE); return; }
    uint8_t user_len = req->body[0];
    if (req->body_len < (uint32_t)(1 + user_len + 1)) { build_error_response(resp, req->opcode, req->seq, STATUS_ERR_PARSE); return; }

    if (user_len > 0 && user_len < sizeof(sess->username)) {
        memcpy(sess->username, req->body + 1, user_len);
        sess->username[user_len] = '\0';
    } else {
        strncpy(sess->username, "user", sizeof(sess->username) - 1);
    }

    sess->session_id = vault_shm_next_session(g_shm);
    sess->session_key = proto_derive_key(sess->username, sess->session_id);
    sess->logged_in = 1;

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
```

### Balance：鎖帳戶 mutex，讀取 balance_cents

255:293:server/vault_server.c

```255:293:server/vault_server.c
static void handle_balance(session_t *sess, frame_t *req, frame_t *resp) {
    uint32_t acct_id;
    memcpy(&acct_id, req->body, 4);
    acct_id = ntohl(acct_id);
    if (acct_id >= MAX_ACCOUNTS) { build_error_response(resp, req->opcode, req->seq, STATUS_ERR_NO_ACCOUNT); return; }

    pthread_mutex_lock(&g_shm->acct[acct_id].lock);
    int64_t balance = g_shm->acct[acct_id].balance_cents;
    pthread_mutex_unlock(&g_shm->acct[acct_id].lock);

    resp->body_len = 10;
    resp->body = malloc(10);
    uint16_t ok = htons(STATUS_OK);
    int64_t nbal = htobe64(balance);
    memcpy(resp->body, &ok, 2);
    memcpy(resp->body + 2, &nbal, 8);
}
```

### Transfer：鎖兩個帳戶（固定順序避免 deadlock）

445:471:server/vault_server.c

```445:471:server/vault_server.c
uint32_t first = (from_id < to_id) ? from_id : to_id;
uint32_t second = (from_id < to_id) ? to_id : from_id;

pthread_mutex_lock(&g_shm->acct[first].lock);
pthread_mutex_lock(&g_shm->acct[second].lock);

if (g_shm->acct[from_id].balance_cents < amount) {
    pthread_mutex_unlock(&g_shm->acct[second].lock);
    pthread_mutex_unlock(&g_shm->acct[first].lock);
    build_error_response(resp, req->opcode, req->seq, STATUS_ERR_INSUFFICIENT);
    return;
}

g_shm->acct[from_id].balance_cents -= amount;
g_shm->acct[to_id].balance_cents += amount;

pthread_mutex_unlock(&g_shm->acct[second].lock);
pthread_mutex_unlock(&g_shm->acct[first].lock);
```

---

## Client：Load Generator（`vault_client`）

### 核心 I/O 模型：encode → write → read(length) → read(rest) → decode

79:122:client/vault_client.c

```79:122:client/vault_client.c
static int send_recv(int fd, frame_t *req, frame_t *resp) {
    uint8_t *out;
    size_t out_len;
    if (proto_encode(req, &out, &out_len) != 0) return -1;
    ssize_t sent = write(fd, out, out_len);
    free(out);
    if (sent != (ssize_t)out_len) return -1;

    uint8_t buf[65536];
    ssize_t n = read(fd, buf, 4);
    if (n != 4) return -1;
    uint32_t pkt_len = ntohl(*(uint32_t *)buf);
    if (pkt_len > sizeof(buf) || pkt_len < HEADER_SIZE) return -1;

    size_t remaining = pkt_len - 4;
    size_t total_read = 4;
    while (remaining > 0) {
        n = read(fd, buf + total_read, remaining);
        if (n <= 0) return -1;
        total_read += n;
        remaining -= n;
    }
    return proto_decode(buf, pkt_len, resp);
}
```

### 多執行緒壓測：barrier 同步起跑、隨機帳戶與操作 mix

324:420:client/vault_client.c

```324:420:client/vault_client.c
static void *worker(void *arg) {
    int thread_id = (int)(long)arg;
    unsigned int seed = time(NULL) ^ thread_id;
    pthread_barrier_wait(&g_barrier);

    int fd = connect_to_server();
    uint32_t session_id = 0;
    if (do_login(fd, &session_id) != 0) return NULL;

    for (int i = 0; i < g_ops; i++) {
        int op = select_operation();
        uint32_t acct1 = rand_r(&seed) % 100;
        uint32_t acct2 = (acct1 + 1 + (rand_r(&seed) % 99)) % 100;
        int64_t amount = (rand_r(&seed) % 100 + 1) * 100;
        /* switch(op) → do_balance/do_deposit/do_withdraw/do_transfer */
    }
    close(fd);
    return NULL;
}
```

---

## Client：ncurses TUI（`vault_cli`）

### TUI session 狀態（含 session_id/session_key）

83:93:client/vault_cli.c

```83:93:client/vault_cli.c
typedef struct {
    int fd;
    int logged_in;
    int connected;
    uint32_t session_id;
    uint32_t session_key;
    char username[64];
    uint32_t seq;
} session_t;
```

### Login：成功後 derive session_key（對齊 server 的 XOR 鉤子）

547:648:client/vault_cli.c

```547:648:client/vault_cli.c
static void cmd_login(void) {
    /* ... build login body ... */
    frame_t req = { .flags = 0, .opcode = OP_LOGIN, .body = body, .body_len = off };
    frame_t resp = {0};
    double latency;
    if (send_recv(&req, &resp, &latency) != 0) { /* network error */ return; }

    if (resp.body_len >= 2) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        if (status == STATUS_OK && resp.body_len >= 6) {
            g_session.session_id = ntohl(*(uint32_t *)(resp.body + 2));
            g_session.session_key = proto_derive_key(username, g_session.session_id);
            g_session.logged_in = 1;
            snprintf(g_session.username, sizeof(g_session.username), "%s", username);
        }
    }
    if (resp.body) free(resp.body);
}
```

---

## Logging（Structured logging + AUDIT）

Logger 提供 level、context（worker/conn/module）與 audit（永遠輸出）：

15:45:include/logger.h

```15:45:include/logger.h
#define LEVEL_DEBUG  0
#define LEVEL_INFO   1
#define LEVEL_WARN   2
#define LEVEL_ERROR  3
#define LEVEL_AUDIT  4

typedef struct {
    int worker_id;
    int conn_id;
    const char *module;
} log_ctx_t;
```

Logger 實作包含 timestamp +（可選）色彩輸出：

160:199:libutil/logger.c

```160:199:libutil/logger.c
static void log_output(int level, const log_ctx_t *ctx, const char *msg) {
    char timestamp[64];
    char context[128];
    format_timestamp(timestamp, sizeof(timestamp));
    format_context(context, sizeof(context), ctx);
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_dest & (LOG_DEST_STDOUT | LOG_DEST_STDERR)) {
        FILE *out = (g_log_dest & LOG_DEST_STDERR) ? stderr : stdout;
        fprintf(out, "[%s] [%s] %s %s\n", timestamp, level_names[level], context, msg);
        fflush(out);
    }
    if ((g_log_dest & LOG_DEST_FILE) && g_log_file) {
        fprintf(g_log_file, "[%s] [%s] %s %s\n", timestamp, level_names[level], context, msg);
        fflush(g_log_file);
    }
    pthread_mutex_unlock(&g_log_mutex);
}
```

---

## 測試（Unit + Integration）

### Unit：Protocol 測試涵蓋 CRC/XOR/key/timestamp/encode-decode

`tests/test_protocol.c` 對協定做單元測試（含標準 CRC32 test vector）：

47:56:tests/test_protocol.c

```47:56:tests/test_protocol.c
TEST(crc32_basic) {
    uint32_t crc = proto_crc32((uint8_t *)"", 0);
    ASSERT_EQ(crc, 0x00000000);
    crc = proto_crc32((uint8_t *)"123456789", 9);
    ASSERT_EQ(crc, 0xCBF43926);
}
```

### Integration：run_all_tests 依序跑 failure/shutdown/concurrency/security

整合測試入口在 `tests/run_all_tests.sh`：

178:191:tests/run_all_tests.sh

```178:191:tests/run_all_tests.sh
pkill -f vault_server 2>/dev/null || true
rm -f /dev/shm/vault_shm 2>/dev/null || true
sleep 1

run_test "Protocol Unit Tests" "$PROJECT_DIR/test_protocol"
run_test "Failure Handling Tests" "$SCRIPT_DIR/test_failures.sh"
run_test "Shutdown Tests" "$SCRIPT_DIR/test_shutdown.sh"
run_test "Concurrency Tests" "$SCRIPT_DIR/test_concurrency.sh"
run_test "Security Tests" "$SCRIPT_DIR/test_security.sh"
```

各腳本測試重點：

- **Failure handling**：亂碼/截斷/錯 magic/超大 length/多次 malformed、connection flood  
  - 入口：`tests/test_failures.sh`（例如送錯 magic 的封包）  
  - 位置：  
```74:99:tests/test_failures.sh
echo "Test 3: Sending packet with wrong magic..."
printf '\x00\x00\x00\x1a\xba\xd0\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | timeout 5 nc -w 2 -q 1 127.0.0.1 7778 2>/dev/null || true
```

- **Concurrency**：跑多組 `vault_client` 壓測 mix  
  - 入口：`tests/test_concurrency.sh`  
- **Security**：bad magic/bad CRC/oversize/truncate/malformed threshold/connection flood/rate limiting/random binary  
  - 入口：`tests/test_security.sh`
- **Shutdown**：SIGINT/SIGTERM 下 server 是否退出與清理 `/dev/shm/vault_shm`  
  - 入口：`tests/test_shutdown.sh`

---

## 已知限制與注意事項（適合寫在報告的 “Limitations”）

- **Windows 相容性**：依賴 `fork/epoll/shm_open`，需 Linux/WSL。  
- **“加密”非安全**：XOR + CRC32 只是教學用途（完整性/偵錯），非真正加密/驗證（不是 MAC/AEAD）。  
- **write path 簡化**：server 在回應時採用「best-effort blocking write」的簡化做法（未完整實作 backpressure/write buffering）。  
  - 位置：`process_read_buffer` 直接 `write(sess->fd, out, out_len)`  
  - 參考：  
```651:663:server/vault_server.c
uint8_t *out;
size_t out_len;
proto_encode(&resp, &out, &out_len);
ssize_t written = write(sess->fd, out, out_len);
if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    free(out);
    free(resp.body);
    if (req.body) free(req.body);
    return -1;
}
```



