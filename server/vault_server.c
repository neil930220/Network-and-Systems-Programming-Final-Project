#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>

#include "protocol.h"
#include "vault_shm.h"
#include "common.h"

/* shared memory pointer */
static vault_shm_t *g_shm;

/* SIGINT handler: trigger graceful shutdown */
void on_sigint(int sig) {
    g_shm->shutdown_flag = 1;
}

/* per-connection session state */
typedef struct {
    int logged_in;
    time_t last_seen;
} session_t;

void worker_loop(int listenfd) {
    while (!g_shm->shutdown_flag) {
        int cfd = accept(listenfd, NULL, NULL);
        if (cfd < 0) continue;

        session_t sess = {0};

        while (1) {
            uint8_t buf[1024];
            ssize_t n = read(cfd, buf, sizeof(buf));
            if (n <= 0) break;

            frame_t req = {0};
            if (proto_decode(buf, n, &req) != 0)
                break;

            sess.last_seen = time(NULL);

            pthread_mutex_lock(&g_shm->global_lock);
            g_shm->total_requests++;
            pthread_mutex_unlock(&g_shm->global_lock);

            frame_t resp = {0};
            resp.opcode = req.opcode;
            resp.seq = req.seq;

            /* LOGIN */
            if (req.opcode == OP_LOGIN) {
                sess.logged_in = 1;
                uint16_t ok = htons(STATUS_OK);
                resp.body_len = 2;
                resp.body = malloc(2);
                memcpy(resp.body, &ok, 2);
            }
            /* HEARTBEAT */
            else if (req.opcode == OP_PING) {
                uint16_t ok = htons(STATUS_OK);
                uint64_t now = htobe64(time(NULL) * 1000);
                resp.body_len = 10;
                resp.body = malloc(10);
                memcpy(resp.body, &ok, 2);
                memcpy(resp.body + 2, &now, 8);
            }
            /* AUTH CHECK */
            else if (!sess.logged_in) {
                uint16_t err = htons(STATUS_ERR_AUTH);
                resp.body_len = 2;
                resp.body = malloc(2);
                memcpy(resp.body, &err, 2);
            }
            /* BALANCE */
            else if (req.opcode == OP_BALANCE) {
                uint32_t acct;
                memcpy(&acct, req.body, 4);
                acct = ntohl(acct);

                pthread_mutex_lock(&g_shm->acct[acct].lock);
                int64_t bal = g_shm->acct[acct].balance_cents;
                pthread_mutex_unlock(&g_shm->acct[acct].lock);

                uint16_t ok = htons(STATUS_OK);
                int64_t nbal = htobe64(bal);
                resp.body_len = 10;
                resp.body = malloc(10);
                memcpy(resp.body, &ok, 2);
                memcpy(resp.body + 2, &nbal, 8);
            }

            uint8_t *out;
            size_t out_len;
            proto_encode(&resp, &out, &out_len);
            write(cfd, out, out_len);

            free(out);
            free(resp.body);
            free(req.body);
        }
        close(cfd);
    }
}

int main() {
    signal(SIGINT, on_sigint);

    /* init shared memory */
    int fd = shm_open("/vault_shm", O_CREAT | O_RDWR, 0666);
    ftruncate(fd, sizeof(vault_shm_t));
    g_shm = mmap(NULL, sizeof(vault_shm_t),
                 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

    pthread_mutex_init(&g_shm->global_lock, &attr);
    for (int i = 0; i < MAX_ACCOUNTS; i++) {
        pthread_mutex_init(&g_shm->acct[i].lock, &attr);
        g_shm->acct[i].balance_cents = 100000;
    }

    /* listen socket */
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(7777);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sfd, (void *)&addr, sizeof(addr));
    listen(sfd, 128);

    /* prefork workers */
    for (int i = 0; i < 4; i++)
        if (fork() == 0)
            worker_loop(sfd);

    pause();
    shm_unlink("/vault_shm");
}
