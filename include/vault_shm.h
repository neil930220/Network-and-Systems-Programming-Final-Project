#ifndef VAULT_SHM_H
#define VAULT_SHM_H

#include <pthread.h>
#include <stdint.h>

#define MAX_ACCOUNTS 10000
#define SHM_NAME "/vault_shm"

/*
 * Shared account record.
 * balance is stored in cents to avoid floating-point errors.
 */
typedef struct {
    pthread_mutex_t lock;     /* process-shared mutex */
    int64_t balance_cents;
} account_t;

/*
 * Shared memory layout.
 * All worker processes mmap this structure.
 */
typedef struct {
    pthread_mutex_t global_lock;   /* protects counters */
    uint64_t total_requests;       /* total requests handled */
    uint64_t total_errors;         /* total error responses */
    uint32_t active_connections;   /* current active connections */
    uint32_t shutdown_flag;        /* set by master on SIGINT */
    uint32_t next_session_id;      /* monotonically increasing session id */
    account_t acct[MAX_ACCOUNTS];
} vault_shm_t;

/*
 * Initialize shared memory segment.
 * Returns pointer to mapped memory or NULL on failure.
 */
vault_shm_t *vault_shm_init(int create);

/*
 * Cleanup shared memory segment.
 */
void vault_shm_cleanup(vault_shm_t *shm);

/*
 * Increment active connections counter.
 */
void vault_shm_conn_add(vault_shm_t *shm);

/*
 * Decrement active connections counter.
 */
void vault_shm_conn_remove(vault_shm_t *shm);

/*
 * Generate next session ID (thread-safe).
 */
uint32_t vault_shm_next_session(vault_shm_t *shm);

#endif
