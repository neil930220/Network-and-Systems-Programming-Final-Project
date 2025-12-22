#ifndef VAULT_SHM_H
#define VAULT_SHM_H

#include <pthread.h>
#include <stdint.h>

#define MAX_ACCOUNTS 10000

/*
 * Shared account record.
 * balance is stored in cents to avoid floating-point errors.
 */
typedef struct {
    pthread_mutex_t lock;     // process-shared mutex
    int64_t balance_cents;
} account_t;

/*
 * Shared memory layout.
 * All worker processes mmap this structure.
 */
typedef struct {
    pthread_mutex_t global_lock;
    uint64_t total_requests;
    uint32_t shutdown_flag;
    account_t acct[MAX_ACCOUNTS];
} vault_shm_t;

#endif
