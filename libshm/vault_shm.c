#include "vault_shm.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

vault_shm_t *vault_shm_init(int create) {
    int flags = O_RDWR;
    if (create) flags |= O_CREAT;
    
    int fd = shm_open(SHM_NAME, flags, 0666);
    if (fd < 0) {
        perror("shm_open");
        return NULL;
    }
    
    if (create) {
        if (ftruncate(fd, sizeof(vault_shm_t)) < 0) {
            perror("ftruncate");
            close(fd);
            return NULL;
        }
    }
    
    vault_shm_t *shm = mmap(NULL, sizeof(vault_shm_t),
                           PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    
    if (shm == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }
    
    if (create) {
        memset(shm, 0, sizeof(vault_shm_t));
        
        /* Initialize process-shared mutex attributes */
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
        
        /* Initialize global lock */
        pthread_mutex_init(&shm->global_lock, &attr);
        
        /* Initialize account locks and balances */
        for (int i = 0; i < MAX_ACCOUNTS; i++) {
            pthread_mutex_init(&shm->acct[i].lock, &attr);
            shm->acct[i].balance_cents = 100000;  /* $1000.00 initial balance */
        }
        
        shm->next_session_id = 1;
        
        pthread_mutexattr_destroy(&attr);
    }
    
    return shm;
}

void vault_shm_cleanup(vault_shm_t *shm) {
    if (shm) {
        munmap(shm, sizeof(vault_shm_t));
    }
    shm_unlink(SHM_NAME);
}

void vault_shm_conn_add(vault_shm_t *shm) {
    pthread_mutex_lock(&shm->global_lock);
    shm->active_connections++;
    pthread_mutex_unlock(&shm->global_lock);
}

void vault_shm_conn_remove(vault_shm_t *shm) {
    pthread_mutex_lock(&shm->global_lock);
    if (shm->active_connections > 0) {
        shm->active_connections--;
    }
    pthread_mutex_unlock(&shm->global_lock);
}

uint32_t vault_shm_next_session(vault_shm_t *shm) {
    pthread_mutex_lock(&shm->global_lock);
    uint32_t session_id = shm->next_session_id++;
    pthread_mutex_unlock(&shm->global_lock);
    return session_id;
}

