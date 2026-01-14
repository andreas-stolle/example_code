#ifndef KVSTORE_H
#define KVSTORE_H

#include "common.h"
#include "hash.h"

struct user_item {
    // Add your fields here.
    // You can access this structure from ht_item's user field defined in hash.h
    pthread_mutex_t lock;
};

struct user_ht {
    // Add your fields here.
    // You can access this structure from the hashtable_t's user field define in hash.h
    pthread_rwlock_t *key_locks;
    pthread_mutex_t global_lock;
};

typedef struct job_queue {
    struct conn_info **buffer;
    size_t head;
    size_t tail;
    size_t count;
    size_t capacity;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} job_queue_t;

#endif
