#include <semaphore.h>
#include <assert.h>

#include "server_utils.h"
#include "common.h"
#include "request_dispatcher.h"
#include "hash.h"
#include "kvstore.h"
#include <pthread.h>

// DO NOT MODIFY THIS.
// ./check.py assumes the hashtable has 256 buckets.
// You should initialize your hashtable with this capacity.
#define HT_CAPACITY 256
#define QUEUE_CAPACITY 100
#define THREAD_COUNT 44

job_queue_t job_queue;

hash_item_t *get_item(char *key) {
    unsigned int bucket_index = hash(key) % ht->capacity;

    pthread_rwlock_rdlock(&ht->user->key_locks[bucket_index]);
    hash_item_t *item = ht->items[bucket_index];
    while (item) {
        if (strcmp(item->key, key) == 0) {
            pthread_rwlock_unlock(&ht->user->key_locks[bucket_index]);
            return item;
        }
        item = item->next;
    }
    pthread_rwlock_unlock(&ht->user->key_locks[bucket_index]);
    return NULL;
}

int set_request(int socket, struct request *request)
{
    size_t len = 0;
    size_t expected_len = request->msg_len;

    char *buffer = malloc(expected_len + 1); // Temporary buffer for payload
    if (!buffer) {
        send_response(socket, STORE_ERROR, 0, NULL);
        return -1;
    }
    unsigned int bucket_index = hash(request->key) % ht->capacity;
    hash_item_t *item = get_item(request->key);

    if (!item) {
        item = (hash_item_t *)malloc(sizeof(hash_item_t));
        if (!item) {
            free(buffer);
            send_response(socket, STORE_ERROR, 0, NULL);
            return -1;
        }

        item->key = strdup(request->key);
        if (!item->key) {
            free(buffer);
            free(item);
            send_response(socket, STORE_ERROR, 0, NULL);
            return -1;
        }
        item->value = malloc(expected_len);
        item->value_size = expected_len;
        item->next = ht->items[bucket_index];
        ht->items[bucket_index] = item;
        item->prev = NULL;
    }
    else {
        char *new_value = realloc(item->value, expected_len);
        if (!new_value) {
            free(buffer);
            send_response(socket, STORE_ERROR, 0, NULL);
            return -1;
        }
        item->value = new_value;
        item->value_size = expected_len;
    }

    while (len < expected_len) {
        size_t bytes_read = read_payload(socket, request, expected_len - len, buffer);
        if (bytes_read <= 0 || bytes_read != (expected_len - len)) {
            if (item->key) free(item->key);
            if (item->value) free(item->value);

            if (item->prev) {
                item->prev->next = item->next;
            } else {
                ht->items[bucket_index] = item->next;
            }
            if (item->next) {
                item->next->prev = item->prev;
            }
            free(item);
            free(buffer);
            send_response(socket, STORE_ERROR, 0, NULL);
            return -1;
        }

        memcpy(item->value + len, buffer, bytes_read);
        len += bytes_read;
    }
    free(buffer);
    check_payload(socket, request, expected_len);
    send_response(socket, OK, 0, NULL);

    return len;
}

int get_request(int socket, struct request *request)
{
    pthread_mutex_lock(&ht->user->global_lock);
    hash_item_t *item = get_item(request->key);
    if (!item) {
        send_response(socket, KEY_ERROR, 0, NULL);
        pthread_mutex_unlock(&ht->user->global_lock);
        return -1;
    }

    pthread_mutex_unlock(&ht->user->global_lock);
    send_response(socket, OK, item->value_size, item->value);
    return 0;
}

int del_request(int socket, struct request *request)
{
    unsigned int bucket_index = hash(request->key) % ht->capacity;
    pthread_mutex_lock(&ht->user->global_lock);

    hash_item_t *item = ht->items[bucket_index];
    hash_item_t *prev = NULL;

    while (item) {
        if (strcmp(item->key, request->key) == 0) {
            if (prev)
                prev->next = item->next;
            else
                ht->items[bucket_index] = item->next;
            if (item->next)
                item->next->prev = prev;

            free(item->key);
            free(item->value);
            free(item);

            pthread_mutex_unlock(&ht->user->global_lock);
            send_response(socket, OK, 0, NULL);
            return 0;
        }
        prev = item;
        item = item->next;
    }

    pthread_mutex_unlock(&ht->user->global_lock);
    send_response(socket, KEY_ERROR, 0, NULL);
    return -1;
}

void *main_job(void *arg)
{
    int method;
    struct conn_info *conn_info = arg;
    struct request *request = allocate_request();
    request->connection_close = 0;

    pr_info("Starting new session from %s:%d\n",
        inet_ntoa(conn_info->addr.sin_addr),
        ntohs(conn_info->addr.sin_port));

    do {
        method = recv_request(conn_info->socket_fd, request);
        // Insert your operations here
        switch (method) {
        case SET:
            set_request(conn_info->socket_fd, request);
            break;
        case GET:
            get_request(conn_info->socket_fd, request);
            break;
        case DEL:
            del_request(conn_info->socket_fd, request);
            break;
        case RST:
            // ./check.py issues a reset request after each test
            // to bring back the hashtable to a known state.
            // Implement your reset command here.
            send_response(conn_info->socket_fd, OK, 0, NULL);
            break;
        case STAT:
            break;
        }

        if (request->key) {
            free(request->key);
        }

    } while (!request->connection_close);

    close_connection(conn_info->socket_fd);
    free(request);
    free(conn_info);
    return (void *)NULL;
}

void enqueue(job_queue_t *queue, struct conn_info *conn_info) {
    pthread_mutex_lock(&queue->lock);

    while (queue->count == queue->capacity) {
        pthread_cond_wait(&queue->not_full, &queue->lock);
    }

    queue->buffer[queue->tail] = conn_info;
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);
}

struct conn_info *dequeue(job_queue_t *queue) {
    pthread_mutex_lock(&queue->lock);

    while (queue->count == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->lock);
    }

    struct conn_info *conn_info = queue->buffer[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;

    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);

    return conn_info;
}

void *worker_function(void *arg) {
    job_queue_t *queue = (job_queue_t *)arg;

    while (1) {
        struct conn_info *conn_info = dequeue(queue);
        main_job(conn_info);
    }
    return NULL;
}

void initialize_queue(job_queue_t *queue, size_t capacity) {
    queue->buffer = (struct conn_info **)malloc(capacity * sizeof(struct conn_info *));
    if (!queue->buffer) {
        perror("Failed to allocate queue buffer");
        exit(EXIT_FAILURE);
    }
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    queue->capacity = capacity;
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
}

void initialize_hashtable() {
    ht = (hashtable_t *)malloc(sizeof(hashtable_t));
    if (!ht) {
        perror("Failed to allocate memory for hashtable");
        exit(EXIT_FAILURE);
    }
    ht->capacity = HT_CAPACITY;
    ht->items = (hash_item_t **)malloc(ht->capacity * sizeof(hash_item_t *));
    if (!ht->items) {
        perror("Failed to allocate memory for buckets");
        free(ht);
        exit(EXIT_FAILURE);
    }
    ht->user = (struct user_ht*)malloc(sizeof(struct user_ht));
    ht->user->key_locks = (pthread_rwlock_t *)malloc(HT_CAPACITY * sizeof(pthread_rwlock_t));
    if (!ht->user->key_locks) {
        perror("Failed to allocate memory for key locks");
        free(ht->items);
        free(ht);
        exit(EXIT_FAILURE);
    }
    for (unsigned int i = 0; i < ht->capacity; i++) {
        ht->items[i] = NULL;
        pthread_rwlock_init(&ht->user->key_locks[i], NULL);
    }
    if (!ht->user) {
        perror("Failed to allocate user_ht");
        free(ht->user->key_locks);
        free(ht->items);
        free(ht);
        exit(EXIT_FAILURE);
    }
    pthread_mutex_init(&ht->user->global_lock, NULL);
}

int main(int argc, char *argv[])
{
    int listen_sock;
    listen_sock = server_init(argc, argv);

    initialize_hashtable();
    initialize_queue(&job_queue, QUEUE_CAPACITY);

    pthread_t threads[THREAD_COUNT];
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_create(&threads[i], NULL, worker_function, &job_queue);
    }

    for (;;) {
        struct conn_info *conn_info = calloc(1, sizeof(struct conn_info));
        if (accept_new_connection(listen_sock, conn_info) < 0) {
            error("Cannot accept new connection");
            free(conn_info);
            continue;
        }
        enqueue(&job_queue, conn_info);
    }

    return 0;
}
