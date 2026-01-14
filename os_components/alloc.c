#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../../os/2-alloc/alloc.h"

#define BATCH_SIZE 4096

struct obj_metadata {
    unsigned long size;
    struct obj_metadata *next;
};

struct obj_metadata *freeList = NULL;
void *heapStart = NULL;
void *heapEnd = NULL;
void *heapCurr = NULL;

size_t align(size_t size)
{
    return (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);
}

void *sbrk_helper(size_t size)
{
    void *allocatedSpace = NULL;

    if (heapStart == NULL) {
        heapStart = sbrk(0);
        heapEnd = heapStart;
        heapCurr = heapStart;
    }

    if ((void *)heapCurr + size <= heapEnd) {
        allocatedSpace = heapCurr;
        heapCurr = (void *)heapCurr + size;
        return allocatedSpace;
    }

    size_t requestedSize = (size > BATCH_SIZE) ? size : BATCH_SIZE;
    void *newBatch = sbrk(requestedSize);
    if (newBatch == (void *) -1)
        return NULL;

    heapCurr = newBatch;
    heapEnd = (void *)newBatch + requestedSize;
    allocatedSpace = heapCurr;
    heapCurr = (void *)heapCurr + size;

    return allocatedSpace;
}

void *mymalloc(size_t size)
{
    if (size == 0)
        return NULL;

    struct obj_metadata *current = freeList;
    struct obj_metadata *previous = NULL;

    while (current != NULL) {
        if (current->size >= size) {
            if (previous)
                previous->next = current->next;
            else
                freeList = current->next;
            return (void *)current + sizeof(long);
        }
        previous = current;
        current = current->next;
    }

    struct obj_metadata *newChunk = sbrk_helper(align(size) + sizeof(long));
    if (newChunk == (void *) -1)
        return NULL;
    newChunk->size = size;

    return (void *)newChunk + sizeof(long);
}

void *mycalloc(size_t nmemb, size_t size)
{
    size_t totalSize = nmemb * size;
    void *ptr = mymalloc(totalSize);
    memset(ptr, 0, totalSize);

    return ptr;
}

void myfree(void *ptr)
{
    if (!ptr)
        return;
    struct obj_metadata *metadata = (struct obj_metadata *) (ptr - sizeof(long));
    metadata->next = freeList;
    freeList = metadata;
}

void *myrealloc(void *ptr, size_t size)
{
    if (!ptr)
        return mymalloc(size);
    if (size == 0) {
        myfree(ptr);
        return NULL;
    }

    struct obj_metadata *metadata = (struct obj_metadata *) (ptr - sizeof(long));
    if (metadata->size >= size)
        return ptr;

    void *newPtr = mymalloc(size);
    if (!newPtr)
        return NULL;
    memcpy(newPtr, ptr, metadata->size);
    myfree(ptr);

    return newPtr;
}

#if 1
void *malloc(size_t size) { return mymalloc(size); }
void *calloc(size_t nmemb, size_t size) { return mycalloc(nmemb, size); }
void *realloc(void *ptr, size_t size) { return myrealloc(ptr, size); }
void free(void *ptr) { myfree(ptr); }
#endif
