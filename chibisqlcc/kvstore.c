#include "kvstore.h"
#include <stddef.h>

#define META_PAGE_SIZE 64
#define MMAP_INITIAL_SIZE (64 * 1024 * 1024) // 64 mb

typedef struct {
    uint8_t *data;
    size_t size;
} mmap_chunk_t;
