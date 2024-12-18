#ifndef CHIBI_KVSTORE_H

#include "btree.h"

typedef struct {
    const char *path;
    int fd;
    btree_t btree;
    bool failed;
} kv_store_t;

kv_store_t *kv_store_open(const char *path);
int kv_store_get(kv_store_t *store, uint8_t *key, uint16_t klen);
int kv_store_set(kv_store_t *store, uint8_t *key, uint16_t klen, uint8_t *value,
                 uint16_t vlen);
int kv_store_delete(kv_store_t *store, uint8_t *key, uint16_t klen);
void kv_store_free(kv_store_t *store);

#endif
