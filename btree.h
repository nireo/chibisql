#ifndef BTREE_H
#define BTREE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BTREE_PAGE_SIZE 4096
#define BTREE_MAX_KEY_SIZE 1000
#define BTREE_MAX_VAL_SIZE 3000
#define HEADER 4

typedef uint8_t *(*get_node_fn)(uint64_t ptr);
typedef uint64_t (*create_node_fn)(uint8_t *node);
typedef void (*delete_node_fn)(uint64_t ptr);

typedef struct btree_t {
  uint64_t root;
  get_node_fn get;
  create_node_fn create;
  delete_node_fn del;
} btree_t;

typedef uint8_t *node_t;
typedef enum node_type_t { NODE_INTERNAL, NODE_LEAF } node_type_t;

void btree_init(btree_t *tree, get_node_fn get, create_node_fn create,
                delete_node_fn del);
void btree_insert(btree_t *tree, uint8_t *key, uint16_t klen, uint8_t *val,
                  uint16_t vlen);
bool btree_delete(btree_t *tree, uint8_t *key, uint16_t klen);

#endif
