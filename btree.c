#include "btree.h"
#include <assert.h>
#include <string.h>

static inline uint16_t get_node_type(node_t node) {
  uint16_t type;
  memcpy(&type, node, sizeof(uint16_t));
  return type;
}

static inline uint16_t get_node_nkeys(node_t node) {
  uint16_t nkeys;
  memcpy(&nkeys, node + 2, sizeof(uint16_t));
  return nkeys;
}

static inline void set_node_header(node_t node, uint16_t type, uint16_t nkeys) {
  memcpy(node, &type, sizeof(uint16_t));
  memcpy(node + 2, &nkeys, sizeof(uint16_t));
}

static inline uint64_t get_node_ptr(node_t node, uint16_t idx) {
  assert(idx < get_node_nkeys(node));

  uint64_t ptr;
  memcpy(&ptr, node + HEADER + 8 * idx, sizeof(uint64_t));
  return ptr;
}

static inline void set_node_ptr(node_t node, uint16_t idx, uint64_t val) {
  assert(idx < get_node_nkeys(node));
  memcpy(node + HEADER + 8 * idx, &val, sizeof(uint64_t));
}

static inline uint16_t get_offset_pos(node_t node, uint16_t idx) {
  assert(1 <= idx && idx <= get_node_nkeys(node));
  return HEADER + 8 * get_node_nkeys(node) + 2 * (idx - 1);
}

static inline uint16_t get_node_offset(node_t node, uint16_t idx) {
  if (idx == 0)
    return 0;
  uint16_t offset;
  memcpy(&offset, node + get_offset_pos(node, idx), sizeof(uint16_t));
  return offset;
}

static inline void set_node_offset(node_t node, uint16_t idx, uint16_t offset) {
  memcpy(node + get_offset_pos(node, idx), &offset, sizeof(uint16_t));
}

static inline uint16_t get_kv_pos(node_t node, uint16_t idx) {
  assert(idx <= get_node_nkeys(node));
  return HEADER + 8 * get_node_nkeys(node) + 2 * get_node_nkeys(node) +
         get_node_offset(node, idx);
}

static void get_node_key(node_t node, uint16_t idx, uint8_t **key,
                         uint16_t *klen) {
  assert(idx < get_node_nkeys(node));
  uint16_t pos = get_kv_pos(node, idx);
  memcpy(klen, node + pos, sizeof(uint16_t));
  *key = node + pos + 4;
}

static int compare_keys(uint8_t *key1, uint16_t len1, uint8_t *key2,
                        uint16_t len2) {
  uint16_t min_len = len1 < len2 ? len1 : len2;
  int cmp = memcmp(key1, key2, min_len);
  if (cmp != 0)
    return cmp;
  return len1 - len2;
}

static uint16_t node_lookup_le(node_t node, uint8_t *key, uint16_t key_len) {
  uint16_t nkeys = get_node_nkeys(node);
  uint16_t found = 0;

  for (uint16_t i = 1; i < nkeys; i++) {
    uint8_t *curr_key;
    uint16_t curr_len;
    get_node_key(node, i, &curr_key, &curr_len);

    int cmp = compare_keys(curr_key, curr_len, key, key_len);
    if (cmp <= 0) {
      found = i;
    }
    if (cmp >= 0) {
      break;
    }
  }
  return found;
}

static void leaf_insert(node_t new_node, node_t old_node, uint16_t idx,
                        uint8_t *key, uint16_t key_len, uint8_t *val,
                        uint16_t val_len) {
  set_node_header(new_node, NODE_LEAF, get_node_nkeys(old_node) + 1);
  node_append_range(new_node, old_node, 0, 0, idx);
  node_append_kv(new_node, idx, 0, key, key_len, val, val_len);
  node_append_range(new_node, old_node, idx + 1, idx,
                    get_node_nkeys(old_node) - idx);
}

static void leaf_update(node_t new_node, node_t old_node, uint16_t idx,
                        uint8_t *key, uint16_t key_len, uint8_t *val,
                        uint16_t val_len) {
  set_node_header(new_node, NODE_LEAF, get_node_nkeys(old_node));
}

void btree_init(btree_t *tree, get_node_fn get, create_node_fn create,
                delete_node_fn del) {
  tree->root = 0;
  tree->get = get;
  tree->create = create;
  tree->del = del;
}
