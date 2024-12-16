#include "btree.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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

static uint16_t node_nbytes(node_t node) {
  return get_kv_pos(node, get_node_nkeys(node));
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

static void node_append_kv(node_t new_node, uint16_t idx, uint64_t ptr,
                           uint8_t *key, uint16_t klen, uint8_t *val,
                           uint16_t vlen) {
  set_node_ptr(new_node, idx, ptr);

  uint16_t pos = get_kv_pos(new_node, idx);
  memcpy(new_node + pos, &klen, sizeof(uint16_t));
  memcpy(new_node + pos + 2, &vlen, sizeof(uint16_t));
  memcpy(new_node + pos + 4, key, klen);
  memcpy(new_node + pos + 4 + klen, val, vlen);

  set_node_offset(new_node, idx + 1,
                  get_node_offset(new_node, idx) + 4 + klen + vlen);
}

static void node_append_range(node_t new_node, node_t old_node,
                              uint16_t dst_idx, uint16_t src_idx, uint16_t n) {
  assert(src_idx + n <= get_node_nkeys(old_node));
  assert(dst_idx + n <= get_node_nkeys(new_node));

  if (n == 0)
    return;

  for (uint16_t i = 0; i < n; i++) {
    set_node_ptr(new_node, dst_idx + i, get_node_ptr(old_node, src_idx + i));
  }

  uint16_t dst_begin = get_node_offset(new_node, dst_idx);
  uint16_t src_begin = get_node_offset(old_node, src_idx);

  for (uint16_t i = 1; i <= n; i++) {
    uint16_t offset =
        dst_begin + get_node_offset(old_node, src_idx + i) - src_begin;
    set_node_offset(new_node, dst_idx + i, offset);
  }

  uint16_t begin = get_kv_pos(old_node, src_idx);
  uint16_t end = get_kv_pos(old_node, src_idx + n);
  memcpy(new_node + get_kv_pos(new_node, dst_idx), old_node + begin,
         end - begin);
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
  node_append_range(new_node, old_node, 0, 0, idx);
  node_append_kv(new_node, idx, 0, key, key_len, val, val_len);
  node_append_range(new_node, old_node, idx + 1, idx,
                    get_node_nkeys(old_node) - idx);
}

static inline uint16_t left_bytes(node_t node, uint16_t b) {
  return HEADER + 8 * b + 2 * b + get_node_offset(node, b);
}

static void node_split2(node_t left, node_t right, node_t old) {
  uint16_t nkeys = get_node_nkeys(old);
  assert(nkeys >= 2);

  uint16_t nleft = nkeys / 2;
  while (true) {
    uint16_t left_bytes =
        HEADER + 8 * nleft + 2 * nleft + get_node_offset(old, nleft);
    if (left_bytes <= BTREE_PAGE_SIZE || nleft <= 1) {
      break;
    }
    nleft--;
  }
  assert(nleft >= 1);

  while (true) {
    uint16_t total_bytes = node_nbytes(old);
    uint16_t left_bytes =
        HEADER + 8 * nleft + 2 * nleft + get_node_offset(old, nleft);
    uint16_t right_bytes = total_bytes - left_bytes + HEADER;

    if (right_bytes <= BTREE_PAGE_SIZE || nleft >= nkeys - 1) {
      break;
    }
    nleft++;
  }
  assert(nleft < nkeys);
  uint16_t nright = nkeys - nleft;

  uint16_t btype = get_node_type(old);
  set_node_header(left, btype, nleft);
  set_node_header(right, btype, nright);

  node_append_range(left, old, 0, 0, nleft);
  node_append_range(right, old, 0, nleft, nright);

  assert(node_nbytes(right) <= BTREE_PAGE_SIZE);
}

typedef struct {
  uint16_t n_splits;
  node_t nodes[3];
} split_result_t;

// split node when it gets too big, remember to free split result.
static split_result_t node_split3(node_t old) {
  split_result_t res = {0};

  if (node_nbytes(old) <= BTREE_PAGE_SIZE) {
    res.n_splits = 1;
    res.nodes[0] = (node_t)malloc(BTREE_PAGE_SIZE);
    memcpy(res.nodes[0], old, BTREE_PAGE_SIZE);
    return res;
  }

  node_t left = malloc(2 * BTREE_PAGE_SIZE);
  node_t right = malloc(BTREE_PAGE_SIZE);
  node_split2(left, right, old);

  if (node_nbytes(left) <= BTREE_PAGE_SIZE) {
    node_t final_left = malloc(BTREE_PAGE_SIZE);
    memcpy(final_left, left, BTREE_PAGE_SIZE);
    free(left);

    res.n_splits = 2;
    res.nodes[0] = final_left;
    res.nodes[1] = right;
    return res;
  }

  node_t leftleft = malloc(BTREE_PAGE_SIZE);
  node_t middle = malloc(BTREE_PAGE_SIZE);

  node_split2(leftleft, middle, left);
  free(left);

  assert(node_nbytes(leftleft) <= BTREE_PAGE_SIZE);

  res.n_splits = 3;
  res.nodes[0] = leftleft;
  res.nodes[1] = middle;
  res.nodes[2] = right;
  return res;
}

void btree_init(btree_t *tree, get_node_fn get, create_node_fn create,
                delete_node_fn del) {
  tree->root = 0;
  tree->get = get;
  tree->create = create;
  tree->del = del;
}
