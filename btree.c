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

static void get_node_val(node_t node, uint16_t idx, uint8_t **val,
                         uint16_t *val_len) {
  assert(idx < get_node_nkeys(node));
  uint16_t pos = get_kv_pos(node, idx);

  uint16_t key_len;
  memcpy(&key_len, node + pos, sizeof(uint16_t));
  memcpy(val_len, node + pos + 2, sizeof(uint16_t));

  *val = node + pos + 4 + key_len;
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
    res.nodes[0] = malloc(BTREE_PAGE_SIZE);
    memcpy(res.nodes[0], old, node_nbytes(old));
    return res;
  }

  node_t left = malloc(2 * BTREE_PAGE_SIZE);
  node_t right = malloc(BTREE_PAGE_SIZE);

  node_split2(left, right, old);

  if (node_nbytes(left) <= BTREE_PAGE_SIZE) {
    node_t final_left = malloc(BTREE_PAGE_SIZE);
    memcpy(final_left, left, node_nbytes(left));
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

  res.n_splits = 3;
  res.nodes[0] = leftleft;
  res.nodes[1] = middle;
  res.nodes[2] = right;
  return res;
}

static void node_replace_kid_1ptr(node_t new_node, node_t old_node,
                                  uint16_t idx, uint64_t ptr) {
  memcpy(new_node, old_node, node_nbytes(old_node));
  set_node_ptr(new_node, idx, ptr);
}

static void node_replace_kid_n(btree_t *tree, node_t new_node, node_t old_node,
                               uint16_t idx, node_t *kids, uint16_t n_kids) {
  uint8_t *old_key;
  uint16_t old_key_len;
  get_node_key(old_node, idx, &old_key, &old_key_len);

  uint8_t *kid_key;
  uint16_t kid_key_len;
  get_node_key(kids[0], 0, &kid_key, &kid_key_len);

  if (n_kids == 1 && kid_key_len == old_key_len &&
      memcmp(kid_key, old_key, kid_key_len) == 0) {
    node_replace_kid_1ptr(new_node, old_node, idx, tree->create(kids[0]));
    return;
  }

  set_node_header(new_node, NODE_INTERNAL,
                  get_node_nkeys(old_node) + n_kids - 1);

  node_append_range(new_node, old_node, 0, 0, idx);

  for (uint16_t i = 0; i < n_kids; i++) {
    uint8_t *key;
    uint16_t key_len;
    get_node_key(kids[i], 0, &key, &key_len);
    node_append_kv(new_node, idx + i, tree->create(kids[i]), key, key_len, NULL,
                   0);
  }

  node_append_range(new_node, old_node, idx + n_kids, idx + 1,
                    get_node_nkeys(old_node) - (idx + 1));
}

void btree_init(btree_t *tree, get_node_fn get, create_node_fn create,
                delete_node_fn del) {
  tree->root = 0;
  tree->get = get;
  tree->create = create;
  tree->del = del;
}

static node_t tree_insert(btree_t *tree, node_t node, uint8_t *key,
                          uint16_t key_len, uint8_t *val, uint16_t val_len);

static void node_insert(btree_t *tree, node_t new_node, node_t node,
                        uint16_t idx, uint8_t *key, uint16_t key_len,
                        uint8_t *val, uint16_t val_len) {
  uint64_t kid_ptr = get_node_ptr(node, idx);
  node_t kid_node = tree->get(kid_ptr);
  node_t updated = tree_insert(tree, kid_node, key, key_len, val, val_len);

  split_result_t split = node_split3(updated);
  free(updated);

  tree->del(kid_ptr);

  node_replace_kid_n(tree, new_node, node, idx, split.nodes, split.n_splits);
  for (int i = 0; i < split.n_splits; i++) {
    free(split.nodes[i]);
  }
}

static node_t tree_insert(btree_t *tree, node_t node, uint8_t *key,
                          uint16_t key_len, uint8_t *val, uint16_t val_len) {
  node_t new_node = malloc(2 * BTREE_PAGE_SIZE);
  uint16_t idx = node_lookup_le(node, key, key_len);
  uint8_t *existing_key;
  uint16_t existing_key_len;
  get_node_key(node, idx, &existing_key, &existing_key_len);

  switch (get_node_type(node)) {
  case NODE_LEAF: {
    if (key_len == existing_key_len &&
        memcmp(key, existing_key, key_len) == 0) {
      leaf_update(new_node, node, idx, key, key_len, val, val_len);
    } else {
      leaf_insert(new_node, node, idx + 1, key, key_len, val, val_len);
    }
    break;
  }
  case NODE_INTERNAL: {
    node_insert(tree, new_node, node, idx, key, key_len, val, val_len);
    break;
  }
  default:
    assert(false && "bad node type!");
  }

  return new_node;
}

void btree_insert(btree_t *tree, uint8_t *key, uint16_t key_len, uint8_t *val,
                  uint16_t val_len) {
  printf("Inserting into tree: %.*s\n", key_len, key);
  assert(key_len > 0 && key_len <= BTREE_MAX_KEY_SIZE);
  assert(val_len <= BTREE_MAX_VAL_SIZE);

  if (tree->root == 0) {
    node_t root = malloc(BTREE_PAGE_SIZE);
    set_node_header(root, NODE_LEAF, 2);

    node_append_kv(root, 0, 0, NULL, 0, NULL, 0);
    node_append_kv(root, 1, 0, key, key_len, val, val_len);

    tree->root = tree->create(root);
    free(root);
    return;
  }

  node_t root_node = tree->get(tree->root);
  node_t new_node = tree_insert(tree, root_node, key, key_len, val, val_len);

  split_result_t split = node_split3(new_node);
  free(new_node);
  tree->del(tree->root);

  if (split.n_splits > 1) {
    node_t new_root = malloc(BTREE_PAGE_SIZE);
    set_node_header(new_root, NODE_INTERNAL, split.n_splits);

    for (uint16_t i = 0; i < split.n_splits; i++) {
      uint8_t *key;
      uint16_t key_len;
      get_node_key(split.nodes[i], 0, &key, &key_len);
      uint64_t ptr = tree->create(split.nodes[i]);
      node_append_kv(new_root, i, ptr, key, key_len, NULL, 0);
    }

    tree->root = tree->create(new_root);
    free(new_root);
  } else {
    tree->root = tree->create(split.nodes[0]);
  }

  for (uint16_t i = 0; i < split.n_splits; i++) {
    free(split.nodes[i]);
  }
}

static void node_merge(node_t new_node, node_t left, node_t right) {
  uint16_t type = get_node_type(left);
  assert(type == get_node_type(right));

  set_node_header(new_node, type, get_node_nkeys(left) + get_node_nkeys(right));

  node_append_range(new_node, left, 0, 0, get_node_nkeys(left));
  node_append_range(new_node, right, get_node_nkeys(left), 0,
                    get_node_nkeys(right));

  assert(node_nbytes(new_node) <= BTREE_PAGE_SIZE);
}

static void node_replace_2kid(node_t new_node, node_t old_node, uint16_t idx,
                              uint64_t ptr, uint8_t *key, uint16_t key_len) {
  set_node_header(new_node, NODE_INTERNAL, get_node_nkeys(old_node) - 1);
  node_append_range(new_node, old_node, 0, 0, idx);
  node_append_kv(new_node, idx, ptr, key, key_len, NULL, 0);
  node_append_range(new_node, old_node, idx + 1, idx + 2,
                    get_node_nkeys(old_node) - (idx + 2));
}

static int should_merge(btree_t *tree, node_t node, uint16_t idx,
                        node_t updated, node_t *sibling) {
  if (node_nbytes(updated) > BTREE_PAGE_SIZE / 4) {
    return 0;
  }

  if (idx > 0) {
    *sibling = tree->get(get_node_ptr(node, idx - 1));
    uint16_t merged = node_nbytes(*sibling) + node_nbytes(updated) - HEADER;
    if (merged <= BTREE_PAGE_SIZE) {
      return -1;
    }
    free(*sibling);
  }

  if (idx + 1 < get_node_nkeys(node)) {
    *sibling = tree->get(get_node_ptr(node, idx + 1));
    uint16_t merged = node_nbytes(*sibling) + node_nbytes(updated) - HEADER;
    if (merged <= BTREE_PAGE_SIZE) {
      return 1;
    }
    free(*sibling);
  }

  return 0;
}

static void leaf_delete(node_t new_node, node_t old_node, uint16_t idx) {
  set_node_header(new_node, NODE_LEAF, get_node_nkeys(old_node) - 1);
  node_append_range(new_node, old_node, 0, 0, idx);
  node_append_range(new_node, old_node, idx, idx + 1,
                    get_node_nkeys(old_node) - (idx + 1));
}

static node_t tree_delete(btree_t *tree, node_t node, uint8_t *key,
                          uint16_t key_len);

static node_t node_delete(btree_t *tree, node_t node, uint16_t idx,
                          uint8_t *key, uint16_t key_len) {
  uint64_t kid_ptr = get_node_ptr(node, idx);
  node_t kid_node = tree->get(kid_ptr);
  node_t updated = tree_delete(tree, kid_node, key, key_len);
  free(kid_node);

  if (!updated) {
    return NULL;
  }

  tree->del(kid_ptr);
  node_t new_node = malloc(BTREE_PAGE_SIZE);

  node_t sibling = NULL;
  int merge_dir = should_merge(tree, node, idx, updated, &sibling);

  switch (merge_dir) {
  case -1: {
    node_t merged = malloc(BTREE_PAGE_SIZE);
    node_merge(merged, sibling, updated);
    tree->del(get_node_ptr(node, idx - 1));
    free(sibling);

    uint8_t *merged_key;
    uint16_t merged_key_len;
    get_node_key(merged, 0, &merged_key, &merged_key_len);

    node_replace_2kid(new_node, node, idx - 1, tree->create(merged), merged_key,
                      merged_key_len);
    free(merged);
    break;
  }
  case 1: {
    node_t merged = malloc(BTREE_PAGE_SIZE);
    node_merge(merged, updated, sibling);
    tree->del(get_node_ptr(node, idx + 1));
    free(sibling);

    uint8_t *merged_key;
    uint16_t merged_key_len;
    get_node_key(merged, 0, &merged_key, &merged_key_len);

    node_replace_2kid(new_node, node, idx, tree->create(merged), merged_key,
                      merged_key_len);
    free(merged);
    break;
  }
  case 0: {
    if (get_node_nkeys(updated) == 0) {
      assert(get_node_nkeys(node) == 1 && idx == 0);
      set_node_header(new_node, NODE_INTERNAL, 0);
    } else {
      node_replace_kid_n(tree, new_node, node, idx, &updated, 1);
    }
    break;
  }
  }

  free(updated);
  return new_node;
}

static node_t tree_delete(btree_t *tree, node_t node, uint8_t *key,
                          uint16_t key_len) {
  uint16_t idx = node_lookup_le(node, key, key_len);

  switch (get_node_type(node)) {
  case NODE_LEAF: {
    uint8_t *existing_key;
    uint16_t existing_key_len;
    get_node_key(node, idx, &existing_key, &existing_key_len);

    if (key_len != existing_key_len ||
        memcmp(key, existing_key, key_len) != 0) {
      return NULL;
    }

    node_t new_node = malloc(BTREE_PAGE_SIZE);
    leaf_delete(new_node, node, idx);
    return new_node;
  }
  case NODE_INTERNAL:
    return node_delete(tree, node, idx, key, key_len);
  default:
    assert(false && "bad node type!");
    return NULL;
  }
}

bool btree_delete(btree_t *tree, uint8_t *key, uint16_t key_len) {
  assert(key_len > 0 && key_len <= BTREE_MAX_KEY_SIZE);

  if (tree->root == 0) {
    return false;
  }

  node_t root_node = tree->get(tree->root);
  node_t updated = tree_delete(tree, root_node, key, key_len);
  free(root_node);

  if (!updated) {
    return false;
  }

  tree->del(tree->root);
  if (get_node_type(updated) == NODE_INTERNAL && get_node_nkeys(updated) == 1) {
    tree->root = get_node_ptr(updated, 0);
  } else {
    tree->root = tree->create(updated);
  }

  free(updated);
  return true;
}
