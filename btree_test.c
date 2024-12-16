#include "btree.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct TestContext {
  btree_t tree;
  struct KeyValue {
    char *key;
    char *value;
    struct KeyValue *next;
  } **ref;
  size_t ref_size;
  struct Page {
    uint64_t ptr;
    node_t node;
    struct Page *next;
  } **pages;
  size_t pages_size;
} TestContext;

static size_t hash_string(const char *str, size_t size) {
  size_t hash = 5381;
  int c;
  while ((c = *str++))
    hash = ((hash << 5) + hash) + c;
  return hash % size;
}

static void ref_put(TestContext *c, const char *key, const char *value) {
  printf("Storing in ref: %s -> %s\n", key, value);
  size_t idx = hash_string(key, c->ref_size);
  struct KeyValue *kv = malloc(sizeof(struct KeyValue));
  kv->key = strdup(key);
  kv->value = strdup(value);
  kv->next = c->ref[idx];
  c->ref[idx] = kv;
}

static char *ref_get(TestContext *c, const char *key) {
  size_t idx = hash_string(key, c->ref_size);
  struct KeyValue *kv = c->ref[idx];
  while (kv) {
    if (strcmp(kv->key, key) == 0)
      return kv->value;
    kv = kv->next;
  }
  return NULL;
}

static void ref_delete(TestContext *c, const char *key) {
  size_t idx = hash_string(key, c->ref_size);
  struct KeyValue **pkv = &c->ref[idx];
  while (*pkv) {
    if (strcmp((*pkv)->key, key) == 0) {
      struct KeyValue *next = (*pkv)->next;
      free((*pkv)->key);
      free((*pkv)->value);
      free(*pkv);
      *pkv = next;
      return;
    }
    pkv = &(*pkv)->next;
  }
}

static void pages_put(TestContext *c, uint64_t ptr, node_t node) {
  assert(c != NULL);
  assert(c->pages != NULL);
  assert(c->pages_size > 0);

  size_t idx = ptr % c->pages_size;
  struct Page *page = malloc(sizeof(struct Page));

  node_t node_copy = malloc(BTREE_PAGE_SIZE);
  memcpy(node_copy, node, BTREE_PAGE_SIZE);

  page->ptr = ptr;
  page->node = node_copy;
  page->next = c->pages[idx];
  c->pages[idx] = page;
}

static node_t pages_get(TestContext *c, uint64_t ptr) {
  size_t idx = ptr % c->pages_size;
  struct Page *page = c->pages[idx];
  while (page) {
    if (page->ptr == ptr)
      return page->node;
    page = page->next;
  }
  return NULL;
}

static void pages_delete(TestContext *c, uint64_t ptr) {
  size_t idx = ptr % c->pages_size;
  struct Page **ppage = &c->pages[idx];
  while (*ppage) {
    if ((*ppage)->ptr == ptr) {
      struct Page *next = (*ppage)->next;
      free((*ppage)->node);
      free(*ppage);
      *ppage = next;
      return;
    }
    ppage = &(*ppage)->next;
  }
}

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

static TestContext *g_test_context = NULL;

static uint64_t new_node_callback(node_t node) {
  static uint64_t next_ptr = 1;
  uint64_t ptr = next_ptr++;
  pages_put(g_test_context, ptr, node);
  return ptr;
}

static node_t get_node_callback(uint64_t ptr) {
  return pages_get(g_test_context, ptr);
}

static void delete_node_callback(uint64_t ptr) {
  pages_delete(g_test_context, ptr);
}

static TestContext *new_test_context() {
  TestContext *c = malloc(sizeof(TestContext));
  if (!c) {
    perror("Failed to allocate TestContext");
    return NULL;
  }

  c->ref_size = 1024;
  c->ref = calloc(c->ref_size, sizeof(struct KeyValue *));
  if (!c->ref) {
    perror("Failed to allocate reference map");
    free(c);
    return NULL;
  }

  c->pages_size = 1024;
  c->pages = calloc(c->pages_size, sizeof(struct Page *));
  if (!c->pages) {
    perror("Failed to allocate pages map");
    free(c->ref);
    free(c);
    return NULL;
  }

  g_test_context = c;

  c->tree.root = 0;
  c->tree.get = get_node_callback;
  c->tree.create = new_node_callback;
  c->tree.del = delete_node_callback;

  return c;
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

static uint32_t fmix32(uint32_t h) {
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

struct data_t {
  char **keys;
  char **values;
  size_t count;
  size_t capacity;
};

static struct data_t *new_collected_data(size_t initial_capacity) {
  struct data_t *data = malloc(sizeof(struct data_t));
  data->keys = malloc(initial_capacity * sizeof(char *));
  data->values = malloc(initial_capacity * sizeof(char *));
  data->count = 0;
  data->capacity = initial_capacity;
  return data;
}

static void collect_add(struct data_t *data, const char *key,
                        const char *value) {
  if (data->count >= data->capacity) {
    data->capacity *= 2;
    data->keys = realloc(data->keys, data->capacity * sizeof(char *));
    data->values = realloc(data->values, data->capacity * sizeof(char *));
  }
  data->keys[data->count] = strdup(key);
  data->values[data->count] = strdup(value);
  data->count++;
}

static void free_collected_data(struct data_t *data) {
  for (size_t i = 0; i < data->count; i++) {
    free(data->keys[i]);
    free(data->values[i]);
  }
  free(data->keys);
  free(data->values);
  free(data);
}

static int compare_strings(const void *a, const void *b) {
  return strcmp(*(const char **)a, *(const char **)b);
}

static void node_dump(TestContext *c, uint64_t ptr, struct data_t *data) {
  node_t node = c->tree.get(ptr);
  assert(node != NULL);

  uint16_t nkeys = get_node_nkeys(node);

  if (get_node_type(node) == NODE_LEAF) {
    for (uint16_t i = 0; i < nkeys; i++) {
      uint8_t *key;
      uint16_t key_len;
      uint8_t *val;
      uint16_t val_len;

      get_node_key(node, i, &key, &key_len);
      get_node_val(node, i, &val, &val_len);

      char *key_str = malloc(key_len + 1);
      char *val_str = malloc(val_len + 1);

      memcpy(key_str, key, key_len);
      memcpy(val_str, val, val_len);
      key_str[key_len] = '\0';
      val_str[val_len] = '\0';

      collect_add(data, key_str, val_str);

      free(key_str);
      free(val_str);
    }
  } else {
    for (uint16_t i = 0; i < nkeys; i++) {
      uint64_t child_ptr = get_node_ptr(node, i);
      node_dump(c, child_ptr, data);
    }
  }
}

static void verify_node(TestContext *c, node_t node) {
  uint16_t nkeys = get_node_nkeys(node);
  assert(nkeys >= 1);

  if (get_node_type(node) == NODE_LEAF) {
    return;
  }

  for (uint16_t i = 0; i < nkeys; i++) {
    uint8_t *parent_key;
    uint16_t parent_key_len;
    get_node_key(node, i, &parent_key, &parent_key_len);

    uint64_t child_ptr = get_node_ptr(node, i);
    node_t child = c->tree.get(child_ptr);
    assert(child != NULL);

    uint8_t *child_key;
    uint16_t child_key_len;
    get_node_key(child, 0, &child_key, &child_key_len);

    assert(parent_key_len == child_key_len);
    assert(memcmp(parent_key, child_key, parent_key_len) == 0);

    verify_node(c, child);
  }
}

static void collect_reference(TestContext *c, struct data_t *data) {
  for (size_t i = 0; i < c->ref_size; i++) {
    struct KeyValue *kv = c->ref[i];
    while (kv) {
      collect_add(data, kv->key, kv->value);
      kv = kv->next;
    }
  }
}

static void verify_tree(TestContext *c) {
  if (c->tree.root == 0) {
    return;
  }

  struct data_t *tree_data = new_collected_data(1024);
  node_dump(c, c->tree.root, tree_data);

  assert(strlen(tree_data->keys[0]) == 0);
  assert(strlen(tree_data->values[0]) == 0);

  free(tree_data->keys[0]);
  free(tree_data->values[0]);
  memmove(tree_data->keys, tree_data->keys + 1,
          (tree_data->count - 1) * sizeof(char *));
  memmove(tree_data->values, tree_data->values + 1,
          (tree_data->count - 1) * sizeof(char *));
  tree_data->count--;

  struct data_t *ref_data = new_collected_data(1024);
  collect_reference(c, ref_data);

  qsort(tree_data->keys, tree_data->count, sizeof(char *), compare_strings);
  qsort(ref_data->keys, ref_data->count, sizeof(char *), compare_strings);

  printf("%zu %zu\n", tree_data->count, ref_data->count);
  assert(tree_data->count == ref_data->count);

  for (size_t i = 0; i < tree_data->count; i++) {
    assert(strcmp(tree_data->keys[i], ref_data->keys[i]) == 0);

    char *ref_value = ref_get(c, tree_data->keys[i]);
    assert(ref_value != NULL);
    assert(strcmp(tree_data->values[i], ref_value) == 0);
  }

  verify_node(c, c->tree.get(c->tree.root));

  free_collected_data(tree_data);
  free_collected_data(ref_data);
}

static void cleanup_test_context(TestContext *c) {
  for (size_t i = 0; i < c->ref_size; i++) {
    struct KeyValue *kv = c->ref[i];
    while (kv) {
      struct KeyValue *next = kv->next;
      free(kv->key);
      free(kv->value);
      free(kv);
      kv = next;
    }
  }
  free(c->ref);

  for (size_t i = 0; i < c->pages_size; i++) {
    struct Page *page = c->pages[i];
    while (page) {
      struct Page *next = page->next;
      free(page->node);
      free(page);
      page = next;
    }
  }
  free(c->pages);

  free(c);
  g_test_context = NULL;
}

static void test_basic(uint32_t (*hasher)(uint32_t)) {
  TestContext *c = new_test_context();

  char key[32], val[32];
  strcpy(key, "k");
  strcpy(val, "v");
  btree_insert(&c->tree, (uint8_t *)key, strlen(key), (uint8_t *)val,
               strlen(val));
  ref_put(c, key, val);
  verify_tree(c);

  for (int i = 0; i < 250000; i++) {
    sprintf(key, "key%u", hasher(i));
    sprintf(val, "vvv%u", hasher(-i));

    btree_insert(&c->tree, (uint8_t *)key, strlen(key), (uint8_t *)val,
                 strlen(val));
    ref_put(c, key, val);

    if (i < 2000) {
      verify_tree(c);
    }
  }
  verify_tree(c);

  for (int i = 2000; i < 250000; i++) {
    sprintf(key, "key%u", hasher(i));
    ref_delete(c, key);
    assert(btree_delete(&c->tree, (uint8_t *)key, strlen(key)));
  }
  verify_tree(c);

  for (int i = 0; i < 2000; i++) {
    sprintf(key, "key%u", hasher(i));
    sprintf(val, "vvv%u", hasher(i));

    btree_insert(&c->tree, (uint8_t *)key, strlen(key), (uint8_t *)val,
                 strlen(val));
    ref_put(c, key, val);
    verify_tree(c);
  }

  cleanup_test_context(c);
}

void test_btree_t_basic_ascending() {
  test_basic((uint32_t(*)(uint32_t))fmix32);
}

void test_btree_t_basic_descending() {
  test_basic((uint32_t(*)(uint32_t))fmix32);
}

void test_btree_t_basic_rand() { test_basic(fmix32); }

void test_btree_t_rand_length() {
  TestContext *c = new_test_context();

  for (int i = 0; i < 2000; i++) {
    uint32_t klen = fmix32(2 * i + 0) % BTREE_MAX_KEY_SIZE;
    uint32_t vlen = fmix32(2 * i + 1) % BTREE_MAX_VAL_SIZE;

    if (klen == 0)
      continue;

    uint8_t *key = malloc(klen);
    uint8_t *val = malloc(vlen);

    for (uint32_t j = 0; j < klen; j++)
      key[j] = rand() % 256;
    for (uint32_t j = 0; j < vlen; j++)
      val[j] = rand() % 256;

    btree_insert(&c->tree, key, klen, val, vlen);
    char *key_str = malloc(klen * 2 + 1);
    char *val_str = malloc(vlen * 2 + 1);
    for (uint32_t j = 0; j < klen; j++)
      sprintf(key_str + j * 2, "%02x", key[j]);
    for (uint32_t j = 0; j < vlen; j++)
      sprintf(val_str + j * 2, "%02x", val[j]);
    ref_put(c, key_str, val_str);

    free(key);
    free(val);
    free(key_str);
    free(val_str);

    verify_tree(c);
  }
  cleanup_test_context(c);
}

int main() {
  srand(time(NULL));

  printf("Running ascending test...\n");
  test_btree_t_basic_ascending();

  printf("Running descending test...\n");
  test_btree_t_basic_descending();

  printf("Running random test...\n");
  test_btree_t_basic_rand();

  printf("Running random length test...\n");
  test_btree_t_rand_length();

  printf("All tests passed!\n");
  return 0;
}
