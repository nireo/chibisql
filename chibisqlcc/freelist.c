#include "freelist.h"
#include <assert.h>
#include <string.h>

static inline uint64_t get_next(uint8_t *node) {
    uint64_t type;
    memcpy(&type, node, sizeof(uint64_t));
    return type;
}

static inline void set_next(uint8_t *node, uint64_t next) {
    memcpy(node, &next, sizeof(uint64_t));
}

static inline uint64_t get_ptr(uint8_t *node, int idx) {
    uint64_t ptr;
    memcpy(&ptr, node + FREE_LIST_HEADER + 8 * idx, sizeof(uint64_t));

    return ptr;
}

static inline void set_ptr(uint8_t *node, int idx, uint64_t ptr) {
    assert(idx < FREE_LIST_CAP);
    memcpy(node + FREE_LIST_HEADER + 8 * idx, &ptr, sizeof(uint64_t));
}

static inline int seq2idx(uint64_t seq) { return (int)(seq % FREE_LIST_CAP); }

static inline void assert_fl(free_list_t *fl) {
    assert(fl->head_page != 0 && fl->tail_page != 0);
    assert(fl->head_seq != fl->tail_seq || fl->head_page == fl->tail_page);
}

static void fl_pop(free_list_t *fl, uint64_t *ptr, uint64_t *head) {
    assert_fl(fl);
    if (fl->head_seq == fl->max_seq) {
        *ptr = 0;
        *head = 0;
        return;
    }

    node_t node = fl->get(fl->head_page);
    *ptr = get_ptr(node, seq2idx(fl->head_seq));
    ++fl->head_seq;

    if (seq2idx(fl->head_seq) == 0) {
        *head = fl->head_page;
        fl->head_page = get_next(node);
        assert(fl->head_page != 0);
    }
}

void free_list_push_tail(free_list_t *fl, uint64_t ptr) {
    assert_fl(fl);
    // add ptr to the tail node
    set_ptr(fl->update(fl->tail_page), seq2idx(fl->tail_seq), ptr);
    ++fl->tail_seq;

    if (seq2idx(fl->tail_seq) == 0) {
        uint64_t next, head;
        fl_pop(fl, &next, &head);
        if (next == 0) {
            // TODO: Alloc
        }
    }
}

uint64_t free_list_pop_head(free_list_t *fl) {
    uint64_t ptr, head;
    fl_pop(fl, &ptr, &head);
    if (head != 0) {
        free_list_push_tail(fl, head);
    }
    return ptr;
}

void free_list_set_max_seq(free_list_t *fl) { fl->max_seq = fl->tail_seq; }
