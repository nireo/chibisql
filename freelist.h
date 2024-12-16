#ifndef CHIBI_FREELIST_H
#define CHIBI_FREELIST_H

#include <stdint.h>

#include "btree.h"

#define FREE_LIST_HEADER 8
#define FREE_LIST_CAP ((BTREE_PAGE_SIZE - FREE_LIST_HEADER) / 8)

typedef struct {
    // callbacks
    get_node_fn get;
    create_node_fn create;
    get_node_fn update; // uses the same signature as get

    // persisted data
    uint64_t head_page; // pointer to the list head node
    uint64_t head_seq;  // monotonic sequence number to index into the list head
    uint64_t tail_page;
    uint64_t tail_seq;

    // in-memory
    uint64_t max_seq; // saved 'tail_seq' to prevent consuming newly added items
} free_list_t;

void free_list_push_tail(free_list_t *fl, uint64_t ptr);
uint64_t free_list_pop_head(free_list_t *fl);
void free_list_set_max_seq(free_list_t *fl);

#endif
