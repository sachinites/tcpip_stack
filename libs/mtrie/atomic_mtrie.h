/* Trimmed down version of mtrie which support Atomic add/delete 
	to be used as FIB */

#ifndef __ATOMIC_MTRIE__
#define __ATOMIC_MTRIE__

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <atomic>
#include "mtrie_enums.h"
#include "../BitOp/bitmap.h"

typedef struct stack Stack_t;

#pragma pack (push,8)

typedef struct atomic_mtrie_node_ {

	bitmap_t prefix;
	bitmap_t wildcard;
    bitmap_t stacked_prefix;    
	struct atomic_mtrie_node_ *parent;
    std::atomic<struct atomic_mtrie_node_*> child[BIT_TYPE_MAX];
    void *data;
    uint16_t prefix_len;
	uint16_t node_id;

} atomic_mtrie_node_t;

typedef struct atomic_mtrie_ {

    atomic_mtrie_node_t *root;
	Stack_t *stack;
    uint16_t prefix_len;
	
} atomic_mtrie_t;

#pragma pack(pop)

mtrie_ops_result_code_t
atomic_mtrie_insert_prefix(atomic_mtrie_t *mtrie,
					bitmap_t *prefix,
					bitmap_t *wildcard,
					uint16_t prefix_len,
                    void *app_data,
                    atomic_mtrie_node_t **result_node,
					atomic_mtrie_node_t **discarded_node);

mtrie_ops_result_code_t
atomic_mtrie_delete_prefix (atomic_mtrie_t *mtrie, 
							bitmap_t *prefix, 
							bitmap_t *wildcard, 
							void **app_data,
							atomic_mtrie_node_t **discarded_node) ;

void
atomic_mtrie_init(atomic_mtrie_t *mtrie, uint16_t prefix_len);

void 
atomic_mtrie_deinit(atomic_mtrie_t *mtrie);

void 
atomic_mtrie_prefix_insert_delete_discarded_node (atomic_mtrie_node_t *node);

void 
atomic_mtrie_prefix_delete_delete_discarded_node (atomic_mtrie_node_t *node);

atomic_mtrie_node_t *atomic_mtrie_longest_prefix_match_search(atomic_mtrie_t *mtrie, bitmap_t *prefix);
atomic_mtrie_node_t *atomic_mtrie_exact_prefix_match_search(atomic_mtrie_t *mtrie, bitmap_t *prefix, bitmap_t *wildcard);

void atomic_mtrie_traverse(atomic_mtrie_t *mtrie,
						   void (*process_fn_ptr)(atomic_mtrie_t *, atomic_mtrie_node_t *, void *),
						   void *app_data);

void
atomic_mtrie_print_node(atomic_mtrie_t *mtrie, atomic_mtrie_node_t *node, void *data) ;

#endif 