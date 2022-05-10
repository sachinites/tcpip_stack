#ifndef __MTRIE__
#define __MTRIE__

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "../../BitOp/bitmap.h"
#include "../../gluethread/glthread.h"

typedef struct stack Stack_t;

typedef struct mtrie_node_ {

	uint16_t node_id;
	bitmap_t prefix;
	bitmap_t mask;
    uint16_t prefix_len;
	struct mtrie_node_ *parent;
	struct mtrie_node_ *child[BIT_TYPE_MAX];
	glthread_t list_glue;
    void *data;
	bitmap_t stacked_prefix;
	/* Stats for analysis */
	uint32_t n_backtracks;
	uint32_t n_comparisons;
} mtrie_node_t;
GLTHREAD_TO_STRUCT(list_glue_to_mtrie_node, mtrie_node_t , list_glue);

typedef struct mtrie_ {

    mtrie_node_t *root;
    uint16_t N; // No of nodes;
	Stack_t *stack;
	/* linear List of all leaf nodes in mtrie*/
	glthread_t list_head;
	uint16_t prefix_len;
}mtrie_t;

static inline bool
mtrie_is_leaf_node (mtrie_node_t *node) {

	return  (!node->child[ZERO] && !node->child[ONE] && !node->child[DONT_CARE]);
}

void mtrie_print_node(mtrie_node_t *node, void *data);
bool mtrie_insert_prefix (mtrie_t *mtrie, 
										  bitmap_t *prefix,
										  bitmap_t *mask,
										  uint16_t prefix_len,
										  void *data);

mtrie_node_t *mtrie_create_new_node(uint16_t prefix_len);
void init_mtrie(mtrie_t *mtrie, uint16_t prefix_len);
void mtrie_print_ipv4_recursive(mtrie_t *mtrie);
mtrie_node_t *mtrie_longest_prefix_match_search(mtrie_t *mtrie, bitmap_t *prefix);
mtrie_node_t *
mtrie_exact_prefix_match_search(mtrie_t *mtrie, bitmap_t *prefix, bitmap_t *mask);
bool mtrie_delete_prefix (mtrie_t *mtrie, bitmap_t *prefix, bitmap_t *mask) ;
void mtrie_destroy(mtrie_t *mtrie) ;
void mtrie_post_order_traverse(mtrie_t *mtrie, void (*process_fn_ptr)(mtrie_node_t *));
void
mtrie_longest_prefix_first_traverse(mtrie_t *mtrie, 
                                                         void (*process_fn_ptr)(mtrie_node_t *, void *),
                                                         void *app_data) ;
#endif