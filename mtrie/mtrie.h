#ifndef __MTRIE__
#define __MTRIE__

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "../BitOp/bitmap.h"
#include "../gluethread/glthread.h"

typedef struct stack Stack_t;

typedef enum mtrie_ops_result_code_ {

	MTRIE_INSERT_SUCCESS,
	MTRIE_INSERT_FAILED,
	MTRIE_INSERT_DUPLICATE,
	MTRIE_DELETE_SUCCESS,
	MTRIE_DELETE_FAILED,
	MTRIE_LOOKUP_SUCCESS,
	MTRIE_LOOKUP_FAILED,
	MTRIE_OPS_UNKNOWN
} mtrie_ops_result_code_t;

typedef struct mtrie_node_ {

	uint16_t node_id;
	bitmap_t prefix;
	bitmap_t wildcard;
    uint16_t prefix_len;
	struct mtrie_node_ *parent;
	struct mtrie_node_ *child[BIT_TYPE_MAX];
	/* list of all leaf nodes in mtrie. Provided to ease a linear walk over all leaves */
	glthread_t list_glue; 
    void *data;
	bitmap_t stacked_prefix;
	/* Stats for analysis */
	uint32_t n_backtracks;
	uint32_t n_comparisons;
} mtrie_node_t;
GLTHREAD_TO_STRUCT(list_glue_to_mtrie_node, mtrie_node_t , list_glue);

typedef void (*app_data_free_cbk)(mtrie_node_t *);

typedef struct mtrie_ {

    mtrie_node_t *root;
    uint16_t N; // No of nodes;
	Stack_t *stack;
	/* linear List of all leaf nodes in mtrie*/
	glthread_t list_head;
	uint16_t prefix_len;
	app_data_free_cbk free_cbk;
}mtrie_t;

static inline bool
mtrie_is_leaf_node (mtrie_node_t *node) {

	return  (!node->child[ZERO] && 
				!node->child[ONE] &&
				!node->child[DONT_CARE]);
}

void mtrie_print_node(mtrie_t *mtrie, mtrie_node_t *node, void *data);
mtrie_ops_result_code_t
mtrie_insert_prefix (mtrie_t *mtrie, 
    							  bitmap_t *prefix,
								  bitmap_t *wildcard,
								  uint16_t prefix_len,
                                  mtrie_node_t **mnode) ;

mtrie_node_t *mtrie_create_new_node(uint16_t prefix_len);
void init_mtrie(mtrie_t *mtrie, uint16_t prefix_len, app_data_free_cbk);
mtrie_node_t *mtrie_longest_prefix_match_search(mtrie_t *mtrie, bitmap_t *prefix);
mtrie_node_t *mtrie_exact_prefix_match_search(mtrie_t *mtrie, bitmap_t *prefix, bitmap_t *wildcard);

mtrie_ops_result_code_t
mtrie_delete_prefix (mtrie_t *mtrie, bitmap_t *prefix, bitmap_t *wildcard, void **app_data) ;

void mtrie_destroy (mtrie_t *mtrie);
void 
mtrie_delete_leaf_node(mtrie_t *mtrie, mtrie_node_t *node);

void
mtrie_longest_prefix_first_traverse(mtrie_t *mtrie, 
                                                         void (*process_fn_ptr)(mtrie_t *, mtrie_node_t *, void *),
                                                         void *app_data) ;

void mtrie_print_raw(mtrie_t *mtrie);
glthread_t * mtrie_node_delete_while_traversal (mtrie_t *mtrie, mtrie_node_t *node);

#endif
