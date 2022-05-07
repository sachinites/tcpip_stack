#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "../../gluethread/glthread.h"

typedef struct stack stack_t;

typedef enum {
	ZERO,
	ONE,
	DONT_CARE,
	BIT_TYPE_MAX
} bit_type_t;

typedef struct mtrie_node_ {

	uint16_t node_id;
	uint32_t prefix;
	uint32_t mask;
    uint8_t prefix_len;
	struct mtrie_node_ *parent;
	struct mtrie_node_ *child[BIT_TYPE_MAX];
	glthread_t list_glue;
    void *data;
	uint32_t stacked_prefix;
	uint8_t stacked_prefix_matched_bits_count;
	/* Stats for analysis */
	uint32_t n_backtracks;
	uint32_t n_comparisons;
} mtrie_node_t;
GLTHREAD_TO_STRUCT(list_glue_to_mtrie_node, mtrie_node_t , list_glue);

typedef struct mtrie_ {

    mtrie_node_t *root;
    uint16_t N; // No of nodes;
	stack_t *stack;
	/* linear List of all leaf nodes in mtrie*/
	glthread_t list_head;
}mtrie_t;

/*
Bit Pos --> 0123456789
Number--> 0001010010
Assuming most significant bit starts from 0
*/
static inline bool
BIT_AT(uint32_t N, uint8_t bit_pos) {

    if (N & (1 << (32 - bit_pos - 1))) {
        return true;
    }
    return false;
}

static inline bit_type_t 
EFFECTIVE_BIT_AT(uint32_t prefix, uint32_t mask, uint8_t pos) {

     if (BIT_AT(mask, pos)) {
            return DONT_CARE;
        }
        else if (BIT_AT(prefix, pos)) {
            return ONE;
        }
        else {
            return ZERO;
        }
}

static uint32_t
bits_generate_ones(uint8_t start_offset, uint8_t end_offset) {

	if (start_offset > 31 || end_offset > 31) assert(0);
	assert(start_offset <= end_offset);

	uint32_t temp = 0xFFFFFFFF;
	temp = temp << start_offset;
	temp = temp >> start_offset;
	temp = temp >> (32 - end_offset -1);
	temp = temp << (32 - end_offset -1);
	return temp;
}
/*
Assuming most significant bit starts from 0
*/
static inline void
bits_copy(uint32_t *src, uint32_t *dst, uint8_t src_start_pos, uint8_t dst_start_pos, uint8_t count) {

    *dst = 0;
    *dst = *src;
    *dst = (*dst) << src_start_pos;
	*dst = (*dst) >> dst_start_pos;
    *dst = *dst >> (32 - count - dst_start_pos );
    *dst = *dst << (32 - count - dst_start_pos );
}

static inline void
bits_copy_preserve(uint32_t *src, uint32_t *dst, uint8_t src_start_pos, uint8_t dst_start_pos, uint8_t count) {

	uint32_t dst_old_mask = bits_generate_ones(dst_start_pos, dst_start_pos + count - 1);
	dst_old_mask = ~dst_old_mask;
	uint32_t old_dst = *dst & dst_old_mask;
	bits_copy(src, dst, src_start_pos, dst_start_pos, count);
	*dst |= old_dst;
}

/* First count bits of bits1 need to be compare with first count bits of bits2 */
static inline bool
bits_compare (uint32_t bits1, uint32_t bits2, uint8_t count) {

	uint32_t unwanted_bits = bits_generate_ones(0, count - 1);
	return ((bits1 & unwanted_bits) == (bits2 & unwanted_bits));
}

#define BIT_MASK_ITERATE_BEGIN(prefix, mask, prefix_len, index, bit) \
{														  		\
	int _i;									             	   \
	for (_i = 0, index = 0; _i < prefix_len; \
			_i++, index = _i) {	  					  \
		if (BIT_AT(mask, _i)) {				 	  \
			bit = DONT_CARE;			  		\
		}											   		  	\
		else if (BIT_AT(prefix, _i)) {	   		\
			bit = ONE;								     \
		}												        \
		else {												  \
			bit = ZERO;							  		\
		}

#define BIT_MASK_ITERATE_END }}

static inline bool
prefix_match(uint32_t input, uint32_t prefix, uint32_t mask, uint8_t prefix_len) {

	if (!prefix_len) return true;

	uint32_t unwanted_bits = 0xFFFFFFFF;
	unwanted_bits = unwanted_bits >> (32 - prefix_len);
	unwanted_bits = unwanted_bits << (32 - prefix_len);

	if ((input & (~mask) & unwanted_bits) == (prefix & (~mask) & unwanted_bits)) {
		return true;
	}
	return false;
}

static inline bool
mtrie_is_leaf_node (mtrie_node_t *node) {

	return  (!node->child[ZERO] && !node->child[ONE] && !node->child[DONT_CARE]);
}


/* For all MTRIE APIs, mask is expressed in opposite way.
For example, 10.0.0.0/24 , mask will be  ->  ..24 ZEROS...11111111
*/

void mtrie_print_node(mtrie_node_t *node);
void mtrie_insert_prefix (mtrie_t *mtrie, 
										  uint32_t prefix,
										  uint32_t mask,
										  uint8_t prefix_len,
										  void *data);

void init_mtrie(mtrie_t *mtrie);
void mtrie_print_ipv4_recursive(mtrie_t *mtrie);
mtrie_node_t *mtrie_longest_prefix_match_search(mtrie_t *mtrie, uint32_t prefix);
mtrie_node_t *
mtrie_exact_prefix_match_search(mtrie_t *mtrie, uint32_t prefix, uint32_t mask);
bool mtrie_delete_prefix (mtrie_t *mtrie, uint32_t prefix, uint32_t mask) ;
void mtrie_destroy(mtrie_t *mtrie) ;
void mtrie_post_order_traverse(mtrie_t *mtrie, void (*process_fn_ptr)(mtrie_node_t *));