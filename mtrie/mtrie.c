#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include <stdbool.h>
#include <arpa/inet.h> /*for inet_ntop & inet_pton*/
#include "mtrie.h"
#include "../stack/stack.h"

static uint16_t node_id = 1;

/* To generate unique Node IDs. No functional, only for debugging
purpose */
static inline uint16_t 
mtrie_get_new_node_id(void) {
    return (node_id++);
}

/* Move all children from src_node to dst_node */
static void
mtrie_move_children(mtrie_node_t *src_node, mtrie_node_t *dst_node) {

    assert(!dst_node->child[ZERO]);
    assert(!dst_node->child[ONE]);
    assert(!dst_node->child[DONT_CARE]);
    dst_node->child[ZERO]  = src_node->child[ZERO] ;
    dst_node->child[ONE]  = src_node->child[ONE] ;
    dst_node->child[DONT_CARE]  = src_node->child[DONT_CARE] ;
     src_node->child[ZERO]  = NULL;
     src_node->child[ONE]  = NULL;
     src_node->child[DONT_CARE] = NULL;
     if (dst_node->child[ZERO])
         dst_node->child[ZERO]->parent = dst_node;
     if (dst_node->child[ONE])
         dst_node->child[ONE]->parent = dst_node;
     if (dst_node->child[DONT_CARE])
         dst_node->child[DONT_CARE]->parent = dst_node;
}

/* Fn to print mtrie_node details. Very helpful in debugging, via gdb especially */
void
mtrie_print_node(mtrie_t *mtrie, mtrie_node_t *node, void *data) {

    (void) mtrie; (void) data;

    printf ("ID : %d\n", node->node_id);
    printf (" Prefix/Len : ");
    bitmap_prefix_print(&node->prefix, &node->wildcard, node->prefix_len);
    printf ("/%d\n", node->prefix_len);
    printf (" Parent Node = %d\n", node->parent ? node->parent->node_id : 0);
    printf (" children = %d %d %d\n", 
        node->child[ZERO] ? node->child[ZERO]->node_id : 0,
        node->child[ONE] ? node->child[ONE]->node_id : 0,
        node->child[DONT_CARE] ? node->child[DONT_CARE]->node_id : 0);
    printf (" data = %p\n", node->data);
}

/* Delete and free the mtrie node */ 
static void
mtrie_node_delete(mtrie_t *mtrie, mtrie_node_t *node, void *data) {

    (void)data;

    bitmap_free_internal(&node->prefix);
    bitmap_free_internal(&node->wildcard);
    bitmap_free_internal(&node->stacked_prefix);
    remove_glthread(&node->list_glue );
    free(node);
    mtrie->N--;
}

mtrie_node_t *
mtrie_create_new_node(uint16_t prefix_len) {

    mtrie_node_t *node = (mtrie_node_t *)calloc(1, sizeof(mtrie_node_t));
    node->node_id = mtrie_get_new_node_id();
    bitmap_init(&node->prefix, prefix_len);
    bitmap_init(&node->wildcard, prefix_len);
    bitmap_init(&node->stacked_prefix, prefix_len);
    return node;
}

/* A fn to split the node A at a given offset off. Algorithm is :
1. Create a new node C
2. Make C the child of Parent node A as per the bit at offset off in A's prefix. Make A the father of C as well.
3. move the rest of the bits following offset from A to C
4. Move all children of A to C, along with A's Data 
5. If A had no children. add C to linear linked list.
6. Create a new child  node B of Parent node A as per the bit at offset off in input prefix. Make A the father of B as well.
7. Fix up parent child pointers between A and C.  
8. C is always leaf node, add it to linear linked list 
9. Decrease the prefix len of parent Node by number of bits moved to node C in step 3
*/
static void 
mtrie_node_split (mtrie_t *mtrie, mtrie_node_t *node, uint8_t split_offset) {

    mtrie_node_t *new_node;
    bit_type_t new_child_pos;

    /* Split offset cannot be zero, if it is zero, we shall grow
    the mtrie on root side */
    assert(split_offset);

    /* Create a new mtrie node */
    new_node = mtrie_create_new_node(mtrie->prefix_len);

    /* If the parent node is leaf, then new node formed after split is necessarily
        leaf */
    if (mtrie_is_leaf_node(node)) {
        glthread_add_next(&mtrie->list_head, &new_node->list_glue);
    }

    /* COPY Prefix : copy node->prefix_len - split_offset + 1 bits 
        from parent node starting from split_offset to end of the prefix */
    bitmap_slow_copy(&node->prefix, &new_node->prefix, split_offset, 0, node->prefix_len - split_offset );
    /* COPY wildcard in the same way as above*/
    bitmap_slow_copy(&node->wildcard, &new_node->wildcard, split_offset, 0, node->prefix_len - split_offset );
    /* Set prefix len in new Node */
    new_node->prefix_len = node->prefix_len - split_offset;

    /* Now move all the Children from parent node to new node */
    mtrie_move_children(node, new_node);
    new_node->data = node->data;
    node->data = NULL;

    /* Establish parent Child Relationship */
    new_node->parent = node;

    if (bitmap_at(&node->wildcard, split_offset)) {
        new_child_pos = DONT_CARE;
    }
    else if (bitmap_at(&node->prefix, split_offset)) {
        new_child_pos = ONE;
    }
    else {
        new_child_pos = ZERO;
    }
    node->child[new_child_pos] = new_node;

    /* Update the parent node Prefix len/Prefix/wildcard*/

    /* Update prefix and wildcard first. 
        Though our mtrie will be constructed accurately, not getting rid
        of out of scope bits in prefix and wildcard would create issue in display of 
        data in show or in gdb. It may not have functional impact though because updating prefix len is enough*/
    bitmap_set(&node->prefix, split_offset, node->prefix_len - 1, false);
    bitmap_set(&node->wildcard, split_offset, node->prefix_len - 1, false);

    /* now update prefix len */
    node->prefix_len = split_offset;

    /* Node which has just splitted cannot be leaf node anymore */
    remove_glthread(&node->list_glue);
}

/* A fn used to insert a prefix / wildcard combination in mtrie. Note that, wildcard is expressed as
all bit 1's representing dont care 
Algorithm : 
We traverse from the root of the tree, comparing the input prefix with the node's prefix bit
by bit. We descent down the tree using input prefix bit sequence as a guidance in the mtree. 
We perform node-split and add a new node as soon as mis-match occurs. Note that, prefix_len
cannot be any arbitrary len, it has to be mtrie->prefix_len always.
*/
bool
mtrie_insert_prefix (mtrie_t *mtrie, 
    							  bitmap_t *prefix,
								  bitmap_t *wildcard,
								  uint16_t prefix_len,
                                  void *data) {

    int i = 0, j = 0;
    bit_type_t bit1, bit2;
    mtrie_node_t *node;

    assert(mtrie->root && prefix_len);
    
    bit1 =  bitmap_effective_bit_at(prefix, wildcard, 0);

    if (!mtrie->root->child[bit1]) {

        mtrie->root->child[bit1] = mtrie_create_new_node(mtrie->prefix_len);
        bitmap_fast_copy(prefix, &mtrie->root->child[bit1]->prefix, prefix_len);
        bitmap_fast_copy(wildcard, &mtrie->root->child[bit1]->wildcard, prefix_len);
        mtrie->root->child[bit1]->prefix_len = prefix_len;
        mtrie->root->child[bit1]->data = data;
        mtrie->root->child[bit1]->parent = mtrie->root;
        init_glthread(&mtrie->root->child[bit1]->list_glue);
        glthread_add_next(&mtrie->list_head, &mtrie->root->child[bit1]->list_glue);
        mtrie->N++;
        return true;
    }

    node = mtrie->root->child[bit1];
    uint16_t node_prefix_len = node->prefix_len;

    ITERATE_MASKED_BITMAP_BEGIN(prefix, wildcard, prefix_len, i, bit1) {

        if (j == node_prefix_len ) {
            if (node->child[bit1]) {
                node = node->child[bit1];
                node_prefix_len = node->prefix_len;
                j = 1;
                continue;
            }
            break;
        }

        bit2 = bitmap_effective_bit_at(&node->prefix, &node->wildcard, j);
        if (bit1 == bit2) {
            j++;
            continue;
        }
        mtrie_node_split(mtrie, node, j);
        mtrie->N++;
        assert(node->child[bit1] == NULL);
        break;
    }
    ITERATE_MASKED_BITMAP_END;

    if (i == prefix_len) {
        if (j == node_prefix_len) {
            printf("Duplicate TCAM entry\n");
        }
        else {
             printf("Input TCAM entry exhausted\n");
             /* All entries are of same size. Input entry cannot be of 
             any arbitrary size  */
             assert(0);
            //mtrie_node_split(mtrie, node, j);
        }
        return false;
    }

    node->child[bit1] = mtrie_create_new_node(mtrie->prefix_len);
    node->child[bit1]->parent = node;
    node = node->child[bit1];
    bitmap_slow_copy(prefix, &node->prefix, i, 0, prefix_len - i);
    bitmap_slow_copy(wildcard, &node->wildcard, i, 0, prefix_len - i);
    node->prefix_len = prefix_len - i;
    node->data = data;
    init_glthread(&node->list_glue);
    glthread_add_next(&mtrie->list_head, &node->list_glue);
    mtrie->N++;
    return true;
    /* Caller should free prefix , wildcard bitmaps */
}

void
init_mtrie(mtrie_t *mtrie, uint16_t prefix_len) {

    assert(!mtrie->root);
    mtrie->root = mtrie_create_new_node(prefix_len);
    mtrie->N = 1;
    mtrie->stack = get_new_stack();
    init_glthread(&mtrie->list_head);
    mtrie->prefix_len = prefix_len;
    mtrie->resurrct = false;
}

static inline void 
stack_push_node (Stack_t *stack, mtrie_node_t *node, bitmap_t *prefix) {
                                    
    if (!node) return;
    bitmap_fast_copy(prefix, &node->stacked_prefix, prefix->tsize);
    push(stack , (void *)node);
}

/* A fn to search a given prefix in the mtrie as per the longest preffix match rule. 
Returns NULL if match is not found, else returns the leaf node if match succeeds. The leaf node
contains the data to be used by application. IT could be Route or ACL */
mtrie_node_t *
mtrie_longest_prefix_match_search(mtrie_t *mtrie, bitmap_t *prefix) {

    uint32_t n_back_tracks = 0, 
                  n_comparisons = 0;
    mtrie_node_t *node, *next_node;
    
    reset_stack(mtrie->stack);

    node = mtrie->root->child[bitmap_at(prefix, 0) ? ONE : ZERO];

    if (node) {
        stack_push_node(mtrie->stack, mtrie->root->child[DONT_CARE], prefix);
    }
    else {
        node = mtrie->root->child[DONT_CARE];
    }

    if (!node) return NULL;

    while(true) {

        n_comparisons++;
        if (!bitmap_prefix_match(prefix, &node->prefix, 
                                                 &node->wildcard, node->prefix_len)) {

            node = (mtrie_node_t *)pop(mtrie->stack);

            if (node) {

                n_back_tracks++;
                bitmap_fast_copy(&node->stacked_prefix, prefix, node->stacked_prefix.tsize);
                bitmap_reset(&node->stacked_prefix);
                stack_push_node(mtrie->stack, mtrie->root->child[DONT_CARE], prefix);
                continue;
            }
            return NULL;
        }

            if (mtrie_is_leaf_node(node)) {
                assert(node->data);
                node->n_comparisons = n_comparisons;
                node->n_backtracks = n_back_tracks;
                assert(!node->child[ZERO] && 
                          !node->child[ONE] && 
                          !node->child[DONT_CARE]);
                return node;
        }
        
        /* Shifts with data type width is not defined */
        bitmap_lshift(prefix, node->prefix_len);

        next_node = node->child[bitmap_at(prefix, 0) ? ONE : ZERO];

        if (next_node) {
            stack_push_node(mtrie->stack, node->child[DONT_CARE], prefix);
        }
        else {
            next_node = node->child[DONT_CARE];
        }

        if (!next_node) return NULL;
        node = next_node;
    }
}

/* A fn To be called on node which has exactly one child. This fn is used as helper
fn during node deletion from mtrie. In this fn, the parent node absorbs its only children
within itself, eventually deleting the child node*/
static void
mtrie_merge_child_node (mtrie_t *mtrie, mtrie_node_t *node, void *unused) {

    (void)unused;

    uint8_t child_count = 0;
    bit_type_t bit;

    /* root node is not allowed to merge its child */
    if (node == mtrie->root) return ;

    if (node->child[ZERO]) {
        child_count++;
        bit = ZERO;
    }

    if (node->child[ONE]) {
        child_count++;
        bit = ONE;
    }

    if (node->child[DONT_CARE]) {
        child_count++;
        bit = DONT_CARE;
    }

    /* A node is eligibe to merge its own child node only when
    it has exactly one child branch*/
    if (child_count != 1) return ;

    /* Parent-child association break */
    mtrie_node_t *child_node = node->child[bit];
    node->child[bit] = NULL;
    child_node->parent = NULL;

    bitmap_slow_copy(&child_node->prefix, &node->prefix, 0,
        node->prefix_len, child_node->prefix_len);
    bitmap_slow_copy(&child_node->wildcard, &node->wildcard, 0, 
        node->prefix_len, child_node->prefix_len);

    node->prefix_len += child_node->prefix_len;
    
    mtrie_move_children(child_node, node);
    
    if (mtrie_is_leaf_node(node)) {
        glthread_add_next(&mtrie->list_head, &node->list_glue);
        node->data = child_node->data;
        child_node->data = NULL;
    }

    mtrie_node_delete(mtrie, child_node, NULL);
}

/* A fn to search a given prefix in the mtrie but as per the exact match. Used for deleting the 
entry from mtrie. 
Returns NULL if match is not found, else returns the leaf node if match succeeds. The leaf node
contains the data to be used by application. IT could be Route or ACL */
mtrie_node_t *
mtrie_exact_prefix_match_search(mtrie_t *mtrie, bitmap_t *prefix, bitmap_t *wildcard) {

    mtrie_node_t *node = mtrie->root;

    if (mtrie_is_leaf_node(node)) return NULL;

    node = node->child[bitmap_effective_bit_at(prefix, wildcard, 0)];

    if (!node) return NULL;

    while (true) {

        if (!(bitmap_fast_compare (prefix, &node->prefix, node->prefix_len) &&
                bitmap_fast_compare(wildcard, &node->wildcard, node->prefix_len))) {

                return NULL;
         }

         if (mtrie_is_leaf_node(node)) return node;

        bitmap_lshift(prefix, node->prefix_len);
        bitmap_lshift(wildcard, node->prefix_len);

        node = node->child[bitmap_effective_bit_at(prefix, wildcard, 0)];

        if (!node) return NULL;
    }
    return NULL;
}

/* Given a pointer to the leaf node of the mtrie, delete it */
static void 
mtrie_delete_leaf_node(mtrie_t *mtrie, mtrie_node_t *node, bool merge) {

    assert(mtrie_is_leaf_node(node));

    mtrie_node_t *parent = node->parent;
    
    /* Its a root ! do not delete */
    if (!parent) return;

    if (parent->child[DONT_CARE] == node)
    {
        parent->child[DONT_CARE] = NULL;
    }
    else if (parent->child[ONE] == node)
    {
        parent->child[ONE] = NULL;
    }
    else
    {
        parent->child[ZERO] = NULL;
    }

    mtrie_node_delete(mtrie, node, NULL);

    if (merge) {
        mtrie_merge_child_node(mtrie, parent, NULL);
    }
}


/* A function used to delete the leaf node from the mtrie , i.e, the actual data. 
    Uses exact match API as helper API to locate the node of interest. 
*/
bool
mtrie_delete_prefix (mtrie_t *mtrie, bitmap_t *prefix, bitmap_t *wildcard, void **app_data) {

    *app_data = NULL;

    mtrie_node_t *node = mtrie_exact_prefix_match_search(mtrie, prefix, wildcard);

    if (!node) {
        return false;
    }

    /* Must be leaf node */
    assert(mtrie_is_leaf_node(node));
  
   *app_data = node->data;

    mtrie_delete_leaf_node(mtrie, node, true);

    return true;
}

/* Mtrie Traversal in longest prefix first search order. Useful to  display user entries 
    in priority order*/
static void
_mtrie_longest_prefix_first_traverse(mtrie_t *mtrie, 
                                                            mtrie_node_t *node,
                                                            void (*process_fn_ptr)(mtrie_t *, mtrie_node_t *, void *),
                                                            void *app_data) {

    if (!node) return;

    _mtrie_longest_prefix_first_traverse(mtrie, node->child[ONE], process_fn_ptr, app_data);
    _mtrie_longest_prefix_first_traverse(mtrie, node->child[ZERO], process_fn_ptr, app_data);
    _mtrie_longest_prefix_first_traverse(mtrie, node->child[DONT_CARE], process_fn_ptr, app_data);
    process_fn_ptr(mtrie, node, app_data);
}

void
mtrie_longest_prefix_first_traverse(mtrie_t *mtrie, 
                                                         void (*process_fn_ptr)(mtrie_t *,mtrie_node_t *, void *),
                                                         void *app_data) {

    _mtrie_longest_prefix_first_traverse(mtrie, mtrie->root, process_fn_ptr, app_data);
}

/* To Delete a tree, we need to do post order traversal, the Tree is non usable and
    need to be re-initialized by application to use it again*/
void mtrie_destroy(mtrie_t *mtrie) {

   mtrie_longest_prefix_first_traverse(mtrie, mtrie_node_delete, NULL);
    free_stack(mtrie->stack);
    assert(IS_GLTHREAD_LIST_EMPTY(&mtrie->list_head));
    mtrie->root = NULL;
}

/* If appln ever make a call to this API, make sure appln to call mtrie_resurrect()
    immediately after traversing the mtrie */
void *
mtrie_extract_appln_data(mtrie_t *mtrie, mtrie_node_t *node) {

    void *app_data;
    app_data = node->data;
    /* Dont do merging here while application is extracting data. Merging will
    be done via resurrection. Hence pass false */
    mtrie_delete_leaf_node(mtrie, node, false);
    mtrie->resurrct = true;
    return app_data;
}

/* API to delete all leaf nodes with NULL data assigned to it, Appln should call it
    if the application has linearly traversed all leaf nodes of mtrie and assign NULL data
    to few of them */
void mtrie_resurrect(mtrie_t *mtrie) {

        if (!mtrie->resurrct) return;
        mtrie_longest_prefix_first_traverse(mtrie,
             mtrie_merge_child_node, NULL);
        mtrie->resurrct = false;
}

void mtrie_print_raw(mtrie_t *mtrie) {

    mtrie_longest_prefix_first_traverse(mtrie,
            mtrie_print_node, NULL);
}

