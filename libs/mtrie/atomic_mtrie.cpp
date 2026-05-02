#include <cstddef>
#include "atomic_mtrie.h"
#include "../stack/stack.h"

/*
 * Memory ordering on child[] pointers (RCU-style publication):
 *
 * - memory_order_release on store: Publishes or unpublishes an edge in the trie.
 *   All prior writes that initialize the target node (or clear the old graph)
 *   are ordered before the pointer becomes visible to other threads.
 *
 * - memory_order_acquire on load: Consumes a child pointer from the live trie.
 *   Pairs with writers' release stores so this thread sees the node body
 *   (prefix, wildcard, data, etc.) as published before the pointer was stored.
 *
 * - memory_order_relaxed on store/load: Used when copying into a node that is
 *   not yet reachable from the trie. Atomicity keeps the pointer read/write
 *   race-free; no cross-thread happens-before is needed until a later release
 *   store installs the subtree. Loads from the shared src use acquire.
 */

extern int (*stdlib_printf)(const char *format, ...);

static uint16_t node_id = 1;

static inline uint16_t 
atomic_mtrie_get_new_node_id(void) {
    return (node_id++);
}

static void 
atomic_mtrie_free_node (atomic_mtrie_node_t *node) {

    //stdlib_printf("Node Freed : %u\n", node->node_id);
    bitmap_free_internal(&node->prefix);
    bitmap_free_internal(&node->wildcard);
    bitmap_free_internal(&node->stacked_prefix);
    delete node;
}

static atomic_mtrie_node_t *
atomic_mtrie_create_new_node (atomic_mtrie_t *mtrie) {

    uint16_t prefix_len = mtrie->prefix_len;
    atomic_mtrie_node_t *node = new atomic_mtrie_node_t;
    bitmap_init(&node->prefix, prefix_len);
    bitmap_init(&node->wildcard, prefix_len);
    bitmap_init(&node->stacked_prefix, prefix_len);
    node->parent = NULL;
    node->child[ZERO] = NULL;
    node->child[ONE] = NULL;
    node->child[DONT_CARE] = NULL;
    node->data = NULL;
    node->prefix_len = 0;
    node->node_id = atomic_mtrie_get_new_node_id();
    return node;
}

static bool
atomic_mtrie_is_leaf_node (atomic_mtrie_node_t *node) {

	/* Acquire: node may be reachable from the trie; need published child ptrs. */
	return  (!node->child[ZERO].load(std::memory_order_acquire) && 
			 !node->child[ONE].load(std::memory_order_acquire) &&
			 !node->child[DONT_CARE].load(std::memory_order_acquire));
}

static void 
atomic_mtrie_copy_children (atomic_mtrie_node_t *src_node, 
                            atomic_mtrie_node_t *dst_node) {

    atomic_mtrie_node_t *temp;

    /* Src may still be in the trie: acquire loads. Dst is private: relaxed stores;
     * a later release on the parent edge will publish the whole subtree. */
    dst_node->child[ZERO].store(
        src_node->child[ZERO].load(std::memory_order_acquire),
        std::memory_order_relaxed);
    dst_node->child[ONE].store(
        src_node->child[ONE].load(std::memory_order_acquire),
        std::memory_order_relaxed);
    dst_node->child[DONT_CARE].store(
        src_node->child[DONT_CARE].load(std::memory_order_acquire),
        std::memory_order_relaxed);

    if ((temp = dst_node->child[ZERO].load(std::memory_order_relaxed)))
         temp->parent = dst_node;
     if ((temp = dst_node->child[ONE].load(std::memory_order_relaxed)))
         temp->parent = dst_node;
    if ((temp = dst_node->child[DONT_CARE].load(std::memory_order_relaxed)))
         temp->parent = dst_node;    
}

static atomic_mtrie_node_t *
atomic_mtrie_clone (atomic_mtrie_t *mtrie, atomic_mtrie_node_t *node) {

    atomic_mtrie_node_t *clone = atomic_mtrie_create_new_node(mtrie);
    
    clone->prefix_len = node->prefix_len;

    /* Copy prefixes */
    bitmap_fast_copy(&node->prefix, &clone->prefix, clone->prefix_len);
    bitmap_fast_copy(&node->wildcard, &clone->wildcard, clone->prefix_len);

    /* Copy parent */
    clone->parent = node->parent;

    /* Copy children */
    atomic_mtrie_copy_children(node, clone);

    /* Copy app data */
    clone->data = node->data;
    return clone;
}

static bit_type_t
node_get_its_child_index(atomic_mtrie_node_t *node) {

    assert (node->parent);

    atomic_mtrie_node_t *parent = node->parent;

    /* Acquire: parent's child slots are trie edges published by writers. */
    if (parent->child[ZERO].load(std::memory_order_acquire) == node)
        return ZERO;
    if (parent->child[ONE].load(std::memory_order_acquire) == node)
        return ONE;
    if (parent->child[DONT_CARE].load(std::memory_order_acquire) == node)
        return DONT_CARE;         

    return DONT_CARE; // Randomly chosen       
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
atomic_mtrie_node_split (atomic_mtrie_t *mtrie, 
                         atomic_mtrie_node_t *node, 
                         uint8_t split_offset) {

    atomic_mtrie_node_t *daughter_node;
    bit_type_t new_child_pos;

    /* Split offset cannot be zero, if it is zero, we shall grow
    the mtrie on root side */
    assert(split_offset);

    /* Create a new mtrie node */
    daughter_node = atomic_mtrie_create_new_node(mtrie);
    
    daughter_node->prefix_len = node->prefix_len - split_offset;

    /* COPY Prefix : copy node->prefix_len - split_offset + 1 bits 
        from parent node starting from split_offset to end of the prefix */
    bitmap_copy_at_offset(&node->prefix, &daughter_node->prefix, 
        split_offset, 0, daughter_node->prefix_len );
    /* COPY wildcard in the same way as above*/
    bitmap_copy_at_offset(&node->wildcard, &daughter_node->wildcard, 
        split_offset, 0, daughter_node->prefix_len );

    /* Now move all the Children from parent node to new node */
    atomic_mtrie_copy_children(node, daughter_node);
    daughter_node->data = node->data;
    node->data = NULL;

    /* Release: unlink old children so readers do not follow stale edges after
     * observing null; pairs with acquire loads in search/traverse. */
    node->child[ZERO].store(nullptr, std::memory_order_release);
    node->child[ONE].store(nullptr, std::memory_order_release);
    node->child[DONT_CARE].store(nullptr, std::memory_order_release);

    /* Establish parent Child Relationship */
    daughter_node->parent = node;

    new_child_pos = bitmap_effective_bit_at(&node->prefix, 
                            &node->wildcard, split_offset);

    /* Release: daughter_node fully initialized above; publish after prior writes. */
    node->child[new_child_pos].store(daughter_node, std::memory_order_release);

    /* Update the parent node Prefix len/Prefix/wildcard*/

    /* Update prefix and wildcard first. 
        Though our mtrie will be constructed accurately, not getting rid
        of out of scope bits in prefix and wildcard would create issue in display of 
        data in show or in gdb. It may not have functional impact though because updating prefix len is enough*/
    bitmap_set(&node->prefix, split_offset, node->prefix_len - 1, false);
    bitmap_set(&node->wildcard, split_offset, node->prefix_len - 1, false);

    /* now update prefix len */
    node->prefix_len = split_offset;
}

void
atomic_mtrie_init(atomic_mtrie_t *mtrie, uint16_t prefix_len) {

    assert(!mtrie->root);
    mtrie->prefix_len = prefix_len;
    mtrie->root = atomic_mtrie_create_new_node(mtrie);
    mtrie->root->prefix_len = 0;
    mtrie->stack = get_new_stack();
}

void 
atomic_mtrie_deinit(atomic_mtrie_t *mtrie) {

    assert (mtrie->root->child[ZERO].load(std::memory_order_acquire) == nullptr);
    assert (mtrie->root->child[ONE].load(std::memory_order_acquire) == nullptr);
    assert (mtrie->root->child[DONT_CARE].load(std::memory_order_acquire) == nullptr);

    free_stack (mtrie->stack);
    mtrie->stack = NULL;
}


mtrie_ops_result_code_t
atomic_mtrie_insert_prefix(atomic_mtrie_t *mtrie,
					bitmap_t *prefix,
					bitmap_t *wildcard,
					uint16_t prefix_len,
                    void *app_data,
                    atomic_mtrie_node_t **result_node,
					atomic_mtrie_node_t **discarded_node) {


    int i = 0, j = 0;
    bit_type_t bit1, bit2;
    *result_node = NULL;
    *discarded_node = NULL;
    atomic_mtrie_node_t *node, *new_node;

    assert(mtrie->root && prefix_len);

    bit1 =  bitmap_effective_bit_at(prefix, wildcard, 0);

    /* Acquire: follow root edge published by insert/delete. */
    node = mtrie->root->child[bit1].load(std::memory_order_acquire);

    if (!node) {

        new_node = atomic_mtrie_create_new_node(mtrie);
        new_node->prefix_len = prefix_len;
        bitmap_fast_copy(prefix, &new_node->prefix, prefix_len);
        bitmap_fast_copy(wildcard, &new_node->wildcard, prefix_len);
        new_node->parent = mtrie->root;
        new_node->data = app_data;
        /* Release: publish new leaf after all fields above are written. */
        mtrie->root->child[bit1].store(new_node, std::memory_order_release);
        *result_node = new_node;
        *discarded_node = NULL;
        return MTRIE_INSERT_SUCCESS;
    }

    uint16_t node_prefix_len = node->prefix_len;

    ITERATE_MASKED_BITMAP_BEGIN(prefix, wildcard, prefix_len, i, bit1) {

        if (j == node_prefix_len ) {
            if ((node = node->child[bit1].load(std::memory_order_acquire))) {
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

        /* 'node' to be splitted, create a clone of this node and subject
            it for splitting */
        new_node = atomic_mtrie_clone (mtrie, node);
        atomic_mtrie_node_split(mtrie, new_node, j);
        assert(new_node->child[bit1].load(std::memory_order_acquire) == NULL);
        break;
    }
    ITERATE_MASKED_BITMAP_END;

    if (i == prefix_len) {
        if (j == node_prefix_len) {

            /* No change in the mtrie */
            *discarded_node = NULL;
            *result_node = node;
            return MTRIE_INSERT_DUPLICATE;
        }
        else {
             //stdlib_printf("Input TCAM entry exhausted\n");
             /* All entries are of same size. Input entry cannot be of 
             any arbitrary size  */
             return MTRIE_INSERT_FAILED;
        }
    }

    atomic_mtrie_node_t *niece_node = atomic_mtrie_create_new_node(mtrie);
    niece_node->prefix_len = prefix_len - i;
    niece_node->parent = new_node;
    bitmap_copy_at_offset(prefix, &niece_node->prefix, i, 0, prefix_len - i);
    bitmap_copy_at_offset(wildcard, &niece_node->wildcard, i, 0, prefix_len - i);
    niece_node->data = app_data;

    /* Release: link niece only after prefix/wildcard/data are ready. */
    new_node->child[bit1].store(niece_node, std::memory_order_release);

    /* RCU update : Now replace 'node' with 'new_node' in mtrie */
    bit_type_t child_node_index = node_get_its_child_index(node);
    /* Release: swap subtree root; readers acquire-load this edge. */
    node->parent->child[child_node_index].store(new_node, std::memory_order_release);
    
    *discarded_node = node;
    *result_node = new_node;
    return MTRIE_INSERT_SUCCESS;    
}

static void
atomic_mtrie_merge_child_node (
        atomic_mtrie_t *mtrie, 
        atomic_mtrie_node_t *parent,
        atomic_mtrie_node_t *child) {

    uint8_t child_count = 0;
    bit_type_t bit;

    /* root node is not allowed to merge its child */
    if (parent == mtrie->root) return ;

    bit = node_get_its_child_index(child);

    /* Parent-child association break */
    parent->child[bit].store(nullptr, std::memory_order_release);
    child->parent = NULL;

    bitmap_copy_at_offset(&child->prefix, &parent->prefix, 0,
        parent->prefix_len, child->prefix_len);
    bitmap_copy_at_offset(&child->wildcard, &parent->wildcard, 0, 
        parent->prefix_len, child->prefix_len);

    parent->prefix_len += child->prefix_len;
    
    atomic_mtrie_copy_children(child, parent);

    if (atomic_mtrie_is_leaf_node(child)) {
        assert (child->data);
        parent->data = child->data;
    }

}

mtrie_ops_result_code_t
atomic_mtrie_delete_prefix (atomic_mtrie_t *mtrie, 
							bitmap_t *prefix, 
							bitmap_t *wildcard, 
							void **app_data,
							atomic_mtrie_node_t **discarded_node) {

    *app_data = NULL;

    atomic_mtrie_node_t *existing_node = 
        atomic_mtrie_exact_prefix_match_search(mtrie, prefix, wildcard);

    if (!existing_node) {
        return MTRIE_DELETE_FAILED;
    }

    assert(atomic_mtrie_is_leaf_node(existing_node));

    *app_data = existing_node->data;

    atomic_mtrie_node_t *parent = existing_node->parent;

    if (parent == mtrie->root) {

        parent->child[node_get_its_child_index(existing_node)].store(
            nullptr, std::memory_order_release);
        *discarded_node = existing_node;
        return MTRIE_DELETE_SUCCESS;
    }

    atomic_mtrie_node_t *parent_clone = 
        atomic_mtrie_create_new_node(mtrie);

    parent_clone->prefix_len = parent->prefix_len;
    bitmap_fast_copy(&parent->prefix, &parent_clone->prefix, parent->prefix_len);
    bitmap_fast_copy(&parent->wildcard, &parent_clone->wildcard, parent->prefix_len);

    parent_clone->parent = parent->parent;
    assert (!parent->data);

    /* Create a child of parent clone which is other than existing_node */
    bit_type_t existing_node_index;
    bit_type_t existing_node_sibling_index;

    existing_node_index = node_get_its_child_index(existing_node);

    switch (existing_node_index) {

        case ZERO:
            if (parent->child[ONE].load(std::memory_order_acquire)) {
                existing_node_sibling_index = ONE;
                break;
            }
            existing_node_sibling_index = DONT_CARE;
            break;

        case ONE:
            if (parent->child[ZERO].load(std::memory_order_acquire)) {
                existing_node_sibling_index = ZERO;
                break;
            }
            existing_node_sibling_index = DONT_CARE;
            break;            
            
        case DONT_CARE:
            if (parent->child[ZERO].load(std::memory_order_acquire)) {
                existing_node_sibling_index = ZERO;
                break;
            }
            existing_node_sibling_index = ONE;
            break;               
    }

    atomic_mtrie_node_t *existing_node_sibling = 
        parent->child[existing_node_sibling_index].load(std::memory_order_acquire);

    atomic_mtrie_node_t *existing_node_sibling_clone = 
        atomic_mtrie_create_new_node(mtrie);

    existing_node_sibling_clone->prefix_len = 
        existing_node_sibling->prefix_len;

    bitmap_copy_at_offset(&existing_node_sibling->prefix,
                     &existing_node_sibling_clone->prefix,
                     0, 0, existing_node_sibling->prefix_len);

    bitmap_copy_at_offset(&existing_node_sibling->wildcard,
                     &existing_node_sibling_clone->wildcard,
                     0, 0, existing_node_sibling->prefix_len);
    
    existing_node_sibling_clone->data = existing_node_sibling->data;

    existing_node_sibling_clone->parent = parent_clone;
    /* Relaxed: parent_clone not yet in trie; final release is below on grandparent. */
    parent_clone->child[existing_node_sibling_index].store(
        existing_node_sibling_clone, std::memory_order_relaxed);

    atomic_mtrie_copy_children (existing_node_sibling, existing_node_sibling_clone);
    atomic_mtrie_merge_child_node(mtrie, parent_clone, existing_node_sibling_clone);
    atomic_mtrie_free_node(existing_node_sibling_clone);

    bit_type_t parent_index = node_get_its_child_index(parent);

    /* Final RCU update: release publishes parent_clone and its wired subtree. */
    parent->parent->child[parent_index].store(parent_clone, std::memory_order_release);
    *discarded_node = parent;

    return MTRIE_DELETE_SUCCESS;
}

void 
atomic_mtrie_prefix_insert_delete_discarded_node (atomic_mtrie_node_t *node) {

    atomic_mtrie_free_node(node);
}

void 
atomic_mtrie_prefix_delete_delete_discarded_node (atomic_mtrie_node_t *node) {

    /* Node is no longer reachable from the trie; no concurrent reader loads these
     * child atomics as trie edges. Relaxed is enough to read the pointer values
     * for teardown (atomicity without cross-thread publish/consume pairing). */
    atomic_mtrie_node_t *zero_child = node->child[ZERO].load(std::memory_order_relaxed);
    atomic_mtrie_node_t *one_child = node->child[ONE].load(std::memory_order_relaxed);
    atomic_mtrie_node_t *dont_care_child = node->child[DONT_CARE].load(std::memory_order_relaxed);

    if (zero_child) {
        atomic_mtrie_free_node(zero_child);
    }
    if (one_child) {
        atomic_mtrie_free_node(one_child);
    }
    if (dont_care_child) {
        atomic_mtrie_free_node(dont_care_child);
    }
}

static inline void 
stack_push_node (Stack_t *stack, atomic_mtrie_node_t *node, bitmap_t *prefix) {
                                    
    if (!node) return;
    bitmap_fast_copy(prefix, &node->stacked_prefix, prefix->tsize);
    push(stack , (void *)node);
}

/* Look up APIs: child[] loads use acquire to pair with release stores on updates. */
atomic_mtrie_node_t *
atomic_mtrie_longest_prefix_match_search(atomic_mtrie_t *mtrie, bitmap_t *prefix) {

    uint32_t n_back_tracks = 0, 
             n_comparisons = 0;
             
    atomic_mtrie_node_t *node, *next_node;
    
    reset_stack(mtrie->stack);

    node = mtrie->root->child[bitmap_at(prefix, 0) ? ONE : ZERO].load(std::memory_order_acquire);

    if (node) {
        stack_push_node(mtrie->stack, mtrie->root->child[DONT_CARE].load(std::memory_order_acquire), prefix);
    }
    else {
        node = mtrie->root->child[DONT_CARE].load(std::memory_order_acquire);
    }

    if (!node) return NULL;

    while(true) {

        n_comparisons++;
        if (!bitmap_prefix_match(prefix, &node->prefix, 
                                                 &node->wildcard, node->prefix_len)) {

            node = (atomic_mtrie_node_t *)pop(mtrie->stack);

            if (node) {

                n_back_tracks++;
                bitmap_fast_copy(&node->stacked_prefix, prefix, node->stacked_prefix.tsize);
                bitmap_reset(&node->stacked_prefix);
                stack_push_node(mtrie->stack, mtrie->root->child[DONT_CARE].load(std::memory_order_acquire), prefix);
                continue;
            }
            return NULL;
        }

        if (atomic_mtrie_is_leaf_node(node)) {
            assert(node->data);
            return node;
        }
        
        /* Shifts with data type width is not defined */
        bitmap_lshift(prefix, node->prefix_len);

        next_node = node->child[bitmap_at(prefix, 0) ? ONE : ZERO].load(std::memory_order_acquire);

        if (next_node) {
            stack_push_node(mtrie->stack, node->child[DONT_CARE].load(std::memory_order_acquire), prefix);
        }
        else {
            next_node = node->child[DONT_CARE].load(std::memory_order_acquire);
        }

        if (!next_node) return NULL;
        node = next_node;
    }
}

atomic_mtrie_node_t *
atomic_mtrie_exact_prefix_match_search(atomic_mtrie_t *mtrie, bitmap_t *prefix, bitmap_t *wildcard) {

    bitmap_t prefix_dup;
    bitmap_t wildcard_dup;
    atomic_mtrie_node_t *node = mtrie->root;

    if (atomic_mtrie_is_leaf_node(node)) return NULL;

    node = node->child[bitmap_effective_bit_at(prefix, wildcard, 0)].load(std::memory_order_acquire);

    if (!node) return NULL;

    bitmap_init (&prefix_dup, prefix->tsize);
    bitmap_init (&wildcard_dup, wildcard->tsize);
    bitmap_fast_copy (prefix, &prefix_dup, prefix->tsize);
    bitmap_fast_copy (wildcard, &wildcard_dup, wildcard->tsize);

    while (true) {

        if (!(bitmap_fast_compare (&prefix_dup, &node->prefix, node->prefix_len) &&
             bitmap_fast_compare(&wildcard_dup, &node->wildcard, node->prefix_len))) {

            bitmap_free_internal(&prefix_dup);
            bitmap_free_internal(&wildcard_dup);
            return NULL;
        }

         if (atomic_mtrie_is_leaf_node(node)) {

                bitmap_free_internal(&prefix_dup);
                bitmap_free_internal(&wildcard_dup);
                return node;
         }

        bitmap_lshift(&prefix_dup, node->prefix_len);
        bitmap_lshift(&wildcard_dup, node->prefix_len);

        node = node->child[bitmap_effective_bit_at(&prefix_dup, &wildcard_dup, 0)].load(std::memory_order_acquire);

        if (!node) {
            bitmap_free_internal(&prefix_dup);
            bitmap_free_internal(&wildcard_dup);
            return NULL;
        }
    }

    bitmap_free_internal(&prefix_dup);
    bitmap_free_internal(&wildcard_dup);
    return NULL;
}

static void
_atomic_mtrie_traverse(atomic_mtrie_t *mtrie,
                       atomic_mtrie_node_t *node,
                       void (*process_fn_ptr)(atomic_mtrie_t *, atomic_mtrie_node_t *, void *),
                       void *app_data) {

    if (!node) return;
    _atomic_mtrie_traverse(mtrie, node->child[ONE].load(std::memory_order_acquire), process_fn_ptr, app_data);
    _atomic_mtrie_traverse(mtrie, node->child[ZERO].load(std::memory_order_acquire), process_fn_ptr, app_data);
    _atomic_mtrie_traverse(mtrie, node->child[DONT_CARE].load(std::memory_order_acquire), process_fn_ptr, app_data);
    process_fn_ptr(mtrie, node, app_data);
}

void atomic_mtrie_traverse(atomic_mtrie_t *mtrie,
                           void (*process_fn_ptr)(atomic_mtrie_t *, atomic_mtrie_node_t *, void *),
                           void *app_data) {

    _atomic_mtrie_traverse(mtrie, mtrie->root, process_fn_ptr, app_data);
}

void
atomic_mtrie_print_node(atomic_mtrie_t *mtrie, atomic_mtrie_node_t *node, void *data) {

    atomic_mtrie_node_t *child;
    (void) mtrie; (void) data;
#if 1
    stdlib_printf (" ID : %u\n", node->node_id);
    stdlib_printf (" Prefix/Len : ");
    bitmap_prefix_print(&node->prefix, &node->wildcard, node->prefix_len);
    stdlib_printf ("/%d\n", node->prefix_len);
    stdlib_printf (" Parent Node = %u\n", node->parent ? node->parent->node_id : 0);
    child = node->child[ZERO].load(std::memory_order_acquire);
    stdlib_printf (" ZERO child = %u\n", child ? child->node_id : 0);
    child = node->child[ONE].load(std::memory_order_acquire);
    stdlib_printf (" ONE child = %u\n", child ? child->node_id : 0);
    child = node->child[DONT_CARE].load(std::memory_order_acquire);
    stdlib_printf (" DONT_CARE child = %u\n", child ? child->node_id : 0);        
    stdlib_printf (" data = %p\n", node->data);
#endif
}
