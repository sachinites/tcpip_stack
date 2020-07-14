#ifdef _KERNEL
#include <sys/param.h>
#include <sys/systm.h>
#include <netrtsock/rtsock_shared_bitvector.h>
#include <sys/jnx/malloc.h>
#define assert(x) KASSERT((x), ("ASSERTED %s, %d\n",__FUNCTION__,__LINE__))
#else
#include <stdio.h>
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "redblack.h"
#define XFREE(ptr)  \
    free(ptr);  \
    ptr = NULL
#endif

/**
 * @file
 *
 * This file provides the redblack tree implementation. The redblack tree is a balanced
 * binary tree, and allows duplicates.
 * @sa redblack.h
 */

/*
 * redblack_root_alloc
 *
 * Built-in root allocator.
 */
static rbroot *
redblack_root_alloc (void)
{
    rbroot *root;
#ifdef _KERNEL
    root = malloc(sizeof(rbroot), M_IFSTATE, M_NOWAIT | M_ZERO);
#else
    root = malloc(sizeof(rbroot));
#endif
    assert(root);

    return root;
}

/*
 * redblack_root_free
 *
 * Built-in root destructor.
 */
static void
redblack_root_free (rbroot *root)
{
    assert (root);
#ifdef _KERNEL
    FREE(root, M_IFSTATE);
#else
    XFREE(root);
#endif
}

/*
 * The redblack tree has built-in allocator and free functions.
 * However, users can specify their own allocator and free functions if
 * they desire, using the _redblack_set_allocator function.
 * Please note that the allocator and free functions are 
 * used ONLY for the root data structure. The other nodes are allocated
 * and freed directly by the caller of the redblack tree.
 */
static struct patricia_root_alloc_s {
    _redblack_root_alloc_fn  root_alloc;
    _redblack_root_free_fn   root_free;
} alloc_info;

/*
 * _redblack_set_allocator
 *
 * This function overrides the built-in allocator and free functions
 * with the user supplied functions.
 */
void _redblack_set_allocator (_redblack_root_alloc_fn my_alloc,
                             _redblack_root_free_fn  my_free)
{
    alloc_info.root_alloc = my_alloc;
    alloc_info.root_free = my_free;
}

/*
 * redblack_find_leftmost
 *
 * Given a starting node, find the leftmost leaf in the (sub)tree.
 */
static rbnode *
redblack_find_leftmost (const rbroot *root, rbnode *node)
{
    while (node->rb_left != &root->nil) {
	node = node->rb_left;
    }
    return(node);
}

/*
 * redblack_find_rightmost
 *
 * Given a starting node, find the rightmost leaf in the (sub)tree.
 */
static rbnode *
redblack_find_rightmost (const rbroot *root, rbnode *node)
{
    while (node->rb_right != &root->nil) {
	node = node->rb_right;
    }
    return(node);
}

/*
 * _redblack_root_init
 *
 * Initialize a red-black root node.  Allocate one if not provided.
 */
rbroot *
_redblack_root_init (rbroot *root, char via_ptr, unsigned int off,
		    char dupes)
{
    if (alloc_info.root_alloc == NULL) {
        _redblack_set_allocator(redblack_root_alloc, redblack_root_free);
    }

    if (!root) {
	root = alloc_info.root_alloc();
    }
    root->root = &root->nil;	
    root->key_offset = off;
    root->key_via_ptr = (via_ptr ? 1 : 0);
    root->key_dupes = (dupes ? 1 : 0);
    _redblack_node_init(root, &root->nil);
    return(root);
}

/*
 * _redblack_root_delete
 *
 * Delete the root of a tree.  The tree itself must be empty for this to
 * succeed.
 */
void
_redblack_root_delete (rbroot *root)
{
    if (root) {
	assert(root->root == &root->nil);
	alloc_info.root_free(root);
    }
}

/*
 * _redblack_node_in_tree
 *
 * Return TRUE if a node is in the tree.  For now, this is only a syntactic
 * check.
 */
char
_redblack_node_in_tree (rbroot *root, rbnode *node)
{
    return(node->rb_parent != NULL || node == root->root);
}

/*
 * _redblack_node_init
 *
 * Passed a pointer to a redblack node, initialize it.  Fortunately, this
 * is easy.
 */
void
_redblack_node_init (rbroot *root, rbnode *node)
{
    node->rb_color = RB_BLACK;
    node->rb_left = node->rb_right = &root->nil;
    node->rb_parent = NULL;
}

/*
 * rb_left_rotate
 *
 * "Rotate" entry and its right child.
 */
static void
rb_left_rotate (rbroot *root, rbnode *node)
{
    rbnode *child;

    child = node->rb_right;

    /*
     * Turn child's left subtree into node's right subtree.
     */
    node->rb_right = child->rb_left;

    if (child->rb_left != &root->nil) {
	child->rb_left->rb_parent = node;
    }

    /*
     * Link node's parent to child.
     */
    child->rb_parent = node->rb_parent;

    if (node->rb_parent == NULL) {
	/*
	 * node was the head, so now the child is the head.
	 */
	root->root = child;
    } else {
	/*
	 * Adjust the appropriate pointer in node's parent.
	 */
	if (node == node->rb_parent->rb_left) {
	    node->rb_parent->rb_left = child;
	} else {
	    node->rb_parent->rb_right = child;
	}
    }

    /*
     * Put node on child's left.
     */
    child->rb_left = node;
    node->rb_parent = child;
}

/*
 * rb_right_rotate
 *
 * "Rotate" node and its left child.
 */
static void
rb_right_rotate (rbroot *root, rbnode *node)
{
    rbnode *child;

    child = node->rb_left;

    /*
     * Turn child's right subtree into node's left subtree.
     */
    node->rb_left = child->rb_right;

    if (child->rb_right != &root->nil) {
	child->rb_right->rb_parent = node;
    }

    /*
     * Link node's parent to child.
     */
    child->rb_parent = node->rb_parent;

    if (node->rb_parent == NULL) {
	/*
	 * node was the head, so now the child is the head.
	 */
	root->root = child;
    } else {
	/*
	 * Adjust the appropriate pointer in node's parent.
	 */
	if (node == node->rb_parent->rb_left) {
	    node->rb_parent->rb_left = child;
	} else {
	    node->rb_parent->rb_right = child;
	}
    }

    /*
     * Put node on child's right.
     */
    child->rb_right = node;
    node->rb_parent = child;
}

/*
 * _redblack_add
 *
 * Add a node to a red-black tree.  Returns TRUE on success.
 */
char
_redblack_add (rbroot *root, rbnode *node, _redblack_compare_func compare)
{
    int cmp = 0;
    rbnode *parent, *t;

    /*
     * Make sure the new node is initialized properly for this tree.
     */
    _redblack_node_init(root, node);


    /*
     * If there's no head, this is the head.
     */
    if (root->root == &root->nil) {
	root->root = node;
	return(1);
    }

    /*
     * This is essentially just a binary tree add.
     */

    /*
     * Walk the tree, stopping when we hit a nil node.
     */
    parent = NULL;
    t = root->root;
    while (t != &root->nil) {
	parent = t;

	cmp = compare ? (*compare)(_redblack_key(root, node), _redblack_key(root, t)):
            (root->compare_fn)(_redblack_key(root, node), _redblack_key(root, t));

	if (cmp < 0) {
	    t = t->rb_left;
	} else if (cmp > 0) {
	    t = t->rb_right;
	} else {
	    /*
	     * The key is already there.  How we proceed depends
	     * on what the caller wants.
	     */
	    if (root->key_dupes) {
		t = t->rb_left;
	    } else {
		return(0);
	    }
	}
    }

    /*
     * Attach the new node where we just fell off.
     */
    if (cmp <= 0) {
	parent->rb_left = node;
    } else {
	parent->rb_right = node;
    }
    node->rb_parent = parent;

    /*
     * End of binary_add
     */

    node->rb_color = RB_RED;

    while (node != root->root && node->rb_parent->rb_color == RB_RED) {
	if (node->rb_parent == node->rb_parent->rb_parent->rb_left) {
	    /*
	     * Current node's parent is the grandparent's left child.
	     */
	    t = node->rb_parent->rb_parent->rb_right;
	    if (t->rb_color == RB_RED) {
		/*
		 * Case 1.
		 */
		node->rb_parent->rb_color = RB_BLACK;
		t->rb_color = RB_BLACK;
		node->rb_parent->rb_parent->rb_color = RB_RED;
		node = node->rb_parent->rb_parent;
	    } else {
		if (node == node->rb_parent->rb_right) {
		    /*
		     * Case 2.
		     */
		    node = node->rb_parent;
		    rb_left_rotate(root, node);
		}
		/*
		 * Case 3.
		 */
		node->rb_parent->rb_color = RB_BLACK;
		node->rb_parent->rb_parent->rb_color = RB_RED;
		rb_right_rotate(root, node->rb_parent->rb_parent);
	    }
	} else {
	    /*
	     * Current node's parent is the grandparent's right child.
	     */
	    t = node->rb_parent->rb_parent->rb_left;
	    if (t->rb_color == RB_RED) {
		/*
		 * Case 1.
		 */
		node->rb_parent->rb_color = RB_BLACK;
		t->rb_color = RB_BLACK;
		node->rb_parent->rb_parent->rb_color = RB_RED;
		node = node->rb_parent->rb_parent;
	    } else {
		if (node == node->rb_parent->rb_left) {
		    /*
		     * Case 2.
		     */
		    node = node->rb_parent;
		    rb_right_rotate(root, node);
		}
		/*
		 * Case 3.
		 */
		node->rb_parent->rb_color = RB_BLACK;
		node->rb_parent->rb_parent->rb_color = RB_RED;
		rb_left_rotate(root, node->rb_parent->rb_parent);
	    }
	}
    }

    root->root->rb_color = RB_BLACK;

    return(1);
}

/*
 * rb_delete_fixup
 *
 * After a node removal, fix up the tree to still be red/black.
 */
static void
rb_delete_fixup (rbroot *root, rbnode *node)
{
    rbnode *sibling;

    /*
     * node has an extra 'black', so work up the tree, pushing
     * the extra black up it.
     */
    while (node != root->root && node->rb_color == RB_BLACK) {
	if (node == node->rb_parent->rb_left) {
	    sibling = node->rb_parent->rb_right;
	    if (sibling->rb_color == RB_RED) {
		/*
		 * Case 1.
		 * Sibling is red, make it black and the parent red,
		 * then do a left rotation.  Get the new sibling
		 * and fall through to the following cases.
		 */
		sibling->rb_color = RB_BLACK;
		node->rb_parent->rb_color = RB_RED;
		rb_left_rotate(root, node->rb_parent);
		sibling = node->rb_parent->rb_right;
		assert(sibling != &root->nil);
	    }
	    if (sibling->rb_left->rb_color == RB_BLACK &&
		sibling->rb_right->rb_color == RB_BLACK) {
		/*
		 * Case 2.
		 * Sibling's children are black, so sibling
		 * must become red.  Move up the tree.
		 */
		sibling->rb_color = RB_RED;
		node = node->rb_parent;
	    } else {
		if (sibling->rb_right->rb_color == RB_BLACK) {
		    /*
		     * Case 3.
		     * Sibling's left child is red and right child
		     * is black, so make the left black, the sibling
		     * red, then do a right rotation.  Get the new
		     * sibling and fall through to the following case.
		     */
		    sibling->rb_left->rb_color = RB_BLACK;
		    sibling->rb_color = RB_RED;
		    rb_right_rotate(root, sibling);
		    sibling = node->rb_parent->rb_right;
		}
		/*
		 * Case 4.
		 * Sibling is black and sibling's right child is red.
		 * Fix up colors and do a left rotation on the parent.
		 * Terminate the walk up the tree by setting node
		 * to be the root.
		 */
		sibling->rb_color = node->rb_parent->rb_color;
		node->rb_parent->rb_color = RB_BLACK;
		sibling->rb_right->rb_color = RB_BLACK;
		rb_left_rotate(root, node->rb_parent);
		node = root->root;
	    }
	} else {
	    /*
	     * All logic is same as above, with left and right exchanged.
	     */
	    sibling = node->rb_parent->rb_left;
	    if (sibling->rb_color == RB_RED) {
		sibling->rb_color = RB_BLACK;
		node->rb_parent->rb_color = RB_RED;
		rb_right_rotate(root, node->rb_parent);
		sibling = node->rb_parent->rb_left;
		assert(sibling != &root->nil);
	    }
	    if (sibling->rb_right->rb_color == RB_BLACK &&
		sibling->rb_left->rb_color == RB_BLACK) {
		sibling->rb_color = RB_RED;
		node = node->rb_parent;
	    } else {
		if (sibling->rb_left->rb_color == RB_BLACK) {
		    sibling->rb_right->rb_color = RB_BLACK;
		    sibling->rb_color = RB_RED;
		    rb_left_rotate(root, sibling);
		    sibling = node->rb_parent->rb_left;
		}
		sibling->rb_color = node->rb_parent->rb_color;
		node->rb_parent->rb_color = RB_BLACK;
		sibling->rb_left->rb_color = RB_BLACK;
		rb_right_rotate(root, node->rb_parent);
		node = root->root;
	    }
	}
    }

    node->rb_color = RB_BLACK;
}

/*
 * rbtree_successor
 *
 * Find the node following the passed-in node.
 * Will return a pointer to the nil node if there is no successor.
 */
static rbnode *
rbtree_successor (rbroot *root, rbnode *node)
{
    rbnode *y;

    if (node->rb_right != &root->nil) {
	/*
	 * Find the leftmost on the right subtree.
	 */
	y = node->rb_right;
	while (y->rb_left != &root->nil) {
	    y = y->rb_left;
	}
    } else {
	/*
	 * Find the ancestor.
	 */
	y = node->rb_parent;
	while (y != NULL && node == y->rb_right) {
	    node = y;
	    y = y->rb_parent;
	}
	if (y == NULL)
	    y = &root->nil;
    }
    return(y);
}

/*
 * rbtree_predecessor
 *
 * Find the node preceding the passed-in node.
 * Will return a pointer to the nil node if there is no predecessor.
 */
static rbnode *
rbtree_predecessor (rbroot *root, rbnode *node)
{
    rbnode *y;

    if (node->rb_left != &root->nil) {
	/*
	 * Find the rightmost on the left subtree.
	 */
	y = node->rb_left;
	while (y->rb_right != &root->nil) {
	    y = y->rb_right;
	}
    } else {
	/*
	 * Find the ancestor.
	 */
	y = node->rb_parent;
	while (y != NULL && node == y->rb_left) {
	    node = y;
	    y = y->rb_parent;
	}
	if (y == NULL)
	    y = &root->nil;
    }
    return(y);
}

/*
 * _redblack_delete
 *
 * Delete a node from a redblack tree.
 * Note that this code doesn't know whether or not the node
 * is actually in the tree.
 */
char
_redblack_delete (rbroot *root, rbnode *node)
{
    rbnode *child, *y;
    char color;

    /*
     * Is there even a tree?
     */
    if (root->root == &root->nil) {
	return(0);
    }

    /*
     * Make sure somebody isn't trying to remove the nil node.
     */
    assert(node != &root->nil);

    /*
     * Figure out which node to splice out.
     */
    if (node->rb_left == &root->nil || node->rb_right == &root->nil) {
	/*
	 * One or fewer children, so can remove the node.
	 */
	y = node;
    } else {
	/*
	 * Two children, so remove the next node.
	 */
	y = rbtree_successor(root, node);
    }

    /*
     * Get the non-nil child, or nil if there are no children.
     */
    if (y->rb_left != &root->nil) {
	child = y->rb_left;
	assert(y->rb_right == &root->nil);
    } else {
	child = y->rb_right;
	assert(y->rb_left == &root->nil);
    }

    /*
     * Remove y by fixing up it's child's parent pointer and
     * its parent's child pointer.
     */
    child->rb_parent = y->rb_parent;
    if (y->rb_parent == NULL) {
	root->root = child;
    } else if (y == y->rb_parent->rb_left) {
	y->rb_parent->rb_left = child;
    } else {
	y->rb_parent->rb_right = child;
    }

    /*
     * If y isn't the victim node, move y to where the victim is.
     */
    if (y != node) {
	/*
	 * Stuff y where node was.
	 * Fix parent's pointer.
	 */
	if (node->rb_parent == NULL) {
	    root->root = y;
	} else if (node->rb_parent->rb_left == node) {
	    node->rb_parent->rb_left = y;
	} else if (node->rb_parent->rb_right == node) {
	    node->rb_parent->rb_right = y;
	}

	/*
	 * Swap node colors.
	 * This makes sure that we test the color of the removed node
	 * when deciding if we should perform a fixup.
	 */
	color = y->rb_color;
	y->rb_color = node->rb_color;
	node->rb_color = color;

	/*
	 * Copy parent and child pointers.
	 */
	y->rb_parent = node->rb_parent;
	y->rb_left = node->rb_left;
	y->rb_right = node->rb_right;

	/*
	 * Fix children's parent pointers.
	 */
	y->rb_left->rb_parent = y;
	y->rb_right->rb_parent = y;
    }

    /*
     * If we just removed a black node, than the red-black properties
     * of the tree do not hold anymore, so go fix it up.
     */
    if (node->rb_color == RB_BLACK)
	rb_delete_fixup(root, child);

    /*
     * Clean out the node.
     */
    node->rb_left = node->rb_right = &root->nil;
    node->rb_parent = NULL;
    return(1);
}

/*
 * _redblack_find_next
 *
 * Given a node, find the lexical next node in the tree.  If the
 * node pointer is NULL the leftmost node in the tree is returned.
 * Returns NULL if the tree is empty or it falls off the right.  Asserts
 * if the node isn't in the tree.
 */
rbnode *
_redblack_find_next (rbroot *root, rbnode *node)
{
    /*
     * If there's nothing in the tree we're done.
     */
    if (root->root == &root->nil) {
	assert(node == NULL);
	return(NULL);
    }

    /*
     * If he didn't specify a node, return the leftmost guy.
     */
    if (node == NULL) {
	return(redblack_find_leftmost(root, root->root));
    }

    node = rbtree_successor(root, node);
    if (node == &root->nil)
	return(NULL);
    return(node);
}

/*
 * _redblack_find_prev
 *
 * Given a node, find the lexical previous node in the tree.  If the
 * node pointer is NULL the rightmost node in the tree is returned.
 * Returns NULL if the tree is empty or it falls off the left.  Asserts
 * if the node isn't in the tree.
 */
rbnode *
_redblack_find_prev (rbroot *root, rbnode *node)
{
    /*
     * If there's nothing in the tree we're done.
     */
    if (root->root == &root->nil) {
	assert(node == NULL);
	return(NULL);
    }

    /*
     * If he didn't specify a node, return the rightmost guy.
     */
    if (node == NULL) {
	return(redblack_find_rightmost(root, root->root));
    }

    node = rbtree_predecessor(root, node);
    if (node == &root->nil)
	return(NULL);
    return(node);
}

/*
 * _redblack_get
 *
 * Given a key, find a node which matches.  If leq is TRUE,
 * return the node with closest key less than the desired key
 * if an exact match cannot be found.
 */
static rbnode *
redblack_get_internal (const rbroot *root, const void *key,
		       _redblack_compare_func compare, char leq)
{
    rbnode *current, *leq_node = NULL;
    int cmp;

    current = root->root;
    if (current == &root->nil) {
	return(NULL);
    }

    while (current != &root->nil) {
	cmp = (*compare)(key, _redblack_key(root, current));
	if (cmp > 0) {
	    /*
	     * current < lookfor, so remember this in case an exact
	     * match cannot be found.
	     */
	    leq_node = current;
	    current = current->rb_right;
	} else if (cmp < 0) {
	    /*
	     * lookfor < current
	     */
	    current = current->rb_left;
	} else {
	    /*
	     * current == lookfor, so done.
	     */
	    return(current);
	}
    }

    /*
     * Return the best thing we found, or nothing.
     */
    if (leq) {
	return(leq_node);
    } else {
	return(NULL);
    }
}

/*
 * _redblack_get
 *
 * Given a key, find a node which matches.
 */
rbnode *
_redblack_get (const rbroot *root, const void *key,
	      _redblack_compare_func compare)
{
    return(redblack_get_internal(root, key, compare, 0));
}

/*
 * _redblack_get_leq
 *
 * Given a key, find a node which matches.
 */
rbnode *
_redblack_get_leq (const rbroot *root, const void *key,
		  _redblack_compare_func compare)
{
    return(redblack_get_internal(root, key, compare, 1));
}

/*
 * _redblack_getnext
 *
 * Find the next matching guy in the tree.  This is a classic getnext,
 * except that if we're told to we will return an exact match if we find
 * one.
 */
rbnode *
_redblack_getnext (rbroot *root, const void *key, char eq,
		  _redblack_compare_func compare)
{
    rbnode *current;

    /*
     * If nothing in tree, nothing to find.
     */
    if (root->root == &root->nil) {
	return(NULL);
    }

    /*
     * Find the node with the requested key.
     */
    current = _redblack_get_leq(root, key, compare);
    if (eq) {
	return(current);
    }

    /*
     * Find the next node.
     */
    return(_redblack_find_next(root, current));
}

/*
 * redblack_walk_helper
 *
 * Recursion helper for _redblack_walk().
 */
static int
redblack_walk_helper (const rbroot *root, rbnode *node, _redblack_walk_fun func,
		      void *arg)
{
    int result;

    if (node->rb_left != &root->nil) {
	result = redblack_walk_helper(root, node->rb_left, func, arg);
	if (result < 0) {
	    return(-1);
	}
    }

    result = (*func)(node, arg);
    if (result < 0) {
	return(-1);
    }

    if (node->rb_right != &root->nil) {
	result = redblack_walk_helper(root, node->rb_right, func, arg);
	if (result < 0) {
	    return(-1);
	}
    }

    return(0);
}

/*
 * _redblack_walk
 *
 * Walk the rbtree tree inorder, calling the function for each node.
 */
void
_redblack_walk (const rbroot *root, _redblack_walk_fun func, void *arg)
{
    if (root->root == &root->nil) {
	return;
    }

    redblack_walk_helper(root, root->root, func, arg);
}

/*
 * redblack_walk_backwards_helper
 *
 * Recursion helper for _redblack_walk_backwards().
 */
static int
redblack_walk_backwards_helper (const rbroot *root, rbnode *node,
				_redblack_walk_fun func, void *arg)
{
    int result;

    if (node->rb_right != &root->nil) {
	result = redblack_walk_backwards_helper(root, node->rb_right, func,
						arg);
	if (result < 0) {
	    return(-1);
	}
    }

    result = (*func)(node, arg);
    if (result < 0) {
	return(-1);
    }

    if (node->rb_left != &root->nil) {
	result = redblack_walk_backwards_helper(root, node->rb_left, func,
						arg);
	if (result < 0) {
	    return(-1);
	}
    }

    return(0);
}

/*
 * _redblack_walk_backwards
 *
 * Walk the rbtree tree backwards, calling the function for each node.
 */
void
_redblack_walk_backwards (const rbroot *root, _redblack_walk_fun func, void *arg)
{
    if (root->root == &root->nil) {
	return;
    }

    redblack_walk_backwards_helper(root, root->root, func, arg);
}

/*
 * redblack_free_helper
 *
 * Recursion helper for _redblack_free().
 */
static void
redblack_free_helper (const rbroot *root, rbnode *node, _redblack_free_fun func)
{
    if (node->rb_left != &root->nil) {
	redblack_free_helper(root, node->rb_left, func);
    }
    if (node->rb_right != &root->nil) {
	redblack_free_helper(root, node->rb_right, func);
    }
    (*func)(node);
}

void
_redblack_free (rbroot *root, _redblack_free_fun func)
{
    if (root->root == &root->nil) {
	return;
    }

    redblack_free_helper(root, root->root, func);
}

static void
redblack_dump_helper (void *fp, const rbroot *root, rbnode *node,
		      void (*func)(void *, rbnode *, int), int level)
{
    if (node->rb_right != &root->nil)
	redblack_dump_helper(fp, root, node->rb_right, func, level+1);

    (*func)(fp, node, level);

    if (node->rb_left != &root->nil)
	redblack_dump_helper(fp, root, node->rb_left, func, level+1);
}

void
_redblack_dump (void *fp, rbroot *root, void (*func)(void *, rbnode *, int),
	       int level)
{
    if (root->root == &root->nil) {
	return;
    }

    redblack_dump_helper(fp, root, root->root, func, level);
}

void
_redblack_flush(rbroot *root){

    rbnode *node = NULL;
    ITERATE_RB_TREE_BEGIN(root, node){
        _redblack_delete(root, node);
    } ITERATE_RB_TREE_END;
}

rbnode *
_redblack_lookup(rbroot *rbroot, void *key, 
        int (*key_match)(void *, rbnode *)){

    rbnode *curr = NULL;
    void *user_data = NULL;
    int rc = 0;
    ITERATE_RB_TREE_BEGIN(rbroot, curr){
        user_data = (unsigned char *)curr - rbroot->key_offset;
        rc = 0;
        if(key_match != NULL)
            rc = key_match(key, user_data);
        else
            rc = rbroot->key_match_fn(key, user_data);
        if(rc == 0)
            return curr;
    } ITERATE_RB_TREE_END;
    return NULL;
}

void
register_rbtree_compare_fn(rbroot *root, _redblack_compare_func compare_fn){

    root->compare_fn = compare_fn;
}

void
register_rbtree_key_match_fn(rbroot *root, _redblack_key_match_func key_match_fn){

    root->key_match_fn = key_match_fn;
}

