/*
 * $Id: redblack.h 577170 2013-04-18 02:45:43Z ib-builder $
 *
 * redblack.h -- Red-black tree implementation, from Cormen
 *
 */

#ifndef	__REDBLACK_H__
#define	__REDBLACK_H__

/**
 * @file redblack.h
 * @brief
 * This file contains the public data structures for the redblack tree
 * package.  The redblack tree is balanced, so this package can be
 * appropriate for highly skewed data, or data which arrives in order.
 *
 * There are two necessary data structures: one is the root of a tree
 * (type rbroot), and the contents of this are hidden from you.  The
 * other is a node (type rbnode).  The contents of this data structure
 * are (unfortunately) public to make the compiler happy.
 *
 * To use this package:
 * First imbed the rbnode structure in your data structure.  You have
 * two choices for the key.  The first is to embed the key into the
 * data structure immediately following the rbnode stucture, as in:
 *
 *		struct foobar {
 *		    ...;
 *		    rbnode redblack;
 *		    u_char  key[KEYSIZE];
 *		    ...;
 *	        }
 *
 * The other choice is to embed a pointer to the key material immediately
 * following the data structure, as in
 *
 *		struct blech {
 *		    ...;
 *		    rbnode redblack;
 *		    sockaddr_un *key_ptr;
 *		    ...;
 *	        }
 *
 * In either case you can also specify an offset to the actual key material.
 * The choice of key location and offset, and whether duplicate keys are
 * allowed in the tree, is specified in a call to
 * _redblack_root_init().  If no rbroot pointer is passed in one is
 * allocated and returned, otherwise the specified root pointer is
 * filled in.
 *
 * For each node that you wish to add to the tree, you must first
 * initialize the node with a call to _redblack_node_init_length() with the
 * node and the length of the associated key, in bytes.  You can also
 * call _redblack_node_init() if the key length was fixed at root
 * initialization.  Then, once the key is installed in the node, you may
 * call _redblack_add().  Note that after calling _redblack_add(), you may
 * NOT change the key.
 *
 * Once the tree is initialized you can use the following functions:
 *
 * _redblack_add() - adds a new node to the tree.  If duplicate keys
 *		    are allowed in the tree, the duplicate will be added.
 *		    Otherwise, the call Will fail (return FALSE) if the key
 *		    you're adding is the same as something already in the tree.
 *
 * _redblack_delete() - deletes a node from the tree.
 *
 * _redblack_get() - look up a node having the specified key.  Returns NULL
 *
 * _redblack_getnext() - given a key, return a
 *			node in the tree which is at least as large as the
 *			key specified.  The call has a parameter which
 *			modifies its behaviour when an exact match is
 *			found in the tree; you can either choose to have
 *			it return the exact match, if there is one, or you
 *			can have it always return a node with a larger
 *			key (a la SNMP getnext).
 *
 * _redblack_find_next() - given a node in the tree, returns a node with
 *			  the next numerically larger key, or NULL if the
 *			  specified node was the largest.  If the given
 *		 	  node is NULL, returns the numerically smallest
 *			  node in the tree.  Good for tree walks.
 *
 * _redblack_find_prev() - given a node in the tree, returns a node with
 *			  the next numerically smaller key, or NULL if
 *			  the specified node was the smallest.  If the
 *			  given node is NULL, returns the numerically
 *			  largest node in the tree.  Note the definitions
 *			  of _redblack_find_next() and redblack_find_prev()
 *			  is such that
 *
 *    node == _redblack_find_prev(root, redblack_find_next(root, node));
 *
 *			  will always be TRUE for any node in the tree or NULL.
 *
 * When you're done with the tree, you can call _redblack_delete_root() on
 * an empty tree to get rid of the root information if the root was allocated
 * at initialization time.
 *
 * Generally you will not want to deal with the redblack structure
 * directly, so it's helpful to be able to be able to get back to the
 * primary structure.  This can be done with a function such as:
 *
 * static inline testnode *
 * rb_to_test (rbnode *node)
 * {
 *     testnode *foo = NULL;
 *     testnode *result;
 *
 *     result = (testnode *) ((int) node - (int)&foo->redblack);
 *     return(result);
 * }
 *
 * Using this, you can then easily define functions which completely hide
 * the redblack structure from the rest of your code.  This is STRONGLY
 * recommended.  ;-)
 */

typedef struct rbroot_ rbroot;
typedef struct rbnode_ rbnode;

/* 
 * char here should match macros defined in kernel 
 * like rtsock_ifstate.h 
 */
/**
 * @brief
 * Key comparison callback function.
 *
 * Given two keys, this function must return an integer value indicating whether
 * one key is less than or greater than the other, or if the keys are equal.
 *
 * @param[in] key1
 *     First key to compare
 * @param[in] key2
 *     Second key to compare
 *
 * @return
 *     0 if the keys are equal;
 *    <0 if @a key1 is less than @a key2;
 *    >0 if @a key1 is greater than @a key2.
 *
 * @sa _redblack_add(), redblack_get(), redblack_get_leq(), redblack_getnext()
 */ 
typedef int (*_redblack_compare_func)(const void *key1, const void *key2);
typedef int (*_redblack_key_match_func)(const void *key1, const void *user_data);
typedef int (*_redblack_walk_fun)(rbnode *, void *);
typedef void (*_redblack_free_fun)(rbnode *);

/**
 * @brief
 * Typedef for user-specified red-black root allocation function.
 *
 * @sa _redblack_set_allocator(), redblack_root_init()
 */
typedef rbroot *(*_redblack_root_alloc_fn)(void);

/**
 * @brief
 * Typedef for user-specified red-black root deallocation function.
 * 
 * @sa _redblack_set_allocator(), redblack_root_init()
 */
typedef void (*_redblack_root_free_fn)(rbroot *);

/**
 * @brief
 * Sets the allocation and deallocation routines for red-black 
 * tree root structure.
 *
 * @note The allocation and deallocation routines are used only for 
 * the tree root. The nodes of the tree must be allocated and deallocated
 * by the caller.
 *
 * @param[in] my_alloc
 *     Function to call when allocating the root structure.
 * @param[in] my_free
 *     Function to call when deallocating the root structure.
 */
void _redblack_set_allocator (_redblack_root_alloc_fn my_alloc,
                             _redblack_root_free_fn  my_free);

/*
 * Prototypes
 */

/**
 * @brief
 * Initializes a red-black tree root. 
 *
 * If @a root is @c NULL, this function will allocate a root structure.
 *
 * @param[in] root
 *     An existing tree root (can be @c NULL)
 * @param[in] key_via_ptr
 *     Determines if the key is directly embeded in the node, or
 *     stored as a pointer. 
 *     @c TRUE if the key is a pointer; @c FALSE if it is embedded directly
 * @param[in] key_offset
 *     Offset (in bytes), of the key within the node
 * @param[in] key_dupes
 *     Determines whether the tree allows duplicate keys.
 *     @c TRUE to allow duplicates; otherwise @c FALSE.
 *
 * @return
 *     A pointer to a new tree root.
 */
rbroot *_redblack_root_init(rbroot *root,
			   char key_via_ptr,
			   unsigned int key_offset,
			   char key_dupes);

/**
 * @brief
 * Deletes the root of the tree.
 *
 * The tree must be empty for this function to succeed.
 *
 * @param[in] root
 *     Root to delete
 */
void _redblack_root_delete(rbroot *root);

/**
 * @brief
 * Adds a new node to the tree.
 *
 * If the tree allows duplicate keys, the node will be added. 
 * Otherwise, this function will return @c FALSE.
 *
 * @param[in] root
 *     Root of the tree
 * @param[in] node
 *     Node to add to the tree
 * @param[in] compare
 *     Callback function to compare keys
 *
 * @return
 *     @c TRUE if the node was successfully added;
 *     otherwise, @c FALSE if the key is a duplicate, and the tree
 *     does not allow duplicates.
 */
char _redblack_add(rbroot *root, rbnode *node,
		     _redblack_compare_func compare);

/**
 * @brief
 * Deletes a node from the tree.
 *
 * @param[in] root
 *     Root of the tree
 * @param[in] node
 *     Node to remove from the tree
 *
 * @return
 *     @c TRUE if the node was removed successfully;
 *     otherwise, @c FALSE if the tree has no root node.
 */
char _redblack_delete(rbroot *root, rbnode *node);


/**
 * @brief
 * Returns the node with the next numerically larger key, or @c NULL if 
 * @a node has the largest key. 
 *
 * If @a node is @c NULL, this function returns the node with the numerically
 * smallest node in the tree.
 *
 * @param[in] root
 *     Root of the tree
 * @param[in] node
 *     Node to compare against
 * 
 * @return
 *     A pointer to an @c rbnode structure;
 *     @c NULL if the tree is empty, or if @a node has the largest key.
 *
 * @sa 
 *   _redblack_find_prev()
 */
rbnode *_redblack_find_next(rbroot *root, rbnode *node);

/**
 * @brief
 * Returns the node with the next numerically smaller key, or @c NULL if
 * @a node has the smallest key. 
 *
 * If @a node is @c NULL, this function returns the numerically largest node
 * in the tree. 
 * 
 * @note The statement:
 * <tt>node == _redblack_find_prev(root, redblack_find_next(root, node))</tt>
 * will always be @c TRUE for any node of the tree, or @c NULL.
 *
 * @param[in] root
 *     Root of the tree
 * @param[in] node
 *     Node to compare against
 *
 * @return
 *     A pointer to an @c rbnode structure;
 *     @c NULL if the tree is empty, or if @a node has the smallest key. 
 *
 * @sa 
 *   _redblack_find_next()
 */
rbnode *_redblack_find_prev(rbroot *root, rbnode *node);

/**
 * @brief
 * Returns the node having the specified key. 
 *
 * This function returns @c NULL if the tree is empty, or if the key 
 * cannot be found.
 *
 * @param[in] root
 *     Root of the tree
 * @param[in] key
 *     Key to compare against
 * @param[in] compare
 *     Callback function used to compare keys
 *
 * @return
 *     A pointer to an @c rbnode structure;
 *     @c NULL if the tree is empty, or if the key cannot be found
 * 
 * @sa _redblack_get_leq()
 */
rbnode *_redblack_get(const rbroot *root, const void *key,
		     _redblack_compare_func compare);

/**
 * @brief
 * Returns the node having the specified key.
 *
 * If @a key cannot be found, this function 
 * returns the node having the closest key less than @a key.
 *
 * @param[in] root
 *     Root of the tree
 * @param[in] key
 *     Key to compare against
 * @param[in] compare
 *     Callback function used to compare keys
 *
 * @return
 *     A pointer to an @c rbnode structure;
 *     @c NULL if the tree is empty, or if the key cannot be found 
 *     and @a leq is @c FALSE.
 * 
 * @sa
 *   _redblack_get()
 */ 
rbnode *_redblack_get_leq(const rbroot *root, const void *key,
			 _redblack_compare_func compare);

/**
 * @brief
 * Returns a node with a key at least as large as the specified key.
 *
 * If @a return_eq is @c TRUE, this function will return the node with the next
 * largest key (similar to SNMP getnext).
 *
 * @param[in] root
 *     Root of the tree
 * @param[in] key
 *     Key to compare against
 * @param[in] return_eq
 *     Pass @c FALSE to return an exact match, if there is one;
 *     otherwise, pass @c TRUE to return the node with the next largest key
 * @param[in] compare
 *     Callback function used to compare keys
 *
 * @return
 *     A pointer to an @c rbnode structure;
 *     @c NULL if the tree is empty, or if no match was found.
 */
rbnode *_redblack_getnext(rbroot *root,
			 const void *key,
			 char return_eq,	/* FALSE for classic getnext */
			 _redblack_compare_func compare);

/**
 * @brief
 * Checks to see if the parent of @a node is @a root.
 *
 * @param[in] root
 *     Root of the tree
 * @param[in] node
 *     Node to be checked
 *
 * @return
 *     @c TRUE if the parent of @a node is @a root;
 *     @c FALSE otherwise.
 */
char _redblack_node_in_tree(rbroot *root, rbnode *node);

/**
 * @brief
 * Initialize internal fields of a red-black tree node.
 *
 * @param[in] root
 *     Root of the tree in which to store @a node
 * @param[in] node
 *     Node to initialize
 */
void _redblack_node_init(rbroot *root, rbnode *node);

void _redblack_walk(const rbroot *, _redblack_walk_fun, void *);
void _redblack_walk_backwards(const rbroot *, _redblack_walk_fun, void *);
void _redblack_free(rbroot *, _redblack_free_fun);
void _redblack_flush(rbroot *);
/*
 * Inlines, for performance
 * 
 * All contents below this line are subject to change without notice.
 * Do not rely on the layout of these structures.
 */
struct rbnode_ {
    struct rbnode_	*rb_left;	/* left branch for redblack search */
    struct rbnode_	*rb_right;	/* right branch for same */
    struct rbnode_	*rb_parent;	/* parent of node */
    char		rb_color;	/* color of node */
    union {
	char	rbu_key[0];	/* start of key */
	char	*rbu_key_ptr[0];/* pointer to key */
    } rb_keys;
};

#define RB_BLACK	0	/* This is a black node */
#define RB_RED		1	/* This is a red node */

/*
 * Note that in this tree, all node pointers (except the parent pointer)
 * point to either a legitimate tree node or the nil node stored in
 * the root.  The algorithm for redblack fixup on node deletion requires
 * that it be able to walk up from the nil node to the root, fixing
 * colors and doing rotations as necessary.
 */
struct rbroot_ {
    rbnode	*root;			/* root node */
    rbnode	nil;			/* NIL node for this tree */
    unsigned int	key_offset;		/* offset to key material */
    char	key_via_ptr;		/* key via pointer (really char) */
    char	key_dupes;		/* dupes allowed (really char) */
    _redblack_compare_func compare_fn;
    _redblack_key_match_func key_match_fn;
};

/*
 * _redblack_key
 *
 * Return a pointer to the start of a node's key material.
 */
static inline const char *
_redblack_key (const rbroot *root, rbnode *node)
{
    if (root->key_via_ptr) {
	return(node->rb_keys.rbu_key_ptr[0] + root->key_offset);
    }
    return((char *)node - root->key_offset);
}

/**
 * @brief
 * Checks to see if the tree is empty.
 *
 * @param[in] root
 *     Root of the tree to check
 *
 * @return
 *     @c TRUE if the tree is empty;
 *     @c FALSE otherwise.
 */
static inline char
_redblack_tree_empty (const rbroot *root)
{
    return(root->root == &root->nil);
}

/**
 * @brief
 * Checks to see if the node is null or nil.
 *
 * @param[in] root
 *     Root of the tree
 * @param[in] node
 *     Node to check
 *
 * @return
 *     @c TRUE if the node is null or nil;
 *     @c FALSE otherwise.
 */
static inline char
_redblack_node_null (const rbroot *root, const rbnode *node)
{
    return((node == 0) || (node == &root->nil));
}

/**
 * @brief
 * Retrun the root node of the tree.
 *
 * @param[in] root
 *     Root of the tree
 *
 * @return
 *     A pointer to an @c rcnode structure;
 *     @c NULL if the tree is empty.
 */
static inline rbnode *
_redblack_tree_root (const rbroot *root)
{
    return(root->root);
}

#define rboffset(struct_name, fld_name) (unsigned int)&(((struct_name *)0)->fld_name)

/*
 * Macro to define an inline to map from a rbnode entry back to the
 * containing data structure.
 *
 * This is just a handy way of defining the inline, which will return
 * NULL if the rbnode pointer is NULL, or the enclosing structure
 * if not.
 */
#define RBNODE_TO_STRUCT(procname, structname, fieldname)		\
    static inline structname * procname (rbnode *ptr)			\
    {									\
	if (ptr)							\
	    return((structname *) (((unsigned char *) ptr) -			\
				    rboffset(structname, fieldname)));	\
	return(NULL);							\
    }


void
_redblack_dump (void *fp, rbroot *root, void (*func)(void *, rbnode *, int),
	       int level);


#define ITERATE_RB_TREE_BEGIN(rbrootptr, rbnodeptr)   \
{                                                     \
    rbnode *_next_node = 0;                           \
        for(rbnodeptr = _redblack_find_next(rbrootptr, NULL); rbnodeptr; rbnodeptr = _next_node){   \
                _next_node = _redblack_find_next(rbrootptr, rbnodeptr);

#define ITERATE_RB_TREE_END }}

rbnode * 
_redblack_lookup(rbroot *rbroot, void *key, int (*key_match)(void *, rbnode *));

void
register_rbtree_compare_fn(rbroot *root, _redblack_compare_func compare_fn);

void
register_rbtree_key_match_fn(rbroot *root, _redblack_key_match_func key_match_fn);

#endif	/* !__REDBLACK_H__ */
