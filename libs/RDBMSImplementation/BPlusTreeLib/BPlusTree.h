#ifndef __BPlusTree_H__
#define __BPlusTree_H__

#define MAX_CHILD_NUMBER 4
#include <stdint.h>
#include <stdbool.h>

/*
* This is downloaded from https://github.com/parachvte/B-Plus-Tree
*/

/* key_mdata_t and BPluskey_t now live in the shared storage-engine header so
 * that engines do not have to depend on the B+tree. */
#include "../core/rdbms_ds.h"

typedef struct BPlusTreeNode {
	bool isRoot, isLeaf;
	int key_num;
	BPluskey_t key[MAX_CHILD_NUMBER + 1];
	void* child[MAX_CHILD_NUMBER + 2 ];
	struct BPlusTreeNode* father;
	struct BPlusTreeNode* next;
	struct BPlusTreeNode* last;

} BPlusTreeNode;

typedef int (*BPlusTree_key_com_fn )(BPluskey_t *, BPluskey_t *, key_mdata_t *, int );
typedef int (*BPlusTree_key_format_fn) (BPluskey_t *, unsigned char *, int);
typedef int (*BPlusTree_value_format_fn) (void *, unsigned char *, int);
typedef void (*BPlusTree_value_free_fn) (void *);

typedef struct BPlusTree {

	BPlusTree_key_com_fn comp_fn;
	BPlusTree_key_format_fn key_fmt_fn;
	BPlusTree_value_format_fn value_fmt_fn;
	BPlusTreeNode *Root;
	uint16_t MaxChildNumber;
	BPlusTree_value_free_fn free_fn;
	key_mdata_t *key_mdata;
	int key_mdata_size;

} BPlusTree_t;

extern void BPlusTree_init (BPlusTree_t *, 
							BPlusTree_key_com_fn, 
							BPlusTree_key_format_fn,
							BPlusTree_value_format_fn, uint16_t MaxChildNumber,
							BPlusTree_value_free_fn free_fn,
							key_mdata_t *key_mdata,
							int key_mdata_units
							);

extern void BPlusTree_SetMaxChildNumber(BPlusTree_t *, int);
extern void BPlusTree_Destroy(BPlusTree_t *);
extern bool BPlusTree_Insert(BPlusTree_t *, BPluskey_t *, void*);

extern void* BPlusTree_Query_Key(BPlusTree_t *tree,
				BPluskey_t *key);
				
extern void BPlusTree_Query_Range(BPlusTree_t *, 
								BPluskey_t *, BPluskey_t *);

extern bool  BPlusTree_Modify(
			 BPlusTree_t *,
			 BPluskey_t * key, void* value);

extern bool BPlusTree_Delete(
			 BPlusTree_t *,
			 BPluskey_t *);

#define BPTREE_ITERATE_ALL_RECORDS_BEGIN(BPlusTree_ptr, key_ptr, rec_ptr)	\
	{	\
		int _i;	\
		bool break_ctrl = false;	\
		BPlusTreeNode *_bnode = BPlusTree_ptr->Root; \
		key_ptr = NULL;	\
		rec_ptr = NULL;	 \
		while (_bnode && !_bnode->isLeaf) {	\
        	_bnode = (BPlusTreeNode *)_bnode->child[0];	\
    	}	\
		while (_bnode)	{ \
			for (_i = 0; _i < _bnode->key_num; _i++) {	\
				key_ptr = &_bnode->key[_i];	\
				rec_ptr = _bnode->child[_i];

#define BPTREE_ITERATAION_BREAK	\
	break_ctrl = true;	\
	break;

#define BPTREE_ITERATAION_CONTINUE	\
	continue

#define BPTREE_ITERATE_ALL_RECORDS_END(BPlusTree_ptr, key_ptr, rec_ptr)	\
		} \
		if (break_ctrl) break;	\
		_bnode = _bnode->next;	\
		}}

void *
BPlusTree_get_next_record (BPlusTree_t *, BPlusTreeNode **, int *, BPluskey_t **);

#endif

