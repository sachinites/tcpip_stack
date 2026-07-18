
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include <time.h>
#include "BPlusTree.h"

int QueryAnsNum;

/** Create a new B+tree Node */
BPlusTreeNode* New_BPlusTreeNode() {
	struct BPlusTreeNode* p = (struct BPlusTreeNode*)calloc(1, sizeof(struct BPlusTreeNode));
	return p;
}

void BPlusTree_init (BPlusTree_t *tree, 
							BPlusTree_key_com_fn comp_fn, 
							BPlusTree_key_format_fn key_fmt_fn,
							BPlusTree_value_format_fn value_fmt_fn,
							uint16_t MaxChildNumber, // not used
							BPlusTree_value_free_fn free_fn,
							key_mdata_t *key_mdata,
							int key_mdata_units
							) {

	tree->Root = New_BPlusTreeNode();
	tree->Root->isRoot = true;
	tree->Root->isLeaf = true;
	tree->comp_fn = comp_fn;
	tree->key_fmt_fn = key_fmt_fn;
	tree->value_fmt_fn = value_fmt_fn;
	tree->MaxChildNumber = MAX_CHILD_NUMBER;
	tree->free_fn = free_fn ? free_fn : free;
	tree->key_mdata = key_mdata;
	tree->key_mdata_size = key_mdata_units;
}

/** Binary search to find the biggest child l that Cur->key[l] <= key */
static int Binary_Search(BPlusTree_t *tree,
										BPlusTreeNode* Cur, 
										BPluskey_t *key) {

	int l = 0, r = Cur->key_num;
	if (tree->comp_fn (key, &Cur->key[l], tree->key_mdata, tree->key_mdata_size) > 0) return l;
	if (r == 0) return 0;
	if (tree->comp_fn(&Cur->key[r - 1], key, tree->key_mdata, tree->key_mdata_size) >= 0) return r - 1;
	while (l < r - 1) {
		int mid = (l + r) >> 1;
		if (tree->comp_fn(&Cur->key[mid], key, tree->key_mdata, tree->key_mdata_size) < 0)
			r = mid;
		else
			l = mid;
	}
	return l;
}

/**
 * Cur(MaxChildNumber) split into two part:
 *	(1) Cur(0 .. Mid - 1) with original key
 *	(2) Temp(Mid .. MaxChildNumber) with key[Mid]
 * where Mid = MaxChildNumber / 2
 * Note that only when Split() is called, a new Node is created
 */
void Insert(BPlusTree_t *tree, 
				  BPlusTreeNode* Cur, 
				  BPluskey_t *key,
				  void* value);

void Split(BPlusTree_t *tree, BPlusTreeNode* Cur) {
	// copy Cur(Mid .. MaxChildNumber) -> Temp(0 .. Temp->key_num)
	BPlusTreeNode* Temp = New_BPlusTreeNode();
	BPlusTreeNode* ch;
	int Mid = tree->MaxChildNumber >> 1;
	Temp->isLeaf = Cur->isLeaf; // Temp's depth == Cur's depth
	Temp->key_num = tree->MaxChildNumber - Mid;
	int i;
	for (i = Mid; i < tree->MaxChildNumber; i++) {
		Temp->child[i - Mid] = Cur->child[i];
		Temp->key[i - Mid] = Cur->key[i];
		if (Temp->isLeaf) {

		} else {
			ch = (BPlusTreeNode*)Temp->child[i - Mid];
			ch->father = Temp;
		}
	}
	// Change Cur
	Cur->key_num = Mid;
	// Insert Temp
	if (Cur->isRoot) {
		// Create a new Root, the depth of Tree is increased
		tree->Root = New_BPlusTreeNode();
		tree->Root->key_num = 2;
		tree->Root->isRoot = true;
		tree->Root->key[0] = Cur->key[0];
		tree->Root->child[0] = Cur;
		tree->Root->key[1] = Temp->key[0];
		tree->Root->child[1] = Temp;
		Cur->father = Temp->father = tree->Root;
		Cur->isRoot = false;
		if (Cur->isLeaf) {
			Cur->next = Temp;
			Temp->last = Cur;
		}
	} else {
		// Try to insert Temp to Cur->father
		Temp->father = Cur->father;
		Insert(tree, Cur->father, &Cur->key[Mid],  (void*)Temp);
	}
}

/** Insert (key, value) into Cur, if Cur is full, then split it to fit the definition of B+tree */
void Insert(BPlusTree_t *tree, 
				  BPlusTreeNode* Cur, 
				  BPluskey_t *key,
				  void* value) {

	int i, ins;
	if (Cur->key_num == 0) ins = 0;
	else if (tree->comp_fn (key, &Cur->key[0], tree->key_mdata, tree->key_mdata_size) > 0) ins = 0;
	else ins = Binary_Search(tree, Cur, key) + 1;
	for (i = Cur->key_num; i > ins; i--) {
		Cur->key[i] = Cur->key[i - 1];
		Cur->child[i] = Cur->child[i - 1];
	}
	Cur->key_num++;
	Cur->key[ins] = *key;
	Cur->child[ins] = value;
	if (Cur->isLeaf == false) { // make links on leaves
		BPlusTreeNode* firstChild = (BPlusTreeNode*)(Cur->child[0]);
		if (firstChild->isLeaf == true) { // which means value is also a leaf as child[0]	
			BPlusTreeNode* temp = (BPlusTreeNode*)(value);
			if (ins > 0) {
				BPlusTreeNode* prevChild;
				BPlusTreeNode* succChild;
				prevChild = (BPlusTreeNode*)Cur->child[ins - 1];
				succChild = prevChild->next;
				prevChild->next = temp;
				temp->next = succChild;
				temp->last = prevChild;
				if (succChild != NULL) succChild->last = temp;
			} else {
				// do not have a prevChild, then refer next directly
				// updated: the very first record on B+tree, and will not come to this case
				temp->next = Cur->child[1];
			}
		}
	}
	if (Cur->key_num == tree->MaxChildNumber) // children is full
		Split(tree, Cur);
}

/** Resort(Give, Get) make their no. of children average */
void Resort(BPlusTreeNode* Left, BPlusTreeNode* Right) {
	int total = Left->key_num + Right->key_num;
	BPlusTreeNode* temp;
	if (Left->key_num < Right->key_num) {
		int leftSize = total >> 1;
		int i = 0, j = 0;
		while (Left->key_num < leftSize) {
			Left->key[Left->key_num] = Right->key[i];
			Left->child[Left->key_num] = Right->child[i];
			if (Left->isLeaf) {

			} else {
				temp = (BPlusTreeNode*)(Right->child[i]);
				temp->father = Left;
			}
			Left->key_num++;
			i++;
		}
		while (i < Right->key_num) {
			Right->key[j] = Right->key[i];
			Right->child[j] = Right->child[i];
			i++;
			j++;
		}
		Right->key_num = j; 
	} else {
		int leftSize = total >> 1;
		int i, move = Left->key_num - leftSize, j = 0;
		for (i = Right->key_num - 1; i >= 0; i--) {
			Right->key[i + move] = Right->key[i];
			Right->child[i + move] = Right->child[i];
		}
		for (i = leftSize; i < Left->key_num; i++) {
			Right->key[j] = Left->key[i];
			Right->child[j] = Left->child[i];
			if (Right->isLeaf) {

			} else {
				temp = (BPlusTreeNode*)Left->child[i];
				temp->father = Right;
			}
			j++;
		}
		Left->key_num = leftSize;
		Right->key_num = total - leftSize;
	}
}

/**
 * Redistribute Cur, using following strategy:
 * (1) resort with right brother
 * (2) resort with left brother
 * (3) merge with right brother
 * (4) merge with left brother
 * in that case root has only one child, set this chil to be root
 */

void Delete(BPlusTree_t *tree, 
					BPlusTreeNode* Cur,
					BPluskey_t *key);

void Redistribute(BPlusTree_t *tree, BPlusTreeNode* Cur) {
	if (Cur->isRoot) {
		if (Cur->key_num == 1 && !Cur->isLeaf) {
			tree->Root = Cur->child[0];
			tree->Root->isRoot = true;
			free(Cur);
		}
		return;
	}
	BPlusTreeNode* Father = Cur->father;
	BPlusTreeNode* prevChild;
	BPlusTreeNode* succChild;
	BPlusTreeNode* temp;
	int my_index = Binary_Search(tree, Father, &Cur->key[0]);
	if (my_index + 1 < Father->key_num) {
		succChild = Father->child[my_index + 1];
		if ((succChild->key_num - 1) * 2 >= tree->MaxChildNumber) { // at least can move one child to Cur
			Resort(Cur, succChild); // (1) resort with right child
			Father->key[my_index + 1] = succChild->key[0];
			return;
		}
	}
	if (my_index - 1 >= 0) {
		prevChild = Father->child[my_index - 1];
		if ((prevChild->key_num - 1) * 2 >= tree->MaxChildNumber) {
			Resort(prevChild, Cur); // (2) resort with left child
			Father->key[my_index] = Cur->key[0];
			return;
		}
	}
	if (my_index + 1 < Father->key_num) { // (3) merge with right child
		int i = 0;
		while (i < succChild->key_num) {
			Cur->key[Cur->key_num] = succChild->key[i];
			Cur->child[Cur->key_num] = succChild->child[i];
			if (Cur->isLeaf) {

			} else {
				temp = (BPlusTreeNode*)(succChild->child[i]);
				temp->father = Cur;
			}
			Cur->key_num++;
			i++;
		}
		Delete(tree, Father, &succChild->key[0]); // delete right child
		return;
	}
	if (my_index - 1 >= 0) { // (4) merge with left child
		int i = 0;
		while (i < Cur->key_num) {
			prevChild->key[prevChild->key_num] = Cur->key[i];
			prevChild->child[prevChild->key_num] = Cur->child[i];
			if (Cur->isLeaf) {

			} else {
				temp = (BPlusTreeNode*)(Cur->child[i]);
				temp->father = prevChild;
			}
			prevChild->key_num++;
			i++;
		}
		Delete(tree, Father, &Cur->key[0]); // delete left child
		return;
	}
}

/** Delete key from Cur, if no. of children < MaxChildNUmber / 2, resort or merge it with brothers */
void Delete(BPlusTree_t *tree, 
					BPlusTreeNode* Cur,
					BPluskey_t *key) {

	int i, del = Binary_Search(tree, Cur, key);
	void* delChild = Cur->child[del];

	for (i = del; i < Cur->key_num - 1; i++) {
		Cur->key[i] = Cur->key[i + 1];
		Cur->child[i] = Cur->child[i + 1];
	}
	Cur->key_num--;
	if (Cur->isLeaf == false) { // make links on leaves
		BPlusTreeNode* firstChild = (BPlusTreeNode*)(Cur->child[0]);
		if (firstChild->isLeaf == true) { // which means delChild is also a leaf
			BPlusTreeNode* temp = (BPlusTreeNode*)delChild;
			BPlusTreeNode* prevChild = temp->last;
			BPlusTreeNode* succChild = temp->next;
			if (prevChild != NULL) prevChild->next = succChild;
			if (succChild != NULL) succChild->last = prevChild;
		}
	}
	if (del == 0 && !Cur->isRoot) { // some fathers' key should be changed
		BPlusTreeNode* temp = Cur;
		while (!temp->isRoot && temp == temp->father->child[0]) {
			temp->father->key[0] = Cur->key[0];
			temp = temp->father;
		}
		if (!temp->isRoot) {
			temp = temp->father;
			int i = Binary_Search(tree, temp, key);
			temp->key[i] = Cur->key[0];
		}
	}
	tree->free_fn(delChild);
	if (Cur->key_num * 2 < tree->MaxChildNumber)
		Redistribute(tree, Cur);
}

/** Find a leaf node that key lays in it
 *	modify indicates whether key should affect the tree
 */
BPlusTreeNode* Find(BPlusTree_t *tree, BPluskey_t *key, int modify) {
	BPlusTreeNode* Cur = tree->Root;
	if (!Cur) return NULL;
	while (1) {
		if (Cur->isLeaf == true)
			break;
		if (tree->comp_fn (key, &Cur->key[0], tree->key_mdata, tree->key_mdata_size) > 0) {
			if (modify == true) Cur->key[0] = *key;
			Cur = Cur->child[0];
		} else {
			int i = Binary_Search(tree, Cur, key);
			Cur = Cur->child[i];
		}
	}
	return Cur;
}

/** Destroy subtree whose root is Cur, By recursion */
void Destroy(BPlusTreeNode* Cur, BPlusTree_value_free_fn free_fn) {
	if (Cur->isLeaf == true) {
		int i;
		for (i = 0; i < Cur->key_num; i++) {
			free(Cur->key[i].key);
			Cur->key[i].key_size = 0;
			free_fn(Cur->child[i]);
			Cur->child[i] = NULL;
		}
	} else {
		int i;
		for (i = 0; i < Cur->key_num; i++)
			Destroy(Cur->child[i], free_fn);
	}
	free(Cur);
}

/** Print subtree whose root is Cur */
#if 0
void Print(BPlusTreeNode* Cur) {
	int i;
	for (i = 0; i < Cur->key_num; i++)
		printf("%d ", Cur->key[i]);
	printf("\n");
	if (!Cur->isLeaf) {
		for (i = 0; i < Cur->key_num; i++)
			Print(Cur->child[i]);
	}
}
#endif 

/** Interface: Insert (key, value) into B+tree */
bool
BPlusTree_Insert(BPlusTree_t *tree, BPluskey_t *key, void* value) {

	BPlusTreeNode* Leaf = Find(tree, key, true);
	int i = Binary_Search(tree, Leaf, key);
	if (tree->comp_fn (&Leaf->key[i], key, tree->key_mdata, tree->key_mdata_size ) == 0) return false;
	Insert(tree, Leaf, key, value);
	return true;
}

/** Interface: query all record whose key satisfy that key = query_key */
void* BPlusTree_Query_Key(BPlusTree_t *tree,
											  BPluskey_t *key) {

  	unsigned char key_output_buffer [128];
	unsigned char value_output_buffer [128];

	BPlusTreeNode* Leaf = Find(tree, key, false);
	if (!Leaf) return NULL;
	QueryAnsNum = 0;
	int i;
	for (i = 0; i < Leaf->key_num; i++) {
		//printf("%d ", Leaf->key[i]);
		if (tree->comp_fn (&Leaf->key[i], key, tree->key_mdata, tree->key_mdata_size) == 0) {
			QueryAnsNum++;
			if (0 && QueryAnsNum < 20) {
				tree->key_fmt_fn (&Leaf->key[i], key_output_buffer, sizeof (key_output_buffer));
				tree->value_fmt_fn ((void *)Leaf->child[i], value_output_buffer, sizeof(value_output_buffer));
			}
			return (void *)Leaf->child[i];
		}
	}
	//printf("Total number of answers is: %d\n", QueryAnsNum);
	return NULL;
}

/** Interface: query all record whose key satisfy that query_l <= key <= query_r */
void BPlusTree_Query_Range(
								BPlusTree_t *tree,
								BPluskey_t *l, BPluskey_t *r) {

	unsigned char key_output_buffer [128];
	unsigned char value_output_buffer [128];

	BPlusTreeNode* Leaf = Find(tree, l, false);
	QueryAnsNum = 0;
	int i;
	for (i = 0; i < Leaf->key_num; i++) {
		if (tree->comp_fn (&Leaf->key[i], l, tree->key_mdata, tree->key_mdata_size) <= 0) break;
	}
	int finish = false;
	while (!finish) {
		while (i < Leaf->key_num) {
			if (tree->comp_fn (&Leaf->key[i], r, tree->key_mdata, tree->key_mdata_size) < 0) {
				finish = true;
				break;
			}
			QueryAnsNum++;
			if (QueryAnsNum == 20) printf("...\n");
			if (QueryAnsNum < 20) {
				tree->key_fmt_fn (&Leaf->key[i], key_output_buffer, sizeof (key_output_buffer));
				tree->value_fmt_fn ((void *)Leaf->child[i], value_output_buffer, sizeof(value_output_buffer));
				printf("[no.%d	key = %s, value = %s]\n", 
					QueryAnsNum, key_output_buffer, value_output_buffer);
			}
			i++;
		}
		if (finish || Leaf->next == NULL) break;
		Leaf = Leaf->next;
		i = 0;
	}
	printf("Total number of answers is: %d\n", QueryAnsNum);
}

/** Interface: modify value on the given key */
bool BPlusTree_Modify(BPlusTree_t *tree,
			 BPluskey_t * key, void* value) {

	unsigned char key_output_buffer [128];
	unsigned char orig_value_output_buffer [128];
	unsigned char new_value_output_buffer [128];

	BPlusTreeNode* Leaf = Find(tree, key, false);
	int i = Binary_Search(tree, Leaf, key);
	if (tree->comp_fn (&Leaf->key[i], key, tree->key_mdata, tree->key_mdata_size) != 0) return false; // don't have this key
	free(Leaf->child[i]);
	Leaf->child[i] = value;
	return true;
}

/** Interface: delete value on the given key */
bool BPlusTree_Delete(BPlusTree_t *tree,
			 BPluskey_t *key) {

	unsigned char key_output_buffer [128];
	unsigned char value_output_buffer [128];

	BPlusTreeNode* Leaf = Find(tree, key, false);
	int i = Binary_Search(tree, Leaf, key);
	if (tree->comp_fn (&Leaf->key[i], key, tree->key_mdata, tree->key_mdata_size) != 0) return false; // don't have this key
	if (0 && tree->key_fmt_fn && tree->value_fmt_fn) {
		tree->key_fmt_fn (key, key_output_buffer , sizeof (key_output_buffer ));
		tree->value_fmt_fn ((void *)Leaf->child[i], value_output_buffer, sizeof (value_output_buffer) );
	}
	void *key_to_free = Leaf->key[i].key;
   	Delete(tree, Leaf, key); 
	free(key_to_free);
	return true;
}

/** Interface: Called to destroy the B+tree */
void BPlusTree_Destroy(BPlusTree_t *tree) {
	if (tree->Root == NULL) return;
	Destroy(tree->Root, tree->free_fn);
	tree->Root = NULL;
}

/**
 * Interface: setting MaxChildNumber in your program
 * A suggest value is cube root of the no. of records
 */
void BPlusTree_SetMaxChildNumber(BPlusTree_t *tree, int number) {
	tree->MaxChildNumber = number + 1;
}

void *
BPlusTree_get_next_record (BPlusTree_t *bptree, 
												BPlusTreeNode **bnode, int *index,
												BPluskey_t **bpkey_out) {

	BPluskey_t *_key;
	void* _rec;

	*bpkey_out = NULL;

	if (!bptree || !bptree->Root) return NULL;

	/* Fetching the first record */
	if (*bnode == NULL) {

		BPTREE_ITERATE_ALL_RECORDS_BEGIN (bptree, _key, _rec) {

			*index = 0;
			*bnode = _bnode;
			*bpkey_out = _key;
			return _bnode->child[*index];

		}  BPTREE_ITERATE_ALL_RECORDS_END(bptree, _key, _rec)
	}

	/* Empty BPlus tree*/
	if (*bnode == NULL) return NULL;

	/* Subsequent fetch*/
	(*index)++;
	if (*index < (*bnode)->key_num) {
		*bpkey_out = &((*bnode)->key[*index]);
		return (*bnode)->child[*index];
	}

	*index = 0;
	*bnode = (*bnode)->next;

	if (*bnode) {
		*bpkey_out = &((*bnode)->key[*index]);
		return (*bnode)->child[*index];
	}

	*index = 0;
	return NULL;
}