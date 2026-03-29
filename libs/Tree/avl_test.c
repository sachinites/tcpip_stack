#include <stdio.h>
#include <stdlib.h>
#include "libtree.h"

/* This is the simple example which shows the usage of AVL
 * tree. Refer to this example and use this AVL tree library in
 * your code the same way */

 /* To compile and run :
 *  gcc -g -c avl_test.c -o avl_test.o
 *  gcc -g -c avl.c -o avl.o
 *  gcc -g avl_test.o avl.o -o avl_test.exe
 *  Run : ./avl_test.exe 
 * */

/* Sample data structure. Your Data Structure must have AVL node as
 * a member. This is called embedded avl node. Your application
 * objects (complex_t) will be inserted into AVL tree using this
 * embedded node */
typedef struct complex_{

    int a;
    int b;
    avltree_node_t avl_node; /* Embedded node */
} complex_t;

/* For each AVL tree, your need to write comparison function which
 * returns -1 , 1 or 0 based on the comparison. The fn accepts two args
 * of type avltree_node_t which are embedded avl nodes inside application
 * objects. Use avltree_container_of to retrieve original application
 * objects
 * _c1_new - new node which is to be inserted into avl tree, or dummy node
 * containing key for lookup operation
 * _c1_existing - AVL node already present in avl tree
 * */
int
compare_complex_no(const avltree_node_t *_c1_new, const avltree_node_t *_c2_existing){

    complex_t *c1,*c2;

    c1 = avltree_container_of(_c1_new, complex_t, avl_node);
    c2 = avltree_container_of(_c2_existing, complex_t, avl_node);
    
    if((c1->a *c1->a + c1->b*c1->b) < 
            (c2->a *c2->a + c2->b*c2->b)){
        return -1;   
    }
    if((c1->a *c1->a + c1->b*c1->b) > 
            (c2->a *c2->a + c2->b*c2->b)){
        return 1;   
    }
    return 0;
}

int
main(int argc, char **argv){

	/* Take the root of the AVL tree, you can also malloc
 	 * it if you dont want to take it as local variable*/
    avltree_t avl_root;

	/* Initialize the AVL tree.*/
	avltree_init(&avl_root, compare_complex_no);
	
	/* Now AVL tree is ready for insertion/deletion */

	/* Let us insert three complex numbers into AVL tree */
    complex_t c1 ;
    c1.a = 10;
    c1.b = 5;
    complex_t c2 ;
    c2.a = 1;
    c2.b = 5;
    complex_t c3 ;
    c3.a = 7;
    c3.b = 5;
	/* To insert application objects into AVL tree, pass
 	 * the embedded avl node as an arg. The comparison fn
 	 * takes care to insert the application objects into 
 	 * AVL tree in required order*/
	avltree_insert(&c1.avl_node, &avl_root);
	avltree_insert(&c2.avl_node, &avl_root);
	avltree_insert(&c3.avl_node, &avl_root);

	/* Let me show you how to Iterate over the avl tree */

	/* Take the cursor variable which should be of type avltree_node_t * */
    avltree_node_t *curr = NULL;

    ITERATE_AVL_TREE_BEGIN(&avl_root, curr){

		/* use avltree_container_of to get the original object from
  		 * the embedded node */
        complex_t *c = avltree_container_of(curr, complex_t, avl_node);
        printf("a = %d, b = %d\n", c->a, c->b);

    } ITERATE_AVL_TREE_END;

	/* How to look up the particular node from AVL tree */

	/* Take dummy object and fill only the keys */
	complex_t key = { 7 , 5 , {0}}; 
	complex_t *result;
	avltree_node_t *result_node;

	/* The comparison fn will search the matching node in
 	 * AVL tree based on key passed as Ist arg */
	result_node = avltree_lookup(&key.avl_node, &avl_root);

	if(result_node){
		result = avltree_container_of(result_node, complex_t, avl_node);
    	printf("look up result = a,b = %d,%d\n", result->a, result->b);	
	}
	else{
		printf("look up key Not found\n");
	}

	/* Check whether AVL tree is empty or not */
	if (avltree_is_empty(&avl_root)){
        printf("AVL tree is Empty\n");
	}

	/* This is how we delete all nodes of AVL tree. It is upto
 	   user to free application data. Not applicable here since
	   all complex numbers we inserted into AVL tree were stack variables
	 */
	ITERATE_AVL_TREE_BEGIN(&avl_root, curr){
		complex_t *c = avltree_container_of(curr, complex_t, avl_node);
		/* Ist remove the node from AVL tree and then bother to free it */
		avltree_remove(curr, &avl_root);
		//free(c);  /* Not applicable here */
	} ITERATE_AVL_TREE_END;
	
	if (avltree_is_empty(&avl_root)){
        printf("AVL Tree Deleted\n");
	}

    ITERATE_AVL_TREE_BEGIN(&avl_root, curr){

        complex_t *c = avltree_container_of(curr, complex_t, avl_node);
        printf("a = %d, b = %d\n", c->a, c->b);
    } ITERATE_AVL_TREE_END;

	/* Free the root of the AVL tree if you had malloc'd it. 
 	 * Not applicable in our case as root was local stack variable*/
    return 0;
}
