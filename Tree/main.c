#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#define stepspace  4

static int compare_int(void* left, void* right);
static void print_tree(rbtree t);
static void print_tree_helper(rbtree_node n, int step);

int compare_int(void* leftp, void* rightp) {
    int left = (int)leftp;
    int right = (int)rightp;
    if (left < right) 
        return -1;
    else if (left > right)
        return 1;
    else {
        assert (left == right);
        return 0;
    }
}


void print_tree_helper(rbtree_node n, int step);

void print_tree(rbtree t) {
    print_tree_helper(t->root, 0);
    puts("");
}

void print_tree_helper(rbtree_node n, int step) {
    int i;
    if (n == NULL) {
        fputs("<empty tree>", stdout);
        return;
    }
    if (n->right != NULL) {
        print_tree_helper(n->right, step + stepspace);
    }
    for(i=0; i<step; i++)
        fputs(" ", stdout);
    if (n->color == BLACK)
        printf("%d\n", (int)n->key);
    else
        printf("<%d>\n", (int)n->key);
    if (n->left != NULL) {
        print_tree_helper(n->left, step + stepspace);
    }
}


preorder(struct rbtree_node_t *ptr)
{
	rbtree t;
        if(t==NULL)     {       printf("Tree is empty");
                                return;
                        }
        if(ptr!=NULL)   {       printf("%d -> ",(int)ptr->key);
                                preorder(ptr->left);
                                preorder(ptr->right);
                        }
}

inorder(struct rbtree_node_t *ptr)
{
        rbtree t;
        if(t==NULL)     {       printf("Tree is empty");
                                return;
                        }
        if(ptr!=NULL)   {       inorder(ptr->left);
				printf("%d -> ",(int)ptr->key);
                                inorder(ptr->right);
                        }
}


postorder(struct rbtree_node_t *ptr)
{
        rbtree t;
        if(t==NULL)     {       printf("Tree is empty");
                                return;
                        }
        if(ptr!=NULL)   {       postorder(ptr->left);
                                postorder(ptr->right);
				printf("%d -> ",(int)ptr->key);
                        }
}



main()
{
    int i,j, x;
    rbtree t = rbtree_create();
    print_tree(t);
while(1){
printf("\nWhat do u want to do??\n");
printf("1.Insert\n");
printf("2.Delete\n");
printf("3.Display the Tree\n");
printf("4.Inorder Tree\n");
printf("5.Preorder Tree\n");
printf("6.Postorder Tree\n");
printf("7.Exit\n");
printf("8. Iterate tree\n");
printf("9. Delete rbtree\n");
printf("Enter your choice:");
scanf("%d",&j);
switch(j)
{
	case 1:
		printf("\nEnter The data tobe Inserted:");
		scanf("%d",&x);
		printf("\n___________Inserting___________\n\n");
		rbtree_insert(t, (void*)x, compare_int);
		break;
	case 2:
		printf("\nEnter The data tobe Deleted:");
		scanf("%d",&x);
		rbtree_delete(t,(void*)x,compare_int);
		break;
	case 3:
		print_tree(t);
		break;
	case 4:
		printf("\n");
		inorder(t->root);
		printf("\n");
		break;
	case 5:
		printf("\n");
		preorder(t->root);
		printf("\n");
		break;
	case 6:
		printf("\n");
		postorder(t->root);
		printf("\n");
		break;		
	case 7:
		printf("\nExiting......");
		exit(1);
		break;
    case 8:{
        printf("\nIterarate rb tree\n");
            node curr;
            ITERATE_RB_TREE_BEGIN(t, curr){
                int n = (int)curr->key;
                printf("%d --> ", n) ;
            } ITERATE_RB_TREE_END;
            break;
        }
    case 9:
        printf("\nDeleteing rb tree\n");
        rbtree_flush(t);
        break;
	default:
		printf("Please Enter a valid number!!\n");
		break;
}
}
}
