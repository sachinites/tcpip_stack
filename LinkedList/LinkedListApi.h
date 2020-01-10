#ifndef __LINKEDLIST__
#define __LINKEDLIST__


#define GET_HEAD_SINGLY_LL(ll) (ll->head)
#define INC_NODE_COUNT_SINGLY_LL(ll) (ll->node_count++)
#define DEC_NODE_COUNT_SINGLY_LL(ll) (ll->node_count--)
#define GET_NODE_COUNT_SINGLY_LL(ll) (ll->node_count)
#define GET_NEXT_NODE_SINGLY_LL(node) (node->next)

typedef enum{
    LL_FALSE,
    LL_TRUE
} bool_t;

typedef struct LL_Node{
    void *data;
    struct LL_Node *next;
} singly_ll_node_t;

typedef struct LL{
    unsigned int node_count;
    singly_ll_node_t *head;
    int (*comparison_fn)(void*, void *);
    int (*order_comparison_fn)(void *, void *);
} ll_t;

ll_t* init_singly_ll();
singly_ll_node_t* singly_ll_init_node(void* data);
int singly_ll_add_node(ll_t *ll, singly_ll_node_t *node);
int singly_ll_add_node_by_val(ll_t *ll, void* data);
int singly_ll_remove_node(ll_t *ll, singly_ll_node_t *node);
unsigned int singly_ll_remove_node_by_value(ll_t *ll, void* data, int size);
bool_t is_singly_ll_empty(ll_t *ll);
void print_singly_LL(ll_t *ll);
void reverse_singly_ll(ll_t *ll);
void delete_singly_ll(ll_t *ll);
int singly_ll_delete_node(ll_t *ll, singly_ll_node_t *node);
unsigned int singly_ll_delete_node_by_value(ll_t *ll, void *data, int size);
singly_ll_node_t *singly_ll_get_node_by_data_ptr(ll_t *ll, void *data);
void singly_ll_delete_node_by_data_ptr(ll_t *ll, void *data);
unsigned int singly_ll_remove_node_by_dataptr(ll_t *ll, void *data);
void singly_ll_set_comparison_fn(ll_t *ll, int (*comparison_fn)(void *, void *));
void singly_ll_set_order_comparison_fn(ll_t *ll, int (*order_comparison_fn)(void *, void *));
void * singly_ll_search_by_key(ll_t *ll, void *key);
void copy_singly_ll(ll_t *src, ll_t *dst);
ll_t * union_singly_ll(ll_t *list1, ll_t *list2);
void singly_ll_delete_data_by_key(ll_t *list, void *key);
void singly_ll_add_ordered_data(ll_t *ll, void *data);

#define ITERATE_LIST_BEGIN(list_ptr, node_ptr)                              \
    {                                                                       \
    singly_ll_node_t *_node_ptr = NULL;                                     \
    node_ptr = GET_HEAD_SINGLY_LL(list_ptr);                                \
    for(; node_ptr!= NULL; node_ptr = _node_ptr){                           \
        _node_ptr = node_ptr->next; 

#define ITERATE_LIST_END  }} 

/* delete safe loop*/
#define ITERATE_LIST_BEGIN2(list_ptr, node_ptr, prev)                       \
    {                                                                       \
    singly_ll_node_t *_node_ptr = NULL; prev = NULL;                        \
    node_ptr = GET_HEAD_SINGLY_LL(list_ptr);                                \
    for(; node_ptr!= NULL; node_ptr = _node_ptr){                           \
        _node_ptr = node_ptr->next; 
         
#define ITERATE_LIST_CONTINUE2(list_ptr, node_ptr, prev)    \
         {if(node_ptr) prev = node_ptr;                     \
         continue;}
            
#define ITERATE_LIST_BREAK2(list_ptr, node_ptr, prev)       \
         break

#define ITERATIVE_LIST_NODE_DELETE2(list_ptr, node_ptr, prev)   \
        {if(node_ptr && prev == NULL){                          \
            list_ptr->head = node_ptr->next;                    \
        }                                                       \
        else if(node_ptr && prev){                              \
            prev->next = node_ptr->next;                        \
        }                                                       \
        free(node_ptr);                                         \
        list_ptr->node_count--;                                 \
        node_ptr = NULL;}
            
#define ITERATE_LIST_END2(list_ptr, node_ptr, prev)   \
             if(node_ptr) prev = node_ptr; }} 

#define LL_LESS_THAN(listptr, data1ptr, data2ptr)      \
    (listptr->order_comparison_fn(data1ptr, data2ptr) == -1)

#define LL_GREATER_THAN(listptr, data1ptr, data2ptr)   \
    (listptr->order_comparison_fn(data1ptr, data2ptr) == 1)

#define LL_EQUAL(listptr, data1ptr, data2ptr)          \
    (listptr->order_comparison_fn(data1ptr, data2ptr) == 0)

#endif
