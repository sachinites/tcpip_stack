#ifndef __ISIS_RTR__
#define __ISIS_RTR__

typedef struct isis_pkt_ isis_lsp_pkt_t;

typedef struct isis_timer_data_ {

    node_t *node;
    interface_t *intf;
    void *data;
    size_t data_size;
} isis_timer_data_t;

typedef struct isis_node_info_ {

uint16_t adj_up_count; 
uint32_t seq_no;
isis_lsp_pkt_t *self_lsp_pkt;
/* LSP DB */
avltree_t lspdb_avl_root;
/* Task to schedule self LSP pkt generation */
task_t *lsp_pkt_gen_task;

} isis_node_info_t ;

bool
isis_is_protocol_enable_on_node(node_t *node);

void
 isis_init (node_t *node) ;

void
 isis_de_init (node_t *node) ;

#define ISIS_NODE_INFO(node_ptr)    \
    ((isis_node_info_t *)(node_ptr->node_nw_prop.isis_node_info))

#define ISIS_INCREMENT_NODE_STATS(node_ptr, field)  \
    (ISIS_NODE_INFO(node_ptr))->field++;

#define ISIS_DECREMENT_NODE_STATS(node_ptr, field)  \
    (ISIS_NODE_INFO(node_ptr))->field--;
    
 void
 isis_show_node_protocol_state(node_t *node);

#endif