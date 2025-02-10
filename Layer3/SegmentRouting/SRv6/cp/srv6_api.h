#ifndef __SRV6_API__
#define __SRV6_API__

#include <stdbool.h>
typedef struct node_ node_t;

#define SRV6_NODE_INFO(node_ptr) \
    (node_ptr->node_nw_prop.srv6_node_info)

bool 
srv6_is_enable (node_t *node);

void 
srv6_init (node_t *node);

void 
srv6_de_init (node_t *node);

uint32_t 
srv6_delete_all_pfx_sids (node_t *node) ;

uint32_t 
srv6_delete_all_adj_sids (node_t *node) ;

#endif 