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

void 
External_srv6_import_locator_config (
        node_t *node,
        const char *loc_name, 
        ipv6_addr_t *prefix, 
        uint8_t *prefix_len,
        uint32_t *metric,
        uint16_t *mt_id,
        uint8_t *algorithm,
        uint8_t *flags);

#endif 