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

void
srv6_local_sid_config_post_processing (
            node_t *node,
            ipv6_addr_t *sid,
            uint8_t prefix_len,
            Srv6_endpcode_t endfn,
            uint8_t flavor,
            ipv6_addr_t *gw,
            Interface *oif, 
            uint32_t metric,
            uint32_t minor_code);

void
srv6_local_sid_unconfig_pre_processing (
            node_t *node,
            ipv6_addr_t *sid,
            uint8_t prefix_len,
            Srv6_endpcode_t endfn,
            uint8_t flavor,
            ipv6_addr_t *gw,
            Interface *oif, 
            uint32_t minor_code) ;

uint32_t 
srv6_delete_all_pfx_sids (node_t *node) ;

uint32_t 
srv6_delete_all_adj_sids (node_t *node) ;

#endif 