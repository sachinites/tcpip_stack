#ifndef __ISIS_SRV6__
#define __ISIS_SRV6__

#include "../../Tree/libtree.h"

typedef struct node_ node_t;
typedef struct ips_srv6_data_ ips_srv6_data_t;

typedef struct isis_srv6_pfx_sid_ {

    avltree_node_t avl_glue;
    ipv6_addr_t prefix; // key
    uint8_t flags;
    uint8_t endfn;

} __attribute__((aligned(8))) isis_srv6_pfx_sid_t;

typedef struct isis_srv6_adj_sid_ {

    avltree_node_t avl_glue;
    ipv6_addr_t prefix; // key
    uint8_t flags;
    uint8_t endfn;

} __attribute__((aligned(8))) isis_srv6_adj_sid_t;

typedef struct isis_srv6_config_ {

    char locator_name[32];
    avltree_t pfxsid_tree;
    avltree_t adj_sid_tree;

}isis_srv6_config_t;

int8_t 
isis_srv6_is_loc_enabled (node_t *node, char *locator_name) ;

isis_srv6_config_t *
isis_srv6_get_config(node_t *node);

void
isis_srv6_new_locator_set (node_t *node, char *loc_name);

void
isis_srv6_locator_unset (node_t *node);

void 
isis_srv6_stop_locator_advertisement (node_t *node);

void
 isis_srv6_stop_adj_sid_advertisement (node_t *node);

void 
isis_srv6_advertise_locator (node_t *node,  ips_srv6_data_t *msg ) ;

void
isis_delete_prefix_sid_from_locator (node_t *node, ips_srv6_data_t *msg) ;

void
isis_add_prefix_sid_to_locator (node_t *node, ips_srv6_data_t *msg);

#endif 