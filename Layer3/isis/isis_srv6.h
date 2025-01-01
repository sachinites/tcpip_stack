#ifndef __ISIS_SRV6__
#define __ISIS_SRV6__

#include "../../Tree/libtree.h"

typedef struct node_ node_t;
typedef struct ips_srv6_data_ ips_srv6_data_t;


typedef struct isis_srv6_locator_ {

    /* Advertise the loc in IPV6 REACH TLV*/
    isis_adv_data_t *loc_adv_tlv236;
    /* Advertise the locator in MT TLV 237*/
    isis_adv_data_t *loc_adv_tlv237;
    /* Advertise the locator in Locator TLV 27*/
    glthread_t adv_data_list_head;

    char locator_name[32];
    ipv6_addr_t prefix;
    uint32_t metric;
    uint16_t mt_id;
    uint8_t flags;
    uint8_t algorithm;
    uint8_t prefix_len;
    
    char padding[7];

} __attribute__((aligned(8)))  isis_srv6_locator_t;

typedef struct isis_srv6_pfx_sid_ {

    isis_adv_data_t *adv_data;
    avltree_node_t avl_glue;
    ipv6_addr_t prefix; // key
    uint8_t flags;
    uint8_t endfn;

} __attribute__((aligned(8))) isis_srv6_pfx_sid_t;

typedef struct isis_srv6_adj_sid_ {

     isis_adv_data_t *adv_data;
    avltree_node_t avl_glue;
    ipv6_addr_t prefix; // key
    uint8_t flags;
    uint8_t endfn;

} __attribute__((aligned(8))) isis_srv6_adj_sid_t;


typedef struct isis_srv6_config_ {

    isis_srv6_locator_t loc;
    avltree_t pfxsid_tree;
    avltree_t adj_sid_tree;

} __attribute__((aligned(8))) isis_srv6_config_t;

#define ISIS_SRV6_LOC(node_ptr) \   
    (&(ISIS_NODE_INFO(node_ptr)->srv6_config->loc))

int8_t 
isis_srv6_is_loc_enabled (node_t *node, char *locator_name) ;

isis_srv6_config_t *
isis_srv6_get_config(node_t *node);

void
isis_srv6_new_locator_set (node_t *node, char *loc_name);

void
isis_srv6_locator_unset (node_t *node);

/* Locator Advertisement Mgmt Fns */
void 
isis_advertise_locator_ipv6_reachability_tlv236 (
                        node_t *node, 
                        isis_srv6_locator_t *loc) ;

void 
isis_withdraw_locator_ipv6_reachability_tlv236 (
                        node_t *node, 
                        isis_srv6_locator_t *loc) ;

void 
isis_advertise_locator_ipv6_reachability_mt_tlv237 (
                        node_t *node, 
                        isis_srv6_locator_t *loc) ;

void 
isis_withdraw_locator_ipv6_reachability_mt_tlv237 (
                        node_t *node, 
                        isis_srv6_locator_t *loc) ;

isis_adv_data_t *
isis_advertise_locator_tlv27_instance (node_t *node, 
                    isis_srv6_locator_t *loc, bool advertise) ;

void 
isis_withdraw_locator_tlv27_instance (node_t *node, 
                    isis_adv_data_t *advt_data) ;

void 
isis_withdraw_locator_tlv27_all_instances (node_t *node) ;

void
isis_srv6_stop_adj_sid_advertisement (node_t *node) ;

void 
isis_srv6_process_locator_ips (node_t *node,  ips_srv6_data_t *msg ) ;

void
isis_srv6_advertise_prefix_sid (node_t *node, isis_srv6_pfx_sid_t *pfx_sid );

void 
isis_srv6_withdraw_pfxsid_advertisement (node_t *node, isis_srv6_pfx_sid_t *pfx_sid) ;

void
isis_srv6_advertise_all_prefix_sids (node_t *node );

void
isis_delete_prefix_sid_from_locator (node_t *node, 
            ips_srv6_data_t *msg) ;

void
isis_add_prefix_sid_to_locator (node_t *node, ips_srv6_data_t *msg);

#endif 