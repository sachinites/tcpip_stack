#ifndef __ISIS_SRV6__
#define __ISIS_SRV6__

#include "../../Tree/libtree.h"

typedef struct isis_node_info_ isis_node_info_t;
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

#define ISIS_SRV6_LOC(node_info_ptr) \
    (&(node_info_ptr)->srv6_config->loc)

void
isis_enable_srv6(isis_node_info_t *node_info);

void
isis_disable_srv6(isis_node_info_t *node_info);

int8_t 
isis_srv6_is_loc_enabled (isis_node_info_t *node_info, char *locator_name) ;

isis_srv6_config_t *
isis_srv6_get_config(isis_node_info_t *node_info);

int
isis_srv6_new_locator_set (isis_node_info_t *node_info, char *loc_name);

void
isis_srv6_locator_unset (isis_node_info_t *node_info);

/* Locator Advertisement Mgmt Fns */
void 
isis_advertise_locator_ipv6_reachability_tlv236 (
                        isis_node_info_t *node_info, 
                        isis_srv6_locator_t *loc) ;

void 
isis_withdraw_locator_ipv6_reachability_tlv236 (
                        isis_node_info_t *node_info, 
                        isis_srv6_locator_t *loc) ;

void 
isis_advertise_locator_ipv6_reachability_mt_tlv237 (
                        isis_node_info_t *node_info, 
                        isis_srv6_locator_t *loc) ;

void 
isis_withdraw_locator_ipv6_reachability_mt_tlv237 (
                        isis_node_info_t *node_info, 
                        isis_srv6_locator_t *loc) ;

isis_adv_data_t *
isis_advertise_locator_tlv27_instance (isis_node_info_t *node_info, 
                    isis_srv6_locator_t *loc, bool advertise) ;

void 
isis_withdraw_locator_tlv27_instance (isis_node_info_t *node_info, 
                    isis_adv_data_t *advt_data) ;

void 
isis_withdraw_locator_tlv27_all_instances (isis_node_info_t *node_info) ;

void
isis_srv6_stop_adj_sid_advertisement (isis_node_info_t *node_info) ;

void
isis_srv6_advertise_prefix_sid (isis_node_info_t *node_info, isis_srv6_pfx_sid_t *pfx_sid );

void 
isis_srv6_withdraw_pfxsid_advertisement (isis_node_info_t *node_info, isis_srv6_pfx_sid_t *pfx_sid) ;

void
isis_srv6_advertise_all_prefix_sids (isis_node_info_t *node_info );

void
isis_delete_prefix_sid_from_locator (isis_node_info_t *node_info, 
                                char *loc_name, 
                                ipv6_addr_t *prefix_sid) ;

void
isis_add_prefix_sid_to_locator (isis_node_info_t *node_info, 
                                char *loc_name, 
                                ipv6_addr_t *prefix_sid, 
                                Srv6_endpcode_t endfn, 
                                uint8_t flavors);

void 
 isis_advertise_rtr_capability_tlv(isis_node_info_t *node_info);

void
 isis_withdraw_rtr_capability_tlv(isis_node_info_t *node_info);
 
#endif 
