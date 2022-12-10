/* This file defines the data structures to work with flows */

#ifndef __SNP_FLOW__
#define __SNP_FLOW__

#include <stdbool.h>
#include <stdint.h>

class Interface;

typedef struct snp_l2_flow_info_ {


} snp_l2_flow_info_t;

typedef struct snp_l3_flow_info_ {

     /* Glue to hook up this flow into L3 routing table entry */
    glthread_t rt_entry_glue;
    /* back pointer to l3 route*/
    l3_route_t l3_route; 
} snp_l3_flow_info_t;


typedef struct snp_l4_flow_info_ {

    
} snp_l4_flow_info_t;

typedef struct snp_flow_key_{

    bool is_src_ip_set;
    uint32_t src_ip;
    bool is_dst_ip_set;
    uint32_t dst_ip;
    bool is_ip_proto_set;
    uint8_t ip_proto;
    bool is_src_port_no_set;
    uint16_t src_port_no;
    bool is_dst_port_no_set;
    uint16_t dst_port_no;
} snp_flow_key_t;

typedef struct snp_flow_ {

    /* Flow keys */
    snp_flow_key_t flow_key;
    /*back pointer to ingress interface*/
    Interface *ingress_intf;
    snp_l2_flow_info_t l2_flow_info;
    snp_l3_flow_info_t l3_flow_info;
    snp_l4_flow_info_t l4_flow_info;

/* Glue to hook up this flow entry into ingress per-interface
    maintained flow tree */
    avltree_node_t avl_node;
} snp_flow_t;

snp_flow_t *
snp_flow_calloc();

bool
snp_flow_insert_into_avl_tree (avltree_t *avl_root, snp_flow_t *flow);

bool
snp_flow_remove_from_avl_tree (avltree_t *avl_root, snp_flow_t *flow);

snp_flow_t *
snp_flow_lookup_from_avl_tree (avltree_t *avl_root, snp_flow_key_t flow_key);

void
snp_flow_print_one_flow (node_t *node, snp_flow_t *flow);

#endif