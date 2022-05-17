#ifndef __ACL_DB_H__
#define  __ACL_DB_H__

#include <stdint.h>
#include <stdbool.h>
#include "../../gluethread/glthread.h"
#include "../../BitOp/bitmap.h"
#include "../../tcpconst.h"

typedef struct mtrie_ mtrie_t;
typedef struct node_ node_t;
typedef struct interface_ interface_t;
typedef struct ethernet_hdr_ ethernet_hdr_t;
typedef struct ip_hdr_ ip_hdr_t;

#define ACL_PREFIX_LEN  128
#define ACCESS_LIST_MAX_NAMELEN 64

typedef enum {
    ACL_IP = ETH_IP,
    ACL_ICMP = ICMP_PROTO,
    ACL_IGMP,
    ACL_GGP,
    ACL_IPENCAP,
    ACL_ST2,
    ACL_CBT,
    ACL_EGP,
    ACL_ISIS = PROTO_ISIS,
    ACL_TCP = TCP_PROTO,
    ACL_UDP = UDP_PROTO,
    ACL_PROTO_STATIC = PROTO_STATIC,
    ACL_GRE,
    ACL_EIGRP,
    ACL_ESP,
    ACL_AH,
    ACL_OSPF,
    ACL_TP,
    ACL_PROTO_ANY = PROTO_ANY,
    ACL_PROTO_MAX = 0xFFFF,
    ACL_PROTO_NONE = 0xFFFF
} acl_proto_t;

typedef enum {
    ACL_PERMIT,
    ACL_DENY,
} acl_action_t;

typedef struct {
    int count;
    uint16_t data[32];
    uint16_t mask[32];
} acl_port_range_masks_t;
typedef struct {
    uint32_t prefix;
    uint32_t mask;
} acl_ipv4_mask_t;
typedef struct {
    uint16_t lb;
    uint16_t ub;
} acl_port_range_t;

/* Stores the info as read from CLI */
typedef struct {
    acl_action_t action;
    acl_proto_t proto;
    union {
        acl_ipv4_mask_t ip4;
    } saddr;
    acl_port_range_t sport;
    union {
        acl_ipv4_mask_t ip4;
    } daddr;
    acl_port_range_t dport;
    int priority;
    uint64_t hit_count;
    /* The above data is converted into value/mask format and stored here*/
    bitmap_t prefix;
    bitmap_t mask;
    glthread_t glue;
} acl_entry_t;
GLTHREAD_TO_STRUCT(glthread_to_acl_entry, acl_entry_t, glue);

typedef struct access_list_ {
    unsigned char name[ACCESS_LIST_MAX_NAMELEN];
    glthread_t head; // list of acl_entry_t in this access list
    glthread_t glue; // glues into node->access_list. A node can have many access lists
    mtrie_t *mtrie;     // Mtrie for this access list
    uint8_t ref_count; // how many systems using this access list
} access_list_t;
GLTHREAD_TO_STRUCT(glthread_to_access_list, access_list_t, glue);

acl_proto_t acl_string_to_proto(unsigned char *proto_name) ;
void acl_entry_free(acl_entry_t *acl_entry);
bool
acl_process_user_config(node_t *node, 
                char *access_list_name,
                acl_entry_t *acl_entry);

bool
acl_process_user_config_for_deletion (
                node_t *node, 
                access_list_t *access_list,
                acl_entry_t *acl_entry);

void
access_list_delete_complete(access_list_t *access_list);

access_list_t * acl_lookup_access_list(node_t *node, char *access_list_name);
access_list_t * acl_create_new_access_list(char *access_list_name);
void access_list_add_acl_entry(access_list_t * access_list, acl_entry_t *acl_entry);
void access_list_check_delete(access_list_t *access_list);
bool acl_install(access_list_t *access_list, acl_entry_t *acl_entry);
acl_action_t
access_list_evaluate (access_list_t *acc_lst,
                                uint16_t l3proto,
                                uint16_t l4roto,
                                uint32_t src_addr,
                                uint32_t dst_addr,
                                uint16_t src_port, 
                                uint16_t dst_port);

void access_list_reference(access_list_t *acc_lst);
void access_list_dereference(access_list_t *acc_lst);
acl_action_t
access_list_evaluate_ip_packet (node_t *node, 
                                                    interface_t *intf, 
                                                    ip_hdr_t *ip_hdr,
                                                    bool ingress);

acl_action_t
access_list_evaluate_ethernet_packet (node_t *node, 
                                                              interface_t *intf, 
                                                              ethernet_hdr_t *eth_hdr,
                                                              bool ingress) ;

/* Return 0 on success */                    
int access_group_config(node_t *node, interface_t *intf, char *dirn, access_list_t *acc_lst);
int access_group_unconfig(node_t *node, interface_t *intf, char *dirn, access_list_t *acc_lst);
void access_list_notify_clients(node_t *node, access_list_t *acc_lst);

#endif