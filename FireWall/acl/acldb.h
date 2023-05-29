#ifndef __ACL_DB_H__
#define  __ACL_DB_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "../../gluethread/glthread.h"
#include "../../BitOp/bitmap.h"
#include "../../tcpconst.h"
#include "../../utils.h"


typedef struct mtrie_ mtrie_t;
typedef struct node_ node_t;
class Interface;
typedef struct ethernet_hdr_ ethernet_hdr_t;
typedef struct ip_hdr_ ip_hdr_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct access_list_  access_list_t;
typedef struct obj_nw_ obj_nw_t;
typedef struct object_group_ object_group_t;
typedef struct task_ task_t;
typedef struct object_group_update_info_ object_group_update_info_t;

#define ACL_PREFIX_LEN  128
#define ACCESS_LIST_MAX_NAMELEN 64
#define ACL_MAX_PORTNO    0xFFFF

/* If Single acl_entry compiles into less than this count value, then
    we install/un-install it synchronously*/
#define ACL_ENTRY_TCAM_COUNT_THRESHOLD 10000

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

typedef struct acl_tcam_ {

    bitmap_t prefix;
    bitmap_t mask;
    glthread_t glue;
} acl_tcam_t;
GLTHREAD_TO_STRUCT(glue_to_acl_tcam, acl_tcam_t, glue);

typedef enum acl_addr_format_ {

    ACL_ADDR_NOT_SPECIFIED,
    ACL_ADDR_HOST,
    ACL_ADDR_SUBNET_MASK,
    ACL_ADDR_OBJECT_NETWORK,
    ACL_ADDR_OBJECT_GROUP
} acl_addr_format_t;

/* Stores the info as read from CLI */
typedef struct acl_entry_{

    uint32_t seq_no;
    acl_action_t action;
    unsigned char *remark;
    
    acl_proto_t proto;
    uint16_t tcam_l4proto_prefix;
    uint16_t tcam_l4proto_wcard;
    uint16_t tcam_l3proto_prefix;
    uint16_t tcam_l3proto_wcard;

    /* Address Storage */
    struct addr {
        acl_addr_format_t acl_addr_format;
        union {
            uint32_t host_addr;
            struct {
                uint32_t subnet_addr;
                uint32_t subnet_mask;
            } subnet;
            obj_nw_t *obj_nw;
            object_group_t *og;
        }u;
    };

    /* Src Address */
    struct addr src_addr;
    uint8_t tcam_saddr_count;
    uint32_t (*tcam_saddr_prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
    uint32_t (*tcam_saddr_wcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];

    acl_port_range_t sport;
    uint8_t tcam_sport_count;
    uint16_t (*tcam_sport_prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
    uint16_t (*tcam_sport_wcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];

    /* Dst Address */
    struct addr dst_addr;
    uint8_t tcam_daddr_count;
    uint32_t (*tcam_daddr_prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
    uint32_t (*tcam_daddr_wcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];

    acl_port_range_t dport;
    uint8_t tcam_dport_count;
    uint16_t (*tcam_dport_prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
    uint16_t (*tcam_dport_wcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];

    int priority;
    uint64_t hit_count;
    
    uint32_t tcam_total_count; /* No of TCAM entries installed in TCAM */
    uint32_t tcam_self_conflicts_count; /* No of self TCAM entries conflicts with self tcam entries */ 
    uint32_t tcam_other_conflicts_count; /* No of TCAM entries of other ACLs which conflicts with this ACL's */

    /* To avoid Duplicate printing */
    uint32_t show_cli_seq;
    bool is_compiled;
    bool is_installed;
    
    access_list_t *access_list; /* Back pointer to owning access list */
    glthread_t glue;

    /*Stats */
    time_t installation_start_time;
    time_t installation_end_time;
    bool installation_in_progress;
    uint32_t expected_tcam_count;
} acl_entry_t;
GLTHREAD_TO_STRUCT(glthread_to_acl_entry, acl_entry_t, glue);

typedef enum acl_iterator_type_ {
    acl_iterator_src_addr,
    acl_iterator_dst_addr,
    acl_iterator_src_port,
    acl_iterator_dst_port
} acl_iterator_type_t;

typedef struct acl_tcam_iterator_ {

    uint32_t *addr_prefix;
    uint32_t *addr_wcard;
    uint16_t *port_prefix;
    uint16_t *port_wcard;
    uint8_t index;
    acl_entry_t *acl_entry;
    acl_iterator_type_t it_type;
    glthread_t og_leaves_lst_head;
    glthread_t og_leaves_lst_head_processed;
} acl_tcam_iterator_t;

typedef struct access_list_processing_info_ {

    task_t *task;
    node_t *node;
    mtrie_t *mtrie;
    bool is_installation;
    acl_entry_t *current_acl;    
    glthread_t pending_acls;
    access_list_t *access_list;
    object_group_update_info_t *og_update_info;
    acl_tcam_iterator_t acl_tcam_src_it;
    acl_tcam_iterator_t acl_tcam_dst_it;
    acl_tcam_iterator_t acl_tcam_src_port_it;
    acl_tcam_iterator_t acl_tcam_dst_port_it;
    acl_tcam_t tcam_entry_template; 
    uint32_t acl_tcams_installed;
} access_list_processing_info_t;

struct access_list_ {
    unsigned char name[ACCESS_LIST_MAX_NAMELEN];
    glthread_t head; // list of acl_entry_t in this access list
    glthread_t glue; // glues into node->access_list. A node can have many access lists
    mtrie_t *mtrie;     // Mtrie for this access list, assignment to this ptr should be atomic
    /* lock the mtrie if we are updating it, only when being updated synchronously*/
    pthread_rwlock_t mtrie_update_lock;
    uint8_t ref_count; // how many sub-systems using this access list
    task_t *notif_job; /* Used when notification is to be sent async to appln */
    /* Store the context for   access-list install & uninstall operations */
    access_list_processing_info_t *processing_info;   
    /*Stats */
    time_t installation_start_time;
    time_t installation_end_time;
} ;
GLTHREAD_TO_STRUCT(glthread_to_access_list, access_list_t, glue);

acl_proto_t acl_string_to_proto(unsigned char *proto_name) ;
void acl_entry_free(acl_entry_t *acl_entry);
void acl_decompile (acl_entry_t *acl_entry) ;

void
access_list_schedule_notification (node_t *node, access_list_t *access_list);

bool
acl_process_user_config(node_t *node, 
                char *access_list_name,
                acl_entry_t *acl_entry);
bool
access_list_delete_complete(node_t *node, access_list_t *access_list);

access_list_t * access_list_lookup_by_name(node_t *node, char *access_list_name);
access_list_t * acl_create_new_access_list(char *access_list_name);
mtrie_t *access_list_get_new_tcam_mtrie ();
void access_list_add_acl_entry(access_list_t * access_list, acl_entry_t *acl_entry);
void access_list_check_delete(access_list_t *access_list);
void acl_entry_install (access_list_t *access_list, acl_entry_t *acl_entry);
void acl_entry_uninstall (access_list_t *access_list, acl_entry_t *acl_entry) ;
bool access_list_is_compiled (access_list_t *access_list);
bool access_list_should_decompile (access_list_t *access_list) ;
bool access_list_should_compile (access_list_t *access_list) ;
void acl_compile (acl_entry_t *acl_entry);
void acl_entry_reset_counters(acl_entry_t *acl_entry);
void access_list_reset_acl_counters (access_list_t *access_list);

acl_action_t
access_list_evaluate (access_list_t *acc_lst,
                                uint16_t l3proto,
                                uint16_t l4roto,
                                uint32_t src_addr,
                                uint32_t dst_addr,
                                uint16_t src_port, 
                                uint16_t dst_port);

void access_list_reference(access_list_t *acc_lst);
void access_list_dereference(node_t *node, access_list_t *acc_lst);
acl_action_t
access_list_evaluate_ip_packet (node_t *node, 
                                                    Interface*intf, 
                                                    ip_hdr_t *ip_hdr,
                                                    bool ingress);

acl_action_t
access_list_evaluate_ethernet_packet (node_t *node, 
                                                              Interface *intf, 
                                                              pkt_block_t *pkt_block,
                                                              bool ingress) ;

/* Return 0 on success */                    
int access_group_config(node_t *node, Interface *intf, char *dirn, access_list_t *acc_lst);
int access_group_unconfig(node_t *node, Interface *intf, char *dirn, access_list_t *acc_lst);
void access_list_notify_clients(node_t *node, access_list_t *acc_lst);


/* Caution : Do not use direct access acl_entry->src_addr.u.obj_nw
to fetch Network object from ACL, as it is union */
static inline obj_nw_t *
acl_get_src_network_object(acl_entry_t *acl_entry) {

    if (acl_entry->src_addr.acl_addr_format == ACL_ADDR_OBJECT_NETWORK) {
        return acl_entry->src_addr.u.obj_nw;
    }
    return NULL;
}

/* Caution : Do not use direct access acl_entry->dst_addr.u.obj_nw
to fetch Network object from ACL, as it is union */
static inline obj_nw_t *
acl_get_dst_network_object(acl_entry_t *acl_entry) {

    if (acl_entry->dst_addr.acl_addr_format == ACL_ADDR_OBJECT_NETWORK) {
        return acl_entry->dst_addr.u.obj_nw;
    }
    return NULL;
}

/* Linking and Delinking Object-Networks and ACLs APIs */
void acl_entry_link_src_object_networks(acl_entry_t *acl_entry, obj_nw_t *obj_nw) ;
void acl_entry_link_dst_object_networks(acl_entry_t *acl_entry, obj_nw_t *obj_nw) ;
void acl_entry_delink_src_object_networks(acl_entry_t *acl_entry) ;
void acl_entry_delink_dst_object_networks(acl_entry_t *acl_entry) ;


/* Caution : Do not use direct access acl_entry->src_addr.u.og
to fetch object group from ACL, as it is union */
static inline object_group_t *
acl_get_src_network_object_group(acl_entry_t *acl_entry) {

    if (acl_entry->src_addr.acl_addr_format == ACL_ADDR_OBJECT_GROUP) {
        return acl_entry->src_addr.u.og;
    }
    return NULL;
}

/* Caution : Do not use direct access acl_entry->dst_addr.u.og
to fetch Network object group from ACL, as it is union */
static inline object_group_t *
acl_get_dst_network_object_group (acl_entry_t *acl_entry) {

    if (acl_entry->dst_addr.acl_addr_format == ACL_ADDR_OBJECT_GROUP) {
        return acl_entry->dst_addr.u.og;
    }
    return NULL;
}

/* Linking and Delinking Object-Networks and ACLs APIs */
void acl_entry_link_src_object_group(acl_entry_t *acl_entry, object_group_t *og) ;
void acl_entry_link_dst_object_group(acl_entry_t *acl_entry, object_group_t *og) ;
void acl_entry_delink_src_object_group(acl_entry_t *acl_entry) ;
void acl_entry_delink_dst_object_group(acl_entry_t *acl_entry) ;


void
access_list_compute_acl_bitmap (access_list_t *access_list, acl_entry_t *acl_entry) ;

void
 access_list_print_bitmap (node_t *node, c_string access_list_name) ;

void
acl_print (acl_entry_t *acl_entry);

void
access_list_schedule_notification (node_t *node, access_list_t *access_list) ;

acl_entry_t *
access_list_lookup_acl_entry_by_seq_no (access_list_t *access_list, uint32_t seq_no);

bool
access_list_delete_acl_entry_by_seq_no (node_t *node, access_list_t *access_list, uint32_t seq_no);

void 
access_list_reenumerate_seq_no (access_list_t *access_list, 
                                                        glthread_t *begin_node);

void
acl_entry_increment_referenced_objects_tcam_user_count(
            acl_entry_t *acl_entry,
            int8_t k,
            bool object_networks,
            bool object_groups);


void
acl_tcam_iterator_init (acl_entry_t *acl_entry, 
                                     acl_tcam_iterator_t *acl_tcam_iterator,
                                     acl_iterator_type_t it_type) ;

bool
acl_tcam_iterator_first (acl_tcam_iterator_t *acl_tcam_iterator);

bool
acl_tcam_iterator_next (acl_tcam_iterator_t *acl_tcam_iterator);

bool
acl_iterators_increment(acl_tcam_iterator_t *src_it,
                                        acl_tcam_iterator_t *dst_it, 
                                        acl_tcam_iterator_t *src_port_it,
                                        acl_tcam_iterator_t *dst_port_it);

void
acl_tcam_iterator_reset (acl_tcam_iterator_t *acl_tcam_iterator);

void
acl_tcam_iterator_deinit (acl_tcam_iterator_t *acl_tcam_iterator);

void
access_list_purge_tcam_mtrie (node_t *node, mtrie_t *mtrie);

void
access_list_trigger_install_job(node_t *node, 
                                access_list_t *access_list,
                                object_group_update_info_t *og_update_info) ;

void
access_list_trigger_uninstall_job(node_t *node, 
                                access_list_t *access_list,
                                object_group_update_info_t *og_update_info);


void
access_list_trigger_acl_decompile_job(node_t *node, 
                                acl_entry_t *acl_entry,
                                object_group_update_info_t *og_update_info);

void
access_list_trigger_acl_compile_job(node_t *node, 
                                acl_entry_t *acl_entry,
                                object_group_update_info_t *og_update_info);

static inline bool
access_list_is_installation_in_progress (access_list_t *access_list) {


    if (!access_list->processing_info) return false;

    access_list_processing_info_t *processing_info = 
        access_list->processing_info;
    
    if (processing_info->is_installation) return true;
    return false;
}

static inline bool
access_list_is_uninstallation_in_progress (access_list_t *access_list){

   if (!access_list->processing_info) return false;

    access_list_processing_info_t *processing_info = 
        access_list->processing_info;
    
    if (!processing_info->is_installation) return true;
    return false;
}

void
access_list_cancel_un_installation_operation (access_list_t *access_list);

c_string
access_list_get_installation_time_duration (access_list_t *access_list, c_string time_str, size_t size) ;

c_string
acl_entry_get_installation_time_duration (acl_entry_t *acl_entry, c_string time_str, size_t size);

uint32_t 
acl_entry_get_tcam_entry_count (acl_entry_t *acl_entry);

acl_action_t 
access_list_evaluate_pkt_block (access_list_t *access_list, pkt_block_t *pkt_block);

#endif
