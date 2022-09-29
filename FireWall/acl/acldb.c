#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include "../../graph.h"
#include "acldb.h"
#include "../../mtrie/mtrie.h"
#include "../../Layer2/layer2.h"
#include "../../Layer3/rt_table/nexthop.h"
#include "../../Layer3/layer3.h"
#include "../../pkt_block.h"
#include "../../Layer4/udp.h"
#include "../object_network/objnw.h"

typedef struct acl_enumerator_ {

    int src_port_index;
    int dst_port_index;
    int src_addr_index;
    int dst_addr_index;
} acl_enumerator_t;

static void
acl_get_member_tcam_entry (acl_entry_t *acl_entry,                      /* Input */
                                                 acl_enumerator_t *acl_enumerator, /* Input */
                                                 acl_tcam_t *tcam_entry) ;

acl_proto_t
acl_string_to_proto(unsigned char *proto_name) {

    /* To be replaced with hashmap when code is converted into C++ */
    if (strncmp(proto_name, "ip", 2) == 0) {
        return ACL_IP;
    }

    if (strncmp(proto_name, "udp", 3) == 0) {
        return ACL_UDP;
    }

    if (strncmp(proto_name, "tcp", 3) == 0) {
        return ACL_TCP;
    }

    if (strncmp(proto_name, "icmp", 4) == 0) {
        return ACL_ICMP;
    }

    if (strncmp(proto_name, "any", 3) == 0) {
        return ACL_PROTO_ANY;
    }

    return ACL_PROTO_NONE;
}

void 
acl_entry_free (acl_entry_t *acl_entry) {

    acl_entry_free_tcam_data(acl_entry);
    acl_entry_delink_src_object_networks(acl_entry);
    acl_entry_delink_dst_object_networks(acl_entry);
    assert(IS_GLTHREAD_LIST_EMPTY(&acl_entry->glue));
    XFREE(acl_entry);
}

void 
acl_entry_free_tcam_data (acl_entry_t *acl_entry) {

    if (acl_entry->tcam_saddr_prefix) {
        XFREE(acl_entry->tcam_saddr_prefix);
        acl_entry->tcam_saddr_prefix = NULL;
    }

    if (acl_entry->tcam_saddr_wcard) {
        XFREE(acl_entry->tcam_saddr_wcard);
        acl_entry->tcam_saddr_wcard = NULL;
    }

   if (acl_entry->tcam_sport_prefix) {
        XFREE(acl_entry->tcam_sport_prefix);
        acl_entry->tcam_sport_prefix = NULL;
   }

    if (acl_entry->tcam_sport_wcard) {
        XFREE(acl_entry->tcam_sport_wcard);
        acl_entry->tcam_sport_wcard = NULL;
   }

    if (acl_entry->tcam_daddr_prefix) {
        XFREE(acl_entry->tcam_daddr_prefix);
        acl_entry->tcam_daddr_prefix = NULL;
    }

    if (acl_entry->tcam_daddr_wcard) {
        XFREE(acl_entry->tcam_daddr_wcard);
        acl_entry->tcam_daddr_wcard = NULL;
    }

   if (acl_entry->tcam_dport_prefix) {
        XFREE(acl_entry->tcam_dport_prefix);
        acl_entry->tcam_dport_prefix = NULL;
   }

    if (acl_entry->tcam_dport_wcard) {
        XFREE(acl_entry->tcam_dport_wcard);
        acl_entry->tcam_dport_wcard = NULL;
   }

   acl_entry_purge_tcam_entries_list(&acl_entry->tcam_success_list_head);
   acl_entry_purge_tcam_entries_list(&acl_entry->tcam_failed_list_head);
}


/* Convert the ACL entry into TCAM entry format */
void
acl_compile (acl_entry_t *acl_entry) {

    if (acl_entry->proto == ACL_PROTO_ANY) {
        /* User has feed "any" in place of protocol in ACL */
        /* Fill L4 proto field and L3 proto field with Dont Care */
        acl_entry->tcam_l4proto_wcard = 0xFFFF; 
        acl_entry->tcam_l3proto_wcard = 0xFFFF; 
        goto SRC_ADDR;
    }

    uint8_t proto_layer = tcpip_protocol_classification(
                                    (uint16_t)acl_entry->proto);

    /* Transport Protocol 2 B*/
    if (proto_layer == TRANSPORT_LAYER ||
         proto_layer == APPLICATION_LAYER) {

        acl_entry->tcam_l4proto_prefix = htons((uint16_t)acl_entry->proto);
        acl_entry->tcam_l4proto_wcard = 0;
    }
    else {
        acl_entry->tcam_l4proto_wcard = 0xFFFF;
    }

    /* Network Layer Protocol 2 B*/
    if (proto_layer == NETWORK_LAYER) {
     /* Protocol 2 B*/
        acl_entry->tcam_l3proto_prefix = htons((uint16_t)acl_entry->proto);
        acl_entry->tcam_l3proto_wcard = 0; 
    }
    else {
        acl_entry->tcam_l3proto_wcard = 0xFFFF;
    }

    SRC_ADDR:

    if (!acl_entry->tcam_saddr_prefix) {
        acl_entry->tcam_saddr_prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        calloc(1, sizeof(*acl_entry->tcam_saddr_prefix));
    }
    else {
        memset(acl_entry->tcam_saddr_prefix, 0, sizeof(*acl_entry->tcam_saddr_prefix));
    }
    if (!acl_entry->tcam_saddr_wcard) {
        acl_entry->tcam_saddr_wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        calloc(1, sizeof(*acl_entry->tcam_saddr_wcard));
    }
    else {
        memset(acl_entry->tcam_saddr_wcard, 0, sizeof(*acl_entry->tcam_saddr_wcard));
    }

    switch (acl_entry->src_addr.acl_addr_format) {

        case ACL_ADDR_NOT_SPECIFIED:
             acl_entry->tcam_saddr_count = 1;
             (*acl_entry->tcam_saddr_prefix)[0] = 0;
              (*acl_entry->tcam_saddr_wcard)[0] = 0xFFFFFFFF;
              break;
        case ACL_ADDR_HOST:
             acl_entry->tcam_saddr_count = 1;
             (*acl_entry->tcam_saddr_prefix)[0] = htonl(acl_entry->src_addr.u.host_addr);
              (*acl_entry->tcam_saddr_wcard)[0] = 0;
            break;
        case ACL_ADDR_SUBNET_MASK:
            acl_entry->tcam_saddr_count = 1;
            (*acl_entry->tcam_saddr_prefix)[0] = 
                htonl(acl_entry->src_addr.u.subnet.subnet_addr & acl_entry->src_addr.u.subnet.subnet_mask);
             (*acl_entry->tcam_saddr_wcard)[0] = htonl(~acl_entry->src_addr.u.subnet.subnet_mask);
            break;
        case ACL_ADDR_OBJECT_NETWORK:
            switch (acl_entry->src_addr.u.obj_nw->type) {
                case OBJ_NW_TYPE_HOST:
                    acl_entry->tcam_saddr_count = 1;
                    (*acl_entry->tcam_saddr_prefix)[0] = htonl(acl_entry->src_addr.u.obj_nw->u.host);
                    (*acl_entry->tcam_saddr_wcard)[0] = 0;
                    break;
                case  OBJ_NW_TYPE_SUBNET:
                    acl_entry->tcam_saddr_count = 1;
                     (*acl_entry->tcam_saddr_prefix)[0] = 
                            htonl(acl_entry->src_addr.u.obj_nw->u.subnet.network & acl_entry->src_addr.u.obj_nw->u.subnet.subnet);
                     (*acl_entry->tcam_saddr_wcard)[0] = htonl(~acl_entry->src_addr.u.obj_nw->u.subnet.subnet);
                    break;
                case OBJ_NW_TYPE_RANGE:
                    range2_prefix_wildcard_conversion32(
                        acl_entry->src_addr.u.obj_nw->u.range.lb,
                        acl_entry->src_addr.u.obj_nw->u.range.ub,
                        acl_entry->tcam_saddr_prefix,
                        acl_entry->tcam_saddr_wcard,
                        (int *)&acl_entry->tcam_saddr_count);
                    break; 
                case OBJ_NW_TYPE_NONE:
                    assert(0);
            }
    }

    /* Src Port Range */
    if (!acl_entry->tcam_sport_prefix) {
        acl_entry->tcam_sport_prefix = (uint16_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        calloc(1, sizeof(*acl_entry->tcam_sport_prefix));
    }
    else {
        memset(acl_entry->tcam_sport_prefix, 0, sizeof(*acl_entry->tcam_sport_prefix));
    }
    if (!acl_entry->tcam_sport_wcard) {
        acl_entry->tcam_sport_wcard = (uint16_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        calloc(1, sizeof(*acl_entry->tcam_sport_wcard));
    }
    else {
        memset(acl_entry->tcam_sport_wcard, 0, sizeof(*acl_entry->tcam_sport_wcard));
    }

    if (acl_entry->sport.lb == 0 && 
         acl_entry->sport.ub == 0 ) {
            
            acl_entry->tcam_sport_count = 1;
            (*acl_entry->tcam_sport_prefix)[0] = 0;
            (*acl_entry->tcam_sport_wcard)[0] = 0xFFFF;
    }
    else {      
        range2_prefix_wildcard_conversion(
            acl_entry->sport.lb,
            acl_entry->sport.ub, 
            acl_entry->tcam_sport_prefix,
            acl_entry->tcam_sport_wcard, 
            (int *)&acl_entry->tcam_sport_count);
    }

     /* Dst ip Address & Mask */

    if (!acl_entry->tcam_daddr_prefix) {
        acl_entry->tcam_daddr_prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        calloc(1, sizeof(*acl_entry->tcam_daddr_prefix));
    }
    else {
        memset(acl_entry->tcam_daddr_prefix, 0, sizeof(*acl_entry->tcam_daddr_prefix));
    }
    if (!acl_entry->tcam_daddr_wcard) {
        acl_entry->tcam_daddr_wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        calloc(1, sizeof(*acl_entry->tcam_daddr_wcard));
    }
    else {
        memset(acl_entry->tcam_daddr_wcard, 0, sizeof(*acl_entry->tcam_daddr_wcard));
    }

    switch (acl_entry->dst_addr.acl_addr_format) {

        case ACL_ADDR_NOT_SPECIFIED:
             acl_entry->tcam_daddr_count = 1;
             (*acl_entry->tcam_daddr_prefix)[0] = 0;
              (*acl_entry->tcam_daddr_wcard)[0] = 0xFFFFFFFF;
              break;
        case ACL_ADDR_HOST:
             acl_entry->tcam_daddr_count = 1;
             (*acl_entry->tcam_daddr_prefix)[0] = htonl(acl_entry->dst_addr.u.host_addr);
              (*acl_entry->tcam_daddr_wcard)[0] = 0;
            break;
        case ACL_ADDR_SUBNET_MASK:
            acl_entry->tcam_daddr_count = 1;
            (*acl_entry->tcam_daddr_prefix)[0] = 
                htonl(acl_entry->dst_addr.u.subnet.subnet_addr & acl_entry->dst_addr.u.subnet.subnet_mask);
             (*acl_entry->tcam_daddr_wcard)[0] = htonl(~acl_entry->dst_addr.u.subnet.subnet_mask);
            break;
        case ACL_ADDR_OBJECT_NETWORK:
            switch (acl_entry->dst_addr.u.obj_nw->type) {
                case OBJ_NW_TYPE_HOST:
                    acl_entry->tcam_daddr_count = 1;
                    (*acl_entry->tcam_daddr_prefix)[0] = htonl(acl_entry->dst_addr.u.obj_nw->u.host);
                    (*acl_entry->tcam_daddr_wcard)[0] = 0;
                    break;
                case  OBJ_NW_TYPE_SUBNET:
                    acl_entry->tcam_daddr_count = 1;
                     (*acl_entry->tcam_daddr_prefix)[0] = 
                            htonl(acl_entry->dst_addr.u.obj_nw->u.subnet.network & acl_entry->dst_addr.u.obj_nw->u.subnet.subnet);
                     (*acl_entry->tcam_daddr_wcard)[0] = htonl(~acl_entry->dst_addr.u.obj_nw->u.subnet.subnet);
                    break;
                case OBJ_NW_TYPE_RANGE:
                    range2_prefix_wildcard_conversion32(
                        acl_entry->dst_addr.u.obj_nw->u.range.lb,
                        acl_entry->dst_addr.u.obj_nw->u.range.ub,
                        acl_entry->tcam_daddr_prefix,
                        acl_entry->tcam_daddr_wcard,
                        (int *)&acl_entry->tcam_daddr_count);
                    break; 
                case OBJ_NW_TYPE_NONE:
                    assert(0);
            }
    }


    /* Dst Port Range */
    if (!acl_entry->tcam_dport_prefix) {
        acl_entry->tcam_dport_prefix = (uint16_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        calloc(1, sizeof(*acl_entry->tcam_dport_prefix));
    }
    else {
        memset(acl_entry->tcam_dport_prefix, 0, sizeof(*acl_entry->tcam_dport_prefix));
    }
    if (!acl_entry->tcam_dport_wcard) {
        acl_entry->tcam_dport_wcard = (uint16_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        calloc(1, sizeof(*acl_entry->tcam_dport_wcard));
    }
    else {
        memset(acl_entry->tcam_dport_wcard, 0, sizeof(*acl_entry->tcam_dport_wcard));
    }

    if (acl_entry->dport.lb == 0 && 
         acl_entry->dport.ub == 0 ) {
            
            acl_entry->tcam_dport_count = 1;
            (*acl_entry->tcam_dport_prefix)[0] = 0;
            (*acl_entry->tcam_dport_wcard)[0] = 0xFFFF;
    }
    else {      
        range2_prefix_wildcard_conversion(
            acl_entry->dport.lb,
            acl_entry->dport.ub, 
            acl_entry->tcam_dport_prefix,
            acl_entry->tcam_dport_wcard, 
            (int *)&acl_entry->tcam_dport_count);
    }
}

access_list_t *
acl_lookup_access_list(node_t *node, char *access_list_name) {

    glthread_t *curr;
    access_list_t *acc_lst;
    ITERATE_GLTHREAD_BEGIN(&node->access_lists_db, curr) {

        acc_lst = glthread_to_access_list(curr);
        if (strncmp(acc_lst->name, 
                           access_list_name, 
                            ACCESS_LIST_MAX_NAMELEN) == 0) {
            return acc_lst;
        }
    } ITERATE_GLTHREAD_END(&node->access_lists_db, curr);

    return NULL;
}

access_list_t *
acl_create_new_access_list(char *access_list_name) {

    access_list_t *acc_lst = (access_list_t *)calloc(1, sizeof(access_list_t));
    strncpy(acc_lst->name, access_list_name, ACCESS_LIST_MAX_NAMELEN);
    init_glthread(&acc_lst->head);
    init_glthread(&acc_lst->glue);
    pthread_spin_init (&acc_lst->spin_lock, PTHREAD_PROCESS_PRIVATE);
    acc_lst->mtrie = (mtrie_t *)calloc(1, sizeof(mtrie_t));
    init_mtrie(acc_lst->mtrie, ACL_PREFIX_LEN);
    acc_lst->ref_count = 0;
    return acc_lst;
}

void
access_list_add_acl_entry(
                                access_list_t * access_list,
                                acl_entry_t *acl_entry) {

    glthread_add_last(&access_list->head, &acl_entry->glue);
    assert(!acl_entry->access_lst);
    acl_entry->access_lst = access_list;
}

 void 
 access_list_check_delete(access_list_t *access_list) {

    assert(IS_GLTHREAD_LIST_EMPTY(&access_list->head));
    assert(IS_GLTHREAD_LIST_EMPTY(&access_list->glue));
    assert(!access_list->mtrie);
    assert(access_list->ref_count == 0);
    pthread_spin_destroy (&access_list->spin_lock);
    XFREE(access_list);
 }

bool
acl_process_user_config (node_t *node, 
                char *access_list_name,
                acl_entry_t *acl_entry) {

    bool rc = false;
    glthread_t *curr;
    access_list_t *access_list;
    bool new_access_list = false;

    acl_compile (acl_entry);

    access_list = acl_lookup_access_list(node, access_list_name);

    if (!access_list) {
        access_list = acl_create_new_access_list(access_list_name);
        new_access_list = true;
    }

    pthread_spin_lock(&access_list->spin_lock);

    acl_entry_install (access_list, acl_entry);

    if (acl_entry_is_partially_installed(acl_entry)) {
       
        /* Revert the Operation */
       acl_entry_uninstall_installed_tcam_entries(access_list, acl_entry);
       pthread_spin_unlock(&access_list->spin_lock);

        if (new_access_list) {
            access_list_check_delete(access_list);
        }
        return false;
    }

    pthread_spin_unlock(&access_list->spin_lock);
    acl_entry_purge_tcam_entries_list(&acl_entry->tcam_success_list_head);
    access_list_add_acl_entry (access_list, acl_entry);

    if (new_access_list) {
        glthread_add_next (&node->access_lists_db, &access_list->glue);
        access_list_reference (access_list);
    }
    else {
        access_list_notify_clients (node, access_list);
    }
    return true;
}

bool
acl_process_user_config_for_deletion (
                node_t *node, 
                access_list_t *access_list,
                acl_entry_t *acl_entry_template) {

    bool rc = false;
    bool is_acl_updated;
    acl_entry_t *installed_acl_entry = NULL;

    is_acl_updated = false;

    acl_compile (acl_entry_template);

    pthread_spin_lock(&access_list->spin_lock);
    acl_entry_uninstall(access_list, acl_entry_template, &installed_acl_entry);
    pthread_spin_unlock(&access_list->spin_lock);


    if (installed_acl_entry) {
        is_acl_updated = true;
    }

    if (acl_entry_is_not_installed_at_all (installed_acl_entry)) {
        
        remove_glthread(&installed_acl_entry->glue);
        installed_acl_entry->access_lst = NULL;
        acl_entry_free(installed_acl_entry);
    }

    acl_entry_free_tcam_data(acl_entry_template);
    
    if (is_acl_updated) {
        access_list_notify_clients(node, access_list);  
    }

    if (IS_GLTHREAD_LIST_EMPTY(&access_list->head)) {
        access_list_delete_complete(access_list);
    }

    return true;
}

void
access_list_delete_complete(access_list_t *access_list) {

    glthread_t *curr;
    acl_entry_t *acl_entry;

    if (access_list->ref_count > 1) {
        printf ("Access List is in use, Cannot delete\n");
        return;
    }

    mtrie_destroy(access_list->mtrie);
    free(access_list->mtrie);
    access_list->mtrie = NULL;

    ITERATE_GLTHREAD_BEGIN(&access_list->head, curr) {

        acl_entry = glthread_to_acl_entry(curr);
        remove_glthread(&acl_entry->glue);
        acl_entry_free(acl_entry);

    }ITERATE_GLTHREAD_END(&access_list->head, curr);

    remove_glthread(&access_list->glue);
    access_list->ref_count--;
    pthread_spin_destroy(&access_list->spin_lock);
    access_list_check_delete(access_list);
    printf ("Access List Deleted\n");
}


/* Mgmt Functions */
void 
access_list_attach_to_interface_ingress(interface_t *intf, char *acc_lst_name) {

    access_list_t *acc_lst = acl_lookup_access_list(intf->att_node, acc_lst_name);

    if (!acc_lst) {
        printf ("Error : Access List not configured\n");
        return;
    }

    if (intf->intf_nw_props.l3_ingress_acc_lst) {
        printf ("Error : Access List already applied to interface\n");
        return;
    }

    pthread_spin_lock(&intf->intf_nw_props.spin_lock_l3_ingress_acc_lst);
    intf->intf_nw_props.l3_ingress_acc_lst = acc_lst;
    pthread_spin_unlock(&intf->intf_nw_props.spin_lock_l3_ingress_acc_lst);

    access_list_reference(acc_lst);
}

void access_list_reference(access_list_t *acc_lst) {

    acc_lst->ref_count++;
}

void access_list_dereference(access_list_t *acc_lst) {

    if (acc_lst->ref_count == 0) {
        access_list_delete_complete(acc_lst);
        return;
    }

    acc_lst->ref_count--;

    if (acc_lst->ref_count == 0) {
        access_list_delete_complete(acc_lst);
        return;
    }
}

/* Evaluating the pkt/data against Access List */

static void
bitmap_fill_with_params(
        bitmap_t *bitmap,
        uint16_t l3proto,
        uint16_t l4proto,
        uint32_t src_addr,
        uint32_t dst_addr,
        uint16_t src_port,
        uint16_t dst_port) {

        uint16_t *ptr2 = (uint16_t *)(bitmap->bits);

        /* Transport Protocol 2 B*/
        *ptr2 = htons(l4proto);
        ptr2++;

        /* Network Layer Protocol 2 B*/
        *ptr2 = htons(l3proto);
        ptr2++;

        uint32_t *ptr4 = (uint32_t *)ptr2;
        *ptr4 = htonl(src_addr);
        ptr4++;

        ptr2 = (uint16_t *)ptr4;
        *ptr2 = htons(src_port);
        ptr2++;

        ptr4 = (uint32_t *)ptr2;

        *ptr4 = htonl(dst_addr);
        ptr4++;

        ptr2 = (uint16_t *)ptr4;
        *ptr2 = htons(dst_port);

        /* 128 bit ACL entry size is supported today */
}

acl_action_t
access_list_evaluate (access_list_t *acc_lst,
                                uint16_t l3proto,
                                uint16_t l4proto,
                                uint32_t src_addr,
                                uint32_t dst_addr,
                                uint16_t src_port, 
                                uint16_t dst_port) {

    acl_action_t action;
    acl_entry_t *hit_acl = NULL;
    mtrie_node_t *hit_node = NULL;

    bitmap_t input;
    bitmap_init(&input, ACL_PREFIX_LEN);

    bitmap_fill_with_params(&input, l3proto, l4proto, src_addr, dst_addr, src_port, dst_port);

    pthread_spin_lock (&acc_lst->spin_lock);

    hit_node = mtrie_longest_prefix_match_search(
                            acc_lst->mtrie, &input);

    /* Deny by default */
    if (!hit_node) {
        action = ACL_DENY;
        goto done;
    }

    hit_acl = (acl_entry_t *)(hit_node->data);
    assert(hit_acl);

    hit_acl->hit_count++;
    action = hit_acl->action;
    goto done;

    done:
    pthread_spin_unlock (&acc_lst->spin_lock);
    bitmap_free_internal(&input);
    return action;
}

acl_action_t
access_list_evaluate_ip_packet (node_t *node, 
                                                    interface_t *intf, 
                                                    ip_hdr_t *ip_hdr,
                                                    bool ingress) {

    uint16_t l4proto = 0;
    uint32_t src_ip = 0,
                  dst_ip = 0;
                 
    uint16_t src_port = 0,
                  dst_port = 0;

    access_list_t *access_lst;

    access_lst = ingress ? intf->intf_nw_props.l3_ingress_acc_lst :
                        intf->intf_nw_props.l3_egress_acc_lst;

    if (!access_lst) return ACL_PERMIT;

    src_ip = ip_hdr->src_ip;
    dst_ip = ip_hdr->dst_ip;
    l4proto = ip_hdr->protocol;

    switch (l4proto) {
        case UDP_PROTO:
            {
                udp_hdr_t *udp_hdr = (udp_hdr_t *)(INCREMENT_IPHDR(ip_hdr));
                src_port = udp_hdr->src_port_no;
                dst_port = udp_hdr->dst_port_no;
            }
            break;
        case TCP_PROTO:
            break;
    }

    return access_list_evaluate(access_lst, 
                                                ETH_IP, 
                                                l4proto,
                                                src_ip,
                                                dst_ip,
                                                src_port,
                                                dst_port);
}


acl_action_t
access_list_evaluate_ethernet_packet (node_t *node, 
                                                    interface_t *intf, 
                                                    pkt_block_t *pkt_block,
                                                    bool ingress) {

    return ACL_PERMIT;
}

/* Access Group Mgmt APIs */
/* Return 0 on success */                    
int 
access_group_config(node_t *node, 
                                   interface_t *intf, 
                                   char *dirn, 
                                   access_list_t *acc_lst) {

    pthread_spinlock_t *spin_lock;
    access_list_t **configured_access_lst = NULL;

    if (strncmp(dirn, "in", 2) == 0 && strlen(dirn) == 2) {
        configured_access_lst = &intf->intf_nw_props.l3_ingress_acc_lst;
        spin_lock = &intf->intf_nw_props.spin_lock_l3_ingress_acc_lst;
    }
    else if (strncmp(dirn, "out", 3) == 0 && strlen(dirn) == 3) {
        configured_access_lst = &intf->intf_nw_props.l3_egress_acc_lst;
        spin_lock = &intf->intf_nw_props.spin_lock_l3_egress_acc_lst;
    }
    else {
        printf ("Error : Direction can be - 'in' or 'out' only\n");
        return -1;
    }

    if (*configured_access_lst) {
        printf ("Error : Access List %s already applied\n", (*configured_access_lst)->name);
        return -1;
    }

    pthread_spin_lock(spin_lock);
    *configured_access_lst = acc_lst;
    access_list_reference(acc_lst);
    pthread_spin_unlock(spin_lock);
    return 0;
}

int 
access_group_unconfig(node_t *node, 
                                       interface_t *intf, 
                                       char *dirn, 
                                      access_list_t *acc_lst) {

    pthread_spinlock_t *spin_lock;
    access_list_t **configured_access_lst = NULL;

    if (strncmp(dirn, "in", 2) == 0 && strlen(dirn) == 2) {
        configured_access_lst = &intf->intf_nw_props.l3_ingress_acc_lst;
        spin_lock = &intf->intf_nw_props.spin_lock_l3_ingress_acc_lst;
    }
    else if (strncmp(dirn, "out", 3) == 0 && strlen(dirn) == 3) {
        configured_access_lst = &intf->intf_nw_props.l3_egress_acc_lst;
        spin_lock = &intf->intf_nw_props.spin_lock_l3_egress_acc_lst;
    }
    else {
        printf ("Error : Direction can in - 'in' or 'out' only\n");
        return -1;
    }

    if (!( *configured_access_lst )) {
        printf ("Error : Access List %s not applied\n", (*configured_access_lst)->name);
        return -1;
    }

    pthread_spin_lock(spin_lock);
    *configured_access_lst = NULL;
    access_list_dereference(acc_lst);
    pthread_spin_unlock(spin_lock);
    return 0;
}

/* ACL change notification */
typedef void (*acl_change_cbk)(node_t *, access_list_t *);

static acl_change_cbk notif_arr[] = { /*add_mode_callbacks_here,*/
                                                            0,
                                                          };

void
access_list_notify_clients(node_t *node, access_list_t *acc_lst) {

    int i = 0 ;
    while (notif_arr[i]) {
        notif_arr[i](node, acc_lst);
        i++;
    }
}

static void
acl_get_member_tcam_entry (acl_entry_t *acl_entry,                      /* Input */
                                                 acl_enumerator_t *acl_enumerator, /* Input */
                                                 acl_tcam_t *tcam_entry) {               /* Output */

    uint16_t bytes_copied = 0;

    bitmap_t *prefix = &tcam_entry->prefix;
    bitmap_t *mask = &tcam_entry->mask;

    bitmap_init (prefix, ACL_PREFIX_LEN);
    bitmap_init (mask, ACL_PREFIX_LEN);
    init_glthread(&tcam_entry->glue);

    uint16_t *prefix_ptr2 = (uint16_t *)prefix->bits;
    uint32_t *prefix_ptr4 = (uint32_t *)prefix->bits;
    uint16_t *mask_ptr2 = (uint16_t *)mask->bits;
    uint32_t *mask_ptr4 = (uint32_t *)mask->bits;

    /* L4 Protocol */
    memcpy(prefix_ptr2, &acl_entry->tcam_l4proto_prefix, sizeof(*prefix_ptr2));
    memcpy(mask_ptr2,  &acl_entry->tcam_l4proto_wcard, sizeof(*mask_ptr2));
    prefix_ptr2++; mask_ptr2++;
    prefix_ptr4 = (uint32_t *)prefix_ptr2;
    mask_ptr4 = (uint32_t *)mask_ptr2;
    bytes_copied += sizeof(*prefix_ptr2);

    /* L3 Protocol */
    memcpy(prefix_ptr2, &acl_entry->tcam_l3proto_prefix, sizeof(*prefix_ptr2));
    memcpy(mask_ptr2,  &acl_entry->tcam_l3proto_wcard, sizeof(*mask_ptr2));
    prefix_ptr2++; mask_ptr2++;
    prefix_ptr4 = (uint32_t *)prefix_ptr2;
    mask_ptr4 = (uint32_t *)mask_ptr2;
    bytes_copied += sizeof(*prefix_ptr2);    

    /* Src ip Address & Mask */
    memcpy(prefix_ptr4, &((*acl_entry->tcam_saddr_prefix)[acl_enumerator->src_addr_index]), sizeof(*prefix_ptr4));
    memcpy(mask_ptr4, &((*acl_entry->tcam_saddr_wcard)[acl_enumerator->src_addr_index]), sizeof(*mask_ptr4));
    prefix_ptr4++; mask_ptr4++;
    prefix_ptr2 = (uint16_t *)prefix_ptr4;
    mask_ptr2 = (uint16_t *)mask_ptr4;
    bytes_copied += sizeof(*prefix_ptr4);

    /* Src Port */
    memcpy(prefix_ptr2, 
            &((*acl_entry->tcam_sport_prefix)[acl_enumerator->src_port_index]),
            sizeof(*prefix_ptr2));

    memcpy(mask_ptr2, 
            &((*acl_entry->tcam_sport_wcard)[acl_enumerator->src_port_index]),
            sizeof(*prefix_ptr2));


    prefix_ptr2++;
    mask_ptr2++;
    prefix_ptr4 = (uint32_t *)prefix_ptr2;
    mask_ptr4 = (uint32_t *)mask_ptr2;
    bytes_copied += sizeof(*prefix_ptr2);

    /* Dst ip Address & Mask */
    memcpy(prefix_ptr4, &((*acl_entry->tcam_daddr_prefix)[acl_enumerator->dst_addr_index]), sizeof(*prefix_ptr4));
    memcpy(mask_ptr4, &((*acl_entry->tcam_daddr_wcard)[acl_enumerator->dst_addr_index]), sizeof(*mask_ptr4));
    prefix_ptr4++; mask_ptr4++;
    prefix_ptr2 = (uint16_t *)prefix_ptr4;
    mask_ptr2 = (uint16_t *)mask_ptr4;
    bytes_copied += sizeof(*prefix_ptr4);

    /* Dst Port */
    memcpy(prefix_ptr2, 
            &((*acl_entry->tcam_dport_prefix)[acl_enumerator->dst_port_index]),
            sizeof(*prefix_ptr2));

    memcpy(mask_ptr2, 
            &((*acl_entry->tcam_dport_wcard)[acl_enumerator->dst_port_index]),
            sizeof(*prefix_ptr2));

    prefix_ptr2++;
    mask_ptr2++;
    prefix_ptr4 = (uint32_t *)prefix_ptr2;
    mask_ptr4 = (uint32_t *)mask_ptr2;
    bytes_copied += sizeof(*prefix_ptr2);
    
    prefix->next = bytes_copied * 8;
    mask->next = prefix->next;
    assert(prefix->next == ACL_PREFIX_LEN);
}


void
acl_entry_uninstall (access_list_t *access_list, 
                                acl_entry_t *acl_entry, 
                                acl_entry_t **mtrie_acl_entry) {

    bool rc;
    int src_port_it, dst_port_it;
    int src_addr_it, dst_addr_it;
    acl_enumerator_t acl_enum;
    acl_tcam_t tcam_entry_template;
    void *acl_entry_in_mtrie = NULL;

    if (mtrie_acl_entry) {
        *mtrie_acl_entry = NULL;
    }

    bitmap_init(&tcam_entry_template.prefix, ACL_PREFIX_LEN);
    bitmap_init(&tcam_entry_template.mask, ACL_PREFIX_LEN);
    init_glthread(&tcam_entry_template.glue);

    for (src_addr_it = 0; src_addr_it < acl_entry->tcam_saddr_count; src_addr_it++) {
    
        for (src_port_it = 0; src_port_it < acl_entry->tcam_sport_count; src_port_it++) {

            for (dst_addr_it = 0; dst_addr_it < acl_entry->tcam_daddr_count; dst_addr_it++) {

                for (dst_port_it = 0; dst_port_it < acl_entry->tcam_dport_count; dst_port_it++) {

                    acl_enum.src_port_index = src_port_it;
                    acl_enum.dst_port_index = dst_port_it;
                    acl_enum.src_addr_index = src_addr_it;
                    acl_enum.dst_addr_index = dst_addr_it;

                    acl_get_member_tcam_entry(acl_entry, &acl_enum, &tcam_entry_template);

#if 0
                    printf ("Un-Installing TCAM Entry  : \n");
                    bitmap_print(&tcam_entry_template.prefix);
                    bitmap_print(&tcam_entry_template.mask);
#endif
                    rc = mtrie_delete_prefix (access_list->mtrie,
                                             &tcam_entry_template.prefix,
                                             &tcam_entry_template.mask,
                                             &acl_entry_in_mtrie);

                    if (rc) {
                        
                        ((acl_entry_t *)acl_entry_in_mtrie)->tcam_installed--;

                        if (mtrie_acl_entry && !(*mtrie_acl_entry)) {
                            *mtrie_acl_entry = (acl_entry_t *)acl_entry_in_mtrie;
                        }
                    }
                    else {
                        printf("Error : Tcam Un-Installation Failed for tcam entry %p\n", &tcam_entry_template);
                    }
                }
            }
        }
    }
    bitmap_free_internal(&tcam_entry_template.prefix);
    bitmap_free_internal(&tcam_entry_template.mask);
}


/* Install all TCAM entries of a given ACL */
void
acl_entry_install (access_list_t *access_list, acl_entry_t *acl_entry) {

    bool rc;
    int src_addr_it, dst_addr_it;
    int src_port_it, dst_port_it;
    acl_enumerator_t acl_enum;
    acl_tcam_t *tcam_entry;

    acl_entry->total_tcam_count = 0;
    acl_entry->tcam_installed = 0 ;
    acl_entry->tcam_installed_failed = 0;

    assert(IS_GLTHREAD_LIST_EMPTY(&acl_entry->tcam_success_list_head));
    assert(IS_GLTHREAD_LIST_EMPTY(&acl_entry->tcam_failed_list_head));

    for (src_addr_it = 0; src_addr_it < acl_entry->tcam_saddr_count; src_addr_it++) {
    
        for (src_port_it = 0; src_port_it < acl_entry->tcam_sport_count; src_port_it++) {

            for (dst_addr_it = 0; dst_addr_it < acl_entry->tcam_daddr_count; dst_addr_it++) {

                for (dst_port_it = 0; dst_port_it < acl_entry->tcam_dport_count; dst_port_it++) {

                    acl_enum.src_port_index = src_port_it;
                    acl_enum.dst_port_index = dst_port_it;
                    acl_enum.src_addr_index = src_addr_it;
                    acl_enum.dst_addr_index = dst_addr_it;

                    tcam_entry = (acl_tcam_t *)XCALLOC(0, 1, acl_tcam_t );
                    bitmap_init(&tcam_entry->prefix, ACL_PREFIX_LEN);
                    bitmap_init(&tcam_entry->mask, ACL_PREFIX_LEN);
                    init_glthread(&tcam_entry->glue);
                    acl_get_member_tcam_entry(acl_entry, &acl_enum, tcam_entry);

#if 0
                    printf ("Installing TCAM Entry  : \n");
                    bitmap_print(&tcam_entry->prefix);
                    bitmap_print(&tcam_entry->mask);
#endif
                    rc = (mtrie_insert_prefix(
                                            access_list->mtrie,
                                            &tcam_entry->prefix,
                                            &tcam_entry->mask,
                                            ACL_PREFIX_LEN,
                                            (void *)acl_entry));

                    acl_entry->total_tcam_count++;

                    if (rc) {
                        acl_entry->tcam_installed++;
                        glthread_add_next(&acl_entry->tcam_success_list_head, &tcam_entry->glue);
                    }
                    else {
                        acl_entry->tcam_installed_failed++;
                        glthread_add_next(&acl_entry->tcam_failed_list_head, &tcam_entry->glue);
                    }
                }
            }
        }
    }
 }

static void 
acl_entry_link_object_networks(acl_entry_t *acl_entry, obj_nw_t *objnw) {

    if (!objnw) return;

    obj_nw_linkage_db_t *db = objnw->db;

    if (!db) {

        objnw->db = (obj_nw_linkage_db_t *)XCALLOC(0, 1, obj_nw_linkage_db_t);
        db = objnw->db;
        init_glthread(&db->acls_list);
        init_glthread(&db->nat_list);
    }

    obj_nw_linked_acl_thread_node_t *obj_nw_linked_acl_thread_node = 
        (obj_nw_linked_acl_thread_node_t *)XCALLOC(0, 1, obj_nw_linked_acl_thread_node_t);

    obj_nw_linked_acl_thread_node->acl = acl_entry;
    init_glthread(&obj_nw_linked_acl_thread_node->glue);

    glthread_add_last(&db->acls_list, &obj_nw_linked_acl_thread_node->glue);
    objnw->ref_count++;
}

static void
acl_entry_delink_object_networks(acl_entry_t *acl_entry, obj_nw_t *objnw) {

    glthread_t *curr;
    obj_nw_linkage_db_t *db;
    obj_nw_linked_acl_thread_node_t *obj_nw_linked_acl_thread_node;
    
    if (!objnw) return;

    db  = objnw->db;

    assert(db);

    ITERATE_GLTHREAD_BEGIN(&db->acls_list, curr) {

        obj_nw_linked_acl_thread_node = glue_to_obj_nw_linked_acl_thread_node(curr);
        if (obj_nw_linked_acl_thread_node->acl == acl_entry) {
            remove_glthread(&obj_nw_linked_acl_thread_node->glue);
            XFREE(obj_nw_linked_acl_thread_node);
            objnw->ref_count--;

            if (IS_GLTHREAD_LIST_EMPTY(&db->acls_list) &&
                    IS_GLTHREAD_LIST_EMPTY(&db->nat_list)) {

                XFREE(db);
                objnw->db = NULL;
                assert(!objnw->ref_count);
            }
            return;
        }
    } ITERATE_GLTHREAD_END(&db->acls_list, curr);
    assert(0);
}

void
acl_entry_delink_src_object_networks(acl_entry_t *acl_entry) {

    obj_nw_t *obj_nw;

    obj_nw = acl_get_src_network_object(acl_entry);

    if (obj_nw) {
        acl_entry_delink_object_networks(acl_entry, obj_nw);
        acl_entry->src_addr.u.obj_nw = NULL;
        acl_entry->src_addr.acl_addr_format = ACL_ADDR_NOT_SPECIFIED;
    }
}

void
acl_entry_delink_dst_object_networks(acl_entry_t *acl_entry) {

    obj_nw_t *obj_nw;

    obj_nw = acl_get_dst_network_object(acl_entry);

    if (obj_nw) {
        acl_entry_delink_object_networks(acl_entry, obj_nw);
        acl_entry->dst_addr.u.obj_nw = NULL;
        acl_entry->dst_addr.acl_addr_format = ACL_ADDR_NOT_SPECIFIED;
    }
}

void
acl_entry_link_src_object_networks(acl_entry_t *acl_entry, obj_nw_t *obj_nw) {

    if (!obj_nw) return;
    
    assert(!acl_get_src_network_object(acl_entry));

    acl_entry_link_object_networks(acl_entry, obj_nw);

    acl_entry->src_addr.u.obj_nw = obj_nw;
    acl_entry->src_addr.acl_addr_format = ACL_ADDR_OBJECT_NETWORK;
}

void
acl_entry_link_dst_object_networks(acl_entry_t *acl_entry, obj_nw_t *obj_nw) {

    if (!obj_nw) return;
    
    assert(!acl_get_dst_network_object(acl_entry));

    acl_entry_link_object_networks(acl_entry, obj_nw);

    acl_entry->dst_addr.u.obj_nw = obj_nw;
    acl_entry->dst_addr.acl_addr_format = ACL_ADDR_OBJECT_NETWORK;
}

/* To be used when Access-list is partially installed Or uninstalled
    into mtrie */
bool
access_list_reinstall (node_t *node, access_list_t *access_list) {

    glthread_t *curr;
    obj_nw_t *obj_nw;
    acl_entry_t *acl_entry;

    pthread_spin_lock(&access_list->spin_lock);

    if (access_list->mtrie) {
        mtrie_destroy(access_list->mtrie);
        XFREE(access_list->mtrie);
        access_list->mtrie = NULL;
    }

    access_list->mtrie = (mtrie_t *)XCALLOC(0, 1, mtrie_t);
    init_mtrie(access_list->mtrie, ACL_PREFIX_LEN); 

    ITERATE_GLTHREAD_BEGIN(&access_list->head, curr) {

       acl_entry = glthread_to_acl_entry(curr);
       acl_entry_free_tcam_data(acl_entry);
       acl_compile(acl_entry);
       acl_entry_install(access_list, acl_entry);
       assert(acl_entry_is_fully_installed(acl_entry));
       acl_entry_purge_tcam_entries_list(&acl_entry->tcam_success_list_head);
    }ITERATE_GLTHREAD_END(&access_list->head, curr);
    
    pthread_spin_unlock(&access_list->spin_lock);
    return true;
}

void
acl_entry_uninstall_installed_tcam_entries (
                        access_list_t *access_list,
                        acl_entry_t *acl_entry) {

    glthread_t *curr;
    acl_tcam_t *tcam_entry;
    void *installed_acl_entry = NULL;

     ITERATE_GLTHREAD_BEGIN (&acl_entry->tcam_success_list_head, curr) {

            tcam_entry = glue_to_acl_tcam(curr);
            
            assert(mtrie_delete_prefix (access_list->mtrie,
                                             &tcam_entry->prefix,
                                             &tcam_entry->mask,
                                             &installed_acl_entry));

            acl_entry->tcam_installed--;
        }  ITERATE_GLTHREAD_END (&acl_entry->tcam_success_list_head, curr);
}

void
acl_entry_purge_tcam_entries_list (glthread_t *tcam_list_head) {

    glthread_t *curr;
    acl_tcam_t *tcam_entry;

    ITERATE_GLTHREAD_BEGIN (tcam_list_head, curr) {

        tcam_entry = glue_to_acl_tcam(curr);
        remove_glthread(&tcam_entry->glue);
        bitmap_free_internal(&tcam_entry->prefix);
        bitmap_free_internal(&tcam_entry->mask);
        XFREE(tcam_entry);

    } ITERATE_GLTHREAD_END (tcam_list_head, curr);
}