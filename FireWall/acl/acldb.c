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

    bitmap_free_internal(&acl_entry->prefix);
    bitmap_free_internal(&acl_entry->mask);
    assert(IS_GLTHREAD_LIST_EMPTY(&acl_entry->glue));
    free(acl_entry);
}


/* Convert the ACL entry into TCAM entry format */
static void
acl_compile (acl_entry_t *acl_entry) {

    bool rc;
    uint16_t temp;
    uint16_t bytes_copied = 0;

    bitmap_t *prefix = &acl_entry->prefix;
    bitmap_t *mask = &acl_entry->mask;

    bitmap_reset(prefix);
    bitmap_reset(mask);
    
    uint16_t *prefix_ptr2 = (uint16_t *)prefix->bits;
    uint32_t *prefix_ptr4 = (uint32_t *)prefix->bits;
    uint16_t *mask_ptr2 = (uint16_t *)mask->bits;
    uint32_t *mask_ptr4 = (uint32_t *)mask->bits;
    
    if (acl_entry->proto == ACL_PROTO_ANY) {
        /* User has feed "any" in place of protocol in ACL */
        /* Fill L4 proto field and L3 proto field with Dont Care */
        *mask_ptr2 = 0xFFFF; 
        prefix_ptr2++; mask_ptr2++;
        bytes_copied += sizeof(*prefix_ptr2);
        *mask_ptr2 = 0xFFFF;
        prefix_ptr2++; mask_ptr2++;
        bytes_copied += sizeof(*prefix_ptr2);
        prefix_ptr4 = (uint32_t *)prefix_ptr2;
        mask_ptr4 = (uint32_t *)mask_ptr2;
        goto SRC_ADDR;
    }

    uint8_t proto_layer = tcpip_protocol_classification(
                                    (uint16_t)acl_entry->proto);

    /* Transport Protocol 2 B*/
    if (proto_layer == TRANSPORT_LAYER ||
         proto_layer == APPLICATION_LAYER) {

        *prefix_ptr2 = htons((uint16_t)acl_entry->proto);
        *mask_ptr2 = 0;
    }
    else {
        *mask_ptr2 = 0xFFFF;
    }

    bytes_copied += sizeof(*prefix_ptr2);
    prefix_ptr2++; mask_ptr2++;
    prefix_ptr4 = (uint32_t *)prefix_ptr2;
    mask_ptr4 = (uint32_t *)mask_ptr2;

    /* Network Layer Protocol 2 B*/
    if (proto_layer == NETWORK_LAYER) {
     /* Protocol 2 B*/
        *prefix_ptr2 = htons((uint16_t)acl_entry->proto);
        *mask_ptr2 = 0;
    }
    else {
        *mask_ptr2 = 0xFFFF;
    }

    bytes_copied += sizeof(*prefix_ptr2);
    prefix_ptr2++; mask_ptr2++;
    prefix_ptr4 = (uint32_t *)prefix_ptr2;
    mask_ptr4 = (uint32_t *)mask_ptr2;

    SRC_ADDR:

    /* Src ip Address & Mask */
    *prefix_ptr4 = htonl(acl_entry->saddr.ip4.prefix);
    *mask_ptr4 =  htonl(~acl_entry->saddr.ip4.mask);
    bytes_copied += sizeof(*prefix_ptr4);
    prefix_ptr4++; mask_ptr4++;
    prefix_ptr2 = (uint16_t *)prefix_ptr4;
    mask_ptr2 = (uint16_t *)mask_ptr4;

    /* Src Port Range */
    /* Not Supported Yet, fill it 16bit prefix as zero, and 16 bit mask as  all 1s */
    *prefix_ptr2 = 0;
    *mask_ptr2 = htons(0xFFFF);
     bytes_copied += sizeof(*prefix_ptr2);
     prefix_ptr2++; mask_ptr2++;
    prefix_ptr4 = (uint32_t *)prefix_ptr2;
    mask_ptr4 = (uint32_t *)mask_ptr2;


     /* Dst ip Address & Mask */
    *prefix_ptr4 = htonl(acl_entry->daddr.ip4.prefix);
    *mask_ptr4 =  htonl(~acl_entry->daddr.ip4.mask);
    bytes_copied += sizeof(*prefix_ptr4);
    prefix_ptr4++; mask_ptr4++;
    prefix_ptr2 = (uint16_t *)prefix_ptr4;
    mask_ptr2 = (uint16_t *)mask_ptr4;

    /* Drt Port Range */
    /* Not Supported Yet, fill it 16bit prefix as zero, and 16 bit mask as  all 1s */
    *prefix_ptr2 = 0;
    *mask_ptr2 = htons(0xFFFF);
     bytes_copied += sizeof(*prefix_ptr2);
     prefix_ptr2++; mask_ptr2++;
    prefix_ptr4 = (uint32_t *)prefix_ptr2;
    mask_ptr4 = (uint32_t *)mask_ptr2;

    /* Fill the residual bits : prefix with Zeros, and Mask with 1s*/
    
    // Prefix : Already done

    // Mask :
    uint16_t bytes_remaining = (ACL_PREFIX_LEN/8) - bytes_copied ;
    uint8_t *mask_ptr1 = (uint8_t *)mask_ptr2;

    while (bytes_remaining) {
        *mask_ptr1 = 0xFF;
        mask_ptr1++;
        bytes_remaining--; 
        bytes_copied++;
    }
    
    prefix->next = bytes_copied * 8;
    mask->next = prefix->next;
    assert(prefix->next == ACL_PREFIX_LEN);
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
}


bool
acl_install(access_list_t *access_list, acl_entry_t *acl_entry) {

     return mtrie_insert_prefix(
                    access_list->mtrie, 
                    &acl_entry->prefix,
                    &acl_entry->mask,
                    ACL_PREFIX_LEN,
                    (void *)acl_entry);
 }

 void 
 access_list_check_delete(access_list_t *access_list) {

    assert(IS_GLTHREAD_LIST_EMPTY(&access_list->head));
    assert(IS_GLTHREAD_LIST_EMPTY(&access_list->glue));
    assert(!access_list->mtrie);
    assert(access_list->ref_count == 0);
    free(access_list);
 }

bool
acl_process_user_config(node_t *node, 
                char *access_list_name,
                acl_entry_t *acl_entry) {

    bool rc = false;
    access_list_t *access_list;
    bool new_access_list = false;

    acl_compile (acl_entry);

    access_list = acl_lookup_access_list(node, access_list_name);

    if (!access_list) {
        access_list = acl_create_new_access_list(access_list_name);
        new_access_list = true;
    }

    rc = acl_install(access_list, acl_entry);

    if (!rc) {
        printf ("Error : ACL Installation into Mtrie Failed\n");
        if (new_access_list) {
            access_list_check_delete(access_list);
        }
        return false;
    }

    access_list_add_acl_entry(access_list, acl_entry);

    if (new_access_list) {
        glthread_add_next(&node->access_lists_db, &access_list->glue);
        access_list_reference(access_list);
    }
    else {
        access_list_notify_clients(node, access_list);
    }

    return true;
}

bool
acl_process_user_config_for_deletion (
                node_t *node, 
                access_list_t *access_list,
                acl_entry_t *acl_entry) {

    bool rc = false;
    void *acl_entry_in_mtrie = NULL;
    acl_entry_t *installed_acl_entry = NULL;

    acl_compile (acl_entry);

   rc = mtrie_delete_prefix(access_list->mtrie, 
                                            &acl_entry->prefix, 
                                            &acl_entry->mask,
                                            &acl_entry_in_mtrie);

    if (!rc) {
        printf ("Error : ACL Entry Do not Exist\n");
        return false;
    }

    installed_acl_entry = (acl_entry_t *)acl_entry_in_mtrie;
    remove_glthread(&installed_acl_entry->glue);

    acl_entry_free(installed_acl_entry);

    if (IS_GLTHREAD_LIST_EMPTY(&access_list->head)) {
        access_list_delete_complete(access_list);
    }
    else {
        access_list_notify_clients(node, access_list);
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

    intf->intf_nw_props.l3_ingress_acc_lst = acc_lst;
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

    hit_node = mtrie_longest_prefix_match_search(acc_lst->mtrie, &input);

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
                  src_mask = 0,
                  dst_ip = 0,
                  dst_mask = 0;
    uint16_t src_port = 0,
                  dst_port = 0;

    access_list_t *access_lst;

    access_lst = ingress ? intf->intf_nw_props.l3_ingress_acc_lst :
                        intf->intf_nw_props.l3_egress_acc_lst;

    if (!access_lst) return ACL_PERMIT;

    src_ip = ip_hdr->src_ip;
    dst_ip = ip_hdr->dst_ip;
    l4proto = ip_hdr->protocol;

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
                                                    ethernet_hdr_t *eth_hdr,
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

    access_list_t **configured_access_lst = NULL;

    if (strncmp(dirn, "in", 2) == 0 && strlen(dirn) == 2) {
        configured_access_lst = &intf->intf_nw_props.l3_ingress_acc_lst;
    }
    else if (strncmp(dirn, "out", 3) == 0 && strlen(dirn) == 3) {
        configured_access_lst = &intf->intf_nw_props.l3_egress_acc_lst;
    }
    else {
        printf ("Error : Direction can be - 'in' or 'out' only\n");
        return -1;
    }

    if (*configured_access_lst) {
        printf ("Error : Access List %s already applied\n", (*configured_access_lst)->name);
        return -1;
    }

    *configured_access_lst = acc_lst;
    access_list_reference(acc_lst);
    return 0;
}

int 
access_group_unconfig(node_t *node, 
                                       interface_t *intf, 
                                       char *dirn, 
                                      access_list_t *acc_lst) {

    access_list_t **configured_access_lst = NULL;

    if (strncmp(dirn, "in", 2) == 0 && strlen(dirn) == 2) {
        configured_access_lst = &intf->intf_nw_props.l3_ingress_acc_lst;
    }
    else if (strncmp(dirn, "out", 3) == 0 && strlen(dirn) == 3) {
        configured_access_lst = &intf->intf_nw_props.l3_egress_acc_lst;
    }
    else {
        printf ("Error : Direction can in - 'in' or 'out' only\n");
        return -1;
    }

    if (!( *configured_access_lst )) {
        printf ("Error : Access List %s not applied\n", (*configured_access_lst)->name);
        return -1;
    }

    *configured_access_lst = NULL;
    access_list_dereference(acc_lst);
    return 0;
}

/* ACL change notification */
typedef void (*acl_change_cbk)(node_t *, access_list_t *);

extern void isis_acl_change(node_t *node, access_list_t *access_lst);

acl_change_cbk notif_arr[] = { isis_acl_change, 
                                                  /*add_mode_callbacks_here,*/
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