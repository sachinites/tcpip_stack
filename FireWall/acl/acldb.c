#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include "../../LinuxMemoryManager/uapi_mm.h"
#include "../../Threads/refcount.h"
#include "../../graph.h"
#include "../../Interface/Interface.h"
#include "../../common/l3_hdrs.h"
#include "acldb.h"
#include "../../mtrie/mtrie.h"
#include "../../Layer2/layer2.h"
#include "../../Layer3/rt_table/nexthop.h"
#include "../../Layer3/layer3.h"
#include "../../pkt_block.h"
#include "../../Layer4/udp.h"
#include "../object_network/objnw.h"
#include "../../EventDispatcher/event_dispatcher.h"
#include "../object_network/object_group.h"
#include "../fwall_trace_const.h"
#include "../object_network/objects_common.h"
#include "../object_network/object_grp_update.h"
#include "../../CLIBuilder/libcli.h"

static void
acl_get_member_tcam_entry (
                acl_entry_t *acl_entry,                              /* Input */
                acl_tcam_iterator_t *acl_tcam_src_it,      /* Input */
                acl_tcam_iterator_t * src_port_it,             /* Input */
                acl_tcam_iterator_t *acl_tcam_dst_it,      /* Input */
                acl_tcam_iterator_t * dst_port_it,             /* Input */
                acl_tcam_t *tcam_entry);                         /* output */

acl_proto_t
acl_string_to_proto(unsigned char *proto_name) {

    /* To be replaced with hashmap when code is converted into C++ */
    if (string_compare(proto_name, "ip", 2) == 0) {
        return ACL_IP;
    }

    if (string_compare(proto_name, "udp", 3) == 0) {
        return ACL_UDP;
    }

    if (string_compare(proto_name, "tcp", 3) == 0) {
        return ACL_TCP;
    }

    if (string_compare(proto_name, "icmp", 4) == 0) {
        return ACL_ICMP;
    }

    if (string_compare(proto_name, "any", 3) == 0) {
        return ACL_PROTO_ANY;
    }

    return ACL_PROTO_NONE;
}

void 
acl_entry_free (acl_entry_t *acl_entry) {

    acl_decompile(acl_entry);
    acl_entry_delink_src_object_networks(acl_entry);
    acl_entry_delink_dst_object_networks(acl_entry);
    acl_entry_delink_src_object_group(acl_entry);
    acl_entry_delink_dst_object_group(acl_entry);
    assert(IS_GLTHREAD_LIST_EMPTY(&acl_entry->glue));
    XFREE(acl_entry);
}

void 
acl_decompile (acl_entry_t *acl_entry) {

    if (!acl_entry->is_compiled) {
        sprintf (tlb, "%s : Acl %s-%u is already decompiled\n", 
            FWALL_ACL, acl_entry->access_list->name, acl_entry->seq_no);
        tcp_trace(0, 0, tlb);        
        return;
    }

    sprintf (tlb, "%s : Acl %s-%u is being decompiled\n", 
            FWALL_ACL, acl_entry->access_list->name, acl_entry->seq_no);
    tcp_trace(0, 0, tlb);

    switch (acl_entry->src_addr.acl_addr_format) {
        case ACL_ADDR_NOT_SPECIFIED:
        case ACL_ADDR_HOST:
        case ACL_ADDR_SUBNET_MASK:
            assert(acl_entry->tcam_saddr_count);    
            assert(acl_entry->tcam_saddr_prefix);
            assert(acl_entry->tcam_saddr_wcard);
            XFREE(acl_entry->tcam_saddr_prefix);
            XFREE(acl_entry->tcam_saddr_wcard);
            acl_entry->tcam_saddr_prefix = NULL;
            acl_entry->tcam_saddr_wcard = NULL;
            acl_entry->tcam_saddr_count = 0;
            break;
        case ACL_ADDR_OBJECT_NETWORK:
            assert(acl_entry->tcam_saddr_count);    
            assert(acl_entry->tcam_saddr_prefix);
            assert(acl_entry->tcam_saddr_wcard);
            acl_entry->tcam_saddr_prefix = NULL;
            acl_entry->tcam_saddr_wcard = NULL;
            acl_entry->tcam_saddr_count = 0;
            object_network_dec_tcam_users_count(acl_entry->src_addr.u.obj_nw);
            break;
        case ACL_ADDR_OBJECT_GROUP:
            assert(!acl_entry->tcam_saddr_count);    
            assert(!acl_entry->tcam_saddr_prefix);
            assert(!acl_entry->tcam_saddr_wcard);
            object_group_dec_tcam_users_count(acl_entry->src_addr.u.og);
            break;            
    }

   if (acl_entry->tcam_sport_prefix) {
        XFREE(acl_entry->tcam_sport_prefix);
        acl_entry->tcam_sport_prefix = NULL;
   }

    if (acl_entry->tcam_sport_wcard) {
        XFREE(acl_entry->tcam_sport_wcard);
        acl_entry->tcam_sport_wcard = NULL;
   }

    switch (acl_entry->dst_addr.acl_addr_format) {
        case ACL_ADDR_NOT_SPECIFIED:
        case ACL_ADDR_HOST:
        case ACL_ADDR_SUBNET_MASK:
            assert(acl_entry->tcam_daddr_count);    
            assert(acl_entry->tcam_daddr_prefix);
            assert(acl_entry->tcam_daddr_wcard);
            XFREE(acl_entry->tcam_daddr_prefix);
            XFREE(acl_entry->tcam_daddr_wcard);
            acl_entry->tcam_daddr_prefix = NULL;
            acl_entry->tcam_daddr_wcard = NULL;
            acl_entry->tcam_daddr_count = 0;
            break;
        case ACL_ADDR_OBJECT_NETWORK:
            assert(acl_entry->tcam_daddr_count);    
            assert(acl_entry->tcam_daddr_prefix);
            assert(acl_entry->tcam_daddr_wcard);
            acl_entry->tcam_daddr_prefix = NULL;
            acl_entry->tcam_daddr_wcard = NULL;
            acl_entry->tcam_daddr_count = 0;
            object_network_dec_tcam_users_count(acl_entry->dst_addr.u.obj_nw);
            break;
        case ACL_ADDR_OBJECT_GROUP:
            assert(!acl_entry->tcam_daddr_count);    
            assert(!acl_entry->tcam_daddr_prefix);
            assert(!acl_entry->tcam_daddr_wcard);
            object_group_dec_tcam_users_count(acl_entry->dst_addr.u.og);
            break;            
    }

   if (acl_entry->tcam_dport_prefix) {
        XFREE(acl_entry->tcam_dport_prefix);
        acl_entry->tcam_dport_prefix = NULL;
   }

    if (acl_entry->tcam_dport_wcard) {
        XFREE(acl_entry->tcam_dport_wcard);
        acl_entry->tcam_dport_wcard = NULL;
   }
   acl_entry->is_compiled = false;
   acl_entry->expected_tcam_count = acl_entry_get_tcam_entry_count (acl_entry);
}

/* mtrie Callback function definitions */

typedef struct mnode_acl_list_node_ {

    acl_entry_t *acl_entry;
    uint32_t ref_count;
    glthread_t glue;
} mnode_acl_list_node_t;
GLTHREAD_TO_STRUCT(glthread_to_mnode_acl_list_node, mnode_acl_list_node_t, glue);

/* called when a a new ACL Tcam entry is inserted into mtrie
    mnode - leaf node 
    app_Data - ptr to acl_entry_t being inserted
 */
static void
access_list_mtrie_allocate_mnode_data (mtrie_node_t *mnode, void *app_data) {

    glthread_t *list_head;
    acl_entry_t *acl_entry;
    mnode_acl_list_node_t *mnode_acl_list_node;

    assert(!mnode->data);
    assert(app_data);

    acl_entry = (acl_entry_t *)app_data;

    mnode->data = XCALLOC(0, 1, glthread_t);

    list_head = (glthread_t *)mnode->data;

    mnode_acl_list_node = (mnode_acl_list_node_t *)XCALLOC(0, 1, mnode_acl_list_node_t);
    mnode_acl_list_node->acl_entry = acl_entry;
    mnode_acl_list_node->ref_count = 1;
    acl_entry->tcam_total_count++;
    init_glthread(&mnode_acl_list_node->glue);
    glthread_add_next (list_head, &mnode_acl_list_node->glue);
}

/* Called When mtrie hits the duplicate entry while inserting a new TCAM entry
    mnode - leaf node
    app_data - acl_entry_t whose member tcam is being inserted
*/
static void
access_list_mtrie_duplicate_entry_found (mtrie_node_t *mnode, void *app_data) {

    bool self_found = false;
    uint32_t other_conflicts = 0;
    glthread_t *list_head, *curr;
    acl_entry_t *acl_entry;
    mnode_acl_list_node_t *mnode_acl_list_node = NULL;
    mnode_acl_list_node_t *mnode_acl_list_node2 = NULL;

    acl_entry = (acl_entry_t *)app_data;
    list_head = (glthread_t *)mnode->data;

    ITERATE_GLTHREAD_BEGIN(list_head, curr) {

        mnode_acl_list_node = glthread_to_mnode_acl_list_node(curr);

        if (acl_entry != mnode_acl_list_node->acl_entry) {
             mnode_acl_list_node->acl_entry->tcam_other_conflicts_count++;
             other_conflicts++;
        }
        else {
            acl_entry->tcam_self_conflicts_count++;
            mnode_acl_list_node->ref_count++;
            self_found = true;
        }
        
    } ITERATE_GLTHREAD_END(list_head, curr);


    acl_entry->tcam_total_count++;
    acl_entry->tcam_other_conflicts_count += other_conflicts;

    if (self_found) return;

    ITERATE_GLTHREAD_BEGIN(list_head, curr) {

        mnode_acl_list_node = glthread_to_mnode_acl_list_node(curr);

        if (acl_entry->seq_no > mnode_acl_list_node->acl_entry->seq_no) {
            continue;
        }
        break;

    } ITERATE_GLTHREAD_END(list_head, curr);

    mnode_acl_list_node2 = (mnode_acl_list_node_t *)XCALLOC(0, 1, mnode_acl_list_node_t);
    mnode_acl_list_node2->acl_entry = acl_entry;
    mnode_acl_list_node2->ref_count = 1;
    init_glthread(&mnode_acl_list_node2->glue);

    if (curr) {
        glthread_add_before(&mnode_acl_list_node->glue, &mnode_acl_list_node2->glue);
    }
    else {
        glthread_add_last(list_head, &mnode_acl_list_node2->glue);
    }
}

/* Called When TCAM entry is deleted from mtrie. 
    mnode - leaf node
    app_data - acl_entry whose tcam member is being deleted */
static void
access_list_mtrie_deallocate_mnode_data (mtrie_node_t *mnode, void *app_data) {

    glthread_t *curr, *list_head;
    acl_entry_t *acl_entry = (acl_entry_t *)app_data;
    mnode_acl_list_node_t *mnode_acl_list_node;
    
    list_head = (glthread_t *)mnode->data;

    ITERATE_GLTHREAD_BEGIN(list_head, curr) {

        mnode_acl_list_node = glthread_to_mnode_acl_list_node(curr);
        
        if (mnode_acl_list_node->acl_entry != acl_entry) {
            mnode_acl_list_node->acl_entry->tcam_other_conflicts_count--;
        }
        else {
            acl_entry->tcam_total_count--;
            if (mnode_acl_list_node->ref_count > 1) {
                mnode_acl_list_node->ref_count--;
                acl_entry->tcam_self_conflicts_count--;
            }
            else {
                remove_glthread(&mnode_acl_list_node->glue);
                XFREE(mnode_acl_list_node);
            }
        }
    }ITERATE_GLTHREAD_END(list_head, curr);

    if (IS_GLTHREAD_LIST_EMPTY(list_head))
    {
        XFREE(list_head);
        mnode->data = NULL;
    }
}

void
access_list_mtrie_app_data_free_cbk (mtrie_node_t *mnode) {

    glthread_t *curr, *list_head;
    mnode_acl_list_node_t *mnode_acl_list_node;
    
    if (!mnode->data) return;

    list_head = (glthread_t *)mnode->data;

    ITERATE_GLTHREAD_BEGIN(list_head, curr) {

        mnode_acl_list_node = glthread_to_mnode_acl_list_node(curr);
        remove_glthread(&mnode_acl_list_node->glue);
        XFREE(mnode_acl_list_node);

    }ITERATE_GLTHREAD_END(list_head, curr);

    XFREE(list_head);
    mnode->data = NULL;
}

/* Convert the ACL entry into TCAM entry format */
void
acl_compile (acl_entry_t *acl_entry) {

    uint8_t proto_layer = 0;

    if (acl_entry->is_compiled) {
        sprintf (tlb, "%s : Acl %s-%u is already compiled\n", 
            FWALL_ACL, acl_entry->access_list->name, acl_entry->seq_no);
        tcp_trace(0, 0, tlb);
        return;
    }

    sprintf (tlb, "%s : Acl %s-%u is being compiled\n", 
            FWALL_ACL, acl_entry->access_list->name, acl_entry->seq_no);
    tcp_trace(0, 0, tlb);

    assert(acl_entry->tcam_saddr_count == 0);
    assert(!acl_entry->tcam_saddr_prefix);
    assert(!acl_entry->tcam_saddr_wcard);
    assert(acl_entry->tcam_daddr_count == 0);
    assert(!acl_entry->tcam_daddr_prefix);
    assert(!acl_entry->tcam_daddr_wcard);

    if (acl_entry->proto == ACL_PROTO_ANY) {
        /* User has feed "any" in place of protocol in ACL */
        /* Fill L4 proto field and L3 proto field with Dont Care */
        acl_entry->tcam_l4proto_wcard = 0xFFFF; 
        acl_entry->tcam_l3proto_wcard = 0xFFFF; 
        goto SRC_ADDR;
    }

    proto_layer = tcpip_protocol_classification(
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

    switch (acl_entry->src_addr.acl_addr_format) {

        case ACL_ADDR_NOT_SPECIFIED:
            acl_entry->tcam_saddr_count = 1;
            acl_entry->tcam_saddr_prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_saddr_count);
            acl_entry->tcam_saddr_wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_saddr_count);
            (*acl_entry->tcam_saddr_prefix)[0] = 0;
            (*acl_entry->tcam_saddr_wcard)[0] = 0xFFFFFFFF;
            break;
        case ACL_ADDR_HOST:
            acl_entry->tcam_saddr_count = 1;
            acl_entry->tcam_saddr_prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_saddr_count);
            acl_entry->tcam_saddr_wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_saddr_count);
            (*acl_entry->tcam_saddr_prefix)[0] = htonl(acl_entry->src_addr.u.host_addr);
            (*acl_entry->tcam_saddr_wcard)[0] = 0;
            break;
        case ACL_ADDR_SUBNET_MASK:
             acl_entry->tcam_saddr_count = 1;
             acl_entry->tcam_saddr_prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_saddr_count);
            acl_entry->tcam_saddr_wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_saddr_count);
            (*acl_entry->tcam_saddr_prefix)[0] =
                htonl(acl_entry->src_addr.u.subnet.subnet_addr & acl_entry->src_addr.u.subnet.subnet_mask);
            (*acl_entry->tcam_saddr_wcard)[0] = htonl(~acl_entry->src_addr.u.subnet.subnet_mask);
            break;
        case ACL_ADDR_OBJECT_NETWORK:
            object_network_borrow_tcam_data(acl_entry->src_addr.u.obj_nw,
                &acl_entry->tcam_saddr_count,
                &acl_entry->tcam_saddr_prefix,
                &acl_entry->tcam_saddr_wcard);
            break;
        case ACL_ADDR_OBJECT_GROUP:
            object_group_inc_tcam_users_count(acl_entry->src_addr.u.og);
            break;
            default : ;
    }

    /* Src Port Range */
    if (!acl_entry->tcam_sport_prefix) {
        acl_entry->tcam_sport_prefix = (uint16_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        XCALLOC_BUFF(0, sizeof(uint16_t) * sizeof(*acl_entry->tcam_sport_prefix));
    }
    else {
        memset(acl_entry->tcam_sport_prefix, 0, 
        sizeof(uint16_t) * sizeof(*acl_entry->tcam_sport_prefix));
    }
    if (!acl_entry->tcam_sport_wcard) {
        acl_entry->tcam_sport_wcard = (uint16_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        XCALLOC_BUFF(0, sizeof(uint16_t) * sizeof(*acl_entry->tcam_sport_wcard));
    }
    else {
        memset(acl_entry->tcam_sport_wcard, 0, 
        sizeof(uint16_t) * sizeof(*acl_entry->tcam_sport_wcard));
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

    switch (acl_entry->dst_addr.acl_addr_format) {

        case ACL_ADDR_NOT_SPECIFIED:
            acl_entry->tcam_daddr_count = 1;
            acl_entry->tcam_daddr_prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_daddr_count);
            acl_entry->tcam_daddr_wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_daddr_count);
            (*acl_entry->tcam_daddr_prefix)[0] = 0;
            (*acl_entry->tcam_daddr_wcard)[0] = 0xFFFFFFFF;
            break;
        case ACL_ADDR_HOST:
            acl_entry->tcam_daddr_count = 1;
            acl_entry->tcam_daddr_prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_daddr_count);
            acl_entry->tcam_daddr_wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_daddr_count);
            (*acl_entry->tcam_daddr_prefix)[0] = htonl(acl_entry->dst_addr.u.host_addr);
            (*acl_entry->tcam_daddr_wcard)[0] = 0;
            break;
        case ACL_ADDR_SUBNET_MASK:
             acl_entry->tcam_daddr_count = 1;
             acl_entry->tcam_daddr_prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_daddr_count);
            acl_entry->tcam_daddr_wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * acl_entry->tcam_daddr_count);
            (*acl_entry->tcam_daddr_prefix)[0] =
                htonl(acl_entry->dst_addr.u.subnet.subnet_addr & acl_entry->dst_addr.u.subnet.subnet_mask);
            (*acl_entry->tcam_daddr_wcard)[0] = htonl(~acl_entry->dst_addr.u.subnet.subnet_mask);
            break;
        case ACL_ADDR_OBJECT_NETWORK:
            object_network_borrow_tcam_data(acl_entry->dst_addr.u.obj_nw,
                &acl_entry->tcam_daddr_count,
                &acl_entry->tcam_daddr_prefix,
                &acl_entry->tcam_daddr_wcard);
            break;
        case ACL_ADDR_OBJECT_GROUP:
            object_group_inc_tcam_users_count(acl_entry->dst_addr.u.og);
            break;
            default : ;
    }

    /* Dst Port Range */
    if (!acl_entry->tcam_dport_prefix) {
        acl_entry->tcam_dport_prefix = (uint16_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        XCALLOC_BUFF(0, sizeof(uint16_t) * sizeof(*acl_entry->tcam_dport_prefix));
    }
    else {
        memset(acl_entry->tcam_dport_prefix, 0, sizeof(uint16_t) * sizeof(*acl_entry->tcam_dport_prefix));
    }
    if (!acl_entry->tcam_dport_wcard) {
        acl_entry->tcam_dport_wcard = (uint16_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
        XCALLOC_BUFF(0, sizeof(uint16_t) * sizeof(*acl_entry->tcam_dport_wcard));
    }
    else {
        memset(acl_entry->tcam_dport_wcard, 0, sizeof(uint16_t) * sizeof(*acl_entry->tcam_dport_wcard));
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

     acl_entry->is_compiled = true;
     assert(acl_entry->expected_tcam_count = 
        acl_entry_get_tcam_entry_count (acl_entry));
}

access_list_t *
access_list_lookup_by_name (node_t *node, char *access_list_name) {

    glthread_t *curr;
    access_list_t *acc_lst;

    ITERATE_GLTHREAD_BEGIN(&node->access_lists_db, curr) {

        acc_lst = glthread_to_access_list(curr);
        if (string_compare(acc_lst->name, 
                           access_list_name, 
                            ACCESS_LIST_MAX_NAMELEN) == 0) {
            return acc_lst;
        }
    } ITERATE_GLTHREAD_END(&node->access_lists_db, curr);

    return NULL;
}

mtrie_t *
access_list_get_new_tcam_mtrie () {

    mtrie_t *mtrie = (mtrie_t *)XCALLOC(0, 1, mtrie_t);
    init_mtrie(mtrie, ACL_PREFIX_LEN, access_list_mtrie_app_data_free_cbk);
    return mtrie;
}

access_list_t *
acl_create_new_access_list(char *access_list_name) {

    access_list_t *acc_lst = (access_list_t *)XCALLOC(0, 1, access_list_t);
    string_copy((char *)acc_lst->name, access_list_name, ACCESS_LIST_MAX_NAMELEN);
    init_glthread(&acc_lst->head);
    init_glthread(&acc_lst->glue);
    pthread_rwlock_init(&acc_lst->mtrie_update_lock, NULL);
    acc_lst->mtrie = access_list_get_new_tcam_mtrie();
    acc_lst->ref_count = 0;
    return acc_lst;
}

void
access_list_add_acl_entry (
                                access_list_t * access_list,
                                acl_entry_t *acl_entry) {

    glthread_t *curr;
    acl_entry_t *acl_entry_prev;
   
    if (acl_entry->seq_no == 0) {

        glthread_add_last(&access_list->head, &acl_entry->glue);

        if (glthread_get_next(&access_list->head) == &acl_entry->glue) {
            acl_entry->seq_no = 1;
        }
        else {
            acl_entry_prev = glthread_to_acl_entry(glthread_get_prev(&acl_entry->glue));
            acl_entry->seq_no = acl_entry_prev->seq_no + 1;
        }
        return;
    }

      ITERATE_GLTHREAD_BEGIN(&access_list->head, curr) {

            acl_entry_prev = glthread_to_acl_entry(curr);
            if (acl_entry->seq_no > acl_entry_prev->seq_no) continue;
            break;
      }  ITERATE_GLTHREAD_END(&access_list->head, curr);

    if (acl_entry_prev) {
        glthread_add_next (&acl_entry_prev->glue, &acl_entry->glue);
    }
    else {
        glthread_add_next (&access_list->head, &acl_entry->glue);
    }

     access_list_reenumerate_seq_no (access_list, &acl_entry->glue);

    assert(!acl_entry->access_list);
    acl_entry->access_list = access_list;
}

 void 
 access_list_check_delete(access_list_t *access_list) {

    assert(IS_GLTHREAD_LIST_EMPTY(&access_list->head));
    assert(IS_GLTHREAD_LIST_EMPTY(&access_list->glue));
    assert(!access_list->mtrie);
    assert(access_list->ref_count == 0);
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

    access_list = access_list_lookup_by_name(node, access_list_name);

    if (!access_list) {
        access_list = acl_create_new_access_list(access_list_name);
        new_access_list = true;
    }

    access_list_add_acl_entry (access_list, acl_entry);

    if (new_access_list) {
        glthread_add_next (&node->access_lists_db, &access_list->glue);
        access_list_reference (access_list);
    }

    if (access_list_should_compile (access_list)) {

        acl_compile(acl_entry);

        /* Async Method */
        if (acl_entry->expected_tcam_count > ACL_ENTRY_TCAM_COUNT_THRESHOLD) {
            access_list_trigger_install_job(node, access_list, NULL);
        }
        else {
            /* Sync Method */
            pthread_rwlock_wrlock(&access_list->mtrie_update_lock);
            acl_entry_install(access_list, acl_entry);
            pthread_rwlock_unlock(&access_list->mtrie_update_lock);
        }
    }

    return true;
}

bool
access_list_delete_complete(node_t *node, access_list_t *access_list) {

    glthread_t *curr;
    acl_entry_t *acl_entry;

    if (access_list->ref_count > 1) {
        cprintf ("Access List is in use, Cannot delete\n");
        return false;
    }

    if (access_list->mtrie) {
        access_list_purge_tcam_mtrie(node, access_list->mtrie);
        access_list->mtrie = NULL;
    }

    ITERATE_GLTHREAD_BEGIN(&access_list->head, curr) {

        acl_entry = glthread_to_acl_entry(curr);
        remove_glthread(&acl_entry->glue);
        acl_entry_free(acl_entry);

    }ITERATE_GLTHREAD_END(&access_list->head, curr);

    remove_glthread(&access_list->glue);
    access_list->ref_count--;
    pthread_rwlock_destroy(&access_list->mtrie_update_lock);
    access_list_check_delete(access_list);
    cprintf ("Access List Deleted\n");
    return true;
}


void access_list_reference(access_list_t *acc_lst) {

    acc_lst->ref_count++;
}

void access_list_dereference(node_t *node, access_list_t *acc_lst) {

    if (acc_lst->ref_count == 0) {
        access_list_delete_complete(node, acc_lst);
        return;
    }

    acc_lst->ref_count--;

    if (acc_lst->ref_count == 0) {
        access_list_delete_complete(node, acc_lst);
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
    glthread_t *list_head;
    acl_entry_t *hit_acl = NULL;
    mtrie_node_t *hit_node = NULL;
    mnode_acl_list_node_t *mnode_acl_list_node;

    bitmap_t input;
    bitmap_init(&input, ACL_PREFIX_LEN);

    bitmap_fill_with_params(&input, l3proto, l4proto, src_addr, dst_addr, src_port, dst_port);
    
    pthread_rwlock_rdlock(&acc_lst->mtrie_update_lock);

    hit_node = mtrie_longest_prefix_match_search(
                            acc_lst->mtrie, &input);

    /* Deny by default */
    if (!hit_node) {
        action = ACL_DENY;
        goto done;
    }

    list_head = (glthread_t *)(hit_node->data);
    assert(list_head);
    assert(!IS_GLTHREAD_LIST_EMPTY(list_head));

    mnode_acl_list_node = glthread_to_mnode_acl_list_node(glthread_get_next(list_head));
    hit_acl = mnode_acl_list_node->acl_entry;
    hit_acl->hit_count++;
    action = hit_acl->action;
    goto done;

    done:
    pthread_rwlock_unlock(&acc_lst->mtrie_update_lock);
    bitmap_free_internal(&input);
    return action;
}

acl_action_t 
access_list_evaluate_pkt_block (access_list_t *access_list, pkt_block_t *pkt_block) {

    byte *pkt;
    pkt_size_t pkt_size;
    ip_hdr_t *ip_hdr = NULL;
    ethernet_hdr_t *eth_hdr = NULL;

    hdr_type_t starting_hdr = pkt_block_get_starting_hdr (pkt_block);

    uint16_t l4proto = 0;
    uint32_t src_ip = 0,
                  dst_ip = 0;
                 
    uint16_t src_port = 0,
                  dst_port = 0;

    switch (starting_hdr)
    {
    case ETH_HDR:
    {
        eth_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

        if (eth_hdr->type == ETH_IP)
        {
            ip_hdr = (ip_hdr_t *)(eth_hdr->payload);
            src_ip = ip_hdr->src_ip;
            dst_ip = ip_hdr->dst_ip;
            l4proto = ip_hdr->protocol;

            switch (l4proto)
            {
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

            return access_list_evaluate(access_list, 
                                                ETH_IP, 
                                                l4proto,
                                                src_ip,
                                                dst_ip,
                                                src_port,
                                                dst_port);
        }
    }
    break;
    case IP_HDR:
        {
            ip_hdr =  (ip_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);
            src_ip = ip_hdr->src_ip;
            dst_ip = ip_hdr->dst_ip;
            l4proto = ip_hdr->protocol;

            switch (l4proto)
            {
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

            return access_list_evaluate(access_list, 
                                                ETH_IP, 
                                                l4proto,
                                                src_ip,
                                                dst_ip,
                                                src_port,
                                                dst_port);
        }
        break;
    default: ;
    }
    return ACL_DENY;
}

acl_action_t
access_list_evaluate_ip_packet (node_t *node, 
                                                    Interface *intf, 
                                                    ip_hdr_t *ip_hdr,
                                                    bool ingress) {

    uint16_t l4proto = 0;
    uint32_t src_ip = 0,
                  dst_ip = 0;
                 
    uint16_t src_port = 0,
                  dst_port = 0;

    access_list_t *access_list;
    
    access_list = ingress ? intf-> l3_ingress_acc_lst2 : \
                                        intf->l3_egress_acc_lst2;

    if (!access_list) return ACL_PERMIT;

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

    return access_list_evaluate(access_list, 
                                                ETH_IP, 
                                                l4proto,
                                                src_ip,
                                                dst_ip,
                                                src_port,
                                                dst_port);
}

acl_action_t
access_list_evaluate_ethernet_packet (node_t *node, 
                                                    Interface *intf, 
                                                    pkt_block_t *pkt_block,
                                                    bool ingress) {

    return ACL_PERMIT;
}

/* Access Group Mgmt APIs */
/* Return 0 on success */
int 
access_group_config(node_t *node, 
                                   Interface *intf, 
                                   char *dirn, 
                                   access_list_t *acc_lst) {

    if (string_compare(dirn, "in", 2) == 0 && strlen(dirn) == 2) {
        if (intf->l3_ingress_acc_lst2) {
            cprintf ("Error : Access List already applied\n");
            return -1;
        }
    }
    else if (string_compare(dirn, "out", 3) == 0 && strlen(dirn) == 3) {
        if (intf->l3_egress_acc_lst2) {
            cprintf ("Error : Access List already applied\n");
            return -1;
        }
    }
    else {
        cprintf ("Error : Direction can be - 'in' or 'out' only\n");
        return -1;
    }

    if (string_compare(dirn, "in", 2) == 0 && strlen(dirn) == 2) {
        intf->l3_ingress_acc_lst2 = acc_lst;
        access_list_reference(acc_lst);
    }
    else if (string_compare(dirn, "out", 3) == 0 && strlen(dirn) == 3) {
        intf->l3_egress_acc_lst2 = acc_lst;
        access_list_reference(acc_lst);
    }

    if (!access_list_is_compiled (acc_lst) &&
         access_list_should_compile (acc_lst)) {

        access_list_trigger_install_job(node, acc_lst, NULL);
    }

    return 0;
}

int 
access_group_unconfig (node_t *node, 
                                       Interface *intf, 
                                       char *dirn, 
                                      access_list_t *acc_lst) {
    
    if (string_compare(dirn, "in", 2) == 0 && strlen(dirn) == 2) {
        if (intf->l3_ingress_acc_lst2 != acc_lst) {
            cprintf ("Error : Access List not applied\n");
            return -1;
        }
    }
    else if (string_compare(dirn, "out", 3) == 0 && strlen(dirn) == 3) {
        if (intf->l3_egress_acc_lst2 != acc_lst) {
            cprintf ("Error : Access List not applied\n");
            return -1;
        }
    }
    else {
        cprintf ("Error : Direction can be - 'in' or 'out' only\n");
        return -1;
    }

    access_list_reference(acc_lst);  

    if (string_compare(dirn, "in", 2) == 0 && strlen(dirn) == 2) {
        intf->l3_ingress_acc_lst2 = NULL;
        access_list_dereference(node, acc_lst);  
    }
    else if (string_compare(dirn, "out", 3) == 0 && strlen(dirn) == 3) {
        intf->l3_egress_acc_lst2 = NULL;
        access_list_dereference(node, acc_lst);  
    }

    if ( access_list_is_compiled(acc_lst) &&
           access_list_should_decompile (acc_lst)) {

        access_list_trigger_uninstall_job (node, acc_lst, NULL);
    }

    access_list_dereference(node, acc_lst);  
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
acl_get_member_tcam_entry (
                acl_entry_t *acl_entry,                              /* Input */
                acl_tcam_iterator_t *acl_tcam_src_it,      /* Input */
                acl_tcam_iterator_t * src_port_it,             /* Input */
                acl_tcam_iterator_t *acl_tcam_dst_it,      /* Input */
                acl_tcam_iterator_t * dst_port_it,             /* Input */
                acl_tcam_t *tcam_entry) {                       /* output */

    uint16_t bytes_copied = 0;

    bitmap_t *prefix = &tcam_entry->prefix;
    bitmap_t *mask = &tcam_entry->mask;

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
    memcpy(prefix_ptr4, acl_tcam_src_it->addr_prefix, sizeof(*prefix_ptr4));
    memcpy(mask_ptr4, acl_tcam_src_it->addr_wcard, sizeof(*mask_ptr4));
    prefix_ptr4++; mask_ptr4++;
    prefix_ptr2 = (uint16_t *)prefix_ptr4;
    mask_ptr2 = (uint16_t *)mask_ptr4;
    bytes_copied += sizeof(*prefix_ptr4);

    /* Src Port */
    memcpy(prefix_ptr2, &((*acl_entry->tcam_sport_prefix)[src_port_it->index]), sizeof(*prefix_ptr2));
    memcpy(mask_ptr2, &((*acl_entry->tcam_sport_wcard)[src_port_it->index]), sizeof(*mask_ptr2));
    prefix_ptr2++;
    mask_ptr2++;
    prefix_ptr4 = (uint32_t *)prefix_ptr2;
    mask_ptr4 = (uint32_t *)mask_ptr2;
    bytes_copied += sizeof(*prefix_ptr2);

    /* Dst ip Address & Mask */
    memcpy(prefix_ptr4, acl_tcam_dst_it->addr_prefix, sizeof(*prefix_ptr4));
    memcpy(mask_ptr4, acl_tcam_dst_it->addr_wcard, sizeof(*mask_ptr4));
    prefix_ptr4++; mask_ptr4++;
    prefix_ptr2 = (uint16_t *)prefix_ptr4;
    mask_ptr2 = (uint16_t *)mask_ptr4;
    bytes_copied += sizeof(*prefix_ptr4);

    /* Dst Port */
    memcpy(prefix_ptr2, &((*acl_entry->tcam_dport_prefix)[dst_port_it->index]), sizeof(*prefix_ptr2));
    memcpy(mask_ptr2, &((*acl_entry->tcam_dport_wcard)[dst_port_it->index]), sizeof(*mask_ptr2));
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
                                acl_entry_t *acl_entry) {

    mtrie_node_t *mnode;
    mtrie_ops_result_code_t rc;
    acl_tcam_t tcam_entry_template;
    acl_tcam_iterator_t src_it;
    acl_tcam_iterator_t dst_it;
    acl_tcam_iterator_t src_port_it, dst_port_it;

    if (!acl_entry->is_installed) {
        sprintf(tlb, "%s : Acl %s-%u is already un-installed\n", FWALL_ACL,
            access_list->name, acl_entry->seq_no);
        tcp_trace(0, 0, tlb);
        return;
    }

    assert(acl_entry->tcam_total_count);

    bitmap_init(&tcam_entry_template.prefix, ACL_PREFIX_LEN);
    bitmap_init(&tcam_entry_template.mask, ACL_PREFIX_LEN);
    init_glthread(&tcam_entry_template.glue);

    sprintf(tlb, "%s : Acl %s-%u tcam un-installation begin\n", FWALL_ACL,
            access_list->name, acl_entry->seq_no);
    tcp_trace(0, 0, tlb);

    acl_tcam_iterator_init(acl_entry, &src_it, acl_iterator_src_addr);
    acl_tcam_iterator_init(acl_entry, &dst_it, acl_iterator_dst_addr);
    acl_tcam_iterator_init(acl_entry, &src_port_it, acl_iterator_src_port);
    acl_tcam_iterator_init(acl_entry, &dst_port_it, acl_iterator_dst_port);
    acl_tcam_iterator_first(&src_it);
    acl_tcam_iterator_first(&dst_it);
    acl_tcam_iterator_first(&src_port_it);
    acl_tcam_iterator_first(&dst_port_it);

    do {

        acl_get_member_tcam_entry(
            acl_entry,
            &src_it,
            &src_port_it,
            &dst_it,
            &dst_port_it,
            &tcam_entry_template);

#if 0
            cprintf ("Un-Installing TCAM Entry  # %u: \n", acl_entry->total_tcam_count);
            bitmap_print(&tcam_entry_template.prefix);
            bitmap_print(&tcam_entry_template.mask);
#endif
        mnode = mtrie_exact_prefix_match_search(
            access_list->mtrie,
            &tcam_entry_template.prefix,
            &tcam_entry_template.mask);

        assert(mnode);

        access_list_mtrie_deallocate_mnode_data(mnode, acl_entry);

        if (mnode->data == NULL) {
            mtrie_delete_leaf_node(access_list->mtrie, mnode);
        }
    } while (acl_iterators_increment(
        &src_it,
        &dst_it,
        &src_port_it,
        &dst_port_it));

    acl_tcam_iterator_deinit(&src_it);
    acl_tcam_iterator_deinit(&dst_it);
    acl_tcam_iterator_deinit(&src_port_it);
    acl_tcam_iterator_deinit(&dst_port_it);
    
    bitmap_free_internal(&tcam_entry_template.prefix);
    bitmap_free_internal(&tcam_entry_template.mask);
    acl_entry->is_installed = false;
    sprintf(tlb, "%s : Acl %s-%u tcam un-installation finished\n", FWALL_ACL,
            access_list->name, acl_entry->seq_no);
    tcp_trace(0, 0, tlb);
}


/* Install all TCAM entries of a given ACL */
void
acl_entry_install (access_list_t *access_list, acl_entry_t *acl_entry) {

    mtrie_node_t *mnode;
    mtrie_ops_result_code_t rc;
    acl_tcam_t tcam_entry_template;    
    acl_tcam_iterator_t src_it;
    acl_tcam_iterator_t dst_it;
    acl_tcam_iterator_t src_port_it, dst_port_it;

    if (acl_entry->is_installed) {
        sprintf(tlb, "%s : Acl %s-%u is already installed\n", FWALL_ACL,
            access_list->name, acl_entry->seq_no);
        tcp_trace(0, 0, tlb);
        return;
    }

    assert(acl_entry->tcam_total_count == 0);
    assert(acl_entry->tcam_other_conflicts_count == 0);
    assert(acl_entry->tcam_self_conflicts_count == 0);

    bitmap_init(&tcam_entry_template.prefix, ACL_PREFIX_LEN);
    bitmap_init(&tcam_entry_template.mask, ACL_PREFIX_LEN);
    init_glthread(&tcam_entry_template.glue);

    sprintf(tlb, "%s : Acl %s-%u tcam installation begin\n", FWALL_ACL,
            access_list->name, acl_entry->seq_no);
    tcp_trace(0, 0, tlb);

    acl_tcam_iterator_init(acl_entry, &src_it, acl_iterator_src_addr);
    acl_tcam_iterator_init(acl_entry, &dst_it, acl_iterator_dst_addr);
    acl_tcam_iterator_init(acl_entry, &src_port_it, acl_iterator_src_port);
    acl_tcam_iterator_init(acl_entry, &dst_port_it, acl_iterator_dst_port);
    acl_tcam_iterator_first(&src_it);
    acl_tcam_iterator_first(&dst_it);
    acl_tcam_iterator_first(&src_port_it);
    acl_tcam_iterator_first(&dst_port_it);

    acl_entry->installation_start_time = time(NULL);
    
    do {

        acl_get_member_tcam_entry(
            acl_entry,
            &src_it,
            &src_port_it,
            &dst_it,
            &dst_port_it,
            &tcam_entry_template);

#if 0
            cprintf ("Installing TCAM Entry  # %u\n",  acl_entry->tcam_total_count);
            bitmap_print(&tcam_entry_template.prefix);
            bitmap_print(&tcam_entry_template.mask);
#endif

        rc = (mtrie_insert_prefix(
            access_list->mtrie,
            &tcam_entry_template.prefix,
            &tcam_entry_template.mask,
            ACL_PREFIX_LEN,
            &mnode));

        switch (rc)
        {
        case MTRIE_INSERT_SUCCESS:
            access_list_mtrie_allocate_mnode_data(mnode, (void *)acl_entry);
            break;
        case MTRIE_INSERT_DUPLICATE:
            access_list_mtrie_duplicate_entry_found(mnode, (void *)acl_entry);
            break;
        case MTRIE_INSERT_FAILED:
            assert(0);
        }

    } while (acl_iterators_increment (
                &src_it,
                &dst_it,
                &src_port_it,
                &dst_port_it));

    acl_entry->installation_end_time = time(NULL);

    acl_tcam_iterator_deinit(&src_it);
    acl_tcam_iterator_deinit(&dst_it);
    acl_tcam_iterator_deinit(&src_port_it);
    acl_tcam_iterator_deinit(&dst_port_it);

    bitmap_free_internal(&tcam_entry_template.prefix);
    bitmap_free_internal(&tcam_entry_template.mask);
    acl_entry->is_installed = true;
    sprintf(tlb, "%s : Acl %s-%u tcam installation finished\n", FWALL_ACL,
            access_list->name, acl_entry->seq_no);
    tcp_trace(0, 0, tlb);
 }

static void 
acl_entry_link_object_networks(acl_entry_t *acl_entry, obj_nw_t *objnw) {

    if (!objnw) return;

    objects_linkage_db_t *db = objnw->db;

    if (!db) {

        objnw->db = (objects_linkage_db_t *)XCALLOC(0, 1, objects_linkage_db_t);
        db = objnw->db;
        init_glthread(&db->acls_list);
        init_glthread(&db->nat_list);
    }

    objects_linked_acl_thread_node_t *obj_nw_linked_acl_thread_node = 
        (objects_linked_acl_thread_node_t *)XCALLOC(0, 1, objects_linked_acl_thread_node_t);

    obj_nw_linked_acl_thread_node->acl = acl_entry;
    init_glthread(&obj_nw_linked_acl_thread_node->glue);

    glthread_add_last(&db->acls_list, &obj_nw_linked_acl_thread_node->glue);
    objnw->ref_count++;
}

static void
acl_entry_delink_object_networks(acl_entry_t *acl_entry, obj_nw_t *objnw) {

    glthread_t *curr;
    objects_linkage_db_t *db;
    objects_linked_acl_thread_node_t *obj_nw_linked_acl_thread_node;
    
    if (!objnw) return;

    db  = objnw->db;

    assert(db);

    ITERATE_GLTHREAD_BEGIN(&db->acls_list, curr) {

        obj_nw_linked_acl_thread_node = glue_to_objects_linked_acl_thread_node(curr);
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

static void 
acl_entry_link_object_group(acl_entry_t *acl_entry, object_group_t *og) {

    if (!og) return;

    objects_linkage_db_t *db = og->db;

    if (!db) {

        og->db = (objects_linkage_db_t *)XCALLOC(0, 1, objects_linkage_db_t);
        db = og->db;
        init_glthread(&db->acls_list);
        init_glthread(&db->nat_list);
    }

    objects_linked_acl_thread_node_t *obj_nw_linked_acl_thread_node = 
        (objects_linked_acl_thread_node_t *)XCALLOC(0, 1, objects_linked_acl_thread_node_t);

    obj_nw_linked_acl_thread_node->acl = acl_entry;
    init_glthread(&obj_nw_linked_acl_thread_node->glue);

    glthread_add_last(&db->acls_list, &obj_nw_linked_acl_thread_node->glue);
    og->ref_count++;
}

static void
acl_entry_delink_object_group(acl_entry_t *acl_entry, object_group_t *og) {

    glthread_t *curr;
    objects_linkage_db_t *db;
    objects_linked_acl_thread_node_t *obj_nw_linked_acl_thread_node;
    
    if (!og) return;

    db  = og->db;

    assert(db);

    ITERATE_GLTHREAD_BEGIN(&db->acls_list, curr) {

        obj_nw_linked_acl_thread_node = glue_to_objects_linked_acl_thread_node(curr);
        if (obj_nw_linked_acl_thread_node->acl == acl_entry) {
            remove_glthread(&obj_nw_linked_acl_thread_node->glue);
            XFREE(obj_nw_linked_acl_thread_node);
            og->ref_count--;

            if (IS_GLTHREAD_LIST_EMPTY(&db->acls_list) &&
                    IS_GLTHREAD_LIST_EMPTY(&db->nat_list)) {

                XFREE(db);
                og->db = NULL;
                assert(!og->ref_count);
            }
            return;
        }
    } ITERATE_GLTHREAD_END(&db->acls_list, curr);
    assert(0);
}

/* Linking and Delinking APIs for Object Groups */
void
acl_entry_delink_src_object_group(acl_entry_t *acl_entry) {

    object_group_t *og;

    og = acl_get_src_network_object_group(acl_entry);

    if (og) {
        acl_entry_delink_object_group(acl_entry, og);
        acl_entry->src_addr.u.og = NULL;
        acl_entry->src_addr.acl_addr_format = ACL_ADDR_NOT_SPECIFIED;
    }
}

void
acl_entry_delink_dst_object_group(acl_entry_t *acl_entry) {

    object_group_t *og;

    og = acl_get_dst_network_object_group(acl_entry);

    if (og) {
        acl_entry_delink_object_group(acl_entry, og);
        acl_entry->dst_addr.u.og = NULL;
        acl_entry->dst_addr.acl_addr_format = ACL_ADDR_NOT_SPECIFIED;
    }
}

void
acl_entry_link_src_object_group(acl_entry_t *acl_entry, object_group_t *og) {

    if (!og) return;
    
    assert(!acl_get_src_network_object_group(acl_entry));

    acl_entry_link_object_group(acl_entry, og);

    acl_entry->src_addr.u.og = og;
    acl_entry->src_addr.acl_addr_format = ACL_ADDR_OBJECT_GROUP;
}

void
acl_entry_link_dst_object_group(acl_entry_t *acl_entry, object_group_t *og) {

    if (!og) return;
    
    assert(!acl_get_dst_network_object_group(acl_entry));

    acl_entry_link_object_group(acl_entry, og);

    acl_entry->dst_addr.u.og = og;
    acl_entry->dst_addr.acl_addr_format = ACL_ADDR_OBJECT_GROUP;
}

/* Linking and Delinking APIs for Object Networks */
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

void
acl_entry_reset_counters(acl_entry_t *acl_entry) {

    acl_entry->tcam_total_count = 0;
    acl_entry->tcam_other_conflicts_count = 0;
    acl_entry->tcam_self_conflicts_count = 0;
}

void
access_list_reset_acl_counters (access_list_t *access_list) {

    glthread_t *curr;
    acl_entry_t *acl_entry;

    ITERATE_GLTHREAD_BEGIN(&access_list->head, curr) {

        acl_entry = glthread_to_acl_entry(curr);
        acl_entry_reset_counters (acl_entry);

    } ITERATE_GLTHREAD_END(&access_list->head, curr);    
}

void
access_list_print_acl_bitmap (access_list_t *access_list, acl_entry_t *acl_entry) {

    acl_tcam_iterator_t src_it;
    acl_tcam_iterator_t dst_it;
    acl_tcam_t tcam_entry_template;
    acl_tcam_iterator_t src_port_it, dst_port_it;          

    cprintf (" access-list %s ",  access_list->name);

    acl_print(acl_entry);
    cprintf("\n");

    bitmap_init(&tcam_entry_template.prefix, ACL_PREFIX_LEN);
    bitmap_init(&tcam_entry_template.mask, ACL_PREFIX_LEN);
    init_glthread(&tcam_entry_template.glue);

    acl_tcam_iterator_init(acl_entry, &src_it, acl_iterator_src_addr);
    acl_tcam_iterator_init(acl_entry, &dst_it, acl_iterator_dst_addr);
    acl_tcam_iterator_init(acl_entry, &src_port_it, acl_iterator_src_port);
    acl_tcam_iterator_init(acl_entry, &dst_port_it, acl_iterator_dst_port);
    acl_tcam_iterator_first(&src_it);
    acl_tcam_iterator_first(&dst_it);
    acl_tcam_iterator_first(&src_port_it);
    acl_tcam_iterator_first(&dst_port_it);

    do {

        acl_get_member_tcam_entry(
            acl_entry,
            &src_it,
            &src_port_it,
            &dst_it,
            &dst_port_it,
            &tcam_entry_template);

            bitmap_prefix_print(&tcam_entry_template.prefix, 
                                             &tcam_entry_template.mask, 
                                             ACL_PREFIX_LEN);
            cprintf("\n");

    } while (acl_iterators_increment (
                &src_it,
                &dst_it,
                &src_port_it,
                &dst_port_it));

    acl_tcam_iterator_deinit(&src_it);
    acl_tcam_iterator_deinit(&dst_it);
    acl_tcam_iterator_deinit(&src_port_it);
    acl_tcam_iterator_deinit(&dst_port_it);
    bitmap_free_internal(&tcam_entry_template.prefix);
    bitmap_free_internal(&tcam_entry_template.mask);
}

void
 access_list_print_bitmap (node_t *node, c_string access_list_name) {

    glthread_t *curr;
    acl_entry_t *acl_entry;
    
    access_list_t *access_list = access_list_lookup_by_name(node, access_list_name);
    
    if (!access_list) return;

     pthread_rwlock_rdlock(&access_list->mtrie_update_lock);

     ITERATE_GLTHREAD_BEGIN(&access_list->head, curr) {

       acl_entry = glthread_to_acl_entry(curr);
       access_list_print_acl_bitmap(access_list, acl_entry);

       }ITERATE_GLTHREAD_END(&access_list->head, curr);

     pthread_rwlock_unlock(&access_list->mtrie_update_lock);
 }

static void
access_list_send_notif_cbk(event_dispatcher_t *ev_dis, void *data, uint32_t data_size) {

    access_list_t *access_list = ( access_list_t  *)data;
    access_list->notif_job = NULL;
    access_list_notify_clients((node_t *)ev_dis->app_data, access_list);
    access_list_dereference((node_t *)ev_dis->app_data, access_list);
}

/* To be used when notification about access_list change is to be send out to applns
asynchronously */
void
access_list_schedule_notification (node_t *node, access_list_t *access_list) {

    if (access_list->notif_job) return;

    access_list->notif_job = task_create_new_job(EV(node), 
                                                            (void *)access_list, 
                                                            access_list_send_notif_cbk,
                                                            TASK_ONE_SHOT,
                                                            TASK_PRIORITY_COMPUTE);

    access_list_reference(access_list);
}

acl_entry_t *
access_list_lookup_acl_entry_by_seq_no (access_list_t *access_list, uint32_t seq_no) {

    glthread_t *curr;
    acl_entry_t *acl_entry;

    ITERATE_GLTHREAD_BEGIN (&access_list->head, curr) {

        acl_entry = glthread_to_acl_entry(curr);
        if (acl_entry->seq_no == seq_no) return acl_entry;

    }ITERATE_GLTHREAD_END(&access_list->head, curr);

    return NULL;
}

void 
access_list_reenumerate_seq_no (access_list_t *access_list, 
                                                        glthread_t *begin_node) {

    uint32_t start_seq_no;
    glthread_t *curr;
    glthread_t *prev_glthread;
    glthread_t *starting_node;
    acl_entry_t *acl_entry = NULL;

    if (!begin_node) return;

    prev_glthread = glthread_get_prev(begin_node);
    if (prev_glthread == &access_list->head) {
        start_seq_no = 1;
        starting_node = &access_list->head;
    }
    else {
        acl_entry = glthread_to_acl_entry(prev_glthread);
        start_seq_no = acl_entry->seq_no + 1;
        starting_node = prev_glthread;
    }

    ITERATE_GLTHREAD_BEGIN(starting_node, curr) {

        acl_entry = glthread_to_acl_entry(curr);
        acl_entry->seq_no = start_seq_no;
        start_seq_no++;

    } ITERATE_GLTHREAD_END(starting_node, curr);
}

bool
access_list_delete_acl_entry_by_seq_no (node_t *node, access_list_t *access_list, uint32_t seq_no) {

    glthread_t *curr;
    acl_entry_t *acl_entry;

    acl_entry = access_list_lookup_acl_entry_by_seq_no(access_list, seq_no);
    
    if (!acl_entry) return false;

    curr = glthread_get_next (&acl_entry->glue);
    remove_glthread(&acl_entry->glue);
    access_list_reenumerate_seq_no (access_list, curr);

    if (!access_list_is_compiled(access_list)) {
         acl_entry_free(acl_entry);
         return true;
    }

    assert(acl_entry->is_compiled);

    /*Sync Method*/
    if (acl_entry->tcam_total_count < ACL_ENTRY_TCAM_COUNT_THRESHOLD) {
        pthread_rwlock_wrlock(&access_list->mtrie_update_lock);
        acl_entry_uninstall(access_list, acl_entry);
        pthread_rwlock_unlock(&access_list->mtrie_update_lock);
        acl_entry_free(acl_entry);
        return true;
    }

    /* Async method */
    acl_entry_free(acl_entry);
    access_list_trigger_install_job(node, access_list, NULL);
    return true;
}

bool 
access_list_should_decompile (access_list_t *access_list) {

    return (access_list->ref_count <= 1);
}

bool 
access_list_should_compile (access_list_t *access_list) {

    return (access_list->ref_count > 1);
}

bool 
access_list_is_compiled (access_list_t *access_list) {

    if (access_list->mtrie && 
            !mtrie_is_leaf_node(access_list->mtrie->root)) {
        
        return true;
     }
     return false;
}

void
acl_entry_increment_referenced_objects_tcam_user_count(
            acl_entry_t *acl_entry,
            int8_t k,
            bool object_networks,
            bool object_groups) {

        assert(k == 1 || k == -1);

       if (object_networks && acl_entry->src_addr.acl_addr_format ==
            ACL_ADDR_OBJECT_NETWORK) {

           if (k == 1)
               object_network_inc_tcam_users_count(acl_entry->src_addr.u.obj_nw);
           else
               object_network_dec_tcam_users_count(acl_entry->src_addr.u.obj_nw);
       }
       else if (object_groups && acl_entry->src_addr.acl_addr_format ==
            ACL_ADDR_OBJECT_GROUP) {

           if (k == 1)
               object_group_inc_tcam_users_count(acl_entry->src_addr.u.og);
           else
               object_group_dec_tcam_users_count(acl_entry->src_addr.u.og);
       }
        
        if (object_networks && acl_entry->dst_addr.acl_addr_format ==
            ACL_ADDR_OBJECT_NETWORK) {

            if (k == 1)
                object_network_inc_tcam_users_count(acl_entry->dst_addr.u.obj_nw);
            else
                object_network_dec_tcam_users_count(acl_entry->dst_addr.u.obj_nw);
       }
       else if (object_groups && acl_entry->dst_addr.acl_addr_format ==
            ACL_ADDR_OBJECT_GROUP) {

           if (k == 1)
               object_group_inc_tcam_users_count(acl_entry->dst_addr.u.og);
           else
               object_group_dec_tcam_users_count(acl_entry->dst_addr.u.og);
       }
}

/* Iterators over ACL's Src and Dst TCAM Data */
void
acl_tcam_iterator_init (acl_entry_t *acl_entry, 
                                     acl_tcam_iterator_t *acl_tcam_iterator,
                                     acl_iterator_type_t it_type) {

    object_group_t *og = NULL;

    acl_tcam_iterator->addr_prefix = NULL;
    acl_tcam_iterator->addr_wcard = NULL;
    acl_tcam_iterator->port_prefix = NULL;
    acl_tcam_iterator->port_wcard = NULL;
    acl_tcam_iterator->index = 0;
    acl_tcam_iterator->acl_entry = acl_entry;
    acl_tcam_iterator->it_type = it_type;
    init_glthread(&acl_tcam_iterator->og_leaves_lst_head);
    init_glthread(&acl_tcam_iterator->og_leaves_lst_head_processed);
    
    switch (it_type) {
        case acl_iterator_src_addr:
            if (acl_entry->src_addr.acl_addr_format == ACL_ADDR_OBJECT_GROUP)
                og = acl_entry->src_addr.u.og;
                break;
        case acl_iterator_dst_addr:
            if (acl_entry->dst_addr.acl_addr_format == ACL_ADDR_OBJECT_GROUP)
                og = acl_entry->dst_addr.u.og;
                break;
        case acl_iterator_src_port:
            break;
        case acl_iterator_dst_port:
            break;
        default: ;
    }
    if (og) {
        object_group_queue_all_leaf_ogs(og, 
        &acl_tcam_iterator->og_leaves_lst_head);
    }
}

bool
acl_tcam_iterator_first (acl_tcam_iterator_t *acl_tcam_iterator) {

    acl_entry_t *acl_entry = acl_tcam_iterator->acl_entry;

    switch (acl_tcam_iterator->it_type) {
        case acl_iterator_src_addr:
            switch (acl_entry->src_addr.acl_addr_format) {
                case ACL_ADDR_NOT_SPECIFIED:
                case ACL_ADDR_HOST:
                case ACL_ADDR_SUBNET_MASK:
                    acl_tcam_iterator->index = 0;
                    acl_tcam_iterator->addr_prefix = &((*acl_entry->tcam_saddr_prefix)[0]);
                    acl_tcam_iterator->addr_wcard = &((*acl_entry->tcam_saddr_wcard)[0]);
                    return true;
                case ACL_ADDR_OBJECT_NETWORK:
                    assert(object_network_is_tcam_compiled(acl_entry->src_addr.u.obj_nw));
                    acl_tcam_iterator->index = 0;
                    acl_tcam_iterator->addr_prefix = &((*acl_entry->src_addr.u.obj_nw->prefix)[0]);
                    acl_tcam_iterator->addr_wcard = &((*acl_entry->src_addr.u.obj_nw->wcard)[0]);
                    return true;
                case ACL_ADDR_OBJECT_GROUP:
                    switch(acl_entry->src_addr.u.og->og_type) {
                        case OBJECT_GRP_NET_ADDR:
                        case OBJECT_GRP_NET_HOST:
                        case OBJECT_GRP_NET_RANGE:
                            DEADCODE;
                            assert(acl_entry->src_addr.u.og->tcam_state == OG_TCAM_STATE_COMPILED);
                            acl_tcam_iterator->index = 0;
                            acl_tcam_iterator->addr_prefix = &((*acl_entry->src_addr.u.og->prefix)[0]);
                            acl_tcam_iterator->addr_wcard = &((*acl_entry->src_addr.u.og->wcard)[0]);
                            return true;
                        case OBJECT_GRP_NESTED:
                            {
                                glthread_t *curr = glthread_get_next(&acl_tcam_iterator->og_leaves_lst_head);
                                if (!curr) return false;
                                obj_grp_list_node_t *obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                                object_group_t *og = obj_grp_list_node->og;
                                switch (og->og_type)
                                {
                                    case OBJECT_GRP_NET_ADDR:
                                    case OBJECT_GRP_NET_HOST:
                                    case OBJECT_GRP_NET_RANGE:
                                        assert(og->tcam_state == OG_TCAM_STATE_COMPILED);
                                        acl_tcam_iterator->index = 0;
                                        acl_tcam_iterator->addr_prefix = &((*og->prefix)[0]);
                                        acl_tcam_iterator->addr_wcard = &((*og->wcard)[0]);
                                        return true;
                                    case OBJECT_GRP_NESTED:
                                        assert(0);
                                }
                            }
                            break;
                    }
                break;
            }
            break;

        case acl_iterator_dst_addr:
            switch (acl_entry->dst_addr.acl_addr_format) {
                case ACL_ADDR_NOT_SPECIFIED:
                case ACL_ADDR_HOST:
                case ACL_ADDR_SUBNET_MASK:
                    acl_tcam_iterator->index = 0;
                    acl_tcam_iterator->addr_prefix = &((*acl_entry->tcam_daddr_prefix)[0]);
                    acl_tcam_iterator->addr_wcard = &((*acl_entry->tcam_daddr_wcard)[0]);
                    return true;
                case ACL_ADDR_OBJECT_NETWORK:
                    assert(object_network_is_tcam_compiled(acl_entry->dst_addr.u.obj_nw));
                    acl_tcam_iterator->index = 0;
                    acl_tcam_iterator->addr_prefix = &((*acl_entry->dst_addr.u.obj_nw->prefix)[0]);
                    acl_tcam_iterator->addr_wcard = &((*acl_entry->dst_addr.u.obj_nw->wcard)[0]);
                    return true;
                case ACL_ADDR_OBJECT_GROUP:
                    switch(acl_entry->dst_addr.u.og->og_type) {
                        case OBJECT_GRP_NET_ADDR:
                        case OBJECT_GRP_NET_HOST:
                        case OBJECT_GRP_NET_RANGE:
                            DEADCODE;
                            assert(acl_entry->dst_addr.u.og->tcam_state == OG_TCAM_STATE_COMPILED);
                            acl_tcam_iterator->index = 0;
                            acl_tcam_iterator->addr_prefix = &((*acl_entry->dst_addr.u.og->prefix)[0]);
                            acl_tcam_iterator->addr_wcard = &((*acl_entry->dst_addr.u.og->wcard)[0]);
                            return true;
                        case OBJECT_GRP_NESTED:
                        {
                            glthread_t *curr = glthread_get_next(&acl_tcam_iterator->og_leaves_lst_head);
                            if (!curr) return false;
                            obj_grp_list_node_t *obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                            object_group_t *og = obj_grp_list_node->og;
                            switch (og->og_type)
                            {
                            case OBJECT_GRP_NET_ADDR:
                            case OBJECT_GRP_NET_HOST:
                            case OBJECT_GRP_NET_RANGE:
                                assert(og->tcam_state == OG_TCAM_STATE_COMPILED);
                                acl_tcam_iterator->index = 0;
                                acl_tcam_iterator->addr_prefix = &((*og->prefix)[0]);
                                acl_tcam_iterator->addr_wcard = &((*og->wcard)[0]);
                                return true;
                            case OBJECT_GRP_NESTED:
                                assert(0);
                            }
                        }
                        break;
                    }
                break;
            } 
        break;
        case acl_iterator_src_port:
            acl_tcam_iterator->index = 0;
            return true;
        break;        
        case acl_iterator_dst_port:
            acl_tcam_iterator->index = 0;
            return true;
        break;        
        default: ;
    }    
    return false;
}

bool
acl_tcam_iterator_next (acl_tcam_iterator_t *acl_tcam_iterator)  {

    acl_entry_t *acl_entry = acl_tcam_iterator->acl_entry;

    switch (acl_tcam_iterator->it_type) {
        case acl_iterator_src_addr:
            switch (acl_entry->src_addr.acl_addr_format) {
                case ACL_ADDR_NOT_SPECIFIED:
                case ACL_ADDR_HOST:
                case ACL_ADDR_SUBNET_MASK:
                    return false;
                case ACL_ADDR_OBJECT_NETWORK:
                    assert(object_network_is_tcam_compiled(acl_entry->src_addr.u.obj_nw));
                    switch(acl_entry->src_addr.u.obj_nw->type) {
                        case OBJ_NW_TYPE_HOST:
                        case OBJ_NW_TYPE_SUBNET:
                            return false;
                        case OBJ_NW_TYPE_RANGE:
                            acl_tcam_iterator->index++;
                            if (acl_tcam_iterator->index >= acl_entry->src_addr.u.obj_nw->count) {
                                return false;
                            }
                            acl_tcam_iterator->addr_prefix = &((*acl_entry->src_addr.u.obj_nw->prefix)[acl_tcam_iterator->index]);
                            acl_tcam_iterator->addr_wcard = &((*acl_entry->src_addr.u.obj_nw->wcard)[acl_tcam_iterator->index]);
                            return true;
                    }
                case ACL_ADDR_OBJECT_GROUP:
                    switch(acl_entry->src_addr.u.og->og_type) {
                        case OBJECT_GRP_NET_ADDR:
                        case OBJECT_GRP_NET_HOST:
                             DEADCODE;
                        case OBJECT_GRP_NET_RANGE:
                             DEADCODE;
                            acl_tcam_iterator->index++;
                            if (acl_tcam_iterator->index >= acl_entry->src_addr.u.og->count) {
                                return false;
                            }
                            acl_tcam_iterator->addr_prefix = &((*acl_entry->src_addr.u.og->prefix)[acl_tcam_iterator->index]);
                            acl_tcam_iterator->addr_wcard = &((*acl_entry->src_addr.u.og->wcard)[acl_tcam_iterator->index]);
                            return true;
                        case OBJECT_GRP_NESTED:
                            {
                                /* Inspecting the prev object processed */
                                 glthread_t *curr = glthread_get_next(&acl_tcam_iterator->og_leaves_lst_head);
                                  assert(curr);
                                  obj_grp_list_node_t *obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                                  object_group_t *og = obj_grp_list_node->og;
                                   switch (og->og_type) {
                                        case OBJECT_GRP_NET_ADDR:
                                        case OBJECT_GRP_NET_HOST:
                                            /* Prev object processing done */
                                            remove_glthread(curr);
                                            glthread_add_next(&acl_tcam_iterator->og_leaves_lst_head_processed,
                                            curr);
                                            /* Get and inspect the next object */
                                            curr = glthread_get_next(&acl_tcam_iterator->og_leaves_lst_head);
                                            if (!curr) return false;
                                            obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                                            og = obj_grp_list_node->og;
                                            switch (og->og_type) {
                                                case OBJECT_GRP_NET_ADDR:
                                                case OBJECT_GRP_NET_HOST:
                                                case OBJECT_GRP_NET_RANGE:
                                                    assert(og->tcam_state == OG_TCAM_STATE_COMPILED);
                                                    acl_tcam_iterator->index = 0;
                                                    acl_tcam_iterator->addr_prefix = &((*og->prefix)[0]);
                                                    acl_tcam_iterator->addr_wcard = &((*og->wcard)[0]);
                                                    return true;
                                                case OBJECT_GRP_NESTED:
                                                    assert(0);
                                            }
                                        case OBJECT_GRP_NET_RANGE:
                                            /* IF prev object is of type Range */
                                            acl_tcam_iterator->index++;
                                            if (acl_tcam_iterator->index < og->count) {
                                                acl_tcam_iterator->addr_prefix = &((*og->prefix)[acl_tcam_iterator->index]);
                                                acl_tcam_iterator->addr_wcard = &((*og->wcard)[acl_tcam_iterator->index]);
                                                return true;
                                            }
                                            remove_glthread(curr);
                                            glthread_add_next(&acl_tcam_iterator->og_leaves_lst_head_processed,
                                            curr);                                            
                                            /* Get and inspect the next object */
                                            curr = glthread_get_next(&acl_tcam_iterator->og_leaves_lst_head);
                                            if (!curr) return false;
                                            obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                                            og = obj_grp_list_node->og;
                                            switch (og->og_type)
                                            {
                                                case OBJECT_GRP_NET_ADDR:
                                                case OBJECT_GRP_NET_HOST:
                                                case OBJECT_GRP_NET_RANGE:
                                                    assert(og->tcam_state == OG_TCAM_STATE_COMPILED);
                                                    acl_tcam_iterator->index = 0;
                                                    acl_tcam_iterator->addr_prefix = &((*og->prefix)[0]);
                                                    acl_tcam_iterator->addr_wcard = &((*og->wcard)[0]);
                                                     return true;
                                                case OBJECT_GRP_NESTED:
                                                    assert(0);
                                            }
                                        case OBJECT_GRP_NESTED:
                                            assert(0);
                                   }
                            }
                            break;
                    }
                break;
            }
            break;

        case acl_iterator_dst_addr:
            switch (acl_entry->dst_addr.acl_addr_format) {
                case ACL_ADDR_NOT_SPECIFIED:
                case ACL_ADDR_HOST:
                case ACL_ADDR_SUBNET_MASK:
                    return false;
                case ACL_ADDR_OBJECT_NETWORK:
                    assert(object_network_is_tcam_compiled(acl_entry->dst_addr.u.obj_nw));
                    switch(acl_entry->dst_addr.u.obj_nw->type) {
                        case OBJ_NW_TYPE_HOST:
                        case OBJ_NW_TYPE_SUBNET:
                            return false;
                        case OBJ_NW_TYPE_RANGE:
                            acl_tcam_iterator->index++;
                            if (acl_tcam_iterator->index >= acl_entry->dst_addr.u.obj_nw->count) {
                                return false;
                            }
                            acl_tcam_iterator->addr_prefix = &((*acl_entry->dst_addr.u.obj_nw->prefix)[acl_tcam_iterator->index]);
                            acl_tcam_iterator->addr_wcard = &((*acl_entry->dst_addr.u.obj_nw->wcard)[acl_tcam_iterator->index]);
                            return true;
                    }
                case ACL_ADDR_OBJECT_GROUP:
                    switch(acl_entry->dst_addr.u.og->og_type) {
                        case OBJECT_GRP_NET_ADDR:
                        case OBJECT_GRP_NET_HOST:
                            return false;
                        case OBJECT_GRP_NET_RANGE:
                            acl_tcam_iterator->index++;
                            if (acl_tcam_iterator->index >= acl_entry->dst_addr.u.og->count) {
                                return false;
                            }
                            acl_tcam_iterator->addr_prefix = &((*acl_entry->dst_addr.u.og->prefix)[acl_tcam_iterator->index]);
                            acl_tcam_iterator->addr_wcard = &((*acl_entry->dst_addr.u.og->wcard)[acl_tcam_iterator->index]);
                            return true;
                        case OBJECT_GRP_NESTED:
                            {
                                /* Inspecting the prev object processed */
                                 glthread_t *curr = glthread_get_next(&acl_tcam_iterator->og_leaves_lst_head);
                                  assert(curr);
                                  obj_grp_list_node_t *obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                                  object_group_t *og = obj_grp_list_node->og;
                                   switch (og->og_type) {
                                        case OBJECT_GRP_NET_ADDR:
                                        case OBJECT_GRP_NET_HOST:
                                            /* Prev object processing done */
                                            remove_glthread(curr);
                                            glthread_add_next(&acl_tcam_iterator->og_leaves_lst_head_processed,
                                            curr);
                                            /* Get and inspect the next object */
                                            curr = glthread_get_next(&acl_tcam_iterator->og_leaves_lst_head);
                                            if (!curr) return false;
                                            obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                                            og = obj_grp_list_node->og;
                                            switch (og->og_type) {
                                                case OBJECT_GRP_NET_ADDR:
                                                case OBJECT_GRP_NET_HOST:
                                                case OBJECT_GRP_NET_RANGE:
                                                    assert(og->tcam_state == OG_TCAM_STATE_COMPILED);
                                                    acl_tcam_iterator->index = 0;
                                                    acl_tcam_iterator->addr_prefix = &((*og->prefix)[0]);
                                                    acl_tcam_iterator->addr_wcard = &((*og->wcard)[0]);
                                                    return true;
                                                case OBJECT_GRP_NESTED:
                                                    assert(0);
                                            }
                                        case OBJECT_GRP_NET_RANGE:
                                            /* IF prev object is of type Range */
                                            acl_tcam_iterator->index++;
                                            if (acl_tcam_iterator->index < og->count) {
                                                acl_tcam_iterator->addr_prefix = &((*og->prefix)[acl_tcam_iterator->index]);
                                                acl_tcam_iterator->addr_wcard = &((*og->wcard)[acl_tcam_iterator->index]);
                                                return true;
                                            }
                                            remove_glthread(curr);
                                            glthread_add_next(&acl_tcam_iterator->og_leaves_lst_head_processed,
                                            curr);               
                                            /* Get and inspect the next object */
                                            curr = glthread_get_next(&acl_tcam_iterator->og_leaves_lst_head);
                                            if (!curr) return false;
                                            obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                                            og = obj_grp_list_node->og;
                                            switch (og->og_type)
                                            {
                                                case OBJECT_GRP_NET_ADDR:
                                                case OBJECT_GRP_NET_HOST:
                                                case OBJECT_GRP_NET_RANGE:
                                                    assert(og->tcam_state == OG_TCAM_STATE_COMPILED);
                                                    acl_tcam_iterator->index = 0;
                                                    acl_tcam_iterator->addr_prefix = &((*og->prefix)[0]);
                                                    acl_tcam_iterator->addr_wcard = &((*og->wcard)[0]);
                                                     return true;
                                                case OBJECT_GRP_NESTED:
                                                    assert(0);
                                            }
                                        case OBJECT_GRP_NESTED:
                                            assert(0);
                                   }
                            }
                            break;
                    }
                break;
            }
        break;
        case acl_iterator_src_port:
            acl_tcam_iterator->index++;
            if (acl_tcam_iterator->index >= acl_entry->tcam_sport_count) return false;
            return true;
        break;        
        case acl_iterator_dst_port:
            acl_tcam_iterator->index++;
            if (acl_tcam_iterator->index >= acl_entry->tcam_dport_count) return false;
            return true;
        break;        
        default: ;
    }    
    return false;
}

void
acl_tcam_iterator_deinit (acl_tcam_iterator_t *acl_tcam_iterator) {

    glthread_t *head, *curr;
    obj_grp_list_node_t *obj_grp_list_node;

    switch (acl_tcam_iterator->it_type) {

        case acl_iterator_src_addr:
        case acl_iterator_dst_addr:

            head = IS_GLTHREAD_LIST_EMPTY(&acl_tcam_iterator->og_leaves_lst_head) ? 
                &acl_tcam_iterator->og_leaves_lst_head_processed : \
                &acl_tcam_iterator->og_leaves_lst_head;

            ITERATE_GLTHREAD_BEGIN(head, curr) {

                obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                remove_glthread(curr);
                obj_grp_list_node->og->ref_count--;
                XFREE(obj_grp_list_node);
            }
            ITERATE_GLTHREAD_END(head, curr)
            break;
        case acl_iterator_src_port:
        case acl_iterator_dst_port:
        break;
        default: ;
    }

    acl_tcam_iterator->addr_prefix = NULL;
    acl_tcam_iterator->addr_wcard = NULL;
    acl_tcam_iterator->port_prefix = NULL;
    acl_tcam_iterator->port_wcard = NULL;
    acl_tcam_iterator->index = 0;
    acl_tcam_iterator->acl_entry = NULL;
}

void
acl_tcam_iterator_reset (acl_tcam_iterator_t *acl_tcam_iterator) {

        glthread_t *curr;

        switch (acl_tcam_iterator->it_type) {

        case acl_iterator_src_addr:
        case acl_iterator_dst_addr:
            acl_tcam_iterator->index = 0;
            curr = glthread_get_next(&acl_tcam_iterator->og_leaves_lst_head_processed);
            if (curr) {
                glthread_add_next (&acl_tcam_iterator->og_leaves_lst_head, curr);
                init_glthread(&acl_tcam_iterator->og_leaves_lst_head_processed);
            }
            break;
        case acl_iterator_src_port:
        case acl_iterator_dst_port:
             acl_tcam_iterator->index = 0;
            break;
        default: ;
    }
    acl_tcam_iterator_first(acl_tcam_iterator);
}

bool
acl_iterators_increment (acl_tcam_iterator_t *src_it,
                                        acl_tcam_iterator_t *dst_it, 
                                        acl_tcam_iterator_t *src_port_it,
                                        acl_tcam_iterator_t *dst_port_it) {

    /* We need to increment iterators in the order for loops are nested over them.
        Order is :
            Src addr, Src Port It, Dst addr, Dst Port it
    */
    if (acl_tcam_iterator_next(dst_port_it)) return true;
    acl_tcam_iterator_reset(dst_port_it);

    if (acl_tcam_iterator_next(dst_it)) return true;
    acl_tcam_iterator_reset(dst_it);

    if (acl_tcam_iterator_next(src_port_it)) return true;
    acl_tcam_iterator_reset(src_port_it);

    return (acl_tcam_iterator_next(src_it));
}

/* Async Operations on Acl (Un)installation */
static void
access_list_processing_job_cbk(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size);

static void
access_list_reschedule_processing_job(
        access_list_processing_info_t *access_list_processing_info) {

        access_list_processing_info->task = 
            task_create_new_job(EV(access_list_processing_info->node),
                                            (void *)access_list_processing_info,
                                            access_list_processing_job_cbk,
                                            TASK_ONE_SHOT,
                                            TASK_PRIORITY_COMPUTE);
}

#define ACCESS_LIST_PREEMPTION_THRESHOLD    10000

static void
access_list_processing_job_cbk(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    glthread_t *curr;
    mtrie_node_t *mnode;
    access_list_t *access_list;
    mtrie_ops_result_code_t rc;
    acl_tcam_t *tcam_entry_template; 
    acl_tcam_iterator_t *acl_tcam_src_it;
    acl_tcam_iterator_t *acl_tcam_dst_it;
    acl_tcam_iterator_t *acl_tcam_src_port_it;
    acl_tcam_iterator_t *acl_tcam_dst_port_it;
    objects_linked_acl_thread_node_t *objects_linked_acl_thread_node;

    access_list_processing_info_t *access_list_processing_info = 
        (access_list_processing_info_t *)arg;

    curr = NULL;
    node_t *node = access_list_processing_info->node;
    acl_entry_t *acl_entry = access_list_processing_info->current_acl;
    access_list = access_list_processing_info->access_list;
    tcam_entry_template = &access_list_processing_info->tcam_entry_template;

    if (!acl_entry) {
        
        curr = dequeue_glthread_first(&access_list_processing_info->pending_acls);

        /* Done with the access list */
        if (!curr) {

            sprintf(tlb, "%s : %sInstallation of Access-list %s finished\n",
                    FWALL_ACL, access_list_processing_info->is_installation ? "" : "Un-",
                    access_list->name);
            tcp_trace(node, 0, tlb);

            if (access_list_processing_info->is_installation) {
                access_list->installation_end_time = time(NULL);
            }

            /* Updating the Data Path */
            if (access_list_processing_info->is_installation) {
                mtrie_t *temp = access_list->mtrie;
                access_list->mtrie = access_list_processing_info->mtrie;
                access_list_purge_tcam_mtrie(node, temp);
                sprintf(tlb, "%s : Data Path Updated for  Access-list %s\n",
                    FWALL_ACL, access_list->name);
                tcp_trace(node, 0, tlb);
            }

            if (access_list_processing_info->og_update_info) {

                access_list_processing_info->og_update_info->access_list_processed_count++;

                if (access_list_processing_info->og_update_info->access_list_processed_count ==
                    access_list_processing_info->og_update_info->access_list_to_be_processed_count) {
                    access_list_processing_info->og_update_info->stage = og_update_fsm_access_list_stage_cleanup;
                    object_group_update_reschedule_task(access_list_processing_info->og_update_info);
                }

            }

            bitmap_free_internal(&tcam_entry_template->prefix);
            bitmap_free_internal(&tcam_entry_template->mask);
            XFREE(access_list_processing_info);
            access_list->processing_info = NULL;
            access_list_schedule_notification (node, access_list);
            access_list_dereference(node, access_list);
            return;
        }

        objects_linked_acl_thread_node = glue_to_objects_linked_acl_thread_node(curr);
        access_list_processing_info->current_acl = objects_linked_acl_thread_node->acl;
        acl_entry = access_list_processing_info->current_acl;
        if (access_list_processing_info->is_installation) {
            acl_entry->installation_start_time = time(NULL);
        }
        XFREE(objects_linked_acl_thread_node );

        /* Compile the ACL is not already */
        if (access_list_processing_info->is_installation && 
                access_list_should_compile(access_list)) {
            acl_compile(acl_entry);
        }

        /* Retrieve Iterators */
        acl_tcam_src_it = &access_list_processing_info->acl_tcam_src_it;
        acl_tcam_dst_it = &access_list_processing_info->acl_tcam_dst_it;
        acl_tcam_src_port_it = &access_list_processing_info->acl_tcam_src_port_it;
        acl_tcam_dst_port_it = &access_list_processing_info->acl_tcam_dst_port_it;
        /* Initialize Iterators */
        acl_tcam_iterator_init(acl_entry, acl_tcam_src_it, acl_iterator_src_addr);
        acl_tcam_iterator_init(acl_entry, acl_tcam_dst_it, acl_iterator_dst_addr);
        acl_tcam_iterator_init(acl_entry, acl_tcam_src_port_it, acl_iterator_src_port);
        acl_tcam_iterator_init(acl_entry, acl_tcam_dst_port_it, acl_iterator_dst_port);
        acl_tcam_iterator_first(acl_tcam_src_it);
        acl_tcam_iterator_first(acl_tcam_dst_it);
        acl_tcam_iterator_first(acl_tcam_src_port_it);
        acl_tcam_iterator_first(acl_tcam_dst_port_it);

        if (access_list_processing_info->is_installation) {
            acl_entry->installation_in_progress = true;
        }

    }
    else {
        /* Retrieve Iterators */
        acl_tcam_src_it = &access_list_processing_info->acl_tcam_src_it;
        acl_tcam_dst_it = &access_list_processing_info->acl_tcam_dst_it;
        acl_tcam_src_port_it = &access_list_processing_info->acl_tcam_src_port_it;
        acl_tcam_dst_port_it = &access_list_processing_info->acl_tcam_dst_port_it;

        if (!acl_iterators_increment (
                acl_tcam_src_it,
                acl_tcam_dst_it,
                acl_tcam_src_port_it,
                acl_tcam_dst_port_it)) { 
                goto ACL_PROCESSING_COMPLETE;
        }

         sprintf (tlb, "%s : %sInstallation of ACL %s-%u resume, Total tcam installed = %u\n", 
                    FWALL_ACL, access_list_processing_info->is_installation ? "" : "Un-",
                    access_list->name, acl_entry->seq_no, acl_entry->tcam_total_count);
        tcp_trace(node, 0, tlb);
    }
    
    do {

        acl_get_member_tcam_entry(
            acl_entry,
            acl_tcam_src_it,
            acl_tcam_src_port_it,
            acl_tcam_dst_it,
            acl_tcam_dst_port_it,
            tcam_entry_template);

#if 0
        cprintf("%sInstalling TCAM Entry\n", access_list_processing_info->is_installation ? "" : "Un-");
        bitmap_print(&tcam_entry_template->prefix);
        bitmap_print(&tcam_entry_template->mask);
#endif    

    if (access_list_processing_info->is_installation) {
        /* If installation */
        rc = (mtrie_insert_prefix(
            access_list_processing_info->mtrie,
            &tcam_entry_template->prefix,
            &tcam_entry_template->mask,
            ACL_PREFIX_LEN,
            &mnode));

        switch (rc)
        {
        case MTRIE_INSERT_SUCCESS:
            access_list_mtrie_allocate_mnode_data(mnode, (void *)acl_entry);
            break;
        case MTRIE_INSERT_DUPLICATE:
            access_list_mtrie_duplicate_entry_found(mnode, (void *)acl_entry);
            break;
        case MTRIE_INSERT_FAILED:
            assert(0);
        }
    }
    else {
        /* If Un-installation */
        mnode = mtrie_exact_prefix_match_search(
            access_list_processing_info->mtrie,
            &tcam_entry_template->prefix,
            &tcam_entry_template->mask);

        assert(mnode);

        access_list_mtrie_deallocate_mnode_data(mnode, acl_entry);
        if (mnode->data == NULL) {
            mtrie_delete_leaf_node(access_list->mtrie, mnode);
        }
    }
    access_list_processing_info->acl_tcams_installed++;

    if ((access_list_processing_info->acl_tcams_installed % 
                ACCESS_LIST_PREEMPTION_THRESHOLD) == 0 && 
        event_dispatcher_should_suspend(EV(node))) {

        access_list_reschedule_processing_job(access_list_processing_info);
        sprintf (tlb, "%s : %sInstallation of ACL %s-%u suspended, Total tcam %sinstalled = %u\n", 
                    FWALL_ACL, access_list_processing_info->is_installation ? "" : "Un-",
                    access_list->name, acl_entry->seq_no, 
                    access_list_processing_info->is_installation ? "" : "Un-",
                    acl_entry->tcam_total_count);
        tcp_trace(node, 0, tlb);
        return;
    }

    } while (acl_iterators_increment (
                acl_tcam_src_it,
                acl_tcam_dst_it,
                acl_tcam_src_port_it,
                acl_tcam_dst_port_it));

    ACL_PROCESSING_COMPLETE:
    /* Acl (Un)/Installation in Completed */
    sprintf(tlb, "%s : %sInstallation of ACL %s-%u finished, Total tcam installed = %u\n",
            FWALL_ACL, access_list_processing_info->is_installation ? "" : "Un-",
            access_list->name, acl_entry->seq_no, acl_entry->tcam_total_count);
    tcp_trace(node, 0, tlb);

     if (access_list_processing_info->is_installation) {
        access_list_processing_info->current_acl->installation_end_time = time(NULL);
        access_list_processing_info->current_acl->installation_in_progress = false;
     }

    access_list_processing_info->current_acl->is_installed = 
        access_list_processing_info->is_installation;

    if (!access_list_processing_info->current_acl->is_installed) {
        if (access_list_should_decompile(access_list)) {
            acl_decompile(access_list_processing_info->current_acl);
        }
    }
    
    access_list_processing_info->current_acl = NULL;

    acl_tcam_iterator_deinit(acl_tcam_src_it);
    acl_tcam_iterator_deinit(acl_tcam_dst_it);
    acl_tcam_iterator_deinit(acl_tcam_src_port_it);
    acl_tcam_iterator_deinit(acl_tcam_dst_port_it);

    access_list_reschedule_processing_job(access_list_processing_info);
}

void
access_list_trigger_install_job(node_t *node, 
                                access_list_t *access_list,
                                object_group_update_info_t *og_update_info) {

    glthread_t *curr;
    acl_entry_t *acl_entry;
    objects_linked_acl_thread_node_t *objects_linked_acl_thread_node;

    access_list_processing_info_t *access_list_processing_info = 
        (access_list_processing_info_t *)XCALLOC(0, 1, access_list_processing_info_t);
    
    access_list_processing_info->is_installation = true;
    access_list_processing_info->node = node;
    access_list_processing_info->og_update_info = og_update_info;
    access_list_processing_info->access_list = access_list;
    access_list_reference (access_list);
    access_list_processing_info->mtrie = access_list_get_new_tcam_mtrie();
    access_list_processing_info->acl_tcams_installed = 0;
    access_list->processing_info = access_list_processing_info;
    access_list->installation_start_time = time(NULL);

    ITERATE_GLTHREAD_BEGIN(&access_list->head, curr) {

        acl_entry = glthread_to_acl_entry(curr);
        objects_linked_acl_thread_node = 
            (objects_linked_acl_thread_node_t *)XCALLOC(0, 1, objects_linked_acl_thread_node_t);
        objects_linked_acl_thread_node->acl = acl_entry;
        acl_entry_reset_counters(acl_entry);
        init_glthread(&objects_linked_acl_thread_node->glue);
        glthread_add_next(&access_list_processing_info->pending_acls, &objects_linked_acl_thread_node->glue);
    
    } ITERATE_GLTHREAD_END(&access_list->head, curr);

    bitmap_init(&access_list_processing_info->tcam_entry_template.prefix, ACL_PREFIX_LEN);
    bitmap_init(&access_list_processing_info->tcam_entry_template.mask, ACL_PREFIX_LEN);
    init_glthread(&access_list_processing_info->tcam_entry_template.glue);

    access_list_reschedule_processing_job (access_list_processing_info);
}


void
access_list_trigger_uninstall_job(node_t *node, 
                                access_list_t *access_list,
                                object_group_update_info_t *og_update_info) {

    glthread_t *curr;
    acl_entry_t *acl_entry;
    objects_linked_acl_thread_node_t *objects_linked_acl_thread_node;

    access_list_processing_info_t *access_list_processing_info = 
        (access_list_processing_info_t *)XCALLOC(0, 1, access_list_processing_info_t);
    
    access_list_processing_info->is_installation = false;
    access_list_processing_info->node = node;
    access_list_processing_info->og_update_info = og_update_info;
    access_list_processing_info->access_list = access_list;
    access_list_reference (access_list);
    access_list_processing_info->mtrie = access_list->mtrie;
    access_list->mtrie = access_list_get_new_tcam_mtrie();
    access_list ->processing_info = access_list_processing_info;

    ITERATE_GLTHREAD_BEGIN(&access_list->head, curr) {

        acl_entry = glthread_to_acl_entry(curr);
        objects_linked_acl_thread_node = 
            (objects_linked_acl_thread_node_t *)XCALLOC(0, 1, objects_linked_acl_thread_node_t);
        objects_linked_acl_thread_node->acl = acl_entry;
        init_glthread(&objects_linked_acl_thread_node->glue);
        glthread_add_next(&access_list_processing_info->pending_acls, &objects_linked_acl_thread_node->glue);

    } ITERATE_GLTHREAD_END(&access_list->head, curr);

    bitmap_init(&access_list_processing_info->tcam_entry_template.prefix, ACL_PREFIX_LEN);
    bitmap_init(&access_list_processing_info->tcam_entry_template.mask, ACL_PREFIX_LEN);
    init_glthread(&access_list_processing_info->tcam_entry_template.glue);

    access_list_reschedule_processing_job (access_list_processing_info);    
}

/* Acl Entry  (De)Compilation are synchronous Operations */
void
access_list_trigger_acl_decompile_job(node_t *node, 
                                acl_entry_t *acl_entry,
                                object_group_update_info_t *og_update_info) {

   acl_decompile (acl_entry);
}

void
access_list_trigger_acl_compile_job(node_t *node, 
                                acl_entry_t *acl_entry,
                                object_group_update_info_t *og_update_info) {

    acl_compile(acl_entry);
}

void
access_list_cancel_un_installation_operation (access_list_t *access_list) {

    glthread_t *curr;
    acl_entry_t *acl_entry;
    objects_linked_acl_thread_node_t *objects_linked_acl_thread_node;
    
    if (!access_list_is_installation_in_progress(access_list) &&
         !access_list_is_uninstallation_in_progress (access_list)) {
        
        return;
    }

    access_list_purge_tcam_mtrie
            (access_list->processing_info->node, access_list->processing_info->mtrie);
        access_list->processing_info->mtrie = NULL;

   task_cancel_job(EV(access_list->processing_info->node),
                                      access_list->processing_info->task);

    access_list->processing_info->task = NULL;

    acl_tcam_iterator_deinit(&access_list->processing_info->acl_tcam_src_it);
    acl_tcam_iterator_deinit(&access_list->processing_info->acl_tcam_dst_it);
    acl_tcam_iterator_deinit(&access_list->processing_info->acl_tcam_src_port_it);
    acl_tcam_iterator_deinit(&access_list->processing_info->acl_tcam_dst_port_it);

    /* Cleanup Pending ACLs */
    ITERATE_GLTHREAD_BEGIN(&access_list->processing_info->pending_acls, curr) {

        objects_linked_acl_thread_node = glue_to_objects_linked_acl_thread_node(curr);
        remove_glthread(curr);
        XFREE(objects_linked_acl_thread_node);

    }ITERATE_GLTHREAD_END(&access_list->processing_info, curr) ;

    /* Was this job triggered due to OG update */
    if (access_list->processing_info->og_update_info) {
        access_list->processing_info->og_update_info->access_list_to_be_processed_count--;
        hashtable_remove (access_list->processing_info->og_update_info->access_lists_ht, (void *)access_list);
    }

    /* Reset ALCs flags */
    ITERATE_GLTHREAD_BEGIN(&access_list->head, curr) {

        acl_entry = glthread_to_acl_entry(curr);
        acl_entry->is_installed = !access_list->processing_info->is_installation;

    }ITERATE_GLTHREAD_END(&access_list->head, curr) ;

    sprintf (tlb, "%s : Access List %s , %sInstallation Cancelled Successfully\n",
                    FWALL_ACL, access_list->name, access_list->processing_info->is_installation ? "" : "Un-");
    tcp_trace(access_list->processing_info->node, 0, tlb);

    access_list_dereference (access_list->processing_info->node, access_list);
    XFREE(access_list->processing_info);
    access_list->processing_info = NULL;
}

static void
mtrie_purge_cbk (event_dispatcher_t *ev_dis, void *mtrie, uint32_t arg_size) {

    mtrie_destroy((mtrie_t *)mtrie);
    XFREE(mtrie);
    return NULL;
}

void
access_list_purge_tcam_mtrie (node_t *node, 
                                                    mtrie_t *mtrie) {

    task_create_new_job(EV_PURGER(node), 
                         (void *)mtrie, 
                         mtrie_purge_cbk, 
                         TASK_ONE_SHOT,
                         TASK_PRIORITY_GARBAGE_COLLECTOR);
}

c_string
access_list_get_installation_time_duration (access_list_t *access_list, c_string time_str, size_t size) {

    time_t end_time;

    if (access_list_is_installation_in_progress(access_list)) {
        end_time = time(NULL);
    }
    else if (access_list_is_compiled(access_list)){
        end_time = access_list->installation_end_time;
    }
    else return NULL;

    return hrs_min_sec_format(difftime(end_time, access_list->installation_start_time),
                                                time_str, size);
}

c_string
acl_entry_get_installation_time_duration (acl_entry_t *acl_entry, c_string time_str, size_t size) {

    time_t end_time;

    if (acl_entry->installation_in_progress) {
        end_time = time(NULL);
    }
    else if (acl_entry->is_installed){
        end_time = acl_entry->installation_end_time;
    }
    else return NULL;

    return hrs_min_sec_format(difftime(end_time, acl_entry->installation_start_time),
                                                time_str, size);
}

uint32_t 
acl_entry_get_tcam_entry_count (acl_entry_t *acl_entry) {

    glthread_t *curr;
    uint32_t count = 1, og_count = 0;
    glthread_t og_list_head = {0,  0};
    obj_grp_list_node_t *obj_grp_list_node;

    if (!acl_entry->is_compiled) return 0;

    switch (acl_entry->src_addr.acl_addr_format)
    {
    case ACL_ADDR_NOT_SPECIFIED:
    case ACL_ADDR_HOST:
    case ACL_ADDR_SUBNET_MASK:
    case ACL_ADDR_OBJECT_NETWORK:
        count *= acl_entry->tcam_saddr_count;
        break;
    case ACL_ADDR_OBJECT_GROUP:
        switch (acl_entry->src_addr.u.og->og_type)
        {
        case OBJECT_GRP_TYPE_UNKNOWN:
            assert(0);
        case OBJECT_GRP_NET_ADDR:
        case OBJECT_GRP_NET_HOST:
        case OBJECT_GRP_NET_RANGE:
            count *= acl_entry->src_addr.u.og->count;
            break;
        case OBJECT_GRP_NESTED:
            object_group_queue_all_leaf_ogs(
                acl_entry->src_addr.u.og, 
                &og_list_head);
             og_count = 0;
            ITERATE_GLTHREAD_BEGIN(&og_list_head, curr) {
                obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                og_count += obj_grp_list_node->og->count;
                obj_grp_list_node->og->ref_count--;
                remove_glthread(curr);
                XFREE(obj_grp_list_node);
            } ITERATE_GLTHREAD_END(&og_list_head, curr);
            count *= og_count;
            break;
        }
        break;
    default:;
    }

    count *= acl_entry->tcam_sport_count;

    switch (acl_entry->dst_addr.acl_addr_format)
    {
    case ACL_ADDR_NOT_SPECIFIED:
    case ACL_ADDR_HOST:
    case ACL_ADDR_SUBNET_MASK:
    case ACL_ADDR_OBJECT_NETWORK:
        count *= acl_entry->tcam_daddr_count;
        break;
    case ACL_ADDR_OBJECT_GROUP:
        switch (acl_entry->dst_addr.u.og->og_type)
        {
        case OBJECT_GRP_TYPE_UNKNOWN:
            assert(0);
        case OBJECT_GRP_NET_ADDR:
        case OBJECT_GRP_NET_HOST:
        case OBJECT_GRP_NET_RANGE:
            count *= acl_entry->dst_addr.u.og->count;
            break;
        case OBJECT_GRP_NESTED:
            object_group_queue_all_leaf_ogs(
                acl_entry->dst_addr.u.og, 
                &og_list_head);
             og_count = 0;
            ITERATE_GLTHREAD_BEGIN(&og_list_head, curr) {
                obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                og_count += obj_grp_list_node->og->count;
                obj_grp_list_node->og->ref_count--;
                remove_glthread(curr);
                XFREE(obj_grp_list_node);
            } ITERATE_GLTHREAD_END(&og_list_head, curr);
            count *= og_count;
            break;
        }
        break;
    default:;
    }

    count *= acl_entry->tcam_dport_count;
    return count;
}

void 
acl_mem_init() {

    MM_REG_STRUCT(0, acl_entry_t);
    MM_REG_STRUCT(0, access_list_t);
    MM_REG_STRUCT(0, acl_tcam_t);
    MM_REG_STRUCT(0, mnode_acl_list_node_t);
    MM_REG_STRUCT(0, acl_tcam_iterator_t);
    MM_REG_STRUCT(0, access_list_processing_info_t);
}
