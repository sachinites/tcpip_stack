#if 0

Object-Groups :

Object-Groups are used to organize and club the network entities with similar properties/constraints or role together. They play a vital role in making the configuration of a network device manageable, and exponentially decrease the number of ACL/NAT rules the admin would need to configure otherwise. 
Object-Groups are hierarchical, meaning nested object-groups can also exist and used by other systems of networking device such as ACLs/NATs, Policies etc. 

Example of Configuration of Object-Groups :

Soft-FireWall> config-node-R2 $ object-group network DNS-Servers host 120.1.1.1
Parse Success.
CLI returned

Soft-FireWall> config-node-R2 $ object-group network DNS-Servers host 120.1.1.2
Parse Success.
CLI returned

Soft-FireWall> config-node-R2 $ object-group network DNS-Servers range 120.1.1.3 120.1.1.4
Parse Success.
CLI returned

Soft-FireWall> config-node-R2 $ object-group network DNS-Servers 121.1.1.0 255.255.255.0
Parse Success.
CLI returned

Now Configure Access-List which to block all IP traffic destined to any of DNS Servers
Soft-FireWall> config-node-R2 $ access-list block-dns-access 1 deny ip 0.0.0.0 0.0.0.0 object-group DNS-Servers
Parse Success.
CLI returned

Now Apply ACL on inside interface of firewall
Soft-FireWall> config-node-R2 $ access-group block-dns-access in interface eth3
Parse Success.
CLI returned

You can see from above config steps, just one single ACL is suffice to block all ip traffic destined to several DNS Servers. This is how powerful tool object-groups are. 

Language : C
Data Structures : BiDirectional N-Trees ( to store object-groups)
(N-Trees are trees where each node can have N children and M parents)
Algorithms : Pre/Post Order traversal over N-Trees. 

#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "../../graph.h"
#include "object_group.h"
#include "objects_common.h"
#include "../acl/acldb.h"
#include "../fwall_trace_const.h"
#include "../../CLIBuilder/libcli.h"

#define HASH_PRIME_CONST    5381

static unsigned int
hashfromkey(void *key) {

    unsigned char *str = (unsigned char *)key;
    unsigned int hash = HASH_PRIME_CONST;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

static int
equalkeys(void *k1, void *k2)
{
    char *ky1 = (char *)k1;
    char *ky2 = (char *)k2;
    int len1 = strlen(ky1);
    int len2 = strlen(ky2);
    if (len1 != len2) return len1 - len2;
    return (0 == memcmp(k1,k2, len1));
}

hashtable_t *object_group_create_new_ht() {

    hashtable_t *h = create_hashtable(128, hashfromkey, equalkeys);
    assert(h);
    return h;
}

/* NESTED OGs are always treated as NOT compiled */
static void
object_group_tcam_compile (object_group_t *og)  {

    if (object_group_is_tcam_compiled(og)) return;

    switch(og->og_type) {

        case OBJECT_GRP_NET_HOST:
            og->count = 1;
            assert(!og->prefix);
            og->prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * og->count);
            assert(!og->wcard);
            og->wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * og->count);
            (*og->prefix)[0] = htonl(og->u.host);
            (*og->wcard)[0] = 0;          
            og->tcam_state = OG_TCAM_STATE_COMPILED;  
            break;
        case OBJECT_GRP_NET_ADDR:
            og->count = 1;
            assert(!og->prefix);
            og->prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * og->count);
            assert(!og->wcard);
            og->wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * og->count);
            (*og->prefix)[0] = htonl(og->u.subnet.network & og->u.subnet.subnet);
            (*og->wcard)[0] = htonl(~og->u.subnet.subnet);   
            og->tcam_state = OG_TCAM_STATE_COMPILED;  
            break;
        case OBJECT_GRP_NET_RANGE:
            assert(!og->prefix);
            assert(!og->wcard);
            og->prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * sizeof(*og->prefix));
            og->wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * sizeof(*og->wcard));
            range2_prefix_wildcard_conversion32(
                og->u.range.lb,
                og->u.range.ub,
                og->prefix,
                og->wcard,
                (int *)&og->count);
                og->tcam_state = OG_TCAM_STATE_COMPILED;  
            break;
        case OBJECT_GRP_NESTED:
        {
            glthread_t *curr;
            obj_grp_list_node_t *obj_grp_list_node;

            ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr) {

                obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                object_group_tcam_compile(obj_grp_list_node->og);

            } ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr);

        }
            break;
        case OBJECT_GRP_TYPE_UNKNOWN:
            assert(0);
        default: ;
    }
}

static void
object_group_tcam_decompile(object_group_t *og) {

    switch (og->og_type)
    {
    case OBJECT_GRP_NET_ADDR:
    case OBJECT_GRP_NET_HOST:
    case OBJECT_GRP_NET_RANGE:
        if (!object_group_is_tcam_compiled(og)) return;
        assert(og->prefix);
        assert(og->wcard);
        XFREE(og->prefix);
        XFREE(og->wcard);
        og->count = 0;
        og->prefix = NULL;
        og->wcard = NULL;
        og->tcam_state = OG_TCAM_STATE_NOT_COMPILED;
        break;
    case OBJECT_GRP_NESTED:
    {
        glthread_t *curr;
        obj_grp_list_node_t *obj_grp_list_node;

        ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr)
        {
            obj_grp_list_node = glue_to_obj_grp_list_node(curr);
            object_group_tcam_decompile(obj_grp_list_node->og);
        }
        ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr);
    }
    break;
    default: ;
    }
}

/* Nested OGs are always assumed to be NOT compiled*/
bool
object_group_is_tcam_compiled(object_group_t *og) {

    switch (og->og_type) {
        case OBJECT_GRP_NET_ADDR:
        case OBJECT_GRP_NET_HOST:
        case OBJECT_GRP_NET_RANGE:
            return og->tcam_state == OG_TCAM_STATE_COMPILED;
        case OBJECT_GRP_NESTED:
            return false;
        default:
            assert(0);
    }
}


void
object_group_dec_tcam_users_count (object_group_t *og) {

    switch(og->og_type) {
        case OBJECT_GRP_NET_ADDR:
        case OBJECT_GRP_NET_HOST:
        case  OBJECT_GRP_NET_RANGE:
            og->tcam_entry_users_ref_count--;
            if (og->tcam_entry_users_ref_count == 0) {
                assert(og->tcam_state == OG_TCAM_STATE_COMPILED);
                object_group_tcam_decompile(og);
            }
            break;
        case OBJECT_GRP_NESTED:
        {
            glthread_t *curr;
            obj_grp_list_node_t *obj_grp_list_node;

            ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr)
            {

                obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                object_group_dec_tcam_users_count(obj_grp_list_node->og);
            }
            ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr);
        }
        break;
    }
}

void
object_group_inc_tcam_users_count (object_group_t *og) {

    switch(og->og_type) {
        case OBJECT_GRP_NET_ADDR:
        case OBJECT_GRP_NET_HOST:
        case  OBJECT_GRP_NET_RANGE:
            if (og->tcam_entry_users_ref_count == 0) {
                assert(og->tcam_state == OG_TCAM_STATE_NOT_COMPILED);
                object_group_tcam_compile(og);
            }
            og->tcam_entry_users_ref_count++;
            break;
        case OBJECT_GRP_NESTED:
        {
            glthread_t *curr;
            obj_grp_list_node_t *obj_grp_list_node;

            ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr)
            {

                obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                object_group_inc_tcam_users_count(obj_grp_list_node->og);
            }
            ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr);
        }
        break;
    }
}

void
object_group_borrow_tcam_data (object_group_t *og,
                            uint8_t *count, 
                            uint32_t (**prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],
                            uint32_t (**wcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT]) {

    *count = og->count;
    *prefix = og->prefix;
    *wcard = og->wcard;
    object_group_inc_tcam_users_count(og);
}


object_group_t *
object_group_lookup_ht_by_name (node_t *node, 
                                                          hashtable_t *ht,
                                                          c_string og_name) { 

    return (object_group_t *)hashtable_search(ht, (void *)og_name);
}

object_group_t *
object_group_remove_from_ht_by_name (node_t *node, hashtable_t *ht, c_string og_name) {

    return (object_group_t *)hashtable_remove(ht, (void *)og_name);
}

bool
object_group_remove_from_ht (node_t *node, hashtable_t *ht, object_group_t *og) {

    object_group_t *og1 = (object_group_t *)hashtable_remove(ht, (void *)og->og_name);
    if (!og1) return false;
    assert(og == og1);
    return true;
}

bool
object_group_insert_into_ht (node_t *node, hashtable_t *ht,  object_group_t *og) {

    c_string key = (c_string) calloc (OBJ_GRP_NAME_LEN, sizeof(byte));
    string_copy (key, og->og_name, OBJ_GRP_NAME_LEN);
    key[OBJ_GRP_NAME_LEN] = '\0';

    if (!hashtable_insert (ht, (void *)key, (void *)og)) {
        return false;
    }
    return true;
}

object_group_t *
object_group_malloc (const c_string name, og_type_t og_type) {

    object_group_t *og;
    og = (object_group_t *)XCALLOC(0, 1, object_group_t);
    og->cycle_det_id = 0;
    string_copy(og->og_name, name, OBJ_GRP_NAME_LEN);
    og->ref_count = 0;
    og->og_desc = NULL;
    og->og_type = og_type;
    init_glthread(&og->parent_og_list_head);
    return og;
}

void
object_group_bind (object_group_t *p_og, object_group_t *c_og) {

    assert(p_og->og_type == OBJECT_GRP_NESTED);

    obj_grp_list_node_t *obj_grp_list_node = (obj_grp_list_node_t *)XCALLOC(0, 1, obj_grp_list_node_t);
    obj_grp_list_node->og = c_og;
    glthread_add_last(&p_og->u.nested_og_list_head, &obj_grp_list_node->glue);

    obj_grp_list_node = (obj_grp_list_node_t *)XCALLOC(0, 1, obj_grp_list_node_t);
    obj_grp_list_node->og = p_og;
    glthread_add_last(&c_og->parent_og_list_head, &obj_grp_list_node->glue);
}

c_string
object_group_network_construct_name (
                                        og_type_t og_type, 
                                        uint32_t ip_addr1,
                                        uint32_t ip_addr2,
                                        c_string output) {

    byte ip_addr[16];
    byte ip_addr3[16];

    memset(output, 0, OBJ_GRP_NAME_LEN);

    switch(og_type) {
        case OBJECT_GRP_NET_ADDR:
        case OBJECT_GRP_NET_RANGE:
            snprintf(output, OBJ_GRP_NAME_LEN, "%s-%s-%s",
                 object_group_type_str(og_type),
                 tcp_ip_covert_ip_n_to_p(ip_addr1, ip_addr),
                 tcp_ip_covert_ip_n_to_p(ip_addr2, ip_addr3));
            break;
        case OBJECT_GRP_NET_HOST:
            snprintf(output, OBJ_GRP_NAME_LEN, "%s-%s", 
                 object_group_type_str(og_type),
                tcp_ip_covert_ip_n_to_p(ip_addr1, ip_addr));
            break;
        case OBJECT_GRP_NESTED:
            assert(0);
            break;
    }
    return output;
}

object_group_t *
object_group_find_child_object_group (object_group_t *og, c_string obj_grp_name) {

    glthread_t *curr;
    obj_grp_list_node_t *obj_grp_list_node;

    if (og->og_type != OBJECT_GRP_NESTED) return NULL;

    ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr) {

        obj_grp_list_node = glue_to_obj_grp_list_node(curr);
        if (string_compare (obj_grp_list_node->og->og_name, 
                                        obj_grp_name,
                                        OBJ_GRP_NAME_LEN) == 0) {
            return obj_grp_list_node->og;
        }
    } ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr) 
    return NULL;
}

void
object_group_display_detail (node_t *node, object_group_t *og) {

    glthread_t *curr;
    obj_grp_list_node_t *obj_grp_list_node;

    cprintf ("OG : %s  ", og->og_name);

    cprintf (" (ref-count : %u, #Tcam-Users-Count : %u, Compiled ? %s)\n", 
        og->ref_count, og->tcam_entry_users_ref_count,
        og->tcam_state == OG_TCAM_STATE_COMPILED ? "Y" : "N");

    ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr) {

        obj_grp_list_node = glue_to_obj_grp_list_node(curr);
        cprintf ("  C-OG : %s ", obj_grp_list_node->og->og_name);
        cprintf (" (ref-count : %u, #Tcam-Users-Count : %u, Compiled ? %s)\n", 
        obj_grp_list_node->og->ref_count, obj_grp_list_node->og->tcam_entry_users_ref_count,
        obj_grp_list_node->og->tcam_state == OG_TCAM_STATE_COMPILED ? "Y" : "N");

    } ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr);

    ITERATE_GLTHREAD_BEGIN(&og->parent_og_list_head, curr) {

        obj_grp_list_node = glue_to_obj_grp_list_node(curr);
        cprintf ("  P-OG : %s ", obj_grp_list_node->og->og_name);
        cprintf (" (ref-count : %u, #Tcam-Users-Count : %u, Compiled ? %s)\n", 
        obj_grp_list_node->og->ref_count, obj_grp_list_node->og->tcam_entry_users_ref_count,
        obj_grp_list_node->og->tcam_state == OG_TCAM_STATE_COMPILED ? "Y" : "N");

    } ITERATE_GLTHREAD_END(&og->parent_og_list_head, curr);
}

#if 0
void 
object_group_display (object_group_t *og) {

    char ip[16];
    switch(og->og_type) {
        case OBJECT_GRP_NET_HOST:
            cprintf ("  object-group network %s %s %s", og->og_name, 
                object_group_type_str(og->og_type),
                tcp_ip_covert_ip_n_to_p(og->u.host , ip));
            cprintf (" (ref-count : %u, #Tcam-Users-Count : %u)\n", 
                og->ref_count, og->tcam_entry_users_ref_count);
            break;
        case OBJECT_GRP_NET_ADDR:
             cprintf ("  object-group network %s %s", og->og_name, 
             tcp_ip_covert_ip_n_to_p (og->u.subnet.network, ip));
             cprintf(" %s", tcp_ip_covert_ip_n_to_p (og->u.subnet.subnet, ip));
            cprintf (" (ref-count : %u, #Tcam-Users-Count : %u)\n", 
                og->ref_count, og->tcam_entry_users_ref_count);             
            break;
        case OBJECT_GRP_NET_RANGE:
            cprintf ("  object-group network %s range %s", og->og_name, 
            tcp_ip_covert_ip_n_to_p (og->u.range.lb, ip));
            cprintf (" %s", tcp_ip_covert_ip_n_to_p (og->u.range.ub, ip));
            cprintf (" (ref-count : %u, #Tcam-Users-Count : %u)\n", 
                og->ref_count, og->tcam_entry_users_ref_count);
            break;
        case OBJECT_GRP_NESTED:
        {
            glthread_t *curr;
            obj_grp_list_node_t *obj_grp_list_node;

            ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr) {

                obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                cprintf (" object-group network %s group-object %s", 
                    og->og_name, obj_grp_list_node->og->og_name);
                cprintf (" (ref-count : %u, #Tcam-Users-Count : %u)\n", 
                og->ref_count, og->tcam_entry_users_ref_count);

                object_group_display(obj_grp_list_node->og);

            } ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr);
        }
        break;
    }

    cprintf ("  ACLs referenced:\n");
    
    objects_linkage_db_t *db = (objects_linkage_db_t *)og->db;

    glthread_t *curr;

    if (db) {

        ITERATE_GLTHREAD_BEGIN(&db->acls_list, curr) {

            objects_linked_acl_thread_node_t *objects_linked_acl_thread_node = glue_to_objects_linked_acl_thread_node(curr);

            cprintf ("   access-list %s \n", objects_linked_acl_thread_node->acl->access_lst->name);

            
        }ITERATE_GLTHREAD_END(&db->acls_list, curr)


        ITERATE_GLTHREAD_BEGIN(&db->nat_list, curr) {

                

        } ITERATE_GLTHREAD_END(&db->nat_list, curr)
    }
}
#endif

void 
object_group_hashtable_print(node_t *node, hashtable_t *ht) {
    
    unsigned int count;
    struct hashtable_itr *itr;

    count = hashtable_count(ht);

    cprintf("Number of Object Groups : %u\n", count);

    if (!count) return;

    itr = hashtable_iterator(ht);

    do
    {
        char *key = (char *)hashtable_iterator_key(itr);
        object_group_t *og = (object_group_t *)hashtable_iterator_value(itr);
        object_group_display_detail (node, og);
        cprintf ("\n");
    } while (hashtable_iterator_advance(itr));

    free(itr);
}

/* Check all references of this object group */
bool
object_group_in_use_by_other_og (object_group_t *og) {

    if (og->og_type == OBJECT_GRP_NET_ADDR ||
         og->og_type == OBJECT_GRP_NET_HOST ||
         og->og_type == OBJECT_GRP_NET_RANGE) {

        return false;
    }

    /* Nested og must not have any parent */
    if (!IS_GLTHREAD_LIST_EMPTY(&og->parent_og_list_head)) {
        return true;
    }

    return false;
}

void 
 object_group_free (node_t *node, object_group_t *og) {

    assert(IS_GLTHREAD_LIST_EMPTY(&og->parent_og_list_head));
    assert(!og->ref_count);
    assert(!og->tcam_entry_users_ref_count);

    if (og->og_type == OBJECT_GRP_NESTED) {
        assert(IS_GLTHREAD_LIST_EMPTY(&og->u.nested_og_list_head));
        assert(!og->og_desc);
    }

    assert(!object_group_remove_from_ht (node, node->object_group_ght, og));

    sprintf (tlb, "%s : OG %s is deleted\n", FWALL_OBJGRP_UPDATE,
        og->og_name);
    tcp_trace(node, 0, tlb);
    XFREE(og);
}

void
object_group_delete (node_t *node, object_group_t *og) {

    glthread_t *curr;
    object_group_t *p_og;
    obj_grp_list_node_t *obj_grp_list_node;
    obj_grp_list_node_t *obj_grp_list_node2;

    assert(!object_group_in_use_by_other_og(og));
    assert(!og->ref_count);
    assert(!og->tcam_entry_users_ref_count);

    if (og->og_type == OBJECT_GRP_NET_ADDR ||
         og->og_type == OBJECT_GRP_NET_HOST ||
         og->og_type == OBJECT_GRP_NET_RANGE) {

        /* Remove Self from its parent Child's list */
        curr = dequeue_glthread_first(&og->parent_og_list_head);
        assert(IS_GLTHREAD_LIST_EMPTY(&og->parent_og_list_head));
        obj_grp_list_node = glue_to_obj_grp_list_node(curr);
        p_og = obj_grp_list_node->og;
        XFREE(obj_grp_list_node);
        obj_grp_list_node = object_group_search_by_ptr (&p_og->u.nested_og_list_head, og);
        assert(obj_grp_list_node);
        remove_glthread(&obj_grp_list_node->glue);
        XFREE(obj_grp_list_node);
        object_group_free (node, og);
        return;
    }

    ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr) {

        obj_grp_list_node = glue_to_obj_grp_list_node(curr);

        if (obj_grp_list_node->og->og_type == OBJECT_GRP_NET_ADDR ||
            obj_grp_list_node->og->og_type == OBJECT_GRP_NET_HOST ||
            obj_grp_list_node->og->og_type == OBJECT_GRP_NET_RANGE) {

            object_group_delete(node, obj_grp_list_node->og);
            continue;
        }

        obj_grp_list_node2 = object_group_search_by_ptr (&obj_grp_list_node->og->parent_og_list_head, og);
        assert(obj_grp_list_node2);
        remove_glthread(&obj_grp_list_node2->glue);
        remove_glthread(&obj_grp_list_node->glue);
        XFREE(obj_grp_list_node);
        XFREE(obj_grp_list_node2);

    } ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr);

    if (og->og_desc) {
        XFREE(og->og_desc);
        og->og_desc = NULL;
    }

    assert(object_group_remove_from_ht (node, node->object_group_ght, og));
    object_group_free (node, og);
}

obj_grp_list_node_t *
object_group_search_by_ptr (glthread_t *head, object_group_t *og) {

    glthread_t *curr;
    obj_grp_list_node_t *obj_grp_list_node;

     ITERATE_GLTHREAD_BEGIN(head, curr) {

        obj_grp_list_node = glue_to_obj_grp_list_node(curr);
        if (obj_grp_list_node->og == og) return obj_grp_list_node;

     } ITERATE_GLTHREAD_END(head, curr);
     return NULL;
}

/* Search in c_og's parent list for p_og, and remove reference */
void
object_group_unbind_parent (object_group_t *p_og, object_group_t *c_og) {

    glthread_t *curr;
    obj_grp_list_node_t *obj_grp_list_node;

    assert(p_og->og_type == OBJECT_GRP_NESTED);

    obj_grp_list_node = object_group_search_by_ptr(&c_og->parent_og_list_head, p_og);

    remove_glthread(&obj_grp_list_node->glue);

    XFREE(obj_grp_list_node);
}

/* Search in p_og's child's list for c_og, and remove reference */
void
object_group_unbind_child (object_group_t *p_og, object_group_t *c_og) {

    glthread_t *curr;
    obj_grp_list_node_t *obj_grp_list_node;

    assert(p_og->og_type == OBJECT_GRP_NESTED);

    obj_grp_list_node = object_group_search_by_ptr(&p_og->u.nested_og_list_head, c_og);

    remove_glthread(&obj_grp_list_node->glue);

    XFREE(obj_grp_list_node);
}

static void
_object_group_queue_all_leaf_ogs(object_group_t *og, glthread_t *list_head) {

    glthread_t *curr;
    obj_grp_list_node_t *obj_grp_list_node, *obj_grp_list_node2;
    
    ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr) {

        obj_grp_list_node = glue_to_obj_grp_list_node(curr);
        if (obj_grp_list_node->og->cycle_det_id == og->cycle_det_id) continue;
        obj_grp_list_node->og->cycle_det_id = og->cycle_det_id;

        switch (obj_grp_list_node->og->og_type) {
            case OBJECT_GRP_NET_ADDR:
            case OBJECT_GRP_NET_HOST:
            case OBJECT_GRP_NET_RANGE:
                obj_grp_list_node2 = (obj_grp_list_node_t *)XCALLOC(0, 1, obj_grp_list_node_t);
                obj_grp_list_node2->og = obj_grp_list_node->og;
                obj_grp_list_node->og->ref_count++;
                init_glthread(&obj_grp_list_node2->glue);
                glthread_add_next(list_head, &obj_grp_list_node2->glue);
                break;
            case OBJECT_GRP_NESTED:
                _object_group_queue_all_leaf_ogs(obj_grp_list_node->og, list_head);
                break;
            default: ;
        }
    } ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr);
}

void
object_group_queue_all_leaf_ogs(object_group_t *og_root, glthread_t *list_head) {

    assert(og_root->og_type == OBJECT_GRP_NESTED);    
    og_root->cycle_det_id = rand();
    _object_group_queue_all_leaf_ogs(og_root, list_head);
}

extern void object_grp_update_mem_init();
void
object_group_mem_init () {

    MM_REG_STRUCT(0, object_group_t);
    MM_REG_STRUCT(0, obj_grp_list_node_t);
    object_grp_update_mem_init();
}
