#include <stdlib.h>
#include <memory.h>
#include "../../LinuxMemoryManager/uapi_mm.h"
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"
#include "../../FireWall/acl/acldb.h"
#include "../../utils.h"
#include "objnw.h"
#include "../../CLIBuilder/libcli.h"

#define HASH_PRIME_CONST    5381

/* Refer : http://www.cs.yorku.ca/~oz/hash.html */
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

hashtable_t *object_network_create_new_ht() {

    hashtable_t *h = create_hashtable(128, hashfromkey, equalkeys);
    return h;
}

obj_nw_t *
network_object_create_new (const char *name, obj_nw_type_t type) {

    obj_nw_t *obj_nw = (obj_nw_t *) XCALLOC (0, 1, obj_nw_t);
    obj_nw->type = type;
    string_copy((char *)obj_nw->name, name, OBJ_NETWORK_NAME_LEN);
    obj_nw->name[OBJ_NETWORK_NAME_LEN] = '\0';
    obj_nw->db = NULL;
    return obj_nw;
}

bool
network_object_insert_into_ht (hashtable_t *ht, obj_nw_t *obj_nw) {

    char *key = (char *)calloc (OBJ_NETWORK_NAME_LEN, sizeof(char));
    string_copy ((char *)key, obj_nw->name, OBJ_NETWORK_NAME_LEN);
    key[OBJ_NETWORK_NAME_LEN] = '\0';

    if (!hashtable_insert (ht, (void *)key, (void *)obj_nw)) {
        return false;
    }
    return true;
}

obj_nw_t *
network_object_remove_from_ht_by_name (hashtable_t *ht, const char *name) {

    return (obj_nw_t *)hashtable_remove(ht, (void *)name);
}

obj_nw_t *
network_object_lookup_by_name (hashtable_t *ht, const char *name) {

   return (obj_nw_t *)hashtable_search(ht, (void *)name);
}

void 
object_network_print (obj_nw_t *obj_nw) {

    char ip[16];
    switch(obj_nw->type) {
        case OBJ_NW_TYPE_HOST:
            cprintf (" object-network %s %s %s", obj_nw->name, obj_nw_type_str(obj_nw->type), tcp_ip_covert_ip_n_to_p(obj_nw->u.host , ip));
            break;
        case OBJ_NW_TYPE_SUBNET:
             cprintf (" object-network %s %s", obj_nw->name, tcp_ip_covert_ip_n_to_p (obj_nw->u.subnet.network, ip));
             cprintf(" %s", tcp_ip_covert_ip_n_to_p (obj_nw->u.subnet.subnet, ip));
            break;
        case OBJ_NW_TYPE_RANGE:
            cprintf (" object-network %s range %s", obj_nw->name, tcp_ip_covert_ip_n_to_p (obj_nw->u.range.lb, ip));
            cprintf (" %s", tcp_ip_covert_ip_n_to_p (obj_nw->u.range.ub, ip));
            break;
        case OBJ_NW_TYPE_NONE:
            cprintf ("None");
            break;
    }

    cprintf (" (ref-count : %u, #Tcam-Users-Count : %u)\n", 
        obj_nw->ref_count, obj_nw->tcam_entry_users_ref_count);

    cprintf ("  ACLs referenced:\n");
    
    objects_linkage_db_t *db = (objects_linkage_db_t *)obj_nw->db;

    glthread_t *curr;

    if (db) {

        ITERATE_GLTHREAD_BEGIN(&db->acls_list, curr) {

            objects_linked_acl_thread_node_t *obj_nw_linked_acl_thread_node = glue_to_objects_linked_acl_thread_node(curr);

            cprintf ("   access-list %s \n", obj_nw_linked_acl_thread_node->acl->access_list->name);

            
        }ITERATE_GLTHREAD_END(&db->acls_list, curr)


        ITERATE_GLTHREAD_BEGIN(&db->nat_list, curr) {

                

        } ITERATE_GLTHREAD_END(&db->nat_list, curr)
    }
}

void 
network_object_hashtable_print(hashtable_t *ht) {
    
    unsigned int count;
    struct hashtable_itr *itr;

    count = hashtable_count(ht);

    cprintf("Number of Object Networks : %u\n", count);

    if (!count) return;

    itr = hashtable_iterator(ht);

    do
    {
        char *key = (char *)hashtable_iterator_key(itr);
        obj_nw_t *obj_nw = (obj_nw_t *)hashtable_iterator_value(itr);
        object_network_print(obj_nw);
    } while (hashtable_iterator_advance(itr));

    free(itr);
}

bool
network_object_check_and_delete (obj_nw_t *obj_nw) {

    assert(!obj_nw->db);
    assert(!object_network_is_tcam_compiled(obj_nw));
    assert(obj_nw->tcam_entry_users_ref_count == 0);
    XFREE(obj_nw);
    return true;
}

bool
object_network_propogate_update (node_t *node, obj_nw_t *obj_nw) {

    bool rc = false;
    glthread_t *curr;
    acl_entry_t *acl_entry;
    objects_linked_acl_thread_node_t *obj_nw_linked_acl_thread_node;

    if (obj_nw->ref_count == 0) return true;

    /* Iterating over object network acls_list may have ACLs repeated twice,
    therefore made following APIs idempotent for below logic to work correctly.
        1. acl_entry_uninstall
        2. acl_entry_install
        3. acl_decompile
        4. acl_compile
    */

    ITERATE_GLTHREAD_BEGIN(&obj_nw->db->acls_list, curr) {
        
        obj_nw_linked_acl_thread_node = glue_to_objects_linked_acl_thread_node(curr);
        acl_entry = obj_nw_linked_acl_thread_node->acl;
        pthread_rwlock_wrlock(&acl_entry->access_list->mtrie_update_lock);
        acl_entry_uninstall(acl_entry->access_list, acl_entry);
        pthread_rwlock_unlock(&acl_entry->access_list->mtrie_update_lock);
        
    } ITERATE_GLTHREAD_END(&obj_nw->db->acls_list, curr);

    ITERATE_GLTHREAD_BEGIN(&obj_nw->db->acls_list, curr) {

        obj_nw_linked_acl_thread_node = glue_to_objects_linked_acl_thread_node(curr);
        acl_entry = obj_nw_linked_acl_thread_node->acl;
        acl_entry_increment_referenced_objects_tcam_user_count(acl_entry, 1, true, false);
        acl_decompile(acl_entry);
        acl_entry_increment_referenced_objects_tcam_user_count(acl_entry, -1, true, false);
    } ITERATE_GLTHREAD_END(&obj_nw->db->acls_list, curr);

    ITERATE_GLTHREAD_BEGIN(&obj_nw->db->acls_list, curr) {

        obj_nw_linked_acl_thread_node = glue_to_objects_linked_acl_thread_node(curr);
        acl_entry = obj_nw_linked_acl_thread_node->acl;

        if (access_list_should_compile(acl_entry->access_list)) {
            acl_compile(acl_entry);
            pthread_rwlock_wrlock(&acl_entry->access_list->mtrie_update_lock);
            acl_entry_install(acl_entry->access_list, acl_entry);
            pthread_rwlock_unlock(&acl_entry->access_list->mtrie_update_lock);
            /* This may send repeated/redundant notification to clients for the same access list, hence, kick a job to send notification for each access list exactly once , instead of doing it synchronously. */
            access_list_schedule_notification(node, acl_entry->access_list);
        }
    } ITERATE_GLTHREAD_END(&obj_nw->db->acls_list, curr);
    return true;
}

bool
object_network_apply_change_host_address(node_t *node, obj_nw_t *obj_nw, char *host_addr) {

    uint32_t old_host_addr;

    assert(obj_nw->type == OBJ_NW_TYPE_HOST);

    uint32_t host_addr_int = tcp_ip_covert_ip_p_to_n(host_addr);

    if (obj_nw->u.host == host_addr_int) return true;

    old_host_addr = obj_nw->u.host;
    obj_nw->u.host = host_addr_int;

    if (!object_network_propogate_update(node, obj_nw)) {
        obj_nw->u.host = old_host_addr;
        object_network_propogate_update(node, obj_nw);
        return false;
    }
    return true;
}

bool
object_network_apply_change_subnet (node_t *node,
                                                               obj_nw_t *obj_nw,
                                                               char *subnet_addr,
                                                               char *subnet_mask) {

    uint32_t old_subnet_addr, old_subnet_mask;

    assert(obj_nw->type == OBJ_NW_TYPE_SUBNET);

    uint32_t subnet_addr_int = tcp_ip_covert_ip_p_to_n(subnet_addr);
    uint32_t subnet_mask_int = tcp_ip_covert_ip_p_to_n(subnet_mask);

    if (obj_nw->u.subnet.network == subnet_addr_int &&
          obj_nw->u.subnet.subnet ==  subnet_mask_int) return true;

    old_subnet_addr = obj_nw->u.subnet.network;
    old_subnet_mask = obj_nw->u.subnet.subnet;
    obj_nw->u.subnet.network =  subnet_addr_int;
    obj_nw->u.subnet.subnet =  subnet_mask_int;

    if (!object_network_propogate_update(node, obj_nw)) {
         obj_nw->u.subnet.network = old_subnet_addr;
         obj_nw->u.subnet.subnet = old_subnet_mask;
        object_network_propogate_update(node, obj_nw);
        return false;
    }
    return true;
}

bool
object_network_apply_change_range (node_t *node,
                                                               obj_nw_t *obj_nw,
                                                               uint32_t lb,
                                                               uint32_t ub) {

    uint32_t old_lb, old_ub;

    assert(obj_nw->type == OBJ_NW_TYPE_RANGE);

    if (obj_nw->u.range.lb == lb && obj_nw->u.range.ub ==  ub) return true;

    old_lb = obj_nw->u.range.lb;
    old_ub = obj_nw->u.range.ub;

    obj_nw->u.range.lb = lb;
    obj_nw->u.range.ub = ub;

    if (!object_network_propogate_update(node, obj_nw)) {
         obj_nw->u.range.lb = old_lb;
         obj_nw->u.range.ub =old_ub;
        object_network_propogate_update(node, obj_nw);
        return false;
    }
    return true;
}

bool
object_network_is_tcam_compiled (obj_nw_t *obj_nw) {

    return obj_nw->count > 0;
}

static void
object_network_tcam_compile (obj_nw_t *obj_nw)  {

    switch(obj_nw->type) {

        case OBJ_NW_TYPE_HOST:
            obj_nw->count = 1;
            assert(!obj_nw->prefix);
            obj_nw->prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * obj_nw->count);
            assert(!obj_nw->wcard);
            obj_nw->wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * obj_nw->count);
            (*obj_nw->prefix)[0] = htonl(obj_nw->u.host);
            (*obj_nw->wcard)[0] = 0;            
            break;
        case OBJ_NW_TYPE_SUBNET:
            obj_nw->count = 1;
            assert(!obj_nw->prefix);
            obj_nw->prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * obj_nw->count);
            assert(!obj_nw->wcard);
            obj_nw->wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * obj_nw->count);
            (*obj_nw->prefix)[0] = htonl(obj_nw->u.subnet.network & obj_nw->u.subnet.subnet);
            (*obj_nw->wcard)[0] = htonl(~obj_nw->u.subnet.subnet);   
            break;
        case OBJ_NW_TYPE_RANGE:
            assert(!obj_nw->prefix);
            assert(!obj_nw->wcard);
            obj_nw->prefix = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * sizeof(*obj_nw->prefix));
            obj_nw->wcard = (uint32_t(*)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT])
                XCALLOC_BUFF(0, sizeof(uint32_t) * sizeof(*obj_nw->wcard));
            range2_prefix_wildcard_conversion32(
                obj_nw->u.range.lb,
                obj_nw->u.range.ub,
                obj_nw->prefix,
                obj_nw->wcard,
                (int *)&obj_nw->count);
            break;
        case OBJ_NW_TYPE_NONE:
            assert(0);
        default: ;
    }
}

static void
object_network_tcam_decompile(obj_nw_t *obj_nw)  {

    assert(obj_nw->prefix);
    assert(obj_nw->wcard);
    XFREE(obj_nw->prefix);
    XFREE(obj_nw->wcard);
    obj_nw->count = 0;
    obj_nw->prefix = NULL;
    obj_nw->wcard = NULL;
}

void
object_network_dec_tcam_users_count (obj_nw_t *obj_nw) {

    assert(obj_nw->tcam_entry_users_ref_count);
    obj_nw->tcam_entry_users_ref_count--;
    if (obj_nw->tcam_entry_users_ref_count == 0) {
        assert(object_network_is_tcam_compiled(obj_nw));
        object_network_tcam_decompile(obj_nw);
    }
}

void
object_network_inc_tcam_users_count (obj_nw_t *obj_nw) {

    if (obj_nw->tcam_entry_users_ref_count == 0) {
        assert(!object_network_is_tcam_compiled(obj_nw));
        object_network_tcam_compile(obj_nw);
    }
    obj_nw->tcam_entry_users_ref_count++;
}

void
object_network_borrow_tcam_data (obj_nw_t *obj_nw,
                            uint8_t *count, 
                            uint32_t (**prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],
                            uint32_t (**wcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT]) {

    object_network_inc_tcam_users_count(obj_nw);
    *count = obj_nw->count;
    *prefix = (obj_nw->prefix);
    *wcard = (obj_nw->wcard);
}

void
object_network_mem_init () {

    MM_REG_STRUCT(0, obj_nw_t);
    MM_REG_STRUCT(0, obj_nw_type_t);
    MM_REG_STRUCT(0, objects_linked_acl_thread_node_t);
    MM_REG_STRUCT(0, objects_linkage_db_t);
}
