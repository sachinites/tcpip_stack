#include <stdlib.h>
#include <memory.h>
#include "../../LinuxMemoryManager/uapi_mm.h"
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"
#include "../../FireWall/acl/acldb.h"
#include "../../utils.h"
#include "objnw.h"

#define HASH_PRIME_CONST    5381

/* Refer : http://www.cs.yorku.ca/~oz/hash.html */
static unsigned int
hashfromkey(void *key) {

        unsigned char *str = (unsigned char *)key;
        unsigned int hash = HASH_PRIME_CONST ;
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
    strncpy(obj_nw->name, name, OBJ_NETWORK_NAME_LEN);
    obj_nw->name[OBJ_NETWORK_NAME_LEN] = '\0';
    obj_nw->db = (obj_nw_linkage_db_t *)XCALLOC(0, 1, obj_nw_linkage_db_t);
    return obj_nw;
}

bool
network_object_insert_into_ht (hashtable_t *ht, obj_nw_t *obj_nw) {

    char *key = (char *)calloc (OBJ_NETWORK_NAME_LEN, sizeof(char));
    strncpy (key, obj_nw->name, OBJ_NETWORK_NAME_LEN);
    key[OBJ_NETWORK_NAME_LEN] = '\0';

    if (!hashtable_insert (ht, (void *)key, (void *)obj_nw)) {
        return false;
    }
    return true;
}

obj_nw_t *
network_object_remove_from_ht_by_name (hashtable_t *ht, const char *name) {

    return  (obj_nw_t *)hashtable_remove(ht, (void *)name);
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
            printf (" network-object %s %s %s\n", obj_nw->name, obj_nw_type_str(obj_nw->type), tcp_ip_covert_ip_n_to_p(obj_nw->u.host , ip));
            break;
        case OBJ_NW_TYPE_SUBNET:
            printf ("%s ", tcp_ip_covert_ip_n_to_p (obj_nw->u.subnet.network, ip));
            printf ("%s\n", tcp_ip_covert_ip_n_to_p (obj_nw->u.subnet.subnet, ip));
            break;
        case OBJ_NW_TYPE_RANGE:
            printf ("[%s -- ", tcp_ip_covert_ip_n_to_p (obj_nw->u.range.lb, ip));
            printf ("%s]\n", tcp_ip_covert_ip_n_to_p (obj_nw->u.range.ub, ip));
            break;
        case OBJ_NW_TYPE_NONE:
            printf ("None\n");
            break;
    }

    printf ("  ACLs referenced:\n");
    
    obj_nw_linkage_db_t *db = (obj_nw_linkage_db_t *)obj_nw->db;

    glthread_t *curr;

    if (db) {

        ITERATE_GLTHREAD_BEGIN(&db->acls_list, curr) {

            obj_nw_linked_acl_thread_node_t *obj_nw_linked_acl_thread_node = glue_to_obj_nw_linked_acl_thread_node(curr);

            printf (" access-list : %s\n", obj_nw_linked_acl_thread_node->acl->access_lst->name);
            
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

    printf("# Object Networks : %u\n", count);

    if (!count) return;

    itr = hashtable_iterator(ht);

    do
    {
        char *key = (char *)hashtable_iterator_key(itr);
        obj_nw_t *obj_nw = (obj_nw_t *)hashtable_iterator_value(itr);
        object_network_print(obj_nw);
    } while (hashtable_iterator_advance(itr));

    XFREE(itr);
}

bool
network_object_check_and_delete (obj_nw_t *obj_nw) {

    return true;
}