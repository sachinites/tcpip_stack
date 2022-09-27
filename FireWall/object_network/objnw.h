#ifndef __OBJNW__
#define __OBJNW__

#include <stdint.h>
#include <stdbool.h>
#include "../../graph.h"
#include "../../gluethread/glthread.h"

typedef  struct hashtable hashtable_t;

#define OBJ_NETWORK_NAME_LEN    32

typedef enum {
    OBJ_NW_TYPE_HOST,
    OBJ_NW_TYPE_SUBNET,
    OBJ_NW_TYPE_RANGE,
    OBJ_NW_TYPE_NONE
} obj_nw_type_t;

static char*
obj_nw_type_str (obj_nw_type_t type) {

    switch (type) {
        case OBJ_NW_TYPE_HOST:
            return "host";
        case OBJ_NW_TYPE_SUBNET:
            return "subnet";
        case OBJ_NW_TYPE_RANGE:
            return "range";
        default:
            return "none";
    }
    return NULL;
}

typedef struct acl_entry_ acl_entry_t;
typedef struct obj_nw_linked_acl_thread_node_ {

    acl_entry_t *acl;
    glthread_t glue;
} obj_nw_linked_acl_thread_node_t;
GLTHREAD_TO_STRUCT(glue_to_obj_nw_linked_acl_thread_node, \
                                                obj_nw_linked_acl_thread_node_t, glue);


typedef struct obj_nw_linkage_db_{

    glthread_t acls_list;
    glthread_t nat_list;
} obj_nw_linkage_db_t;


typedef struct obj_nw_ {

    obj_nw_type_t type;
    unsigned char name[OBJ_NETWORK_NAME_LEN];
    union {
        uint32_t host;
        struct {
            uint32_t network;
            uint32_t subnet;
        } subnet;
        struct {
            uint32_t lb;
            uint32_t ub;
        }range;
    }u;

    obj_nw_linkage_db_t *db;
    
    /* Tcam Data */
    uint16_t count;
    uint32_t (*prefix)[32];
    uint32_t (*wcard)[32];

    uint32_t ref_count;
    
} obj_nw_t;

hashtable_t *object_network_create_new_ht () ;

obj_nw_t *
network_object_create_new (const char *name, obj_nw_type_t type);

bool
network_object_insert_into_ht (hashtable_t *ht, obj_nw_t *obj_nw);

void
network_object_compile (obj_nw_t *obj_nw) ;

void
network_object_free_tcam_data (obj_nw_t *obj_nw); 

bool
network_object_check_and_delete (obj_nw_t *obj_nw); 

obj_nw_t *
network_object_remove_from_ht_by_name (hashtable_t *ht, const char *name);

obj_nw_t *
network_object_lookup_by_name (hashtable_t *ht, const char *name);

void
network_object_hashtable_print (hashtable_t *ht) ;

void 
object_network_print (obj_nw_t *obj_nw);

#endif