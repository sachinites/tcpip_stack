#ifndef __OBJNW__
#define __OBJNW__

#include <stdint.h>
#include <stdbool.h>
#include "../../graph.h"
#include "../../gluethread/glthread.h"
#include "../../c-hashtable/hashtable.h"
#include "objects_common.h"

typedef struct node_ node_t;

#define OBJ_NETWORK_NAME_LEN    128

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

    objects_linkage_db_t *db;
    
    /* Tcam Data */
    uint16_t count;
    uint32_t (*prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
    uint32_t (*wcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
    uint16_t tcam_entry_users_ref_count;

    uint16_t ref_count;
} obj_nw_t;

bool
object_network_is_tcam_compiled (obj_nw_t *obj_nw) ;

void
object_network_tcam_compile(obj_nw_t *obj_nw) ;

void
object_network_tcam_decompile(obj_nw_t *obj_nw) ;

void
object_network_dec_tcam_users_count (obj_nw_t *obj_nw);

void
object_network_inc_tcam_users_count (obj_nw_t *obj_nw);

void
object_network_borrow_tcam_data (obj_nw_t *obj_nw,
                            uint8_t *count, 
                            uint32_t (**prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],
                            uint32_t (**wcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT]);

hashtable_t *object_network_create_new_ht () ;

obj_nw_t *
network_object_create_new (const char *name, obj_nw_type_t type);

bool
network_object_insert_into_ht (hashtable_t *ht, obj_nw_t *obj_nw);

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

bool
object_network_apply_change_host_address(node_t *node, obj_nw_t *obj_nw, char *host_addr);
bool
object_network_apply_change_subnet (node_t *node,
                                                               obj_nw_t *obj_nw,
                                                               char *subnet_addr,
                                                               char *subnet_mask);
bool
object_network_apply_change_range (node_t *node,
                                                               obj_nw_t *obj_nw,
                                                               uint32_t lb,
                                                               uint32_t ub) ;
bool
object_network_propogate_update (node_t *node, obj_nw_t *obj_nw);

#endif