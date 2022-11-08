#ifndef __OBJ_GRP__
#define __OBJ_GRP__

#include <stdint.h>
#include <stdbool.h>
#include "../../utils.h"
#include "../../gluethread/glthread.h"
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"
#include "objects_common.h"

#define OBJ_GRP_NAME_LEN    128

typedef struct node_ node_t ;

typedef enum og_type_ {

    OBJECT_GRP_TYPE_UNKNOWN,
    OBJECT_GRP_NET_ADDR,
    OBJECT_GRP_NET_HOST,
    OBJECT_GRP_NET_RANGE,
    OBJECT_GRP_NESTED
} og_type_t;

static inline c_string 
object_group_type_str(og_type_t type) {

    switch(type) {
        case OBJECT_GRP_TYPE_UNKNOWN:
            return "Unknown";
        case OBJECT_GRP_NET_ADDR:
            return "net";
        case OBJECT_GRP_NET_HOST:
            return "host";
        case OBJECT_GRP_NET_RANGE:
            return "range";
        case OBJECT_GRP_NESTED:
            return "nested";
    }
    return NULL;
}

/* Track whether the OG is compiled or not to avoid redundant compilation
of OGs.  Note that only LEAF OGs are tracked, NESTED OGs are always assumed to
be NOT Compiled */
typedef enum object_group_tcam_compilation_state_ {

    OG_TCAM_STATE_NOT_COMPILED,
    OG_TCAM_STATE_COMPILED
} og_tcam_compilation_state_t;

typedef struct object_group_ {

    int cycle_det_id;
    unsigned char og_name[OBJ_GRP_NAME_LEN];
    /* child og's do not contribute to this ref_count */
    uint32_t ref_count;
    c_string og_desc;
    og_type_t og_type;
    union {
        uint32_t host;
        struct {
            uint32_t network;
            uint32_t subnet;
        } subnet;
        struct {
            uint32_t lb;
            uint32_t ub;
        } range;
        glthread_t nested_og_list_head;
    }u;
    glthread_t parent_og_list_head;

    objects_linkage_db_t *db;

    /* The below five members are valid only for LEAF OGs*/
    /*Tcam Data */
    uint16_t count;
    uint32_t (*prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
    uint32_t (*wcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
    uint16_t tcam_entry_users_ref_count;
    og_tcam_compilation_state_t tcam_state;

} object_group_t;

typedef struct obj_grp_list_node_ {
    object_group_t *og;
    glthread_t glue;    
}obj_grp_list_node_t;
GLTHREAD_TO_STRUCT(glue_to_obj_grp_list_node, obj_grp_list_node_t, glue);

bool
object_group_is_tcam_compiled(object_group_t *og);
void
object_group_dec_tcam_users_count (object_group_t *og);
void
object_group_inc_tcam_users_count (object_group_t *og);
void
object_group_borrow_tcam_data (object_group_t *og,
                            uint8_t *count, 
                            uint32_t (**prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],
                            uint32_t (**wcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT]);

object_group_t *
object_group_lookup_ht_by_name (node_t *node, hashtable_t *ht, c_string og_name);

bool
object_group_insert_into_ht (node_t *node, hashtable_t *ht,  object_group_t *og);

object_group_t *
object_group_remove_from_ht_by_name (node_t *node, hashtable_t *ht, c_string og_name);

bool
object_group_remove_from_ht (node_t *node, hashtable_t *ht, object_group_t *og);

void
object_group_purge_ht (node_t *node, hashtable_t *ht);

hashtable_t *
object_group_create_new_ht (void);

void
object_group_display_detail (node_t *node, object_group_t *og);

object_group_t *
object_group_malloc (const c_string name, og_type_t og_type);

object_group_t *
object_group_find_child_object_group (object_group_t *og, c_string obj_grp_name);

c_string
object_group_network_construct_name (
                                        og_type_t og_type, 
                                        uint32_t ip_addr1,
                                        uint32_t ip_addr2,
                                        c_string output);

void
object_group_bind (object_group_t *p_og, object_group_t *c_og);
void
object_group_unbind_parent (object_group_t *p_og, object_group_t *c_og);
void
object_group_unbind_child (object_group_t *p_og, object_group_t *c_og) ;

void 
object_group_hashtable_print(node_t *node, hashtable_t *ht);

bool
object_group_in_use_by_other_og (object_group_t *og);

void 
 object_group_free (node_t *node, object_group_t *og);

void
object_group_delete (node_t *node, object_group_t *og);

obj_grp_list_node_t *
object_group_search_by_ptr(glthread_t *head, object_group_t *og);

void
object_group_queue_all_leaf_ogs(object_group_t *og_root, glthread_t *list_head);

#endif 