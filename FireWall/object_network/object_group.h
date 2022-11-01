#ifndef __OBJ_GRP__
#define __OBJ_GRP__

#include <stdint.h>
#include <stdbool.h>
#include "../../utils.h"
#include "../../gluethread/glthread.h"
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"

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
            return "NET";
        case OBJECT_GRP_NET_HOST:
            return "HOST";
        case OBJECT_GRP_NET_RANGE:
            return "RANGE";
        case OBJECT_GRP_NESTED:
            return "NESTED";
    }
    return NULL;
}

typedef struct object_group_ {

    uint32_t cycle_det_id;
    unsigned char og_name[OBJ_GRP_NAME_LEN];
    uint32_t og_ref_count;
    c_string og_desc;
    og_type_t og_type;
    union {
        uint32_t host;
        struct {
            uint32_t addr;
            uint32_t mask;
        } addr;
        struct {
            uint32_t lb_ip_addr;
            uint32_t ub_ip_addr;
        } range;
        glthread_t nested_og_list_head;
    }u;
    glthread_t parent_og_list_head;
} object_group_t;

typedef struct obj_grp_list_node_ {
    object_group_t *og;
    glthread_t glue;    
}obj_grp_list_node_t;
GLTHREAD_TO_STRUCT(glue_to_obj_grp_list_node, obj_grp_list_node_t, glue);

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
object_group_display (node_t *node, object_group_t *og);

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

#endif 