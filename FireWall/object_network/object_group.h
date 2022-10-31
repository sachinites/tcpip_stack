#ifndef __OBJ_GRP__
#define __OBJ_GRP__

#include <stdint.h>
#include <stdbool.h>
#include "../../utils.h"
#include "../../gluethread/glthread.h"
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"

#define OBJ_GRP_NAME_LEN    255

typedef struct node_ node_t ;

typedef enum og_type_ {

    OBJECT_GRP_TYPE_UNKNOWN,
    OBJECT_GRP_NET_ADDR,
    OBJECT_GRP_NET_HOST,
    OBJECT_GRP_NET_RANGE,
    OBJECT_GRP_NESTED
} og_type_t;

typedef struct object_group_ {

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
    glthread_t glue;
} object_group_t;
GLTHREAD_TO_STRUCT (glue_to_object_group, object_group_t, glue);

typedef struct obj_grp_list_node_ {
    object_group_t *og_grp;
    glthread_t glue;    
}obj_grp_list_node_t;

object_group_t *
object_group_lookup_ht_by_name (node_t *node, hashtable_t *ht, c_string og_name);

bool
object_group_insert_into_ht (node_t *node, hashtable_t *ht,  object_group_t *og_grp);

object_group_t *
object_group_remove_from_ht_by_name (node_t *node, hashtable_t *ht, c_string og_name);

bool
object_group_remove_from_ht (node_t *node, hashtable_t *ht, object_group_t *og_grp);

void
object_group_purge_ht (node_t *node, hashtable_t *ht);

void
object_group_init_ht (node_t *node);

void
object_group_display (node_t *node, object_group_t *og_grp);

#endif 