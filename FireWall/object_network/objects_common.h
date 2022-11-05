#ifndef __OBJECTS_COMMON__
#define __OBJECTS_COMMON__

#include "../../gluethread/glthread.h"

typedef struct acl_entry_ acl_entry_t;

typedef struct obj_nw_linked_acl_thread_node_ {

    acl_entry_t *acl;
    glthread_t glue;
} objects_linked_acl_thread_node_t;
GLTHREAD_TO_STRUCT(glue_to_objects_linked_acl_thread_node, \
                                                objects_linked_acl_thread_node_t, glue);


typedef struct objects_linkage_db_{

    glthread_t acls_list;
    glthread_t nat_list;
} objects_linkage_db_t;

#endif